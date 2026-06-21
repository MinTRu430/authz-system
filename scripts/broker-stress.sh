#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="${STAMP:-$(date +%Y%m%d_%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-$ROOT/results/broker-stress/$STAMP}"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")

N="${BROKER_STRESS_N:-50000}"
CONSUME_N="${BROKER_CONSUME_N:-$N}"
CONCURRENCIES="${BROKER_STRESS_CONCURRENCIES:-10,50,100}"
CACHE_ON_TTL="${BROKER_CACHE_ON_TTL:-2s}"
CACHE_OFF_TTL="0s"
TIMEOUT="${BROKER_STRESS_TIMEOUT:-15s}"

SUMMARY="$RESULT_DIR/summary.md"
MAIN_LOG="$RESULT_DIR/run.log"

mkdir -p "$RESULT_DIR"

cat >"$SUMMARY" <<EOF
# Нагрузочные испытания Kafka и NATS

- дата запуска: $(date --iso-8601=seconds)
- число сообщений для публикации и полного пути: $N
- число сообщений для проверки потребления: $CONSUME_N
- уровни параллелизма: $CONCURRENCIES
- кэш включён: $CACHE_ON_TTL
- кэш выключен: $CACHE_OFF_TTL

Режим \`publish\` измеряет путь «авторизация публикации -> подпись -> подтверждённая публикация брокером».

Режим \`e2e\` измеряет полный путь «авторизация публикации -> подпись -> брокер -> получение -> проверка подписи -> авторизация обработки -> обработчик».

Режим \`consume\` исключает авторизацию публикации: сообщение подписывается и непосредственно отправляется брокеру, после чего измеряются доставка, проверка подписи, авторизация обработки и допуск к обработчику.

| Брокер | Режим | Сценарий | Кэш | Сообщения | Параллелизм | Ожидание | Успешно | Ошибки | Разрешено | Заблокировано | Запрещено | Неверная подпись | Сообщений/с | Среднее, мс | p50, мс | p95, мс | p99, мс | Вызовы обработчика |
|---|---|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
EOF

log() {
  echo "$*" | tee -a "$MAIN_LOG"
}

restore_stack() {
  "${COMPOSE[@]}" up -d policy-server-1 policy-server-2 policy-server-3 payments >/dev/null 2>&1 || true
}
trap restore_stack EXIT

run_case() {
  local broker="$1"
  local mode="$2"
  local scenario="$3"
  local count="$4"
  local concurrency="$5"
  local cache_ttl="$6"
  local expect="${7:-auto}"
  local name="${broker}_${mode}_${scenario}_n${count}_c${concurrency}_cache_${cache_ttl//[^a-zA-Z0-9]/_}"
  local log_file="$RESULT_DIR/${name}.log"
  local json_file="$RESULT_DIR/${name}.json"

  log ""
  log "=== $broker/$mode/$scenario n=$count c=$concurrency cache=$cache_ttl expect=$expect ==="

  set +e
  docker exec orders /app/brokerstress \
    -broker "$broker" \
    -mode "$mode" \
    -scenario "$scenario" \
    -n "$count" \
    -c "$concurrency" \
    -cache-ttl "$cache_ttl" \
    -timeout "$TIMEOUT" \
    -expect "$expect" >"$log_file" 2>&1
  local rc=$?
  set -e

  cat "$log_file" | tee -a "$MAIN_LOG"
  awk -F'JSON: ' '/^JSON: / { value=$2 } END { if (value != "") print value }' "$log_file" >"$json_file"
  awk -F'MARKDOWN: ' '/^MARKDOWN: / { value=$2 } END { if (value != "") print value }' "$log_file" >>"$SUMMARY"

  if [[ ! -s "$json_file" ]]; then
    log "ОШИБКА: $name не сформировал JSON"
    return 1
  fi
  if [[ "$rc" -ne 0 ]]; then
    log "ОШИБКА: $name завершился с кодом $rc"
    return "$rc"
  fi
}

log "[*] Каталог результатов: $RESULT_DIR"
log "[*] Проверка и запуск ранее собранного стенда"
"${COMPOSE[@]}" up -d
sleep "${STACK_SETTLE_SECONDS:-5}"
docker exec orders test -x /app/brokerstress

# Нагрузочная утилита содержит собственного потребителя. Остановка payments
# исключает повторную обработку тех же Kafka/NATS сообщений и шум в журналах.
"${COMPOSE[@]}" stop payments >/dev/null

IFS=',' read -r -a concurrency_values <<<"$CONCURRENCIES"

for broker in kafka nats; do
  for concurrency in "${concurrency_values[@]}"; do
    run_case "$broker" publish valid "$N" "$concurrency" "$CACHE_ON_TTL"
    run_case "$broker" e2e valid "$N" "$concurrency" "$CACHE_ON_TTL"
  done
done

for broker in kafka nats; do
  for scenario in valid invalid-signature denied; do
    for concurrency in "${concurrency_values[@]}"; do
      run_case "$broker" consume "$scenario" "$CONSUME_N" "$concurrency" "$CACHE_ON_TTL"
    done
  done
done

# Сравнение с отключенным кэшем. Результаты с включенным кэшем уже записаны выше.
for broker in kafka nats; do
  for concurrency in "${concurrency_values[@]}"; do
    run_case "$broker" publish valid "$N" "$concurrency" "$CACHE_OFF_TTL"
    run_case "$broker" e2e valid "$N" "$concurrency" "$CACHE_OFF_TTL"
  done
done

cat >>"$SUMMARY" <<'EOF'

## Условия правильности

- для `publish/valid` ожидается, что все операции разрешены;
- для `e2e/valid` число вызовов обработчика должно совпадать с числом успешных сообщений;
- для `consume/invalid-signature` вызовы обработчика должны отсутствовать;
- для `consume/denied` вызовы обработчика должны отсутствовать;
- ненулевое поле `errors` означает, что фактическое поведение не совпало с ожидаемым.

## Сопоставление кэша

Для сравнения кэша следует сопоставлять строки с одинаковыми брокером, режимом и параллелизмом, но значениями `2s` и `0s` в столбце «Кэш». Основные показатели: p95, p99 и число сообщений в секунду.
EOF

restore_stack
trap - EXIT

log ""
log "[+] Нагрузочные испытания завершены"
log "[+] Краткий отчёт: $SUMMARY"
log "[+] JSON-файлы: $RESULT_DIR/*.json"
