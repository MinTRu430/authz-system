#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="${STAMP:-$(date +%Y%m%d_%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-$ROOT/results/broker-failover-stress/$STAMP}"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
POLICY_SERVERS=(policy-server-1 policy-server-2 policy-server-3)

N="${BROKER_FAILOVER_N:-50000}"
PROBE_N="${BROKER_FAILOVER_PROBE_N:-2000}"
CONCURRENCY="${BROKER_FAILOVER_CONCURRENCY:-10}"
PROBE_CONCURRENCY="${BROKER_FAILOVER_PROBE_CONCURRENCY:-50}"
PACE="${BROKER_FAILOVER_PACE:-3ms}"
TIMEOUT="${BROKER_FAILOVER_TIMEOUT:-5s}"
CACHE_TTL="${BROKER_FAILOVER_CACHE_TTL:-2s}"

SUMMARY="$RESULT_DIR/summary.md"
MAIN_LOG="$RESULT_DIR/run.log"

mkdir -p "$RESULT_DIR"

cat >"$SUMMARY" <<EOF
# Переключение реплик policy-server под брокерной нагрузкой

- дата запуска: $(date --iso-8601=seconds)
- длительная нагрузка: $N операций, параллелизм $CONCURRENCY, задержка между операциями $PACE
- проверка каждого состояния: $PROBE_N операций, параллелизм $PROBE_CONCURRENCY
- кэш: $CACHE_TTL

| Брокер | Фаза | Ожидание | Сообщения | Успешно | Ошибки | Разрешено | Заблокировано | Сообщений/с | p95, мс | p99, мс |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
EOF

log() {
  echo "$*" | tee -a "$MAIN_LOG"
}

restore_stack() {
  "${COMPOSE[@]}" up -d "${POLICY_SERVERS[@]}" payments >/dev/null 2>&1 || true
}
trap restore_stack EXIT

append_result() {
  local broker="$1"
  local phase="$2"
  local log_file="$3"
  local json_file="$RESULT_DIR/${broker}_${phase}.json"

  awk -F'JSON: ' '/^JSON: / { value=$2 } END { if (value != "") print value }' "$log_file" >"$json_file"
  if [[ ! -s "$json_file" ]]; then
    log "ОШИБКА: не сформирован JSON для $broker/$phase"
    return 1
  fi

  local values
  values="$(awk -F'JSON: ' '/^JSON: / { value=$2 } END { print value }' "$log_file")"
  local expect total success errors allowed blocked throughput p95 p99
  expect="$(printf '%s' "$values" | sed -n 's/.*"expect":"\([^"]*\)".*/\1/p')"
  total="$(printf '%s' "$values" | sed -n 's/.*"total":\([0-9]*\).*/\1/p')"
  success="$(printf '%s' "$values" | sed -n 's/.*"success":\([0-9]*\).*/\1/p')"
  errors="$(printf '%s' "$values" | sed -n 's/.*"errors":\([0-9]*\).*/\1/p')"
  allowed="$(printf '%s' "$values" | sed -n 's/.*"allowed":\([0-9]*\).*/\1/p')"
  blocked="$(printf '%s' "$values" | sed -n 's/.*"blocked":\([0-9]*\).*/\1/p')"
  throughput="$(printf '%s' "$values" | sed -n 's/.*"throughput":\([0-9.]*\).*/\1/p')"
  p95="$(printf '%s' "$values" | sed -n 's/.*"p95_ms":\([0-9.]*\).*/\1/p')"
  p99="$(printf '%s' "$values" | sed -n 's/.*"p99_ms":\([0-9.]*\).*/\1/p')"
  printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
    "$broker" "$phase" "$expect" "$total" "$success" "$errors" "$allowed" "$blocked" "$throughput" "$p95" "$p99" >>"$SUMMARY"
}

run_probe() {
  local broker="$1"
  local phase="$2"
  local expect="$3"
  local log_file="$RESULT_DIR/${broker}_${phase}.log"

  log "=== $broker: $phase, ожидается $expect ==="
  set +e
  docker exec orders /app/brokerstress \
    -broker "$broker" \
    -mode publish \
    -scenario valid \
    -n "$PROBE_N" \
    -c "$PROBE_CONCURRENCY" \
    -cache-ttl "$CACHE_TTL" \
    -timeout "$TIMEOUT" \
    -expect "$expect" >"$log_file" 2>&1
  local rc=$?
  set -e
  cat "$log_file" | tee -a "$MAIN_LOG"
  append_result "$broker" "$phase" "$log_file"
  if [[ "$rc" -ne 0 ]]; then
    log "ОШИБКА: проверка $broker/$phase не совпала с ожиданием"
    return "$rc"
  fi
}

run_broker_failover() {
  local broker="$1"
  local continuous_log="$RESULT_DIR/${broker}_continuous.log"

  log ""
  log "=== Начало непрерывной нагрузки $broker ==="
  "${COMPOSE[@]}" up -d "${POLICY_SERVERS[@]}"
  sleep 3

  docker exec orders /app/brokerstress \
    -broker "$broker" \
    -mode publish \
    -scenario valid \
    -n "$N" \
    -c "$CONCURRENCY" \
    -cache-ttl "$CACHE_TTL" \
    -timeout "$TIMEOUT" \
    -pace "$PACE" \
    -expect any >"$continuous_log" 2>&1 &
  local load_pid=$!

  sleep 2
  "${COMPOSE[@]}" stop policy-server-1
  sleep 1
  run_probe "$broker" "one_replica_down" allowed

  "${COMPOSE[@]}" stop policy-server-2
  sleep 1
  run_probe "$broker" "two_replicas_down" allowed

  "${COMPOSE[@]}" stop policy-server-3
  sleep 1
  run_probe "$broker" "all_replicas_down" blocked

  "${COMPOSE[@]}" up -d "${POLICY_SERVERS[@]}"
  sleep 4
  run_probe "$broker" "recovered" allowed

  wait "$load_pid"
  cat "$continuous_log" | tee -a "$MAIN_LOG"
  append_result "$broker" "continuous_transition" "$continuous_log"
}

log "[*] Каталог результатов: $RESULT_DIR"
"${COMPOSE[@]}" up -d
sleep "${STACK_SETTLE_SECONDS:-5}"
docker exec orders test -x /app/brokerstress
"${COMPOSE[@]}" stop payments >/dev/null

run_broker_failover kafka
run_broker_failover nats

cat >>"$SUMMARY" <<'EOF'

## Критерии

- при остановке одной реплики все операции проверки должны оставаться разрешёнными;
- при остановке двух реплик операции должны продолжаться через оставшуюся реплику;
- при остановке всех трёх реплик операции должны классифицироваться как `blocked`;
- после восстановления реплик операции снова должны разрешаться;
- строка `continuous_transition` показывает распределение разрешённых и заблокированных операций во время единого непрерывного прогона.
EOF

restore_stack
trap - EXIT

log ""
log "[+] Проверка переключения под нагрузкой завершена"
log "[+] Краткий отчёт: $SUMMARY"
log "[+] JSON-файлы: $RESULT_DIR/*.json"
