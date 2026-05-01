#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="${STAMP:-$(date +%Y%m%d_%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-$ROOT/results/final/$STAMP/bench}"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
N="${FINAL_N:-200}"
C="${FINAL_C:-10}"
WARMUP="${FINAL_WARMUP:-20}"
ASYNC_SETTLE_SECONDS="${ASYNC_SETTLE_SECONDS:-20}"
SUMMARY="$RESULT_DIR/bench_summary.csv"
MAIN_LOG="$RESULT_DIR/final-bench.log"

mkdir -p "$RESULT_DIR"
echo "transport,scenario,n,c,ok,fail,rps,min_ms,avg_ms,p50_ms,p95_ms,p99_ms,max_ms" > "$SUMMARY"

log() {
  echo "$*" | tee -a "$MAIN_LOG"
}

snapshot_metrics() {
  local label="$1"
  curl -s http://localhost:9090/metrics > "$RESULT_DIR/payments_metrics_${label}.prom" || true
  curl -sk https://localhost:8443/metrics > "$RESULT_DIR/policy_metrics_1_${label}.prom" || true
  curl -sk https://localhost:8444/metrics > "$RESULT_DIR/policy_metrics_2_${label}.prom" || true
  curl -sk https://localhost:8445/metrics > "$RESULT_DIR/policy_metrics_3_${label}.prom" || true
}

run_bench() {
  local transport="$1" scenario="$2"
  local log_file="$RESULT_DIR/${transport}_${scenario}.log"

  log ""
  log "=== измерение ${transport}/${scenario} n=${N} c=${C} прогрев=${WARMUP} ==="
  set +e
  docker exec orders /app/transportbench \
    -transport "$transport" \
    -scenario "$scenario" \
    -n "$N" \
    -c "$C" \
    -warmup "$WARMUP" >"$log_file" 2>&1
  local rc=$?
  set -e

  cat "$log_file" | tee -a "$MAIN_LOG"
  if [[ "$rc" -ne 0 ]]; then
    log "ОШИБКА: измерение ${transport}/${scenario}"
    return "$rc"
  fi

  awk -F'CSV: ' '/^CSV: / && $2 !~ /^transport,/ { line=$2 } END { if (line != "") print line }' "$log_file" >> "$SUMMARY"
}

log "[*] Результаты итогового измерения -> $RESULT_DIR"
log "[*] Запуск стенда"
"${COMPOSE[@]}" up --build -d | tee -a "$MAIN_LOG"
sleep "${STACK_SETTLE_SECONDS:-5}"

snapshot_metrics "before"

run_bench "grpc" "allow"
run_bench "grpc" "deny"
run_bench "rest" "allow"
run_bench "rest" "deny"
run_bench "kafka" "allow"
run_bench "kafka" "deny"
sleep "$ASYNC_SETTLE_SECONDS"
run_bench "nats" "allow"
run_bench "nats" "deny"
sleep "$ASYNC_SETTLE_SECONDS"

snapshot_metrics "after"
"${COMPOSE[@]}" logs --no-color --tail=600 payments policy-server-1 policy-server-2 policy-server-3 orders kafka nats > "$RESULT_DIR/docker_after.log" 2>&1 || true
make -C "$ROOT/deploy" audit-all > "$RESULT_DIR/audit_after.log" 2>&1 || true

{
  echo "=== сводка измерений ==="
  cat "$SUMMARY"
  echo
  echo "=== метрики авторизации payments после измерения ==="
  grep -E 'authz_(checks_total|protected_operations_total|cache_total|fail_closed_total|policy_check_latency_seconds_(count|sum)|policy_health_checks_total|policy_availability_state|policy_circuit_transitions_total|policy_failover_total|policy_endpoint_requests_total|policy_endpoint_health_total|policy_endpoint_availability_state|message_signed_total|message_signature_checks_total|message_signature_failures_total|broker_message_processing_total|broker_messages_retried_total|broker_messages_deadlettered_total|broker_dlq_publish_errors_total|broker_consume_errors_total)' "$RESULT_DIR/payments_metrics_after.prom" || true
  echo
  echo "=== счетчики асинхронной обработки в журналах ==="
  printf "kafka_consume_ok,"
  grep -c 'KAFKA CONSUME OK' "$RESULT_DIR/docker_after.log" || true
  printf "nats_consume_ok,"
  grep -c 'NATS CONSUME OK' "$RESULT_DIR/docker_after.log" || true
} > "$RESULT_DIR/summary.txt"

log ""
log "[+] Итоговое измерение завершено"
log "[+] сводка: $SUMMARY"
log "[+] текстовая сводка: $RESULT_DIR/summary.txt"
