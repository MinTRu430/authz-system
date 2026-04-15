#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="${STAMP:-$(date +%Y%m%d_%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-$ROOT/results/final/$STAMP/functional}"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
POLICY_FILE="$ROOT/policies/policies.yaml"
POLICY_BACKUP="$RESULT_DIR/policies.yaml.before"
SUMMARY="$RESULT_DIR/summary.csv"
MAIN_LOG="$RESULT_DIR/final-functional.log"

mkdir -p "$RESULT_DIR"
cp "$POLICY_FILE" "$POLICY_BACKUP"
echo "phase,transport,scenario,expected,result,exit_code,log_file,command" > "$SUMMARY"

log() {
  echo "$*" | tee -a "$MAIN_LOG"
}

csv_escape() {
  local v="$1"
  v="${v//\"/\"\"}"
  printf '"%s"' "$v"
}

append_summary() {
  local phase="$1" transport="$2" scenario="$3" expected="$4" result="$5" rc="$6" log_file="$7" cmd="$8"
  {
    csv_escape "$phase"; printf ","
    csv_escape "$transport"; printf ","
    csv_escape "$scenario"; printf ","
    csv_escape "$expected"; printf ","
    csv_escape "$result"; printf ","
    printf "%s," "$rc"
    csv_escape "$log_file"; printf ","
    csv_escape "$cmd"; printf "\n"
  } >> "$SUMMARY"
}

run_case() {
  local phase="$1" transport="$2" scenario="$3" expected="$4" cmd="$5"
  local name="${phase}_${transport}_${scenario}"
  local log_file="$RESULT_DIR/${name}.log"

  log ""
  log "=== ${phase}/${transport}/${scenario} expect=${expected} ==="
  log "$cmd"

  set +e
  bash -lc "$cmd" >"$log_file" 2>&1
  local rc=$?
  set -e

  cat "$log_file" | tee -a "$MAIN_LOG"

  local result="fail"
  if [[ "$expected" == "success" && "$rc" -eq 0 ]]; then
    result="pass"
  elif [[ "$expected" == "failure" && "$rc" -ne 0 ]]; then
    result="pass"
  fi

  append_summary "$phase" "$transport" "$scenario" "$expected" "$result" "$rc" "$log_file" "$cmd"
  if [[ "$result" != "pass" ]]; then
    log "FAILED: ${phase}/${transport}/${scenario}"
    return 1
  fi
}

set_rule_effect() {
  local rule_id="$1" effect="$2"
  local tmp
  tmp="$(mktemp)"
  awk -v id="$rule_id" -v effect="$effect" '
    /^- id: / {
      in_rule = ($0 == "- id: " id)
    }
    in_rule && /^[[:space:]]*effect:/ {
      print "  effect: " effect
      in_rule = 0
      next
    }
    { print }
  ' "$POLICY_FILE" > "$tmp"
  cp "$tmp" "$POLICY_FILE"
  rm -f "$tmp"
}

reload_policies() {
  run_case "reload" "policy" "reload" "success" "make -C '$ROOT/deploy' reload"
}

wait_log_case() {
  local transport="$1" scenario="$2" pattern="$3" timeout="$4"
  local cmd
  cmd="deadline=\$((SECONDS+$timeout)); while [ \$SECONDS -lt \$deadline ]; do docker compose -f '$ROOT/deploy/docker-compose.yml' logs --since=${timeout}s payments | grep -q '$pattern' && exit 0; sleep 2; done; docker compose -f '$ROOT/deploy/docker-compose.yml' logs --tail=200 payments; exit 1"
  run_case "functional" "$transport" "$scenario" "success" "$cmd"
}

restore_policy() {
  if [[ -f "$POLICY_BACKUP" ]]; then
    cp "$POLICY_BACKUP" "$POLICY_FILE"
    make -C "$ROOT/deploy" reload >/dev/null 2>&1 || true
  fi
}
trap restore_policy EXIT

snapshot() {
  local label="$1"
  curl -s http://localhost:9090/metrics > "$RESULT_DIR/payments_metrics_${label}.prom" || true
  curl -sk https://localhost:8443/metrics > "$RESULT_DIR/policy_metrics_${label}.prom" || true
  "${COMPOSE[@]}" logs --no-color --tail=400 payments policy-server orders kafka nats > "$RESULT_DIR/docker_${label}.log" 2>&1 || true
  make -C "$ROOT/deploy" audit > "$RESULT_DIR/audit_${label}.log" 2>&1 || true
}

reload_case() {
  local transport="$1" rule="$2" allow_cmd="$3"
  log ""
  log "=== reload impact: ${transport}, rule=${rule} ==="

  set_rule_effect "$rule" "deny"
  reload_policies
  sleep "${RELOAD_SETTLE_SECONDS:-3}"
  run_case "reload-impact" "$transport" "allow_rule_changed_to_deny" "failure" "$allow_cmd"

  set_rule_effect "$rule" "allow"
  reload_policies
  sleep "${RELOAD_SETTLE_SECONDS:-3}"
  run_case "reload-impact" "$transport" "allow_rule_restored" "success" "$allow_cmd"
}

log "[*] final functional results -> $RESULT_DIR"
log "[*] starting demo stack"
"${COMPOSE[@]}" up --build -d | tee -a "$MAIN_LOG"
sleep "${STACK_SETTLE_SECONDS:-5}"
snapshot "before"

run_case "functional" "grpc" "allow" "success" "docker exec orders /app/orders charge"
run_case "functional" "grpc" "deny" "failure" "docker exec orders /app/orders refund"

run_case "functional" "rest" "allow" "success" "docker exec orders /app/orders rest-charge"
run_case "functional" "rest" "deny" "failure" "docker exec orders /app/orders rest-refund"

run_case "functional" "kafka" "publish_allow" "success" "docker exec orders /app/orders kafka-publish"
wait_log_case "kafka" "consume_allow" "KAFKA CONSUME OK" 60
run_case "functional" "kafka" "publish_deny" "failure" "docker exec orders /app/orders kafka-publish-deny"

run_case "functional" "nats" "publish_allow" "success" "docker exec orders /app/orders nats-publish"
wait_log_case "nats" "consume_allow" "NATS CONSUME OK" 20
run_case "functional" "nats" "publish_deny" "failure" "docker exec orders /app/orders nats-publish-deny"

reload_case "grpc" "R1" "docker exec orders /app/orders charge"
reload_case "rest" "R_HTTP_1" "docker exec orders /app/orders rest-charge"
reload_case "kafka" "R_KAFKA_1" "docker exec orders /app/orders kafka-publish"
reload_case "nats" "R_NATS_1" "docker exec orders /app/orders nats-publish"

run_case "degrade" "grpc" "fail_closed" "success" "make -C '$ROOT/deploy' degrade-test"
run_case "degrade" "rest" "fail_closed" "success" "make -C '$ROOT/deploy' degrade-rest-test"
run_case "degrade" "kafka" "publish_fail_closed" "success" "make -C '$ROOT/deploy' degrade-kafka-test"
run_case "degrade" "kafka" "consume_fail_closed" "success" "make -C '$ROOT/deploy' degrade-kafka-consume-test"
run_case "degrade" "nats" "publish_fail_closed" "success" "make -C '$ROOT/deploy' degrade-nats-test"
run_case "degrade" "nats" "consume_fail_closed" "success" "make -C '$ROOT/deploy' degrade-nats-consume-test"

snapshot "after"
{
  echo "=== payments authz metrics ==="
  grep -E 'authz_(checks_total|cache_total|fail_closed_total|policy_check_latency_seconds_(count|sum))' "$RESULT_DIR/payments_metrics_after.prom" || true
  echo
  echo "=== policy-server metrics ==="
  grep -E 'policy_' "$RESULT_DIR/policy_metrics_after.prom" || true
} > "$RESULT_DIR/metrics_summary.txt"

log ""
log "[+] final functional suite complete"
log "[+] summary: $SUMMARY"
log "[+] metrics: $RESULT_DIR/metrics_summary.txt"
