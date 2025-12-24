#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/bench.sh                # default: charge, N=200, WARMUP=20
#   ./scripts/bench.sh charge 500     # charge, N=500
#   ./scripts/bench.sh refund 200     # refund (deny path), N=200
#
# Measures end-to-end latency of calling orders CLI inside container:
# docker exec orders /app/orders <cmd>
#
# Outputs: min/avg/p50/p95/max, RPS

CMD="${1:-charge}"        # charge|refund
N="${2:-200}"             # number of measured requests
WARMUP="${WARMUP:-20}"    # warmup requests (not included)
CONTAINER="${CONTAINER:-orders}"

if [[ "$CMD" != "charge" && "$CMD" != "refund" ]]; then
  echo "Usage: $0 charge|refund [N]"
  exit 2
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}\$"; then
  echo "Container '${CONTAINER}' is not running. Start stack: make -C deploy up"
  exit 1
fi

echo "[*] Bench cmd=${CMD} N=${N} warmup=${WARMUP} container=${CONTAINER}"

# Warmup (ignore errors for refund; for charge we expect success)
for _ in $(seq 1 "${WARMUP}"); do
  if [[ "$CMD" == "refund" ]]; then
    docker exec "${CONTAINER}" /app/orders refund >/dev/null 2>&1 || true
  else
    docker exec "${CONTAINER}" /app/orders charge >/dev/null 2>&1
  fi
done

times_ms=()

# Helpers: get monotonic time in ns
now_ns() { date +%s%N; }

ok=0
fail=0

t0_all=$(now_ns)

for _ in $(seq 1 "${N}"); do
  t0=$(now_ns)

  if [[ "$CMD" == "refund" ]]; then
    # deny is expected -> exit code is non-zero, so ignore it
    docker exec "${CONTAINER}" /app/orders refund >/dev/null 2>&1 || true
    rc=0
  else
    docker exec "${CONTAINER}" /app/orders charge >/dev/null 2>&1
    rc=$?
  fi

  t1=$(now_ns)
  dt_ms=$(( (t1 - t0) / 1000000 ))
  times_ms+=("${dt_ms}")

  if [[ "$rc" -eq 0 ]]; then ok=$((ok+1)); else fail=$((fail+1)); fi
done

t1_all=$(now_ns)
total_ms=$(( (t1_all - t0_all) / 1000000 ))

# Sort times for percentiles
sorted=$(printf "%s\n" "${times_ms[@]}" | sort -n)

min=$(echo "$sorted" | head -n 1)
max=$(echo "$sorted" | tail -n 1)

sum=0
for v in "${times_ms[@]}"; do sum=$((sum+v)); done
avg=$((sum / ${#times_ms[@]}))

# percentile function: nearest-rank
# p50 index = ceil(0.50*n), p95 = ceil(0.95*n)
pctl() {
  local p="$1"
  local n="${#times_ms[@]}"
  local idx=$(( (p*n + 99) / 100 ))   # ceil(p*n/100)
  if [[ "$idx" -lt 1 ]]; then idx=1; fi
  echo "$sorted" | sed -n "${idx}p"
}

p50=$(pctl 50)
p95=$(pctl 95)

# RPS
# avoid division by zero
if [[ "$total_ms" -eq 0 ]]; then
  rps="inf"
else
  # integer rps
  rps=$(( (N * 1000) / total_ms ))
fi

echo
echo "=== RESULTS (${CMD}) ==="
echo "Requests: ${N}  warmup: ${WARMUP}"
echo "OK: ${ok}  FAIL: ${fail}"
echo "Total time: ${total_ms} ms"
echo "RPS: ~${rps}"
echo "Latency (ms):"
echo "  min: ${min}"
echo "  avg: ${avg}"
echo "  p50: ${p50}"
echo "  p95: ${p95}"
echo "  max: ${max}"
echo
echo "Tip: correlate with Prometheus:"
echo "  authz_policy_check_latency_seconds, authz_checks_total, policy_decisions_total"
