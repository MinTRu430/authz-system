#!/usr/bin/env bash
set -euo pipefail

# Использование:
#   ./scripts/bench.sh                # по умолчанию: charge, N=200, WARMUP=20
#   ./scripts/bench.sh charge 500     # charge, N=500
#   ./scripts/bench.sh refund 200     # refund (deny path), N=200
#
# Измеряет end-to-end latency вызова orders CLI внутри container:
# docker exec orders /app/orders <cmd>
#
# Выводит: min/avg/p50/p95/max, RPS

CMD="${1:-charge}"        # charge|refund
N="${2:-200}"             # число измеряемых requests
WARMUP="${WARMUP:-20}"    # warmup requests, не входят в измерение
CONTAINER="${CONTAINER:-orders}"

if [[ "$CMD" != "charge" && "$CMD" != "refund" ]]; then
  echo "Использование: $0 charge|refund [N]"
  exit 2
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}\$"; then
  echo "Container '${CONTAINER}' не запущен. Запустите стенд: make -C deploy up"
  exit 1
fi

echo "[*] Benchmark cmd=${CMD} N=${N} warmup=${WARMUP} container=${CONTAINER}"

# Warmup: ошибки refund игнорируются, для charge ожидается success.
for _ in $(seq 1 "${WARMUP}"); do
  if [[ "$CMD" == "refund" ]]; then
    docker exec "${CONTAINER}" /app/orders refund >/dev/null 2>&1 || true
  else
    docker exec "${CONTAINER}" /app/orders charge >/dev/null 2>&1
  fi
done

times_ms=()

# Helper: получить monotonic time в ns.
now_ns() { date +%s%N; }

ok=0
fail=0

t0_all=$(now_ns)

for _ in $(seq 1 "${N}"); do
  t0=$(now_ns)

  if [[ "$CMD" == "refund" ]]; then
    # deny ожидается, поэтому non-zero exit code игнорируется.
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

# Сортировка времен для percentiles.
sorted=$(printf "%s\n" "${times_ms[@]}" | sort -n)

min=$(echo "$sorted" | head -n 1)
max=$(echo "$sorted" | tail -n 1)

sum=0
for v in "${times_ms[@]}"; do sum=$((sum+v)); done
avg=$((sum / ${#times_ms[@]}))

# percentile function: nearest-rank.
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

# RPS.
# Защита от деления на ноль.
if [[ "$total_ms" -eq 0 ]]; then
  rps="inf"
else
  # integer rps
  rps=$(( (N * 1000) / total_ms ))
fi

echo
echo "=== РЕЗУЛЬТАТЫ (${CMD}) ==="
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
echo "Подсказка: сопоставьте с Prometheus:"
echo "  authz_policy_check_latency_seconds, authz_checks_total, policy_decisions_total"
