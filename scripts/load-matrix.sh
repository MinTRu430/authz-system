#!/usr/bin/env bash
set -euo pipefail

# Generates CSV for report:
# mode, n, c, rps, p50_ms, p95_ms, p99_ms, avg_ms, ok, fail

MODE="${1:-charge}"
N="${2:-5000}"

OUT="${OUT:-load_${MODE}_$(date +%Y%m%d_%H%M%S).csv}"
echo "mode,n,c,rps,p50_ms,p95_ms,p99_ms,avg_ms,ok,fail" > "$OUT"

for C in 1 5 10 20 50 100; do
  echo "[*] mode=$MODE n=$N c=$C"

  RES=$(go run ../cmd/loadtest \
  -mode "$MODE" -n "$N" -c "$C" \
  -ca ../certs/ca.pem \
  -cert ../certs/orders.pem \
  -key ../certs/orders-key.pem \
  -servername payments \
  -addr localhost:50051 \
  2>/dev/null | tee /dev/stderr)


  RPS=$(echo "$RES" | awk '/^RPS:/{print $2}')
  OK=$(echo "$RES"  | awk '/^OK:/{print $2}')
  FAIL=$(echo "$RES"| awk '/^OK:/{print $4}')

  P50=$(echo "$RES" | awk '/^  p50:/{print $2}')
  P95=$(echo "$RES" | awk '/^  p95:/{print $2}')
  P99=$(echo "$RES" | awk '/^  p99:/{print $2}')
  AVG=$(echo "$RES" | awk '/^  avg:/{print $2}')

  # Convert durations like "123ms" / "1.2s" to ms (best-effort)
  to_ms () {
    local v="$1"
    if [[ "$v" == *ms ]]; then echo "${v%ms}"
    elif [[ "$v" == *s ]]; then
      python3 - <<PY
v="${v%s}"
print(int(float(v)*1000))
PY
    else echo ""
    fi
  }

  echo "${MODE},${N},${C},${RPS},$(to_ms "$P50"),$(to_ms "$P95"),$(to_ms "$P99"),$(to_ms "$AVG"),${OK},${FAIL}" >> "$OUT"
done

echo
echo "[+] CSV saved: $OUT"
