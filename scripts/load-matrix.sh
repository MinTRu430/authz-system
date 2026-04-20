#!/usr/bin/env bash
set -euo pipefail

# Генерирует CSV для отчета:
# mode, n, c, rps, p50_ms, p95_ms, p99_ms, avg_ms, ok, fail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-charge}"
N="${2:-5000}"

RESULT_DIR="${RESULT_DIR:-$ROOT/results/load}"
OUT="${OUT:-$RESULT_DIR/load_${MODE}_$(date +%Y%m%d_%H%M%S).csv}"
mkdir -p "$(dirname "$OUT")"
echo "mode,n,c,rps,p50_ms,p95_ms,p99_ms,avg_ms,ok,fail" > "$OUT"

for C in 1 5 10 20 50 100; do
  echo "[*] mode=$MODE n=$N c=$C"

  RES=$(cd "$ROOT" && go run ./cmd/loadtest \
  -mode "$MODE" -n "$N" -c "$C" \
  -ca certs/ca.pem \
  -cert certs/orders.pem \
  -key certs/orders-key.pem \
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

  # Конвертирует durations вроде "123ms" / "1.2s" в ms (best-effort).
  to_ms () {
    local v="$1"
    if [[ "$v" == *ms ]]; then echo "${v%ms}"
    elif [[ "$v" == *s ]]; then
      awk -v s="${v%s}" 'BEGIN { printf "%.0f\n", s * 1000 }'
    else echo ""
    fi
  }

  echo "${MODE},${N},${C},${RPS},$(to_ms "$P50"),$(to_ms "$P95"),$(to_ms "$P99"),$(to_ms "$AVG"),${OK},${FAIL}" >> "$OUT"
done

echo
echo "[+] CSV сохранен: $OUT"
