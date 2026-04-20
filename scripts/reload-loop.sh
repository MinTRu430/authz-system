#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DURATION="${1:-60}"   # seconds
INTERVAL="${2:-2}"    # seconds

end=$(( $(date +%s) + DURATION ))
echo "[*] reload-loop: duration=${DURATION}s interval=${INTERVAL}s"

while [ "$(date +%s)" -lt "$end" ]; do
  make -C "$ROOT/deploy" reload >/dev/null
  sleep "$INTERVAL"
done

echo "[+] reload-loop завершен"
