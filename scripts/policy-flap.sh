#!/usr/bin/env bash
set -euo pipefail
DURATION="${1:-60}"  # seconds
DOWN="${2:-3}"       # seconds down
UP="${3:-7}"         # seconds up
end=$(( $(date +%s) + DURATION ))
echo "[*] policy-flap duration=${DURATION}s down=${DOWN}s up=${UP}s"
while [ "$(date +%s)" -lt "$end" ]; do
  (cd deploy && docker compose stop policy-server >/dev/null)
  sleep "$DOWN"
  (cd deploy && docker compose start policy-server >/dev/null)
  sleep "$UP"
done
echo "[+] policy-flap done"
