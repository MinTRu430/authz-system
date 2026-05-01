#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
POLICY_SERVERS=(policy-server-1 policy-server-2 policy-server-3)
DURATION="${1:-60}"  # seconds
DOWN="${2:-3}"       # seconds down
UP="${3:-7}"         # seconds up
end=$(( $(date +%s) + DURATION ))
echo "[*] Периодическая остановка policy-server: длительность=${DURATION}s остановка=${DOWN}s работа=${UP}s"
while [ "$(date +%s)" -lt "$end" ]; do
  "${COMPOSE[@]}" stop "${POLICY_SERVERS[@]}" >/dev/null
  sleep "$DOWN"
  "${COMPOSE[@]}" start "${POLICY_SERVERS[@]}" >/dev/null
  sleep "$UP"
done
echo "[+] Периодическая остановка policy-server завершена"
