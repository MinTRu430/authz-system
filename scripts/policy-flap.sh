#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
DURATION="${1:-60}"  # seconds
DOWN="${2:-3}"       # seconds down
UP="${3:-7}"         # seconds up
end=$(( $(date +%s) + DURATION ))
echo "[*] Периодическая остановка policy-server: длительность=${DURATION}s остановка=${DOWN}s работа=${UP}s"
while [ "$(date +%s)" -lt "$end" ]; do
  "${COMPOSE[@]}" stop policy-server >/dev/null
  sleep "$DOWN"
  "${COMPOSE[@]}" start policy-server >/dev/null
  sleep "$UP"
done
echo "[+] Периодическая остановка policy-server завершена"
