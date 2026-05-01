#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/deploy/docker-compose.yml")
POLICY_SERVERS=(policy-server-1 policy-server-2 policy-server-3)
STAMP="$(date +%Y%m%d_%H%M%S)"
RESULT_DIR="${RESULT_DIR:-$ROOT/results/degrade}"
OUT="${OUT:-$RESULT_DIR/degrade_${STAMP}.log}"

mkdir -p "$(dirname "$OUT")"

echo "[*] Лог проверки отказа -> $OUT"

{
  echo "=== ВРЕМЯ ==="
  date -Iseconds
  echo

  echo "=== 0) Начальная проверка: charge при доступном policy-server ==="
  docker exec orders /app/orders charge || true
  echo

  echo "=== 1) Остановка всех policy-server ==="
  "${COMPOSE[@]}" stop "${POLICY_SERVERS[@]}"
  sleep 1
  echo

  echo "=== 2) Вызов charge при недоступном policy-server: ожидается запрет ==="
  docker exec orders /app/orders charge || true
  echo

  echo "=== 3) Запуск всех policy-server ==="
  "${COMPOSE[@]}" up -d "${POLICY_SERVERS[@]}"
  sleep 3
  echo

  echo "=== 4) Повторный charge: ожидается OK ==="
  docker exec orders /app/orders charge || true
  echo

  echo "=== 5) Последние журналы: orders/payments/policy-server ==="
  docker logs --tail 50 orders || true
  echo
  docker logs --tail 50 payments || true
  echo
  docker logs --tail 80 policy-server-1 || true
  echo
  docker logs --tail 80 policy-server-2 || true
  echo
  docker logs --tail 80 policy-server-3 || true
  echo

  echo "=== 6) Снимок метрик: payments / policy-server ==="
  echo "--- payments /metrics (grep authz_) ---"
  curl -s http://localhost:9090/metrics | egrep "authz_|grpc_" | head -n 50 || true
  echo
  echo "--- policy-server-1 /metrics (grep policy_) ---"
  curl -sk https://localhost:8443/metrics | egrep "policy_|authz_" | head -n 50 || true
  echo
  echo "--- policy-server-2 /metrics (grep policy_) ---"
  curl -sk https://localhost:8444/metrics | egrep "policy_|authz_" | head -n 50 || true
  echo
  echo "--- policy-server-3 /metrics (grep policy_) ---"
  curl -sk https://localhost:8445/metrics | egrep "policy_|authz_" | head -n 50 || true
  echo

  echo "=== ГОТОВО ==="
} | tee "$OUT"
