#!/usr/bin/env bash
set -euo pipefail

STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="degrade_${STAMP}.log"

echo "[*] Degradation test log -> $OUT"

{
  echo "=== TIME ==="
  date -Iseconds
  echo

  echo "=== 0) Baseline: charge (policy-server up) ==="
  docker exec orders /app/orders charge || true
  echo

  echo "=== 1) Stop policy-server ==="
  docker compose -f deploy/docker-compose.yml stop policy-server
  sleep 1
  echo

  echo "=== 2) Call charge while DOWN (expect deny/fail-closed) ==="
  docker exec orders /app/orders charge || true
  echo

  echo "=== 3) Start policy-server ==="
  docker compose -f deploy/docker-compose.yml up -d policy-server
  sleep 2
  echo

  echo "=== 4) Charge again (expect OK) ==="
  docker exec orders /app/orders charge || true
  echo

  echo "=== 5) Last logs (orders/payments/policy-server) ==="
  docker logs --tail 50 orders || true
  echo
  docker logs --tail 50 payments || true
  echo
  docker logs --tail 80 policy-server || true
  echo

  echo "=== 6) Metrics snapshot (payments / policy-server) ==="
  echo "--- payments /metrics (grep authz_) ---"
  curl -s http://localhost:9090/metrics | egrep "authz_|grpc_" | head -n 50 || true
  echo
  echo "--- policy-server /metrics (grep policy_) ---"
  curl -sk https://localhost:8443/metrics | egrep "policy_|authz_" | head -n 50 || true
  echo

  echo "=== DONE ==="
} | tee "$OUT"
