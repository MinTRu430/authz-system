#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-policies/policies_10k.yaml}"
N="${2:-10000}"

mkdir -p "$(dirname "$OUT")"

# 1) Базовые "реальные" правила (ваши):
cat > "$OUT" <<YAML
- id: R1
  source: orders
  target: payments
  transport: grpc
  operation: /payments.v1.Payments/Charge
  resource: "*"
  effect: allow

- id: R2
  source: "*"
  target: payments
  transport: grpc
  operation: /payments.v1.Payments/Refund
  resource: "*"
  effect: deny

- id: R3
  source: orders
  target: payments
  transport: http
  operation: POST
  resource: /payments/charge
  effect: allow

- id: R4
  source: orders
  target: payments
  transport: http
  operation: POST
  resource: /payments/refund
  effect: deny

YAML

# 2) Добавляем лишние правила (не матчатся под реальные вызовы),
# чтобы нагрузить обработку политик (поиск/сопоставление/объём).
# IMPORTANT: финальный deny-all мы добавим последним.
for i in $(seq 6 "$N"); do
cat >> "$OUT" <<YAML
- id: R$i
  source: svc-$i
  target: svc-$i
  transport: grpc
  operation: /dummy.v1.Dummy/Op$i
  resource: "*"
  effect: allow

YAML
done

# 3) deny-all в конце (как у вас):
cat >> "$OUT" <<YAML
- id: R5
  source: "*"
  target: "*"
  transport: "*"
  operation: "*"
  resource: "*"
  effect: deny
YAML

echo "[+] Generated $OUT with $N transport-aware rules (grpc/rest basics + fillers + R5 deny-all at end)"
