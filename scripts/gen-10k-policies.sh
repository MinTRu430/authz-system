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

- id: R5
  source: orders
  target: payments
  transport: broker
  broker: kafka
  operation: publish
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R6
  source: orders
  target: payments
  transport: broker
  broker: kafka
  operation: consume
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R7
  source: orders
  target: payments
  transport: broker
  broker: kafka
  operation: publish
  resource: payments.refund.forced
  message_type: payment.refund.forced.v1
  effect: deny

- id: R8
  source: orders
  target: payments
  transport: broker
  broker: nats
  operation: publish
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R9
  source: orders
  target: payments
  transport: broker
  broker: nats
  operation: consume
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R10
  source: orders
  target: payments
  transport: broker
  broker: nats
  operation: publish
  resource: payments.refund.forced
  message_type: payment.refund.forced.v1
  effect: deny

YAML

# 2) Добавляем лишние правила (не матчатся под реальные вызовы),
# чтобы нагрузить обработку политик (поиск/сопоставление/объём).
# Важно: финальный deny-all добавляется последним.
for i in $(seq 12 "$N"); do
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
- id: R11
  source: "*"
  target: "*"
  transport: "*"
  operation: "*"
  resource: "*"
  broker: "*"
  message_type: "*"
  effect: deny
YAML

echo "[+] Сгенерирован $OUT с $N правилами с учетом транспорта (базовые правила grpc/rest/kafka/nats, дополнительные правила и R11 deny-all в конце)"
