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
  rpc: /payments.v1.Payments/Charge
  effect: allow

- id: R2
  source: "*"
  target: payments
  rpc: /payments.v1.Payments/Refund
  effect: deny

YAML

# 2) Добавляем N-3 "лишних" правил (не матчатся под реальные вызовы),
# чтобы нагрузить обработку политик (поиск/сопоставление/объём).
# IMPORTANT: финальный deny-all мы добавим последним.
for i in $(seq 4 "$N"); do
cat >> "$OUT" <<YAML
- id: R$i
  source: svc-$i
  target: svc-$i
  rpc: /dummy.v1.Dummy/Op$i
  effect: allow

YAML
done

# 3) deny-all в конце (как у вас):
cat >> "$OUT" <<YAML
- id: R3
  source: "*"
  target: "*"
  rpc: "*"
  effect: deny
YAML

echo "[+] Generated $OUT with $N rules (R1,R2 + fillers + R3 deny-all at end)"
