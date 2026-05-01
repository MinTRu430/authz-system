# DLQ и подписи Kafka/NATS

Команды:

```bash
make -C deploy test-dlq
make -C deploy degrade-all
```

Результат: успешно.

Подтвержденные сценарии:

- Kafka message с неверной HMAC-подписью отклоняется до `policy-server` и попадает в `authz.dlq.payments.requested` с reason `invalid_signature`;
- NATS message с неверной HMAC-подписью отклоняется до `policy-server` и попадает в `authz.dlq.payments.requested` с reason `invalid_signature`;
- Kafka consume при недоступности всех трех `policy-server` повторяется и после исчерпания retry попадает в DLQ с reason `policy_unavailable`;
- NATS consume при недоступности всех трех `policy-server` повторяется локально и после исчерпания retry попадает в DLQ с reason `policy_unavailable`;
- allow path для Kafka/NATS после восстановления `policy-server` снова обрабатывает сообщения штатно.

Фрагменты журналов:

```text
payments | 2026/05/01 13:01:30 KAFKA DLQ OK: topic=authz.dlq.payments.requested reason=policy_unavailable source=orders message_type=payment.requested.v1
payments | 2026/05/01 13:01:57 NATS DLQ OK: subject=authz.dlq.payments.requested reason=policy_unavailable source=orders message_type=payment.requested.v1
payments | 2026/05/01 13:02:11 KAFKA DLQ OK: topic=authz.dlq.payments.requested reason=invalid_signature source=orders message_type=payment.requested.v1
payments | 2026/05/01 13:02:11 NATS DLQ OK: subject=authz.dlq.payments.requested reason=invalid_signature source=orders message_type=payment.requested.v1
```

Сценарии missing signature и payload mismatch дополнительно закреплены unit-тестами пакетов signing/adapters; runtime smoke в этом наборе покрывает invalid signature и policy unavailable.
