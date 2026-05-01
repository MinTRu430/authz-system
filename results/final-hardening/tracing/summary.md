# OpenTelemetry smoke

Tracing включался точечно для контейнера `orders`:

```bash
docker exec -e OTEL_ENABLED=true -e OTEL_EXPORTER=stdout orders /app/orders charge
docker exec -e OTEL_ENABLED=true -e OTEL_EXPORTER=stdout orders /app/orders rest-charge
docker exec -e OTEL_ENABLED=true -e OTEL_EXPORTER=stdout orders /app/orders kafka-publish
docker exec -e OTEL_ENABLED=true -e OTEL_EXPORTER=stdout orders /app/orders nats-publish
```

Результат: успешно.

Зафиксированные span names:

- `transport.grpc.client`;
- `transport.http.client`;
- `broker.publish.authorize`;
- `authz.authorize`;
- `authz.cache.get`;
- `authz.policy.check`.

Проверенные атрибуты:

- `authz.transport`;
- `authz.broker`;
- `authz.result`;
- `authz.cache_hit`;
- `authz.policy_endpoint_index`;
- `broker.name`;
- `broker.operation`.

В stdout spans не попадали payload, секреты, HMAC-подписи, topic/subject, message type, source/target и raw URL.

Kafka/NATS trace context propagation через headers намеренно не включался в этом этапе, чтобы не менять HMAC canonical contract.
