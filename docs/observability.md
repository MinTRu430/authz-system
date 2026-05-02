# Наблюдаемость

Проект собирает метрики на двух уровнях:

- на границе защищаемых служб, где работают адаптеры gRPC, REST, Kafka и NATS;
- внутри `policy-server`, где выполняются загрузка политик, сопоставление правил и принятие решений.

## Метки

Используются только низкокардинальные метки:

- `transport`: `grpc`, `http`, `broker`;
- `broker`: `kafka`, `nats`, `none`;
- `result`: `allow`, `deny`, `unavailable`, `ok`, `fail`, `error`;
- `reason`: фиксированные причины отказа, повтора или DLQ;
- `endpoint`: индекс экземпляра `policy-server`, например `0` или `1`.

В метки намеренно не добавляются адреса, темы Kafka, subject NATS, типы сообщений, имена служб, номера правил и версии политик. Это сохраняет предсказуемый объем временных рядов.

## Авторизация на границе служб

- `authz_checks_total{result,transport,broker}` показывает итоговые решения адаптеров.
- `authz_protected_operations_total{transport,broker,result}` удобно использовать как общий счетчик защищенных операций в сравнительных экспериментах.
- `authz_policy_check_latency_seconds{transport,broker}` измеряет задержку обращения адаптера к `policy-server`.
- `authz_fail_closed_total` фиксирует блокировки из-за недоступности `policy-server`.

Для оценки влияния централизованной проверки полезно сравнивать `authz_policy_check_latency_seconds` между `grpc`, `http`, `broker/kafka` и `broker/nats`.

## Кэш решений

- `authz_cache_total{type,transport,broker}` считает `hit` и `miss`.

Для анализа эффективности кэша используется отношение `hit / (hit + miss)` отдельно по транспорту и брокеру.

## Доступность policy-server и переключение между экземплярами

- `authz_policy_health_checks_total{result}` считает прикладные проверки `/v1/health`.
- `authz_policy_availability_state` показывает агрегированное состояние доступности: `1` - доступен, `0` - недоступен.
- `authz_policy_circuit_transitions_total{state}` показывает переходы circuit breaker.
- `authz_policy_failover_total` считает попытки переключения между экземплярами.
- `authz_policy_endpoint_requests_total{endpoint,result}` показывает результат `/v1/check` по каждому экземпляру.
- `authz_policy_endpoint_health_total{endpoint,result}` показывает результат `/v1/health` по каждому экземпляру.
- `authz_policy_endpoint_availability_state{endpoint}` показывает состояние каждого экземпляра по индексу.

Эти метрики нужны для сценариев отказа одного или двух экземпляров и полного отказа всех экземпляров. Если часть реплик недоступна, но хотя бы один `policy-server` отвечает, `authz_policy_failover_total` растет, а `authz_fail_closed_total` не должен расти на разрешенных запросах.

## Метрики policy-server

- `policy_decisions_total{result}` считает решения `policy-server`.
- `policy_check_requests_total{result}` считает HTTP-запросы `/v1/check`.
- `policy_check_duration_seconds` измеряет полную задержку обработки `/v1/check`.
- `policy_match_latency_seconds` измеряет только сопоставление правил.
- `policy_rules_total` показывает число активных правил.
- `policy_index_buckets_total` показывает число корзин индексированного сопоставления.
- `policy_reload_total{result}` считает успешные и неуспешные перезагрузки политик.
- `policy_reload_duration_seconds` измеряет длительность перезагрузки.
- `policy_store_sync_total{result}` считает попытки синхронизации с централизованным хранилищем.
- `policy_store_sync_duration_seconds` измеряет длительность синхронизации.
- `policy_store_db_errors_total{operation}` считает ошибки обращения к PostgreSQL по типу операции.
- `policy_store_last_sync_timestamp_seconds` показывает время последней попытки синхронизации.
- `policy_replica_in_sync` показывает, находится ли реплика в синхронизированном состоянии.

В нормальном состоянии `policy_replica_in_sync` должен быть равен `1` на каждой реплике. При временной недоступности PostgreSQL реплика продолжает обслуживать last-known-good policy, но `policy_replica_in_sync` переходит в `0`, а `policy_store_sync_total{result="stale"}` и `policy_store_db_errors_total{operation="load_active"}` растут.

Для оценки индекса полезно сравнивать `policy_check_duration_seconds` и `policy_match_latency_seconds`: первая метрика включает HTTP, разбор запроса и кодирование ответа, вторая отражает только поиск правила.

## Подпись сообщений Kafka/NATS

- `authz_message_signed_total{broker}` считает подписанные сообщения.
- `authz_message_signature_checks_total{broker,result}` считает проверки подписи.
- `authz_message_signature_failures_total{broker,reason}` показывает причины отклонения.

При подделке заголовков или полезной нагрузки должна расти метрика отказов подписи, а `policy-server` не должен получать запрос авторизации по такому сообщению.

## Повторы и DLQ

- `authz_broker_message_processing_total{broker,result}` показывает итог обработки сообщения.
- `authz_broker_messages_retried_total{broker,reason}` считает повторы.
- `authz_broker_messages_deadlettered_total{broker,reason}` считает сообщения, отправленные в DLQ.
- `authz_broker_dlq_publish_errors_total{broker}` показывает ошибки публикации в DLQ.
- `authz_broker_consume_errors_total{broker,reason}` считает ошибки потребления.

Терминальные ошибки, например неверная подпись или запрет политики, должны приводить к DLQ. Временная недоступность `policy-server` сначала приводит к повторам, затем к DLQ после исчерпания лимита.

## Быстрая проверка

```bash
curl -s http://localhost:9090/metrics | grep -E 'authz_'
curl -sk https://localhost:8443/metrics | grep -E 'policy_'
curl -sk https://localhost:8444/metrics | grep -E 'policy_'
curl -sk https://localhost:8445/metrics | grep -E 'policy_'
curl -s http://localhost:9091/api/v1/targets
```

В Docker Compose Prometheus скрейпит `policy-server` через mTLS. Для этого в контейнер монтируется каталог `certs/` в режиме `read-only`, а сам контейнер запускается с правами, достаточными для чтения локальных ключей с режимом `0600`.

Для `policy-server` используется mTLS. Если нужен прикладной health check снаружи:

```bash
curl -sk https://localhost:8443/v1/health --cert certs/orders.pem --key certs/orders-key.pem --cacert certs/ca.pem
curl -sk https://localhost:8444/v1/health --cert certs/orders.pem --key certs/orders-key.pem --cacert certs/ca.pem
curl -sk https://localhost:8445/v1/health --cert certs/orders.pem --key certs/orders-key.pem --cacert certs/ca.pem
```

## Трассировка OpenTelemetry

Трассировка добавлена как необязательный слой наблюдаемости. По умолчанию она выключена, поэтому обычный запуск и проверки не требуют коллектора.

Включить stdout exporter:

```bash
OTEL_ENABLED=true OTEL_EXPORTER=stdout make -C deploy up
make -C deploy test-all
docker compose -f deploy/docker-compose.yml logs payments policy-server-1 policy-server-2 policy-server-3 orders
```

Подключить OTLP endpoint:

```bash
OTEL_ENABLED=true OTEL_EXPORTER=otlp OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4317 make -C deploy up
```

Поддерживаемые переменные:

- `OTEL_ENABLED=true|false`;
- `OTEL_SERVICE_NAME`;
- `OTEL_EXPORTER=stdout|otlp|none`;
- `OTEL_EXPORTER_OTLP_ENDPOINT`;
- `OTEL_EXPORTER_OTLP_INSECURE=true|false`.

Ключевые spans:

- `transport.grpc.authorize` и `transport.http.authorize` - вход в транспортный модуль;
- `authz.authorize` - общий путь авторизации;
- `authz.cache.get` - проверка кэша решений;
- `authz.policy.check` - запрос к `policy-server`;
- `authz.policy.health` - прикладная проверка готовности `policy-server`;
- `authz.fail_closed` - запрет при отказе;
- `policy_server.check` - обработка `/v1/check`;
- `policy_server.match` - сопоставление правил;
- `policy_server.reload` - перезагрузка политики;
- `policy_server.health` - обработка `/v1/health`;
- `broker.publish.authorize` - авторизация публикации Kafka/NATS;
- `broker.consume.verify_signature` - проверка подписи сообщения;
- `broker.consume.authorize` - авторизация обработки сообщения;
- `broker.consume.retry` - повтор обработки;
- `broker.consume.dead_letter` - отправка в DLQ.

Безопасные атрибуты:

- `authz.transport`;
- `authz.broker`;
- `authz.result`;
- `authz.cache_hit`;
- `authz.policy_endpoint_index`;
- `authz.fail_closed`;
- `broker.name`;
- `broker.operation`;
- `broker.signature_result`;
- `broker.retry_count`;
- `broker.dlq`;
- `policy.result`;
- `policy.rules_count`;
- `policy.index_buckets`;
- `policy.reload_result`.

В трассы намеренно не пишутся payload, секреты, подписи, полный URL, topic/subject, message type, source service, target service, rule id и версия политики. Kafka/NATS trace context через заголовки сообщений пока не распространяется: текущий HMAC-контракт не подписывает `traceparent`, поэтому доверять такому контексту как части защищенной идентичности нельзя. Это можно расширить отдельно, если trace context будет включен в подписываемую каноническую строку.
