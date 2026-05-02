# Сводка архитектуры

Этот документ кратко описывает финальную архитектуру `authz-system` для использования в диссертации и презентации.

## Цель

Проект реализует транспортно-независимую систему централизованной авторизации межсервисного взаимодействия. Один и тот же модуль ядра защищает синхронные и асинхронные пути взаимодействия без встраивания логики конкретного транспорта в механизм проверки политик.

Поддерживаемые транспорты:

- gRPC;
- HTTP/REST;
- Kafka;
- NATS.

## Ядро авторизации

Ядро находится в `internal/authz`.

Ответственность ядра:

- определять общую модель `AuthzRequest`;
- нормализовать устаревшие gRPC-правила и запросы разных транспортов;
- обрабатывать решения, возвращаемые `policy-server`;
- кэшировать решения с ключами, учитывающими транспорт;
- обеспечивать запрет при отказе при `FailOpen=false`;
- экспортировать метрики Prometheus.

Общие поля запроса:

- `source`;
- `target`;
- `transport`;
- `operation`;
- `resource`;
- `broker`;
- `message_type`.

Ядро не зависит от Kafka, NATS, внутреннего устройства HTTP-маршрутизации или gRPC protobuf-описаний.

## Сервер политик

`policy-server` является централизованной точкой принятия решений.

Ответственность:

- загружать YAML-правила политик из файлового источника или централизованного PostgreSQL-хранилища;
- предоставлять `/v1/check` для принятия решений авторизации;
- предоставлять `/v1/policies/reload` для динамической перезагрузки;
- записывать события журнала аудита для административных операций перезагрузки;
- экспортировать метрики Prometheus;
- применять запрет по умолчанию через порядок правил.

В production-like конфигурации Docker Compose активная версия политики хранится в PostgreSQL (`policy-store`). Таблица `policy_active` содержит единственную активную версию, а все три экземпляра `policy-server` периодически синхронизируются с ней. При временной недоступности PostgreSQL реплика продолжает использовать последнюю успешно загруженную политику и сообщает `sync_status=stale` в `/v1/health`. Файловый режим сохранен как локальный режим совместимости.

Startup seed выполняется из `POLICY_FILE`, если централизованное хранилище еще не содержит активной версии. Reload в PostgreSQL mode создает новую версию в `policy_versions`, активирует ее через `policy_active`, а rollback повторно активирует выбранную предыдущую версию. Подробная схема описана в `docs/policy-store.md`.

В окружении Docker Compose запускаются три экземпляра `policy-server`: `policy-server-1`, `policy-server-2` и `policy-server-3`. Клиенты получают список endpoint-ов через `POLICY_URLS` и переключаются между репликами при ошибках доступности.

## Модуль gRPC

Модуль gRPC находится в `internal/authz/grpcadapter` и реализован как перехватчики одиночных и потоковых вызовов.

Поток выполнения:

1. Извлечь идентификатор вызывающей службы из mTLS.
2. Прочитать полное имя gRPC-метода.
3. Построить `AuthzRequest` с `transport=grpc`.
4. Вызвать общий модуль проверки авторизации.
5. Разрешить обработчик или вернуть `PermissionDenied`.

Устаревшие правила с полем `rpc` сохранены для обратной совместимости.

## Модуль REST

Модуль REST находится в `internal/authz/httpadapter` и реализован как промежуточный HTTP-обработчик.

Поток выполнения:

1. Извлечь идентификатор вызывающей службы из mTLS.
2. Нормализовать путь маршрута без параметров запроса.
3. Использовать HTTP-метод как `operation`.
4. Построить `AuthzRequest` с `transport=http`.
5. Разрешить обработчик или вернуть `403 Forbidden`.

Защищаемые маршруты:

- `POST /payments/charge`;
- `POST /payments/refund`.

## Слой обмена сообщениями

Общий слой обмена сообщениями задает границы авторизации для публикации и обработки сообщений.

Общие поля асинхронного взаимодействия:

- служба-источник;
- целевая логическая служба;
- имя брокера сообщений;
- операция: `publish` или `consume`;
- ресурс: topic, subject или queue;
- тип сообщения.

Этот слой позволяет модулям Kafka и NATS нормализовать сообщения в ту же модель ядра.

## Модуль Kafka

Модуль Kafka защищает:

- публикацию сообщения;
- обработку сообщения.

Поток выполнения:

1. `orders` публикует `payment.requested.v1` в topic `payments.requested`.
2. `payments` читает сообщение.
3. Публикация и обработка сообщения выполняют проверки авторизации.

Служебные заголовки сообщений:

- `X-Service-Name`;
- `X-Message-Type`.

## Модуль NATS

Модуль NATS реализует тот же договор для NATS subjects.

Поток выполнения:

1. `orders` публикует `payment.requested.v1` в subject `payments.requested`.
2. `payments` получает сообщение и выполняет авторизацию перед обработкой.
3. Запрещенная публикация в `payments.refund.forced` блокируется.

Это подтверждает, что слой обмена сообщениями может поддерживать несколько брокеров без изменения логики ядра.

## Криптографическая идентификация сообщений

Kafka и NATS сообщения подписываются HMAC-SHA256 до отправки. Подпись покрывает broker, topic/subject, source service, message type, timestamp и SHA-256 полезной нагрузки. Consumer проверяет подпись до нормализации `BrokerInteraction` и до обращения к `policy-server`.

Сообщения с отсутствующей подписью, неизвестным ключом службы, неверным hash полезной нагрузки или timestamp вне допустимого окна отклоняются без обработки. Это устраняет доверие к служебным заголовкам как к неподтвержденному источнику идентичности.

## Надежность асинхронной обработки

Для Kafka и NATS добавлен общий слой надежности обработки сообщений:

- terminal errors отправляются в dead-letter resource;
- временная недоступность политик и ошибки обработчика повторяются с backoff;
- после исчерпания повторов сообщение отправляется в DLQ;
- успешный путь обработки не меняется.

Kafka использует DLQ topic вида `authz.dlq.<topic>` и подтверждает исходный offset только после успешной обработки или успешной публикации в DLQ. Если DLQ publish завершается ошибкой, offset не подтверждается.

NATS использует DLQ subject вида `authz.dlq.<subject>` и локальные повторы, так как обычный NATS без JetStream не предоставляет полноценный механизм explicit ack/requeue.

## Кэш решений

Кэш решений является частью ядра.

Поля ключа кэша:

- source;
- target;
- transport;
- operation;
- resource;
- broker;
- message type.

Кэш различает gRPC, REST, Kafka и NATS взаимодействия. Дефект fail-open-through-cache исправлен: попадания разрешающих решений в кэш все равно проверяют готовность `policy-server` через прикладной health check при `FailOpen=false`. При нескольких экземплярах достаточно одного готового `policy-server`; если все экземпляры недоступны, запрос запрещается.

## Запрет при отказе

При `FailOpen=false` недоступность всех настроенных экземпляров `policy-server` приводит к запрету. Клиент авторизации поддерживает три endpoint-а, хранит circuit breaker/backoff отдельно для каждого экземпляра и переключается на следующий экземпляр при транспортной ошибке или неготовности текущего.

Подтвержденные случаи:

- gRPC-запрос блокируется;
- REST-запрос блокируется;
- публикация в Kafka блокируется;
- обработка сообщения Kafka блокируется;
- публикация в NATS блокируется;
- обработка сообщения NATS блокируется.

Метрика:

- `authz_fail_closed_total`.

## Наблюдаемость

Метрики:

- `authz_checks_total{result,transport,broker}`;
- `authz_protected_operations_total{transport,broker,result}`;
- `authz_cache_total{type,transport,broker}`;
- `authz_policy_check_latency_seconds{transport,broker}`;
- `authz_fail_closed_total`;
- `authz_policy_circuit_transitions_total{state}`;
- `authz_policy_availability_state`;
- `authz_policy_failover_total`;
- `authz_policy_endpoint_requests_total{endpoint,result}`;
- `authz_policy_endpoint_health_total{endpoint,result}`;
- `authz_policy_endpoint_availability_state{endpoint}`;
- `authz_message_signed_total{broker}`;
- `authz_message_signature_checks_total{broker,result}`;
- `authz_message_signature_failures_total{broker,reason}`;
- `authz_broker_message_processing_total{broker,result}`;
- `authz_broker_messages_retried_total{broker,reason}`;
- `authz_broker_messages_deadlettered_total{broker,reason}`;
- `authz_broker_dlq_publish_errors_total{broker}`;
- `authz_broker_consume_errors_total{broker,reason}`;
- `policy_decisions_total{result}`;
- `policy_check_requests_total{result}`;
- `policy_check_duration_seconds`;
- `policy_match_latency_seconds`;
- `policy_reload_total{result}`;
- `policy_reload_duration_seconds`;
- `policy_rules_total`;
- `policy_index_buckets_total`.

Средства наблюдения:

- Prometheus;
- Grafana;
- журнал аудита перезагрузки политик;
- OpenTelemetry-трассировка ключевого пути авторизации.

Трассировка выключена по умолчанию и включается через `OTEL_ENABLED=true`. Поддержаны stdout exporter и OTLP exporter. Spans покрывают транспортный модуль, `Authorizer`, кэш, policy client, `policy-server`, сопоставление правил, проверку подписи сообщений, retry и DLQ. В атрибуты не попадают полезная нагрузка, секреты, подписи, topic/subject, message type, source/target и номера правил.

## Архитектурные свойства

Подтвержденные свойства:

- централизованная точка принятия решений авторизации;
- транспортно-независимая модель запроса в ядре;
- единая модель политик для синхронных и асинхронных взаимодействий;
- расширяемая модель транспортных модулей;
- поддержка нескольких брокеров сообщений;
- криптографическая проверка идентичности Kafka/NATS сообщений;
- retry и dead-letter поведение для асинхронных сообщений;
- динамическая перезагрузка политик;
- запрет при отказе;
- кэширование решений;
- воспроизводимое окружение Docker;
- воспроизводимые сценарии функциональных и нагрузочных экспериментов.
