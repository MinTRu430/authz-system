# Сводка архитектуры

Этот документ кратко описывает финальную архитектуру `authz-system` для использования в диссертации и презентации.

## Цель

Проект реализует транспортно-независимый фреймворк централизованной авторизации межсервисного взаимодействия. Он показывает, что один и тот же authorization core может защищать синхронные и асинхронные interaction paths без встраивания transport-specific логики в policy engine.

Поддерживаемые транспорты:

- gRPC;
- HTTP/REST;
- Kafka;
- NATS.

## Core authorization layer

Ядро фреймворка находится в `internal/authz`.

Ответственность core:

- определять общую модель `AuthzRequest`;
- нормализовать legacy gRPC rules и transport-specific requests;
- обрабатывать policy decisions, возвращаемые `policy-server`;
- кэшировать решения с transport-aware keys;
- обеспечивать fail-closed behavior при `FailOpen=false`;
- экспортировать Prometheus metrics.

Общие поля request:

- `source`;
- `target`;
- `transport`;
- `operation`;
- `resource`;
- `broker`;
- `message_type`.

Core не зависит от Kafka, NATS, HTTP routing internals или gRPC protobuf definitions.

## Policy Server

`policy-server` является централизованной точкой принятия решений.

Ответственность:

- загружать YAML policy rules;
- предоставлять `/v1/check` для authorization decisions;
- предоставлять `/v1/policies/reload` для dynamic reload;
- записывать audit events для administrative reload operations;
- экспортировать Prometheus metrics;
- применять default-deny semantics через порядок policies.

Policies монтируются в Docker Compose как directory, поэтому reload видит изменения файлов без перезапуска container.

## gRPC Adapter

gRPC adapter находится в `internal/authz/grpcadapter` и реализован как unary и stream interceptors.

Поток выполнения:

1. Извлечь caller service identity из mTLS.
2. Прочитать full gRPC method name.
3. Построить `AuthzRequest` с `transport=grpc`.
4. Вызвать core authorizer.
5. Разрешить handler или вернуть `PermissionDenied`.

Legacy `rpc` policy rules сохранены для backward compatibility.

## REST Adapter

REST adapter находится в `internal/authz/httpadapter` и реализован как HTTP middleware.

Поток выполнения:

1. Извлечь caller service identity из mTLS.
2. Нормализовать route path без query parameters.
3. Использовать HTTP method как `operation`.
4. Построить `AuthzRequest` с `transport=http`.
5. Разрешить handler или вернуть `403 Forbidden`.

Demo endpoints:

- `POST /payments/charge`;
- `POST /payments/refund`.

## Broker abstraction layer

Generic broker layer определяет authorization boundaries для publish/consume.

Общие поля async interaction:

- source service;
- target logical service;
- broker name;
- operation: `publish` или `consume`;
- resource: topic, subject или queue;
- message type.

Этот слой позволяет broker-specific adapters нормализовать сообщения в ту же core model.

## Kafka Adapter

Kafka adapter защищает:

- producer publish;
- consumer processing.

Demo flow:

1. `orders` публикует `payment.requested.v1` в topic `payments.requested`.
2. `payments` consume-ит сообщение.
3. Publish и consume оба выполняют authorization checks.

Demo metadata headers:

- `X-Service-Name`;
- `X-Message-Type`.

## NATS Adapter

NATS adapter реализует тот же broker contract для NATS subjects.

Demo flow:

1. `orders` публикует `payment.requested.v1` в subject `payments.requested`.
2. `payments` получает сообщение и выполняет authorization перед обработкой.
3. Запрещенный publish в `payments.refund.forced` блокируется.

Это подтверждает, что broker abstraction может поддерживать несколько brokers без изменения core logic.

## Cache

Decision cache является частью framework core.

Поля cache key:

- source;
- target;
- transport;
- operation;
- resource;
- broker;
- message type.

Cache различает gRPC, REST, Kafka и NATS interactions. Дефект fail-open-through-cache был исправлен: allow cache hits все равно проверяют доступность policy-server при `FailOpen=false`, поэтому недоступность policy-server приводит к fail-closed denial.

## Fail-Closed

При `FailOpen=false` любая недоступность policy-server приводит к denial.

Подтвержденные случаи:

- gRPC request blocked;
- REST request blocked;
- Kafka publish blocked;
- Kafka consume processing blocked;
- NATS publish blocked;
- NATS consume processing blocked.

Метрика:

- `authz_fail_closed_total`.

## Observability

Metrics:

- `authz_checks_total{result,transport,broker}`;
- `authz_cache_total{type,transport,broker}`;
- `authz_policy_check_latency_seconds{transport,broker}`;
- `authz_fail_closed_total`;
- `policy_decisions_total{result}`.

Monitoring stack:

- Prometheus;
- Grafana;
- policy reload audit log.

## Архитектурные свойства

Подтвержденные свойства:

- centralized authorization decision point;
- transport-agnostic core request model;
- reusable policy model для sync и async interactions;
- adapter-based extension model;
- поддержка нескольких brokers;
- dynamic policy reload;
- fail-closed safety;
- decision caching;
- воспроизводимый Docker demo environment;
- воспроизводимые functional и benchmark experiment scripts.
