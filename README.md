# AuthZ System: транспортно-независимый фреймворк авторизации межсервисного взаимодействия

`authz-system` - экспериментальный фреймворк централизованной авторизации межсервисного взаимодействия в микросервисных системах. Проект подготовлен как инженерный артефакт для магистерского исследования.

Фреймворк предоставляет единую транспортно-независимую модель авторизации и набор транспортных адаптеров:

- gRPC unary/stream-перехватчики;
- HTTP/REST middleware;
- общий слой авторизации для брокеров сообщений;
- адаптер Kafka;
- адаптер NATS.

Система следует принципам Zero Trust и default deny: каждое защищаемое взаимодействие нормализуется в общий запрос авторизации, проверяется централизованным `policy-server` и блокируется, если `policy-server` недоступен при `FailOpen=false`.

## Архитектура

Основные компоненты:

- `internal/authz` - ядро фреймворка: модель запроса, сопоставление политик, кэш решений, authorizer, метрики и поведение fail-closed.
- `internal/authz/grpcadapter` - gRPC unary/stream-перехватчики поверх core authorizer.
- `internal/authz/httpadapter` - HTTP/REST middleware и нормализация маршрутов поверх core authorizer.
- `internal/authz/kafkaadapter` - Kafka-specific адаптер publish/consume поверх общего broker layer.
- `internal/authz/natsadapter` - NATS-specific адаптер publish/consume поверх общего broker layer.
- `policy-server` - централизованный сервис, который загружает YAML policies, предоставляет `/v1/check`, поддерживает reload, audit и Prometheus metrics.
- `services/orders` - demo client service и CLI driver для gRPC, REST, Kafka и NATS вызовов.
- `services/payments` - защищаемый demo service со сценариями gRPC, REST, Kafka consumer и NATS subscriber.
- `deploy` - Docker Compose окружение с policy-server, demo services, Kafka, NATS, Prometheus и Grafana.
- `scripts` - воспроизводимые функциональные, degradation, chaos и benchmark сценарии.
- `results` - сгенерированные экспериментальные артефакты и итоговые сводки.

Форма запроса ядра:

```yaml
source: orders
target: payments
transport: grpc | http | broker
operation: <rpc method | HTTP method | publish | consume>
resource: <rpc wildcard | normalized route | topic/subject>
broker: <kafka | nats | *>
message_type: <event type | *>
```

Устаревшее gRPC-поле `rpc` по-прежнему поддерживается и нормализуется так:

```yaml
transport: grpc
operation: <rpc>
resource: "*"
```

## Модель политик

Политики загружаются из `policies/policies.yaml`.

Примеры правил:

```yaml
- id: R1
  source: orders
  target: payments
  rpc: /payments.v1.Payments/Charge
  effect: allow

- id: R_HTTP_1
  source: orders
  target: payments
  transport: http
  operation: POST
  resource: /payments/charge
  effect: allow

- id: R_KAFKA_1
  source: orders
  target: payments
  transport: broker
  broker: kafka
  operation: publish
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R_NATS_1
  source: orders
  target: payments
  transport: broker
  broker: nats
  operation: publish
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R3
  source: "*"
  target: "*"
  transport: "*"
  operation: "*"
  resource: "*"
  effect: deny
```

Сопоставление выполняется по принципу first match, поэтому финальное wildcard deny rule реализует default deny.

Для broker demo metadata сообщений использует:

- `X-Service-Name` - service identity отправителя в demo message contract;
- `X-Message-Type` - тип события.

Это demo transport contract. В production identity для broker traffic должна быть привязана к broker authentication, mTLS/SASL, message signatures или другому криптографически защищенному механизму.

## Требования

- Docker;
- Docker Compose v2;
- OpenSSL;
- Go 1.24 для локальной сборки и тестов.

## Воспроизводимость

Demo environment использует закрепленные версии infrastructure images:

- `apache/kafka:4.2.0`;
- `nats:2.10.29`;
- `prom/prometheus:v2.55.0`;
- `grafana/grafana:11.2.0`.

Dockerfile-ы приложений используют `golang:1.24.11-alpine3.22` для сборки и `alpine:3.22.2` для runtime images. Сгенерированные protobuf Go files уже закоммичены, поэтому Docker builds не устанавливают плавающие версии `protoc` generators.

Сгенерированные certificates, audit data и experiment outputs являются локальными runtime artifacts и не коммитятся. Audit file policy-server хранится в Docker named volume и читается через `make -C deploy audit`.

## Быстрый старт

Минимальный путь после чистого clone:

```bash
cd authz-system
make -C deploy certs
make -C deploy up
make -C deploy test-all
make -C deploy status
```

Сгенерировать локальные demo certificates:

```bash
make -C deploy certs
```

Поднять полное окружение:

```bash
make -C deploy up
```

Команда запускает:

- `policy-server`;
- `payments`;
- `orders`;
- Apache Kafka;
- инициализацию Kafka topics для demo-сценариев;
- NATS;
- Prometheus;
- Grafana.

Показать service URLs:

```bash
make -C deploy status
```

Makefile вычисляет project paths относительно собственного расположения, поэтому команды вида `make -C deploy ...` можно запускать из repository root без дополнительных environment variables.

## Базовые функциональные проверки

Запустить demo для всех транспортов:

```bash
make -C deploy test-all
```

Или запустить отдельно:

```bash
make -C deploy test-grpc
make -C deploy test-rest
make -C deploy test-kafka
make -C deploy test-nats
```

Ожидаемое поведение:

- gRPC `Charge` разрешен;
- gRPC `Refund` запрещен;
- REST `POST /payments/charge` разрешен;
- REST `POST /payments/refund` запрещен;
- Kafka publish и consume события `payment.requested.v1` разрешены;
- Kafka forbidden publish `payment.refund.forced.v1` запрещен;
- NATS publish и consume события `payment.requested.v1` разрешены;
- NATS forbidden publish `payment.refund.forced.v1` запрещен.

## Reload, audit и fail-closed

Перезагрузить policies без перезапуска services:

```bash
make -C deploy reload
```

Посмотреть audit log:

```bash
make -C deploy audit
```

Запустить fail-closed degradation checks:

```bash
make -C deploy degrade-all
```

Отдельные degradation targets:

```bash
make -C deploy degrade-test
make -C deploy degrade-rest-test
make -C deploy degrade-kafka-test
make -C deploy degrade-kafka-consume-test
make -C deploy degrade-nats-test
make -C deploy degrade-nats-consume-test
```

Эти проверки останавливают `policy-server` и подтверждают, что разрешенные interaction paths блокируются, пока `policy-server` недоступен.

## Chaos и нагрузочные сценарии

Reload loop:

```bash
make -C deploy chaos-reload
```

Policy-server flap:

```bash
make -C deploy chaos-policy-flap
```

gRPC load test:

```bash
make -C deploy load
make -C deploy load-deny
make -C deploy load-matrix
```

Legacy `docker exec` benchmark:

```bash
make -C deploy bench
```

## Финальные воспроизводимые эксперименты

Функциональная матрица для gRPC, REST, Kafka и NATS:

```bash
make -C deploy final-functional
```

Сравнительный latency/throughput benchmark:

```bash
make -C deploy final-bench
```

Полный final suite:

```bash
make -C deploy final-suite
```

Короткий benchmark smoke:

```bash
FINAL_N=100 FINAL_C=10 FINAL_WARMUP=10 make -C deploy final-bench
```

Более крупный benchmark для диссертации:

```bash
FINAL_N=1000 FINAL_C=50 FINAL_WARMUP=100 make -C deploy final-bench
```

Сгенерированные artifacts сохраняются в:

```text
results/final/<timestamp>/functional/
results/final/<timestamp>/bench/
```

Дополнительные outputs load/degrade helper-скриптов сохраняются в `results/load/` и `results/degrade/`, если используются standalone scripts.

Основные artifacts:

- `summary.csv` - functional allow/deny/reload/degrade matrix;
- `bench_summary.csv` - latency и throughput по transports;
- `payments_metrics_*.prom` - snapshots authz metrics;
- `policy_metrics_*.prom` - snapshots policy-server metrics;
- `audit_*.log` - evidence для policy reload audit;
- `docker_*.log` - service logs для async consume и fail-closed evidence.

## Метрики

Prometheus:

```text
http://localhost:9091
```

Payments metrics:

```text
http://localhost:9090/metrics
```

Ключевые metrics:

- `authz_checks_total{result,transport,broker}` - authorization decisions на framework edge;
- `authz_cache_total{type,transport,broker}` - decision cache hit/miss;
- `authz_policy_check_latency_seconds{transport,broker}` - latency policy check;
- `authz_fail_closed_total` - fail-closed denials;
- `policy_decisions_total{result}` - decisions на policy-server.

Grafana:

```text
http://localhost:3000
```

Demo credentials по умолчанию:

```text
admin / admin
```

## Подтвержденные свойства

- централизованные policy decisions через `policy-server`;
- транспортно-независимая модель authorization request;
- поддержка синхронных transports: gRPC и REST;
- поддержка асинхронных broker transports: Kafka и NATS;
- расширяемая граница broker adapter;
- dynamic YAML policy reload без перезапуска service;
- audit trail для administrative reload operations;
- decision cache с transport/broker-aware keys;
- fail-closed behavior при недоступности `policy-server`;
- Prometheus metrics для decisions, cache, latency и fail-closed denials.

## Исследовательские заметки

Архитектурная сводка для диссертации и презентации:

```text
docs/architecture-summary.md
```

Сводка экспериментов:

```text
results/summary.md
```

## Заметки по безопасности

- Demo certificates генерируются локально и игнорируются git.
- Administrative token является demo-only.
- REST и gRPC demo identity используют mTLS.
- Broker demo identity использует message headers для воспроизводимости; в production deployments message identity должна быть связана с broker-level или cryptographic authentication.
