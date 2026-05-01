# AuthZ System: транспортно-независимая система авторизации межсервисного взаимодействия

`authz-system` - экспериментальная система централизованной авторизации межсервисного взаимодействия в микросервисной среде. Проект подготовлен как инженерный артефакт для магистерского исследования.

Система предоставляет единую транспортно-независимую модель авторизации и набор модулей подключения:

- перехватчики gRPC для одиночных и потоковых вызовов;
- промежуточный обработчик HTTP/REST;
- общий слой авторизации для обмена сообщениями;
- модуль Kafka;
- модуль NATS.

Система следует принципам Zero Trust и запрета по умолчанию: каждое защищаемое взаимодействие нормализуется в общий запрос авторизации, проверяется централизованным сервером политик `policy-server` и блокируется, если все настроенные экземпляры `policy-server` недоступны при `FailOpen=false`.

## Архитектура

Основные компоненты:

- `internal/authz` - ядро: модель запроса, сопоставление политик, кэш решений, проверка авторизации, метрики и поведение запрета при отказе.
- `internal/authz/grpcadapter` - перехватчики gRPC поверх общего ядра авторизации.
- `internal/authz/httpadapter` - промежуточный обработчик HTTP/REST и нормализация маршрутов поверх общего ядра авторизации.
- `internal/authz/kafkaadapter` - модуль Kafka для проверки публикации и обработки сообщений через общий слой обмена сообщениями.
- `internal/authz/natsadapter` - модуль NATS для проверки публикации и обработки сообщений через общий слой обмена сообщениями.
- `policy-server` - централизованная служба, которая загружает YAML-политики, предоставляет `/v1/check` и `/v1/health`, поддерживает перезагрузку политик, журнал аудита и метрики Prometheus.
- `services/orders` - клиентская служба и командный интерфейс для gRPC, REST, Kafka и NATS вызовов.
- `services/payments` - защищаемая служба со сценариями gRPC, REST, обработчиком Kafka и подписчиком NATS.
- `deploy` - окружение Docker Compose с двумя экземплярами `policy-server`, службами, Kafka, NATS, Prometheus и Grafana.
- `scripts` - воспроизводимые сценарии функциональной проверки, отказов, хаоса и нагрузки.
- `results` - сгенерированные экспериментальные артефакты и итоговые сводки.

Форма запроса авторизации в ядре:

```yaml
source: orders
target: payments
transport: grpc | http | broker
operation: <rpc-метод | HTTP-метод | publish | consume>
resource: <wildcard rpc | нормализованный маршрут | topic/subject>
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

Сопоставление выполняется по принципу первого подходящего правила, поэтому финальное wildcard-правило с `effect: deny` реализует запрет по умолчанию.

Для сообщений через Kafka и NATS используются служебные заголовки и HMAC-подпись метаданных сообщения:

- `X-Service-Name` - имя службы-источника;
- `X-Message-Type` - тип события.
- `X-Authz-Signature-Version` - версия схемы подписи;
- `X-Authz-Timestamp` - время формирования подписи в формате Unix seconds;
- `X-Authz-Payload-SHA256` - SHA-256 полезной нагрузки;
- `X-Authz-Signature` - HMAC-SHA256 подпись в base64url.

Подписывается стабильная строка:

```text
v1
broker=<kafka|nats>
resource=<topic|subject>
source=<service>
message_type=<event-type>
timestamp=<unix-seconds>
payload_sha256=<lowercase-hex-sha256>
```

Получатель проверяет подпись, срок действия timestamp и hash полезной нагрузки до обращения к `policy-server`. Сообщения без подписи, с неверной подписью или с устаревшим timestamp не обрабатываются.

Переменные окружения для Kafka/NATS:

```text
AUTHZ_MESSAGE_SIGNING_MODE=required
AUTHZ_MESSAGE_SIGNING_SECRET=base64:<service-secret>
AUTHZ_MESSAGE_VERIFICATION_SECRETS=orders=base64:<orders-secret>,payments=base64:<payments-secret>
AUTHZ_MESSAGE_MAX_AGE=5m
AUTHZ_MESSAGE_FUTURE_SKEW=30s
```

Режим `disabled` оставлен только для узких тестовых сценариев. В составе Docker Compose подпись включена.

## Требования

- Docker;
- Docker Compose v2;
- OpenSSL;
- Go 1.24 для локальной сборки и тестов.

## Воспроизводимость

Окружение использует закрепленные версии инфраструктурных образов:

- `apache/kafka:4.2.0`;
- `nats:2.10.29`;
- `prom/prometheus:v2.55.0`;
- `grafana/grafana:11.2.0`.

Dockerfile-ы приложений используют `golang:1.24.11-alpine3.22` для сборки и `alpine:3.22.2` для runtime-образов. Сгенерированные protobuf-файлы Go уже закоммичены, поэтому Docker-сборки не устанавливают плавающие версии генераторов `protoc`.

Сгенерированные сертификаты, данные журнала аудита и результаты экспериментов являются локальными артефактами выполнения и не коммитятся. Журналы аудита экземпляров `policy-server` хранятся в именованных томах Docker и читаются через `make -C deploy audit` или `make -C deploy audit-all`.

## Быстрый старт

Минимальный путь после чистого клонирования репозитория:

```bash
cd authz-system
make -C deploy certs
make -C deploy up
make -C deploy test-all
make -C deploy status
```

Сгенерировать локальные сертификаты:

```bash
make -C deploy certs
```

Поднять полное окружение:

```bash
make -C deploy up
```

Команда запускает:

- `policy-server-1`;
- `policy-server-2`;
- `policy-server-3`;
- `payments`;
- `orders`;
- Apache Kafka;
- инициализацию тем Kafka;
- NATS;
- Prometheus;
- Grafana.

Показать адреса служб:

```bash
make -C deploy status
```

Makefile вычисляет пути проекта относительно собственного расположения, поэтому команды вида `make -C deploy ...` можно запускать из корня репозитория без дополнительных переменных окружения.

## Несколько экземпляров policy-server

Окружение Docker Compose поднимает три экземпляра:

- `policy-server-1` доступен с хоста на `https://localhost:8443`;
- `policy-server-2` доступен с хоста на `https://localhost:8444`;
- `policy-server-3` доступен с хоста на `https://localhost:8445`.

Службы используют переменную:

```text
POLICY_URLS=https://policy-server-1:8443,https://policy-server-2:8443,https://policy-server-3:8443
```

Для обратной совместимости сохраняется одиночный режим:

```text
POLICY_URL=https://policy-server-1:8443
```

Если `POLICY_URLS` задан, он имеет приоритет. Клиент авторизации пробует следующий экземпляр, если текущий недоступен; если все экземпляры недоступны, сохраняется запрет при отказе.

## Надежность обработки Kafka/NATS сообщений

Для Kafka и NATS включена обработка проблемных сообщений через retry и dead-letter.

Terminal errors отправляются в DLQ без вызова бизнес-обработчика:

- неверная или отсутствующая подпись сообщения;
- несовпадение hash полезной нагрузки;
- неизвестный ключ службы;
- запрет авторизации.

Transient errors повторяются локально с backoff:

- временная недоступность всех `policy-server`;
- ошибка бизнес-обработчика сообщения.

После исчерпания повторов сообщение отправляется в DLQ:

```text
authz.dlq.<topic|subject>
```

Основные настройки:

```text
BROKER_DLQ_ENABLED=true
BROKER_DLQ_PREFIX=authz.dlq
BROKER_MAX_RETRIES=3
BROKER_RETRY_BACKOFF=500ms
BROKER_DEAD_LETTER_ON_DENY=true
BROKER_DEAD_LETTER_ON_SIGNATURE_ERROR=true
```

Для Kafka исходное сообщение подтверждается только после успешной обработки или успешной публикации в DLQ. Если публикация в DLQ завершается ошибкой, offset не подтверждается. Для обычного NATS без JetStream используется локальный retry; полноценный broker-level ack/requeue оставлен для возможного перехода на JetStream.

## Базовые функциональные проверки

Запустить проверки для всех транспортов:

```bash
make -C deploy test-all
```

Или запустить отдельно:

```bash
make -C deploy test-grpc
make -C deploy test-rest
make -C deploy test-kafka
make -C deploy test-nats
make -C deploy test-dlq
```

Ожидаемое поведение:

- gRPC `Charge` разрешен;
- gRPC `Refund` запрещен;
- REST `POST /payments/charge` разрешен;
- REST `POST /payments/refund` запрещен;
- публикация и обработка события Kafka `payment.requested.v1` разрешены;
- запрещенная публикация Kafka `payment.refund.forced.v1` блокируется;
- публикация и обработка события NATS `payment.requested.v1` разрешены;
- запрещенная публикация NATS `payment.refund.forced.v1` блокируется.

## Перезагрузка политик, аудит и запрет при отказе

Перезагрузить политики без перезапуска служб:

```bash
make -C deploy reload
```

Посмотреть журнал аудита:

```bash
make -C deploy audit
```

Перезагрузить политики на всех экземплярах:

```bash
make -C deploy reload-all
```

Прочитать аудит всех экземпляров:

```bash
make -C deploy audit-all
```

Запустить проверки запрета при отказе:

```bash
make -C deploy degrade-all
```

Отдельные цели проверки отказов:

```bash
make -C deploy degrade-test
make -C deploy degrade-rest-test
make -C deploy degrade-kafka-test
make -C deploy degrade-kafka-consume-test
make -C deploy degrade-nats-test
make -C deploy degrade-nats-consume-test
```

Эти проверки останавливают все экземпляры `policy-server` и подтверждают, что ранее разрешенные пути взаимодействия блокируются, пока ни один экземпляр недоступен.

Проверить переключение между экземплярами:

```bash
make -C deploy failover
```

## Сценарии хаоса и нагрузки

Циклическая перезагрузка политик:

```bash
make -C deploy chaos-reload
```

Периодическая остановка и запуск `policy-server`:

```bash
make -C deploy chaos-policy-flap
```

Нагрузочная проверка gRPC:

```bash
make -C deploy load
make -C deploy load-deny
make -C deploy load-matrix
```

Измерение через `docker exec`:

```bash
make -C deploy bench
```

## Итоговые воспроизводимые эксперименты

Функциональная матрица для gRPC, REST, Kafka и NATS:

```bash
make -C deploy final-functional
```

Сравнительное измерение задержки и пропускной способности:

```bash
make -C deploy final-bench
```

Полный итоговый набор проверок:

```bash
make -C deploy final-suite
```

Короткая проверка измерений:

```bash
FINAL_N=100 FINAL_C=10 FINAL_WARMUP=10 make -C deploy final-bench
```

Более крупный прогон для диссертации:

```bash
FINAL_N=1000 FINAL_C=50 FINAL_WARMUP=100 make -C deploy final-bench
```

Сгенерированные артефакты сохраняются в:

```text
results/final/<timestamp>/functional/
results/final/<timestamp>/bench/
```

Дополнительные результаты вспомогательных скриптов нагрузки и отказов сохраняются в `results/load/` и `results/degrade/`.

Основные артефакты:

- `summary.csv` - матрица проверок разрешения, запрета, перезагрузки и отказов;
- `bench_summary.csv` - задержка и пропускная способность по транспортам;
- `payments_metrics_*.prom` - снимки метрик авторизации;
- `policy_metrics_*.prom` - снимки метрик `policy-server`;
- `audit_*.log` - подтверждение записей журнала аудита при перезагрузке политик;
- `docker_*.log` - журналы служб для проверки асинхронной обработки и запрета при отказе.

## Метрики

Prometheus:

```text
http://localhost:9091
```

Метрики `payments`:

```text
http://localhost:9090/metrics
```

Ключевые метрики:

- `authz_checks_total{result,transport,broker}` - решения авторизации на границе системы;
- `authz_protected_operations_total{transport,broker,result}` - защищенные операции по транспорту и результату;
- `authz_cache_total{type,transport,broker}` - попадания и промахи кэша решений;
- `authz_policy_check_latency_seconds{transport,broker}` - задержка проверки политики;
- `authz_fail_closed_total` - запреты из-за недоступности `policy-server`;
- `authz_policy_circuit_transitions_total{state}` - переходы состояния доступности `policy-server`;
- `authz_policy_availability_state` - текущее агрегированное состояние доступности `policy-server`;
- `authz_policy_failover_total` - переключения между экземплярами `policy-server`;
- `authz_policy_endpoint_requests_total{endpoint,result}` - обращения к экземплярам `policy-server`;
- `authz_policy_endpoint_health_total{endpoint,result}` - проверки готовности экземпляров `policy-server`;
- `authz_policy_endpoint_availability_state{endpoint}` - состояние готовности каждого экземпляра по индексу;
- `authz_message_signed_total{broker}` - подписанные сообщения Kafka/NATS;
- `authz_message_signature_checks_total{broker,result}` - проверки подписи сообщений;
- `authz_message_signature_failures_total{broker,reason}` - причины отклонения подписей;
- `authz_broker_message_processing_total{broker,result}` - результаты обработки сообщений;
- `authz_broker_messages_retried_total{broker,reason}` - повторы обработки;
- `authz_broker_messages_deadlettered_total{broker,reason}` - сообщения, отправленные в DLQ;
- `authz_broker_dlq_publish_errors_total{broker}` - ошибки публикации в DLQ;
- `authz_broker_consume_errors_total{broker,reason}` - ошибки потребления сообщений;
- `policy_decisions_total{result}` - решения на стороне `policy-server`;
- `policy_check_requests_total{result}` - запросы `/v1/check` на стороне `policy-server`;
- `policy_check_duration_seconds` - полная задержка обработки `/v1/check`;
- `policy_match_latency_seconds` - задержка сопоставления правил внутри `policy-server`;
- `policy_reload_total{result}` - результаты перезагрузки политик;
- `policy_reload_duration_seconds` - длительность перезагрузки политик;
- `policy_rules_total` - число активных правил;
- `policy_index_buckets_total` - число корзин индексированного сопоставления.

Подробная карта наблюдаемости находится в [`docs/observability.md`](docs/observability.md).

## Трассировка

OpenTelemetry-трассировка выключена по умолчанию и не требуется для обычного запуска. Включить вывод spans в журналы контейнеров можно так:

```bash
OTEL_ENABLED=true OTEL_EXPORTER=stdout make -C deploy up
make -C deploy test-all
docker compose -f deploy/docker-compose.yml logs payments policy-server-1 policy-server-2 policy-server-3 orders
```

Поддерживаются режимы:

```text
OTEL_ENABLED=false
OTEL_EXPORTER=stdout
OTEL_EXPORTER=otlp
OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector:4317
```

Основные spans:

- `transport.grpc.authorize`;
- `transport.http.authorize`;
- `authz.authorize`;
- `authz.cache.get`;
- `authz.policy.check`;
- `authz.policy.health`;
- `authz.fail_closed`;
- `policy_server.check`;
- `policy_server.match`;
- `policy_server.reload`;
- `policy_server.health`;
- `broker.publish.authorize`;
- `broker.consume.verify_signature`;
- `broker.consume.authorize`;
- `broker.consume.retry`;
- `broker.consume.dead_letter`.

В spans записываются только низкокардинальные атрибуты: транспорт, брокер, результат, попадание в кэш, индекс экземпляра `policy-server`, факт запрета при отказе, результат проверки подписи, retry count и факт DLQ. Полезная нагрузка сообщений, секреты, HMAC-подписи, raw URL, topic/subject, message type, source/target и номера правил в трассировку не пишутся.

Grafana:

```text
http://localhost:3000
```

Учетные данные по умолчанию:

```text
admin / admin
```

## Подтвержденные свойства

- централизованное принятие решений через `policy-server`;
- транспортно-независимая модель запроса авторизации;
- поддержка синхронных транспортов: gRPC и REST;
- поддержка асинхронных транспортов через Kafka и NATS;
- расширяемая граница модулей обмена сообщениями;
- динамическая перезагрузка YAML-политик без перезапуска служб;
- журнал аудита для административных операций перезагрузки;
- кэш решений с ключами, учитывающими транспорт, брокер и тип сообщения;
- запрет при отказе, если `policy-server` недоступен;
- переключение между несколькими экземплярами `policy-server`;
- метрики Prometheus для решений, кэша, задержки и запретов при отказе.

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

- Сертификаты генерируются локально и игнорируются git.
- Административный токен предназначен для локального стенда.
- REST и gRPC используют mTLS для идентификации служб.
- Идентификация сообщений использует служебные заголовки для воспроизводимости; в производственной среде подлинность сообщения должна быть связана с аутентификацией брокера или криптографической проверкой.
