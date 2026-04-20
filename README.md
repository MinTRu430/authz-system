# AuthZ System: транспортно-независимая система авторизации межсервисного взаимодействия

`authz-system` - экспериментальная система централизованной авторизации межсервисного взаимодействия в микросервисной среде. Проект подготовлен как инженерный артефакт для магистерского исследования.

Система предоставляет единую транспортно-независимую модель авторизации и набор модулей подключения:

- перехватчики gRPC для одиночных и потоковых вызовов;
- промежуточный обработчик HTTP/REST;
- общий слой авторизации для обмена сообщениями;
- модуль Kafka;
- модуль NATS.

Система следует принципам Zero Trust и запрета по умолчанию: каждое защищаемое взаимодействие нормализуется в общий запрос авторизации, проверяется централизованным сервером политик `policy-server` и блокируется, если `policy-server` недоступен при `FailOpen=false`.

## Архитектура

Основные компоненты:

- `internal/authz` - ядро: модель запроса, сопоставление политик, кэш решений, проверка авторизации, метрики и поведение запрета при отказе.
- `internal/authz/grpcadapter` - перехватчики gRPC поверх общего ядра авторизации.
- `internal/authz/httpadapter` - промежуточный обработчик HTTP/REST и нормализация маршрутов поверх общего ядра авторизации.
- `internal/authz/kafkaadapter` - модуль Kafka для проверки публикации и обработки сообщений через общий слой обмена сообщениями.
- `internal/authz/natsadapter` - модуль NATS для проверки публикации и обработки сообщений через общий слой обмена сообщениями.
- `policy-server` - централизованная служба, которая загружает YAML-политики, предоставляет `/v1/check`, поддерживает перезагрузку политик, журнал аудита и метрики Prometheus.
- `services/orders` - клиентская служба и командный интерфейс для gRPC, REST, Kafka и NATS вызовов.
- `services/payments` - защищаемая служба со сценариями gRPC, REST, обработчиком Kafka и подписчиком NATS.
- `deploy` - окружение Docker Compose с `policy-server`, службами, Kafka, NATS, Prometheus и Grafana.
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

Для сообщений через Kafka и NATS используются служебные заголовки:

- `X-Service-Name` - имя службы-источника;
- `X-Message-Type` - тип события.

В производственной среде подлинность отправителя сообщений должна подтверждаться средствами брокера, mTLS/SASL, подписью сообщений или другим криптографически защищенным механизмом.

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

Сгенерированные сертификаты, данные журнала аудита и результаты экспериментов являются локальными артефактами выполнения и не коммитятся. Файл журнала аудита `policy-server` хранится в именованном томе Docker и читается через `make -C deploy audit`.

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

- `policy-server`;
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

Эти проверки останавливают `policy-server` и подтверждают, что ранее разрешенные пути взаимодействия блокируются, пока `policy-server` недоступен.

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
- `authz_cache_total{type,transport,broker}` - попадания и промахи кэша решений;
- `authz_policy_check_latency_seconds{transport,broker}` - задержка проверки политики;
- `authz_fail_closed_total` - запреты из-за недоступности `policy-server`;
- `policy_decisions_total{result}` - решения на стороне `policy-server`.

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
