# Централизованная межсервисная авторизация в микросервисной архитектуре (Go)

## Аннотация

Проект представляет собой **экспериментальный прототип системы централизованной межсервисной авторизации** для микросервисной архитектуры, реализованный на языке Go.

Система предназначена для контроля доступа между сервисами на уровне **gRPC-, HTTP/REST- и Kafka-взаимодействий** и реализует принципы **Zero Trust** и **default deny**.  
Проект разработан в рамках производственной практики и используется как практическая часть магистерского исследования.

---

## Ключевые особенности

- взаимная аутентификация сервисов на основе **mTLS**;
- централизованное принятие решений об авторизации;
- отсутствие необходимости в service mesh или sidecar-прокси;
- динамическая перезагрузка политик доступа;
- аудит изменений политик;
- интеграция с Prometheus и Grafana;
- экспериментальная оценка накладных расходов.

---

## Архитектура системы

Система построена по принципу централизованной авторизации и включает следующие компоненты:

### Policy Server
- хранение и применение политик доступа;
- REST API для проверки прав доступа;
- перезагрузка политик без перезапуска;
- аудит административных действий;
- экспорт метрик Prometheus.

### AuthZ Agent
- библиотека, встраиваемая в микросервисы;
- реализован в виде gRPC unary/stream interceptor’ов и HTTP middleware;
- содержит общий broker abstraction layer и Kafka adapter;
- извлекает идентичность сервиса из mTLS-сертификата;
- выполняет синхронную проверку прав перед gRPC, REST или Kafka publish/consume.

### Демонстрационные сервисы
- **orders** — сервис-клиент, инициирующий межсервисные вызовы;
- **payments** — защищённый сервис (методы `Charge` и `Refund`).
- Kafka demo — `orders` публикует событие `payment.requested.v1`, `payments` читает и обрабатывает его после authz check.

### Наблюдаемость
- **Prometheus** — сбор метрик;
- **Grafana** — визуализация;
- **audit log** — контроль изменений политик.

---

## Политики доступа

Политики описываются в YAML-файле `policies/policies.yaml`.  
Используется принцип **запрета по умолчанию (default deny)**.

### Пример политик

```yaml
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

- id: R_HTTP_1
  source: orders
  target: payments
  transport: http
  operation: POST
  resource: /payments/charge
  effect: allow

- id: R_HTTP_2
  source: orders
  target: payments
  transport: http
  operation: POST
  resource: /payments/refund
  effect: deny

- id: R_BROKER_1
  source: orders
  target: payments
  transport: broker
  broker: kafka
  operation: publish
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R_BROKER_2
  source: orders
  target: payments
  transport: broker
  broker: kafka
  operation: consume
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R_BROKER_3
  source: orders
  target: payments
  transport: broker
  broker: kafka
  operation: publish
  resource: payments.refund.forced
  message_type: payment.refund.forced.v1
  effect: deny

- id: R3
  source: "*"
  target: "*"
  transport: "*"
  operation: "*"
  resource: "*"
  effect: deny
```

Поле `rpc` из ранней версии формата пока поддерживается как legacy-форма gRPC-правил и при загрузке нормализуется в `transport: grpc`, `operation: <rpc>`, `resource: "*"`. Для REST используется `transport: http`, `operation` содержит HTTP-метод, а `resource` содержит нормализованный путь без query-параметров. Для broker-сценариев `operation` принимает значения `publish` или `consume`, `resource` содержит topic/subject/queue, а `message_type` задаёт тип события.

Отдельный пример broker-only политик находится в `policies/policies_broker_example.yaml`.

### Kafka demo contract

Kafka adapter использует общий broker abstraction layer и не меняет core-логику авторизации. В demo-сценарии metadata сообщения передаётся через Kafka headers:

- `X-Service-Name` — сервис-источник сообщения;
- `X-Message-Type` — тип события.

Это demo transport contract. Для production-сценариев service identity должна подтверждаться механизмами брокера, mTLS/SASL, подписью сообщения или другим криптографически защищённым способом.

### Интерпретация политик доступа

- сервис `orders` имеет право вызывать метод `Charge` сервиса `payments`;
- вызов метода `Refund` запрещён для всех сервисов;
- любые иные межсервисные вызовы запрещены по умолчанию в соответствии с принципом *default deny*.

---

## Требования к окружению

Для запуска и тестирования прототипа необходимы:

- Docker;
- Docker Compose (v2);
- OpenSSL;
- Go версии **не ниже 1.22** (для локальной сборки и генерации артефактов).

---

## Быстрый старт

### Шаг 1. Генерация сертификатов (выполняется один раз)

```bash
chmod +x certs/generate-certs.sh
./certs/generate-certs.sh
```
## Запуск и тестирование стенда

### Шаг 1. Генерация сертификатов (выполняется один раз)

```bash
chmod +x certs/generate-certs.sh
./certs/generate-certs.sh
```

В результате выполнения данного шага будут сгенерированы:

- Корневой центр сертификации (CA);
- Клиентские сертификаты для сервисов:
  - `orders`;
  - `payments`;
  - `policy-server`.

Сертификаты используются для взаимной аутентификации сервисов и реализации межсервисной авторизации.

### Шаг 2. Запуск стенда

```bash
make -C deploy restart
```

В ходе запуска будут подняты следующие контейнеры:

- `policy-server` — сервис централизованной авторизации;
- `kafka` — локальный Apache Kafka broker для async demo;
- `payments` — сервис платежей;
- `orders` — сервис заказов;
- `prometheus` — сбор метрик;
- `grafana` — визуализация метрик.

Для проверки состояния контейнеров:

```bash
docker ps
```

### Шаг 3. Функциональное тестирование

```bash
make -C deploy test
make -C deploy test-rest
make -C deploy test-kafka
```

**Ожидаемый результат:**

- Вызов метода `Charge` завершается успешно;
- Вызов метода `Refund` завершается ошибкой `PermissionDenied`.
- REST-вызов `POST /payments/charge` завершается успешно;
- REST-вызов `POST /payments/refund` завершается ошибкой `403 Forbidden`.
- Kafka publish `payment.requested.v1` завершается успешно;
- Kafka consumer `payments` обрабатывает разрешённое сообщение;
- Kafka publish `payment.refund.forced.v1` блокируется политикой.

Полученный результат подтверждает корректную работу механизма централизованной межсервисной авторизации и применение политик доступа.

---

## Администрирование

### Перезагрузка политик доступа

Для применения изменений в политиках без перезапуска сервисов:

```bash
make -C deploy reload
```

### Проверка fail-closed

```bash
make -C deploy degrade-test
make -C deploy degrade-rest-test
make -C deploy degrade-kafka-test
make -C deploy degrade-kafka-consume-test
```

### Просмотр журнала аудита
```bash
make -C deploy audit
```

Журнал аудита фиксирует:

- Время изменения конфигурации;
- Инициатора изменения;
- Предыдущую и текущую версии политик доступа.

---

## Метрики и мониторинг

### Prometheus

URL: http://localhost:9091

Основные метрики:

- `policy_decisions_total` — количество принятых решений по политикам;
- `authz_checks_total` — количество проверок авторизации с метками `result` и `transport`;
- `authz_cache_total` — cache hit/miss с меткой `transport`;
- `authz_policy_check_latency_seconds` — задержка проверки политик с меткой `transport`;
- `authz_fail_closed_total` — количество блокировок в режиме fail-closed.

### Grafana

URL: http://localhost:3000

Логин / пароль: `admin` / `admin`

---

## Нагрузочное тестирование

Для оценки накладных расходов централизованной межсервисной авторизации реализован бенчмарк, измеряющий end-to-end задержку межсервисных вызовов.

### Запуск бенчмарка

Прямой запуск:

```bash
./scripts/bench.sh charge 500
./scripts/bench.sh refund 500
```

Или с использованием Makefile:

```bash
make -C deploy bench
```
### Результаты эксперимента

По результатам нагрузочного тестирования установлено, что:

- Медианная задержка (p50) составляет порядка 110–115 мс;
- Значение p95 не превышает 150 мс;
- Накладные расходы являются стабильными и предсказуемыми;
- Различия между сценариями allow и deny минимальны.

В условиях production-среды (без использования `docker exec`) ожидается существенно меньшая задержка.

---

## Безопасность

- Приватные ключи и сертификаты не хранятся в репозитории;
- Все секреты генерируются локально при запуске стенда;
- Административный токен используется исключительно в демонстрационных целях.
