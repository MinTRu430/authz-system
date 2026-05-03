# Release Summary

Текущий базовый commit кодовой версии: `cbc2621 add centralized policy store and version consistency`

## Назначение проекта

`authz-system` реализует framework обеспечения безопасности межсервисного взаимодействия. Проект демонстрирует централизованную авторизацию для синхронных и асинхронных транспортов через общее транспортно-независимое ядро.

## Поддерживаемые транспорты

- gRPC;
- HTTP/REST;
- Kafka;
- NATS.

## Основные свойства

- transport-agnostic authz core;
- gRPC и REST adapters поверх общего ядра;
- broker abstraction layer;
- Kafka и NATS adapters;
- HMAC-подпись сообщений Kafka/NATS;
- retry и dead-letter behavior для асинхронных сценариев;
- indexed policy matching;
- централизованный `policy-server`;
- 3 реплики `policy-server`;
- PostgreSQL-backed policy store;
- единая active policy version через `policy_active`;
- rollback активной версии;
- sync loop реплик `policy-server`;
- last-known-good policy при временной недоступности PostgreSQL;
- multi-endpoint failover;
- fail-closed при недоступности всех `policy-server`;
- dynamic reload;
- audit log;
- Prometheus metrics;
- optional OpenTelemetry tracing;
- воспроизводимый Docker Compose стенд.

## Быстрый запуск

```bash
make -C deploy up
make -C deploy test-all
make -C deploy test-dlq
make -C deploy policy-sync-status
```

Проверка отказов:

```bash
make -C deploy failover
make -C deploy degrade-all
```

Работа с версиями политик:

```bash
make -C deploy policy-versions
make -C deploy reload-all
make -C deploy policy-rollback VERSION=<version>
```

## Ключевые проверки релиза

На финальном аудите пройдены:

```bash
go test ./...
docker compose -f deploy/docker-compose.yml config
make -C deploy test-all
make -C deploy test-dlq
make -C deploy degrade-all
make -C deploy failover
make -C deploy policy-sync-status
```

Также проверены:

- отсутствие приватных ключей и сертификатов в Git;
- корректность `.gitignore` для сертификатов, логов и временных результатов;
- актуальность README и документов в `docs/`;
- наличие итоговых summaries в `results/final-hardening/` и `results/policy-store-consistency/`;
- PostgreSQL outage: реплики переходят в `sync_status=stale`, но продолжают работать с last-known-good policy;
- восстановление PostgreSQL возвращает реплики в `sync_status=ok`.

## Ключевые документы и результаты

- `README.md`;
- `docs/architecture-summary.md`;
- `docs/observability.md`;
- `docs/policy-store.md`;
- `results/final-hardening/summary.md`;
- `results/policy-store-consistency/summary.md`;
- `results/final-hardening/environment.md`;
- `results/policy-store-consistency/environment.md`.

## Известные ограничения

- PostgreSQL является критическим компонентом для обновления политик, но не для уже загруженных решений.
- Между репликами `policy-server` не внедрен отдельный distributed consensus; согласованность active version обеспечивается через PostgreSQL.
- Для обычного NATS без JetStream нет полноценного broker-level ack/requeue.
- Kafka/NATS trace context через headers не включен в HMAC-контракт.
- Production secret manager, Kubernetes и Helm не входят в текущий scope.
- В Docker Compose используются воспроизводимые стендовые секреты, не предназначенные для production deployment.

## Финальный статус

Репозиторий готов как инженерный и исследовательский артефакт для отчёта по практике и магистерской диссертации.
