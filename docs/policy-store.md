# Централизованное хранилище политик

Этот документ описывает режимы загрузки политик и согласование активной версии между репликами `policy-server`.

## Режимы работы

Источник политик задается переменной `POLICY_SOURCE`.

```text
POLICY_SOURCE=file
POLICY_SOURCE=postgres
```

Если переменная не задана, используется `file`.

## File mode

`POLICY_SOURCE=file` оставлен как режим совместимости и локальной отладки.

В этом режиме `policy-server` читает `POLICY_FILE`, нормализует правила, компилирует индекс и применяет snapshot атомарно. Версия детерминирована и строится от hash содержимого:

```text
file-<sha256-12>
```

Reload перечитывает локальный файл конкретной реплики.

## PostgreSQL mode

В production-like Docker Compose используется `POLICY_SOURCE=postgres`.

Основные переменные:

```text
POLICY_STORE_DSN=postgres://authz:authz@policy-store:5432/authz?sslmode=disable
POLICY_STORE_SYNC_INTERVAL=2s
POLICY_FILE=/app/policies/policies.yaml
```

PostgreSQL является единым источником активной версии политики. Все три реплики `policy-server` читают одну и ту же active version из таблицы `policy_active`.

## Схема данных

Минимальная схема:

- `policy_versions` хранит версии YAML-политик, hash, автора, комментарий и время создания;
- `policy_active` содержит единственную активную версию;
- `policy_audit` фиксирует административные действия.

Активная версия определяется только через `policy_active`, а не через поле состояния в `policy_versions`.

## Startup seed

Если при старте в PostgreSQL нет активной версии, `policy-server` использует `POLICY_FILE` для первичного seed.

Seed выполняется безопасно для одновременного старта трех реплик:

1. реплика проверяет наличие active version;
2. при отсутствии active version создает новую версию из `POLICY_FILE`;
3. активирует ее через транзакционное обновление `policy_active`;
4. остальные реплики видят уже созданную active version и просто загружают ее.

## Sync loop

Каждая реплика периодически выполняет синхронизацию:

1. читает active version из PostgreSQL;
2. сравнивает `version` и `content_hash` с текущим snapshot;
3. при изменении парсит YAML, компилирует indexed policy и атомарно применяет snapshot;
4. обновляет `last_sync_at` и `sync_status`.

Если PostgreSQL временно недоступен, но активная политика уже загружена, реплика продолжает обслуживать запросы по last-known-good policy и сообщает:

```text
sync_status=stale
```

Если активной политики нет, `/v1/health` возвращает `503`.

## Reload

В PostgreSQL mode команда:

```bash
make -C deploy reload
```

читает текущий `POLICY_FILE`, создает новую версию в PostgreSQL, активирует ее и сразу применяет на текущей реплике. Остальные реплики подтягивают новую active version через sync loop.

Команда:

```bash
make -C deploy reload-all
```

сохранена для совместимости. В PostgreSQL mode она выполняет один centralized reload и затем показывает состояние синхронизации всех реплик.

## Rollback

Откат выполняется активацией предыдущей валидной версии:

```bash
make -C deploy policy-rollback VERSION=p1-ef957497983c
```

После rollback все реплики подтягивают выбранную версию через sync loop.

## Административные команды

```bash
make -C deploy policy-versions
make -C deploy policy-sync-status
make -C deploy policy-activate VERSION=<version>
make -C deploy policy-rollback VERSION=<version>
```

## Health

`/v1/health` возвращает:

- `status`;
- `version`;
- `content_hash`;
- `rules`;
- `buckets`;
- `policy_source`;
- `sync_status`;
- `last_sync_at`;
- `sync_error`.

Для внешней проверки используется mTLS:

```bash
curl -sk https://localhost:8443/v1/health --cert certs/orders.pem --key certs/orders-key.pem --cacert certs/ca.pem
```

## Метрики

Основные метрики:

- `policy_store_sync_total{result}`;
- `policy_store_sync_duration_seconds`;
- `policy_store_db_errors_total{operation}`;
- `policy_store_last_sync_timestamp_seconds`;
- `policy_replica_in_sync`.

Версии и hash не добавляются в labels, чтобы не создавать высокую кардинальность.

## Ограничения

- PostgreSQL является критическим компонентом для обновления политик.
- Уже загруженная политика продолжает работать при временной недоступности PostgreSQL.
- Согласованность обеспечивается через PostgreSQL, без отдельного consensus между `policy-server`.
- Seed из файла предназначен для bootstrap.
- Внешний secret manager и Kubernetes-механика не входят в этот блок.
