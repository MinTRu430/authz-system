# Сводка проверки policy store consistency

## Исходное ограничение

До этого блока согласованность политик между тремя экземплярами `policy-server` обеспечивалась процедурно через `reload-all`: каждая реплика перезагружала локальный файл. Такой подход работал для стенда, но допускал риск, что одна реплика останется на старой версии политики.

## Что реализовано

Добавлено централизованное PostgreSQL-хранилище политик. Активная версия теперь определяется одной строкой в `policy_active`, а содержимое версий хранится в `policy_versions`. Все три реплики `policy-server` работают с `POLICY_SOURCE=postgres` и периодически синхронизируют активную версию через sync loop.

Файловый режим `POLICY_SOURCE=file` сохранен для локальной совместимости. В PostgreSQL mode файл используется для bootstrap seed и для команды reload from file.

## Проверка согласованности

Перед reload все три реплики показали одинаковое состояние:

- `policy_source=postgres`;
- `version=p1-ef957497983c`;
- `content_hash=ef957497983cab2aa6eceaa12e98879d25d3e10ff195dc27d1515973d3d91f96`;
- `sync_status=ok`;
- `rules=10008`;
- `buckets=10008`.

Результат сохранен в `health-before.json`.

## Reload через centralized store

Команда `make -C deploy reload-all` создала и активировала новую версию `p3-ef957497983c` через один экземпляр `policy-server`. После ожидания sync loop все три реплики перешли на эту версию и сохранили одинаковый `content_hash`.

Результаты сохранены в:

- `reload-all.log`;
- `health-after-reload.json`;
- `policy-versions.log`;
- `audit-all.log`.

## Rollback

Команда `make -C deploy policy-rollback VERSION=p1-ef957497983c` вернула active version на `p1-ef957497983c`. После синхронизации все три реплики снова показали одинаковую версию и `sync_status=ok`.

Результаты сохранены в:

- `rollback.log`;
- `health-after-rollback.json`.

## PostgreSQL outage

При остановленном `policy-store` все три реплики продолжили обслуживать последнюю успешно загруженную политику:

- `/v1/health` оставался `status=ok`;
- `sync_status` переходил в `stale`;
- `sync_error` содержал ошибку подключения к `policy-store`;
- `orders charge` продолжал проходить по last-known-good policy.

Во время outage метрики зафиксировали:

- `policy_replica_in_sync 0`;
- `policy_store_db_errors_total{operation="load_active"} 3`;
- `policy_store_sync_total{result="stale"} 3`.

После восстановления PostgreSQL все три реплики вернулись в `sync_status=ok`.

Результат сохранен в `postgres-outage.log`.

## Метрики

Сохранен полный scrape:

- payments metrics;
- `policy-server-1` metrics;
- `policy-server-2` metrics;
- `policy-server-3` metrics.

Файл: `metrics.prom`.

После восстановления стенда финальные значения подтвердили рабочее состояние:

- `policy_replica_in_sync 1` на каждой реплике;
- `policy_store_sync_total{result="ok"}` растет;
- `policy_store_sync_total{result="error"} 0`;
- `policy_store_db_errors_total` вернулся к нулевым значениям на новых процессах после degrade/failover рестартов.

Prometheus targets сохранены в `prometheus-targets.json`; `payments` и все три `policy-server` находятся в состоянии `up`.

## Интеграционные проверки

Пройдены команды:

```bash
go test ./policy-server
go test ./...
docker compose -f deploy/docker-compose.yml config
make -C deploy up
make -C deploy test-all
make -C deploy test-dlq
make -C deploy reload-all
make -C deploy audit-all
make -C deploy failover
make -C deploy degrade-all
make -C deploy policy-versions
make -C deploy policy-sync-status
POLICY_STORE_TEST_DSN='postgres://authz:authz@localhost:5432/authz?sslmode=disable' go test ./policy-server -run 'Postgres|PolicyStore|Sync' -v
```

`failover` подтвердил работу при отказе одной и двух реплик `policy-server`, а также fail-closed при отказе всех трех. `degrade-all` подтвердил fail-closed для gRPC, REST, Kafka и NATS после перехода на PostgreSQL-backed policy store.

Gated PostgreSQL tests подтвердили создание версий, транзакционную активацию, rollback, idempotent schema migration, безопасный startup seed, отказ от невалидной политики и last-known-good поведение sync loop.

## Вывод

Блок `centralized policy store / version consistency` можно считать завершенным. PostgreSQL-backed store устраняет процедурную рассинхронизацию active policy между репликами: все экземпляры получают одну и ту же активную версию из `policy_active`, а reload и rollback становятся операциями над централизованной active version.

## Оставшиеся ограничения

- PostgreSQL становится критическим компонентом для обновления политик, но не для уже загруженных решений.
- Между `policy-server` не внедрялся распределенный consensus; согласованность обеспечивается через PostgreSQL.
- При временной недоступности PostgreSQL реплики работают с last-known-good policy.
- Seed из файла используется только для bootstrap.
- Production-секретизация, внешний secret manager, Kubernetes и Helm остаются вне этого блока.
