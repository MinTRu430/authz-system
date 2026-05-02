# Окружение эксперимента

Дата: 2026-05-02T14:06:18+03:00

Ветка: `policy-store-consistency`

Базовый commit: `2701541b5c5f63b589d9345a1dce895f2e93c06e`

Примечание: эксперимент выполнен на рабочей копии с изменениями блока `centralized policy store / version consistency`, еще не зафиксированными отдельным commit.

Go: `go version go1.25.5 linux/amd64`

Docker Server: `29.4.0`

Сервисы Docker Compose:

- `policy-store`;
- `policy-server-1`;
- `policy-server-2`;
- `policy-server-3`;
- `orders`;
- `payments`;
- `kafka`;
- `nats`;
- `prometheus`;
- `grafana`.

Конфигурация политик:

- `POLICY_SOURCE=postgres`;
- `POLICY_STORE_DSN=postgres://authz:authz@policy-store:5432/authz?sslmode=disable`;
- `POLICY_STORE_SYNC_INTERVAL=2s`;
- bootstrap выполняется из `POLICY_FILE=/app/policies/policies.yaml`, если в PostgreSQL нет активной версии.

Включенные свойства:

- централизованное PostgreSQL-хранилище политик;
- таблицы `policy_versions`, `policy_active`, `policy_audit`;
- единственная активная версия через `policy_active`;
- startup seed из файла;
- sync loop трех реплик `policy-server`;
- rollback активной версии;
- last-known-good поведение при временной недоступности PostgreSQL;
- file mode сохранен как режим совместимости;
- multi-endpoint failover трех `policy-server`;
- fail-closed при недоступности всех `policy-server`.
