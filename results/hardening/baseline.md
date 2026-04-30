# Baseline перед production-like hardening

Дата: 2026-04-30T15:41:53+03:00

## Git

- Ветка: `production-hardening`
- Commit: `0dad0b0`
- Исходная ветка: `master`
- Рабочее дерево: отслеживаемые файлы без изменений до создания baseline summary
- Untracked: `.codex` оставлен без изменений и не удалялся

## Подготовка ветки

Создана отдельная рабочая ветка:

```bash
git switch -c production-hardening
```

Ветка создана от стабильного commit `0dad0b0`.

## Baseline-проверки

| Команда | Результат | Примечание |
|---|---|---|
| `go test ./...` | пройдено | unit/integration-style tests для Go packages проходят |
| `docker compose -f deploy/docker-compose.yml config` | пройдено | compose configuration корректно раскрывается |
| `make -C deploy up` | пройдено | стенд поднят с пересборкой образов |
| `make -C deploy test-all` | пройдено | gRPC, REST, Kafka и NATS allow/deny сценарии прошли |
| `make -C deploy degrade-all` | пройдено | fail-closed подтвержден для gRPC, REST, Kafka publish/consume и NATS publish/consume |
| `make -C deploy status` | пройдено | endpoints и monitoring URLs выведены |

## Итог состояния стенда

После проверок запущены основные сервисы Docker Compose:

- `policy-server`;
- `payments`;
- `orders`;
- `kafka`;
- `nats`;
- `prometheus`;
- `grafana`.

## Финальные suite targets

Следующие targets не запускались в рамках быстрого baseline gate, потому что они повторяют значительную часть `test-all`/`degrade-all` и могут занимать заметное время:

- `make -C deploy final-functional`;
- `make -C deploy final-bench`;
- `make -C deploy final-suite`.

Их стоит запускать отдельным расширенным прогоном перед финальными сравнительными экспериментами.

## Вывод

Текущая версия готова к началу production-like hardening. Блокеров на baseline-этапе не выявлено.

Следующий безопасный этап: проектирование indexed policy matching без изменения внешнего поведения авторизации.
