# Failover для трех реплик policy-server

Команда:

```bash
make -C deploy failover
```

Результат: успешно.

Проверенные сценарии:

- все три `policy-server` работают, `orders charge` проходит;
- остановлен `policy-server-1`, запрос проходит через оставшиеся реплики;
- остановлены `policy-server-1` и `policy-server-2`, запрос проходит через `policy-server-3`;
- остановлен `policy-server-3`, запрос проходит через `policy-server-1` или `policy-server-2`;
- остановлены `policy-server-1` и `policy-server-3`, запрос проходит через `policy-server-2`;
- остановлены `policy-server-2` и `policy-server-3`, запрос проходит через `policy-server-1`;
- остановлены все три реплики, `orders charge` завершается `PermissionDenied` с `fail-closed: policy-server unavailable`;
- после восстановления всех трех реплик `orders charge` снова проходит.

Ключевые метрики после восстановления находятся в `failover_metrics.txt`.
