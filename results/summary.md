# Итоговая сводка экспериментов

Эта сводка объединяет подтвержденное поведение финальной версии framework `authz-system`.

## Область проверки

Оценивались транспорты:

- gRPC;
- HTTP/REST;
- Kafka;
- NATS.

Оценивались свойства:

- корректность allow/deny;
- dynamic policy reload;
- fail-closed behavior при деградации policy-server;
- поведение decision cache;
- metrics и audit evidence;
- сравнительные latency/throughput smoke benchmarks.

## Функциональные результаты

Финальная функциональная матрица автоматизирована командой:

```bash
make -C deploy final-functional
```

Подтвержденные проверки:

| Transport | Allow | Deny | Reload Impact | Fail-Closed |
|---|---:|---:|---:|---:|
| gRPC | yes | yes | yes | yes |
| REST | yes | yes | yes | yes |
| Kafka publish | yes | yes | yes | yes |
| Kafka consume | yes | n/a | covered by policy model | yes |
| NATS publish | yes | yes | yes | yes |
| NATS consume | yes | n/a | covered by policy model | yes |

Последний проверенный functional artifact:

```text
results/final_smoke4/functional/summary.csv
```

Все строки в этом smoke run прошли успешно.

## Результаты benchmark smoke

Финальная benchmark matrix автоматизирована командой:

```bash
make -C deploy final-bench
```

Последняя short smoke configuration:

```text
FINAL_N=20
FINAL_C=5
FINAL_WARMUP=5
```

Последний short smoke artifact:

```text
results/final_smoke5/bench/bench_summary.csv
```

Наблюдаемые short-run results:

| Transport | Scenario | p95 ms | Notes |
|---|---|---:|---|
| gRPC | allow | 0.829 | direct mTLS gRPC path |
| gRPC | deny | 0.351 | expected PermissionDenied counted as successful deny |
| REST | allow | 6.593 | mTLS HTTP middleware path |
| REST | deny | 8.022 | expected 403 counted as successful deny |
| Kafka | publish allow | 2.334 | publish authz plus broker write |
| Kafka | publish deny | 0.007 | denied before broker write |
| NATS | publish allow | 1.024 | publish authz plus broker publish |
| NATS | publish deny | 0.036 | denied before broker publish |

Эти numbers являются smoke-check values, а не финальными статистическими claims. Для диссертационных прогонов следует использовать larger settings, например:

```bash
FINAL_N=1000 FINAL_C=50 FINAL_WARMUP=100 make -C deploy final-bench
```

## Подтверждение метриками

Финальный benchmark smoke сформировал metrics с labels `transport` и `broker`:

```text
authz_cache_total{broker="kafka",transport="broker",type="hit"} ...
authz_cache_total{broker="nats",transport="broker",type="hit"} ...
authz_checks_total{broker="none",transport="grpc",result="allow"} ...
authz_checks_total{broker="none",transport="http",result="deny"} ...
```

Async consume evidence из того же smoke run:

```text
kafka_consume_ok,25
nats_consume_ok,25
```

## Reload

Reload был проверен для:

- gRPC allow rule `R1`;
- REST allow rule `R_HTTP_1`;
- Kafka publish allow rule `R_KAFKA_1`;
- NATS publish allow rule `R_NATS_1`.

Метод:

1. Временно изменить effect разрешающего rule на `deny`.
2. Выполнить policy reload.
3. Проверить, что ранее разрешенная operation теперь запрещена.
4. Восстановить allow rule.
5. Выполнить policy reload.
6. Проверить, что operation снова успешна.

Важная deployment note: Docker Compose монтирует весь directory `policies`, а не одиночный файл, поэтому policy reload надежно видит file updates.

## Fail-Closed

Fail-closed был проверен для:

- gRPC request path;
- REST request path;
- Kafka producer publish;
- Kafka consumer processing;
- NATS publisher;
- NATS subscriber processing.

Ожидаемое поведение:

- когда `policy-server` недоступен и `FailOpen=false`, protected operation блокируется;
- `authz_fail_closed_total` увеличивается;
- cached allow decisions не обходят недоступность policy-server.

## Заметки по stress и chaos

Ранее подтвержденные stress scenarios:

- baseline и concurrency matrix;
- 10k policy rules;
- stress runs с 50k и 200k requests;
- reload under load;
- policy-server flap;
- degrade tests.

Representative confirmed result:

```text
10k rules, charge, concurrency=100:
avg ~8.5 ms, p95 ~14 ms, p99 ~18 ms
```

Длинные stress runs показали рост tail latency. Это интерпретируется как operational limitation при sustained load, а не как safety violation: authorization остается fail-closed.

## Интерпретация

Sync vs async:

- gRPC и REST защищают direct request/response paths.
- Kafka и NATS защищают publish и consume boundaries.
- Broker deny paths дешевле, потому что denied messages отклоняются до broker write.

Kafka vs NATS:

- оба используют одну broker abstraction и policy model;
- Kafka демонстрирует durable topic-based async flow;
- NATS демонстрирует lightweight subject-based async flow;
- добавление NATS не потребовало изменений в authorization core.

Cache:

- cache hit/miss metrics подтверждают, что repeated checks избегают repeated policy decisions;
- cache keys включают transport, broker и message type;
- fail-closed safety имеет приоритет над cached allow decisions.

Transport-agnostic architecture:

- все transports сходятся в один `AuthzRequest`;
- policy-server не знает implementation details transports;
- добавление второго broker adapter подтвердило extensibility.

## Рекомендации по дальнейшей оптимизации

- Добавить persistent NATS JetStream scenario для durable consume experiments.
- Добавить broker-authenticated identities вместо demo message headers.
- Добавить matrix benchmarks для REST и broker paths по аналогии с существующей gRPC load matrix.
- Добавить dashboards с разбиением по `transport` и `broker`.
- Добавить CI smoke checks для `go test`, compose config и final functional smoke.
