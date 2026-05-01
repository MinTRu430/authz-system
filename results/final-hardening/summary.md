# Финальная сводка production-like hardening

Дата проведения: 2026-05-01.

Результаты находятся в `results/final-hardening/`.

## Что проведено

- unit/build проверка: `go test ./...`;
- проверка конфигурации: `docker compose -f deploy/docker-compose.yml config`;
- запуск стенда: `make -C deploy up`;
- функциональная матрица: `make -C deploy final-hardening-functional`;
- отдельные проверки: `test-all`, `test-dlq`, `reload-all`, `audit-all`, `failover`, `degrade-all`;
- сравнительный bench: `make -C deploy final-hardening-bench FINAL_N=200 FINAL_C=10 FINAL_WARMUP=20`;
- concurrency matrix для gRPC/REST: `c=1/10/50/100`;
- stress: gRPC 50k requests при `c=100`, REST 5k requests при `c=100`;
- OpenTelemetry stdout smoke для gRPC, REST, Kafka, NATS.

## Что подтверждено

- gRPC allow/deny работает;
- REST allow/deny работает;
- Kafka publish/consume allow работает, publish deny блокируется;
- NATS publish/consume allow работает, publish deny блокируется;
- reload влияет на gRPC, REST, Kafka и NATS без перезапуска;
- fail-closed работает для gRPC, REST, Kafka publish/consume и NATS publish/consume;
- failover работает с тремя репликами `policy-server`;
- при отказе всех трех реплик авторизация блокируется;
- HMAC signing блокирует сообщения с неверной подписью до обработки;
- retry/DLQ работает для `policy_unavailable`;
- indexed matching активен на 10008 правилах и 10008 index buckets;
- Prometheus scrape видит `policy-server-1`, `policy-server-2`, `policy-server-3` в состоянии `up`;
- OpenTelemetry tracing включается опционально и не нужен для обычного запуска.

## Изменения после hardening

- `policy-server` теперь работает в трех репликах;
- `POLICY_URLS` содержит три endpoint-а;
- `reload-all`, `audit-all`, `failover`, degrade targets работают с тремя репликами;
- сертификат `policy-server` содержит SAN `policy-server-3`;
- Prometheus собирает метрики со всех трех `policy-server`;
- результаты финальных проверок структурированы в `results/final-hardening/`.

## Основные цифры

Текущая политика:

- active rules: 10008;
- index buckets: 10008;
- версии всех трех policy-server после финального health: `ef957497983c-20260501T131309`.

Сравнительный bench при `n=200`, `c=10`:

| Transport | Scenario | RPS | Avg ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|
| gRPC | allow | 13298.8 | 0.729 | 1.852 | 4.368 |
| gRPC | deny | 38666.7 | 0.247 | 0.507 | 0.671 |
| REST | allow | 2254.1 | 4.248 | 14.133 | 23.570 |
| REST | deny | 2750.6 | 2.882 | 14.534 | 21.859 |
| Kafka | publish allow | 53575.6 | 0.171 | 0.392 | 0.444 |
| Kafka | publish deny | 390588.4 | 0.007 | 0.016 | 0.032 |
| NATS | publish allow | 28547.9 | 0.330 | 1.083 | 1.248 |
| NATS | publish deny | 166211.0 | 0.008 | 0.010 | 0.084 |

Concurrency matrix highlights:

- gRPC `c=100`: avg 10.890 ms, p95 46.608 ms, p99 51.944 ms;
- REST `c=100`: avg 31.857 ms, p95 122.720 ms, p99 193.123 ms.

Stress:

- gRPC 50k, `c=100`: 50000/50000 ok, avg 1.434 ms, p95 2.690 ms, p99 3.998 ms;
- REST 5k, `c=100`: 5000/5000 ok, avg 33.394 ms, p95 211.018 ms, p99 385.346 ms.

Failover metrics after recovery:

- `authz_policy_failover_total`: 7 in failover-focused scrape, 16 after additional degrade/failover exercises;
- endpoint availability after recovery: endpoints `0`, `1`, `2` are `1`;
- `authz_fail_closed_total`: grows when all replicas are unavailable.

DLQ/signing metrics in final scrape:

- Kafka `invalid_signature` DLQ: 1;
- NATS `invalid_signature` DLQ: 1;
- Kafka `policy_unavailable` retry: 3, DLQ: 1;
- NATS `policy_unavailable` retry: 3, DLQ: 1.

## Артефакты

- `environment.md` - окружение и версии;
- `functional/summary.csv` - функциональная матрица allow/deny/reload/degrade;
- `functional/metrics_summary.txt` - метрики после функционального набора;
- `load/bench_summary.csv` - сравнительный bench;
- `load/concurrency_matrix.csv` - matrix `c=1/10/50/100` для gRPC/REST;
- `stress/stress_summary.csv` - stress-прогоны;
- `failover/summary.md` и `failover/failover_metrics.txt` - сценарии отказа реплик;
- `dlq/summary.md` - HMAC/DLQ/retry результаты;
- `metrics/*.prom` - полные Prometheus scrapes;
- `metrics/prometheus-targets-final.json` - состояние scrape targets;
- `tracing/summary.md` - OpenTelemetry smoke.

## Наблюдения

- Indexed matching сохраняет низкую задержку сопоставления на 10008 правилах: средняя `policy_match_latency_seconds` по репликам находится в десятках микросекунд.
- gRPC показывает более стабильные хвосты на коротких и stress-прогонах.
- REST сильнее реагирует на высокую конкуренцию, что видно по p95/p99 при `c=50/100`.
- Kafka и NATS publish path быстрый, потому что bench измеряет publish/authorize путь, а обработка consume подтверждается отдельными функциональными и DLQ-сценариями.
- Multi-endpoint client корректно переживает отказ одной и двух реплик, но полный отказ всех трех реплик приводит к обязательному fail-closed.

## Ограничения

- Строгая согласованность версий между репликами обеспечивается через `reload-all`, без распределенного консенсуса.
- NATS используется без JetStream, поэтому полноценный broker-level ack/requeue не реализован.
- Tracing context через Kafka/NATS headers не включен, чтобы не менять текущий HMAC canonical contract.
- Production secret manager не внедрялся: HMAC secrets задаются через переменные окружения.
- Runtime smoke покрывает invalid signature; missing signature, payload mismatch и wrong secret дополнительно закреплены unit-тестами.

## Вердикт

Production-like hardening завершен. Стенд воспроизводимо поднимается с тремя репликами `policy-server`, основные транспорты работают, failover/fail-closed подтверждены, HMAC signing и retry/DLQ подтверждены, метрики и tracing готовы для анализа в диссертации.
