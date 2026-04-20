# Результаты экспериментов

Финальные experiment scripts сохраняют timestamped artifacts в этот directory.

Сгенерированные paths намеренно игнорируются git:

- `results/final/<timestamp>/functional/`
- `results/final/<timestamp>/bench/`
- custom `RESULT_DIR=...` smoke runs, например `results/final_smoke5/`

Основные files:

- `summary.csv` для functional allow/deny/reload/degrade checks;
- `bench_summary.csv` для latency и throughput measurements;
- `payments_metrics_*.prom` и `policy_metrics_*.prom` для Prometheus snapshots;
- `audit_*.log` для policy reload audit evidence;
- `docker_*.log` для service logs и async consume evidence.

Итоговая curated summary хранится в `results/summary.md`.
