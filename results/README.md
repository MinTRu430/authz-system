# Experiment Results

Final experiment scripts write timestamped artifacts under this directory.

Generated paths are intentionally ignored by git:

- `results/final/<timestamp>/functional/`
- `results/final/<timestamp>/bench/`
- custom `RESULT_DIR=...` smoke runs, for example `results/final_smoke5/`

Main files:

- `summary.csv` for functional allow/deny/reload/degrade checks;
- `bench_summary.csv` for latency and throughput measurements;
- `payments_metrics_*.prom` and `policy_metrics_*.prom` for Prometheus snapshots;
- `audit_*.log` for policy reload audit evidence;
- `docker_*.log` for service logs and async consume evidence.

The curated final summary is tracked in `results/summary.md`.
