# Final Experiment Summary

This summary consolidates the confirmed behavior of the final `authz-system` framework version.

## Scope

Evaluated transports:

- gRPC;
- HTTP/REST;
- Kafka;
- NATS.

Evaluated properties:

- allow/deny correctness;
- dynamic policy reload;
- fail-closed behavior under policy-server degradation;
- decision cache behavior;
- metrics and audit evidence;
- comparative latency/throughput smoke benchmarks.

## Functional Results

The final functional matrix is automated by:

```bash
make -C deploy final-functional
```

Confirmed checks:

| Transport | Allow | Deny | Reload Impact | Fail-Closed |
|---|---:|---:|---:|---:|
| gRPC | yes | yes | yes | yes |
| REST | yes | yes | yes | yes |
| Kafka publish | yes | yes | yes | yes |
| Kafka consume | yes | n/a | covered by policy model | yes |
| NATS publish | yes | yes | yes | yes |
| NATS consume | yes | n/a | covered by policy model | yes |

Latest verified functional artifact:

```text
results/final_smoke4/functional/summary.csv
```

All rows in that smoke run passed.

## Benchmark Smoke Results

The final benchmark matrix is automated by:

```bash
make -C deploy final-bench
```

Latest short smoke configuration:

```text
FINAL_N=20
FINAL_C=5
FINAL_WARMUP=5
```

Latest short smoke artifact:

```text
results/final_smoke5/bench/bench_summary.csv
```

Observed short-run results:

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

These numbers are smoke-check values, not final statistical claims. Dissertation-oriented runs should use larger settings, for example:

```bash
FINAL_N=1000 FINAL_C=50 FINAL_WARMUP=100 make -C deploy final-bench
```

## Metrics Evidence

The final benchmark smoke produced metrics with transport and broker labels:

```text
authz_cache_total{broker="kafka",transport="broker",type="hit"} ...
authz_cache_total{broker="nats",transport="broker",type="hit"} ...
authz_checks_total{broker="none",transport="grpc",result="allow"} ...
authz_checks_total{broker="none",transport="http",result="deny"} ...
```

Async consume evidence from the same smoke run:

```text
kafka_consume_ok,25
nats_consume_ok,25
```

## Reload

Reload was verified for:

- gRPC allow rule `R1`;
- REST allow rule `R_HTTP_1`;
- Kafka publish allow rule `R_KAFKA_1`;
- NATS publish allow rule `R_NATS_1`.

Method:

1. Temporarily change allow rule effect to `deny`.
2. Call policy reload.
3. Verify previously allowed operation is denied.
4. Restore allow rule.
5. Call policy reload.
6. Verify operation succeeds again.

Important deployment note: Docker Compose mounts the whole `policies` directory, not a single file, so policy reload observes file updates reliably.

## Fail-Closed

Fail-closed was verified for:

- gRPC request path;
- REST request path;
- Kafka producer publish;
- Kafka consumer processing;
- NATS publisher;
- NATS subscriber processing.

Expected behavior:

- when `policy-server` is unavailable and `FailOpen=false`, the protected operation is blocked;
- `authz_fail_closed_total` increases;
- cached allow decisions do not bypass policy-server unavailability.

## Stress and Chaos Notes

Previously confirmed stress scenarios:

- baseline and concurrency matrix;
- 10k policy rules;
- stress runs with 50k and 200k requests;
- reload under load;
- policy-server flap;
- degrade tests.

Representative confirmed result:

```text
10k rules, charge, concurrency=100:
avg ~8.5 ms, p95 ~14 ms, p99 ~18 ms
```

Long stress runs showed increasing tail latency. This is interpreted as an operational limitation under sustained load, not a safety violation: authorization remains fail-closed.

## Interpretation

Sync vs async:

- gRPC and REST protect direct request/response paths.
- Kafka and NATS protect publish and consume boundaries.
- Broker deny paths are cheap because denied messages are rejected before broker write.

Kafka vs NATS:

- Both use the same broker abstraction and policy model.
- Kafka demonstrates durable topic-based async flow.
- NATS demonstrates a lightweight subject-based async flow.
- Adding NATS did not require changes to the authorization core.

Cache:

- cache hit/miss metrics confirm that repeated checks avoid repeated policy decisions;
- cache keys include transport, broker and message type;
- fail-closed safety takes precedence over cached allow decisions.

Transport-agnostic architecture:

- all transports converge into the same `AuthzRequest`;
- policy-server does not know transport implementation details;
- adding a second broker adapter validated extensibility.

## Recommended Next Optimizations

- Add a persistent NATS JetStream scenario for durable consume experiments.
- Add broker-authenticated identities instead of demo message headers.
- Add matrix benchmarks for REST and broker paths similar to the existing gRPC load matrix.
- Add dashboards broken down by `transport` and `broker`.
- Add CI smoke checks for `go test`, compose config, and final functional smoke.
