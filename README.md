# AuthZ System: Transport-Agnostic Inter-Service Authorization Framework

`authz-system` is an experimental framework for centralized authorization of inter-service communication in microservice systems. It was developed as the engineering artifact for a master's research project.

The framework provides one transport-agnostic authorization model and several transport adapters:

- gRPC unary/stream interceptors;
- HTTP/REST middleware;
- generic broker authorization layer;
- Kafka adapter;
- NATS adapter.

The system follows Zero Trust and default-deny principles: every protected interaction is normalized into a common authorization request, checked by a centralized `policy-server`, and denied when the policy-server is unavailable and `FailOpen=false`.

## Architecture

High-level components:

- `internal/authz` — framework core: request model, policy matching, decision cache, authorizer, metrics, fail-closed behavior.
- `internal/authz/kafkaadapter` — Kafka-specific publish/consume adapter over the generic broker layer.
- `internal/authz/natsadapter` — NATS-specific publish/consume adapter over the generic broker layer.
- `policy-server` — centralized service that loads YAML policies, exposes `/v1/check`, supports reload, audit and Prometheus metrics.
- `services/orders` — demo client service and CLI driver for gRPC, REST, Kafka and NATS calls.
- `services/payments` — protected demo service exposing gRPC, REST, Kafka consumer and NATS subscriber paths.
- `deploy` — Docker Compose environment with policy-server, demo services, Kafka, NATS, Prometheus and Grafana.
- `scripts` — reproducible functional, degradation, chaos and benchmark scenarios.
- `results` — generated experiment artifacts and final summaries.

Core request shape:

```yaml
source: orders
target: payments
transport: grpc | http | broker
operation: <rpc method | HTTP method | publish | consume>
resource: <rpc wildcard | normalized route | topic/subject>
broker: <kafka | nats | *>
message_type: <event type | *>
```

The gRPC legacy policy field `rpc` is still supported and is normalized to:

```yaml
transport: grpc
operation: <rpc>
resource: "*"
```

## Policy Model

Policies are loaded from `policies/policies.yaml`.

Example rules:

```yaml
- id: R1
  source: orders
  target: payments
  rpc: /payments.v1.Payments/Charge
  effect: allow

- id: R_HTTP_1
  source: orders
  target: payments
  transport: http
  operation: POST
  resource: /payments/charge
  effect: allow

- id: R_KAFKA_1
  source: orders
  target: payments
  transport: broker
  broker: kafka
  operation: publish
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R_NATS_1
  source: orders
  target: payments
  transport: broker
  broker: nats
  operation: publish
  resource: payments.requested
  message_type: payment.requested.v1
  effect: allow

- id: R3
  source: "*"
  target: "*"
  transport: "*"
  operation: "*"
  resource: "*"
  effect: deny
```

Matching is first-match, so the final wildcard deny rule implements default deny.

For broker demos, message metadata uses:

- `X-Service-Name` — source service identity for the demo message contract;
- `X-Message-Type` — event type.

This is a demo transport contract. Production service identity for broker traffic should be backed by broker authentication, mTLS/SASL, message signatures, or another cryptographically protected mechanism.

## Requirements

- Docker;
- Docker Compose v2;
- OpenSSL;
- Go 1.24 for local builds and tests.

## Quick Start

Generate local demo certificates once:

```bash
make -C deploy certs
```

Start the full environment:

```bash
make -C deploy up
```

This starts:

- `policy-server`;
- `payments`;
- `orders`;
- Apache Kafka;
- NATS;
- Prometheus;
- Grafana.

Check service URLs:

```bash
make -C deploy status
```

## Basic Functional Checks

Run all transport demos:

```bash
make -C deploy test-all
```

Or run them separately:

```bash
make -C deploy test-grpc
make -C deploy test-rest
make -C deploy test-kafka
make -C deploy test-nats
```

Expected behavior:

- gRPC `Charge` is allowed;
- gRPC `Refund` is denied;
- REST `POST /payments/charge` is allowed;
- REST `POST /payments/refund` is denied;
- Kafka publish and consume of `payment.requested.v1` are allowed;
- Kafka forbidden publish `payment.refund.forced.v1` is denied;
- NATS publish and consume of `payment.requested.v1` are allowed;
- NATS forbidden publish `payment.refund.forced.v1` is denied.

## Reload, Audit and Fail-Closed

Reload policies without restarting services:

```bash
make -C deploy reload
```

View audit log:

```bash
make -C deploy audit
```

Run fail-closed degradation checks:

```bash
make -C deploy degrade-all
```

Individual degradation targets:

```bash
make -C deploy degrade-test
make -C deploy degrade-rest-test
make -C deploy degrade-kafka-test
make -C deploy degrade-kafka-consume-test
make -C deploy degrade-nats-test
make -C deploy degrade-nats-consume-test
```

These tests stop `policy-server` and verify that allowed interactions are blocked while the policy-server is unavailable.

## Chaos and Load Scenarios

Reload loop:

```bash
make -C deploy chaos-reload
```

Policy-server flap:

```bash
make -C deploy chaos-policy-flap
```

gRPC load test:

```bash
make -C deploy load
make -C deploy load-deny
make -C deploy load-matrix
```

Legacy `docker exec` benchmark:

```bash
make -C deploy bench
```

## Final Reproducible Experiments

Functional matrix for gRPC, REST, Kafka and NATS:

```bash
make -C deploy final-functional
```

Comparative latency/throughput benchmark:

```bash
make -C deploy final-bench
```

Full final suite:

```bash
make -C deploy final-suite
```

Short benchmark smoke:

```bash
FINAL_N=100 FINAL_C=10 FINAL_WARMUP=10 make -C deploy final-bench
```

Larger dissertation-oriented benchmark:

```bash
FINAL_N=1000 FINAL_C=50 FINAL_WARMUP=100 make -C deploy final-bench
```

Generated artifacts are saved under:

```text
results/final/<timestamp>/functional/
results/final/<timestamp>/bench/
```

Main artifacts:

- `summary.csv` — functional allow/deny/reload/degrade matrix;
- `bench_summary.csv` — latency and throughput per transport;
- `payments_metrics_*.prom` — authz metrics snapshots;
- `policy_metrics_*.prom` — policy-server metrics snapshots;
- `audit_*.log` — policy reload audit evidence;
- `docker_*.log` — service logs for async consume and fail-closed evidence.

## Metrics

Prometheus:

```text
http://localhost:9091
```

Payments metrics:

```text
http://localhost:9090/metrics
```

Key metrics:

- `authz_checks_total{result,transport,broker}` — authorization decisions at framework edge;
- `authz_cache_total{type,transport,broker}` — decision cache hit/miss;
- `authz_policy_check_latency_seconds{transport,broker}` — policy check latency;
- `authz_fail_closed_total` — fail-closed denials;
- `policy_decisions_total{result}` — policy-server decisions.

Grafana:

```text
http://localhost:3000
```

Default demo credentials:

```text
admin / admin
```

## Confirmed Properties

- centralized policy decisions through `policy-server`;
- transport-agnostic authorization request model;
- support for synchronous transports: gRPC and REST;
- support for asynchronous broker transports: Kafka and NATS;
- extensible broker adapter boundary;
- dynamic YAML policy reload without service restart;
- audit trail for administrative reload operations;
- decision cache with transport/broker-aware keys;
- fail-closed behavior when `policy-server` is unavailable;
- Prometheus metrics for decisions, cache, latency and fail-closed denials.

## Research Notes

Architecture summary for dissertation/presentation:

```text
docs/architecture-summary.md
```

Experiment summary:

```text
results/summary.md
```

## Security Notes

- Demo certificates are generated locally and ignored by git.
- Administrative token is demo-only.
- REST and gRPC demo identity use mTLS.
- Broker demo identity uses message headers for reproducibility; production deployments must bind message identity to broker-level or cryptographic authentication.
