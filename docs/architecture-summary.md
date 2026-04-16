# Architecture Summary

This document summarizes the final architecture of `authz-system` for dissertation and presentation use.

## Goal

The project implements a transport-agnostic framework for centralized authorization of inter-service communication. It demonstrates that the same authorization core can protect synchronous and asynchronous interactions without embedding transport-specific logic into the policy engine.

Supported transports:

- gRPC;
- HTTP/REST;
- Kafka;
- NATS.

## Core Authorization Layer

The framework core lives in `internal/authz`.

Responsibilities:

- define the common `AuthzRequest` model;
- normalize legacy gRPC rules and transport-specific requests;
- evaluate policy decisions returned by `policy-server`;
- cache decisions using transport-aware keys;
- enforce fail-closed behavior when `FailOpen=false`;
- export Prometheus metrics.

Common request fields:

- `source`;
- `target`;
- `transport`;
- `operation`;
- `resource`;
- `broker`;
- `message_type`.

The core does not depend on Kafka, NATS, HTTP routing internals or gRPC protobuf definitions.

## Policy Server

`policy-server` is the centralized decision point.

Responsibilities:

- load YAML policy rules;
- expose `/v1/check` for authorization decisions;
- expose `/v1/policies/reload` for dynamic reload;
- write audit events for administrative reload operations;
- expose Prometheus metrics;
- apply default-deny semantics through policy ordering.

Policies are mounted as a directory in Docker Compose so reload sees file updates without restarting the container.

## gRPC Adapter

The gRPC adapter is implemented as unary and stream interceptors.

Flow:

1. Extract caller service identity from mTLS.
2. Read the full gRPC method name.
3. Build an `AuthzRequest` with `transport=grpc`.
4. Call the core authorizer.
5. Allow the handler or return `PermissionDenied`.

Legacy `rpc` policy rules are preserved for backward compatibility.

## REST Adapter

The REST adapter is implemented as HTTP middleware.

Flow:

1. Extract caller service identity from mTLS.
2. Normalize the route path without query parameters.
3. Use HTTP method as `operation`.
4. Build an `AuthzRequest` with `transport=http`.
5. Allow the handler or return `403 Forbidden`.

Demo endpoints:

- `POST /payments/charge`;
- `POST /payments/refund`.

## Broker Abstraction Layer

The generic broker layer defines publish/consume authorization boundaries.

Common async interaction fields:

- source service;
- target logical service;
- broker name;
- operation: `publish` or `consume`;
- resource: topic, subject or queue;
- message type.

This layer lets broker-specific adapters normalize messages into the same core model.

## Kafka Adapter

The Kafka adapter protects:

- producer publish;
- consumer processing.

Demo flow:

1. `orders` publishes `payment.requested.v1` to topic `payments.requested`.
2. `payments` consumes the message.
3. Publish and consume both perform authorization checks.

Demo metadata headers:

- `X-Service-Name`;
- `X-Message-Type`.

## NATS Adapter

The NATS adapter implements the same broker contract for NATS subjects.

Demo flow:

1. `orders` publishes `payment.requested.v1` to subject `payments.requested`.
2. `payments` receives and authorizes before processing.
3. Forbidden publish to `payments.refund.forced` is denied.

This confirms the broker abstraction can support multiple brokers without changing core logic.

## Cache

The decision cache is part of the framework core.

Cache key fields:

- source;
- target;
- transport;
- operation;
- resource;
- broker;
- message type.

The cache distinguishes gRPC, REST, Kafka and NATS interactions. A fail-open-through-cache defect was fixed: allow cache hits still probe policy-server availability when `FailOpen=false`, so an unavailable policy-server causes fail-closed denial.

## Fail-Closed

When `FailOpen=false`, any policy-server unavailability results in denial.

Confirmed cases:

- gRPC request blocked;
- REST request blocked;
- Kafka publish blocked;
- Kafka consume processing blocked;
- NATS publish blocked;
- NATS consume processing blocked.

Metric:

- `authz_fail_closed_total`.

## Observability

Metrics:

- `authz_checks_total{result,transport,broker}`;
- `authz_cache_total{type,transport,broker}`;
- `authz_policy_check_latency_seconds{transport,broker}`;
- `authz_fail_closed_total`;
- `policy_decisions_total{result}`.

Monitoring stack:

- Prometheus;
- Grafana;
- policy reload audit log.

## Architectural Properties

Confirmed properties:

- centralized authorization decision point;
- transport-agnostic core request model;
- reusable policy model for sync and async interactions;
- adapter-based extension model;
- support for multiple brokers;
- dynamic policy reload;
- fail-closed safety;
- decision caching;
- reproducible Docker demo environment;
- reproducible functional and benchmark experiment scripts.
