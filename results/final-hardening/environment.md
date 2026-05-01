# Окружение финальных экспериментов

Дата: 2026-05-01T15:57:32+03:00

Ветка: production-hardening

Commit: 31bb641

Go: go version go1.25.5 linux/amd64

Docker: Docker version 29.4.0, build 9d7ad9f

Docker Compose: Docker Compose version v5.1.3

## Сервисы

- `policy-server-1`: `https://localhost:8443`
- `policy-server-2`: `https://localhost:8444`
- `policy-server-3`: `https://localhost:8445`
- `payments`: gRPC `localhost:50051`, REST `https://localhost:8080`, metrics `http://localhost:9090/metrics`
- `orders`
- Apache Kafka `apache/kafka:4.2.0`
- NATS `nats:2.10.29`
- Prometheus `http://localhost:9091`
- Grafana `http://localhost:3000`

Control-plane работает в режиме трех реплик `policy-server`.

## Production-like возможности

- indexed policy matching;
- application-level mTLS health check `/v1/health`;
- circuit breaker/backoff;
- multi-endpoint failover;
- HMAC signing для Kafka/NATS сообщений;
- retry/DLQ для Kafka/NATS;
- расширенные Prometheus metrics;
- optional OpenTelemetry tracing.
