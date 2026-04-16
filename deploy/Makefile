DEPLOY_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ROOT_DIR := $(abspath $(DEPLOY_DIR)/..)
COMPOSE := docker compose -f $(DEPLOY_DIR)/docker-compose.yml


.PHONY: certs up down build restart logs status audit reload \
	test test-grpc test-rest test-kafka test-nats test-all \
	bench load load-deny load-matrix final-functional final-bench final-suite final-demo \
	degrade-down degrade-up degrade-test degrade-rest-test degrade-kafka-test degrade-kafka-consume-test degrade-nats-test degrade-nats-consume-test degrade-all \
	chaos-reload chaos-policy-flap

certs:
	$(ROOT_DIR)/certs/generate-certs.sh

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

build:
	$(COMPOSE) build

restart:
	$(COMPOSE) down
	$(COMPOSE) up --build -d

logs:
	$(COMPOSE) logs -f

test:
	@echo "=== TEST allow: Charge ==="
	docker exec orders /app/orders charge
	@echo ""
	@echo "=== TEST deny: Refund ==="
	- docker exec orders /app/orders refund

test-grpc: test

test-rest:
	@echo "=== TEST REST allow: POST /payments/charge ==="
	docker exec orders /app/orders rest-charge
	@echo ""
	@echo "=== TEST REST deny: POST /payments/refund ==="
	- docker exec orders /app/orders rest-refund

test-kafka:
	@echo "=== TEST Kafka allow: orders publish payment.requested ==="
	docker exec orders /app/orders kafka-publish
	@echo ""
	@echo "=== TEST Kafka consume: payments processes payment.requested ==="
	@deadline=$$(( $$(date +%s) + 60 )); \
	while [ "$$(date +%s)" -lt "$$deadline" ]; do \
	  $(COMPOSE) logs --since=60s payments | grep -q "KAFKA CONSUME OK" && exit 0; \
	  sleep 2; \
	done; \
	$(COMPOSE) logs --tail=200 payments; \
	exit 1
	@echo ""
	@echo "=== TEST Kafka deny: forbidden forced refund publish ==="
	- docker exec orders /app/orders kafka-publish-deny

test-nats:
	@echo "=== TEST NATS allow: orders publish payment.requested ==="
	docker exec orders /app/orders nats-publish
	@echo ""
	@echo "=== TEST NATS consume: payments processes payment.requested ==="
	@deadline=$$(( $$(date +%s) + 20 )); \
	while [ "$$(date +%s)" -lt "$$deadline" ]; do \
	  $(COMPOSE) logs --since=20s payments | grep -q "NATS CONSUME OK" && exit 0; \
	  sleep 2; \
	done; \
	$(COMPOSE) logs --tail=200 payments; \
	exit 1
	@echo ""
	@echo "=== TEST NATS deny: forbidden forced refund publish ==="
	- docker exec orders /app/orders nats-publish-deny

test-all: test-grpc test-rest test-kafka test-nats

status:
	@echo "Prometheus: http://localhost:9091"
	@echo "Grafana:    http://localhost:3000 (admin/admin)"
	@echo "Policy metrics:   https://localhost:8443/metrics"
	@echo "Payments metrics: http://localhost:9090/metrics"
	@echo "Payments REST:    https://localhost:8080 (mTLS)"
	@echo "Kafka:            kafka:9092 inside docker network"
	@echo "NATS:             nats://nats:4222 inside docker network, monitoring http://localhost:8222"

reload:
	@echo "=== Reload policies (admin, mTLS) ==="
	curl -k -X POST https://localhost:8443/v1/policies/reload \
	  --cert $(ROOT_DIR)/certs/orders.pem --key $(ROOT_DIR)/certs/orders-key.pem --cacert $(ROOT_DIR)/certs/ca.pem \
	  -H "X-Admin-Token: dev-admin-token" -H "X-Actor: student"

audit:
	@echo "=== AUDIT LOG (admin, mTLS) ==="
	curl -k https://localhost:8443/v1/audit/tail \
	  --cert $(ROOT_DIR)/certs/orders.pem --key $(ROOT_DIR)/certs/orders-key.pem --cacert $(ROOT_DIR)/certs/ca.pem \
	  -H "X-Admin-Token: dev-admin-token" || true


bench:
	$(ROOT_DIR)/scripts/bench.sh charge 200

final-functional:
	$(ROOT_DIR)/scripts/final-functional.sh


final-bench:
	$(ROOT_DIR)/scripts/final-bench.sh


final-suite:
	$(ROOT_DIR)/scripts/final-suite.sh


final-demo: restart test-all status


load:
	cd $(ROOT_DIR) && go run ./cmd/loadtest \
	  -mode charge -n 5000 -c 50 \
	  -ca certs/ca.pem \
	  -cert certs/orders.pem \
	  -key certs/orders-key.pem \
	  -servername payments \
	  -addr localhost:50051


load-deny:
	cd $(ROOT_DIR) && go run ./cmd/loadtest \
	  -mode refund -n 5000 -c 50 \
	  -ca certs/ca.pem \
	  -cert certs/orders.pem \
	  -key certs/orders-key.pem \
	  -servername payments \
	  -addr localhost:50051


load-matrix:
	$(ROOT_DIR)/scripts/load-matrix.sh charge 5000




degrade-down:
	@echo "=== Degradation: stop policy-server ==="
	$(COMPOSE) stop policy-server

degrade-up:
	@echo "=== Degradation: start policy-server ==="
	$(COMPOSE) up -d policy-server

degrade-all: degrade-test degrade-rest-test degrade-kafka-test degrade-kafka-consume-test degrade-nats-test degrade-nats-consume-test

chaos-reload:
	$(ROOT_DIR)/scripts/reload-loop.sh 60 2

chaos-policy-flap:
	$(ROOT_DIR)/scripts/policy-flap.sh 60 3 7

degrade-test:
	@echo "=== Degradation test (fail-closed) ==="
	@echo "[1] Baseline check: policy-server up -> Charge should succeed"
	docker exec orders /app/orders charge
	@echo
	@echo "[2] Stop policy-server -> Charge should be denied (fail-closed)"
	$(COMPOSE) stop policy-server
	@sleep 1
	@echo "Calling charge while policy-server is DOWN..."
	@docker exec orders /app/orders charge && (echo "UNEXPECTED: charge succeeded" && exit 1) || echo "OK: denied as expected"
	@echo
	@echo "[3] Start policy-server -> Charge should succeed again"
	$(COMPOSE) up -d policy-server
	@sleep 1
	docker exec orders /app/orders charge
	@echo
	@echo "[+] Degradation test finished"


degrade-rest-test:
	@echo "=== REST degradation test (fail-closed) ==="
	@echo "[1] Baseline check: policy-server up -> REST charge should succeed"
	docker exec orders /app/orders rest-charge
	@echo
	@echo "[2] Stop policy-server -> REST charge should be denied (fail-closed)"
	$(COMPOSE) stop policy-server
	@sleep 1
	@echo "Calling REST charge while policy-server is DOWN..."
	@docker exec orders /app/orders rest-charge && (echo "UNEXPECTED: REST charge succeeded" && exit 1) || echo "OK: denied as expected"
	@echo
	@echo "[3] Start policy-server -> REST charge should succeed again"
	$(COMPOSE) up -d policy-server
	@sleep 1
	docker exec orders /app/orders rest-charge
	@echo
	@echo "[+] REST degradation test finished"


degrade-kafka-test:
	@echo "=== Kafka publish degradation test (fail-closed) ==="
	@echo "[1] Baseline check: policy-server up -> Kafka publish should succeed"
	docker exec orders /app/orders kafka-publish
	@echo
	@echo "[2] Stop policy-server -> Kafka publish should be denied (fail-closed)"
	$(COMPOSE) stop policy-server
	@sleep 1
	@docker exec orders /app/orders kafka-publish && (echo "UNEXPECTED: Kafka publish succeeded" && exit 1) || echo "OK: denied as expected"
	@echo
	@echo "[3] Start policy-server -> Kafka publish should succeed again"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders kafka-publish
	@echo
	@echo "[+] Kafka publish degradation test finished"


degrade-kafka-consume-test:
	@echo "=== Kafka consume degradation test (fail-closed) ==="
	@echo "[1] Stop payments consumer and inject an authorized-format message directly into Kafka"
	$(COMPOSE) stop payments
	docker exec orders /app/orders kafka-publish-raw
	@echo
	@echo "[2] Stop policy-server and start payments -> consume should be denied before processing"
	$(COMPOSE) stop policy-server
	docker start payments
	@sleep 35
	@$(COMPOSE) logs --since=45s payments | grep "KAFKA CONSUME DENY" && echo "OK: consume denied as expected" || (echo "MISSING: Kafka consume deny log" && exit 1)
	@echo
	@echo "[3] Restore policy-server and verify Kafka publish/consume recovers"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders kafka-publish
	@sleep 10
	$(COMPOSE) logs --since=20s payments | grep "KAFKA CONSUME OK"
	@echo
	@echo "[+] Kafka consume degradation test finished"


degrade-nats-test:
	@echo "=== NATS publish degradation test (fail-closed) ==="
	@echo "[1] Baseline check: policy-server up -> NATS publish should succeed"
	docker exec orders /app/orders nats-publish
	@echo
	@echo "[2] Stop policy-server -> NATS publish should be denied (fail-closed)"
	$(COMPOSE) stop policy-server
	@sleep 1
	@docker exec orders /app/orders nats-publish && (echo "UNEXPECTED: NATS publish succeeded" && exit 1) || echo "OK: denied as expected"
	@echo
	@echo "[3] Start policy-server -> NATS publish should succeed again"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders nats-publish
	@echo
	@echo "[+] NATS publish degradation test finished"


degrade-nats-consume-test:
	@echo "=== NATS consume degradation test (fail-closed) ==="
	@echo "[1] Baseline check: policy-server up -> NATS consume should succeed"
	docker exec orders /app/orders nats-publish
	@sleep 2
	$(COMPOSE) logs --since=20s payments | grep "NATS CONSUME OK"
	@echo
	@echo "[2] Stop policy-server and inject an authorized-format message directly into NATS"
	$(COMPOSE) stop policy-server
	@sleep 1
	docker exec orders /app/orders nats-publish-raw
	@sleep 3
	@$(COMPOSE) logs --since=15s payments | grep "NATS CONSUME DENY" && echo "OK: consume denied as expected" || (echo "MISSING: NATS consume deny log" && exit 1)
	@echo
	@echo "[3] Restore policy-server and verify NATS publish/consume recovers"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders nats-publish
	@sleep 3
	$(COMPOSE) logs --since=20s payments | grep "NATS CONSUME OK"
	@echo
	@echo "[+] NATS consume degradation test finished"
