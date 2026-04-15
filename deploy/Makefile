COMPOSE=docker compose -f docker-compose.yml


.PHONY: certs up down build restart logs test test-rest test-kafka test-nats status audit reload bench final-functional final-bench final-suite degrade-test degrade-rest-test degrade-kafka-test degrade-kafka-consume-test degrade-nats-test degrade-nats-consume-test

certs:
	./certs/generate-certs.sh

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

test-rest:
	@echo "=== TEST REST allow: POST /payments/charge ==="
	docker exec orders /app/orders rest-charge
	@echo ""
	@echo "=== TEST REST deny: POST /payments/refund ==="
	- docker exec orders /app/orders rest-refund

test-kafka:
	@echo "=== TEST Kafka allow: orders publish payment.requested ==="
	docker exec orders /app/orders kafka-publish
	@sleep 3
	@echo ""
	@echo "=== TEST Kafka consume: payments processes payment.requested ==="
	docker compose -f docker-compose.yml logs --tail=120 payments | grep "KAFKA CONSUME OK"
	@echo ""
	@echo "=== TEST Kafka deny: forbidden forced refund publish ==="
	- docker exec orders /app/orders kafka-publish-deny

test-nats:
	@echo "=== TEST NATS allow: orders publish payment.requested ==="
	docker exec orders /app/orders nats-publish
	@sleep 2
	@echo ""
	@echo "=== TEST NATS consume: payments processes payment.requested ==="
	docker compose -f docker-compose.yml logs --since=20s payments | grep "NATS CONSUME OK"
	@echo ""
	@echo "=== TEST NATS deny: forbidden forced refund publish ==="
	- docker exec orders /app/orders nats-publish-deny

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
	  --cert ../certs/orders.pem --key ../certs/orders-key.pem --cacert ../certs/ca.pem \
	  -H "X-Admin-Token: dev-admin-token" -H "X-Actor: student"

audit:
	@echo "=== AUDIT LOG (admin, mTLS) ==="
	curl -k https://localhost:8443/v1/audit/tail \
	  --cert ../certs/orders.pem --key ../certs/orders-key.pem --cacert ../certs/ca.pem \
	  -H "X-Admin-Token: dev-admin-token" || true


bench:
	../scripts/bench.sh charge 200

final-functional:
	../scripts/final-functional.sh


final-bench:
	../scripts/final-bench.sh


final-suite:
	../scripts/final-suite.sh


load:
	go run ../cmd/loadtest \
	  -mode charge -n 5000 -c 50 \
	  -ca ../certs/ca.pem \
	  -cert ../certs/orders.pem \
	  -key ../certs/orders-key.pem \
	  -servername payments \
	  -addr localhost:50051


load-deny:
	go run ../cmd/loadtest \
	  -mode refund -n 5000 -c 50 \
	  -ca ../certs/ca.pem \
	  -cert ../certs/orders.pem \
	  -key ../certs/orders-key.pem \
	  -servername payments \
	  -addr localhost:50051


load-matrix:
	../scripts/load-matrix.sh charge 5000




degrade-down:
	@echo "=== Degradation: stop policy-server ==="
	docker compose -f docker-compose.yml stop policy-server

degrade-up:
	@echo "=== Degradation: start policy-server ==="
	docker compose -f docker-compose.yml up -d policy-server

degrade-test:
	@echo "=== Degradation test (fail-closed) ==="
	@echo "[1] Baseline check: policy-server up -> Charge should succeed"
	docker exec orders /app/orders charge
	@echo
	@echo "[2] Stop policy-server -> Charge should be denied (fail-closed)"
	docker compose -f docker-compose.yml stop policy-server
	@sleep 1
	@echo "Calling charge while policy-server is DOWN..."
	@docker exec orders /app/orders charge && (echo "UNEXPECTED: charge succeeded" && exit 1) || echo "OK: denied as expected"
	@echo
	@echo "[3] Start policy-server -> Charge should succeed again"
	docker compose -f docker-compose.yml up -d policy-server
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
	docker compose -f docker-compose.yml stop policy-server
	@sleep 1
	@echo "Calling REST charge while policy-server is DOWN..."
	@docker exec orders /app/orders rest-charge && (echo "UNEXPECTED: REST charge succeeded" && exit 1) || echo "OK: denied as expected"
	@echo
	@echo "[3] Start policy-server -> REST charge should succeed again"
	docker compose -f docker-compose.yml up -d policy-server
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
	docker compose -f docker-compose.yml stop policy-server
	@sleep 1
	@docker exec orders /app/orders kafka-publish && (echo "UNEXPECTED: Kafka publish succeeded" && exit 1) || echo "OK: denied as expected"
	@echo
	@echo "[3] Start policy-server -> Kafka publish should succeed again"
	docker compose -f docker-compose.yml up -d policy-server
	@sleep 3
	docker exec orders /app/orders kafka-publish
	@echo
	@echo "[+] Kafka publish degradation test finished"


degrade-kafka-consume-test:
	@echo "=== Kafka consume degradation test (fail-closed) ==="
	@echo "[1] Stop payments consumer and inject an authorized-format message directly into Kafka"
	docker compose -f docker-compose.yml stop payments
	docker exec orders /app/orders kafka-publish-raw
	@echo
	@echo "[2] Stop policy-server and start payments -> consume should be denied before processing"
	docker compose -f docker-compose.yml stop policy-server
	docker start payments
	@sleep 35
	@docker compose -f docker-compose.yml logs --since=45s payments | grep "KAFKA CONSUME DENY" && echo "OK: consume denied as expected" || (echo "MISSING: Kafka consume deny log" && exit 1)
	@echo
	@echo "[3] Restore policy-server and verify Kafka publish/consume recovers"
	docker compose -f docker-compose.yml up -d policy-server
	@sleep 3
	docker exec orders /app/orders kafka-publish
	@sleep 10
	docker compose -f docker-compose.yml logs --since=20s payments | grep "KAFKA CONSUME OK"
	@echo
	@echo "[+] Kafka consume degradation test finished"


degrade-nats-test:
	@echo "=== NATS publish degradation test (fail-closed) ==="
	@echo "[1] Baseline check: policy-server up -> NATS publish should succeed"
	docker exec orders /app/orders nats-publish
	@echo
	@echo "[2] Stop policy-server -> NATS publish should be denied (fail-closed)"
	docker compose -f docker-compose.yml stop policy-server
	@sleep 1
	@docker exec orders /app/orders nats-publish && (echo "UNEXPECTED: NATS publish succeeded" && exit 1) || echo "OK: denied as expected"
	@echo
	@echo "[3] Start policy-server -> NATS publish should succeed again"
	docker compose -f docker-compose.yml up -d policy-server
	@sleep 3
	docker exec orders /app/orders nats-publish
	@echo
	@echo "[+] NATS publish degradation test finished"


degrade-nats-consume-test:
	@echo "=== NATS consume degradation test (fail-closed) ==="
	@echo "[1] Baseline check: policy-server up -> NATS consume should succeed"
	docker exec orders /app/orders nats-publish
	@sleep 2
	docker compose -f docker-compose.yml logs --since=20s payments | grep "NATS CONSUME OK"
	@echo
	@echo "[2] Stop policy-server and inject an authorized-format message directly into NATS"
	docker compose -f docker-compose.yml stop policy-server
	@sleep 1
	docker exec orders /app/orders nats-publish-raw
	@sleep 3
	@docker compose -f docker-compose.yml logs --since=15s payments | grep "NATS CONSUME DENY" && echo "OK: consume denied as expected" || (echo "MISSING: NATS consume deny log" && exit 1)
	@echo
	@echo "[3] Restore policy-server and verify NATS publish/consume recovers"
	docker compose -f docker-compose.yml up -d policy-server
	@sleep 3
	docker exec orders /app/orders nats-publish
	@sleep 3
	docker compose -f docker-compose.yml logs --since=20s payments | grep "NATS CONSUME OK"
	@echo
	@echo "[+] NATS consume degradation test finished"
