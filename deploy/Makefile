COMPOSE=docker compose -f docker-compose.yml


.PHONY: certs up down build restart logs test status audit reload bench

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

status:
	@echo "Prometheus: http://localhost:9091"
	@echo "Grafana:    http://localhost:3000 (admin/admin)"
	@echo "Policy metrics:   https://localhost:8443/metrics"
	@echo "Payments metrics: http://localhost:9090/metrics"

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

