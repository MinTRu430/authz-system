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


