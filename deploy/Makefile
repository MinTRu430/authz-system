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
	@echo "=== ТЕСТ allow: Charge ==="
	docker exec orders /app/orders charge
	@echo ""
	@echo "=== ТЕСТ deny: Refund ==="
	- docker exec orders /app/orders refund

test-grpc: test

test-rest:
	@echo "=== ТЕСТ REST allow: POST /payments/charge ==="
	docker exec orders /app/orders rest-charge
	@echo ""
	@echo "=== ТЕСТ REST deny: POST /payments/refund ==="
	- docker exec orders /app/orders rest-refund

test-kafka:
	@echo "=== ТЕСТ Kafka allow: orders publish payment.requested ==="
	docker exec orders /app/orders kafka-publish
	@echo ""
	@echo "=== ТЕСТ Kafka consume: payments processes payment.requested ==="
	@deadline=$$(( $$(date +%s) + 60 )); \
	while [ "$$(date +%s)" -lt "$$deadline" ]; do \
	  $(COMPOSE) logs --since=60s payments | grep -q "KAFKA CONSUME OK" && exit 0; \
	  sleep 2; \
	done; \
	$(COMPOSE) logs --tail=200 payments; \
	exit 1
	@echo ""
	@echo "=== ТЕСТ Kafka deny: forbidden forced refund publish ==="
	- docker exec orders /app/orders kafka-publish-deny

test-nats:
	@echo "=== ТЕСТ NATS allow: orders publish payment.requested ==="
	docker exec orders /app/orders nats-publish
	@echo ""
	@echo "=== ТЕСТ NATS consume: payments processes payment.requested ==="
	@deadline=$$(( $$(date +%s) + 20 )); \
	while [ "$$(date +%s)" -lt "$$deadline" ]; do \
	  $(COMPOSE) logs --since=20s payments | grep -q "NATS CONSUME OK" && exit 0; \
	  sleep 2; \
	done; \
	$(COMPOSE) logs --tail=200 payments; \
	exit 1
	@echo ""
	@echo "=== ТЕСТ NATS deny: forbidden forced refund publish ==="
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
	@echo "=== Перезагрузка policies (admin, mTLS) ==="
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
	@echo "=== Degradation: остановка policy-server ==="
	$(COMPOSE) stop policy-server

degrade-up:
	@echo "=== Degradation: запуск policy-server ==="
	$(COMPOSE) up -d policy-server

degrade-all: degrade-test degrade-rest-test degrade-kafka-test degrade-kafka-consume-test degrade-nats-test degrade-nats-consume-test

chaos-reload:
	$(ROOT_DIR)/scripts/reload-loop.sh 60 2

chaos-policy-flap:
	$(ROOT_DIR)/scripts/policy-flap.sh 60 3 7

degrade-test:
	@echo "=== Degradation test (fail-closed) ==="
	@echo "[1] Базовая проверка: policy-server доступен -> Charge должен пройти"
	docker exec orders /app/orders charge
	@echo
	@echo "[2] Остановить policy-server -> Charge должен быть запрещен (fail-closed)"
	$(COMPOSE) stop policy-server
	@sleep 1
	@echo "Вызов charge при недоступном policy-server..."
	@docker exec orders /app/orders charge && (echo "НЕОЖИДАННО: charge прошел" && exit 1) || echo "OK: запрос запрещен, как ожидалось"
	@echo
	@echo "[3] Запустить policy-server -> Charge снова должен пройти"
	$(COMPOSE) up -d policy-server
	@sleep 1
	docker exec orders /app/orders charge
	@echo
	@echo "[+] Degradation test завершен"


degrade-rest-test:
	@echo "=== REST degradation test (fail-closed) ==="
	@echo "[1] Базовая проверка: policy-server доступен -> REST charge должен пройти"
	docker exec orders /app/orders rest-charge
	@echo
	@echo "[2] Остановить policy-server -> REST charge должен быть запрещен (fail-closed)"
	$(COMPOSE) stop policy-server
	@sleep 1
	@echo "Вызов REST charge при недоступном policy-server..."
	@docker exec orders /app/orders rest-charge && (echo "НЕОЖИДАННО: REST charge прошел" && exit 1) || echo "OK: запрос запрещен, как ожидалось"
	@echo
	@echo "[3] Запустить policy-server -> REST charge снова должен пройти"
	$(COMPOSE) up -d policy-server
	@sleep 1
	docker exec orders /app/orders rest-charge
	@echo
	@echo "[+] REST degradation test завершен"


degrade-kafka-test:
	@echo "=== Kafka publish degradation test (fail-closed) ==="
	@echo "[1] Базовая проверка: policy-server доступен -> Kafka publish должен пройти"
	docker exec orders /app/orders kafka-publish
	@echo
	@echo "[2] Остановить policy-server -> Kafka publish должен быть запрещен (fail-closed)"
	$(COMPOSE) stop policy-server
	@sleep 1
	@docker exec orders /app/orders kafka-publish && (echo "НЕОЖИДАННО: Kafka publish прошел" && exit 1) || echo "OK: запрос запрещен, как ожидалось"
	@echo
	@echo "[3] Запустить policy-server -> Kafka publish снова должен пройти"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders kafka-publish
	@echo
	@echo "[+] Kafka publish degradation test завершен"


degrade-kafka-consume-test:
	@echo "=== Kafka consume degradation test (fail-closed) ==="
	@echo "[1] Остановить payments consumer и записать authorized-format message напрямую в Kafka"
	$(COMPOSE) stop payments
	docker exec orders /app/orders kafka-publish-raw
	@echo
	@echo "[2] Остановить policy-server и запустить payments -> consume должен быть запрещен до обработки"
	$(COMPOSE) stop policy-server
	docker start payments
	@sleep 35
	@$(COMPOSE) logs --since=45s payments | grep "KAFKA CONSUME DENY" && echo "OK: consume запрещен, как ожидалось" || (echo "НЕ НАЙДЕН: Kafka consume deny log" && exit 1)
	@echo
	@echo "[3] Восстановить policy-server и проверить восстановление Kafka publish/consume"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders kafka-publish
	@sleep 10
	$(COMPOSE) logs --since=20s payments | grep "KAFKA CONSUME OK"
	@echo
	@echo "[+] Kafka consume degradation test завершен"


degrade-nats-test:
	@echo "=== NATS publish degradation test (fail-closed) ==="
	@echo "[1] Базовая проверка: policy-server доступен -> NATS publish должен пройти"
	docker exec orders /app/orders nats-publish
	@echo
	@echo "[2] Остановить policy-server -> NATS publish должен быть запрещен (fail-closed)"
	$(COMPOSE) stop policy-server
	@sleep 1
	@docker exec orders /app/orders nats-publish && (echo "НЕОЖИДАННО: NATS publish прошел" && exit 1) || echo "OK: запрос запрещен, как ожидалось"
	@echo
	@echo "[3] Запустить policy-server -> NATS publish снова должен пройти"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders nats-publish
	@echo
	@echo "[+] NATS publish degradation test завершен"


degrade-nats-consume-test:
	@echo "=== NATS consume degradation test (fail-closed) ==="
	@echo "[1] Базовая проверка: policy-server доступен -> NATS consume должен пройти"
	docker exec orders /app/orders nats-publish
	@sleep 2
	$(COMPOSE) logs --since=20s payments | grep "NATS CONSUME OK"
	@echo
	@echo "[2] Остановить policy-server и отправить authorized-format message напрямую в NATS"
	$(COMPOSE) stop policy-server
	@sleep 1
	docker exec orders /app/orders nats-publish-raw
	@sleep 3
	@$(COMPOSE) logs --since=15s payments | grep "NATS CONSUME DENY" && echo "OK: consume запрещен, как ожидалось" || (echo "НЕ НАЙДЕН: NATS consume deny log" && exit 1)
	@echo
	@echo "[3] Восстановить policy-server и проверить восстановление NATS publish/consume"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders nats-publish
	@sleep 3
	$(COMPOSE) logs --since=20s payments | grep "NATS CONSUME OK"
	@echo
	@echo "[+] NATS consume degradation test завершен"
