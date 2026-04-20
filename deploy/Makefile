DEPLOY_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ROOT_DIR := $(abspath $(DEPLOY_DIR)/..)
COMPOSE := docker compose -f $(DEPLOY_DIR)/docker-compose.yml


.PHONY: certs up down build restart logs status audit reload \
	test test-grpc test-rest test-kafka test-nats test-all \
	bench load load-deny load-matrix final-functional final-bench final-suite final-run \
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
	@echo "=== ПРОВЕРКА: Charge должен пройти ==="
	docker exec orders /app/orders charge
	@echo ""
	@echo "=== ПРОВЕРКА: Refund должен быть запрещен ==="
	- docker exec orders /app/orders refund

test-grpc: test

test-rest:
	@echo "=== ПРОВЕРКА REST: POST /payments/charge должен пройти ==="
	docker exec orders /app/orders rest-charge
	@echo ""
	@echo "=== ПРОВЕРКА REST: POST /payments/refund должен быть запрещен ==="
	- docker exec orders /app/orders rest-refund

test-kafka:
	@echo "=== ПРОВЕРКА Kafka: публикация payment.requested должна пройти ==="
	docker exec orders /app/orders kafka-publish
	@echo ""
	@echo "=== ПРОВЕРКА Kafka: payments должен обработать payment.requested ==="
	@deadline=$$(( $$(date +%s) + 60 )); \
	while [ "$$(date +%s)" -lt "$$deadline" ]; do \
	  $(COMPOSE) logs --since=60s payments | grep -q "KAFKA CONSUME OK" && exit 0; \
	  sleep 2; \
	done; \
	$(COMPOSE) logs --tail=200 payments; \
	exit 1
	@echo ""
	@echo "=== ПРОВЕРКА Kafka: запрещенная публикация принудительного возврата ==="
	- docker exec orders /app/orders kafka-publish-deny

test-nats:
	@echo "=== ПРОВЕРКА NATS: публикация payment.requested должна пройти ==="
	docker exec orders /app/orders nats-publish
	@echo ""
	@echo "=== ПРОВЕРКА NATS: payments должен обработать payment.requested ==="
	@deadline=$$(( $$(date +%s) + 20 )); \
	while [ "$$(date +%s)" -lt "$$deadline" ]; do \
	  $(COMPOSE) logs --since=20s payments | grep -q "NATS CONSUME OK" && exit 0; \
	  sleep 2; \
	done; \
	$(COMPOSE) logs --tail=200 payments; \
	exit 1
	@echo ""
	@echo "=== ПРОВЕРКА NATS: запрещенная публикация принудительного возврата ==="
	- docker exec orders /app/orders nats-publish-deny

test-all: test-grpc test-rest test-kafka test-nats

status:
	@echo "Prometheus: http://localhost:9091"
	@echo "Grafana:    http://localhost:3000 (admin/admin)"
	@echo "Метрики policy-server: https://localhost:8443/metrics"
	@echo "Метрики payments:      http://localhost:9090/metrics"
	@echo "REST payments:         https://localhost:8080 (mTLS)"
	@echo "Kafka:            kafka:9092 внутри сети Docker"
	@echo "NATS:             nats://nats:4222 внутри сети Docker, наблюдение http://localhost:8222"

reload:
	@echo "=== Перезагрузка политик (администратор, mTLS) ==="
	curl -k -X POST https://localhost:8443/v1/policies/reload \
	  --cert $(ROOT_DIR)/certs/orders.pem --key $(ROOT_DIR)/certs/orders-key.pem --cacert $(ROOT_DIR)/certs/ca.pem \
	  -H "X-Admin-Token: dev-admin-token" -H "X-Actor: student"

audit:
	@echo "=== Журнал аудита (администратор, mTLS) ==="
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


final-run: restart test-all status


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
	@echo "=== Проверка отказа: остановка policy-server ==="
	$(COMPOSE) stop policy-server

degrade-up:
	@echo "=== Проверка отказа: запуск policy-server ==="
	$(COMPOSE) up -d policy-server

degrade-all: degrade-test degrade-rest-test degrade-kafka-test degrade-kafka-consume-test degrade-nats-test degrade-nats-consume-test

chaos-reload:
	$(ROOT_DIR)/scripts/reload-loop.sh 60 2

chaos-policy-flap:
	$(ROOT_DIR)/scripts/policy-flap.sh 60 3 7

degrade-test:
	@echo "=== Проверка запрета при отказе ==="
	@echo "[1] Базовая проверка: policy-server доступен -> Charge должен пройти"
	docker exec orders /app/orders charge
	@echo
	@echo "[2] Остановить policy-server -> Charge должен быть запрещен"
	$(COMPOSE) stop policy-server
	@sleep 1
	@echo "Вызов charge при недоступном policy-server..."
	@docker exec orders /app/orders charge && (echo "НЕОЖИДАННО: charge прошел" && exit 1) || echo "ОК: запрос запрещен, как ожидалось"
	@echo
	@echo "[3] Запустить policy-server -> Charge снова должен пройти"
	$(COMPOSE) up -d policy-server
	@sleep 1
	docker exec orders /app/orders charge
	@echo
	@echo "[+] Проверка отказа завершена"


degrade-rest-test:
	@echo "=== REST: проверка запрета при отказе ==="
	@echo "[1] Базовая проверка: policy-server доступен -> REST charge должен пройти"
	docker exec orders /app/orders rest-charge
	@echo
	@echo "[2] Остановить policy-server -> REST charge должен быть запрещен"
	$(COMPOSE) stop policy-server
	@sleep 1
	@echo "Вызов REST charge при недоступном policy-server..."
	@docker exec orders /app/orders rest-charge && (echo "НЕОЖИДАННО: REST charge прошел" && exit 1) || echo "ОК: запрос запрещен, как ожидалось"
	@echo
	@echo "[3] Запустить policy-server -> REST charge снова должен пройти"
	$(COMPOSE) up -d policy-server
	@sleep 1
	docker exec orders /app/orders rest-charge
	@echo
	@echo "[+] REST: проверка отказа завершена"


degrade-kafka-test:
	@echo "=== Kafka: проверка запрета публикации при отказе ==="
	@echo "[1] Базовая проверка: policy-server доступен -> публикация Kafka должна пройти"
	docker exec orders /app/orders kafka-publish
	@echo
	@echo "[2] Остановить policy-server -> публикация Kafka должна быть запрещена"
	$(COMPOSE) stop policy-server
	@sleep 1
	@docker exec orders /app/orders kafka-publish && (echo "НЕОЖИДАННО: публикация Kafka прошла" && exit 1) || echo "ОК: запрос запрещен, как ожидалось"
	@echo
	@echo "[3] Запустить policy-server -> публикация Kafka снова должна пройти"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders kafka-publish
	@echo
	@echo "[+] Kafka: проверка отказа публикации завершена"


degrade-kafka-consume-test:
	@echo "=== Kafka: проверка запрета обработки при отказе ==="
	@echo "[1] Остановить получатель payments и записать сообщение напрямую в Kafka"
	$(COMPOSE) stop payments
	docker exec orders /app/orders kafka-publish-raw
	@echo
	@echo "[2] Остановить policy-server и запустить payments -> обработка должна быть запрещена"
	$(COMPOSE) stop policy-server
	docker start payments
	@sleep 35
	@$(COMPOSE) logs --since=45s payments | grep "KAFKA CONSUME DENY" && echo "ОК: обработка запрещена, как ожидалось" || (echo "НЕ НАЙДЕН: журнал запрета обработки Kafka" && exit 1)
	@echo
	@echo "[3] Восстановить policy-server и проверить восстановление публикации и обработки Kafka"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders kafka-publish
	@sleep 10
	$(COMPOSE) logs --since=20s payments | grep "KAFKA CONSUME OK"
	@echo
	@echo "[+] Kafka: проверка отказа обработки завершена"


degrade-nats-test:
	@echo "=== NATS: проверка запрета публикации при отказе ==="
	@echo "[1] Базовая проверка: policy-server доступен -> публикация NATS должна пройти"
	docker exec orders /app/orders nats-publish
	@echo
	@echo "[2] Остановить policy-server -> публикация NATS должна быть запрещена"
	$(COMPOSE) stop policy-server
	@sleep 1
	@docker exec orders /app/orders nats-publish && (echo "НЕОЖИДАННО: публикация NATS прошла" && exit 1) || echo "ОК: запрос запрещен, как ожидалось"
	@echo
	@echo "[3] Запустить policy-server -> публикация NATS снова должна пройти"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders nats-publish
	@echo
	@echo "[+] NATS: проверка отказа публикации завершена"


degrade-nats-consume-test:
	@echo "=== NATS: проверка запрета обработки при отказе ==="
	@echo "[1] Базовая проверка: policy-server доступен -> обработка NATS должна пройти"
	docker exec orders /app/orders nats-publish
	@sleep 2
	$(COMPOSE) logs --since=20s payments | grep "NATS CONSUME OK"
	@echo
	@echo "[2] Остановить policy-server и отправить сообщение напрямую в NATS"
	$(COMPOSE) stop policy-server
	@sleep 1
	docker exec orders /app/orders nats-publish-raw
	@sleep 3
	@$(COMPOSE) logs --since=15s payments | grep "NATS CONSUME DENY" && echo "ОК: обработка запрещена, как ожидалось" || (echo "НЕ НАЙДЕН: журнал запрета обработки NATS" && exit 1)
	@echo
	@echo "[3] Восстановить policy-server и проверить восстановление публикации и обработки NATS"
	$(COMPOSE) up -d policy-server
	@sleep 3
	docker exec orders /app/orders nats-publish
	@sleep 3
	$(COMPOSE) logs --since=20s payments | grep "NATS CONSUME OK"
	@echo
	@echo "[+] NATS: проверка отказа обработки завершена"
