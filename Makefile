.PHONY: help up down test check-clean

help:
	@echo "php2shell research lab targets:"
	@echo "  make up          - Start reproducible test containers (8.4.26 on :18080, 8.4.27 on :18081)"
	@echo "  make down        - Stop and remove test containers"
	@echo "  make test        - Run unit tests for tooling/checker"
	@echo "  make audit-lab   - Run non-destructive checker against local lab containers"

up:
	docker compose -f tooling/docker-compose.yml up -d

down:
	docker compose -f tooling/docker-compose.yml down

test:
	python3 -m unittest discover -s tooling/checker -p "test_*.py"

audit-lab:
	@echo "[*] Auditing vulnerable baseline (8.4.26):"
	python3 tooling/checker/checker.py --url http://127.0.0.1:18080/ --local --verbose
	@echo "\n[*] Auditing patched control (8.4.27):"
	python3 tooling/checker/checker.py --url http://127.0.0.1:18081/ --local --verbose
