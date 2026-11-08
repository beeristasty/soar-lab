.PHONY: up down certs test lint smoke
certs:
	cd wazuh-docker/single-node && docker compose -f generate-indexer-certs.yml run --rm generator
up: certs
	docker compose up -d --build
down:
	docker compose down
test:
	cd soar && python -m pytest -q
lint:
	cd soar && python -m pytest -q tests/test_dsl.py
smoke:
	./scripts/smoke-test.sh
