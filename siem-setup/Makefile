# SIEM Log Aggregator — task runner.
# Targets beyond `up`/`down`/`reset` are filled in by later build-order blocks.

.PHONY: up down reset test pipeline e2e

up:              ## start everything
	docker compose up -d --build

down:            ## stop, keep data
	docker compose down

reset:           ## wipe all data (Kafka, Postgres, log volumes)
	docker compose down -v

test:            ## unit tests, no Docker
	python -m pytest

pipeline:        ## injector scenarios -> alerts in Postgres (stack must be up)
	bash tests/pipeline/run_pipeline.sh

e2e:             ## real attacker scenarios A1-A3, C1-C2 (block 5)
	@echo "e2e tests not implemented yet (block 5)"
