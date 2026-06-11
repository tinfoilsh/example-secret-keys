ARTIFACTS_DIR := gen
BINARY := $(ARTIFACTS_DIR)/tinfoil-vault
GEN := ansible/generated-files
INVENTORY := ansible/inventory.yml
INVENTORY_EXAMPLE := ansible/inventory.example.yml
ENV_FILE := ../.env
GO_LD_FLAGS := "-s -w"
WORKLOAD_REPO := tinfoilsh/example-secret-keys

.PHONY: all
all: build

# Build for local testing
.PHONY: build
build:
	go build -o $(BINARY) -ldflags $(GO_LD_FLAGS) .

# Build for the vault host (linux/amd64)
.PHONY: build-prod
build-prod:
	@echo "Compiling for linux/amd64"
	GOOS=linux GOARCH=amd64 go build -o $(BINARY) -ldflags $(GO_LD_FLAGS) .

# Load ../.env and write secrets.json for Ansible from EXAMPLE_KEY.
.PHONY: copy-artifacts
copy-artifacts: build-prod
	@test -f $(ENV_FILE) || { echo "ERROR: cp .env.example .env and fill in values"; exit 1; }
	@set -a && . $(ENV_FILE) && set +a && \
	test -n "$$EXAMPLE_KEY" || { echo "ERROR: EXAMPLE_KEY unset in .env"; exit 1; }
	mkdir -p $(GEN)
	cp $(BINARY) $(GEN)/tinfoil-vault
	@set -a && . $(ENV_FILE) && set +a && \
	jq -n --arg v "$$EXAMPLE_KEY" '{ "$(WORKLOAD_REPO)": { "EXAMPLE_KEY": $$v } }' > $(GEN)/secrets.json

# Resolve inventory: prefer a local inventory.yml, else the committed example.
.PHONY: deploy
deploy: copy-artifacts
	@test -f $(ENV_FILE) || { echo "ERROR: cp .env.example .env and fill in values"; exit 1; }
	@set -a && . $(ENV_FILE) && set +a && \
	test -n "$$VAULT_TOKEN" || { echo "ERROR: VAULT_TOKEN unset in .env"; exit 1; }; \
	inv="$(INVENTORY)"; \
	if [ ! -f "$$inv" ]; then inv="$(INVENTORY_EXAMPLE)"; fi; \
	cd ansible && ansible-playbook -i "$$inv" playbook.yml --diff -e vault_token="$$VAULT_TOKEN"

# Refresh only the token + secrets.json on an already-provisioned host.
.PHONY: deploy-secrets
deploy-secrets: copy-artifacts
	@test -f $(ENV_FILE) || { echo "ERROR: cp .env.example .env and fill in values"; exit 1; }
	@set -a && . $(ENV_FILE) && set +a && \
	test -n "$$VAULT_TOKEN" || { echo "ERROR: VAULT_TOKEN unset in .env"; exit 1; }; \
	inv="$(INVENTORY)"; \
	if [ ! -f "$$inv" ]; then inv="$(INVENTORY_EXAMPLE)"; fi; \
	cd ansible && ansible-playbook -i "$$inv" playbook.yml --diff --tags secrets -e vault_token="$$VAULT_TOKEN"

# Run the vault locally using values from ../.env (smoke test without Caddy).
.PHONY: run-local
run-local: build
	@test -f $(ENV_FILE) || { echo "ERROR: cp .env.example .env and fill in values"; exit 1; }
	@set -a && . $(ENV_FILE) && set +a && \
	test -n "$$VAULT_TOKEN" && test -n "$$EXAMPLE_KEY" || { echo "ERROR: VAULT_TOKEN and EXAMPLE_KEY required in .env"; exit 1; }; \
	tmp=$$(mktemp); \
	jq -n --arg v "$$EXAMPLE_KEY" '{ "$(WORKLOAD_REPO)": { "EXAMPLE_KEY": $$v } }' > "$$tmp"; \
	VAULT_TOKEN="$$VAULT_TOKEN" $(BINARY) -secrets "$$tmp"

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: clean
clean:
	rm -rf $(ARTIFACTS_DIR) $(GEN)
