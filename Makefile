.PHONY: build test race bench vet fmt tidy check demo run run-admin run-authority \
	devsecrets compose-up compose-down

build:
	go build ./...

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -run='^$$' -bench=. -benchmem ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

# Run the same gates CI runs.
check: build vet test

# Narrated end-to-end run of the whole flow (no external setup needed).
demo:
	go run ./cmd/demo

# Run the gateway locally (dev: allow-all policy, no principal auth, no servers registered
# yet — so every proxied request is denied until you configure one).
# Set PASSPORT_SERVERS / PASSPORT_PRINCIPAL_MODE etc. to configure — see README.
run:
	PASSPORT_ALLOW_ALL=1 PASSPORT_DEV_NO_AUTH=1 go run ./cmd/gateway

# Run the admin control-plane API locally (UNAUTHENTICATED unless PASSPORT_ADMIN_TOKEN set).
run-admin:
	go run ./cmd/admin

# Run the credential authority locally. Prints the CA pubkey to set as PASSPORT_WORKLOAD_CA.
run-authority:
	PASSPORT_BOOTSTRAP_TOKENS=boot=agent-1 go run ./cmd/authority

# Generate throwaway dev secrets/identities for the docker-compose stack (writes deploy/.env
# and deploy/secrets/). DEV ONLY.
devsecrets:
	go run ./cmd/devsecrets --out deploy

# Bring up the full local stack (gateway + authority + admin + Postgres + demo upstream).
# Runs `devsecrets` first if deploy/.env is missing. See docs/DEPLOYMENT.md.
compose-up: deploy/.env
	cd deploy && docker compose up --build

deploy/.env:
	$(MAKE) devsecrets

compose-down:
	cd deploy && docker compose down -v
