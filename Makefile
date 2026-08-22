BIN     := deadair
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/alephnull-sh/deadair/internal/cli.Version=$(VERSION)
DIST    := dist
GOVULNCHECK_VERSION := v1.7.0

DARWIN_ARM64 := $(DIST)/$(BIN)_$(VERSION)_darwin-arm64
LINUX_AMD64  := $(DIST)/$(BIN)_$(VERSION)_linux-amd64
LINUX_ARM64  := $(DIST)/$(BIN)_$(VERSION)_linux-arm64

COMPOSE := docker compose -f integration/docker-compose.yml
CI_COMPOSE := docker compose -p deadair-ci-capture -f integration/docker-compose.yml
SCAN_LAB_COMPOSE := docker compose -p deadair-scan-lab -f integration/docker-compose.yml
OPENSEARCH_COMPOSE := docker compose -f integration/opensearch-docker-compose.yml
MSSP_LAB_OUT ?= integration/mssp-lab-out
MSSP_LAB_OUT_ABS := $(if $(filter /%,$(MSSP_LAB_OUT)),$(MSSP_LAB_OUT),$(CURDIR)/$(MSSP_LAB_OUT))
MSSP_LAB_METRICS_ADDR ?= 127.0.0.1:19317
CI_OUT ?= integration/ci-out
CI_OUT_ABS := $(if $(filter /%,$(CI_OUT)),$(CI_OUT),$(CURDIR)/$(CI_OUT))
SCAN_LAB_OUT ?= integration/scan-lab-out
SCAN_LAB_OUT_ABS := $(if $(filter /%,$(SCAN_LAB_OUT)),$(SCAN_LAB_OUT),$(CURDIR)/$(SCAN_LAB_OUT))

.PHONY: build static-build test race vet fmt check tidy-check validate vuln release integration elastic-integration integration-up integration-test integration-down opensearch-integration opensearch-integration-up opensearch-integration-test opensearch-integration-down record-ci record-scan-lab record-sentinel-lab mssp-lab mssp-lab-up mssp-lab-run mssp-lab-down

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN) ./cmd/deadair

static-build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o /dev/null ./cmd/deadair

RELEASE_TARGETS := darwin-arm64 darwin-amd64 linux-amd64 linux-arm64 windows-amd64 windows-arm64

release:
	mkdir -p $(DIST)
	@for t in $(RELEASE_TARGETS); do \
		goos=$${t%-*}; goarch=$${t#*-}; ext=""; \
		[ "$$goos" = "windows" ] && ext=".exe"; \
		out="$(DIST)/deadair_$(VERSION)_$$t$$ext"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch go build -trimpath -ldflags '$(LDFLAGS)' -o "$$out" ./cmd/deadair || exit 1; \
	done
	(cd $(DIST) && shasum -a 256 deadair_$(VERSION)_* > checksums.txt)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

check: vet test race
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

tidy-check:
	@set -eu; \
	tmpmod=.deadair-tidy.$$$$.mod; \
	tmpsum=$${tmpmod%.mod}.sum; \
	trap 'rm -f "$$tmpmod" "$$tmpsum"' EXIT HUP INT TERM; \
	cp go.mod "$$tmpmod"; \
	if [ -f go.sum ]; then cp go.sum "$$tmpsum"; fi; \
	go mod tidy -modfile="$$tmpmod"; \
	diff -u go.mod "$$tmpmod"; \
	if [ -f go.sum ]; then \
		diff -u go.sum "$$tmpsum"; \
	elif [ -s "$$tmpsum" ]; then \
		echo "go mod tidy would create go.sum"; \
		exit 1; \
	fi

validate: check static-build tidy-check

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

integration-up:
	$(COMPOSE) up -d --wait

integration-test:
	go test -tags=integration -count=1 -v ./integration -run TestElastic

integration-down:
	$(COMPOSE) down -v

elastic-integration: integration-up integration-test integration-down

opensearch-integration-up:
	$(OPENSEARCH_COMPOSE) up -d --wait

opensearch-integration-test:
	go test -tags=integration -count=1 -v ./integration -run TestOpenSearch

opensearch-integration-down:
	$(OPENSEARCH_COMPOSE) down -v

opensearch-integration: opensearch-integration-up opensearch-integration-test opensearch-integration-down

fleet-integration:
	$(COMPOSE) up -d --wait
	$(OPENSEARCH_COMPOSE) up -d --wait
	go test -tags=integration -count=1 -v ./integration -run TestFleet
	$(OPENSEARCH_COMPOSE) down -v
	$(COMPOSE) down -v

integration: elastic-integration opensearch-integration fleet-integration

record-ci: build
	@status=0; \
	$(CI_COMPOSE) up -d --wait elasticsearch || status=$$?; \
	if [ $$status -eq 0 ]; then \
		DEADAIR_CI_OUT="$(CI_OUT_ABS)" \
		DEADAIR_CI_BINARY="$(CURDIR)/bin/$(BIN)" \
		./integration/prepare-ci.sh || status=$$?; \
	fi; \
	if [ $$status -eq 0 ]; then \
		DEADAIR_CI_OUT="$(CI_OUT_ABS)" \
		vhs docs/assets/ci.tape || status=$$?; \
	fi; \
	$(CI_COMPOSE) down -v; \
	exit $$status

record-scan-lab: build
	@status=0; \
	$(SCAN_LAB_COMPOSE) up -d --wait || status=$$?; \
	if [ $$status -eq 0 ]; then \
		DEADAIR_SCAN_LAB_OUT="$(SCAN_LAB_OUT_ABS)" \
		DEADAIR_SCAN_LAB_BINARY="$(CURDIR)/bin/$(BIN)" \
		DEADAIR_SCAN_LAB_EXAMPLES="$(CURDIR)/docs/examples" \
		./integration/prepare-scan-lab.sh || status=$$?; \
	fi; \
	if [ $$status -eq 0 ]; then \
		DEADAIR_SCAN_LAB_OUT="$(SCAN_LAB_OUT_ABS)" \
		vhs docs/assets/check-lab.tape || status=$$?; \
	fi; \
	if [ $$status -eq 0 ]; then \
		DEADAIR_SCAN_LAB_OUT="$(SCAN_LAB_OUT_ABS)" \
		vhs docs/assets/scan-lab.tape || status=$$?; \
	fi; \
	$(SCAN_LAB_COMPOSE) down -v; \
	exit $$status

record-sentinel-lab: build
	@test -n "$(DEADAIR_AZURE_SUBSCRIPTION_ID)" || (echo "DEADAIR_AZURE_SUBSCRIPTION_ID is required" >&2; exit 1)
	@test -n "$(DEADAIR_AZURE_RESOURCE_GROUP)" || (echo "DEADAIR_AZURE_RESOURCE_GROUP is required" >&2; exit 1)
	@test -n "$(DEADAIR_SENTINEL_WORKSPACE)" || (echo "DEADAIR_SENTINEL_WORKSPACE is required" >&2; exit 1)
	@test "$(DEADAIR_SENTINEL_CAPTURE_CONFIRM)" = "record-disposable-sentinel:$(DEADAIR_SENTINEL_WORKSPACE)" || (echo "Set DEADAIR_SENTINEL_CAPTURE_CONFIRM=record-disposable-sentinel:$(DEADAIR_SENTINEL_WORKSPACE) to confirm this is a disposable lab" >&2; exit 1)
	DEADAIR_BACKEND=sentinel \
	AZURE_TOKEN_CREDENTIALS="$${AZURE_TOKEN_CREDENTIALS:-AzureCLICredential}" \
	vhs docs/assets/sentinel-lab.tape

mssp-lab-up:
	$(COMPOSE) up -d --wait
	$(OPENSEARCH_COMPOSE) up -d --wait

mssp-lab-run: build
	DEADAIR_MSSP_LAB_OUT="$(MSSP_LAB_OUT_ABS)" \
	DEADAIR_MSSP_LAB_BINARY="$(CURDIR)/bin/$(BIN)" \
	DEADAIR_MSSP_LAB_METRICS_ADDR="$(MSSP_LAB_METRICS_ADDR)" \
	go test -tags=integration -count=1 -v ./integration -run TestMSSPLab

mssp-lab-down:
	$(OPENSEARCH_COMPOSE) down -v
	$(COMPOSE) down -v

mssp-lab: build
	@status=0; \
	$(COMPOSE) up -d --wait || status=$$?; \
	if [ $$status -eq 0 ]; then $(OPENSEARCH_COMPOSE) up -d --wait || status=$$?; fi; \
	if [ $$status -eq 0 ]; then \
		DEADAIR_MSSP_LAB_OUT="$(MSSP_LAB_OUT_ABS)" \
		DEADAIR_MSSP_LAB_BINARY="$(CURDIR)/bin/$(BIN)" \
		DEADAIR_MSSP_LAB_METRICS_ADDR="$(MSSP_LAB_METRICS_ADDR)" \
		go test -tags=integration -count=1 -v ./integration -run TestMSSPLab || status=$$?; \
	fi; \
	$(OPENSEARCH_COMPOSE) down -v; \
	$(COMPOSE) down -v; \
	exit $$status
