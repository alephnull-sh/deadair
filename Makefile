BIN     := deadair
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/Big-Comfy/deadair/internal/cli.Version=$(VERSION)
DIST    := dist

DARWIN_ARM64 := $(DIST)/$(BIN)_$(VERSION)_darwin-arm64
LINUX_AMD64  := $(DIST)/$(BIN)_$(VERSION)_linux-amd64
LINUX_ARM64  := $(DIST)/$(BIN)_$(VERSION)_linux-arm64

COMPOSE := docker compose -f integration/docker-compose.yml
OPENSEARCH_COMPOSE := docker compose -f integration/opensearch-docker-compose.yml
MSSP_LAB_OUT ?= integration/mssp-lab-out
MSSP_LAB_OUT_ABS := $(if $(filter /%,$(MSSP_LAB_OUT)),$(MSSP_LAB_OUT),$(CURDIR)/$(MSSP_LAB_OUT))
MSSP_LAB_METRICS_ADDR ?= 127.0.0.1:19317

.PHONY: build static-build test race vet fmt check tidy-check validate release integration elastic-integration integration-up integration-test integration-down opensearch-integration opensearch-integration-up opensearch-integration-test opensearch-integration-down mssp-lab mssp-lab-up mssp-lab-run mssp-lab-down

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
