GOLANGCI_LINT_VERSION := v2.15.0
STATICCHECK_VERSION := v0.8.2

.PHONY: all build test integration fmt-check vet staticcheck golangci-lint lint clean

all: lint test build

build:
	go build -o bin/pqscope ./cmd/pqscope

test:
	go test -race ./...

# Network tests against real TLS and SSH servers in Docker (and a local
# openssl 3.5+ if present). Set PQSCOPE_REQUIRE_DOCKER=1 to fail, not skip,
# without Docker.
integration:
	go test -race -tags integration -count=1 -timeout 15m ./internal/discover/network/

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	go vet ./...
	go vet -tags integration ./internal/discover/network/

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) -tags integration ./...

golangci-lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

lint: fmt-check vet staticcheck golangci-lint

clean:
	rm -rf bin
