GOLANGCI_LINT_VERSION := v2.15.0
STATICCHECK_VERSION := v0.8.2

.PHONY: all build test fmt-check vet staticcheck golangci-lint lint clean

all: lint test build

build:
	go build -o bin/pqscope ./cmd/pqscope

test:
	go test -race ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	go vet ./...

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

golangci-lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

lint: fmt-check vet staticcheck golangci-lint

clean:
	rm -rf bin
