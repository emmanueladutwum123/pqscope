GOLANGCI_LINT_VERSION := v2.15.0
STATICCHECK_VERSION := v0.8.2

.PHONY: all build test integration eval eval-score paper-data fmt-check vet staticcheck golangci-lint lint clean

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

# RQ1 evaluation: runs the competitors (pinned third-party images and
# packages) and the network corpus servers in Docker, scores everything
# against testdata/corpus, writes paper/data/rq1_*.csv, and cross-checks the
# summary with eval/score.py.
eval:
	eval/run.sh all testdata/corpus eval/out
	$(MAKE) eval-score

# Scores whatever eval/out holds, without running anything else.
eval-score:
	go run ./cmd/pqscope eval --corpus testdata/corpus --runs eval/out --out paper/data
	python3 eval/score.py paper/data

paper-data: eval

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
