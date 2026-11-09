GOLANGCI_LINT_VERSION := v2.15.0
STATICCHECK_VERSION := v0.8.2

.PHONY: all build test integration eval eval-score bench paper-data paper-numbers paper-check paper fmt-check vet staticcheck golangci-lint lint clean

all: lint test build

build:
	go build -o bin/pqscope ./cmd/pqscope

test:
	go test -race ./...

# Network tests against real TLS and SSH servers in Docker (and a local
# openssl 3.5+ if present). Set PQSCOPE_REQUIRE_DOCKER=1 to fail, not skip,
# without Docker.
integration:
	go test -race -tags integration -count=1 -timeout 15m ./internal/discover/network/ ./internal/bench/

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

# RQ4 migration costs: OpenSSL size cross-check and tc netem TLS runs in
# Docker (bench/run.sh), then primitive and loopback TLS benchmarks on this
# machine, writing paper/data/rq4_*.csv. Takes several minutes; close other
# programs first, since the machine's load is in the numbers.
bench:
	bench/run.sh bench/out
	go run ./cmd/pqscope bench --runs bench/out --out paper/data --revision "$$(git describe --always --dirty)"

paper-data: eval bench

# The paper's numbers, tables and figures, generated from paper/data. The
# sources hold no typed numbers; paper-check enforces that and that
# paper/generated/ matches the data.
paper-numbers:
	python3 paper/gen.py

paper-check:
	python3 paper/gen.py --check
	python3 paper/check_numbers.py
	python3 -m unittest discover -s paper -p 'test_*.py'

# Builds paper/main.pdf. Needs tectonic (https://tectonic-typesetting.github.io),
# which fetches the LaTeX packages it needs on first use.
paper: paper-numbers paper-check
	cd paper && tectonic -X compile main.tex

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	go vet ./...
	go vet -tags integration ./internal/discover/network/ ./internal/bench/

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) -tags integration ./...

golangci-lint:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

lint: fmt-check vet staticcheck golangci-lint

clean:
	rm -rf bin paper/main.pdf
