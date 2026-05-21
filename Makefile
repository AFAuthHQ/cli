.PHONY: build test lint fmt clean install tidy sync-vectors help

BIN := bin/afauth
PKG := github.com/afauthhq/cli

# Path to the AFAuthHQ/spec checkout used by `sync-vectors`. Override on
# the command line: `make sync-vectors SPEC_REPO=/path/to/spec`.
SPEC_REPO ?= ../spec

help:
	@echo "Available targets:"
	@echo "  build         Build the afauth binary to ./bin/"
	@echo "  install       Install afauth to \$$GOPATH/bin"
	@echo "  test          Run unit tests"
	@echo "  lint          Run linters (requires golangci-lint)"
	@echo "  fmt           Format Go sources"
	@echo "  tidy          Run go mod tidy"
	@echo "  sync-vectors  Refresh testdata/spec-vectors from SPEC_REPO"
	@echo "  clean         Remove built artifacts"

build:
	@mkdir -p bin
	go build -o $(BIN) $(PKG)/cmd/afauth

install:
	go install $(PKG)/cmd/afauth

test:
	go test -race ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

tidy:
	go mod tidy

sync-vectors:
	@if [ ! -d "$(SPEC_REPO)/vectors" ]; then \
		echo "error: $(SPEC_REPO)/vectors not found (set SPEC_REPO=/path/to/spec)"; \
		exit 1; \
	fi
	@mkdir -p testdata/spec-vectors/signatures \
	          testdata/spec-vectors/discovery \
	          testdata/spec-vectors/recipients \
	          testdata/spec-vectors/errors \
	          testdata/spec-vectors/replay-window
	@cp $(SPEC_REPO)/vectors/keypair.json testdata/spec-vectors/keypair.json
	@cp $(SPEC_REPO)/vectors/signatures/*.json testdata/spec-vectors/signatures/
	@cp $(SPEC_REPO)/vectors/discovery/*.json testdata/spec-vectors/discovery/
	@cp $(SPEC_REPO)/vectors/recipients/*.json testdata/spec-vectors/recipients/
	@cp $(SPEC_REPO)/vectors/errors/*.json testdata/spec-vectors/errors/
	@cp $(SPEC_REPO)/vectors/replay-window/*.json testdata/spec-vectors/replay-window/
	@SHA=$$(cd $(SPEC_REPO) && git rev-parse HEAD); \
	  printf "spec_sha: %s\nsynced_at: %s\n" "$$SHA" "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	    > testdata/spec-vectors/VERSION
	@echo "synced spec vectors @ $$(cat testdata/spec-vectors/VERSION | head -1)"

clean:
	rm -rf bin dist
