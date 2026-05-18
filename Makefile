.PHONY: build test lint fmt clean install tidy help

BIN := bin/afauth
PKG := github.com/afauthhq/cli

help:
	@echo "Available targets:"
	@echo "  build    Build the afauth binary to ./bin/"
	@echo "  install  Install afauth to \$$GOPATH/bin"
	@echo "  test     Run unit tests"
	@echo "  lint     Run linters (requires golangci-lint)"
	@echo "  fmt      Format Go sources"
	@echo "  tidy     Run go mod tidy"
	@echo "  clean    Remove built artifacts"

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

clean:
	rm -rf bin dist
