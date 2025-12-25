# CryptoScan Makefile
# Copyright 2025 Cyber Security Non-Profit (CSNP)

BINARY_NAME=cryptoscan
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

.PHONY: all build clean test lint install run help

all: build

## build: Build the binary
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/cryptoscan

## install: Install to GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/cryptoscan

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

## test: Run tests
test:
	go test -v -race ./...

## test-coverage: Run tests with coverage
test-coverage:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## lint: Run linters
lint:
	golangci-lint run

## fmt: Format code
fmt:
	go fmt ./...
	goimports -w .

## vet: Run go vet
vet:
	go vet ./...

## tidy: Tidy dependencies
tidy:
	go mod tidy

## run: Run the scanner on current directory
run: build
	./$(BINARY_NAME) scan .

## release: Build release binaries for all platforms
release: clean
	mkdir -p dist
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 ./cmd/cryptoscan
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 ./cmd/cryptoscan
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 ./cmd/cryptoscan
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 ./cmd/cryptoscan
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe ./cmd/cryptoscan

## docker: Build Docker image
docker:
	docker build -t csnp/cryptoscan:$(VERSION) .
	docker tag csnp/cryptoscan:$(VERSION) csnp/cryptoscan:latest

## help: Show this help
help:
	@echo "CryptoScan - QRAMM Cryptographic Discovery Scanner"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'
