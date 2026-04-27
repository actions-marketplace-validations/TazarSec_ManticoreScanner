.PHONY: build test vet lint clean install

BINARY := manticore
PKG := ./cmd/manticore
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/TazarSec/ManticoreScanner/internal/buildinfo.Version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

lint: vet

clean:
	rm -f $(BINARY)

install:
	go install $(PKG)
