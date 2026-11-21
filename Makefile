.PHONY: bench build check gosec lint test test-race vuln vet

BIN := bin/gocloak-mcp

bench:
	go test -bench=. -benchmem -run=^$$ ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/gocloak-mcp

check: lint test-race vet vuln gosec build

lint:
	golangci-lint run ./...

test:
	go test -cover ./...

test-race:
	go test -race -cover ./...

vuln:
	govulncheck ./...

gosec:
	gosec ./...

vet:
	go vet ./...
