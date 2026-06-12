.PHONY: build test run clean install lint

BINARY_NAME=secretscanner
GO=go

build:
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)

test:
	go test -v -cover ./internal/...

run: build
	./bin/$(BINARY_NAME) --path ./test/fixtures --dry-run

clean:
	rm -rf bin/

install:
	$(GO) install ./cmd/$(BINARY_NAME)

lint:
	golangci-lint run

dev: build
	./bin/$(BINARY_NAME) --path . --dry-run --verbose