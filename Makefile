BINARY    = infix-webui
GOARCH   ?= $(shell go env GOARCH)
GOOS     ?= $(shell go env GOOS)

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) \
	go build -ldflags="-s -w" -o $(BINARY) .

.PHONY: dev
dev:
	go run . -listen :8080

.PHONY: clean
clean:
	rm -f $(BINARY)
