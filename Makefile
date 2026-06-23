.PHONY: test vet build release install-hook

APP     := secretguard
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

test:
	go test ./... -v

vet:
	go vet ./...

build:
	go build -o bin/$(APP) ./cmd/$(APP)

release:
	VERSION=$(VERSION) OUTDIR=./bin ./scripts/build.sh

install-hook:
	go build -o bin/$(APP) ./cmd/$(APP)
	./bin/$(APP) install-hook
