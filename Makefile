.PHONY: test vet build

test:
	go test ./... -v

vet:
	go vet ./...

build:
	go build -o bin/secretguard ./cmd/secretguard
