.PHONY: test vet build release install-hook

APP     := secretguard

test:
	go test ./... -v

vet:
	go vet ./...

build:
	go build -o bin/$(APP) ./cmd/$(APP)

release:
	goreleaser release --snapshot --clean

install-hook:
	go build -o bin/$(APP) ./cmd/$(APP)
	./bin/$(APP) install-hook
