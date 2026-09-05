.PHONY: build test race vet fmt-check check

build:
	go build ./cmd/...

test:
	go test -count=1 ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt-check:
	test -z "$$(gofmt -l .)"

check: fmt-check test vet
