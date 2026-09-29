
all: test

lint:
	golangci-lint run

build:
	go build *.go

test: lint
	go test -timeout 180s -coverprofile=cov.out

.PHONY: all build test
