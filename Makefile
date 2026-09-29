
all: build

clean:
	rm -f *.so

lint:
	golangci-lint run

build:
	go mod tidy
	go build -buildmode=plugin -o vault.so *.go

test: lint
	make -C vault test

cover:
	cd vault && go test -timeout 180s -coverprofile=cov.out . && go tool cover -func=cov.out | tail -1

vault-up:
	docker compose up -d --wait

vault-down:
	docker compose down

test-docker:
	VAULT_TEST_ADDR=http://127.0.0.1:8200 VAULT_TEST_TOKEN=root make -C vault test

.PHONY: all build clean lint test cover vault-up vault-down test-docker
