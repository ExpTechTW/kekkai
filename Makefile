BINARY := waf-edge
PKG    := ./cmd/edge

.PHONY: all bpf build build-linux vet test clean run

all: bpf build

bpf:
	@bash scripts/build-bpf.sh

build:
	go build -o bin/$(BINARY) $(PKG)

build-linux:
	GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY).linux-amd64 $(PKG)

vet:
	go vet ./...

test:
	go test ./...

run: build
	sudo ./bin/$(BINARY) -config ./deploy/edge.example.yaml

clean:
	rm -rf bin internal/loader/bpf/xdp_filter.o
