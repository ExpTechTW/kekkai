AGENT_BIN := kekkai-agent
CLI_BIN   := kekkai
AGENT_PKG := ./cmd/kekkai-agent
CLI_PKG   := ./cmd/kekkai

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all bpf build build-agent build-cli build-linux vet test clean run \
        update update-check config-check config-backup config-show status

all: bpf build

bpf:
	@bash scripts/build-bpf.sh

build: build-agent build-cli

build-agent:
	go build $(LDFLAGS) -o bin/$(AGENT_BIN) $(AGENT_PKG)

build-cli:
	go build $(LDFLAGS) -o bin/$(CLI_BIN) $(CLI_PKG)

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(AGENT_BIN).linux-amd64 $(AGENT_PKG)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(CLI_BIN).linux-amd64   $(CLI_PKG)

vet:
	go vet ./...

test:
	go test ./...

run: build-agent
	sudo ./bin/$(AGENT_BIN) -config ./deploy/kekkai.example.yaml

status: build-cli
	./bin/$(CLI_BIN) status

clean:
	rm -rf bin internal/loader/bpf/xdp_filter.o

update:
	@bash scripts/update.sh

update-check:
	@bash scripts/update.sh --check-only

# ---------- config management ----------
CFG ?= /etc/kekkai/kekkai.yaml

config-check:
	@/usr/local/bin/kekkai check $(CFG)

config-backup:
	@sudo /usr/local/bin/kekkai backup $(CFG)

config-show:
	@/usr/local/bin/kekkai show $(CFG)
