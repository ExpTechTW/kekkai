AGENT_BIN := kekkai-agent
CLI_BIN   := kekkai
AGENT_PKG := ./cmd/kekkai-agent
CLI_PKG   := ./cmd/kekkai

VERSION ?= $(shell tr -d ' \n\r' < internal/buildinfo/VERSION)
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all bpf build build-agent build-cli build-linux vet test clean run status \
        install update repair doctor uninstall \
        config-check config-backup config-show

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
	@mkdir -p /tmp/kekkai-run
	@./bin/$(AGENT_BIN) -config /tmp/kekkai-run/kekkai.yaml -reset -iface lo >/dev/null 2>&1 || true
	sudo ./bin/$(AGENT_BIN) -config /tmp/kekkai-run/kekkai.yaml

status: build-cli
	./bin/$(CLI_BIN) status

clean:
	rm -rf bin internal/loader/bpf/xdp_filter.o

# ---------- one-script installer wrappers ----------
# Every lifecycle action goes through ./kekkai.sh so there is one
# source of truth for install / update / repair / doctor / uninstall.

install:
	@bash ./kekkai.sh install

update:
	@bash ./kekkai.sh update

repair:
	@bash ./kekkai.sh repair

doctor:
	@bash ./kekkai.sh doctor

uninstall:
	@bash ./kekkai.sh uninstall

# ---------- config management ----------
CFG ?= /etc/kekkai/kekkai.yaml

config-check:
	@/usr/local/bin/kekkai check $(CFG)

config-backup:
	@sudo /usr/local/bin/kekkai backup $(CFG)

config-show:
	@/usr/local/bin/kekkai show $(CFG)
