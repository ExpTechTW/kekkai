#!/usr/bin/env bash
# One-shot bootstrap for a fresh Linux host (Debian / Ubuntu / Raspberry Pi OS).
# - installs build deps (clang, libbpf-dev, kernel headers, make, go if missing)
# - verifies kernel features (BTF, bpffs)
# - picks a default network interface
# - compiles eBPF object and Go binary
# - writes /etc/waf-go/edge.yaml (if absent)
#
# Usage:  bash scripts/bootstrap.sh [--iface eth0] [--no-install] [--no-run]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IFACE=""
DO_INSTALL=1
DO_RUN=0
GO_MIN_MAJOR=1
GO_MIN_MINOR=22

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)      IFACE="$2"; shift 2 ;;
    --no-install) DO_INSTALL=0; shift ;;
    --run)        DO_RUN=1; shift ;;
    -h|--help)
      sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

need_sudo() {
  if [[ $EUID -eq 0 ]]; then echo ""; else echo "sudo"; fi
}
SUDO="$(need_sudo)"

# --- 1. OS sanity -----------------------------------------------------------
[[ "$(uname)" == "Linux" ]] || die "bootstrap.sh only runs on Linux (got $(uname))"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64) : ;;
  *) die "unsupported arch: $ARCH" ;;
esac
log "host: $(uname -srm)"

# --- 2. apt dependencies ----------------------------------------------------
if [[ $DO_INSTALL -eq 1 ]]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "no apt-get found; skipping package install (install clang, libbpf-dev, linux-headers manually)"
  else
    log "installing build dependencies via apt"
    $SUDO apt-get update -y
    $SUDO apt-get install -y --no-install-recommends \
      clang llvm libbpf-dev "linux-headers-$(uname -r)" \
      make gcc pkg-config ca-certificates curl
  fi
fi

# --- 3. Go toolchain --------------------------------------------------------
install_go() {
  local version="1.23.4"
  local tarball="go${version}.linux-${ARCH/x86_64/amd64}.tar.gz"
  tarball="${tarball/aarch64/arm64}"
  log "installing Go ${version} to /usr/local/go"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"
  export PATH="/usr/local/go/bin:$PATH"
  if ! grep -q '/usr/local/go/bin' "$HOME/.profile" 2>/dev/null; then
    echo 'export PATH=/usr/local/go/bin:$PATH' >> "$HOME/.profile"
  fi
}

# Make a pre-existing /usr/local/go install visible to this shell even when
# --no-install skipped the toolchain step.
if [[ -x /usr/local/go/bin/go ]]; then
  export PATH="/usr/local/go/bin:$PATH"
fi

if command -v go >/dev/null 2>&1; then
  GO_VER="$(go env GOVERSION 2>/dev/null | sed 's/go//')"
  GO_MAJOR="${GO_VER%%.*}"
  GO_REST="${GO_VER#*.}"
  GO_MINOR="${GO_REST%%.*}"
  if (( GO_MAJOR < GO_MIN_MAJOR )) || { (( GO_MAJOR == GO_MIN_MAJOR )) && (( GO_MINOR < GO_MIN_MINOR )); }; then
    warn "go ${GO_VER} too old, need >= ${GO_MIN_MAJOR}.${GO_MIN_MINOR}"
    [[ $DO_INSTALL -eq 1 ]] && install_go || die "upgrade go manually"
  else
    log "go ${GO_VER} ok"
  fi
else
  warn "go not found"
  [[ $DO_INSTALL -eq 1 ]] && install_go || die "install go manually"
fi
export PATH="/usr/local/go/bin:$PATH"

# --- 4. kernel feature checks ----------------------------------------------
log "kernel: $(uname -r)"
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  warn "/sys/kernel/btf/vmlinux not readable — CO-RE may fail. Kernel built without CONFIG_DEBUG_INFO_BTF?"
else
  log "BTF present"
fi

if ! mount | grep -q 'type bpf '; then
  log "mounting bpffs at /sys/fs/bpf"
  $SUDO mount -t bpf bpf /sys/fs/bpf || warn "bpffs mount failed"
else
  log "bpffs already mounted"
fi
$SUDO mkdir -p /sys/fs/bpf/waf-go

# --- 5. pick default iface --------------------------------------------------
if [[ -z "$IFACE" ]]; then
  IFACE="$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')"
  [[ -z "$IFACE" ]] && IFACE="$(ip -br link | awk '$1!="lo" && $2=="UP" {print $1; exit}')"
fi
[[ -n "$IFACE" ]] || die "could not detect network interface; pass --iface"
log "using iface: $IFACE"

# XDP driver support hint
DRIVER="$(ethtool -i "$IFACE" 2>/dev/null | awk -F': ' '/^driver:/ {print $2}')"
case "$DRIVER" in
  bcmgenet|virtio_net|e1000|e1000e)
    warn "driver '$DRIVER' has no native XDP — agent will run in generic/SKB mode (functional but slower)"
    ;;
  ixgbe|i40e|ice|mlx5_core|ena|bnxt_en)
    log "driver '$DRIVER' supports native XDP"
    ;;
  "") : ;;
  *) log "driver '$DRIVER' — XDP support: check driver docs" ;;
esac

# --- 6. build eBPF + Go -----------------------------------------------------
log "compiling eBPF object"
make bpf

log "compiling Go binary"
make build

$SUDO install -D -m 0755 "$ROOT/bin/waf-edge" /usr/local/bin/waf-edge
log "installed binary: /usr/local/bin/waf-edge"

# --- 7. config --------------------------------------------------------------
CFG=/etc/waf-go/edge.yaml
if [[ ! -f "$CFG" ]]; then
  log "writing default config to $CFG"
  $SUDO mkdir -p /etc/waf-go
  $SUDO tee "$CFG" >/dev/null <<EOF
node_id: $(hostname)
region: default
iface: $IFACE
EOF
else
  warn "$CFG already exists — leaving untouched"
fi

log "bootstrap complete"
echo
echo "next steps:"
echo "  sudo /usr/local/bin/waf-edge -config $CFG"
echo

if [[ $DO_RUN -eq 1 ]]; then
  log "launching waf-edge (Ctrl+C to stop)"
  exec $SUDO /usr/local/bin/waf-edge -config "$CFG"
fi
