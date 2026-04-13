#!/usr/bin/env bash
# kekkai — one-script installer / updater / repair tool.
#
# Usage:
#   bash kekkai.sh               # auto-detect state and do the right thing
#   bash kekkai.sh install       # force first-time install
#   bash kekkai.sh update        # force update from git
#   bash kekkai.sh repair        # force re-install of binaries + systemd unit
#   bash kekkai.sh doctor        # read-only health check (delegates to `kekkai doctor`)
#   bash kekkai.sh uninstall     # remove everything except config
#
# Flags (apply to any subcommand):
#   --force       bypass safety checks (dirty tree, branch mismatch, downgrade)
#   --no-install  skip apt dependency install
#   --iface NAME  force a specific interface in the default config
#   --run         launch the agent in foreground at the end (debugging)
#
# Auto-detect logic (no subcommand):
#   - no binaries yet            → install
#   - binaries present but no systemd unit OR unit disabled → repair
#   - everything installed + git has new commits → update
#   - everything installed + no new commits → doctor
#
set -euo pipefail

# ROOT is the directory containing this script — the repo root, since
# kekkai.sh lives at the top level so `bash kekkai.sh` from a fresh
# clone does the right thing without extra path juggling.
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
AGENT_BIN=/usr/local/bin/kekkai-agent
CLI_BIN=/usr/local/bin/kekkai
ROLLBACK_BIN=/usr/local/bin/kekkai-agent.prev
CONFIG_DIR=/etc/kekkai
CONFIG_FILE="$CONFIG_DIR/kekkai.yaml"
STATS_DIR=/var/run/kekkai
BPFFS_DIR=/sys/fs/bpf/kekkai
UNIT_NAME=kekkai-agent.service
UNIT_SRC="$ROOT/deploy/systemd/kekkai-agent.service"
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
GO_MIN="1.22"
GO_DOWNLOAD_VERSION="1.23.4"
BRANCH=main

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
CMD=""
FORCE=0
DO_INSTALL_DEPS=1
IFACE_OVERRIDE=""
DO_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|update|repair|doctor|uninstall)
      CMD="$1"; shift ;;
    --force)       FORCE=1; shift ;;
    --no-install)  DO_INSTALL_DEPS=0; shift ;;
    --iface)       IFACE_OVERRIDE="$2"; shift 2 ;;
    --run)         DO_RUN=1; shift ;;
    -h|--help)
      sed -n '2,23p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done || true

# ---------------------------------------------------------------------------
# Pretty output (sandstone colours; works in 16-colour terminals)
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" == "" ]]; then
  C_RESET=$'\033[0m'
  C_DIM=$'\033[2m'
  C_BOLD=$'\033[1m'
  C_OK=$'\033[1;32m'    # green
  C_WARN=$'\033[1;33m'  # yellow
  C_ERR=$'\033[1;31m'   # red
  C_INFO=$'\033[1;36m'  # cyan
  C_TITLE=$'\033[1;35m' # violet — kekkai barrier theme
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_OK=""; C_WARN=""; C_ERR=""; C_INFO=""; C_TITLE=""
fi

step() { printf '\n%s◈ %s%s\n' "$C_TITLE" "$*" "$C_RESET"; }
log()  { printf '%s[+]%s %s\n' "$C_OK"   "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_RESET" "$*"; }
err()  { printf '%s[x]%s %s\n' "$C_ERR"  "$C_RESET" "$*" >&2; }
info() { printf '%s[·]%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
die()  { err "$*"; exit 1; }

banner() {
  printf '%s\n' "$C_TITLE"
  cat <<'EOF'
  ██╗  ██╗███████╗██╗  ██╗██╗  ██╗ █████╗ ██╗
  ██║ ██╔╝██╔════╝██║ ██╔╝██║ ██╔╝██╔══██╗██║
  █████╔╝ █████╗  █████╔╝ █████╔╝ ███████║██║
  ██╔═██╗ ██╔══╝  ██╔═██╗ ██╔═██╗ ██╔══██║██║
  ██║  ██╗███████╗██║  ██╗██║  ██╗██║  ██║██║
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
EOF
  printf '%s  結界 · edge barrier installer%s\n\n' "$C_INFO" "$C_RESET"
}

# ---------------------------------------------------------------------------
# OS / arch detection
# ---------------------------------------------------------------------------
# Return values match what GitHub release assets will use once we publish
# prebuilt binaries (follows Go's GOOS/GOARCH conventions).
detect_os() {
  case "$(uname -s)" in
    Linux)  echo linux ;;
    Darwin) echo darwin ;;
    *)      echo "unsupported" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)         echo amd64 ;;
    aarch64|arm64)        echo arm64 ;;
    armv7l|armv6l)        echo armv6 ;;  # rpi 3 and older
    *)                    echo unsupported ;;
  esac
}

need_sudo() {
  [[ $EUID -eq 0 ]] && echo "" || echo "sudo"
}

SUDO="$(need_sudo)"
OS="$(detect_os)"
ARCH="$(detect_arch)"

# ---------------------------------------------------------------------------
# Repo / source detection
# ---------------------------------------------------------------------------
# If we're inside the kekkai git repo the script can build from source.
# Otherwise it would need a prebuilt binary — not available yet, so error.
SOURCE_MODE="repo"
if [[ ! -d "$ROOT/.git" ]] || [[ ! -f "$ROOT/go.mod" ]]; then
  SOURCE_MODE="release"
fi

# ---------------------------------------------------------------------------
# State detection — which subcommand should auto mode run?
# ---------------------------------------------------------------------------
detect_state() {
  # Returns one of: install / repair / update / healthy
  if [[ ! -x "$AGENT_BIN" ]] || [[ ! -x "$CLI_BIN" ]]; then
    echo install
    return
  fi
  if [[ ! -f "$UNIT_DST" ]]; then
    echo repair
    return
  fi
  if command -v systemctl >/dev/null 2>&1; then
    if ! $SUDO systemctl is-enabled --quiet "$UNIT_NAME" 2>/dev/null; then
      echo repair
      return
    fi
  fi
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo repair
    return
  fi
  # binaries + unit + config present → check for upstream updates
  if [[ "$SOURCE_MODE" == "repo" ]] && command -v git >/dev/null 2>&1; then
    git fetch origin "$BRANCH" >/dev/null 2>&1 || true
    local before remote
    before="$(git rev-parse HEAD 2>/dev/null || echo "")"
    remote="$(git rev-parse "origin/$BRANCH" 2>/dev/null || echo "")"
    if [[ -n "$before" ]] && [[ -n "$remote" ]] && [[ "$before" != "$remote" ]]; then
      echo update
      return
    fi
  fi
  echo healthy
}

# ---------------------------------------------------------------------------
# Dependency install
# ---------------------------------------------------------------------------
install_deps() {
  [[ $DO_INSTALL_DEPS -eq 0 ]] && { info "skipping apt (--no-install)"; return; }
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "no apt-get; install clang/libbpf-dev/linux-headers manually"
    return
  fi
  log "installing apt dependencies"
  $SUDO apt-get update -y
  $SUDO apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev "linux-headers-$(uname -r)" \
    make gcc pkg-config ca-certificates curl
}

install_go() {
  local tarball="go${GO_DOWNLOAD_VERSION}.${OS}-${ARCH}.tar.gz"
  log "installing Go ${GO_DOWNLOAD_VERSION} to /usr/local/go"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"
  export PATH="/usr/local/go/bin:$PATH"
  if ! grep -q '/usr/local/go/bin' "$HOME/.profile" 2>/dev/null; then
    echo 'export PATH=/usr/local/go/bin:$PATH' >> "$HOME/.profile"
  fi
}

ensure_go() {
  [[ -x /usr/local/go/bin/go ]] && export PATH="/usr/local/go/bin:$PATH"

  if ! command -v go >/dev/null 2>&1; then
    warn "go not found"
    [[ $DO_INSTALL_DEPS -eq 1 ]] || die "install go manually (>= $GO_MIN)"
    install_go
    return
  fi
  local ver major minor
  ver="$(go env GOVERSION 2>/dev/null | sed 's/go//')"
  major="${ver%%.*}"; minor="$(echo "$ver" | awk -F. '{print $2}')"
  local need_major need_minor
  need_major="${GO_MIN%%.*}"; need_minor="${GO_MIN##*.}"
  if (( major < need_major )) || { (( major == need_major )) && (( minor < need_minor )); }; then
    warn "go $ver too old (need >= $GO_MIN)"
    [[ $DO_INSTALL_DEPS -eq 1 ]] || die "upgrade go manually"
    install_go
  else
    log "go $ver ok"
  fi
}

check_kernel() {
  log "kernel: $(uname -r)"
  [[ "$OS" == "linux" ]] || die "kekkai requires Linux"
  [[ "$ARCH" == "amd64" || "$ARCH" == "arm64" ]] || die "unsupported arch: $(uname -m)"
  if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
    warn "/sys/kernel/btf/vmlinux not readable — OK, kekkai doesn't need BTF"
  fi
  if ! mount | grep -q 'type bpf '; then
    log "mounting bpffs at /sys/fs/bpf"
    $SUDO mount -t bpf bpf /sys/fs/bpf || warn "bpffs mount failed"
  fi
  $SUDO mkdir -p "$BPFFS_DIR"
}

detect_iface() {
  if [[ -n "$IFACE_OVERRIDE" ]]; then
    echo "$IFACE_OVERRIDE"
    return
  fi
  local iface
  iface="$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')"
  [[ -z "$iface" ]] && iface="$(ip -br link 2>/dev/null | awk '$1!="lo" && $2=="UP" {print $1; exit}')"
  echo "$iface"
}

# ---------------------------------------------------------------------------
# Build from source (repo mode)
# ---------------------------------------------------------------------------
build_from_source() {
  [[ "$SOURCE_MODE" == "repo" ]] || \
    die "release binaries not available yet — clone the repo and run from there"

  log "compiling eBPF object"
  make bpf

  log "compiling Go binaries (kekkai-agent + kekkai)"
  make build
  [[ -x "$ROOT/bin/kekkai-agent" ]] || die "build failed: bin/kekkai-agent missing"
  [[ -x "$ROOT/bin/kekkai" ]]       || die "build failed: bin/kekkai missing"
}

install_binaries() {
  local src_agent="$ROOT/bin/kekkai-agent"
  local src_cli="$ROOT/bin/kekkai"

  # Rollback snapshot of the current daemon (update only — install has
  # nothing to roll back to).
  if [[ -f "$AGENT_BIN" ]]; then
    $SUDO cp -a "$AGENT_BIN" "$ROLLBACK_BIN" || true
  fi

  $SUDO install -D -m 0755 "$src_agent" "$AGENT_BIN"
  log "installed: $AGENT_BIN"

  $SUDO install -D -m 0755 "$src_cli" "$CLI_BIN"
  log "installed: $CLI_BIN"
}

install_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    info "$CONFIG_FILE already exists — leaving untouched"
    return
  fi
  local iface
  iface="$(detect_iface)"
  [[ -n "$iface" ]] || die "could not detect a default interface; pass --iface <name>"
  log "writing default config to $CONFIG_FILE (iface=$iface)"
  $SUDO install -d -m 0755 "$CONFIG_DIR"
  # We delegate the template to `kekkai-agent -reset` so shell and Go stay
  # in sync on one source of truth for the default config.
  $SUDO "$AGENT_BIN" -reset -config "$CONFIG_FILE" -iface "$iface" >/dev/null
  warn "edit $CONFIG_FILE and add your management network to filter.ingress_allowlist"
}

install_systemd_unit() {
  command -v systemctl >/dev/null 2>&1 || { warn "systemctl not found — skipping unit install"; return; }
  [[ -f "$UNIT_SRC" ]] || die "systemd unit template missing: $UNIT_SRC"
  log "installing systemd unit to $UNIT_DST"
  $SUDO install -D -m 0644 "$UNIT_SRC" "$UNIT_DST"
  $SUDO systemctl daemon-reload
}

enable_and_start() {
  command -v systemctl >/dev/null 2>&1 || return
  if $SUDO systemctl is-enabled --quiet "$UNIT_NAME" 2>/dev/null; then
    log "unit already enabled"
  else
    log "enabling unit at boot"
    $SUDO systemctl enable "$UNIT_NAME" || warn "enable failed"
  fi
  log "starting unit"
  if ! $SUDO systemctl restart "$UNIT_NAME"; then
    warn "restart failed; rolling back if possible"
    if [[ -f "$ROLLBACK_BIN" ]]; then
      $SUDO install -m 0755 "$ROLLBACK_BIN" "$AGENT_BIN"
      $SUDO systemctl restart "$UNIT_NAME" || true
      die "rolled back to previous binary. check: journalctl -u $UNIT_NAME -n 50"
    fi
    die "no rollback available. check: journalctl -u $UNIT_NAME -n 50"
  fi
  sleep 1
  if ! $SUDO systemctl is-active --quiet "$UNIT_NAME"; then
    if [[ -f "$ROLLBACK_BIN" ]]; then
      warn "service did not stay active; rolling back"
      $SUDO install -m 0755 "$ROLLBACK_BIN" "$AGENT_BIN"
      $SUDO systemctl restart "$UNIT_NAME" || true
    fi
    $SUDO journalctl -u "$UNIT_NAME" -n 20 --no-pager >&2 || true
    die "service failed to come up"
  fi
}

# ---------------------------------------------------------------------------
# Git update (repo mode only)
# ---------------------------------------------------------------------------
git_update() {
  [[ "$SOURCE_MODE" == "repo" ]] || die "not in a git repo"
  command -v git >/dev/null 2>&1 || die "git not found"

  # The embedded .o file is tracked but overwritten on every build, so a
  # prior run leaves it dirty. Restore before sanity check.
  if git ls-files --error-unmatch internal/loader/bpf/xdp_filter.o >/dev/null 2>&1; then
    git checkout -- internal/loader/bpf/xdp_filter.o 2>/dev/null || true
  fi

  if [[ $FORCE -eq 0 ]] && ! git diff --quiet; then
    echo
    git status --short
    echo
    die "working tree has uncommitted changes. commit, stash, or pass --force"
  fi

  local current_branch
  current_branch="$(git symbolic-ref --short HEAD 2>/dev/null || echo DETACHED)"
  if [[ "$current_branch" != "$BRANCH" ]] && [[ $FORCE -eq 0 ]]; then
    die "on branch '$current_branch', expected '$BRANCH'. switch or pass --force"
  fi

  local before remote
  before="$(git rev-parse HEAD)"
  log "current HEAD: ${before:0:12}"
  log "fetching origin/$BRANCH"
  git fetch origin "$BRANCH"
  remote="$(git rev-parse "origin/$BRANCH")"

  if [[ "$before" == "$remote" ]]; then
    log "already up to date"
    return 0
  fi

  log "incoming:     ${remote:0:12}"
  git --no-pager log --oneline "$before..$remote" | sed 's/^/    /' || true

  # Refuse time-travel (downgrade).
  local before_ts remote_ts
  before_ts="$(git show -s --format=%ct "$before")"
  remote_ts="$(git show -s --format=%ct "$remote")"
  if (( remote_ts < before_ts )) && [[ $FORCE -eq 0 ]]; then
    die "remote commit is older than local — refusing to downgrade (pass --force)"
  fi

  log "fast-forwarding"
  git merge --ff-only "origin/$BRANCH" || die "fast-forward failed (diverged? use --force + git reset)"
  return 0
}

validate_config_against_new_binary() {
  [[ -f "$CONFIG_FILE" ]] || return 0
  log "validating $CONFIG_FILE against new binary"
  if ! "$ROOT/bin/kekkai-agent" -check "$CONFIG_FILE" >/tmp/kekkai-check.log 2>&1; then
    cat /tmp/kekkai-check.log >&2
    die "new binary rejects current config — aborting install"
  fi
  log "config ok"
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
do_install() {
  banner
  step "first-time install · $OS/$ARCH"
  install_deps
  ensure_go
  check_kernel
  build_from_source
  install_binaries
  install_config
  install_systemd_unit
  enable_and_start
  log "install complete"
  post_install_hints
}

do_update() {
  banner
  step "update · $OS/$ARCH"
  ensure_go
  git_update
  build_from_source
  validate_config_against_new_binary

  local old_sha new_sha
  old_sha=""; [[ -f "$AGENT_BIN" ]] && old_sha="$(sha256sum "$AGENT_BIN" | awk '{print $1}')"
  new_sha="$(sha256sum "$ROOT/bin/kekkai-agent" | awk '{print $1}')"
  if [[ "$old_sha" == "$new_sha" ]]; then
    log "binary unchanged — nothing to restart"
    return 0
  fi
  install_binaries
  enable_and_start
  log "update complete"
}

do_repair() {
  banner
  step "repair · $OS/$ARCH"
  ensure_go
  build_from_source
  install_binaries
  [[ -f "$CONFIG_FILE" ]] || install_config
  install_systemd_unit
  enable_and_start
  log "repair complete"
}

do_doctor() {
  if [[ -x "$CLI_BIN" ]]; then
    exec "$CLI_BIN" doctor
  fi
  # kekkai not installed yet — run read-only checks inline.
  step "doctor · system not yet installed"
  info "OS:       $OS"
  info "arch:     $ARCH"
  info "kernel:   $(uname -r)"
  info "source:   $SOURCE_MODE"
  [[ -x "$AGENT_BIN" ]] && log "$AGENT_BIN present" || warn "$AGENT_BIN missing"
  [[ -x "$CLI_BIN"   ]] && log "$CLI_BIN present"   || warn "$CLI_BIN missing"
  [[ -f "$UNIT_DST"  ]] && log "$UNIT_DST present"  || warn "$UNIT_DST missing"
  [[ -f "$CONFIG_FILE" ]] && log "$CONFIG_FILE present" || warn "$CONFIG_FILE missing"
  echo
  info "run:  bash ./kekkai.sh install"
}

do_uninstall() {
  banner
  step "uninstall (config preserved)"
  command -v systemctl >/dev/null 2>&1 && {
    $SUDO systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
  }
  $SUDO rm -f "$UNIT_DST" "$AGENT_BIN" "$CLI_BIN" "$ROLLBACK_BIN"
  $SUDO systemctl daemon-reload 2>/dev/null || true
  $SUDO rm -rf "$BPFFS_DIR" "$STATS_DIR"
  info "config preserved at $CONFIG_FILE"
  info "to remove it:  sudo rm -rf $CONFIG_DIR"
  log "uninstall complete"
}

post_install_hints() {
  echo
  info "next steps:"
  printf '  %s1.%s edit config:      sudo nano %s\n' "$C_BOLD" "$C_RESET" "$CONFIG_FILE"
  printf '  %s2.%s validate:         kekkai check\n' "$C_BOLD" "$C_RESET"
  printf '  %s3.%s restart:          sudo systemctl restart kekkai-agent\n' "$C_BOLD" "$C_RESET"
  printf '  %s4.%s watch live:       sudo kekkai status\n' "$C_BOLD" "$C_RESET"
  printf '  %s5.%s diagnose:         kekkai doctor\n' "$C_BOLD" "$C_RESET"
  echo

  if [[ $DO_RUN -eq 1 ]]; then
    log "launching kekkai-agent in foreground (Ctrl+C to stop)"
    exec $SUDO "$AGENT_BIN" -config "$CONFIG_FILE"
  fi
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
[[ "$OS" != "unsupported" ]] || die "unsupported OS: $(uname -s)"
[[ "$ARCH" != "unsupported" ]] || die "unsupported arch: $(uname -m)"

if [[ -z "$CMD" ]]; then
  CMD="$(detect_state)"
  case "$CMD" in
    install) info "detected state: not installed → install" ;;
    repair)  info "detected state: partial install → repair" ;;
    update)  info "detected state: upstream has new commits → update" ;;
    healthy) info "detected state: healthy → running doctor"; CMD="doctor" ;;
  esac
fi

case "$CMD" in
  install)   do_install ;;
  update)    do_update ;;
  repair)    do_repair ;;
  doctor)    do_doctor ;;
  uninstall) do_uninstall ;;
  *) die "unknown command: $CMD" ;;
esac
