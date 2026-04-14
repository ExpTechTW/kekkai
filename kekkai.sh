#!/usr/bin/env bash
# kekkai — one-script installer / updater / repair tool.
#
# Usage:
#   bash kekkai.sh               # auto-detect state and do the right thing
#   bash kekkai.sh install       # force first-time install
#   bash kekkai.sh update        # force update (source depends on update.channel)
#   bash kekkai.sh repair        # force re-install of binaries + systemd unit
#   bash kekkai.sh doctor        # read-only health check (delegates to `kekkai doctor`)
#   bash kekkai.sh uninstall     # remove everything except config
#
# Flags (apply to any subcommand):
#   --force       bypass safety checks (dirty tree, branch mismatch, downgrade)
#   --no-install  skip apt dependency install
#   --iface NAME  force a specific interface in the default config
#   --run         launch the agent in foreground at the end (debugging)
#   --sudo-shortcut     force enable passwordless `kekkai` sudo + shell alias
#   --no-sudo-shortcut  disable passwordless sudo shortcut setup
#
# Auto-detect logic (no subcommand):
#   - no binaries yet            → install
#   - binaries present but no systemd unit OR unit disabled → repair
#   - everything installed + update source has new version → update
#   - everything installed + no new commits → doctor
#
set -euo pipefail

# ROOT resolution:
# - repo mode: directory containing kekkai.sh (normal git clone usage)
# - raw mode (`bash <(curl ...)`): fallback to ~/kekkai (or $KEKKAI_REPO)
#   because $0 becomes /dev/fd/* and is not a writable project directory.
resolve_root() {
  if [[ -n "${KEKKAI_REPO:-}" ]]; then
    mkdir -p "$KEKKAI_REPO"
    (cd "$KEKKAI_REPO" && pwd)
    return
  fi

  local script_dir
  script_dir="$(cd "$(dirname "$0")" && pwd)"

  if [[ "$script_dir" == /dev/fd* ]] || [[ "$script_dir" == /proc/*/fd* ]]; then
    local fallback="${HOME:-/tmp}/kekkai"
    mkdir -p "$fallback"
    (cd "$fallback" && pwd)
    return
  fi

  echo "$script_dir"
}

ROOT="$(resolve_root)"
cd "$ROOT"

# Ensure a reusable local script copy exists for `kekkai update`.
# This is critical when running via process substitution:
#   bash <(curl -fsSL .../kekkai.sh)
# where $0 is /dev/fd/* and no on-disk kekkai.sh exists by default.
persist_self_script() {
  local target="$ROOT/kekkai.sh"
  if [[ -f "$target" ]] && [[ -s "$target" ]]; then
    return 0
  fi
  if [[ -r "$0" ]]; then
    cat "$0" > "$target" 2>/dev/null || true
    chmod +x "$target" 2>/dev/null || true
  fi
}

persist_self_script

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
SUDOERS_DIR=/etc/sudoers.d
SUDOERS_FILE_PREFIX=kekkai-cli-
GO_MIN="1.22"
GO_DOWNLOAD_VERSION="1.23.4"
BRANCH=main
REPO_OWNER=ExpTechTW
REPO_NAME=kekkai
RELEASES_API_BASE="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases"

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
CMD=""
FORCE=0
DO_INSTALL_DEPS=1
IFACE_OVERRIDE=""
DO_RUN=0
SETUP_SUDO_SHORTCUT=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|update|repair|doctor|uninstall)
      CMD="$1"; shift ;;
    --force)       FORCE=1; shift ;;
    --no-install)  DO_INSTALL_DEPS=0; shift ;;
    --iface)       IFACE_OVERRIDE="$2"; shift 2 ;;
    --run)         DO_RUN=1; shift ;;
    --sudo-shortcut) SETUP_SUDO_SHORTCUT=1; shift ;;
    --no-sudo-shortcut) SETUP_SUDO_SHORTCUT=0; shift ;;
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
  # Returns one of: install / repair / update / healthy.
  #
  # "update" is triggered by either:
  #   a) the remote has commits we don't
  #   b) the local HEAD is newer than the installed agent binary's
  #      mtime — meaning the user already pulled but never rebuilt.
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

  if [[ "$SOURCE_MODE" == "repo" ]] && command -v git >/dev/null 2>&1; then
    git fetch origin "$BRANCH" >/dev/null 2>&1 || true

    local head remote
    head="$(git rev-parse HEAD 2>/dev/null || echo "")"
    remote="$(git rev-parse "origin/$BRANCH" 2>/dev/null || echo "")"

    # (a) Remote has new commits → clearly need to update.
    if [[ -n "$head" ]] && [[ -n "$remote" ]] && [[ "$head" != "$remote" ]]; then
      echo update
      return
    fi

    # (b) Local HEAD is newer than the installed daemon binary. This
    #     catches "user ran git pull but never rebuilt" — the repo is
    #     caught up to origin but the binary on disk is stale.
    if [[ -n "$head" ]]; then
      local head_ts bin_ts
      head_ts="$(git show -s --format=%ct "$head" 2>/dev/null || echo 0)"
      if command -v stat >/dev/null 2>&1; then
        # Prefer GNU stat, fall back to BSD stat.
        bin_ts="$(stat -c %Y "$AGENT_BIN" 2>/dev/null || stat -f %m "$AGENT_BIN" 2>/dev/null || echo 0)"
      else
        bin_ts=0
      fi
      if [[ "$head_ts" != "0" ]] && [[ "$bin_ts" != "0" ]] && (( head_ts > bin_ts )); then
        echo update
        return
      fi
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
    make gcc pkg-config ca-certificates curl libcap2-bin
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

iface_has_default_allowlist_ip() {
  local iface="$1"
  [[ -n "$iface" ]] || return 1
  # default allowlist is 192.168.0.0/16
  ip -o -4 addr show dev "$iface" scope global 2>/dev/null | \
    awk '
      {
        split($4, parts, "/")
        ip = parts[1]
        split(ip, octets, ".")
        if (octets[1] == 192 && octets[2] == 168) {
          found = 1
        }
      }
      END { exit(found ? 0 : 1) }
    '
}

read_update_channel_from_config() {
  local cfg="${1:-$CONFIG_FILE}"
  [[ -f "$cfg" ]] || return 1
  awk '
    /^[[:space:]]*#/ { next }
    /^update:[[:space:]]*$/ { in_update=1; next }
    /^[^[:space:]]/ { in_update=0 }
    in_update && /^[[:space:]]+channel:[[:space:]]*/ {
      line=$0
      sub(/^[[:space:]]+channel:[[:space:]]*/, "", line)
      gsub(/["'\''[:space:]]/, "", line)
      print line
      exit 0
    }
  ' "$cfg"
}

resolve_update_channel() {
  local ch
  ch="${KEKKAI_UPDATE_CHANNEL:-}"
  if [[ -z "$ch" ]]; then
    ch="$(read_update_channel_from_config "$CONFIG_FILE" 2>/dev/null || true)"
  fi
  [[ -n "$ch" ]] || ch="release"
  case "$ch" in
    git:main|release|pre-release) ;;
    *)
      warn "unknown update.channel '$ch' — fallback to git:main"
      ch="git:main"
      ;;
  esac
  echo "$ch"
}

prepare_binaries() {
  if [[ "$SOURCE_MODE" == "repo" ]]; then
    ensure_go
    build_from_source
    return 0
  fi

  local channel
  channel="$(resolve_update_channel)"
  case "$channel" in
    release|pre-release)
      fetch_release_binaries_to_root_bin "$channel"
      ;;
    git:main)
      die "update.channel=git:main requires repo mode. For raw install use update.channel=release or pre-release."
      ;;
    *)
      die "unsupported update.channel: $channel"
      ;;
  esac
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

install_binaries_from() {
  local src_agent="$1"
  local src_cli="$2"
  [[ -x "$src_agent" ]] || die "missing agent binary: $src_agent"
  [[ -x "$src_cli" ]] || die "missing cli binary: $src_cli"

  # Rollback snapshot of the current daemon (update only — install has
  # nothing to roll back to).
  if [[ -f "$AGENT_BIN" ]]; then
    $SUDO cp -a "$AGENT_BIN" "$ROLLBACK_BIN" || true
  fi

  $SUDO install -D -m 0755 "$src_agent" "$AGENT_BIN"
  log "installed: $AGENT_BIN"

  $SUDO install -D -m 0755 "$src_cli" "$CLI_BIN"
  log "installed: $CLI_BIN"

  setup_status_capabilities
}

install_binaries() {
  install_binaries_from "$ROOT/bin/kekkai-agent" "$ROOT/bin/kekkai"
}

read_cli_version() {
  local bin="$1"
  [[ -x "$bin" ]] || { echo "(none)"; return 0; }
  local v
  v="$("$bin" version 2>/dev/null | awk 'NR==1{print $2}' || true)"
  [[ -n "$v" ]] || v="unknown"
  echo "$v"
}

print_version_transition() {
  local old_v="$1"
  local new_v="$2"
  info "version: ${old_v} -> ${new_v}"
}

setup_sudo_shortcut() {
  [[ $SETUP_SUDO_SHORTCUT -eq 1 ]] || return 0
  [[ "$OS" == "linux" ]] || { warn "--sudo-shortcut is Linux-only"; return 0; }

  local target_user
  target_user="${SUDO_USER:-$USER}"
  if [[ -z "$target_user" ]] || [[ "$target_user" == "root" ]]; then
    warn "skip sudo shortcut setup for root user"
    return 0
  fi

  local target_home
  target_home="$(eval echo "~$target_user")"
  if [[ -z "$target_home" ]] || [[ ! -d "$target_home" ]]; then
    warn "cannot resolve home for user '$target_user'; skip sudo shortcut setup"
    return 0
  fi

  local sudoers_file="$SUDOERS_DIR/${SUDOERS_FILE_PREFIX}${target_user}"
  local sudoers_line="$target_user ALL=(root) NOPASSWD: $CLI_BIN *"
  log "configuring passwordless sudo for $CLI_BIN (user=$target_user)"
  $SUDO install -d -m 0755 "$SUDOERS_DIR"
  printf '%s\n' "$sudoers_line" | $SUDO tee "$sudoers_file" >/dev/null
  $SUDO chmod 0440 "$sudoers_file"
  if ! $SUDO visudo -cf "$sudoers_file" >/dev/null; then
    $SUDO rm -f "$sudoers_file"
    die "invalid sudoers syntax generated; aborted --sudo-shortcut"
  fi

  local shell_name rc_file alias_line
  shell_name="$(basename "${SHELL:-}")"
  case "$shell_name" in
    zsh)  rc_file="$target_home/.zshrc" ;;
    bash) rc_file="$target_home/.bashrc" ;;
    *)    rc_file="$target_home/.profile" ;;
  esac
  alias_line="alias kekkai='sudo $CLI_BIN'"
  if [[ ! -f "$rc_file" ]]; then
    $SUDO touch "$rc_file"
    $SUDO chown "$target_user":"$target_user" "$rc_file" 2>/dev/null || true
  fi
  if ! $SUDO grep -Fq "$alias_line" "$rc_file" 2>/dev/null; then
    printf '\n%s\n' "$alias_line" | $SUDO tee -a "$rc_file" >/dev/null
    $SUDO chown "$target_user":"$target_user" "$rc_file" 2>/dev/null || true
    log "added alias to $rc_file"
  else
    info "alias already present in $rc_file"
  fi
  info "open a new shell or run: source $rc_file"
}

setup_status_capabilities() {
  [[ "$OS" == "linux" ]] || return 0
  if ! command -v setcap >/dev/null 2>&1; then
    warn "setcap not found; install libcap2-bin to allow non-root 'kekkai status'"
    return 0
  fi

  # Some kernels still gate BPF object read behind CAP_SYS_ADMIN.
  local caps="cap_bpf,cap_perfmon,cap_sys_admin+ep"
  if $SUDO setcap "$caps" "$CLI_BIN"; then
    log "granted $caps on $CLI_BIN (non-root status support)"
  else
    warn "setcap failed for $CLI_BIN; 'kekkai status' may still require sudo"
  fi
}

repair_bpffs_status_permissions() {
  [[ "$OS" == "linux" ]] || return 0
  [[ -d "$BPFFS_DIR" ]] || return 0
  # Keep status readable for non-root users.
  $SUDO chmod 0755 "$BPFFS_DIR" 2>/dev/null || true
  $SUDO chmod 0644 "$BPFFS_DIR"/* 2>/dev/null || true
}

probe_status_permissions() {
  [[ "$OS" == "linux" ]] || return 0
  local ok=1

  if [[ ! -d "$BPFFS_DIR" ]]; then
    warn "status permission probe: $BPFFS_DIR missing (agent may not have pinned maps yet)"
    return 0
  fi
  if [[ ! -r "$BPFFS_DIR" || ! -x "$BPFFS_DIR" ]]; then
    warn "status permission probe: $BPFFS_DIR is not traversable by current user"
    ok=0
  fi

  if [[ -e "$BPFFS_DIR/stats" ]]; then
    if [[ ! -r "$BPFFS_DIR/stats" ]]; then
      warn "status permission probe: $BPFFS_DIR/stats is not readable"
      ok=0
    fi
  else
    warn "status permission probe: $BPFFS_DIR/stats missing"
    ok=0
  fi

  if command -v getcap >/dev/null 2>&1; then
    local caps
    caps="$(getcap "$CLI_BIN" 2>/dev/null || true)"
    if [[ "$caps" == *cap_bpf* && "$caps" == *cap_perfmon* && "$caps" == *cap_sys_admin* ]]; then
      info "status permission probe: CLI capabilities ok"
    else
      warn "status permission probe: $CLI_BIN missing required capabilities (need cap_bpf,cap_perfmon,cap_sys_admin+ep)"
      ok=0
    fi
  else
    warn "status permission probe: getcap not found (cannot verify CLI capabilities)"
  fi

  if [[ $ok -eq 1 ]]; then
    log "status permission probe passed"
  else
    warn "status permission probe warns: non-root 'kekkai status' may still fail"
  fi
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
  if ! iface_has_default_allowlist_ip "$iface"; then
    warn "detected iface '$iface' is not in default ingress_allowlist 192.168.0.0/16"
    warn "service may reject startup until you set filter.ingress_allowlist to your management subnet"
  fi
  warn "review $CONFIG_FILE and set filter.ingress_allowlist to your management network"
}

install_systemd_unit() {
  command -v systemctl >/dev/null 2>&1 || { warn "systemctl not found — skipping unit install"; return; }
  log "installing systemd unit to $UNIT_DST"
  if [[ -f "$UNIT_SRC" ]]; then
    $SUDO install -D -m 0644 "$UNIT_SRC" "$UNIT_DST"
  else
    warn "systemd unit template not found in $ROOT; using built-in fallback unit"
    local tmp_unit
    tmp_unit="$(mktemp)"
    cat > "$tmp_unit" <<'EOF'
[Unit]
Description=kekkai edge XDP firewall agent
Documentation=https://github.com/ExpTechTW/kekkai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kekkai-agent -config /etc/kekkai/kekkai.yaml -managed-config /etc/kekkai/kekkai.agent.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s
User=root
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=false
ReadWritePaths=/sys/fs/bpf /var/run /run /etc/kekkai
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kekkai-agent

[Install]
WantedBy=multi-user.target
EOF
    $SUDO install -D -m 0644 "$tmp_unit" "$UNIT_DST"
    rm -f "$tmp_unit"
  fi
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
  repair_bpffs_status_permissions
  probe_status_permissions
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
  # Avoid interactive hangs on first SSH contact with github.com.
  # Users can disable this behavior by setting:
  #   KEKKAI_GIT_ACCEPT_NEW_HOSTKEY=0
  local accept_new_hostkey="${KEKKAI_GIT_ACCEPT_NEW_HOSTKEY:-1}"
  if [[ "$accept_new_hostkey" == "1" ]]; then
    GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o StrictHostKeyChecking=accept-new}" \
      git fetch origin "$BRANCH"
  else
    git fetch origin "$BRANCH"
  fi
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

fetch_release_metadata() {
  local channel="$1"
  local endpoint
  case "$channel" in
    release)
      endpoint="$RELEASES_API_BASE/latest"
      ;;
    pre-release)
      endpoint="$RELEASES_API_BASE?per_page=30"
      ;;
    *)
      die "fetch_release_metadata: unsupported channel '$channel'"
      ;;
  esac
  curl -fsSL -H "Accept: application/vnd.github+json" "$endpoint"
}

select_release_assets() {
  local channel="$1"
  local os="$2"
  local arch="$3"
  python3 -c '
import json
import sys

channel, os_name, arch = sys.argv[1:4]
data = json.load(sys.stdin)

def pick_release(obj):
    if channel == "release":
        return obj
    for rel in obj:
        if rel.get("draft"):
            continue
        if rel.get("prerelease"):
            return rel
    return None

release = pick_release(data)
if not release:
    raise SystemExit("no matching release found")

assets = release.get("assets", [])

def is_noise(name):
    n = name.lower()
    return n.endswith((".sha256", ".sha256sum", ".sig", ".txt", ".json", ".sbom"))

def score(kind, name):
    n = name.lower()
    if kind not in n:
        return -1
    if kind == "kekkai" and "agent" in n:
        return -1
    if is_noise(name):
        return -1
    s = 0
    if os_name in n:
        s += 5
    if arch in n:
        s += 5
    if f"{os_name}-{arch}" in n or f"{os_name}_{arch}" in n:
        s += 3
    if n.endswith((".tar.gz", ".tgz", ".zip")):
        s -= 1
    return s

def best_asset(kind):
    best = None
    best_s = -1
    for a in assets:
        name = a.get("name", "")
        s = score(kind, name)
        if s > best_s:
            best_s = s
            best = a
    return best if best_s >= 8 else None

agent = best_asset("kekkai-agent")
cli = best_asset("kekkai")
if agent is None or cli is None:
    raise SystemExit("release assets for kekkai-agent/kekkai not found for target os/arch")

print(release.get("tag_name", "unknown"))
print(agent["browser_download_url"])
print(cli["browser_download_url"])
' "$channel" "$os" "$arch"
}

download_release_binary() {
  local url="$1"
  local want_name="$2"
  local tmpdir="$3"
  local archive="$tmpdir/$(basename "${url%%\?*}")"
  [[ -n "$archive" ]] || die "invalid asset url: $url"

  curl -fL --retry 4 --retry-delay 1 --retry-all-errors --connect-timeout 10 \
    "$url" -o "$archive" || return 1

  local out="$tmpdir/$want_name"
  case "$archive" in
    *.tar.gz|*.tgz)
      local ex="$tmpdir/extract-$want_name"
      mkdir -p "$ex"
      tar -xzf "$archive" -C "$ex"
      local found
      found="$(find "$ex" -type f -name "$want_name" -print -quit)"
      [[ -n "$found" ]] || die "archive $(basename "$archive") missing $want_name"
      cp "$found" "$out"
      ;;
    *.zip)
      command -v unzip >/dev/null 2>&1 || die "unzip not found (required for zip release assets)"
      local ex="$tmpdir/extract-$want_name"
      mkdir -p "$ex"
      unzip -q "$archive" -d "$ex"
      local found
      found="$(find "$ex" -type f -name "$want_name" -print -quit)"
      [[ -n "$found" ]] || die "archive $(basename "$archive") missing $want_name"
      cp "$found" "$out"
      ;;
    *)
      cp "$archive" "$out"
      ;;
  esac

  chmod +x "$out"
  # Quick sanity check: broken/partial downloads often crash immediately.
  # We treat signal exits as corrupted binary and abort update early.
  "$out" -h >/dev/null 2>&1 || {
    local rc=$?
    if (( rc >= 128 )); then
      err "downloaded $want_name looks corrupted (exit=$rc)"
      return 1
    fi
  }
  echo "$out"
}

release_update() {
  local channel="$1"
  local old_ver
  old_ver="$(read_cli_version "$CLI_BIN")"
  command -v curl >/dev/null 2>&1 || die "curl not found"
  command -v python3 >/dev/null 2>&1 || die "python3 not found (required for release metadata parsing)"

  local meta
  meta="$(fetch_release_metadata "$channel")" || die "failed to fetch GitHub release metadata"

  local parsed
  parsed="$(printf '%s' "$meta" | select_release_assets "$channel" "$OS" "$ARCH")" || die "failed to resolve release assets for $OS/$ARCH"
  local tag agent_url cli_url
  tag="$(printf '%s\n' "$parsed" | sed -n '1p')"
  agent_url="$(printf '%s\n' "$parsed" | sed -n '2p')"
  cli_url="$(printf '%s\n' "$parsed" | sed -n '3p')"
  [[ -n "$agent_url" && -n "$cli_url" ]] || die "release metadata incomplete"

  log "selected release: $tag ($channel)"
  info "agent asset: $(basename "${agent_url%%\?*}")"
  info "cli asset:   $(basename "${cli_url%%\?*}")"

  local tmpdir
  tmpdir="$(mktemp -d)"

  local new_agent new_cli
  new_agent="$(download_release_binary "$agent_url" "kekkai-agent" "$tmpdir")" || die "failed to download/verify kekkai-agent binary"
  new_cli="$(download_release_binary "$cli_url" "kekkai" "$tmpdir")" || die "failed to download/verify kekkai binary"
  local new_ver
  new_ver="$(read_cli_version "$new_cli")"

  validate_config_against_new_binary "$new_agent"

  local old_sha new_sha
  old_sha=""; [[ -f "$AGENT_BIN" ]] && old_sha="$(sha256sum "$AGENT_BIN" | awk '{print $1}')"
  new_sha="$(sha256sum "$new_agent" | awk '{print $1}')"
  if [[ "$old_sha" == "$new_sha" ]]; then
    repair_bpffs_status_permissions
    setup_status_capabilities
    probe_status_permissions
    log "up-to-date (binary unchanged — nothing to restart)"
    print_version_transition "$old_ver" "$new_ver"
    rm -rf "$tmpdir"
    return 0
  fi

  install_binaries_from "$new_agent" "$new_cli"
  rm -rf "$tmpdir"
  setup_sudo_shortcut
  enable_and_start
  log "update complete (channel=$channel, tag=$tag)"
  print_version_transition "$old_ver" "$new_ver"
}

fetch_release_binaries_to_root_bin() {
  local channel="$1"
  command -v curl >/dev/null 2>&1 || die "curl not found"
  command -v python3 >/dev/null 2>&1 || die "python3 not found (required for release metadata parsing)"

  local meta
  meta="$(fetch_release_metadata "$channel")" || die "failed to fetch GitHub release metadata"

  local parsed
  parsed="$(printf '%s' "$meta" | select_release_assets "$channel" "$OS" "$ARCH")" || die "failed to resolve release assets for $OS/$ARCH"
  local tag agent_url cli_url
  tag="$(printf '%s\n' "$parsed" | sed -n '1p')"
  agent_url="$(printf '%s\n' "$parsed" | sed -n '2p')"
  cli_url="$(printf '%s\n' "$parsed" | sed -n '3p')"
  [[ -n "$agent_url" && -n "$cli_url" ]] || die "release metadata incomplete"

  log "selected release: $tag ($channel)"
  info "agent asset: $(basename "${agent_url%%\?*}")"
  info "cli asset:   $(basename "${cli_url%%\?*}")"

  local tmpdir
  tmpdir="$(mktemp -d)"
  local new_agent new_cli
  new_agent="$(download_release_binary "$agent_url" "kekkai-agent" "$tmpdir")" || die "failed to download/verify kekkai-agent binary"
  new_cli="$(download_release_binary "$cli_url" "kekkai" "$tmpdir")" || die "failed to download/verify kekkai binary"

  mkdir -p "$ROOT/bin"
  cp "$new_agent" "$ROOT/bin/kekkai-agent"
  cp "$new_cli" "$ROOT/bin/kekkai"
  chmod +x "$ROOT/bin/kekkai-agent" "$ROOT/bin/kekkai"
  rm -rf "$tmpdir"
}

validate_config_against_new_binary() {
  local candidate_bin="${1:-$ROOT/bin/kekkai-agent}"
  [[ -f "$CONFIG_FILE" ]] || return 0
  log "validating $CONFIG_FILE against new binary"
  local rc=0
  if "$candidate_bin" -check "$CONFIG_FILE" >/tmp/kekkai-check.log 2>&1; then
    rc=0
  else
    rc=$?
  fi
  if (( rc != 0 )); then
    echo
    err "new binary validation failed:"
    sed 's/^/    /' /tmp/kekkai-check.log >&2
    echo
    if (( rc >= 128 )); then
      err "the new binary crashed during check (exit=$rc), likely corrupted download or bad artifact."
      err "the installed config was NOT applied; old binary/service stay untouched."
      echo
      info "retry update first:"
      info "  bash ./kekkai.sh update"
      info "if it repeats, pin previous tag or check release artifact health."
      exit 1
    fi
    err "the installed config is incompatible with the new binary."
    err "the old binary and service are still running untouched."
    echo
    info "to fix, one of:"
    info "  1. edit the config:        sudo nano $CONFIG_FILE"
    info "  2. reset to a clean template (backs up the broken file first):"
    info "       sudo $ROOT/bin/kekkai-agent -reset -config $CONFIG_FILE"
    info "     then edit to add filter.ingress_allowlist, and re-run:"
    info "       bash ./kekkai.sh update"
    info "  3. restore from an earlier backup:"
    info "       ls /etc/kekkai/kekkai.yaml.*"
    info "       sudo cp /etc/kekkai/kekkai.yaml.<kind>.<ts> $CONFIG_FILE"
    exit 1
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
  check_kernel
  prepare_binaries
  install_binaries
  setup_sudo_shortcut
  install_config
  install_systemd_unit
  enable_and_start
  log "install complete"
  post_install_hints
}

do_update() {
  banner
  step "update · $OS/$ARCH"
  local old_ver
  old_ver="$(read_cli_version "$CLI_BIN")"
  local channel
  channel="$(resolve_update_channel)"
  log "update channel: $channel"

  case "$channel" in
    git:main)
      ensure_go
      git_update
      build_from_source
      validate_config_against_new_binary "$ROOT/bin/kekkai-agent"
      local new_ver
      new_ver="$(read_cli_version "$ROOT/bin/kekkai")"

      local old_sha new_sha
      old_sha=""; [[ -f "$AGENT_BIN" ]] && old_sha="$(sha256sum "$AGENT_BIN" | awk '{print $1}')"
      new_sha="$(sha256sum "$ROOT/bin/kekkai-agent" | awk '{print $1}')"
      if [[ "$old_sha" == "$new_sha" ]]; then
        repair_bpffs_status_permissions
        setup_status_capabilities
        probe_status_permissions
        log "up-to-date (binary unchanged — nothing to restart)"
        print_version_transition "$old_ver" "$new_ver"
        return 0
      fi
      install_binaries
      setup_sudo_shortcut
      enable_and_start
      log "update complete (channel=git:main)"
      print_version_transition "$old_ver" "$new_ver"
      ;;
    release|pre-release)
      release_update "$channel"
      ;;
    *)
      die "unsupported update channel: $channel"
      ;;
  esac
}

do_repair() {
  banner
  step "repair · $OS/$ARCH"
  prepare_binaries
  install_binaries
  setup_sudo_shortcut
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
  printf '  %s4.%s watch live:       kekkai status\n' "$C_BOLD" "$C_RESET"
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
