#!/usr/bin/env bash
# kekkai — one-script installer / updater / repair tool.
#
# Usage:
#   bash kekkai.sh               # auto-detect state and do the right thing
#   bash kekkai.sh install       # force first-time install
#   bash kekkai.sh update        # force update (pulls prebuilt release assets)
#   bash kekkai.sh repair        # force re-install of binaries + systemd unit
#   bash kekkai.sh doctor        # read-only health check (delegates to `kekkai doctor`)
#   bash kekkai.sh uninstall     # remove everything except config
#
# Flags (apply to any subcommand):
#   --no-install  skip apt dependency install
#   --iface NAME  force a specific interface in the default config
#   --run         launch the agent in foreground at the end (debugging)
#
# Update model: kekkai is distributed as prebuilt GitHub release binaries.
# `update.channel` may be `release` (default) or `pre-release`. There is no
# source-build mode — operators never need Go, git, clang, or this repo on
# the target host.
#
# Runtime note: kekkai CLI always runs under sudo (e.g. `sudo kekkai status`)
# because on Debian/Ubuntu/Pi OS the kernel sysctl
# `kernel.unprivileged_bpf_disabled` blocks non-root bpf() regardless of caps.
# The installer writes a sudoers drop-in (/etc/sudoers.d/kekkai-cli-<user>)
# so `sudo kekkai ...` won't prompt for a password. No shell alias is added —
# users should type literal `sudo kekkai` to build portable muscle memory.
#
# Auto-detect logic (no subcommand):
#   - no binaries yet            → install
#   - binaries present but no systemd unit OR unit disabled → repair
#   - otherwise                  → doctor (use `update` subcommand explicitly
#                                  to check for a new release)
#
set -euo pipefail

# ROOT resolution:
# - normal: directory containing kekkai.sh on disk (/usr/local/bin or dev dir)
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
SCRIPT_INSTALL_PATH=/usr/local/bin/kekkai.sh
BASH_COMPLETION_DST=/usr/share/bash-completion/completions/kekkai
ZSH_COMPLETION_DST=/usr/share/zsh/vendor-completions/_kekkai
CONFIG_DIR=/etc/kekkai
CONFIG_FILE="$CONFIG_DIR/kekkai.yaml"
STATS_DIR=/var/run/kekkai
BPFFS_DIR=/sys/fs/bpf/kekkai
UNIT_NAME=kekkai-agent.service
UNIT_SRC="$ROOT/deploy/systemd/kekkai-agent.service"
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
SUDOERS_DIR=/etc/sudoers.d
SUDOERS_FILE_PREFIX=kekkai-cli-
LOCAL_AGENT_BIN="$ROOT/bin/kekkai-agent"
LOCAL_CLI_BIN="$ROOT/bin/kekkai"
BRANCH=main
REPO_OWNER=ExpTechTW
REPO_NAME=kekkai
RELEASES_API_BASE="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases"
RAW_BASE="https://raw.githubusercontent.com/$REPO_OWNER/$REPO_NAME"

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
CMD=""
DO_INSTALL_DEPS=1
IFACE_OVERRIDE=""
DO_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|update|repair|doctor|uninstall)
      CMD="$1"; shift ;;
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
  C_BLUE=$'\033[1;34m'  # blue — "something changed" accent for update results
  C_TITLE=$'\033[1;35m' # violet — kekkai barrier theme
else
  C_RESET=""; C_DIM=""; C_BOLD=""; C_OK=""; C_WARN=""; C_ERR=""; C_INFO=""; C_BLUE=""; C_TITLE=""
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
# ---------------------------------------------------------------------------
# State detection — which subcommand should auto mode run?
# ---------------------------------------------------------------------------
detect_state() {
  # Returns one of: install / repair / healthy.
  #
  # Update detection from the installed state is no longer automatic —
  # operators run `kekkai update` explicitly when they want to check GitHub
  # releases. The auto-mode path just ensures the local install is sane.
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
    release|pre-release) ;;
    *)
      warn "unknown update.channel '$ch' — fallback to release"
      ch="release"
      ;;
  esac
  echo "$ch"
}

prepare_binaries() {
  local channel
  channel="$(resolve_update_channel)"
  fetch_release_binaries_to_root_bin "$channel"
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

  install_completions
}

# persist_script_for_updates puts a copy of kekkai.sh at /usr/local/bin/kekkai.sh
# so future `sudo kekkai update` calls can find it via resolveUpdateScript().
#
# Three sources, in priority order:
#   1. $ROOT/kekkai.sh (repo clone or persist_self_script() already worked)
#   2. $0 itself, if it's a readable regular file (not /dev/fd/*)
#   3. curl from the main branch on GitHub (last resort for one-shot
#      `curl | bash` installs where $0 is /dev/fd/* and $ROOT is empty)
persist_script_for_updates() {
  [[ "$OS" == "linux" ]] || return 0

  local src=""
  if [[ -f "$ROOT/kekkai.sh" ]] && [[ -s "$ROOT/kekkai.sh" ]]; then
    src="$ROOT/kekkai.sh"
  elif [[ -r "$0" ]] && [[ -f "$0" ]]; then
    src="$0"
  fi

  # Skip self-copy: if $0 is already the installed script (common during
  # `sudo kekkai update`, where kekkai delegates to /usr/local/bin/kekkai.sh),
  # `install` would error with "same file". Treat that case as already persisted.
  if [[ -n "$src" ]]; then
    local src_real dst_real
    src_real="$(readlink -f "$src" 2>/dev/null || echo "$src")"
    dst_real="$(readlink -f "$SCRIPT_INSTALL_PATH" 2>/dev/null || echo "$SCRIPT_INSTALL_PATH")"
    if [[ "$src_real" == "$dst_real" ]]; then
      return 0
    fi
    $SUDO install -D -m 0755 "$src" "$SCRIPT_INSTALL_PATH"
    log "installed: $SCRIPT_INSTALL_PATH (for future 'sudo kekkai update')"
    return 0
  fi

  # Fallback: fetch from GitHub. Acceptable here because we're already
  # mid-install from curl|bash — the user has implicitly trusted main.
  if command -v curl >/dev/null 2>&1; then
    local tmp
    tmp="$(mktemp)"
    if curl -fsSL "$RAW_BASE/$BRANCH/kekkai.sh" -o "$tmp" 2>/dev/null && [[ -s "$tmp" ]]; then
      $SUDO install -D -m 0755 "$tmp" "$SCRIPT_INSTALL_PATH"
      rm -f "$tmp"
      log "installed: $SCRIPT_INSTALL_PATH (fetched from $BRANCH — for future 'sudo kekkai update')"
      return 0
    fi
    rm -f "$tmp"
  fi

  warn "could not persist kekkai.sh to $SCRIPT_INSTALL_PATH — 'sudo kekkai update' will need KEKKAI_SCRIPT set"
}

# fetch_or_copy_asset: stage a repo-tracked file at $1 (relative to $ROOT)
# into a temp path. Prefers the on-disk copy; falls back to curl from
# $RAW_BASE/$BRANCH/$1. Echoes the staged path on success, empty on failure.
fetch_or_copy_asset() {
  local rel="$1"
  local local_src="$ROOT/$rel"
  if [[ -f "$local_src" ]] && [[ -s "$local_src" ]]; then
    echo "$local_src"
    return 0
  fi
  command -v curl >/dev/null 2>&1 || return 1
  local tmp
  tmp="$(mktemp)"
  if curl -fsSL "$RAW_BASE/$BRANCH/$rel" -o "$tmp" 2>/dev/null && [[ -s "$tmp" ]]; then
    echo "$tmp"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# install_completions drops the bash + zsh completion scripts into the
# distro's standard vendor paths. Silently skips targets whose parent
# dir doesn't exist (e.g. systems without zsh installed). Non-fatal.
install_completions() {
  [[ "$OS" == "linux" ]] || return 0

  local bash_src zsh_src
  bash_src="$(fetch_or_copy_asset contrib/completions/kekkai.bash)" || bash_src=""
  zsh_src="$(fetch_or_copy_asset contrib/completions/_kekkai)"      || zsh_src=""

  if [[ -n "$bash_src" ]] && [[ -d "$(dirname "$BASH_COMPLETION_DST")" ]]; then
    $SUDO install -D -m 0644 "$bash_src" "$BASH_COMPLETION_DST"
    log "installed: $BASH_COMPLETION_DST"
  fi
  if [[ -n "$zsh_src" ]] && [[ -d "$(dirname "$ZSH_COMPLETION_DST")" ]]; then
    $SUDO install -D -m 0644 "$zsh_src" "$ZSH_COMPLETION_DST"
    log "installed: $ZSH_COMPLETION_DST"
  fi

  # Clean up any temp files fetch_or_copy_asset may have created.
  [[ -n "$bash_src" && "$bash_src" != "$ROOT"* ]] && rm -f "$bash_src"
  [[ -n "$zsh_src"  && "$zsh_src"  != "$ROOT"* ]] && rm -f "$zsh_src"

  if [[ -z "$bash_src" ]] && [[ -z "$zsh_src" ]]; then
    warn "shell completions not installed (no local or remote source)"
  fi
}

install_binaries() {
  install_binaries_from "$LOCAL_AGENT_BIN" "$LOCAL_CLI_BIN"
}

read_cli_version() {
  local bin="$1"
  [[ -x "$bin" ]] || { echo "(none)"; return 0; }
  local v
  v="$("$bin" version 2>/dev/null | awk 'NR==1{print $2}' || true)"
  [[ -n "$v" ]] || v="unknown"
  echo "$v"
}


# print_update_result renders the final coloured summary block that users
# should scan first after an update. Two states:
#
#   state=updated    → blue accent, headline "UPDATED"
#   state=unchanged  → green accent, headline "ALREADY UP-TO-DATE"
#
# Args: state old_ver new_ver tag channel changed
# `tag` / `channel` / `changed` may be empty. `changed` is a human-readable
# comma-separated list of components that were actually rewritten (e.g.
# "agent, cli, kekkai.sh") — only rendered for state=updated.
print_update_result() {
  local state="$1" old_v="$2" new_v="$3" tag="$4" channel="$5" changed="$6"
  local accent headline
  case "$state" in
    updated)
      accent="$C_BLUE"
      headline="UPDATED"
      ;;
    unchanged)
      accent="$C_OK"
      headline="ALREADY UP-TO-DATE"
      ;;
    *)
      accent="$C_INFO"
      headline="$state"
      ;;
  esac

  local bar="═══════════════════════════════════════════════"
  echo
  printf '%s%s%s\n' "$accent" "$bar" "$C_RESET"
  printf '%s  ◈ %s%s\n' "$accent" "$headline" "$C_RESET"
  printf '%s%s%s\n' "$accent" "$bar" "$C_RESET"
  if [[ "$state" == "unchanged" ]]; then
    printf '  %sversion%s    %s%s%s  (no change)\n' \
      "$C_DIM" "$C_RESET" "$C_BOLD" "$new_v" "$C_RESET"
  else
    printf '  %sversion%s    %s%s%s  →  %s%s%s\n' \
      "$C_DIM" "$C_RESET" \
      "$C_DIM" "$old_v" "$C_RESET" \
      "$C_BOLD" "$new_v" "$C_RESET"
  fi
  if [[ "$state" == "updated" && -n "$changed" ]]; then
    printf '  %schanged%s    %s\n' "$C_DIM" "$C_RESET" "$changed"
  fi
  if [[ -n "$tag" ]]; then
    printf '  %stag%s        %s\n' "$C_DIM" "$C_RESET" "$tag"
  fi
  if [[ -n "$channel" ]]; then
    printf '  %schannel%s    %s\n' "$C_DIM" "$C_RESET" "$channel"
  fi
  printf '%s%s%s\n' "$accent" "$bar" "$C_RESET"
  echo
}

setup_passwordless_sudo() {
  # Install a sudoers drop-in so `sudo kekkai ...` never prompts for a
  # password. Intentionally NO shell alias — we want the literal `sudo`
  # keystrokes so users build the right muscle memory across hosts where
  # the alias may not exist.
  [[ "$OS" == "linux" ]] || return 0

  local target_user
  target_user="${SUDO_USER:-$USER}"
  if [[ -z "$target_user" ]] || [[ "$target_user" == "root" ]]; then
    info "skip sudoers drop-in for root user"
    return 0
  fi

  local sudoers_file="$SUDOERS_DIR/${SUDOERS_FILE_PREFIX}${target_user}"
  local sudoers_line="$target_user ALL=(root) NOPASSWD: $CLI_BIN, $CLI_BIN *"
  log "configuring passwordless sudo for $CLI_BIN (user=$target_user)"
  $SUDO install -d -m 0755 "$SUDOERS_DIR"
  printf '%s\n' "$sudoers_line" | $SUDO tee "$sudoers_file" >/dev/null
  $SUDO chmod 0440 "$sudoers_file"
  if ! $SUDO visudo -cf "$sudoers_file" >/dev/null; then
    $SUDO rm -f "$sudoers_file"
    warn "sudoers syntax check failed; removed $sudoers_file"
    warn "you will be prompted for a password each time you run: sudo kekkai"
    return 0
  fi
  info "sudo kekkai will no longer prompt for a password"
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

require_release_tools() {
  command -v curl    >/dev/null 2>&1 || die "curl not found"
  command -v python3 >/dev/null 2>&1 || die "python3 not found (required for release metadata parsing)"
}

# fetch_release_artifacts: shared release fetch/parse/download.
# Inputs:  channel, tmpdir
# Outputs (via globals): REL_TAG, REL_NEW_AGENT, REL_NEW_CLI
#
# Using globals keeps the caller simple (vs. parsing stdout). A trailing
# `unset` in each caller is unnecessary — install is a one-shot script.
fetch_release_artifacts() {
  local channel="$1"
  local tmpdir="$2"

  require_release_tools

  local meta parsed
  meta="$(fetch_release_metadata "$channel")" || die "failed to fetch GitHub release metadata"
  parsed="$(printf '%s' "$meta" | select_release_assets "$channel" "$OS" "$ARCH")" \
    || die "failed to resolve release assets for $OS/$ARCH"

  REL_TAG="$(printf '%s\n' "$parsed" | sed -n '1p')"
  local agent_url cli_url
  agent_url="$(printf '%s\n' "$parsed" | sed -n '2p')"
  cli_url="$(printf '%s\n' "$parsed"   | sed -n '3p')"
  [[ -n "$agent_url" && -n "$cli_url" ]] || die "release metadata incomplete"

  log "selected release: $REL_TAG ($channel)"
  info "agent asset: $(basename "${agent_url%%\?*}")"
  info "cli asset:   $(basename "${cli_url%%\?*}")"

  REL_NEW_AGENT="$(download_release_binary "$agent_url" "kekkai-agent" "$tmpdir")" \
    || die "failed to download/verify kekkai-agent binary"
  REL_NEW_CLI="$(download_release_binary "$cli_url" "kekkai" "$tmpdir")" \
    || die "failed to download/verify kekkai binary"
}

# files_match: 0 (true) if both files exist and have identical sha256.
files_match() {
  local a="$1" b="$2"
  [[ -f "$a" && -f "$b" ]] || return 1
  local a_sha b_sha
  a_sha="$(sha256sum "$a" | awk '{print $1}')"
  b_sha="$(sha256sum "$b" | awk '{print $1}')"
  [[ "$a_sha" == "$b_sha" ]]
}

# agent_unchanged / cli_unchanged: 0 (true) if the candidate binary matches
# the currently installed one byte-for-byte. Used to decide whether a
# release actually needs a service restart (or any write at all).
agent_unchanged() { files_match "$AGENT_BIN" "$1"; }
cli_unchanged()   { files_match "$CLI_BIN"   "$1"; }

# sync_script_from_remote: fetch the latest kekkai.sh from $RAW_BASE and
# compare with the currently installed /usr/local/bin/kekkai.sh.
#
# Exit codes:
#   0   → remote content differs, installed copy was overwritten
#   10  → remote matches installed copy (no-op)
#   11  → fetch failed (network / curl missing) — caller should warn but not fail
#
# Kept separate from binary updates because the script can ship fixes that
# have no corresponding binary release (this very patch is one such case).
sync_script_from_remote() {
  [[ "$OS" == "linux" ]] || return 10
  command -v curl >/dev/null 2>&1 || return 11

  local tmp
  tmp="$(mktemp)"
  if ! curl -fsSL "$RAW_BASE/$BRANCH/kekkai.sh" -o "$tmp" 2>/dev/null || [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    return 11
  fi

  if files_match "$SCRIPT_INSTALL_PATH" "$tmp"; then
    rm -f "$tmp"
    return 10
  fi

  $SUDO install -D -m 0755 "$tmp" "$SCRIPT_INSTALL_PATH"
  rm -f "$tmp"
  return 0
}

release_update() {
  local channel="$1"
  local old_ver
  old_ver="$(read_cli_version "$CLI_BIN")"

  local tmpdir
  tmpdir="$(mktemp -d)"
  fetch_release_artifacts "$channel" "$tmpdir"
  local new_ver
  new_ver="$(read_cli_version "$REL_NEW_CLI")"

  validate_config_against_new_binary "$REL_NEW_AGENT"

  # Three-way diff: agent binary, CLI binary, and kekkai.sh itself.
  # Any single one changing counts as "updated". kekkai.sh can ship
  # fixes independent of a binary release, so we can't gate on agent alone.
  local -a changed_parts=()
  local need_restart=0

  if ! agent_unchanged "$REL_NEW_AGENT"; then
    changed_parts+=("agent")
    need_restart=1
  fi
  if ! cli_unchanged "$REL_NEW_CLI"; then
    changed_parts+=("cli")
  fi

  if (( need_restart )); then
    install_binaries_from "$REL_NEW_AGENT" "$REL_NEW_CLI"
  elif (( ${#changed_parts[@]} > 0 )); then
    # CLI changed but agent didn't — still need to install the new CLI,
    # just no service restart.
    $SUDO install -D -m 0755 "$REL_NEW_CLI" "$CLI_BIN"
    log "installed: $CLI_BIN"
    install_completions
  fi
  rm -rf "$tmpdir"

  # Script sync: independent of binary changes. Done after binaries
  # because sync_script_from_remote may overwrite the script this very
  # process is running — bash has already parsed our source, so this is
  # safe as long as we don't source the file again afterward.
  #
  # NOTE: `set -e` would kill us on the non-zero API returns (10/11) if we
  # called this as a bare statement. The `|| script_rc=$?` idiom isolates
  # the call from errexit so we can branch on the exit code ourselves.
  local script_rc=0
  sync_script_from_remote || script_rc=$?
  case $script_rc in
    0)  changed_parts+=("kekkai.sh") ;;
    10) : ;; # already up-to-date
    11) warn "could not fetch remote kekkai.sh (network?) — skipped script sync" ;;
  esac

  if (( need_restart )); then
    setup_passwordless_sudo
    enable_and_start
  fi

  if (( ${#changed_parts[@]} == 0 )); then
    print_update_result unchanged "$old_ver" "$new_ver" "$REL_TAG" "$channel" ""
  else
    local changed_str="${changed_parts[*]}"
    changed_str="${changed_str// /, }"
    print_update_result updated "$old_ver" "$new_ver" "$REL_TAG" "$channel" "$changed_str"
  fi
}

fetch_release_binaries_to_root_bin() {
  local channel="$1"
  local tmpdir
  tmpdir="$(mktemp -d)"
  fetch_release_artifacts "$channel" "$tmpdir"

  mkdir -p "$ROOT/bin"
  install -m 0755 "$REL_NEW_AGENT" "$LOCAL_AGENT_BIN"
  install -m 0755 "$REL_NEW_CLI"   "$LOCAL_CLI_BIN"
  rm -rf "$tmpdir"
}

validate_config_against_new_binary() {
  local candidate_bin="${1:-$LOCAL_AGENT_BIN}"
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
      info "  sudo kekkai update"
      info "if it repeats, pin previous tag or check release artifact health."
      exit 1
    fi
    err "the installed config is incompatible with the new binary."
    err "the old binary and service are still running untouched."
    echo
    info "to fix, one of:"
    info "  1. edit the config:        sudo nano $CONFIG_FILE"
    info "  2. reset to a clean template (backs up the broken file first):"
    info "       sudo kekkai reset"
    info "     then edit to add filter.ingress_allowlist, and re-run:"
    info "       sudo kekkai update"
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
  persist_script_for_updates
  setup_passwordless_sudo
  install_config
  install_systemd_unit
  enable_and_start
  log "install complete"
  post_install_hints
}

do_update() {
  banner
  step "update · $OS/$ARCH"
  local channel
  channel="$(resolve_update_channel)"
  log "update channel: $channel"
  release_update "$channel"
}

do_repair() {
  banner
  step "repair · $OS/$ARCH"
  prepare_binaries
  install_binaries
  persist_script_for_updates
  setup_passwordless_sudo
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
  [[ -x "$AGENT_BIN" ]] && log "$AGENT_BIN present" || warn "$AGENT_BIN missing"
  [[ -x "$CLI_BIN"   ]] && log "$CLI_BIN present"   || warn "$CLI_BIN missing"
  [[ -f "$UNIT_DST"  ]] && log "$UNIT_DST present"  || warn "$UNIT_DST missing"
  [[ -f "$CONFIG_FILE" ]] && log "$CONFIG_FILE present" || warn "$CONFIG_FILE missing"
  echo
  info "run the one-liner installer from the README to bootstrap kekkai"
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
  info "next steps (always run kekkai with sudo):"
  printf '  %s1.%s edit config:      sudo nano %s\n' "$C_BOLD" "$C_RESET" "$CONFIG_FILE"
  printf '  %s2.%s validate:         sudo kekkai check\n' "$C_BOLD" "$C_RESET"
  printf '  %s3.%s restart:          sudo systemctl restart kekkai-agent\n' "$C_BOLD" "$C_RESET"
  printf '  %s4.%s watch live:       sudo kekkai status\n' "$C_BOLD" "$C_RESET"
  printf '  %s5.%s diagnose:         sudo kekkai doctor\n' "$C_BOLD" "$C_RESET"
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
