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
#   --force       update: pick the newest tag across release and pre-release
#   --local       dev only: motd, completions, and the systemd unit come from
#                 this checkout instead of the verified release assets
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
# granting NOPASSWD only for the safe subcommands (status, doctor, ports,
# version, check, show, reload, bypass, config) and for
# `sudoedit /etc/kekkai/kekkai.yaml`. update, reset, and backup still prompt.
# No shell alias is added — users should type literal `sudo kekkai`.
#
# Auto-detect logic (no subcommand):
#   - no binaries yet            → install
#   - binaries present but no systemd unit OR unit disabled → repair
#   - otherwise                  → doctor (use `update` subcommand explicitly
#                                  to check for a new release)
#
set -euo pipefail

# Temp files created while root must not use a predictable /tmp name.
# track_tmp remembers them and cleanup_tracked_tmp removes them on exit,
# including when die() aborts the script.
_KEKKAI_TMP=()
track_tmp() {
  _KEKKAI_TMP+=("$1")
}
cleanup_tracked_tmp() {
  local p
  [[ ${#_KEKKAI_TMP[@]} -eq 0 ]] && return 0
  for p in "${_KEKKAI_TMP[@]}"; do
    [[ -n "$p" && "$p" != "/" ]] || continue
    rm -rf -- "$p" || true
  done
}
trap cleanup_tracked_tmp EXIT

# ROOT resolution:
# - normal: directory containing kekkai.sh on disk (/usr/local/bin or dev dir)
# - raw mode (`bash <(curl ...)`): fallback to ~/kekkai (or $KEKKAI_REPO)
#   because $0 becomes /dev/fd/* and is not a writable project directory.
# resolve_root prints a directory, or "-" when the caller (the main shell,
# not this command substitution) must create a private temp dir. track_tmp
# inside this function would be lost: ROOT="$(resolve_root)" is a subshell.
resolve_root() {
  if [[ -n "${KEKKAI_REPO:-}" ]]; then
    mkdir -p "$KEKKAI_REPO"
    (cd "$KEKKAI_REPO" && pwd)
    return
  fi

  local script_dir
  script_dir="$(cd "$(dirname "$0")" && pwd)"

  if [[ "$script_dir" == /dev/fd* ]] || [[ "$script_dir" == /proc/*/fd* ]]; then
    if [[ -n "${HOME:-}" ]]; then
      mkdir -p "${HOME}/kekkai"
      (cd "${HOME}/kekkai" && pwd)
      return
    fi
    # No home directory. "-" is not a path `pwd` can print.
    printf '%s\n' "-"
    return
  fi

  printf '%s\n' "$script_dir"
}

# establish_root runs in the main shell so the no-home temp dir is tracked.
establish_root() {
  local resolved
  resolved="$(resolve_root)"
  if [[ "$resolved" == "-" ]]; then
    resolved="$(mktemp -d)"
    track_tmp "$resolved"
  fi
  if [[ -z "$resolved" ]]; then
    printf '%s\n' "could not resolve a working directory" >&2
    exit 1
  fi
  # curl | bash leaves ROOT as the caller's cwd, which may be "/" (cloud-init).
  # That directory is not an install source; verified files stay in mktemp.
  ROOT="$resolved"
  cd "$ROOT"
}

establish_root

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
AGENT_BIN=/usr/local/bin/kekkai-agent
CLI_BIN=/usr/local/bin/kekkai
ROLLBACK_BIN=/usr/local/bin/kekkai-agent.prev
SCRIPT_INSTALL_PATH=/usr/local/bin/kekkai.sh
BASH_COMPLETION_DST=/usr/share/bash-completion/completions/kekkai
ZSH_COMPLETION_DST=/usr/share/zsh/vendor-completions/_kekkai
MOTD_DST=/etc/update-motd.d/98-kekkai
STATE_DIR=/var/lib/kekkai
STAGED_DIR=/var/lib/kekkai/staged
AUTO_UPDATE_ERROR_FILE=/var/lib/kekkai/auto_update_error.txt
CONFIG_DIR=/etc/kekkai
CONFIG_FILE="$CONFIG_DIR/kekkai.yaml"
STATS_DIR=/var/run/kekkai
BPFFS_DIR=/sys/fs/bpf/kekkai
UNIT_NAME=kekkai-agent.service
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
SUDOERS_DIR=/etc/sudoers.d
SUDOERS_FILE_PREFIX=kekkai-cli-
REPO_OWNER=ExpTechTW
REPO_NAME=kekkai
RELEASES_API_BASE="https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases"
# Flat names published next to the binaries and listed in SHA256SUMS.
ASSET_SUMS=SHA256SUMS
ASSET_SCRIPT=kekkai.sh
ASSET_MOTD=kekkai-motd
ASSET_BASH_COMP=kekkai.bash
ASSET_ZSH_COMP=_kekkai
ASSET_UNIT=kekkai-agent.service

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

# Persistent log for kekkai.sh operations. Matches the agent's log
# directory so operators have one place to look when debugging an
# install / update / repair. We only append plain text (no ANSI) here —
# the terminal gets the colourised version, the file gets the scraped
# version.
KEKKAI_SH_LOG=/var/log/kekkai/kekkai.sh.log

# _kslog_append writes a single already-rendered line into the
# persistent log file. Best-effort: if the file isn't writable (non-root
# dev run, missing dir) we silently drop it rather than breaking the
# visible output. Timestamp format matches the agent's logx handler
# (UTC, 1-second resolution) so both log streams line up chronologically
# when they end up in the same terminal scrollback.
_kslog_append() {
  local level="$1" msg="$2"
  [[ -n "$KEKKAI_SH_LOG" ]] || return 0
  local ts
  ts="$(date -u '+%Y/%m/%d %H:%M:%S')"
  # mkdir -p is idempotent and cheap; we do it every call in case the
  # directory was removed between invocations. The :-"" guard means a
  # failed mkdir just drops the line instead of erroring out.
  mkdir -p "$(dirname "$KEKKAI_SH_LOG")" 2>/dev/null || return 0
  printf '[%s(UTC)][%-5s][kekkai.sh] %s\n' "$ts" "$level" "$msg" \
    >> "$KEKKAI_SH_LOG" 2>/dev/null || true
}

step() { printf '\n%s◈ %s%s\n' "$C_TITLE" "$*" "$C_RESET"; _kslog_append STEP "$*"; }
log()  { printf '%s[+]%s %s\n' "$C_OK"   "$C_RESET" "$*"; _kslog_append INFO "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_WARN" "$C_RESET" "$*"; _kslog_append WARN "$*"; }
err()  { printf '%s[x]%s %s\n' "$C_ERR"  "$C_RESET" "$*" >&2; _kslog_append ERROR "$*"; }
info() { printf '%s[·]%s %s\n' "$C_INFO" "$C_RESET" "$*"; _kslog_append INFO "$*"; }
die()  { err "$*"; exit 1; }

# safe_rm_rf refuses an empty path, which would otherwise become `rm -rf /`.
safe_rm_rf() {
  local p
  for p in "$@"; do
    if [[ -z "$p" || "$p" == "/" ]]; then
      die "refusing to remove empty path or /"
    fi
    rm -rf -- "$p"
  done
}

# Linux IFNAMSIZ is 16 including NUL. "." and ".." match the character
# class but are path components, not interface names.
validate_iface_name() {
  local n="$1"
  [[ "$n" == "." || "$n" == ".." ]] && return 1
  [[ "$n" =~ ^[A-Za-z0-9._@:-]{1,15}$ ]] || return 1
  return 0
}

# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------
CMD=""
DO_INSTALL_DEPS=1
IFACE_OVERRIDE=""
DO_RUN=0
FORCE_UPDATE=0
# --local is the only path that reads motd, completions, or the unit from
# the working tree. The default is the checksum-verified release asset.
USE_LOCAL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    install|update|repair|doctor|uninstall)
      CMD="$1"; shift ;;
    --no-install)  DO_INSTALL_DEPS=0; shift ;;
    --iface)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        die "--iface requires a name"
      fi
      IFACE_OVERRIDE="$2"; shift 2 ;;
    --run)         DO_RUN=1; shift ;;
    --force)       FORCE_UPDATE=1; shift ;;
    --local)       USE_LOCAL=1; shift ;;
    -h|--help)
      cat <<'EOF'
kekkai — one-script installer / updater / repair tool.

Usage:
  bash kekkai.sh               # auto-detect state and do the right thing
  bash kekkai.sh install       # force first-time install
  bash kekkai.sh update        # force update (pulls prebuilt release assets)
  bash kekkai.sh repair        # force re-install of binaries + systemd unit
  bash kekkai.sh doctor        # read-only health check (delegates to `kekkai doctor`)
  bash kekkai.sh uninstall     # remove everything except config

Flags (apply to any subcommand):
  --no-install  skip apt dependency install
  --iface NAME  force a specific interface in the default config
  --run         launch the agent in foreground at the end (debugging)
  --force       update: pick the newest tag across release and pre-release
  --local       use the motd script, shell completions, and systemd unit from
                this checkout instead of the verified release assets (dev only)
  -h, --help    show this help

Release assets are verified against SHA256SUMS before they are installed.
A missing checksum file aborts the install.
EOF
      exit 0
      ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ -n "$IFACE_OVERRIDE" ]] && ! validate_iface_name "$IFACE_OVERRIDE"; then
  die "invalid interface name: $IFACE_OVERRIDE"
fi

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
  [[ $DO_INSTALL_DEPS -eq 0 ]] && { info "skipping apt (--no-install)"; return 0; }
  if ! command -v apt-get >/dev/null 2>&1; then
    warn "no apt-get; install clang/libbpf-dev/linux-headers manually"
    return 0
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
  return 0
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
  REL_DOWNLOAD_DIR="$(mktemp -d)"
  track_tmp "$REL_DOWNLOAD_DIR"
  fetch_release_artifacts "$channel" "$REL_DOWNLOAD_DIR"
}

install_binaries_from() {
  local src_agent="$1"
  local src_cli="$2"
  [[ -n "$src_agent" && -x "$src_agent" ]] || die "missing agent binary: $src_agent"
  [[ -n "$src_cli" && -x "$src_cli" ]] || die "missing cli binary: $src_cli"

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
  install_motd
  return 0
}

# persist_script_for_updates installs the checksum-verified kekkai.sh from
# the release currently being installed. It does not copy a local checkout
# or curl the main branch — those are writable or unpinned. The bootstrap
# `curl …/main/kekkai.sh | bash` still works: that process downloads the
# release asset and installs that verified copy.
persist_script_for_updates() {
  [[ "$OS" == "linux" ]] || return 0
  [[ -n "${REL_NEW_SCRIPT:-}" && -s "$REL_NEW_SCRIPT" ]] \
    || die "refusing to install kekkai.sh: no checksum-verified release asset"
  $SUDO install -D -m 0755 "$REL_NEW_SCRIPT" "$SCRIPT_INSTALL_PATH"
  log "installed: $SCRIPT_INSTALL_PATH (verified release asset)"
  return 0
}

# aux_source picks the checkout file only when --local was passed.
# Otherwise it returns the checksum-verified release path (may be empty
# when an older release did not publish that asset).
aux_source() {
  local local_path="$1"
  local verified="${2:-}"
  if (( USE_LOCAL )); then
    if [[ -f "$local_path" ]]; then
      printf '%s\n' "$local_path"
    fi
    return 0
  fi
  if [[ -n "$verified" && -f "$verified" ]]; then
    printf '%s\n' "$verified"
  fi
  return 0
}

# install_completions drops the bash + zsh completion scripts into the
# distro's standard vendor paths. Silently skips targets whose parent
# dir doesn't exist (e.g. systems without zsh installed). Non-fatal.
install_completions() {
  [[ "$OS" == "linux" ]] || return 0

  local bash_src zsh_src
  bash_src="$(aux_source "$ROOT/contrib/completions/kekkai.bash" "${REL_NEW_BASH_COMP:-}")"
  zsh_src="$(aux_source "$ROOT/contrib/completions/_kekkai" "${REL_NEW_ZSH_COMP:-}")"

  if [[ -n "$bash_src" && -f "$bash_src" && -d "$(dirname "$BASH_COMPLETION_DST")" ]]; then
    $SUDO install -D -m 0644 "$bash_src" "$BASH_COMPLETION_DST"
    log "installed: $BASH_COMPLETION_DST"
  fi
  if [[ -n "$zsh_src" && -f "$zsh_src" && -d "$(dirname "$ZSH_COMPLETION_DST")" ]]; then
    $SUDO install -D -m 0644 "$zsh_src" "$ZSH_COMPLETION_DST"
    log "installed: $ZSH_COMPLETION_DST"
  fi

  if [[ -z "$bash_src" && -z "$zsh_src" ]]; then
    warn "shell completions not installed (no verified release asset)"
  fi
  return 0
}

# install_motd drops the auto-update failure notice into
# /etc/update-motd.d/ and ensures the state directory exists for
# kekkai-agent's auto-update goroutine. Silently skips if the host
# doesn't use update-motd.d (mostly non-systemd distros).
install_motd() {
  [[ "$OS" == "linux" ]] || return 0

  # State dirs are created unconditionally — agent auto-update and the
  # rotating logger both need them even on hosts without update-motd.d.
  $SUDO install -d -m 0755 "$STATE_DIR"
  $SUDO install -d -m 0755 "$STAGED_DIR"
  $SUDO install -d -m 0755 /var/log/kekkai

  if [[ ! -d "$(dirname "$MOTD_DST")" ]]; then
    info "update-motd.d not present — skipping login-warning hook"
    return 0
  fi

  local motd_src
  motd_src="$(aux_source "$ROOT/contrib/motd/98-kekkai" "${REL_NEW_MOTD:-}")"
  if [[ -z "$motd_src" || ! -f "$motd_src" ]]; then
    warn "motd script not installed (no verified release asset)"
    return 0
  fi
  $SUDO install -D -m 0755 "$motd_src" "$MOTD_DST"
  log "installed: $MOTD_DST"
  return 0
}

install_binaries() {
  [[ -n "${REL_NEW_AGENT:-}" && -n "${REL_NEW_CLI:-}" ]] \
    || die "no verified binaries to install"
  install_binaries_from "$REL_NEW_AGENT" "$REL_NEW_CLI"
  return 0
}

# cleanup_download_dir removes the private mktemp dir that held verified
# artifacts. Best-effort: the EXIT trap retries if this is skipped.
cleanup_download_dir() {
  local d="${REL_DOWNLOAD_DIR:-}"
  REL_DOWNLOAD_DIR=""
  if [[ -z "$d" || "$d" == "/" || ! -d "$d" ]]; then
    return 0
  fi
  rm -rf -- "$d" || true
  return 0
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
  if [[ -n "$changed" ]]; then
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
  # NOPASSWD covers safe subcommands only. No shell alias — users type
  # literal `sudo kekkai` so the habit survives hosts without this drop-in.
  [[ "$OS" == "linux" ]] || return 0

  local target_user
  target_user="${SUDO_USER:-$USER}"
  if [[ -z "$target_user" ]] || [[ "$target_user" == "root" ]]; then
    info "skip sudoers drop-in for root user"
    return 0
  fi

  local sudoers_file="$SUDOERS_DIR/${SUDOERS_FILE_PREFIX}${target_user}"

  # Passwordless sudo is restricted to SAFE subcommands. A blanket
  # "kekkai *" was a privesc footgun: `kekkai config` launched a root editor
  # (shell escape -> root), and `update`/`reset`/`backup` download+run a
  # binary or write files. Those are excluded here and will prompt for a
  # password. Config editing is delegated to sudoedit (runs the editor as the
  # invoking user, not root). This block is rewritten on every install/update,
  # so it also migrates any older broad drop-in.
  local safe="status doctor ports version check show reload bypass config"
  local cmds="" c
  for c in $safe; do
    cmds+="$CLI_BIN $c, $CLI_BIN $c *, "
  done
  cmds="${cmds%, }"

  log "configuring passwordless sudo for $CLI_BIN (user=$target_user, safe subcommands only)"
  $SUDO install -d -m 0755 "$SUDOERS_DIR"
  {
    printf '# kekkai CLI — passwordless sudo for SAFE subcommands only.\n'
    printf '# Edit the config with: sudoedit %s   (editor runs as you, not root)\n' "$CONFIG_FILE"
    printf '# update/reset/backup are intentionally excluded and prompt for a password.\n'
    printf '%s ALL=(root) NOPASSWD: %s\n' "$target_user" "$cmds"
    printf '%s ALL=(root) NOPASSWD: sudoedit %s\n' "$target_user" "$CONFIG_FILE"
  } | $SUDO tee "$sudoers_file" >/dev/null
  $SUDO chmod 0440 "$sudoers_file"
  if ! $SUDO visudo -cf "$sudoers_file" >/dev/null; then
    $SUDO rm -f "$sudoers_file"
    warn "sudoers syntax check failed; removed $sudoers_file"
    warn "you will be prompted for a password each time you run: sudo kekkai"
    return 0
  fi
  info "passwordless sudo enabled for safe subcommands; update/reset/backup still prompt"
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

  # Persist KEKKAI_UPDATE_CHANNEL into the fresh config so future
  # `kekkai update` runs (without the env var) don't flip back to the
  # default `release` channel. Only apply when the env var is explicitly
  # set AND it's a supported value — otherwise leave whatever the
  # template generated.
  local desired_channel="${KEKKAI_UPDATE_CHANNEL:-}"
  case "$desired_channel" in
    release|pre-release)
      if grep -qE '^[[:space:]]+channel:' "$CONFIG_FILE" 2>/dev/null; then
        $SUDO sed -i -E "s|^([[:space:]]+channel:[[:space:]]*).*$|\1$desired_channel|" "$CONFIG_FILE"
        log "update.channel set to $desired_channel (from KEKKAI_UPDATE_CHANNEL)"
      fi
      ;;
  esac

  if ! iface_has_default_allowlist_ip "$iface"; then
    warn "detected iface '$iface' is not in default ingress_allowlist 192.168.0.0/16"
    warn "service may reject startup until you set filter.ingress_allowlist to your management subnet"
  fi
  warn "review $CONFIG_FILE and set filter.ingress_allowlist to your management network"
}

install_systemd_unit() {
  command -v systemctl >/dev/null 2>&1 || { warn "systemctl not found — skipping unit install"; return 0; }
  log "installing systemd unit to $UNIT_DST"
  local unit_src
  unit_src="$(aux_source "$ROOT/deploy/systemd/kekkai-agent.service" "${REL_NEW_UNIT:-}")"
  if [[ -n "$unit_src" && -f "$unit_src" ]]; then
    $SUDO install -D -m 0644 "$unit_src" "$UNIT_DST"
  else
    if (( USE_LOCAL )); then
      warn "systemd unit not found in this checkout; using built-in fallback unit"
    else
      warn "release has no ${ASSET_UNIT} asset; using built-in fallback unit"
    fi
    local tmp_unit
    tmp_unit="$(mktemp)"
    track_tmp "$tmp_unit"
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
ReadWritePaths=/sys/fs/bpf /var/run /run /etc/kekkai /var/log/kekkai /var/lib/kekkai
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
  return 0
}

enable_and_start() {
  command -v systemctl >/dev/null 2>&1 || return 0
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
import re
import sys

channel, os_name, arch = sys.argv[1:4]
data = json.load(sys.stdin)

# Tag format is fixed by draft-release.yml: vYYYY.MM.DD+build.N
# Anything that does not match sorts as (0,0,0,0) so it loses to any
# well-formed tag — we never want to accidentally pick a hand-pushed
# tag over the CI-generated ones.
TAG_RE = re.compile(r"^v(\d{4})\.(\d{2})\.(\d{2})\+build\.(\d+)$")

def parse_version(tag):
    m = TAG_RE.match(tag or "")
    if not m:
        return (0, 0, 0, 0)
    return tuple(int(m.group(i)) for i in range(1, 5))

def pick_release(obj):
    # release channel: /releases/latest already returns the single
    # newest non-prerelease release, nothing to sort.
    if channel == "release":
        return obj

    # pre-release channel: the list endpoint is sorted by created_at
    # (newest first), which is NOT the same as version order — a
    # re-published older build would hop to the top and shadow the
    # real latest. Sort by parsed tag version and take the max.
    candidates = [r for r in obj if not r.get("draft") and r.get("prerelease")]
    if not candidates:
        return None
    return max(candidates, key=lambda r: parse_version(r.get("tag_name", "")))

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

def find_exact(name):
    for a in assets:
        if a.get("name") == name and a.get("browser_download_url"):
            return a
    return None

agent = best_asset("kekkai-agent")
cli = best_asset("kekkai")
sums = find_exact("SHA256SUMS")
script = find_exact("kekkai.sh")
if agent is None or cli is None:
    raise SystemExit("release assets for kekkai-agent/kekkai not found for target os/arch")
if sums is None or script is None:
    raise SystemExit("release is missing SHA256SUMS or kekkai.sh; refusing to install unverified files")

def url_of(name):
    asset = find_exact(name)
    if asset is None:
        return ""
    return asset["browser_download_url"]

# One field per line. Lines 6-9 are blank when that release has no asset.
print(release.get("tag_name", "unknown"))
print(agent["browser_download_url"])
print(cli["browser_download_url"])
print(sums["browser_download_url"])
print(script["browser_download_url"])
print(url_of("kekkai-motd"))
print(url_of("kekkai.bash"))
print(url_of("_kekkai"))
print(url_of("kekkai-agent.service"))
' "$channel" "$os" "$arch"
}

# parsed_field reads line N (1-based) from select_release_assets output.
parsed_field() {
  local n="$1"
  local text="$2"
  printf '%s\n' "$text" | sed -n "${n}p"
}

# --retry-all-errors arrived in curl 7.71. Ubuntu 20.04 ships 7.68, and
# passing the flag there makes every download fail.
curl_has_retry_all_errors() {
  if [[ -z "${CURL_RETRY_ALL_CHECKED:-}" ]]; then
    CURL_RETRY_ALL_CHECKED=1
    CURL_RETRY_ALL_ERRORS=0
    if curl --help all 2>/dev/null | grep -q -- '--retry-all-errors'; then
      CURL_RETRY_ALL_ERRORS=1
    fi
  fi
  [[ "${CURL_RETRY_ALL_ERRORS}" == 1 ]]
}

# curl_fetch_to downloads url to dest. Non-zero on failure; it does not exit.
curl_fetch_to() {
  local url="$1"
  local dest="$2"
  [[ -n "$url" ]] || return 1
  local -a args=(-fL --retry 4 --retry-delay 1 --connect-timeout 10)
  if curl_has_retry_all_errors; then
    args+=(--retry-all-errors)
  fi
  curl "${args[@]}" "$url" -o "$dest"
}

download_asset_file() {
  local url="$1"
  local dest="$2"
  [[ -n "$url" ]] || die "empty download url"
  curl_fetch_to "$url" "$dest" || die "failed to download $(basename "$dest")"
  [[ -s "$dest" ]] || die "download of $(basename "$dest") is empty; refusing to continue"
}

# stage_verified_binary unpacks an already-verified asset. Checksums are
# checked by the caller before this runs, so the -h probe never executes
# an unverified binary. Prints the staged path on stdout.
stage_verified_binary() {
  local archive="$1"
  local want_name="$2"
  local tmpdir="$3"
  local out="$tmpdir/$want_name"
  case "$archive" in
    *.tar.gz|*.tgz)
      local ex="$tmpdir/extract-$want_name"
      mkdir -p "$ex"
      tar -xzf "$archive" -C "$ex" || return 1
      local found
      found="$(find "$ex" -type f -name "$want_name" -print -quit)"
      [[ -n "$found" ]] || { err "archive $(basename "$archive") missing $want_name"; return 1; }
      cp "$found" "$out"
      ;;
    *.zip)
      command -v unzip >/dev/null 2>&1 || { err "unzip not found (required for zip release assets)"; return 1; }
      local ex="$tmpdir/extract-$want_name"
      mkdir -p "$ex"
      unzip -q "$archive" -d "$ex" || return 1
      local found
      found="$(find "$ex" -type f -name "$want_name" -print -quit)"
      [[ -n "$found" ]] || { err "archive $(basename "$archive") missing $want_name"; return 1; }
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
  printf '%s\n' "$out"
}

require_release_tools() {
  command -v curl    >/dev/null 2>&1 || die "curl not found"
  command -v python3 >/dev/null 2>&1 || die "python3 not found (required for release metadata parsing)"
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    die "sha256sum or shasum is required to verify release assets"
  fi
}

# file_sha256 prints the hex digest. sha256sum is preferred; shasum -a 256
# covers hosts (notably macOS) that do not ship sha256sum.
file_sha256() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print tolower($1)}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$f" | awk '{print tolower($1)}'
    return
  fi
  return 127
}

# verify_sha256_file returns 0 only when `name` in sums matches the file.
# Callers abort; there is no fallback to an unverified install.
verify_sha256_file() {
  local file="$1" sums="$2" name="$3"
  [[ -f "$sums" && -s "$sums" ]] || { err "SHA256SUMS is missing or empty"; return 1; }
  [[ -f "$file" ]] || { err "missing ${name}"; return 1; }
  local expect actual
  # length() instead of {64}: mawk 1.3.3/1.3.4 (Debian/Ubuntu/Raspbian)
  # does not implement awk interval expressions. Strip CR so a CRLF
  # checksum file still matches.
  expect="$(awk -v name="$name" '
    {
      gsub(/\r/, "")
    }
    length($1) == 64 && $1 !~ /[^0-9A-Fa-f]/ {
      fn = $2
      sub(/^\*/, "", fn)
      if (fn == name) { print tolower($1); exit }
    }
  ' "$sums")" || { err "failed to read SHA256SUMS"; return 1; }
  [[ -n "$expect" ]] || { err "SHA256SUMS has no entry for ${name}"; return 1; }
  actual="$(file_sha256 "$file")" || { err "sha256sum/shasum failed while verifying ${name}"; return 1; }
  [[ -n "$actual" ]] || { err "could not hash ${name}; install sha256sum or shasum"; return 1; }
  if [[ "$actual" != "$expect" ]]; then
    err "checksum mismatch for ${name}"
    return 1
  fi
  log "checksum ok: $name"
  return 0
}

# keep_verified_script copies a verified kekkai.sh out of the download
# directory so later cleanup of that directory cannot delete it.
keep_verified_script() {
  local src="$1"
  local dest
  dest="$(mktemp)"
  track_tmp "$dest"
  cp "$src" "$dest"
  chmod 0755 "$dest"
  REL_NEW_SCRIPT="$dest"
}

reset_release_artifacts() {
  REL_TAG=""
  REL_NEW_AGENT=""
  REL_NEW_CLI=""
  REL_NEW_SCRIPT=""
  REL_NEW_MOTD=""
  REL_NEW_BASH_COMP=""
  REL_NEW_ZSH_COMP=""
  REL_NEW_UNIT=""
}

# load_verified_aux downloads one optional release file and verifies it.
# An empty URL means this release does not publish the asset: the dest
# variable is cleared and the function returns 0. A download or checksum
# failure returns 1. Nothing is left executable until the caller checks.
load_verified_aux() {
  local url="$1" sums="$2" name="$3" dest="$4" varname="$5"
  printf -v "$varname" '%s' ""
  [[ -n "$url" ]] || return 0
  if ! curl_fetch_to "$url" "$dest" || [[ ! -s "$dest" ]]; then
    err "failed to download ${name}"
    return 1
  fi
  verify_sha256_file "$dest" "$sums" "$name" || return 1
  printf -v "$varname" '%s' "$dest"
  return 0
}

# fetch_release_artifacts: shared release fetch/parse/download.
# Inputs:  channel, tmpdir
# Outputs (via globals): REL_TAG, REL_NEW_AGENT, REL_NEW_CLI, REL_NEW_SCRIPT,
#   and when the release publishes them: REL_NEW_MOTD, REL_NEW_BASH_COMP,
#   REL_NEW_ZSH_COMP, REL_NEW_UNIT.
#
# Every downloaded file is checksum-verified against that release's
# SHA256SUMS before anything is executed or installed. A missing sums
# file or a mismatch aborts; there is no unverified fallback.
fetch_release_artifacts() {
  local channel="$1"
  local tmpdir="$2"

  require_release_tools
  reset_release_artifacts

  local meta parsed
  meta="$(fetch_release_metadata "$channel")" || die "failed to fetch GitHub release metadata"
  parsed="$(printf '%s' "$meta" | select_release_assets "$channel" "$OS" "$ARCH")" \
    || die "failed to resolve release assets for $OS/$ARCH (SHA256SUMS and kekkai.sh are required)"

  REL_TAG="$(parsed_field 1 "$parsed")"
  local agent_url cli_url sums_url script_url
  local motd_url bash_url zsh_url unit_url
  agent_url="$(parsed_field 2 "$parsed")"
  cli_url="$(parsed_field 3 "$parsed")"
  sums_url="$(parsed_field 4 "$parsed")"
  script_url="$(parsed_field 5 "$parsed")"
  motd_url="$(parsed_field 6 "$parsed")"
  bash_url="$(parsed_field 7 "$parsed")"
  zsh_url="$(parsed_field 8 "$parsed")"
  unit_url="$(parsed_field 9 "$parsed")"
  [[ -n "$agent_url" && -n "$cli_url" && -n "$sums_url" && -n "$script_url" ]] \
    || die "release metadata is incomplete (need binaries, SHA256SUMS, and kekkai.sh); refusing to install"

  log "selected release: $REL_TAG ($channel)"
  info "agent asset: $(basename "${agent_url%%\?*}")"
  info "cli asset:   $(basename "${cli_url%%\?*}")"

  local sums="$tmpdir/$ASSET_SUMS"
  local script="$tmpdir/$ASSET_SCRIPT"
  local agent_dl="$tmpdir/$(basename "${agent_url%%\?*}")"
  local cli_dl="$tmpdir/$(basename "${cli_url%%\?*}")"
  download_asset_file "$sums_url" "$sums"
  download_asset_file "$script_url" "$script"
  download_asset_file "$agent_url" "$agent_dl"
  download_asset_file "$cli_url" "$cli_dl"

  # Verify every download before chmod +x or executing a binary.
  verify_sha256_file "$agent_dl" "$sums" "$(basename "$agent_dl")" \
    || die "refusing to install unverified kekkai-agent"
  verify_sha256_file "$cli_dl" "$sums" "$(basename "$cli_dl")" \
    || die "refusing to install unverified kekkai"
  verify_sha256_file "$script" "$sums" "$ASSET_SCRIPT" \
    || die "refusing to install unverified kekkai.sh"
  load_verified_aux "$motd_url" "$sums" "$ASSET_MOTD" "$tmpdir/$ASSET_MOTD" REL_NEW_MOTD \
    || die "refusing to install unverified ${ASSET_MOTD}"
  load_verified_aux "$bash_url" "$sums" "$ASSET_BASH_COMP" "$tmpdir/$ASSET_BASH_COMP" REL_NEW_BASH_COMP \
    || die "refusing to install unverified ${ASSET_BASH_COMP}"
  load_verified_aux "$zsh_url" "$sums" "$ASSET_ZSH_COMP" "$tmpdir/$ASSET_ZSH_COMP" REL_NEW_ZSH_COMP \
    || die "refusing to install unverified ${ASSET_ZSH_COMP}"
  load_verified_aux "$unit_url" "$sums" "$ASSET_UNIT" "$tmpdir/$ASSET_UNIT" REL_NEW_UNIT \
    || die "refusing to install unverified ${ASSET_UNIT}"

  REL_NEW_AGENT="$(stage_verified_binary "$agent_dl" "kekkai-agent" "$tmpdir")" \
    || die "failed to prepare kekkai-agent after checksum verification"
  REL_NEW_CLI="$(stage_verified_binary "$cli_dl" "kekkai" "$tmpdir")" \
    || die "failed to prepare kekkai after checksum verification"
  keep_verified_script "$script"
}

# files_match: 0 (true) if both files exist and have identical sha256.
files_match() {
  local a="$1" b="$2"
  [[ -f "$a" && -f "$b" ]] || return 1
  local a_sha b_sha
  a_sha="$(file_sha256 "$a")" || return 1
  b_sha="$(file_sha256 "$b")" || return 1
  [[ -n "$a_sha" && "$a_sha" == "$b_sha" ]]
}

# agent_unchanged / cli_unchanged: 0 (true) if the candidate binary matches
# the currently installed one byte-for-byte. Used to decide whether a
# release actually needs a service restart (or any write at all).
agent_unchanged() { files_match "$AGENT_BIN" "$1"; }
cli_unchanged()   { files_match "$CLI_BIN"   "$1"; }

# version_is_newer: 0 (true) if $1 (candidate) is strictly newer than $2
# (installed), using natural version sort. Used to refuse downgrades —
# if somebody runs `kekkai update` while on pre-release build.9, the
# release channel's build.4 must NOT replace it.
#
# Special values:
#   - "unknown" / "(none)" for the installed version → always accept
#     (treat as "we don't know what's on disk, trust the candidate")
#   - "unknown" / "(none)" for the candidate         → always refuse
#     (can't prove it's newer)
version_is_newer() {
  local candidate="$1" installed="$2"
  [[ "$candidate" == "unknown" || "$candidate" == "(none)" || -z "$candidate" ]] && return 1
  [[ "$installed" == "unknown" || "$installed" == "(none)" || -z "$installed" ]] && return 0
  [[ "$candidate" == "$installed" ]] && return 1
  local top
  top="$(printf '%s\n%s\n' "$candidate" "$installed" | sort -V | tail -n1)"
  [[ "$top" == "$candidate" ]]
}

# use_staged_binaries reports whether /var/lib/kekkai/staged/ holds a
# complete, strictly-newer release that release_update should consume
# instead of fetching. Requirements:
#
#   - both binaries present and non-empty
#   - VERSION marker present and parseable
#   - VERSION strictly newer than the currently installed CLI
#
# The binaries are not executed here. release_update verifies them
# against the release SHA256SUMS before any exec. A missing piece
# returns 1 and release_update falls through to the fetch path.
use_staged_binaries() {
  [[ -d "$STAGED_DIR" ]] || return 1
  [[ -s "$STAGED_DIR/kekkai-agent" && -s "$STAGED_DIR/kekkai" ]] || return 1
  [[ -f "$STAGED_DIR/VERSION" ]] || return 1

  local staged_ver installed_ver
  staged_ver="$(cat "$STAGED_DIR/VERSION" 2>/dev/null | tr -d '[:space:]')"
  [[ -n "$staged_ver" ]] || return 1

  # Strip any leading `v` to line up with read_cli_version's format.
  staged_ver="${staged_ver#v}"
  installed_ver="$(read_cli_version "$CLI_BIN")"

  # Must be strictly newer — identical tag would mean we're about to
  # reinstall the same bytes, which is wasted work. Downgrade is
  # impossible here because the agent's staging logic only writes when
  # it has proven it's newer.
  if ! version_is_newer "$staged_ver" "$installed_ver"; then
    return 1
  fi
  return 0
}

# install_verified_script copies the kekkai.sh that belongs to the release
# being installed (REL_NEW_SCRIPT). It does not fetch the main branch.
#
# Exit codes:
#   0   → installed copy was overwritten
#   10  → installed copy already matches
install_verified_script() {
  [[ "$OS" == "linux" ]] || return 10
  [[ -n "${REL_NEW_SCRIPT:-}" && -s "$REL_NEW_SCRIPT" ]] \
    || die "refusing to install kekkai.sh without a checksum-verified release asset"
  if [[ -f "$SCRIPT_INSTALL_PATH" ]] && files_match "$SCRIPT_INSTALL_PATH" "$REL_NEW_SCRIPT"; then
    return 10
  fi
  $SUDO install -D -m 0755 "$REL_NEW_SCRIPT" "$SCRIPT_INSTALL_PATH"
  return 0
}

# fetch_release_by_tag loads one release object. '+' in the tag is
# percent-encoded so it is not treated as a space. Returns non-zero on
# HTTP errors so the staged path can fall back instead of aborting.
fetch_release_by_tag() {
  local tag="$1"
  [[ -n "$tag" ]] || return 1
  local enc="${tag//+/%2B}"
  curl -fsSL -H "Accept: application/vnd.github+json" \
    "$RELEASES_API_BASE/tags/${enc}"
}

clear_staged_dir() {
  if [[ -z "${STAGED_DIR:-}" || "$STAGED_DIR" == "/" || ! -d "$STAGED_DIR" ]]; then
    return 0
  fi
  $SUDO rm -f "$STAGED_DIR"/* 2>/dev/null || true
  return 0
}

# verify_staged_copies checks private copies (not the live staged dir)
# against the tag's SHA256SUMS. Returns 1 on tag 404, missing sums, or a
# mismatch. The caller warns, clears the staged dir, and downloads.
verify_staged_copies() {
  local tag="$1"
  local tmpdir="$2"
  local meta parsed
  if ! meta="$(fetch_release_by_tag "$tag" 2>/dev/null)"; then
    warn "could not fetch release ${tag}; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi
  # A tag URL returns one release object. Channel "release" keeps that
  # object as-is (it does not require prerelease=false).
  if ! parsed="$(printf '%s' "$meta" | select_release_assets release "$OS" "$ARCH" 2>/dev/null)"; then
    warn "release ${tag} is missing SHA256SUMS or platform assets; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi

  local sums_url script_url motd_url bash_url zsh_url unit_url
  sums_url="$(parsed_field 4 "$parsed")"
  script_url="$(parsed_field 5 "$parsed")"
  motd_url="$(parsed_field 6 "$parsed")"
  bash_url="$(parsed_field 7 "$parsed")"
  zsh_url="$(parsed_field 8 "$parsed")"
  unit_url="$(parsed_field 9 "$parsed")"
  if [[ -z "$sums_url" || -z "$script_url" ]]; then
    warn "release ${tag} is missing SHA256SUMS or kekkai.sh; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi

  local sums="$tmpdir/$ASSET_SUMS"
  local script="$tmpdir/$ASSET_SCRIPT"
  if ! curl_fetch_to "$sums_url" "$sums" || [[ ! -s "$sums" ]]; then
    warn "could not download SHA256SUMS for ${tag}; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi
  if ! curl_fetch_to "$script_url" "$script" || [[ ! -s "$script" ]]; then
    warn "could not download kekkai.sh for ${tag}; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi
  if ! verify_sha256_file "$script" "$sums" "$ASSET_SCRIPT"; then
    warn "kekkai.sh for ${tag} failed checksum verification; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi
  if ! verify_sha256_file "$tmpdir/kekkai-agent" "$sums" "kekkai-agent-${OS}-${ARCH}"; then
    warn "staged kekkai-agent failed checksum verification; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi
  if ! verify_sha256_file "$tmpdir/kekkai" "$sums" "kekkai-${OS}-${ARCH}"; then
    warn "staged kekkai failed checksum verification; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi
  if ! load_verified_aux "$motd_url" "$sums" "$ASSET_MOTD" "$tmpdir/$ASSET_MOTD" REL_NEW_MOTD \
    || ! load_verified_aux "$bash_url" "$sums" "$ASSET_BASH_COMP" "$tmpdir/$ASSET_BASH_COMP" REL_NEW_BASH_COMP \
    || ! load_verified_aux "$zsh_url" "$sums" "$ASSET_ZSH_COMP" "$tmpdir/$ASSET_ZSH_COMP" REL_NEW_ZSH_COMP \
    || ! load_verified_aux "$unit_url" "$sums" "$ASSET_UNIT" "$tmpdir/$ASSET_UNIT" REL_NEW_UNIT; then
    warn "a release asset for ${tag} failed checksum verification; clearing ${STAGED_DIR} and downloading instead"
    return 1
  fi

  keep_verified_script "$script"
  REL_NEW_AGENT="$tmpdir/kekkai-agent"
  REL_NEW_CLI="$tmpdir/kekkai"
  REL_TAG="$tag"
  REL_DOWNLOAD_DIR="$tmpdir"
  return 0
}

# try_prepare_staged_release copies staged binaries into a private temp
# dir, verifies those copies, and points REL_NEW_* at them. Any failure
# clears the staged dir and returns 1 so the caller can download.
try_prepare_staged_release() {
  local tag tmpdir
  tag="$(tr -d '[:space:]' < "$STAGED_DIR/VERSION" 2>/dev/null || true)"
  if [[ -z "$tag" ]]; then
    warn "staged VERSION is empty; clearing ${STAGED_DIR} and downloading instead"
    reset_release_artifacts
    clear_staged_dir
    return 1
  fi
  tmpdir="$(mktemp -d)"
  track_tmp "$tmpdir"
  if ! cp -f "$STAGED_DIR/kekkai-agent" "$tmpdir/kekkai-agent" \
    || ! cp -f "$STAGED_DIR/kekkai" "$tmpdir/kekkai"; then
    warn "could not copy staged binaries; clearing ${STAGED_DIR} and downloading instead"
    reset_release_artifacts
    clear_staged_dir
    rm -rf -- "$tmpdir" || true
    return 1
  fi
  chmod 0755 "$tmpdir/kekkai-agent" "$tmpdir/kekkai" || true
  if ! verify_staged_copies "$tag" "$tmpdir"; then
    reset_release_artifacts
    clear_staged_dir
    rm -rf -- "$tmpdir" || true
    return 1
  fi
  return 0
}

# pick_max_channel_tag: compare the latest release vs latest pre-release
# and echo back whichever has the higher version string. Used by --force
# to pick the genuinely-newest GitHub release regardless of what the
# config says about the preferred channel.
#
# Output: "<channel> <tag>" on stdout, empty string on failure.
#
# Implementation note: we deliberately re-use fetch_release_metadata +
# select_release_assets here rather than parsing inline, so the regex /
# "find max prerelease" logic stays in one place. The two sub-shell
# calls are OK cost-wise — both hit GitHub once each, and --force is a
# one-shot operator action, not a tight loop.
pick_max_channel_tag() {
  # Initialize: bash 4.4+ leaves `local rel_tag` unset, and set -u aborts
  # when one channel's lookup never assigns it.
  local rel_meta="" prerel_meta="" rel_tag="" prerel_tag=""
  rel_meta="$(fetch_release_metadata release 2>/dev/null || true)"
  prerel_meta="$(fetch_release_metadata pre-release 2>/dev/null || true)"

  # A release that is missing SHA256SUMS or kekkai.sh makes the selector
  # exit non-zero. That channel is skipped; it must not abort --force.
  if [[ -n "$rel_meta" ]]; then
    rel_tag="$(printf '%s' "$rel_meta" | select_release_assets release "$OS" "$ARCH" 2>/dev/null | sed -n '1p' || true)"
  fi
  if [[ -n "$prerel_meta" ]]; then
    prerel_tag="$(printf '%s' "$prerel_meta" | select_release_assets pre-release "$OS" "$ARCH" 2>/dev/null | sed -n '1p' || true)"
  fi

  # Strip leading v so sort -V compares cleanly.
  local rel_cmp="${rel_tag#v}" prerel_cmp="${prerel_tag#v}"

  if [[ -z "$rel_cmp" ]] && [[ -z "$prerel_cmp" ]]; then
    if [[ -z "$rel_meta" && -z "$prerel_meta" ]]; then
      echo "--force: could not fetch release metadata" >&2
    else
      echo "--force: neither channel has SHA256SUMS; refusing to install unverified files" >&2
    fi
    return 1
  fi
  if [[ -z "$prerel_cmp" ]]; then
    echo "release $rel_tag"; return 0
  fi
  if [[ -z "$rel_cmp" ]]; then
    echo "pre-release $prerel_tag"; return 0
  fi

  # Both present — pick the strictly larger. On tie, prefer `release`
  # (stable wins the coin flip).
  local top
  top="$(printf '%s\n%s\n' "$rel_cmp" "$prerel_cmp" | sort -V | tail -n1)"
  if [[ "$top" == "$prerel_cmp" ]] && [[ "$rel_cmp" != "$prerel_cmp" ]]; then
    echo "pre-release $prerel_tag"
  else
    echo "release $rel_tag"
  fi
}

release_update() {
  local channel="$1"
  local force_flag="${2:-0}"
  local old_ver
  old_ver="$(read_cli_version "$CLI_BIN")"

  # --force resolves the channel fresh, scanning BOTH channels for the
  # highest version tag. The caller's `channel` argument is ignored in
  # this mode. We also bypass the staged-binaries short-circuit so the
  # user always gets a genuine re-download — --force is a "give me
  # whatever is latest on GitHub right now, no caching" escape hatch.
  if (( force_flag )); then
    local picked pick_rc=0 pick_err msg
    pick_err="$(mktemp)"
    track_tmp "$pick_err"
    picked="$(pick_max_channel_tag 2>"$pick_err")" || pick_rc=$?
    if (( pick_rc != 0 )); then
      msg="$(head -n 1 "$pick_err" 2>/dev/null || true)"
      [[ -n "$msg" ]] || msg="--force: could not fetch release metadata"
      die "$msg"
    fi
    [[ -n "$picked" ]] || die "--force: no release candidates found"
    channel="${picked%% *}"
    info "--force: cross-channel pick → channel=$channel tag=${picked#* }"
  fi

  # Prefer binaries the running kekkai-agent has already staged into
  # /var/lib/kekkai/staged/. This skips the second fetch when
  # auto_update_download has already done the work — the operator running
  # `sudo kekkai update` by hand just applies what's on disk.
  # --force always re-fetches so operators who suspect the staged copy
  # is broken can get a clean reinstall.
  #
  # Staged files are copied into a private temp dir and verified there.
  # Tag 404, a missing SHA256SUMS, or a mismatch warns, clears the staged
  # dir, and falls through to fetch_release_artifacts.
  local used_staged=0
  if (( force_flag == 0 )) && use_staged_binaries; then
    if try_prepare_staged_release; then
      used_staged=1
      log "using staged binaries from $STAGED_DIR (tag=$REL_TAG)"
    fi
  fi
  if (( used_staged == 0 )); then
    REL_DOWNLOAD_DIR="$(mktemp -d)"
    track_tmp "$REL_DOWNLOAD_DIR"
    fetch_release_artifacts "$channel" "$REL_DOWNLOAD_DIR"
  fi
  local new_ver
  new_ver="$(read_cli_version "$REL_NEW_CLI")"

  validate_config_against_new_binary "$REL_NEW_AGENT"
  sync_user_config_to_canonical "$REL_NEW_AGENT" || die "config canonical sync failed"

  # Downgrade guard: `kekkai update` must NEVER replace a newer binary with
  # an older one. Common footgun: user installs pre-release (build.9), then
  # forgets to set update.channel=pre-release in config, so the next update
  # resolves to channel=release (build.4) and rolls them back.
  #
  # --force bypasses this check by design (operator explicitly asked for
  # whatever is latest regardless of direction); a warning is still
  # printed if the "latest" turns out to be older than what's installed.
  local -a changed_parts=()
  local need_restart=0
  local downgrade_refused=0

  if (( force_flag )); then
    if [[ "$new_ver" != "$old_ver" ]] && ! version_is_newer "$new_ver" "$old_ver"; then
      warn "--force: installing $new_ver over $old_ver (downgrade protection bypassed)"
    fi
  elif [[ "$new_ver" != "$old_ver" ]] && ! version_is_newer "$new_ver" "$old_ver"; then
    downgrade_refused=1
    warn "refusing to downgrade: $channel channel offers $new_ver but installed is $old_ver"
    warn "to switch channels, set update.channel in $CONFIG_FILE or export KEKKAI_UPDATE_CHANNEL"
    warn "to force override regardless of direction, run: sudo kekkai update --force"
  fi

  if (( downgrade_refused == 0 )); then
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
      install_motd
    fi
    # Consumed staged binaries — clear the staging dir so the next
    # auto-update tick starts from a clean slate and doctor's status
    # reflects the current installed version.
    if (( used_staged == 1 )); then
      clear_staged_dir
    fi
  fi

  # Install the kekkai.sh that belongs to this release (already verified).
  # A refused downgrade does not install that release's script either:
  # the asset is the same release we just declined to put on disk.
  # bash has already parsed this process, so replacing the on-disk script
  # is safe as long as we don't source it again.
  #
  # NOTE: `set -e` would kill us on the non-zero "already matches" return
  # (10) if we called this as a bare statement.
  if (( downgrade_refused == 0 )); then
    local script_rc=0
    install_verified_script || script_rc=$?
    case $script_rc in
      0)  changed_parts+=("kekkai.sh") ;;
      10) : ;; # already up-to-date
      *) die "failed to install verified kekkai.sh (exit ${script_rc})" ;;
    esac
  fi

  if (( need_restart )); then
    setup_passwordless_sudo
    enable_and_start
  fi

  # A refused downgrade writes nothing. old_ver is still what is installed.
  if (( downgrade_refused )); then
    print_update_result unchanged "$old_ver" "$old_ver" "$REL_TAG" "$channel" ""
  elif (( ${#changed_parts[@]} == 0 )); then
    print_update_result unchanged "$old_ver" "$new_ver" "$REL_TAG" "$channel" ""
  else
    local changed_str="${changed_parts[*]}"
    changed_str="${changed_str// /, }"
    print_update_result updated "$old_ver" "$new_ver" "$REL_TAG" "$channel" "$changed_str"
  fi
  cleanup_download_dir
  return 0
}

validate_config_against_new_binary() {
  local candidate_bin="${1:-}"
  [[ -f "$CONFIG_FILE" ]] || return 0
  [[ -n "$candidate_bin" && -x "$candidate_bin" ]] || die "no verified binary to validate config against"
  log "validating $CONFIG_FILE against new binary"

  # mktemp gives us a per-run log file owned by whoever is executing
  # this function — avoids the "owned by root from a previous run"
  # permission denied footgun on a shared /tmp.
  local log_file
  log_file="$(mktemp)"
  track_tmp "$log_file"
  local rc=0
  if "$candidate_bin" -check "$CONFIG_FILE" >"$log_file" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  if (( rc != 0 )); then
    echo
    err "new binary validation failed:"
    sed 's/^/    /' "$log_file" >&2
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
    info "  1. edit the config:        sudoedit $CONFIG_FILE"
    info "  2. reset to a clean template (backs up the broken file first):"
    info "       sudo kekkai reset"
    info "     then edit to add filter.ingress_allowlist, and re-run:"
    info "       sudo kekkai update"
    info "  3. restore from an earlier backup:"
    info "       ls /etc/kekkai/kekkai.yaml.*"
    info "       sudo cp /etc/kekkai/kekkai.yaml.<kind>.<ts> $CONFIG_FILE"
    rm -f "$log_file"
    exit 1
  fi
  rm -f "$log_file"
  log "config ok"
}

sync_user_config_to_canonical() {
  local candidate_bin="${1:-}"
  [[ -f "$CONFIG_FILE" ]] || return 0
  [[ -n "$candidate_bin" && -x "$candidate_bin" ]] || die "no verified binary to sync config against"

  local tmp_show show_log backup_log
  tmp_show="$(mktemp)"
  show_log="$(mktemp)"
  backup_log="$(mktemp)"
  track_tmp "$tmp_show"
  track_tmp "$show_log"
  track_tmp "$backup_log"

  # Render canonical config (with comments + defaulted fields) via the new
  # binary so newly introduced keys are written into /etc/kekkai/kekkai.yaml
  # after update.
  if ! "$candidate_bin" -show -config "$CONFIG_FILE" >"$tmp_show" 2>"$show_log"; then
    echo
    err "failed to render canonical config with new binary:"
    sed 's/^/    /' "$show_log" >&2 || true
    echo
    return 1
  fi

  local cur_ver next_ver
  cur_ver="$(awk -F': *' '/^version:[[:space:]]*[0-9]+/{print $2; exit}' "$CONFIG_FILE" | tr -d '[:space:]')"
  next_ver="$(awk -F': *' '/^version:[[:space:]]*[0-9]+/{print $2; exit}' "$tmp_show" | tr -d '[:space:]')"

  # Only sync user config when schema version changes. For same-version
  # updates we intentionally keep the user's existing file shape as-is.
  if [[ -z "$cur_ver" || -z "$next_ver" ]]; then
    info "config canonical sync: skipped (unable to read schema version)"
    rm -f "$tmp_show"
    return 0
  fi
  if [[ "$cur_ver" == "$next_ver" ]]; then
    info "config canonical sync: skipped (schema unchanged v$cur_ver)"
    rm -f "$tmp_show"
    return 0
  fi

  local backup_out
  if ! backup_out="$("$candidate_bin" -backup -config "$CONFIG_FILE" 2>"$backup_log")"; then
    echo
    err "failed to backup config before canonical sync:"
    sed 's/^/    /' "$backup_log" >&2 || true
    echo
    return 1
  fi
  [[ -n "$backup_out" ]] && info "$backup_out"

  $SUDO install -D -m 0644 "$tmp_show" "$CONFIG_FILE" || {
    rm -f "$tmp_show"
    err "failed to write canonical config to $CONFIG_FILE"
    return 1
  }
  log "config canonical sync: wrote normalized config to $CONFIG_FILE (v${cur_ver:-unknown} -> v${next_ver:-unknown})"
  rm -f "$tmp_show"
  return 0
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
  cleanup_download_dir
  log "install complete"
  prompt_run_doctor
  post_install_hints
}

do_update() {
  banner
  if (( FORCE_UPDATE )); then
    step "update · $OS/$ARCH · --force (cross-channel latest)"
  else
    step "update · $OS/$ARCH"
  fi
  local channel
  channel="$(resolve_update_channel)"
  log "update channel: $channel"
  release_update "$channel" "$FORCE_UPDATE"
  prompt_run_doctor
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
  cleanup_download_dir
  log "repair complete"
  prompt_run_doctor
}

# After install/update, prompt the operator (loudly) to run the health
# check themselves. We deliberately do NOT run `kekkai doctor` here: it
# requires root and, in a delegated / non-root invocation, even our own log
# append fails. So just print a big, impossible-to-miss banner. Plain printf
# only — no step/log helpers, so this never touches the root-owned log file
# and never errors regardless of who runs the script.
prompt_run_doctor() {
  [[ -x "$CLI_BIN" ]] || return 0
  printf '%s\n' "$C_WARN"
  printf '  ┌────────────────────────────────────────────────────────┐\n'
  printf '  │  ◈  NEXT STEP — run a health check                       │\n'
  printf '  │                                                          │\n'
  printf '  │        sudo kekkai doctor                                │\n'
  printf '  │                                                          │\n'
  printf '  │  verifies kernel >= 6.6 (UDP/DNS), filter attach, config │\n'
  printf '  └────────────────────────────────────────────────────────┘\n'
  printf '%s' "$C_RESET"
}

do_doctor() {
  if [[ -x "$CLI_BIN" ]]; then
    # exec replaces this process and skips the EXIT trap.
    cleanup_tracked_tmp
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
  local p
  for p in "$BPFFS_DIR" "$STATS_DIR"; do
    [[ -n "$p" && "$p" != "/" ]] || die "refusing to remove empty path or /"
  done
  $SUDO rm -rf -- "$BPFFS_DIR" "$STATS_DIR"
  info "config preserved at $CONFIG_FILE"
  info "to remove it:  sudo rm -rf $CONFIG_DIR"
  log "uninstall complete"
}

post_install_hints() {
  echo
  info "next steps (always run kekkai with sudo):"
  printf '  %s1.%s edit config:      sudoedit %s\n' "$C_BOLD" "$C_RESET" "$CONFIG_FILE"
  printf '  %s2.%s validate:         sudo kekkai check\n' "$C_BOLD" "$C_RESET"
  printf '  %s3.%s restart:          sudo systemctl restart kekkai-agent\n' "$C_BOLD" "$C_RESET"
  printf '  %s4.%s watch live:       sudo kekkai status\n' "$C_BOLD" "$C_RESET"
  printf '  %s5.%s diagnose:         sudo kekkai doctor\n' "$C_BOLD" "$C_RESET"
  echo

  if [[ $DO_RUN -eq 1 ]]; then
    log "launching kekkai-agent in foreground (Ctrl+C to stop)"
    # exec replaces this process and skips the EXIT trap.
    cleanup_tracked_tmp
    exec $SUDO "$AGENT_BIN" -config "$CONFIG_FILE"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
# Tests source this file with KEKKAI_SH_SOURCE_ONLY=1 after the functions
# are defined. A normal execution never sets that variable.
if [[ "${KEKKAI_SH_SOURCE_ONLY:-}" == 1 ]]; then
  return 0
fi

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
