#!/usr/bin/env bash
set -euo pipefail

UNIT_NAME="kekkai-agent.service"
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
AGENT_BIN="/usr/local/bin/kekkai-agent"
CLI_BIN="/usr/local/bin/kekkai"
ROLLBACK_BIN="/usr/local/bin/kekkai-agent.prev"
CONFIG_DIR="/etc/kekkai"
BPFFS_DIR="/sys/fs/bpf/kekkai"
STATS_DIR="/var/run/kekkai"
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_FILE_PREFIX="kekkai-cli-"

ASSUME_YES=0
PURGE_HOME=0
TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME="$(eval echo "~$TARGET_USER" 2>/dev/null || echo "")"

usage() {
  cat <<'EOF'
Usage:
  bash scripts/delete.sh [--yes] [--purge-home]

Options:
  --yes         Skip confirmation prompt.
  --purge-home  Also delete ~/kekkai repository directory.
EOF
}

log()  { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*"; }
err()  { printf '[x] %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) ASSUME_YES=1; shift ;;
    --purge-home) PURGE_HOME=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  die "please run as root (example: sudo bash scripts/delete.sh --yes)"
fi

if [[ $ASSUME_YES -ne 1 ]]; then
  echo "This will permanently remove:"
  echo "  - $UNIT_DST"
  echo "  - $AGENT_BIN, $CLI_BIN, $ROLLBACK_BIN"
  echo "  - $CONFIG_DIR"
  echo "  - $BPFFS_DIR, $STATS_DIR"
  echo "  - sudoers shortcut files: $SUDOERS_DIR/${SUDOERS_FILE_PREFIX}*"
  if [[ $PURGE_HOME -eq 1 && -n "$TARGET_HOME" ]]; then
    echo "  - $TARGET_HOME/kekkai"
  fi
  printf 'Continue? [y/N] '
  read -r ans
  case "$ans" in
    y|Y|yes|YES) ;;
    *) echo "aborted"; exit 1 ;;
  esac
fi

if command -v systemctl >/dev/null 2>&1; then
  log "stopping and disabling $UNIT_NAME"
  systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
fi

log "removing binaries and unit"
rm -f "$AGENT_BIN" "$CLI_BIN" "$ROLLBACK_BIN" "$UNIT_DST"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed "$UNIT_NAME" 2>/dev/null || true
fi

log "removing runtime and config data"
rm -rf "$BPFFS_DIR" "$STATS_DIR" "$CONFIG_DIR"

if [[ -d "$SUDOERS_DIR" ]]; then
  log "removing sudoers shortcut files"
  rm -f "$SUDOERS_DIR"/"${SUDOERS_FILE_PREFIX}"*
fi

if [[ -n "$TARGET_HOME" && -d "$TARGET_HOME" ]]; then
  log "cleaning shell alias from user rc files ($TARGET_USER)"
  for rc in "$TARGET_HOME/.bashrc" "$TARGET_HOME/.zshrc" "$TARGET_HOME/.profile"; do
    [[ -f "$rc" ]] || continue
    sed -i "/alias kekkai='sudo \/usr\/local\/bin\/kekkai'/d" "$rc" || true
  done
fi

if [[ $PURGE_HOME -eq 1 && -n "$TARGET_HOME" ]]; then
  if [[ -d "$TARGET_HOME/kekkai" ]]; then
    log "removing $TARGET_HOME/kekkai"
    rm -rf "$TARGET_HOME/kekkai"
  fi
fi

log "delete complete"
echo
echo "Reinstall when ready:"
echo "  curl -fsSL https://raw.githubusercontent.com/ExpTechTW/kekkai/main/kekkai.sh | KEKKAI_UPDATE_CHANNEL=pre-release bash -s -- install"
