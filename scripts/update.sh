#!/usr/bin/env bash
# In-place updater for waf-go edge.
#
#   git fetch → inspect incoming changes → rebuild eBPF + Go → validate
#   the installed config against the new binary → reinstall → restart
#   systemd unit (only if the binary actually changed).
#
# Safety:
#   * refuses to run if the working tree has uncommitted changes (override
#     with --force; useful in dev)
#   * refuses to downgrade if HEAD would move backwards in time
#   * dry-runs `waf-edge -check` against the NEW binary before committing
#     to the install step; bad config never reaches the running service
#   * keeps a rollback binary at /usr/local/bin/waf-edge.prev
#
# Usage:
#   bash scripts/update.sh                 # fetch main, update if new commits
#   bash scripts/update.sh --branch dev    # update from a different branch
#   bash scripts/update.sh --force         # ignore dirty tree, allow rebase
#   bash scripts/update.sh --no-restart    # install but don't bounce service
#   bash scripts/update.sh --check-only    # just report "update available"
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BRANCH="main"
FORCE=0
RESTART=1
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --branch)     BRANCH="$2"; shift 2 ;;
    --force)      FORCE=1; shift ;;
    --no-restart) RESTART=0; shift ;;
    --check-only) CHECK_ONLY=1; shift ;;
    -h|--help)    sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

need_sudo() { [[ $EUID -eq 0 ]] && echo "" || echo "sudo"; }
SUDO="$(need_sudo)"

# Make pre-existing /usr/local/go toolchain visible even in non-login shells.
if [[ -x /usr/local/go/bin/go ]]; then
  export PATH="/usr/local/go/bin:$PATH"
fi

command -v git  >/dev/null || die "git not found"
command -v make >/dev/null || die "make not found"
command -v go   >/dev/null || die "go not found (run bootstrap.sh first)"

# --- 1. working tree sanity ------------------------------------------------
if [[ $FORCE -eq 0 ]] && ! git diff --quiet; then
  die "working tree has uncommitted changes. commit, stash, or pass --force"
fi

CURRENT_BRANCH="$(git symbolic-ref --short HEAD 2>/dev/null || echo DETACHED)"
if [[ "$CURRENT_BRANCH" != "$BRANCH" ]]; then
  if [[ $FORCE -eq 0 ]]; then
    die "on branch '$CURRENT_BRANCH', expected '$BRANCH'. switch branch or pass --force"
  fi
  warn "on branch '$CURRENT_BRANCH' but updating to '$BRANCH' (--force)"
fi

BEFORE="$(git rev-parse HEAD)"
log "current HEAD: $BEFORE"

# --- 2. fetch ---------------------------------------------------------------
log "fetching origin/$BRANCH"
git fetch origin "$BRANCH"

REMOTE="$(git rev-parse "origin/$BRANCH")"
if [[ "$BEFORE" == "$REMOTE" ]]; then
  log "already up to date"
  [[ $CHECK_ONLY -eq 1 ]] && exit 0
  # Still allow rebuild on request? Just exit — nothing to do.
  exit 0
fi

log "incoming: $REMOTE"
# Show the commits we're about to apply so the operator knows what's coming.
git --no-pager log --oneline "$BEFORE..$REMOTE" | sed 's/^/    /'

if [[ $CHECK_ONLY -eq 1 ]]; then
  log "update available (use without --check-only to apply)"
  exit 0
fi

# --- 3. refuse time-travel (downgrade) -------------------------------------
# Compare committer dates. Allow fast-forward; reject if we'd go backwards.
BEFORE_TS="$(git show -s --format=%ct "$BEFORE")"
REMOTE_TS="$(git show -s --format=%ct "$REMOTE")"
if (( REMOTE_TS < BEFORE_TS )) && [[ $FORCE -eq 0 ]]; then
  die "remote is OLDER than current HEAD — refusing to downgrade (pass --force)"
fi

# --- 4. apply ---------------------------------------------------------------
log "fast-forwarding to origin/$BRANCH"
git merge --ff-only "origin/$BRANCH" || die "fast-forward failed (diverged? use --force + git reset)"

# --- 5. build ---------------------------------------------------------------
log "compiling eBPF object"
make bpf

log "compiling Go binary"
make build

NEW_BIN="$ROOT/bin/waf-edge"
[[ -x "$NEW_BIN" ]] || die "build did not produce $NEW_BIN"

# --- 6. validate NEW binary against installed config -----------------------
CFG=/etc/waf-go/edge.yaml
if [[ -f "$CFG" ]]; then
  log "validating $CFG against new binary"
  if ! "$NEW_BIN" -check "$CFG" >/tmp/waf-edge-check.log 2>&1; then
    cat /tmp/waf-edge-check.log >&2
    die "new binary rejects current config — aborting install"
  fi
  log "config ok"
else
  warn "$CFG not present — skipping config validation"
fi

# --- 7. install + rollback snapshot ----------------------------------------
INSTALL_PATH=/usr/local/bin/waf-edge
ROLLBACK_PATH=/usr/local/bin/waf-edge.prev

OLD_SHA=""
if [[ -f "$INSTALL_PATH" ]]; then
  OLD_SHA="$(sha256sum "$INSTALL_PATH" | awk '{print $1}')"
fi
NEW_SHA="$(sha256sum "$NEW_BIN" | awk '{print $1}')"

if [[ "$OLD_SHA" == "$NEW_SHA" ]]; then
  log "binary unchanged ($NEW_SHA) — nothing to restart"
  exit 0
fi

log "installing new binary (sha256: ${NEW_SHA:0:16}...)"
if [[ -f "$INSTALL_PATH" ]]; then
  $SUDO cp -a "$INSTALL_PATH" "$ROLLBACK_PATH"
  log "rollback snapshot: $ROLLBACK_PATH"
fi
$SUDO install -m 0755 "$NEW_BIN" "$INSTALL_PATH"

# --- 8. restart systemd service --------------------------------------------
if [[ $RESTART -eq 0 ]]; then
  warn "skipping restart (--no-restart)"
  log "update complete; restart later with:  sudo systemctl restart waf-edge"
  exit 0
fi

if ! command -v systemctl >/dev/null 2>&1; then
  warn "systemctl not found — skipping restart"
  exit 0
fi

if ! $SUDO systemctl list-unit-files waf-edge.service >/dev/null 2>&1; then
  warn "waf-edge.service not installed — run bootstrap.sh to install unit"
  exit 0
fi

log "restarting waf-edge.service"
if ! $SUDO systemctl restart waf-edge.service; then
  warn "restart failed — rolling back"
  if [[ -f "$ROLLBACK_PATH" ]]; then
    $SUDO install -m 0755 "$ROLLBACK_PATH" "$INSTALL_PATH"
    $SUDO systemctl restart waf-edge.service || true
    die "rollback installed. check: journalctl -u waf-edge -n 50"
  fi
  die "no rollback available. check: journalctl -u waf-edge -n 50"
fi

# Give the service a moment to come up, then confirm.
sleep 1
if ! $SUDO systemctl is-active --quiet waf-edge.service; then
  warn "service did not stay active — rolling back"
  if [[ -f "$ROLLBACK_PATH" ]]; then
    $SUDO install -m 0755 "$ROLLBACK_PATH" "$INSTALL_PATH"
    $SUDO systemctl restart waf-edge.service || true
  fi
  $SUDO journalctl -u waf-edge -n 30 --no-pager >&2 || true
  die "rolled back to previous binary"
fi

log "update complete; waf-edge is running the new binary"
log "logs:   journalctl -u waf-edge -f"
log "status: systemctl status waf-edge"
