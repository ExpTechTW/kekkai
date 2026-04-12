#!/usr/bin/env bash
# Compile eBPF C source to object file consumed by go:embed.
# Requires clang >= 14 and Linux kernel headers / vmlinux.h.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/bpf/xdp_filter.c"
OUT_DIR="$ROOT/internal/loader/bpf"
OUT="$OUT_DIR/xdp_filter.o"

mkdir -p "$OUT_DIR"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  TARGET_ARCH=__TARGET_ARCH_x86 ;;
  aarch64) TARGET_ARCH=__TARGET_ARCH_arm64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

clang -O2 -g -target bpf \
  -D "$TARGET_ARCH" \
  -I/usr/include/"$(uname -m)"-linux-gnu \
  -c "$SRC" -o "$OUT"

echo "built: $OUT"
