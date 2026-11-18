set -eu
for p in "$1"[0-9]* "$1"p[0-9]*; do umount "$p" 2>/dev/null || true; done
