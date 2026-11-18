set -eu
sync
for p in "$1"[0-9]* "$1"p[0-9]*; do umount "$p" 2>/dev/null || true; done
if command -v eject >/dev/null 2>&1 && eject "$1" 2>/dev/null; then echo EJECTED; exit 0; fi
if command -v udisksctl >/dev/null 2>&1 && udisksctl power-off -b "$1" 2>/dev/null; then echo EJECTED; exit 0; fi
echo NOT_EJECTED
exit 0
