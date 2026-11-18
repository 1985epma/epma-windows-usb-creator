set -eu
trap '' INT
DEV="$1"; PART="$2"; LABEL="$3"; USB_MNT="$4"; OWNER="$5"; FLAG="$6"
umount_parts() { for p in "$DEV"[0-9]* "$DEV"p[0-9]*; do umount "$p" 2>/dev/null || true; done; }
if [ -e "$FLAG" ]; then echo SEED_NOT_TOUCHED; exit 0; fi
umount_parts
if [ -e "$FLAG" ]; then echo SEED_NOT_TOUCHED; exit 0; fi
wipefs -a "$DEV"
parted -s "$DEV" mklabel gpt
parted -s "$DEV" mkpart primary fat32 1MiB 100%
partprobe "$DEV"
udevadm settle --timeout=15 2>/dev/null || sleep 2
i=0
while [ ! -b "$PART" ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done
[ -b "$PART" ] || { echo "The new partition $PART did not appear." >&2; exit 1; }
umount_parts
if [ -e "$FLAG" ]; then echo SEED_CANCELED; exit 0; fi
mkfs.vfat -F 32 -n "$LABEL" "$PART"
udevadm settle --timeout=15 2>/dev/null || true
umount_parts
mount -o uid="${OWNER%%:*}",gid="${OWNER##*:}" "$PART" "$USB_MNT"
