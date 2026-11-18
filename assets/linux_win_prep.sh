set -eu
DEV="$1"; PART="$2"; ISO="$3"; ISO_MNT="$4"; USB_MNT="$5"; OWNER="$6"
umount_parts() { for p in "$DEV"[0-9]* "$DEV"p[0-9]*; do umount "$p" 2>/dev/null || true; done; }
umount_parts
wipefs -a "$DEV"
parted -s "$DEV" mklabel gpt
parted -s "$DEV" mkpart primary fat32 1MiB 100%
parted -s "$DEV" set 1 esp on
partprobe "$DEV"
udevadm settle --timeout=15 2>/dev/null || sleep 2
i=0
while [ ! -b "$PART" ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done
[ -b "$PART" ] || { echo "The new partition $PART did not appear." >&2; exit 1; }
umount_parts
mkfs.vfat -F 32 -n WIN11USB "$PART"
udevadm settle --timeout=15 2>/dev/null || true
umount_parts
if ! mount -t udf,iso9660 -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"; then
echo "Mounting the ISO as UDF/ISO 9660 failed; letting mount detect the type." >&2
mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"
fi
mount -o uid="${OWNER%%:*}",gid="${OWNER##*:}" "$PART" "$USB_MNT"
