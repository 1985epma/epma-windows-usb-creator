set -eu
sync
umount "$2"
{ echo 3 > /proc/sys/vm/drop_caches; } 2>/dev/null || true
mount -o ro,uid="${3%%:*}",gid="${3##*:}" "$1" "$2"
