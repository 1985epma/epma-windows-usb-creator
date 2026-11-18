set -eu
trap '' INT
ISO="$1"; ISO_MNT="$2"; OWNER="$3"
if ! mount -t udf,iso9660 -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"; then
echo "Mounting the ISO as UDF/ISO 9660 failed; letting mount detect the type." >&2
mount -o loop,ro,uid="${OWNER%%:*}",gid="${OWNER##*:}" "$ISO" "$ISO_MNT"
fi
