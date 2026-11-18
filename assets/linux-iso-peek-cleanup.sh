set -eu
trap '' INT
umount "$1" || true
