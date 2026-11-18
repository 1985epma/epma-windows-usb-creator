set -eu
trap '' INT
ISO="$1"; DEV="$2"; SIZE="$3"; BS="$4"; STOP="$5"
{ blockdev --flushbufs "$DEV"; echo 3 > /proc/sys/vm/drop_caches; } >/dev/null 2>&1 || true
off=0; i=0
while [ "$off" -lt "$SIZE" ]; do
  if [ -e "$STOP" ]; then echo "VERIFY_CANCELED"; exit 0; fi
  len=$(( SIZE - off ))
  if [ "$len" -gt "$BS" ]; then len=$BS; fi
  if ! cmp -s <(dd if="$ISO" bs="$BS" skip="$i" count=1 2>/dev/null | head -c "$len") \
              <(dd if="$DEV" bs="$BS" skip="$i" count=1 2>/dev/null | head -c "$len"); then
    echo "VERIFY_FAIL $off"; exit 0
  fi
  off=$((off + len)); i=$((i + 1))
  echo "VERIFY_PROGRESS $off"
done
echo "VERIFY_OK"
exit 0
