set -eu
trap '' INT
for p in "$2"[0-9]* "$2"p[0-9]*; do umount "$p" 2>/dev/null || true; done
if [ "$5" = direct ]; then
  dd if="$1" of="$2" bs="$3" conv=fsync status=progress oflag=direct &
else
  dd if="$1" of="$2" bs="$3" conv=fsync status=progress &
fi
pid=$!
canceled=0
while kill -0 "$pid" 2>/dev/null; do
  if [ -e "$4" ]; then kill "$pid" 2>/dev/null || true; canceled=1; break; fi
  sleep 1
done
if [ "$canceled" = 1 ]; then wait "$pid" 2>/dev/null || true; echo WRITE_CANCELED; exit 0; fi
wait "$pid"
sync
