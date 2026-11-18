set -eu
trap '' INT
dd if="$1" of="$2" bs="$3" &
pid=$!
canceled=0
while kill -0 "$pid" 2>/dev/null; do
  if [ -e "$4" ]; then kill "$pid" 2>/dev/null || true; canceled=1; break; fi
  kill -INFO "$pid" 2>/dev/null || true
  sleep 1
done
if [ "$canceled" = 1 ]; then wait "$pid" 2>/dev/null || true; echo WRITE_CANCELED; exit 0; fi
wait "$pid"
sync
