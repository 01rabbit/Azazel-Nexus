#!/bin/sh
set -eu
umask 077
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=/src:/src/src:/src/runtime/src
cd /src
binary=$(command -v llama-server)
mkdir -p /usr/libexec/azazel
if [ "$binary" != /usr/libexec/azazel/llama-server ]; then
  cp "$binary" /usr/libexec/azazel/llama-server
fi
binary=/usr/libexec/azazel/llama-server
# No installation or network access: stdlib + repository packages only.
exec python3 -m bench.mio_quality.runner \
  --binary "$binary" --model "/models/$QUALITY_MODEL" \
  --output /out/quality.json --summary /out/summary.md
