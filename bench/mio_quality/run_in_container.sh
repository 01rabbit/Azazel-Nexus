#!/bin/sh
# Host launcher: usage run_in_container.sh MODELS_DIR OUT_DIR [MODEL_FILENAME]
set -eu
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || { echo 'usage: run_in_container.sh MODELS_DIR OUT_DIR [MODEL_FILENAME]' >&2; exit 2; }
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
models=$(CDPATH= cd -- "$1" && pwd)
mkdir -p "$2"
out=$(CDPATH= cd -- "$2" && pwd)
model=${3:-qwen2.5-1.5b-instruct-q4_k_m.gguf}
case "$model" in */*|.|..) echo 'model must be a filename' >&2; exit 2 ;; esac
[ -f "$models/$model" ]
[ ! -e "$out/quality.json" ] && [ ! -e "$out/summary.md" ]
exec docker run --rm --network none \
  --mount "type=bind,source=$repo,target=/src,readonly" \
  --mount "type=bind,source=$models,target=/models,readonly" \
  --mount "type=bind,source=$out,target=/out" \
  --env "QUALITY_MODEL=$model" --entrypoint /bin/sh az-llama:b11716 \
  /src/bench/mio_quality/container_entry.sh
