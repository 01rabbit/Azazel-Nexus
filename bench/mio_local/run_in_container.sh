#!/bin/sh
# Entry point inside az-llama:b11716; /src and /models are read-only mounts.
set -eu
umask 077
: "${AZ_LLAMA_SERVER:=$(command -v llama-server)}"
export AZ_LLAMA_SERVER
[ -x "$AZ_LLAMA_SERVER" ]
[ ! -e /out/repo ] && [ ! -e /out/venv ] && [ ! -e /out/run.jsonl ]
mkdir -p /out
cp -R /src /out/repo
# Drop worktree metadata: installation and execution require no Git access.
rm -rf /out/repo/.git
python3 -m venv /out/venv
/out/venv/bin/python -m pip install 'setuptools>=68' wheel 'pytest>=8' 'pynacl>=1.5' \
  dbus-next==0.2.3 PyYAML==6.0.3 > /out/install.log 2>&1
/out/venv/bin/python -m pip install --no-build-isolation --no-deps \
  /out/repo /out/repo/runtime >> /out/install.log 2>&1
mkdir -p /usr/libexec/azazel
if [ "$AZ_LLAMA_SERVER" != /usr/libexec/azazel/llama-server ]; then
  cp "$AZ_LLAMA_SERVER" /usr/libexec/azazel/llama-server
fi
AZ_LLAMA_SERVER=/usr/libexec/azazel/llama-server
AZ_GGUF_DIR=/models
export AZ_LLAMA_SERVER AZ_GGUF_DIR
cd /models
sha256sum -c > /out/models-check.log <<'SUMS'
6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e  qwen2.5-1.5b-instruct-q4_k_m.gguf
b5aed3ff090e2dba9587a211dc75a350ac1f501048829f140df90763f908c555  hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf
e4165e3a71af97f1b4820da61079826d8752a2088e313af0c7d346796c38eff5  Phi-3.5-mini-instruct-Q4_K_M.gguf
SUMS
cd /out/repo
export PYTHONDONTWRITEBYTECODE=1
/out/venv/bin/python -m pytest -q -p no:cacheprovider tests/e2e_local_inference \
  > /out/e2e.log 2>&1
/out/venv/bin/python -m bench.mio_local.runner \
  --model /models/qwen2.5-1.5b-instruct-q4_k_m.gguf \
  --model /models/hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf \
  --model /models/Phi-3.5-mini-instruct-Q4_K_M.gguf \
  --requests 20 --threads 2 --context 2048 --max-tokens 512 \
  --deadline-s 120 --start-deadline-s 120 \
  --load-workers 1 --load-cpu 0.25 --load-memory-mib 256 \
  --output /out/run.jsonl > /out/bench.log 2>&1
/out/venv/bin/python -m bench.mio_local.summary /out/run.jsonl --output /out/summary.md
