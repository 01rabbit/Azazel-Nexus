# M.I.O. local performance bench

This opt-in, standard-library benchmark is development material. Run it from
an integrated Milestone 3 checkout with Lane A's `local_advisory` and Lane B's
`mio_serve` and `llama_server_record`. It uses their public prompt, advisory
reader, record builder and process lifecycle. Streaming measurement is a
bench-only HTTP-over-AF_UNIX observer. It does not call entryd, grant admission,
modify `RUNTIMES`, change Edge authority, or generate HG-05/route evidence.

## Run on colima dc34

The planned host is aarch64, 4 CPUs, 8 GiB, Docker context `colima-dc34` (Colima
profile `dc34`). The image is the CPU-only static llama.cpp `az-llama:b11716`.
The runner records the binary digest, while the version label is the declared
image pin; verify the image/binary before interpreting results. Server startup
is process-cold, not a guarantee that the host filesystem cache is cold.

The supported candidates are the orchestrator's observed replacement set.
The supplied `SHA256SUMS` records these digests (the entry script verifies the
files before execution):

| Model filename | License | SHA-256 |
| --- | --- | --- |
| `qwen2.5-1.5b-instruct-q4_k_m.gguf` | Apache-2.0 | `6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e` |
| `hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf` | Llama 3.2 Community License | `b5aed3ff090e2dba9587a211dc75a350ac1f501048829f140df90763f908c555` |
| `Phi-3.5-mini-instruct-Q4_K_M.gguf` | MIT | `e4165e3a71af97f1b4820da61079826d8752a2088e313af0c7d346796c38eff5` |

Ollama's Qwen3.5 GGUFs fail upstream llama.cpp loading with
`rope.dimension_sections`; they are excluded from both E2E selection and the
benchmark matrix. These licenses and digests describe the supplied artifacts.
No models or measured results belong in this repository.

From the integrated checkout, use the single [container entry script](run_in_container.sh):

```sh
mkdir -p /tmp/mio-results
docker --context colima-dc34 run --rm \
  --cpus 4 --memory 8g --memory-swap 8g --pids-limit 128 \
  -v "$PWD:/src:ro" \
  -v /Users/mao/.claude/jobs/b59933b2/tmp/models:/models:ro \
  -v /tmp/mio-results:/out \
  --entrypoint /bin/sh az-llama:b11716 /src/bench/mio_local/run_in_container.sh
```

The script copies the read-only checkout to `/out/repo`, creates `/out/venv`,
installs both distributions and test dependencies, then runs the functional
E2E before all three models' bench cells. It requires Python >=3.11, pip,
venv, a compiler and Python headers (the runtime builds its Linux timer
extension). Dependency installation needs package-index access or a populated
pip cache. The model and binary are never downloaded by the script.
`AZ_LLAMA_SERVER` can select an existing binary, otherwise PATH is searched.
It is copied into the package-owned executable path in this disposable
container. Logs, JSONL and Markdown results go under `/out`. Use a fresh output
directory; an existing run is refused. E2E failure stops the benchmark.

Observed smoke on dc34: aarch64, 4 CPU, 8 GiB, CPU-only b11716;
`--host /path.sock` selects AF_UNIX and ready `GET /health` returns 200.
Chat responses provide `choices[0].message.content`, `usage` and llama.cpp
`timings`. Both request paths use Lane B's `inference_document` serializer and
the same `/v1/chat/completions` HTTP-over-AF_UNIX endpoint. Bench SSE observation
is retained for TTFT; both paths request the same JSON schema constraint and
use `build_prompt` plus `read_local_advisory` for advisory validity. A schema
constraint alone never establishes advisory validity.

Each model gets four cells in fixed order: no load at concurrency 1/2, then
background load at concurrency 1/2. Each cell starts and stops a fresh server.
Two server slots, CPU-only execution, temperature zero, thread count, context
and output cap stay fixed across cells. Prompt caching is disabled in each
request. The first request is retained; there is no excluded warm-up.
Twenty total requests per cell cycle evenly through the four fixed synthetic
P0-public situation frames in [frames.json](frames.json). The questions cover
authentication and DNS investigations, paired in English and Japanese. This
is a fixed workload, not a semantic correctness or language quality score.

## Record contract: azazel-nexus/mio-bench/1

Each UTF-8 JSONL line is one complete model/condition cell. It has:

| Field | Meaning |
| --- | --- |
| `schema`, `provenance`, `not_hg05` | Exactly `azazel-nexus/mio-bench/1`, `bench`, `true` |
| `environment` | Architecture, visible CPU count/affinity, effective memory ceiling, declared llama.cpp version, binary SHA-256, OS description |
| `model`, `frames_digest` | Model basename and SHA-256; SHA-256 of the exact frame file |
| `condition` | Client concurrency 1/2, load flag, total request count, deadline seconds, token cap |
| `runtime_options`, `load` | Context/threads/slots/GPU layers; worker count, per-worker CPU duty fraction, total memory MiB, maximum duration seconds |
| `cold_start_ms` | Wall time from start through successful health; null on failure |
| `attempted`, `stream_completed` | Number dispatched; number with a complete bounded SSE stream |
| `valid_advisory_rate` | Number accepted as `Advisory` by `read_local_advisory`, divided by configured requests; all failures count against validity |
| `ttft_ms`, `total_ms` | Distributions of first nonempty content delta arrival and stream completion wall time, respectively, from request start |
| `tokens_per_s` | End-to-end output throughput: server-reported output tokens / total wall seconds |
| `generation_tokens_per_s` | Server-reported output tokens / `timings.predicted_ms` seconds, when provided |
| `resources` | Peak RSS bytes, CPU seconds, CPU percent (one core = 100%), resource samples and window seconds |
| `requests` | Ordered frame IDs/index, validity, exception type or null, successful stream timing/token counts; failed request elapsed time |
| `error` | Cell startup/lifecycle error type or null; never exception messages |

Every distribution is `{n, p50, p95}`. Percentiles use nearest rank
`sorted[ceil(p*n)-1]` and are null unless that metric has at least 20 samples.
Null token counts/timings are unavailable, never estimates or zero. Successful
streams with rejected advice still contribute latency/throughput; interrupted
streams contribute no successful-stream percentile. Per-request failures
remain visible. A startup failure has zero attempts and validity zero.
Neither questions nor response text is copied into the results.

Linux `/proc` sampling every 50 ms identifies the server by its unique socket
argument; it excludes the runner and background load. Peak RSS is the maximum
of sampled VmRSS/VmHWM. CPU seconds are sampled user+system ticks from process
birth; the window includes startup through cleanup, so CPU percent is a
whole-cell average and can exceed 100% for multiple threads. This targets the
single-process, multithreaded llama-server build. Very short-lived processes
may escape sampling; missing `/proc` metrics remain null. The memory ceiling
is the minimum of physical memory and a finite cgroup v1/v2 limit. Docker's
CPU quota is fixed in the command; visible CPU count alone is not that quota.

The load is an approximation of Edge resource contention, not an Edge
performance measurement: 1..4 processes, CPU duty 0..1 per worker on a 50 ms
cycle, and 0..1024 MiB total resident page-touched memory. Every worker has a
hard maximum duration and the context manager reaps, terminates, then kills
if needed. Requests are bounded to 20..10000, deadlines <=600 s, startup
<=300 s, and the worst-case cell <=21600 s. The model cap is 16. The socket
stream has a 1 MiB ceiling, a 64 KiB line ceiling and an absolute watchdog.

## Tests and distribution boundaries

```sh
AZ_REPO="$PWD" /Users/mao/.claude/jobs/b59933b2/tmp/ut.sh -q \
  --basetemp="$(mktemp -d /tmp/azD.XXXX)" bench/mio_local/test_runner.py
```

Tests inject a fake lifecycle server and fake streaming HTTP responses;
there is no socket bind or real model requirement. They also check the fixed
privacy classes, public builder adapter, summary guard and load cleanup.

Both [library](../../pyproject.toml) and [runtime](../../runtime/pyproject.toml)
setuptools configurations discover only `src`. No bench console entry point,
package data or runtime dependency is added. The existing installer stages
only declared product files. Source scans remain scoped to `src` and
`runtime/src` without exemptions; a bench test also asserts that neither
source tree imports `bench`. Keep this directory out of shipped distributions.
