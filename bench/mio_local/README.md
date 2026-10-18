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

From the integrated checkout, create an output directory and run:

```sh
mkdir -p /tmp/mio-results
docker --context colima-dc34 run --rm --network none \
  --cpus 4 --memory 8g --memory-swap 8g --pids-limit 128 \
  -v "$PWD:/work:ro" \
  -v /Users/mao/.claude/jobs/b59933b2/tmp/models:/models:ro \
  -v /tmp/mio-results:/results \
  -w /work --entrypoint /bin/sh az-llama:b11716 -ec '
    mkdir -p /usr/libexec/azazel
    cp "$(command -v llama-server)" /usr/libexec/azazel/llama-server
    export PYTHONPATH=/work:/work/src:/work/runtime/src
    python3 -m bench.mio_local.runner \
      --model /models/qwen3.5_0.8b.gguf \
      --model /models/qwen3.5_2b.gguf \
      --model /models/hf.co_XpressAI_shisa-v2.1-llama3.2-3b-GGUF_Q4_K_M.gguf \
      --requests 20 --threads 2 --context 2048 --max-tokens 256 \
      --deadline-s 120 --start-deadline-s 120 \
      --load-workers 1 --load-cpu 0.25 --load-memory-mib 256 \
      --output /results/run.jsonl
    python3 -m bench.mio_local.summary /results/run.jsonl \
      --output /results/summary.md
  '
```

The image must expose `llama-server` and Python >=3.11 on PATH (activate its
venv if needed). Copying the binary keeps the package-owned executable path
required by `RuntimeBinary`; the container is disposable. No network is used.
Use new output filenames for each run: both commands refuse to overwrite.
The three model filenames come from the orchestration plan; qwen models are
Apache-2.0, and Shisa uses the Llama 3.2 Community License. Model files and
results are not added to this repository.

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
