# M.I.O. local inference — functional E2E and bench, 2026-10-18

**Bench record, not HG-05 evidence and not admission evidence.** Production
stays not-admitted (`RUNTIMES` empty, admission gate closed, HG-05 unmeasured).
Raw files: [`mio-local-bench-2026-10-18/`](mio-local-bench-2026-10-18/)
(`summary.md`, `run.jsonl` — no model text is recorded — and `e2e.log`).

## Environment

colima profile `dc34` on an Apple-silicon MacBook: Linux 6.8 aarch64 VM with
4 vCPU and 8 GiB, Docker container limited to `--memory=8g --cpus=4`,
Debian 13, llama.cpp `b11716` built from source, CPU only, static
(`llama-server` digest `sha256:c296…2668`). Server: `-t 2 -c 2048 --parallel 2
-ngl 0`, AF_UNIX socket, schema-constrained JSON output. This approximates an
8 GiB target class but is **not** the target hardware (different CPU, arch,
memory system); the numbers inform model selection only.

## Functional E2E (real llama-server)

`tests/e2e_local_inference`: **12 passed**. The real path
entryd `mio.advise` → router → locald `mio.local.infer` → long-lived
llama-server → schema-constrained JSON → `read_local_advisory` → audited reply,
with test-only admission. Covered: advice returned, privacy classes, deadline →
timed out, crash → restart budget → fence, instruction-shaped output →
not advice, oversized and malformed output refused, missing socket, no prompt or
response text in any ledger, Edge authority unchanged.

## Bench (20 requests per cell, bilingual security-operations frames)

| Model (Q4_K_M) | License | Peak RSS | Cold start | Total p50 / p95 (1 client) | Valid advice |
| --- | --- | --- | --- | --- | --- |
| Qwen2.5-1.5B-Instruct | Apache-2.0 | 1.26 GiB | 0.5 s | 6.9 s / 8.6 s | 100 % |
| shisa v2.1 Llama 3.2 3B | Llama 3.2 Community | 2.45 GiB | 0.9 s | 21.5 s / 38.9 s | 95–100 % |

- Two concurrent clients roughly double total latency (Qwen 12.8 s p50,
  Llama 46.7 s p50); an Edge-like background load (1 worker, 25 % CPU, 256 MiB)
  changed little.
- Both fit an 8 GiB class with room for Core, but Llama-3B's p95 approaches the
  30 s per-inference deadline at two clients; Qwen-1.5B stays well inside it.
- `Phi-3.5-mini` (MIT, 3.0 GiB) loads, but every grammar-constrained request
  fails with HTTP 400 "Failed to initialize samplers" on b11716, so it is
  excluded. Ollama's Qwen3.5 GGUFs do not load in upstream llama.cpp.
- "Valid" means accepted by `read_local_advisory` (shape, no commands/URLs),
  not factual quality. Unconstrained field names were the main refusal cause and
  are now constrained by the schema.

## Not established

Target-hardware latency and memory (HG-05), behaviour under real Edge Core
load, answer quality, and anything about provider admission.
