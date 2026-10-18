# Local retrieval and optional explanation — hardware measurement gate

Status: **not run; hardware-unverified; required before admission**.
Follow [campaign prerequisites, approvals and stop conditions](../hil-campaign.md).
The shipped admission gate remains closed. Do not manually unmask, patch admission,
set environment overrides, or invoke a model in this build to collect numbers.
HG-05 Core reserve must first be validated on the DUT and an operator must approve
an isolated measurement campaign using an approved measurement harness. If that
path is unavailable, record blocked/not-run; do not substitute a container run.
Final production admission additionally requires review of these measurements.

1. Retain DUT class (initially 8 GiB), kernel/image, CPU/storage class, runtime
   architecture and executable hash, source/build provenance, both model hashes,
   quantization, context/thread/batch settings, test corpus digest and repeats.
   Use bge-m3 Q8_0 for embeddings and Qwen2.5-1.5B-Instruct Q4_K_M only in a
   separately approved generative exercise. No model starts before prerequisites.
2. Measure cold/warm startup to AF_UNIX healthy response for each server. Retain
   every sample, failures/timeouts, peak and steady RSS (per process and aggregate
   cgroup), cache preparation RSS/time, swap and OOM events. bge-m3 RSS is pending;
   Qwen ~1.23 GiB is container evidence only, never a sizing/admission pass.
3. Measure retrieval p50/p95 with cold and warm vector caches, query embedding
   separately, exact library/corpus and repetition counts. Measure explanation
   p50/p95 separately, accepted/dropped explanation counts and deadline outcomes.
   Recommended production configuration keeps generation OFF; testing it does
   not authorize enabling it. Never retain raw sensitive prompts in ordinary audit.
4. Repeat embedding alone, generation alone and combined where approved under
   the declared Core workload. Record reserve/headroom impact, Core/audit/lease
   continuity, CPU contention and responsiveness. Validate the 4 GiB aggregate
   safety ceiling, 3840 MiB provider budget and 256 MiB locald/cache allowance;
   lower qualified needs or keep a provider unavailable if they do not fit.
5. Exercise crash/restart-budget persistence, wrong/missing binary, wrong model,
   stale cache, timeout and memory pressure. Confirm keyword fallback/refusal is
   audited and no explanation server starts without separate admission. Observe
   no non-AF_UNIX sockets, outbound packets, privilege or Edge authority widening.
6. Archive sanitised raw sample tables, workload and independent observations
   through the campaign evidence lifecycle. Review HG-05, runtime measurements,
   operator approval and staged activation separately. Missing observations,
   interrupted Core work, unexpected traffic or incomplete audit block admission.

No VM/container latency or RSS qualifies target hardware, another architecture,
or another memory class. Keep failures and repeat after relevant image/runtime/
model/workload changes. This runbook supplies no approval or admission bypass.
