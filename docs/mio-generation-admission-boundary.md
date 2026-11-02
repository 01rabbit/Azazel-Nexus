# Generative slow lane: blocked at admission

Status: additive runtime seam, closed by default. No production generation
loader or grant exists. The current normal fast lane remains
`AssistantCore(model=None)` with authenticated Knowledge Lite advisories.

Audited source: Nexus `8301bc82f31313e930c25e75788b6fd89295e559`;
MIO pin `9fedb01bc9936531407a5181aa8fa5553ec19d55`.

The existing contract cannot authenticate a separate `generation` admission:

- `AdmissionPolicy` accepts exactly `("embedding",)`.
- `AdmissionContext` and `verify_local_model_admission` reject any other role.
- Protected admission storage, runtime measurement and loader selection describe
  embedding only; an embedding approval cannot fund generation.
- `LOCAL_MODEL_ADMISSION_ENABLED` is false. `ServingProcess.start` refuses
  before spawning. `prepare_local_models` returns `server=None` to the advice
  service even when its independently supervised embedding retriever exists.

The separate sealed `GenerationCapability` has no production minting reader.
Both the global admission gate and the new generation gate remain false.
A test-only `FixtureLane` overrides authorization only in the unit test module
and marks its metadata `origin: fixture`; production readers cannot load it.
An embedding approval cannot authorize this lane. No policy, systemd isolation,
installer, HG, LOCAL or fail-closed rule changes here.

Before production admission can connect this seam to a real model, a separately
reviewed contract must define all of the following:

1. A separately authenticated `generation` role, explicit protected policy and
   atomic approval artifact; keep embedding approval non-substitutable. Bind
   operator purpose, key/security epoch, node/commissioning/DUT, catalog/model,
   installed generation and lineage, fixed binary/ABI/argv, compatibility tuple,
   validity window, independently enrolled attester and revocation checks.
2. A real attested generation campaign with measured peak RSS, startup,
   prefill/decode latency and Core reserve under required load, using the exact
   fixed generation settings. Embedding retrieval timings and fixture values
   cannot satisfy it. Define resource fit and concurrent embedding/generation
   reserve accounting within the existing containment envelope.
3. A loader-minted, sealed generation capability holding verified descriptors;
   recheck role, expiry, generation and trust before dispatch and while idle.
   Reuse product-owned `llama-server`, supervisor restart budgets and withdrawal.
   No arbitrary endpoint, host Ollama access or network bypass is permitted.
4. An advisory-only asynchronous request/result contract binding immutable
   generation ID, frame ID and trace ID. Specify hard queue capacity, request
   and output byte/token bounds, monotonic deadline, cancellation, supersession
   and stale-result rejection. Cancellation must bound provider work, not merely
   discard a future. Fast Knowledge/MIO publication must not await the queue.
5. A validated MIO structured callable with measured provider timing and actual
   provider usage. Missing usage remains unknown; absent admission/server stays
   closed/degraded. Fixture-only responses must identify their fixture origin.
   Validate complete result/frame/trace/generation binding before publication.
   Model prose cannot alter routing, authorization, enforcement, Edge score or
   lease, and cannot replace deterministic evidence or fast Knowledge results.

The software seam runs after fast assessment in normal `mio.local.assess`.
It creates one bounded worker only after authorization, with one pending slot,
a five-second default deadline (hard maximum thirty seconds), 768 output tokens
per structured task, and sixteen retained results. Exact repeated source polls
the result; a changed report with the same request ID supersedes old work. A
worker deadline watcher stops the owned supervised server on timeout/cancel,
using its existing process-group cleanup; it never starts or restarts it.
Stopping a server requires explicit loader replacement before future use.

The normal entry reply carries separate `slow_analysis` metadata, which never
feeds route selection or replaces `fast_assistance`. Fast and slow initially
share the validated MIO frame. Completed slow results retain their original
frame/trace/generation bindings when polled; the new fast assessment can have
its own fresh frame. This is polling, not a background push/publication service.
An additive Draft candidate protocol also permits explicit original-job polling:
`mio.local.generation.result` takes exactly `result_handle`, `generation_id` and
`trace_id` identifier arguments, no event payload, and the same SERVICE principal
restriction as assessment. A queued receipt includes a random 64-hex-character
handle. This is retrieval correlation, never an admission grant. Both generation
authorization gates and the current capability remain required on polling.

The reply is `{"outcome":"generation_result","slow_analysis":...}`. A missing,
expired, evicted, unauthorized or mismatched binding returns only
`{"state":"stale","usage":"unknown"}`. A valid handle returns only its original
job's queued/terminal metadata and original generation/frame/trace. A changed
current event is assessed separately; polling never projects old assistance into
that event. `LocalSocketClient.generation_result(receipt)` validates all original
bindings and never alters its current `last_slow_analysis` or fast assistance.
It uses the existing authenticated AF_UNIX exchange and does not rerun source,
perform embedding lookup, or start generation work.

The incident explainer polls this result only through its explainer-authorized
`mio-advise` entry socket. Before the first poll it appends the receipt to a
separate private `mio-generation-results/YYYY-MM-DD.jsonl` event store (0700
directory, 0600 segments, bounded to 8 MiB and fourteen days). Receipt and
terminal events bind incident ID/sequence/request ID to the original
frame/trace/generation/handle. This append-only store is not hash-chained and
does not amend the Edge intake chain or the original explanation record. Its
handles and generation identifiers never enter `recent.json` or the UI.

GenerationLane state is process-local. After an explainer restart, an
uncompleted durable receipt is polled again; if its original result has expired
or been evicted, the lane records only `stale` and never starts the work again.
A newer incident sequence or intake reset supersedes the earlier receipt. Only
a complete, schema-validated response may add a sanitized
`model_proposed_unverified` advisory to the recent projection. Timeout, cancel,
superseded, stale and other terminal outcomes carry status only; none can
change Edge policy, fast assistance or admission.

Handles expire on a monotonic sixty-second TTL starting at queue acceptance
(configurable positive maximum: three hundred seconds), with sixteen retained
records and the existing 128 KiB advisory output bound. Expiry/cap eviction
forgets retrieval, including the legacy source cache; reads do not extend TTL.
Original exact-source polling and changed-source supersession semantics remain.
This protocol is an additive Draft candidate awaiting owner/API acceptance before
rollout; it grants no production permission.
No startup grant, process-start path or production policy is introduced. The structured transport uses existing product-owned `LocalServer`
and MIO response schemas, then the core's grounding/lifecycle validation. Usage
is known only for actual nonnegative integer provider counters on every call;
missing counters remain unknown. Existing inference consumers retain strict
usage requirements unless explicitly opting into unknown usage.

Tests cover default denial, role/expiry/seal/generation refusal, one pending
slot, timeout/provider stop, supersession, result binding mismatch, provider
usage known/unknown, the real MIO core with an inert fixture provider and fast
Knowledge preservation. Fixture assertions are software evidence only. No
product-model success or measured resource/latency claim is made. Production
capability issuance, attested generation reserve accounting and the protected
policy ceremony remain blocked on owner review of requirements 1–3 above.
