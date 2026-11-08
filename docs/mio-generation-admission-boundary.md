# Generative slow lane: blocked at admission

Status: additive runtime seam, closed by default. No production generation
loader or grant exists. The current normal fast lane remains
`AssistantCore(model=None)` with authenticated Knowledge Lite advisories.

Historical audit reference: Nexus `8301bc82f31313e930c25e75788b6fd89295e559`;
MIO pin `9fedb01bc9936531407a5181aa8fa5553ec19d55`. This identifies an
earlier audit snapshot, not the current candidate head.

Current candidate scope (before this documentation-only correction):
[PR #398](https://github.com/01rabbit/Azazel-Nexus/pull/398) head
`6c3f07011c2dc337d2ecb2bc0e8b44179e2a180a` is the base of
[PR #399](https://github.com/01rabbit/Azazel-Nexus/pull/399), whose head is
`bdae6388c014dd78a3a1897e44460dd1c67d2a54`. Fixture results in this scope are
synthetic software evidence; they do not establish real-model or product-process
success. Admission remains disabled, with no production generation issuer or
generation server; existing HG and generation reserve gates remain intact.

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
a five-second default deadline (hard maximum thirty seconds), an output ceiling
of 768 tokens per structured task (budget opt-in caps below), and sixteen retained results. Exact repeated source polls
the result; a changed report with the same request ID supersedes old work. A
worker deadline watcher stops the owned supervised server only while a provider
request is in flight (timeout, cancel or supersession, while it is in flight); after
a transport failure the worker stops it once the failed or returned call has ended.
It uses its existing process-group cleanup and never starts or restarts it. An idle
provider is kept: supersession or cancel with no request in flight stops nothing.
A content-invalid model response (non-JSON, non-object, non-finite numbers) fails
only that job; the provider is retained and not stopped. Stopping a server
requires explicit loader replacement before future use: after a successful
`stop()` the lane is permanently stopped, any pending job is dropped and its receipt
published as `degraded`, and a stopped lane admits no new work: later new submits return
`degraded` with no result handle and no inference. Same-source retries still retrieve an
existing cached result or queued/active handle (the stored receipt), and poll handles
remain usable until their TTL. A pending job dropped by the stop is recorded as a terminal
`degraded` entry in the same sixteen-entry result cache (same TTL), so an exact retry returns
`degraded` with its original handle; if an active job's receipt was already pruned or expired,
the retry returns `degraded` with no handle rather than an unpollable `queued` one. The in-flight job keeps its `timeout`/`cancelled` receipt.

If `stop()` raises, termination is unconfirmed. The lane fences the server
permanently and attempts `stop()` only once. When that failure is confirmed, it
publishes `degraded` receipts for the in-flight job and any pending job without
waiting for `infer()` to return; until then, the prior `timeout`/`cancelled` receipt
may still be visible. A late return of the blocked call cannot overwrite them. The
lane keeps at most that single blocked worker, queues nothing
further and rejects every later new submit as `degraded` without inference; exact
retries of existing work return its stored (degraded) receipt or cached result. A new
lane/server from the loader is required.

A successful `stop()` is recorded for the job and is never called a second time
(the worker does not repeat the watcher's stop after the resulting transport
failure). A `timeout` or `cancelled` receipt can be visible while the stop outcome
is still pending; receipts are overwritten with `degraded` only after a stop
failure is confirmed. If `stop()` hangs rather than raises, no such confirmation
arrives and the pending/queued and active slots can stay stuck until it returns
(open limitation, G-4). `submit` checks cached/active/pending matches, then the stop/fence flags, under
the lane lock, so a stop or fence that lands mid-call admits no new receipt or pending job.

Known limitations: admission closing mid-flight is not an in-flight stop trigger,
so a request already running finishes or hits its deadline. The production
supervisor `stop()` implementation is outside this change and unchanged; a stop
that hangs or fails there remains an open limitation (G-4) beyond this fence.

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

Each terminal event is appended to the receipt's daily segment, so a midnight
rollover cannot retain a result while retiring its receipt. A final torn row
refuses this optional store on restart without modifying the file or disabling
the fast explainer, Knowledge lookup or Edge intake; status reports the slow
result store as unavailable.

GenerationLane state is process-local. After an explainer restart, a legacy
uncompleted durable receipt is polled again; if its original result has expired
or been evicted, the lane records only `stale` and never starts the work again.
A newer incident sequence or intake reset supersedes the earlier receipt. Only
a budget-v1 complete, schema-validated response may add a sanitized
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

## Opt-in generation budget and durable result status

`GenerationLane(budget_enabled=True)` connects the agreed MIO budget API when
it is available. With budget enabled, a missing or older API refuses all sends
with `count_unknown`; it never routes to the unbudgeted transport. The older
compatibility path exists only when budget is disabled. Production still has no generation
issuer and both admission constants remain false. Budget failure never retries
through the compatibility path.

The software fixture profile uses per-task output caps 768 / 384 / 512, with
no automatic shrinking below those values, slack 32, and a positive 0.05s
provider minimum per task. These are fixture configuration values, not measured
performance or semantic sufficiency claims. All three schemas and MIO grounding
must still pass. No production time profile or HG evidence is inferred from
these values. The absolute 5s default / 30s maximum deadline starts at queue
acceptance. `R=max(0.5s,10% of D)` reserves final work and task overhead; remaining
provider time is divided 45:20:35 with later-task minimum reservations. The sum
of provider allocations cannot exceed D-R, even when earlier calls return early.
R, weights, slack and provider minimums are explicit `BudgetSettings` values,
independent of admission/HG and recorded separately from server identity.
For the adopted `fixture-v1` identity these values are fixed: 10%, 500ms,
45:20:35, slack32, and 50ms per call. Runtime and CORE readers share the same
policy validation; a self-declared weaker reserve, different weights/slack or
minimum is refused. A different policy needs a separately accepted profile.
Readers also require each complete call's allocation to meet the recorded
minimum. Per-task output caps can still be supplied explicitly within the
existing ceiling.
Compile, count and validation time consume this same deadline.

The authenticated local server supplies model alias, model file/type identity,
BOS/EOS tokenizer identifiers, chat template, runtime build and `n_ctx` through
`/props`. Their hashes and a self-consistent tuple digest are private receipt
metadata. They identify the serving instance's declarations, not a new content
attestation; existing held-descriptor admission remains authoritative. The tuple
must exist and remain identical before/after counting and before dispatch.
A future authorized loader must also populate `GenerationCapability.model_context_limit`
from the verified model record corresponding to its model ID. No loader or issuer
is added here. The effective plan limit is `C=min(/props n_ctx, model_context_limit)`;
that configured bound is recorded in `profile.configured_context_limit` separately
from the server tuple. Both planner and reader enforce the min. Missing/invalid
model bounds refuse all budgeted sends with `count_unknown`. The fixed test
harness declares its 2048-token fixture bound; this is not production evidence.
Missing or changing fields refuse the next send with `count_unknown`.

The final request is rendered through that server's `/apply-template` and
counted through `/tokenize`. Budgeted inference sends the exact returned token
IDs to native `/completion`, together with the effective JSON schema, output
cap and remaining deadline. This removes any assumption that a separately
rendered count equals the OpenAI chat endpoint's internal prompt. There are no
character estimates, additional inference probes or unbudgeted retries.
Native per-request boolean `truncated` is the sole integrity signal: false is
preserved, true is truncated, missing/invalid is unknown. `tokens_evaluated` and
`tokens_predicted` are strict actual usage; native timings remain bounded
telemetry. The OpenAI-compatible response lacks these primary fields and caused
the earlier small-input `stop` / unknown result. Stop or matching usage never
implies preserved integrity. Actual input usage must equal the exact pre-count,
output usage must fit the cap, and explicit preserved integrity plus confirmed
stop are required. Unknown usage, incomplete output, malformed JSON, count
mismatch or a failed second/third task prevents model publication.

The private `generation_budget` v1 receipt records all three ordered tasks,
including failed and unsent tasks. A complete receipt requires its verified tuple
and full profile, effective C=min(server,configured model bound), I+O+S <= C, consistent schema/policy versions, positive per-call
allocations, elapsed time within each allocation and the final reserve, and
allocation totals within D-R. Failed receipts retain honest partial/unknown
fields and elapsed overruns; they cannot become complete. Readers share a CORE-only validator, reject
unknown versions and missing new-format metadata, and compute overall coverage
as the worst of upstream and all task coverage. Pre-projection slicing is
recorded before constructing the slow frame; any such loss remains unknown.
Selected material is labelled “選択した根拠に基づく生成助言（未検証、一部資料省略）”.
Old complete records remain readable, but the current UI shows static advice
and “旧記録・予算未確認”; it does not promote them to within-budget success.

The first failure remains `primary_outcome`; bounded unique `reasons` append
later cancellation, revocation, timeout or cleanup facts. `terminal_outcome`
records the control decision without replacing that first cause.
Results, cleanup and supersession are independent axes. A timeout can be
terminal while cleanup is pending. The control worker does not join a blocked
infer/stop worker. Dispatch closes immediately when stop is requested; no new
work uses that lane. Cleanup may confirm only before the original deadline;
failure, observation loss or deadline exhaustion permanently fences it.
Late inference or stop cannot promote an unconfirmed result to complete.
G-4's actual process/resource termination guarantee remains an independent,
unresolved gate.

The append-only result store writes at most one result, one cleanup revision
and one superseded event per receipt in the original daily segment. It checks
full bindings, duplicate revisions and monotonic transitions. Only pending
cleanup keeps polling after a terminal result. Poll deadlines never extend;
TTL/eviction or transport loss finalizes unconfirmed. Restart does not reset a
monotonic deadline: persisted pending cleanup immediately becomes
`restart_unconfirmed`. Cleanup failure is retained even after supersession.
When invalidation precedes result arrival, the receipt-bound superseded event
is saved first and the first real result has `result_state=superseded`. This
preserves actual sent usage and pending cleanup instead of inventing an empty
terminal result; queued receipt polling continues until a real result arrives.
Cleanup still requires a saved pending result. Storage failure leaves the fast
result available and reports slow storage unavailable. Public UI projections contain status and omission counts only,
without handles, identifiers, prompt text or selection unit IDs.

### MIO #48 dispatch notification contract

A budgeted transport implements `invoke_budgeted(task,prompt,on_dispatch)`.
All authorization, cancellation, fit and deadline refusal gates run before
sending, including a product-only `before_dispatch` check at the HTTP boundary.
The transport uses bounded socket sends and calls `on_dispatch()` synchronously
once after its first positive send return. It never notifies a known unsent
request. A partial request followed by send/deadline/response failure remains
sent-and-failed; it is not rolled back to zero. The post-send accounting callback
does not re-run a deadline/cancel gate that could erase those positive bytes.
Any previously known usage remains in the receipt; a failed call's unavailable
usage is unknown. Normal successful request payloads, native integrity extraction,
three-task validation and the absolute deadline remain the same. Missing or duplicate notifications
are closed failures (`dispatch_tracking_unavailable` / `send_notification_conflict`),
not successful model answers. A late notification cannot change a saved receipt.
The private and public budget projections retain these closed reasons and keep
`coordinator_disposition` separate from the original failure. The #48 candidate
wheel is used for isolated connection tests; the consumer dependency pin is
unchanged by this work.

For this weekend's budgeted Nexus caller through `mio_generation`, later tasks
receive bounded IDs and classifications for prior report and gap content. This
scope does not guarantee ID-only inputs for the shared MIO API when callers use
`references` or `knowledge`; that path remains open work. Public incident views
show the validated task dispatch flags and report fence state as `unknown`, since
a cleanup observation alone does not establish the current lane fence. No raw
receipt or provider payload is exported.

### Incident-bound handoff and restart

The budgeted runtime journals request and dispatch accounting and unknown IDs,
without persisting model, prompt, source or unknown bodies. After a restart or
caller epoch mismatch, an unconfirmed result cannot become complete; retained
terminal accounting does not restore the model text. The recent projection's
v1 binding requires the original incident, request, frame and lifetime, the
template version, unknown IDs and origins, verified/current evidence references,
receipt-verified hypothesis IDs and a complete advisory reference manifest.
Consumers withhold advice when that binding is missing or invalid. ID membership
does not independently verify a source or the meaning of a statement. The
budget caller is the authority for source metadata: frame references and frame
unknown IDs come from the authenticated Edge-to-Nexus local caller path and are
labelled `source=frame`, `trust=verified` as a caller assertion. Their observation
age must be less than the original receipt lifetime. Broker references require
explicit adapter-verified trust and an observed timestamp; missing metadata is
unverified/unknown, and only explicit revocation information yields revoked.
The current budget caller configures no broker; its adapter seam does not turn
raw request or model trust claims into verified sources.
Each binding evidence reference carries non-secret `observed_at` and
`valid_until` timestamps (observation plus the original receipt TTL). The binding
`expires_at` is the minimum of the receipt expiry and all known source deadlines;
this never extends or changes the receipt itself. Readers re-evaluate each source
deadline on every display/export, including a saved recent snapshot: at or after
`valid_until`, freshness is expired and advice is withheld. Missing/invalid times
also withhold; a saved `freshness=current` flag cannot renew a source.

Runtime extracts structured IDs from validated assistance and each raw task
response, and scans prose with MIO's ID grammar before display sanitization.
Prose uses the same NFKC normalization as public text. Reference-like tokens with
ambiguous boundaries or joined/malformed IDs make completeness partial rather
than silently disappearing. Separate IDs with whitespace or punctuation; Japanese text directly adjoining an ID (for example, `仮説h1を確認`) remains partial.
Compatibility spellings such as `h¹`, `𝐡1` and `ｈ１` use membership after NFKC: known IDs are accepted and unknown IDs remain partial.
Content digests are the exception to compatibility normalization: only raw ASCII
`sha256:[0-9a-f]{64}` (exact lowercase prefix and exactly 64 lowercase hex digits)
is a typed evidence ID. The same type is accepted in `binding.evidence_refs[].id`
and extracted from delimited advisory prose for membership checking. A digest
mentioned only in prose remains unlisted/partial; verified/current frame source
membership and receipt reference checks are still required. Uppercase, 63/65
digits, other prefixes, base64-like values, fullwidth spellings and embedded Cf
characters cannot acquire this type. Other long tokens retain the 32+ rejection.
Non-ID punctuation such as `+` or `/` directly after a digest separates tokens: the digest is extracted for membership, while the remainder follows the usual allowlist/secret guards and prose may become fixed withheld text; this boundary alone does not require partial completeness.
An ID-character suffix (ASCII alphanumeric, `_`, `-`, `.`, `:`, e.g. `Abc`, `_x`, `-1`, `.x`, `:1`) instead extends the same token, fails the digest type and triggers the 32+ ambiguous/partial rule; existing trailing-period stripping still applies.
The type does not apply to `source`, unknown categories or arbitrary text fields.
The prose privacy guard is unchanged: recognizing an ID for membership does not
authorize displaying its raw text. Digest-bearing prose can still become the
fixed withheld text while the valid ID remains visible in binding metadata.
The prose repertoire includes ASCII `% & + / * # @ ~ ^ | < > = $`; independent secret/path privacy guards still apply.
Secret-labelled keys in `key=value` or `key: value`
prose cause the entire string, including its value, to become fixed withheld text.
After NFKC and format-control (Cf) removal, every non-ASCII-alphanumeric character (Unicode-wide `[^A-Za-z0-9]`) separates key elements, including Japanese punctuation. The secret-check skeleton preserves each run of boundaries as `|`, including `=` and `:`; it never deletes them to join adjacent words. Long secret labels (including `passwd`, `passphrase`, `passcode`, and `token`) match substrings within key elements regardless of value context. Only `pass`, `pwd`, `pin`, `auth`, `otp`, and `key` are short aliases: they match whole elements regardless of assignment operators, value length, or following prose. This also withholds compound labels such as `pin_status`, `user.auth.name`, and `my otp value`, including their entire values. Consecutive fragments of one or two characters are joined for exact alias checks (for example, `hint,p,w;d: value`); longer elements stop this scan. Joined aliases need no value context. Ordinary prose such as `check auth status h1`, `pin the route h1`, `pass the check h1`, and `key observation h1` may consequently be withheld; this known conservative behavior is deferred for separate work. Ordinary words such as `spinning`, `author`, `compass`, `bypass`, and `passive` do not match a short alias by substring. The writer rechecks the projected text, so a long label created by punctuation removal is withheld too. Chained keys are checked before any prose sanitization. The independent character repertoire guard still rejects format controls in public prose.
`hypothesis_ids` comes from validated hypothesis provenance; `advisory_refs`
contains the structured reference set, including unknown and gap references.
An ID occurring only in prose is excluded and sets private
`unlisted_prose_ids=true` and public `completeness=partial`. Only
`completeness=complete` is displayable; missing completeness also withholds.
A referenced model unknown without its live body, unavailable extraction, or
an oversized manifest also withholds. Bodies are never added to binding or
journal. Unknown IDs marked unavailable after restart cannot authorize advice.
These checks establish membership, not semantic truth or model quality.
Templates 1.9.0 (stored receipts) and 1.10.0 are accepted; the Nexus MIO dependency pin
identifies the advice4 candidate wheel (template 1.10.0).

The native incident card, status JSON and handoff JSON/Markdown retain the
validated non-secret binding: incident/request/frame IDs, template version,
original timestamps, completeness, ID-only unknown origin/category/status,
source trust/freshness/deadlines and hypothesis/advisory reference IDs. These
fields remain advisory metadata, never operator actions or proof of facts.
The public metadata guard also rejects secret-like, address and encoded values;
fixed reference IDs are handled as typed IDs, not arbitrary host:port strings.
Withheld results expose a fixed `reason_code` and Japanese `reason_ja`.
Missing and partial bindings both use `binding_unverified`; expired bindings,
incident mismatch, unknown templates and unverified sources have specific codes.

After recovery, a non-complete slow projection may carry the closed
`recovery` object with `status=unavailable_after_restart` and ID-only `unknowns`.
It does not fabricate a complete binding or restore unknown bodies. Readers
reject recovery metadata on complete results. Receipt accounting, terminal
reasons, original TTLs and the permanent restart fence are unchanged.
