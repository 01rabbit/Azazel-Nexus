# M.I.O. Runtime Control Plane

Status: **target contract, partially implemented**. This document specifies
the Nexus-owned runtime control plane for M.I.O.

| Section | State |
| --- | --- |
| §2 capacity envelopes | implemented (`resource_profile.py`, since #26) |
| §3 provider admission | implemented for local model providers (`cognition.py`, `compatibility.py`). What may be *offered* as a model, and what offering one does not mean, is fixed by [the model catalog contract](model-catalog.md) (Nexus#94) — it reaches `present` and stops there. The resource gate **refuses for lack of a measured Core reserve** — [`HG-05`](hardware-gates.md) — and since Nexus#68 the path a measurement would travel is built and driven: [the measurement procedure](core-reserve-measurement.md). Approval and staged activation are reached only with a reserve, where they refuse for having no implementation |
| §4 confinement | not implemented; needs a running provider, which §3 does not yet admit — and will not until approval and staged activation are implemented, one gate past the reserve |
| §5 route selection | implemented (`routing.py`) as the local-first ladder, with the envelope and budgets declared rather than discovered. Remote is `disabled` with no egress path. **Being replaced by policy-first / fastest-permitted** — [the route policy](mio-route-policy.md), Nexus#81 |
| §6 deterministic sanitizer | implemented (`sanitizer.py`) — see [the sanitizer](mio-sanitizer.md), which records three points the contract leaves open |
| §7 fallback | implemented (`routing.py`): all eight triggers, each with what it must never do. The invariant that a fallback never widens is checked over all 8 × 3 pairings |
| §8 publishing state and reasons | implemented (`CognitionReading`, four independent reasons) |
| §9 audit visibility | route selection and terminal outcomes are written to the entry daemon’s own verified chain; the broader audit producers below remain incomplete |

**Remote assistance remains unadmitted.** The library has no network client;
the runtime entry uses only local Unix socket clients. The separate remoted
still has no commissioned provider or inference transport. Enabling it needs an
enumerated privacy-class admission, a deterministic sanitizer, and explicit
operator permission, plus Fabric `mio_contracts` for the wire shape (§10).

Related: [M.I.O. dual cognition doctrine](mio-dual-cognition.md) (Edge-owned
semantics) · [the deterministic sanitizer](mio-sanitizer.md) ·
[the model catalog contract](model-catalog.md) ·
[offline model import](model-import.md) ·
[the operator screen](operator-view.md) ·
[online acquisition](model-acquisition.md) ·
[Capability model](capability-model.md) ·
[Contract ownership](contract-ownership.md) ·
[Inheritance ledger](inheritance-ledger.md) ·
[Azazel-Nexus #5](https://github.com/01rabbit/Azazel-Nexus/issues/5)

## 1. Division of ownership

This document covers **only** what Nexus performs on the host. It does not
restate or modify Edge-owned cognitive semantics.

| Concern | Owner |
| --- | --- |
| `MioSituationFrame`, hypothesis and grounding semantics, typed read-only evidence access, recommendation semantics, deterministic arbitration, canonical audit meaning | **Azazel-Edge** |
| Canonical wire shape of the frames and advisory results (`mio_contracts`) | **Azazel-Fabric** — *target, not released* |
| Provider admission, launch, confinement, resource measurement, route selection, sanitizer execution, merge presentation, capability-state publication | **Azazel-Nexus** (this document) |

M.I.O., local models, remote assistance, Knowledge, and Deception are
advisory. None may authorize or execute an Edge action, in any state, under any
resource profile. Nothing in this document creates an exception.

## 2. Capacity envelopes and their vocabulary

Nexus uses one selector, defined in [capability model](capability-model.md) §2.
The table below maps each **resource envelope** to the eligibility that envelope
*permits*. That is the only mapping this document holds, and provider admission
(§3) is what needs it.

| Usable RAM (MiB, after firmware reservation) | Nexus envelope name | Eligibility the envelope permits |
| --- | --- | --- |
| `< 7168` | `diagnostic` | diagnostics only |
| `7168` – `15359` | `core` | Core |
| `15360` – `31743` | `lite` | "Lite-capable" |
| `>= 31744` | `standard` | "Full-capable" |

Each threshold is the nominal module size it admits minus a **1024 MiB
firmware-reservation allowance** (8192 − 1024, 16384 − 1024, 32768 − 1024),
because usable RAM never reaches nominal — firmware takes UEFI runtime services,
ACPI tables, kernel-reserved regions, and integrated-GPU stolen memory, which
alone is commonly 512 MiB. [Capability model](capability-model.md) §2 holds the
derivation, the measured case behind it, and the residual risk that a host
reserving more than 1024 MiB still selects one envelope low.

The envelope is selected from that reading alone. The Core reserve is applied
afterwards, per provider, in §3 below — an envelope is never a statement that a
given model fits.

`lite` and `standard` name a **resource envelope**. "Lite-capable" and
"Full-capable" name what that envelope *permits*, which is only realized when
the topology, verified-asset, and trust/health dimensions independently agree.
Documents that assert capability use the eligibility phrasing; documents that
assert measurement use the envelope name.

**An envelope never derives a capability state.** The four selector values
(`diagnostic`, `core`, `lite`, `standard`) and the three capability states this
document publishes in §8 (`CORE`, `LITE`, `FULL`) are different kinds of thing,
and no mapping between them exists in either direction: `standard` and `FULL`
are not synonyms, and `diagnostic` has no capability-state counterpart. The
envelope and the capability state are separate published fields (§8), and a host
on `standard` may report `CORE`. [Capability model](capability-model.md) §1.1
holds the rule and its reasoning, which are not restated here.

Edge's `Full-eligible` belongs to the capability-state vocabulary and is
therefore absent from the table above.
[Inheritance ledger](inheritance-ledger.md) §4.3 records why Nexus keeps
`standard` and why the two must not be used interchangeably.

**Capacity is not topology and is not authority.** No envelope enables a
capability by itself.

## 3. Provider admission

A cognition provider is a local model runtime or a remote assistance endpoint.
A provider is *admitted* before it can be selected, never at first use.

Admission runs the ordered gates in
[contract ownership](contract-ownership.md) §4 and additionally requires:

| Requirement | Local model provider | Remote provider |
| --- | --- | --- |
| Signed asset with an exact tested compatibility tuple | required | required (client identity and endpoint metadata) |
| Declared format, tokenizer format, parser/runtime version, quantization, context size, memory need | required | not applicable |
| Resource envelope sufficient for the declared memory need, after the Core reserve | required | required for the client only |
| Commissioned egress path | not applicable | required |
| Privacy classes the provider is admitted to carry | not applicable | required, enumerated |
| Provider retention and region admission data | not applicable | required |

A provider that fails any gate is **not admitted**, and its absence degrades
capability without blocking anything deterministic. Model download or
verification failure MUST leave a working Core environment.

Admission is never inferred from availability: a reachable endpoint or a
present file is not an admitted provider.

## 4. Confinement

Model runtimes and remote clients run under dedicated accounts with:

- read-only access to their own assets, and to nothing else;
- no secrets, no control sockets, no host runtime sockets;
- no network by default for local models; egress-only to the admitted endpoint
  for the remote client;
- syscall and LSM confinement, and hard cgroup budgets for CPU, memory, PIDs,
  and I/O;
- no shell, no package manager, no general-purpose network tool.

Forbidden without exception: model-supplied code, dynamic loaders, native
plugins, pickle-like executable serialization, tool invocation, and any network
fetch during model load.

No cognition process has a path to the enforcement socket, the arbiter's
signing credential, the commissioning record, or the activation controller.
A provider that obtains one is a confinement failure, not a feature.

## 5. Route selection

The route is selected per request. Modes and their meaning are Edge-owned
doctrine ([M.I.O. dual cognition](mio-dual-cognition.md)); what follows is how
Nexus decides and bounds them.

Local-first is the default posture:

```text
deterministic no-model handoff   always available, never removed
        -> local M.I.O.          when a local provider is admitted and healthy
        -> remote assistance     optional; never required, never blocking
```

Inputs to the decision: mission policy, the request's privacy class, admitted
provider set, provider health, remote deadline budget, local resource headroom,
and incident severity. RAM is an input to *headroom* only.

Every request carries a correlation ID, a privacy class, a deadline, and an
expiry. A response that arrives after its expiry is discarded, not merged.

Budgets are declared, not discovered:

| Budget | Applies to |
| --- | --- |
| maximum request bytes | sanitized remote frame |
| maximum response bytes | remote response, enforced while reading |
| request rate and cumulative privacy budget | per mission and per class |
| deadline | per request; the earlier of the request deadline and the mission ceiling |
| concurrency | per provider, bounded by the resource envelope |

Exceeding a budget is a local fallback (§7), never a truncation that is passed
off as a complete answer.

## 6. Deterministic sanitizer

The sanitizer is the one-way egress boundary. Nexus requires it to be
**deterministic**: the same frame, the same policy version, and the same alias
key produce byte-identical output. A sanitizer that is not reproducible cannot
be audited, so non-determinism is a defect, not a tolerance.

Rules:

- allowlist by privacy class; anything unlisted is denied;
- ambiguous classification, invalid structure, or unavailable policy resolves
  to **deny remote egress** — deny-on-ambiguity is not a fallback, it is the
  default;
- identities are replaced by aliases that are deterministic **only within a
  declared mission or request scope**; the same subject in a different mission
  maps differently, and cross-mission correlation is prohibited;
- raw payloads, secrets, credentials, internal addressing, and exact location
  are removed, never transformed;
- a redaction record and request fingerprint are written locally; only the
  record *reference* travels in the frame;
- coarse time and count buckets replace exact timestamps and counts.

A remote response cannot request or trigger follow-up disclosure. Every
follow-up is a new, locally constructed, separately audited sanitized frame.

## 7. Fallback

Each of these converges to a safe local state. None blocks Edge, and none
escalates to a broader route:

| Trigger | Result |
| --- | --- |
| provider timeout or deadline expiry | return the local result unchanged; record the sanitized request fingerprint only |
| authentication or mTLS failure | provider unavailable; no retry with relaxed trust |
| stale or replayed response | discard; do not merge |
| response fails parsing, or exceeds its size budget | discard; render nothing from it |
| privacy-policy denial | no egress occurs at all |
| asset verification failure | provider not admitted; local or Core path only |
| resource pressure | shed remote work, then optional model work, then the local model — never capture, evidence, audit, or lease expiry |
| restart of any cognition service | resume at `CORE ONLY` and re-admit before rising |

A remote deadline expiry never queues data for later submission. Restricted
frames and sanitizer failures produce **zero** remote egress.

Loss of remote assistance returns the state to `LOCAL`. Loss of the local model
returns it to `CORE ONLY`, where deterministic explanations and the
deterministic voice alert continue unchanged.

## 8. Publishing capability state and its reasons

Nexus publishes the overall `FULL` / `LITE` / `CORE` summary **and** the
independent reason for each downgrade. A single summary state without reasons
is not sufficient: it hides which dimension failed.

| Published field | Content |
| --- | --- |
| summary state | `FULL`, `LITE`, or `CORE` |
| cognition state | `CORE ONLY`, `LOCAL`, or `HYBRID` |
| resource reason | envelope, headroom, active shedding step |
| topology reason | commissioned egress present or absent |
| asset reason | which provider assets are verified, rejected, or missing |
| trust/health reason | provider identity, manifest freshness, audit assurance |

Reasons are independent. A node may sit in `CORE ONLY` for an asset reason
while resource, topology, and trust are all nominal, and the operator surface
must show that rather than implying scarcity.

State changes are audit events. **A state change cannot change the Edge
authority boundary**, and no downgrade or restoration grants a new authority.
Restoration above the current state requires a passing health window and
re-admission; a restart alone never restores a provider.

Entryd records `mio.capability.transition` in the existing route audit chain
through `router._record`. Each event contains `from`, `to` (the existing
`CapabilityState` vocabulary), and `reasons`. The first observation has
`from: null`; thereafter a change to either state **or reasons** produces one
event, including reason changes while the summary remains CORE. Unchanged
observations append nothing. `MioEntryService.capability()` and the commissioned
profile reader are read-only; reconciliation owns all transition writes.

The current evidence sources cannot justify a rise above CORE. The verified
commissioning profile is a ceiling, recorded separately as `reasons.profile`
(`CORE`, `LITE`, `FULL`; absent/invalid verification selects CORE). It is never
an admission grant. Entryd independently reports these closed reason sets:

| Dimension | Codes / current evidence |
| --- | --- |
| resource | `core_reserve_unmeasured`: HG-05 reserve/headroom is not established |
| trust | existing `Evidence.NOT_CHECKED` code `not-checked`: remote trust is unchecked |
| health | separate `local` and `remote`: `unavailable`, `not_admitted`, `no_admission_evidence`, `invalid_observation`, from the existing bounded Unix socket probes |
| topology | `no_verified_egress`: entryd has no verified commissioned egress evidence |

Every dimension is evaluated even if another already requires CORE. Malformed
observations and reader failures become conservative fixed codes without parser
text; audit failures propagate. A socket refusal is availability evidence, never
provider admission, a passing health window, or verified topology. Installed RAM
is never used as a substitute for commissioning or measured headroom. No new
approval flag, privilege, unit-operation API, or environment bypass is added.
`LOCAL_MODEL_ADMISSION_ENABLED` stays false, the existing route admission gates
remain in force, and Edge authority is unchanged.

Reconciliation runs at startup and in the accept-loop stop predicate (including
idle loops), with a request-boundary check as well. Sampling and transition
writes are limited to **once per ten seconds**. Intermediate flaps are coalesced
to the next sampled observation; this is sampled state history, not an exhaustive
probe log. A failed append aborts the request/loop without advancing the
comparison basis. After verifying the chain at construction, entryd scans once
for its last transition, ignoring later unrelated route records. The comparison
basis and last event time survive restart in the ledger, so unchanged restart
observations do not duplicate events. The remaining sampling interval survives
restart too, using a monotonic timer in-process; a wall-clock rollback at
restart can delay sampling by at most ten seconds. Plain
status reads neither advance that timer nor mutate the comparison basis.

## 9. Audit visibility

Each of the following is individually audit-visible, with its correlation ID:

- the route decision and the inputs that produced it;
- the provider identity actually used;
- the sanitized request fingerprint and redaction record reference;
- response provenance per claim, including which provider and generation;
- material disagreement between sources, preserved rather than averaged;
- timeout, expiry, budget exhaustion, and every fallback taken;
- capability-state transitions with their per-dimension reasons.

The merger freezes a structured claim set — source, model, generation, input,
freshness, confidence, limitations — **before** any narrative text is produced.
Contradictions remain separate and replayable. A merged narrative is a
rendering of that claim set, never a substitute for it.

`azazel_nexus_runtime.mio_router.MioRouter` now owns the in-process route
execution boundary. It calls `route_audit.select_and_record` before dispatching
to `RemoteInferenceService.handle` or `LocalRuntimeService.handle`, with no new
network code. Its own `AuditLedger` lives at
`/var/lib/azazel/state/mio/route.jsonl` (under `AZAZEL_ROOT` in harnesses), separate
from auditd's chain and watchdog's chain. `az-mio-entryd` now composes this
owner with Unix socket adapters, retaining the separate provider accounts.
The router’s direct service defaults remain available to existing in-process
callers; the entry always supplies socket clients. Remoted retains its startup
refusal. Locald serves bounded refusals with production admission closed.

### Metadata-only entry daemon

`az-mio-entryd` takes no command-line arguments. Its `mio.route` verb accepts
only `privacy_class` (the existing PrivacyClass enumeration) and `deadline_ms`
(an ordinal bounded at 60,000 ms; zero is refused). It admits OPERATOR and
SERVICE; the entry’s service policy resolves only `azarbiter`. Prompt, body,
payload, caller identity, model, provider and path arguments are undeclared
and refused by the existing protocol.

The contract names are account `azmioentry`, socket leaf `mio-entry` at
`/var/lib/azazel/run/mio-entry/mio-entry.sock`, and state leaf `mio` at
`/var/lib/azazel/state/mio/route.jsonl`. Startup verifies the chain and proves
it can append a startup event before binding; it refuses a missing or
unwritable installer-owned ledger leaf. The shared `serve_forever` accept
loop, kernel-derived `PrincipalPolicy` and systemd readiness callback apply.

Before selecting, the entry records bounded availability observations from
locald (`mio`) and remoted (`remote`). The fixed probes use uncommissioned
identifiers, carry no payload and never confer admission. They authenticate
socket ownership/group and server peer UID, use the existing length-prefixed
framing and EOF rule, and each have a 500 ms I/O budget. These probe budgets
are separate from the route’s `deadline_ms`, which bounds selection inputs;
this verb performs no inference. Absent accounts or sockets, refused
connections, explicit refusals, invalid responses and deadlines become fixed
unavailable/refusal reason codes. Provider reply text is discarded.

Selection reads the existing operator-signed full commissioning proposal through
`mio_commissioning.commissioned_profile`. The Nexus v2 wrapper includes the
explicit CORE / LITE / FULL ceiling, mapped to `core` / `local-only` /
`fastest-permitted` route profiles; it changes no Edge authority. The existing
`commissioning-proposal` signature must cover the entire wrapper and match the
independently retained expected copy and current node/operator trust. A v1
proposal, absent/unreadable input, unknown value, invalid signature or lab host
selects CORE. RAM never substitutes for that selection.

The entry unit uses a private [systemd credential snapshot](https://www.freedesktop.org/software/systemd/man/257/systemd.exec.html#Credentials).
This setup requires directory-source support for `LoadCredential`; the target
is Debian 13 with systemd 257, which supports it. The directory source is exactly
`/etc/azazel/mio-profile/`, never
`/etc/azazel/commissioning/`. Installation and tmpfiles always create this
root:root 0700 directory, even when empty. Retention atomically publishes only
`commissioning-proposal.expected.json` and `commissioning-proposal.json` there;
a successful `az-nexus-commission proposal-review --operator LABEL` publishes
`commissioning-proposal.sig` after verification and input rechecks. Source files
are root-owned 0600. Do not place other files in this directory: systemd copies
all its contents. Raw role drafts, commissioning records, active records and
protection keys remain outside it.

Two individual credentials supply `/etc/azazel/node.yaml` as `mio-node` and
`/etc/azazel/operator-trust/operators.json` as `mio-trust`. The latter contains
only enrolled public keys and revocations, never private signing keys. Provision
these through the existing administrator setup without widening their source
permissions. Empty `SetCredential` defaults let missing node/trust sources
produce CORE. The proposal directory must exist and be readable by systemd;
if it is removed or unreadable, credential setup can fail before entryd starts.
An empty installed directory starts with CORE.

The five credential copies are read-only 0400, owned by `azmioentry`; proposal
names are prefixed `mio-profile_`. The reader uses the fixed system-unit
credential directory, with no environment path override. All five exact byte
strings are hashed on each read; YAML parsing, trust decoding, proposal rebuild
and signature verification are cached until any bytes change. Unexpected reader
exceptions also yield CORE. Without the optional Fabric extra verification yields
CORE. Proposal, node and public-trust snapshots refresh on every entryd restart;
**revocations take effect at the next entryd restart**, not during an existing
snapshot's lifetime. Restart entryd through the existing operational procedure
after any trust change. This historical ceiling supplies no activation,
current-hardware or provider-admission evidence.
Remote admission is computed by `remote_trust.remote_admission` with
`unchecked_reading()`, no opt-in and no sanitised frame. Local admission is
always false with the explicit HG-05 unmeasured Core reserve reason, and
predictions are empty. Even reachable provider sockets cannot lift these
gates. The router consequently records deterministic handoff and refusal,
with each candidate’s reason, and replies with `route`, `outcome`, `reason`
and `ledger_seq`. No handoff claims an advisory answer or changes Edge
authority.

The shared `runtime_paths` declares socket leaves `mio-entry`, `mio` and
`remote`; unit/account/layout/script declarations use the same contract.
Entry tests exercise those shared helpers under `AZAZEL_ROOT`. Entry routing
does not consult `knowledge.status`; Knowledge availability is independent.
Linux-only tests exercise a real entry socket exchange and a fake locald
returning “not admitted”, then verify and read back the route chain. On macOS
those SO_PEERCRED tests are skipped; they do not establish Linux runtime
execution on that runner.

The chain records candidate dispositions and reasons, verified envelope
provenance/fingerprint, structured refusal reasons (including content, provider
and policy revision mismatch), transport counts/reasons, response digest and
terminal outcomes. The optional `audit` callback on remote `handle` defaults to
`None`, preserving direct callers' behavior. The router supplies its ledger
callback; audit exceptions propagate and stop further dispatch. In particular,
a selection append failure dispatches nothing, and an envelope audit failure
prevents transport. Transport outcomes are appended before reply classification.
No prompt, request body, response text or credential is copied into these events.

Timeout maps to `TIMED_OUT`, TLS failure to `TLS_FAILED`, envelope refusals to
`SANITIZER_FAILED`, rejected advice to `NOT_ADVICE`, and validated advisory to
`ANSWERED`. Other failures map to `FAILED`. Exact mismatch/refusal reasons remain
separate records. Only a `FELL_BACK` outcome records a `fallback_once` decision, once,
before dispatching its target from the original permitted set. A sanitizer
refusal ends the attempt without fallback, as required by `outcome_for`.
Local replies currently report readiness only: `ready` ends with
`local_ready_no_answer` / `REFUSED`, `fallback_available=False`, and no remote
call. An unassessed local route also ends without fallback. Only a real local
readiness refusal permits one fallback within the original permitted set; its
audit reason includes the local refusal that caused it. Malformed remote payloads
record only the fixed `malformed_payload` reason, never parser exception text.
A second failure ends without retry. Deterministic handoff reports no advisory
answer (`FAILED` / `REFUSED`); entry may subsequently fetch the deterministic
playbook reference described below. Edge continues.

This is software evidence for route audit production, not evidence of deployed
M.I.O. inference or the whole audit list above. Per-claim response provenance,
material source disagreement, redaction references, request-wide correlation
IDs still require their respective producers. The
current chain preserves envelope provenance and exact mismatch reasons; it does
not claim to implement a claim merger.

Remote text renders as inert content: no tool calls, no automatically followed
links, no instruction treated as a command.

## 10. What this document does not establish

Issue [#5](https://github.com/01rabbit/Azazel-Nexus/issues/5) states runtime
acceptance criteria — an 8 GiB system operating Core, gates passing
independently at 16 and 32 GiB, a remote provider never called outside its
admitted privacy classes, convergence under timeout and restart, and tests
proving a provider output cannot alter an Edge decision.

**None of those criteria is met by this document, and none can be checked off
until the following exist:**

1. repository bootstrap — package layout, dependency manifest, CI
   ([contract ownership](contract-ownership.md) §6, [roadmap](roadmap.md)
   Phase 0);
2. an exact Azazel-Fabric pin;
3. Fabric `mio_contracts`, which is **not released** — the remote frame and
   advisory result have no canonical shape yet, so the remote path cannot be
   implemented against a contract;
4. a test harness capable of resource, timeout, restart, and failure injection.

This document specifies the control plane so that implementation has something
to be measured against. It is not evidence that the control plane exists.


### What an operator receives today

While local model admission is closed (`LOCAL_MODEL_ADMISSION_ENABLED = False`,
and no admitted evidence), entryd's routing never selects LOCAL. A `mio.advise`
frame that passes the entry checks still returns `route: deterministic handoff`
and `outcome: refused`. After that decision, entryd requests a deterministic
playbook reference from locald via `mio.local.reference`. A validated result is
attached under `reference`, with `banner`, trusted `fields` and machine metadata;
it is never attached as `advice` or counted as an advisory answer. Keyword banners
identify deterministic matching and contain no model wording. Unreviewed
playbooks retain the template notice.

The reference exchange has its own fixed 500 ms ceiling, independent of routing
and model admission. It uses keyword matching only: no embedding, explanation,
Knowledge lookup or model startup. Locald's SERVICE policy admits only
`azmioentry` to this verb. Entry and its socket client independently validate the
reference schema, keyword provenance and trusted explanation source. Absent,
slow, refused or malformed locald replies leave the handoff intact, omit
`reference` and set `reference_status: unavailable`; the reply's routing reason
is kept. Route, outcome
and route-ledger decision bytes do not depend on reference availability. The
insufficient-information gate retains its fixed response; out-of-scope frames
receive no reference. No reference grants Edge authority or provider admission.

No operator-facing client for `mio.advise` ships yet: the verb is reachable over
the entry socket with the runtime's length-prefixed protocol. An operator Unix
account needs `azazel-operator` as its primary group, or as a supplementary
group (`usermod -aG azazel-operator <user>`) once the runtime reads Linux
supplementary groups from the peer (a fix found by the same rehearsal). Daemon
accounts that carry the group for socket access are never classified as
operators.

### Local advisory payload path (Milestone 3)

`mio.route` remains metadata only. `mio.advise` accepts a separate JSON
`event` payload containing exactly `request_id`, `privacy_class`, `question`
and `context` (a list of `{kind, text}` objects). Its only argument is
`deadline_ms` (1–60,000). Entry admits OPERATOR and SERVICE, with the service
policy restricted to `azarbiter`. Situation frames are at most 32 KiB of
UTF-8 JSON, with at most 16 context items and 4 KiB per text value. Request
IDs use the existing identifier grammar; context kinds use bounded lower-case
identifiers. Unknown keys and malformed values are refused.

On a permitted, predicted LOCAL selection, the router sends the frame to
`mio.local.infer`, authenticating the `azmio` socket owner and peer. Locald's
service policy resolves only `azmioentry`; its inference verb admits SERVICE
only. The transport uses the existing length prefix and `event` payload slot,
with a bounded I/O deadline supplied from `deadline_ms`. Local model and
runtime IDs are supplied by trusted composition, never by this payload.

The prompt requests JSON `{advice, fields}` and advice only. Output passes
through `read_local_advisory`, reusing the remote advisory reader's bounds
and instruction refusals. The reply carries advice and fields for display;
`mio.local.request`, `mio.local.advisory.read` and `mio.local.refused` events
contain only digests, counts, lengths and fixed refusal codes. Locald keeps
its own `local.jsonl` ledger beside entry's `route.jsonl`. Neither stores
situation or response text. Terminal route events distinguish ANSWERED,
NOT_ADVICE, TIMED_OUT and FAILED, using the existing one-fallback rule and
privacy restrictions.

Production still has CORE as its default profile, no local admission, no
prediction evidence, an unmeasured HG-05 reserve and a pinned runtime with closed admission
allowlist. Trusted harnesses can inject admission, predictions and a fake
server to exercise the path. Availability probes never change these gates;
the new verbs do not commission a model or alter Edge authority.


### Optional local Knowledge context

After admitted local retrieval, locald passes `deadline_s` to the Knowledge
client: the remaining request budget minus `DELIVERY_RESERVE_S` (20 ms for
bounded validation, audit and delivery) and `PIPELINE_RESERVE_S` (50 ms for the
deterministic selection that follows), capped at `KNOWLEDGE_MAX_S` (250 ms). A
nonpositive budget skips lookup with `skipped_budget_exhausted`. The client uses
one monotonic transport deadline across connect, send and receive, without
retries. A silent, unavailable or defective Knowledge service contributes no
context (`unavailable`) and costs at most the cap: playbook advice is still
delivered, though a tight budget may lose the optional model explanation.

Usable references are returned separately under `knowledge`, with
`source_kind: knowledge_lite`, verified bundle `generation`, `freshness`
(`current` or `static`), `trust_check: verified`, and the existing citation
fields. Both socket client and delivery reader validate this bounded schema; entryd
relays the optional `knowledge` key, and the deterministic handoff reference
(`read_reference`) still rejects it. References are dropped from the end
rather than letting them push a valid advisory over the 48 KiB delivered
bound, and the prompt's reference message is capped separately, so the list
may name references the model did not see. Provenance rests on the
`KnowledgeRef` type produced after verification and the peer-authenticated
socket; offline evaluation fixtures are never delivered.
Trust results describe the lookup's existing signature/revocation checks, not
an approval. Expired indicators remain withheld by the existing serving filter;
static reference material remains available. Verified Knowledge enters the
explanation prompt only through the trusted reference message, as before; it
never selects the candidate or reaches an authority decision, and model output
is still validated field by field. Situation quotes remain in
`fields.cited_facts`, separate from model explanation fields.
These are software contracts and unit-test results, not hardware evidence.
