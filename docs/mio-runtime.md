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
network code. Its own route chain lives in daily segments under
`/var/lib/azazel/state/mio/route/` (under `AZAZEL_ROOT` in harnesses), separate
from auditd's chain and watchdog's chain; see *Route ledger segments and
retention* below. `az-mio-entryd` now composes this
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
`/var/lib/azazel/state/mio/` with route segments in `route/`. Startup verifies
the retained chain and proves it can append a startup event before binding; it
refuses a missing or unwritable installer-owned state leaf. The shared
`serve_forever` accept loop, kernel-derived `PrincipalPolicy` and systemd
readiness callback apply.

### Route ledger segments and retention

The route ledger was one `route.jsonl`, verified in full at every start and
grown by about 20 MB a day at the explainer's six `mio.advise` a minute, so
start-up time grew with the node's age toward the unit's start timeout
(#211 S4). It is now `route/YYYY-MM-DD.jsonl` (UTC day, `0600`, directory
`0700 azmioentry`), one `AuditLedger` chain through all segments: a segment's
first entry chains onto the last hash of the previous segment, so a deleted,
reordered or edited segment is a break. The reader is
`azazel_nexus.route_ledger.RouteChain`; the writer is
`azazel_nexus_runtime.mio_route_ledger.RouteLedger`, which reuses the
explainer's and intake's `DailySegments` rotation, ageing and clock guards.

- **Bounds.** 46 MiB per segment, 192 MiB in total and 14 days. Retention
  deletes whole oldest segments only and never the newest or current one, so
  today's segment survives any total-size pressure.
- **Per-caller shares.** Each day's segment is divided into budgets that no
  other caller can spend: 28 MiB for the explainer (`azexplain`; its six
  advice requests a minute write about 20 MB a day), 4 MiB for the arbiter
  (`azarbiter`), 4 MiB for each other kernel-reported UID (operators, root)
  within a 12 MiB pool for all of them together, and a 2 MiB control reserve
  for start and capability records. The arbiter's share is outside the pool,
  so operators that spend the whole pool cannot refuse the arbiter's
  `mio.route` (#227). A request is admitted only with 64 KiB left in its caller's share;
  otherwise it is refused with `rate_limited` (detail `route_budget`) until
  the next UTC day. A flooding caller therefore exhausts only its own share:
  at the 30-a-minute rate limit one caller would write about 100 MB a day,
  which the share, not the rate limit, stops at 4 MiB. Each request's records
  open with a small `mio.entry.request` record naming whose share they are
  charged to (`explainer`, `arbiter` or `uid:N`), so a restart recounts
  today's shares from today's segment rather than forgetting them. A segment
  written before the arbiter had its own share counts the arbiter's records
  of that day in the pool.
- **Boundary.** Before deleting a segment, the writer durably replaces
  `route/retained-boundary.json` with the deleted segment's last sequence and
  hash, the oldest retained segment and the retired name. Verification starts
  there instead of at genesis. A crash between that write and the unlink
  leaves a segment the boundary already retired; readers ignore it and the
  next start removes it. Removing the boundary, or the oldest retained
  segment, is a break.
- **Bounded start.** Start-up verifies only the retained segments, in one pass
  that also restores the last capability reading, plus one read of today's
  segment to recount the shares: at most 192 MiB plus the current segment,
  whatever the node's age. Each new segment opens with a
  `mio.capability.carried` record, so retention never removes the last
  recorded observation that `azazel-nexus status` shows. It is not a
  transition and not a new observation: it repeats the reading before it
  together with that reading's original time in `observed_at` (its own
  `occurred_at` is only when it was carried). Status and entryd's restore show
  and use `observed_at`, so a reading restored after a restart or a day
  boundary is never presented as fresher than it is. A carried record that
  differs from the reading it carries (state, reasons or `observed_at`) is a
  rewritten history: entryd refuses to start and status reads unknown. The
  reading a carried record repeats is the ledger's last capability record:
  entryd remembers a capability record as soon as the segment holds it, even
  when a later step of that append (the directory sync or retention) fails,
  so such a failure cannot make the next carried record differ from the
  transition before it (#227). A record counts as held only when the
  segment's last line has its sequence and hash; when the segment cannot be
  read to tell, entryd re-reads the chain's last capability record before it
  compares the next sample or writes a carried record, and writes neither
  while that read fails. What a read shows is the page cache, so after a
  failed fsync this follows what the running node and its next start see,
  not what a power loss would keep. A segment opens, and gets its carried record,
  whenever it holds no record yet, so an empty segment left by a crash right
  after it was created still opens with one.
- **Migration.** On first start after upgrade, a pre-segment
  `state/mio/route.jsonl` is moved aside in bounded time: only its last
  record is read (from the end of the file), the boundary is written durably
  at that head and marked `legacy_unverified` with the head and the file's
  size, and the unchanged file is renamed to `route/legacy-route.jsonl`
  (`0400`). Start-up never reads the whole legacy file, so a node that ran the
  single file for months starts as fast as a new one. The first segment
  continues its chain (its first entry follows the legacy head). Full
  verification of the archive is offline:
  `python3 -m azazel_nexus.route_ledger` (as root) verifies the retained
  segments and the archive in full against the recorded head and size, and
  the lab `audit` does the same. Retention never deletes the archive; removing
  it after export is the owner's decision. A legacy file whose last record is
  unreadable is refused and left in place; a legacy file found beside an
  existing segment chain is refused; a crash between the boundary and the
  rename is finished by the next start. Until entryd has migrated,
  `azazel-nexus status` still reads the single file.
- **Per-principal rate.** Entryd admits at most 30 requests a minute per
  kernel-reported UID, with a burst of 10, before anything is written. Over
  the limit it replies `rate_limited` (detail `principal_rate`). The rate
  bounds bursts; the shares above bound daily growth.
- **Refusal records.** Every refusal the transport reports, whatever its
  reason (`rate_limited`, `principal_denied`, `malformed_frame`, ...), is
  recorded at most once a minute per UID, carrying the counts by reason
  suppressed since and the in-memory refusal counters (entryd has no status
  surface), and is charged to that caller's share. A refusal record that no
  longer fits is counted, not fatal: the refused request did nothing. The
  suppressed counts it would have carried are kept for that caller's next
  refusal record rather than dropped, so the counts are "at least": a record
  whose line landed although its write reported failure is counted again in
  the next one.
- **Clock.** Segments are named by the UTC wall-clock day, held by the same
  guards as the intake and explainer stores. A node without an RTC boots with
  its clock behind; until time sync steps it forward, records go into the
  segment for that earlier day, and a forward step within the first 15 minutes
  of uptime is followed rather than held. A backward step never writes before
  the newest segment (records continue in it), and a forward jump during a run
  cannot age the ledger out: ageing follows elapsed time. A segment dated
  ahead of the clock keeps receiving records until the clock passes it, which
  can make one segment hold more than a day; its shares still apply.
- **Capacity on `/var/lib`.** The route ledger uses at most about 238 MiB
  (192 MiB retained plus one 46 MiB current segment), **plus** the
  `legacy-route.jsonl` archive on a node upgraded from the single file: its
  size is whatever `route.jsonl` had reached (about 20 MB for each day the
  integrated loop ran), recorded in the boundary, and it stays until the
  owner removes it. One caller at its rate limit spends its 4 MiB share in
  well under an hour and then waits for the next day; the disk does not
  grow.

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
The proposal carries raw identity (board serial, storage serials and models,
permanent MACs), which [inventory confidentiality](inventory-confidentiality.md)
§3 allows only in the encrypted commissioning record, so it is never copied out
of it. The Ed25519 signature covers the whole payload, and the verifier rebuilds
the payload from the retained inventory, so no digest or identity-free subset
could be verified instead. The unit therefore loads exactly five individual
files, no directory:

| credential | source |
| --- | --- |
| `mio-profile_commissioning-proposal.expected.json` | `/etc/azazel/commissioning/commissioning-proposal.expected.json` |
| `mio-profile_commissioning-proposal.json` | `/etc/azazel/commissioning/commissioning-proposal.json` |
| `mio-profile_commissioning-proposal.sig` | `/etc/azazel/mio-profile/commissioning-proposal.sig` |
| `mio-trust` | `/etc/azazel/operator-trust/operators.json` |
| `mio-node` | `/etc/azazel/node.yaml` |

The two proposal files are read in place on the encrypted volume; no other file
there (role drafts, commissioning records, active records) and no protection key
is loaded. Installation and tmpfiles always create `/etc/azazel/mio-profile/`
as root:root 0700, even when empty. A successful
`az-nexus-commission proposal-review --operator LABEL` publishes only the 64-byte
`commissioning-proposal.sig` there, atomically and create-only, after
verification and input rechecks; the signature holds no identity and pins the
reviewed proposal bytes exactly, so an unreviewed or later-changed proposal does
not verify. Source files are root-owned 0600.

Every credential has a `SetCredential=ID:absent` fallback. entryd is ordered
after `azazel-activated.service`, which is ordered after
`etc-azazel-commissioning.mount` ([commissioning storage at boot](commissioning-storage-at-boot.md));
a volume that is locked or not mounted when entryd starts leaves an empty mount
point, the two proposal credentials become `absent`, and the reader selects CORE
without verifying. After unlocking, restart entryd to pick up the proposal.

entryd does not itself check that the source is LUKS-backed or that it is an
ordinary file: systemd reads the source before entryd runs. The directory is
`root:azcommission 0750` on the mounted volume and as the bare mount point
(`packaging/install.sh`, [commissioning rehearsal](hil-runbooks/commissioning-rehearsal.md)
§3); the group gets read and search only, and the commissioning tools refuse a
group- or other-writable directory, so only root can create or replace entries
at the two fixed names. Whatever is placed there still has to verify against
the reviewed signature in the root-only `/etc/azazel/mio-profile/`, which pins
the payload exactly, so it can never select more than CORE. What it can do is
stop entryd from starting: a fixed name that is a symlink to a device such as
`/dev/zero` fails credential setup with 243/CREDENTIALS instead of using the
fallback. That is an availability effect on entryd only (no routing handoffs,
Edge unaffected), recovered by removing the entry. Granting the group write on
that directory, or any other write path into it, would widen this to the
grantee. No reader-side check can sit in front of `LoadCredential`, so this is
documented rather than mitigated.

Mechanism check on a Debian 13 aarch64 VM with systemd 257, using a throwaway
unit with `LoadCredential=probe:<path under a mount>/file`,
`SetCredential=probe:absent` and `After=` the mount (a mechanics check, not
hardware evidence): `After=` adds no implicit `Requires=`, `Wants=` or
`RequiresMountsFor=`; with the mount inactive and the file absent the unit
starts and the credential is `absent`; a symlink to `/dev/zero` fails the start
with 243/CREDENTIALS without the fallback; a symlink to an ordinary file is
followed; a directory at the name is loaded as a directory.

**Migration from earlier releases (#244).** Earlier releases also published
`commissioning-proposal.expected.json` and `commissioning-proposal.json` into
`/etc/azazel/mio-profile/`, in plain bytes outside the encrypted volume. entryd
no longer loads them. `packaging/install.sh` runs
`tools/purge_mio_profile_copies.py` on every install, which removes exactly those
two names and any temporary file a crashed publication left (`.proposal-` and
32 lowercase hex digits), only as ordinary files, inside that directory opened
without following a symlink and required, as review requires, to be owned by
root with mode 0700; the signature and any other file are kept. A symlink or
other object at a matching name, a symlinked directory or a different owner or
mode refuses the whole step and the install, with nothing removed, for
administrator inspection. The installer then stops right after creating the
accounts and the `/etc/azazel`, `/etc/azazel/commissioning` and
`/etc/azazel/mio-profile` directories: no other directory, unit file, preset or
tmpfiles rule is updated, so an upgraded node keeps its previous units, whose
entryd still loads the old copies, until the entry is fixed and the install is
rerun. On a node not upgraded through the installer, run as root from the
reviewed checkout:

```sh
sudo python3 -I tools/purge_mio_profile_copies.py /etc/azazel/mio-profile
sudo ls -la /etc/azazel/mio-profile   # expect at most commissioning-proposal.sig
```

Deleting a file does not scrub the blocks it used on the unencrypted file
system; where that matters, treat the old copies under the node's storage
disposal procedure. The proposal and its signature on the encrypted volume are
unchanged, so no re-commissioning or re-review is needed; restart entryd so it
loads from the new sources.

Two individual credentials supply `/etc/azazel/node.yaml` as `mio-node` and
`/etc/azazel/operator-trust/operators.json` as `mio-trust`. The latter contains
only enrolled public keys and revocations, never private signing keys. Provision
these through the existing administrator setup without widening their source
permissions. The `SetCredential=ID:absent` lines are the fallbacks when a source file is
missing; the reader treats the value `absent` in any of the five as no source
and yields CORE. (systemd 257 drops an empty `SetCredential=ID:` line as invalid
syntax, so an empty fallback would leave entryd unable to start,
243/CREDENTIALS, rather than CORE.) A node without a reviewed signature starts
with CORE.

The five credential copies are read-only (observed on systemd 257: root:root
0440 with an ACL granting `azmioentry` read); proposal
names keep the `mio-profile_` prefix of the earlier directory source. They live
in the unit's credential directory in memory, never on persistent storage. The reader uses the fixed system-unit
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
A local readiness reply that is not a refusal (`ready`, unassessed) records
`local_ready_no_answer` (or the unassessed reason) as `NO_ANSWER` / `REFUSED` with
`fallback_available=False` and no remote call. Only a real local readiness
refusal permits one fallback within the original permitted set; its audit reason
includes the local refusal that caused it. Malformed remote payloads record only
the fixed `malformed_payload` reason, never parser exception text.

**One deadline per request** (implemented; software evidence only). Entry
measures the request's deadline once, on the monotonic clock, when the request
arrives, and passes it to the router (`deadline_at`). Selection compares
predictions with what is left of it, not with the caller's original budget. Each
AI attempt receives the remaining time minus `HANDOFF_RESERVE_MS` (50 ms, kept for
the terminal step); the fallback never receives a fresh copy of the original
`deadline_ms`. An AI attempt is not started when less than `MIN_AI_ATTEMPT_MS`
(100 ms) would be left for it; that records `mio.route.not_started` with
`deadline_budget_insufficient`. A reply that arrives at or after the deadline is
discarded (`mio.route.late_reply`) and classified `TIMED_OUT`, never `ANSWERED`.
Both constants are software budgets, not measured hardware latency. The remote
transport keeps its own commissioned deadline; the router bounds it from outside
(not started without room, discarded when late) because the remote verb carries
no deadline argument.

**A deterministic terminal step** (implemented). At most two AI attempts are made
(`MAX_AI_ATTEMPTS`): the selected route and the one fallback from the original
permitted set, never the provider that failed and never a route the selection did
not permit. Every request that no AI answered — a second failure, a sanitiser
refusal, a no-answer readiness, an insufficient budget, or a selection that chose
the handoff — ends in the deterministic handoff. The router records
`mio.route.handoff` with the cause (`selected`, `fallback`,
`no_permitted_fallback`, `ai_attempts_ended`, `ai_attempts_exhausted`,
`deadline_budget_insufficient`), the number of AI attempts and one bounded entry
per failed attempt (route, terminal event, fixed refusal word), then the handoff's
own terminal record (`FAILED` / `REFUSED`: no advisory answer). The terminal step
calls no AI and needs nothing from Edge: Edge detection, decisions and evidence are
not inputs of this path. Entry then fetches the playbook reference described below.
Edge continues.

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
and `outcome: refused`. After that decision, entryd asks the model-free reference
service (`azazel-mio-referenced.service`, verb `mio.reference`) for a deterministic
playbook reference. That service is separate from the model host
`azazel-mio-locald.service`: it runs no model, holds no model path, imports no
runtime, admission, embedding or Knowledge code, and needs no
`local_model_provider` wiring, so a CORE node with no admitted model can still
serve verified playbook text. The model host's wiring gate and admission are
unchanged; the reference service neither needs nor satisfies them.

Every handoff reply to `mio.advise` carries a `handoff` object with a fixed
`kind`, a fixed `notice` (English or Japanese, by the question's language) that
states that no AI answered and that Edge's deterministic control plane keeps
decision and enforcement authority, `ai_attempts` (0–2) and the bounded
`failures` of those attempts. Then exactly one of:

- `reference_status: attached` and `reference` (`kind:
  deterministic_reference`): `banner`, trusted `fields` and machine metadata from
  verified playbooks. It is never attached as `advice` or counted as an advisory
  answer. Keyword banners identify deterministic matching and contain no model
  wording; unreviewed playbooks retain the template notice.
- `reference_status: unavailable` and `reference_reason` (`kind:
  deterministic_notice`): a fixed word for why there is no reference — the
  playbook selection's reason (`no_pack`, `store_unreadable`, `pack_degraded`,
  `asset_missing`, `digest_mismatch`, `invalid_library`, `none_selected`,
  `multiple_baselines`), the request's (`out_of_scope`, `insufficient_information`,
  `no_matching_playbook`, `malformed_frame`, `invalid_deadline`, `deadline`), or
  the exchange's (`reference_service_unavailable`, `reference_refused`).

The reference exchange takes what is left of the request's one deadline, capped
at 500 ms; it is not started with no time left, and a document that arrives at or
after the deadline is discarded. It uses keyword matching only: no embedding,
explanation, Knowledge lookup or model startup. The reference service's SERVICE
policy admits only `azmioentry`. Entry and its socket client independently
validate the reference schema, keyword provenance and trusted explanation source.
Absent, slow, refused or malformed reference replies leave the handoff intact and
name their reason; the reply's routing reason is kept. Route and outcome do not
depend on reference availability. The insufficient-information gate retains its
fixed response. No reference grants Edge authority or provider admission.

Evidence: `tests/unit/test_mio_reference.py` (in-process, mocks),
`tests/unit/test_mio_reference_socket.py` (real daemons over real `SO_PEERCRED`
sockets with a test-signed, activated Mission Pack, plus the activation library's
grant decision with nothing wired), `tests/unit/test_mio_router_deadline.py`
(injected monotonic clock). None of it is systemd, hardware or HG-05 evidence.

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
its own `local.jsonl` ledger, separate from entry's route segments. Neither stores
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
