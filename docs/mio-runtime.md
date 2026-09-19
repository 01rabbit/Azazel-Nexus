# M.I.O. Runtime Control Plane

Status: **target contract**. This document specifies the Nexus-owned runtime
control plane for M.I.O. No part of it is implemented in this repository.

Related: [M.I.O. dual cognition doctrine](mio-dual-cognition.md) (Edge-owned
semantics) · [Capability model](capability-model.md) ·
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
Three vocabularies exist for the same four envelopes; they are synonyms only
where this table says so, and must not be multiplied further.

| Usable RAM (MiB, after firmware reservation) | Nexus envelope name | Eligibility phrasing |
| --- | --- | --- |
| `< 7168` | `diagnostic` | diagnostics only |
| `7168` – `15359` | `core` | Core |
| `15360` – `31743` | `lite` | "Lite-capable" |
| `>= 31744` | `standard` | "Full-capable" / Edge's "Full-eligible" |

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
