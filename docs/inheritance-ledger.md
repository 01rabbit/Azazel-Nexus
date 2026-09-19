# Edge-to-Nexus Inheritance Ledger

Status: **target contract**. This ledger records what Azazel-Nexus intends to
inherit and on what evidence. It is not a claim that any entry is implemented
in this repository, which still has no package, pin, or CI.

Related: [Contract ownership](contract-ownership.md) ·
[Capability model](capability-model.md) · [Commissioning](commissioning.md) ·
[Azazel-Nexus #7](https://github.com/01rabbit/Azazel-Nexus/issues/7)

Audit date: 2026-09-19. Facts below were read from the `main` branch of each
repository and from the linked issues on that date. Re-audit before citing.

## 1. Product relationship

Azazel-Nexus is the successor **integration** product for validated Azazel-Edge
concepts. Azazel-Edge is **not** obsolete and is not being replaced:

| | Azazel-Edge (AZ-01) | Azazel-Nexus (AZ-07) |
| --- | --- | --- |
| Role | lightweight deterministic reference core; bounded concept and Pi-class proving ground | rugged x86_64 integration product |
| Owns | evidence, arbiter, audit semantics, M.I.O. cognitive contracts, no-model fallback | commissioning, resource profiles, provider/model lifecycle, Mission Packs, embedded Lite runtimes, recovery, integrated HIL |
| Hardware | constrained devices, Raspberry Pi class | generic rugged x86_64 |

Neither product changes the authority rule. Edge-derived deterministic
arbitration is the only decision and enforcement authority. M.I.O., Knowledge,
Deception, installers, user interfaces, and remote services are advisory,
materialization, or support planes in both products.

## 2. Inheritance rules

1. Nexus consumes **versioned** Edge and Fabric contracts and validated
   reference behavior. It MUST NOT copy a legacy installer, a hard-coded
   interface default, or historical UI vocabulary as an implicit product
   contract.
2. New work begins **in Nexus** when it concerns rugged x86_64 deployment,
   provider/model lifecycle, Mission Packs, embedded or full optional nodes,
   topology commissioning, or integrated HIL.
3. New work begins **in Edge** when it concerns a small-footprint
   deterministic-core change or a bounded concept experiment. An Edge
   experiment becomes a Nexus capability only after its contract, authority
   boundary, failure behavior, test evidence, and rollback/recovery behavior
   are explicit.
4. A backport from Nexus to Edge requires an **explicit new Edge issue** naming
   the minimal reference-core benefit, with a compatibility and evidence
   record. A closed historical Edge issue MUST NOT be reopened as a shortcut,
   and MUST NOT be used as the entry point for implementation.
5. Every adopted capability records: source contract and version, authority
   boundary, resource/topology/trust/health gates, degradation behavior, test
   evidence, and rollback/recovery behavior.
6. An advisory result never becomes authority by passing through this ledger.

## 3. Classification vocabulary

| Class | Meaning |
| --- | --- |
| `reference-core` | Edge behavior consumed by Nexus without semantic change |
| `integrated` | Nexus-owned deployment or operational integration of an Edge/Fabric contract |
| `experimental` | concept or HIL work; **not eligible for a production claim** |
| `rejected` / `retired` | not inherited; rationale and successor recorded |

These compose with the series status terms (`target contract`, `implemented`,
`verified`, `supported`, `experimental`, `retired`). A capability can be
`reference-core` in class and still only `implemented` in status — that is the
normal case today, and it is why no entry below is marked `verified`.

## 4. Observed Edge state

Read from `01rabbit/Azazel-Edge` `main` on the audit date.

| Observation | Value |
| --- | --- |
| M.I.O. implementation | `py/azazel_edge/mio/` — `broker`, `contracts`, `evaluation`, `frame_builder`, `grounding`, `model_adapter`, `playbook`, `reasoning`, `replay`, `resource_profile`, `trace` |
| Outcome-as-Evidence implementation | `py/azazel_edge/outcome/` — `adapter`, `assessment`, `contracts`, `observer`, `ownership`, `postcondition`, `release_evidence`, `replay`, `shared_export`, `telemetry` |
| Fabric pin | `requirements/fabric.txt` pins the exact tag `v0.8.0` (git tag, never a branch) |
| x86_64 integration boundary | `docs/X86_64_INTEGRATION_BOUNDARY.md`, status "R0 target contract; implementation evidence pending" |
| Fabric dependency nature | **optional integration extra** — the file states baseline Edge behavior is unchanged without it |
| Device-specific installer | `installer/` exists and is Edge-owned |

### 4.1 The Fabric dependency is not inherited unchanged

Edge treats Fabric as an optional extra. Nexus cannot: integration across
products *is* the Nexus product, so Nexus requires a Fabric pin as a hard
dependency. The **pin policy** is inherited (an exact tag, never a branch or a
development commit); the **optionality** is not. Nexus has no pin yet; adopting
one is Phase 0 work in the [roadmap](roadmap.md).

### 4.2 Open: Edge has two decision/enforcement paths

Azazel-Edge currently contains two independent paths that can select and apply
a defensive action:

- `rust/azazel-edge-core/src/main.rs` — `decide_defense()`, `maybe_enforce()`,
  `build_enforcement_plan()`, `run_command()`;
- `py/azazel_edge/arbiter/action.py` — `ActionArbiter`.

Edge issue [#400](https://github.com/01rabbit/Azazel-Edge/issues/400) states
this explicitly and concludes that the Python `ActionArbiter` "MUST NOT be
documented as the sole live execution truth until the wiring is explicitly
proven/unified".

**Consequence for Nexus.** The Nexus
[implementation specification](IMPLEMENTATION_SPEC.md) §1 and §4 require a
single arbiter service to be the sole intent issuer. That is a Nexus
requirement and remains correct as a target contract, but it is **a condition
Nexus places on the Edge package it consumes, not a property Edge has already
demonstrated**. Recording it as inherited-and-proven would be an overclaim.

Nexus therefore admits an Edge package only when that package declares a single
authoritative decision/enforcement boundary for the x86_64 profile. Which Edge
path that is, and how it is proven, is Edge's to decide; Nexus proposes no
resolution here.

Edge's own x86_64 boundary document (§4.3) speaks of "the deterministic
arbiter" in the singular but does not state which of the two paths it is, so
the question is open rather than answered. Edge
[#410](https://github.com/01rabbit/Azazel-Edge/issues/410), which defined that
boundary, is **closed**. Under §2.4 a closed issue must not be reopened or used
as the entry point for this work, so closing this gap required a **new Edge
issue**: [#412](https://github.com/01rabbit/Azazel-Edge/issues/412) asks which
path is authoritative for the x86_64 profile, what becomes of the other, how a
consumer verifies the answer from the released artifact, and whether the
constrained-device profile answers differently.

That issue asks the question; it does not answer it, and Nexus proposes no
answer. Until Edge states one, this row stays open and Nexus treats the
single-boundary requirement as an **unmet admission condition**. Nexus admits
no Edge package that does not declare a single authoritative decision and
enforcement boundary, and this ledger records the arbitration row as
`reference-core` in class but not proven at its boundary.

### 4.3 The x86_64 package boundary Nexus consumes

Edge [#410](https://github.com/01rabbit/Azazel-Edge/issues/410) closed on
2026-09-18 via merged PR
[#411](https://github.com/01rabbit/Azazel-Edge/pull/411), which added
`docs/X86_64_INTEGRATION_BOUNDARY.md` to Azazel-Edge. That document is the
reference for what Nexus may consume. Its own status line reads **"R0 target
contract; implementation evidence pending"** — the issue completed the
*definition*, not the implementation. Facts Nexus depends on:

| Fact | Value |
| --- | --- |
| Future package name | `azazel-edge-runtime` (x86_64); does not exist yet |
| Package contents | deterministic runtime only: evidence intake, NOC/SOC evaluators, arbiter, explanations, audit, operator/API services, Suricata with a **disabled** service template |
| Install-time effects | none permitted: no bridge, default-route change, forwarding, DHCP/NAT, listener bound to a physical interface, or Suricata capture |
| Appliance installer | `installer/internal/install_internal_network.sh` assumes `br0`, `eth0`, `wlan0`; MUST NOT run on a generic x86_64 host |
| Resource tiers | 8 GB Core, 16 GB Lite, 32 GB or more Full-eligible, each "subject to storage, topology, trust, and health gates" |

Two alignments are worth recording. Edge's tier wording matches the Nexus
intersection rule — capacity is explicitly subject to independent topology,
trust, and health gates — and Edge's prohibition on the appliance installer
matches [commissioning](commissioning.md) §1. The vocabularies differ: Edge
says `Full-eligible` where Nexus says `standard`. Nexus keeps `standard`
because it names a **resource envelope**, whereas "Full-eligible" names an
outcome of the intersection; the two are not synonyms and must not be used
interchangeably in either repository.

## 5. Capability ledger

### 5.1 Deterministic core

| Capability | Class | Edge source | Status and evidence | Nexus adoption |
| --- | --- | --- | --- | --- |
| Deterministic arbitration as sole authority | `reference-core` | `arbiter/action.py`; Rust decision path | `implemented`; **boundary not unified** — see §4.2 | condition of package admission |
| Evidence plane and provenance | `reference-core` | `evidence_plane/` | `implemented` | Nexus stores and anchors; semantics unchanged |
| Audit event semantics | `reference-core` | Fabric `schema.audit` via Edge projections | `implemented` | Nexus owns chain enforcement and anchoring only |
| Action lease, rollback, receipt semantics | `reference-core` | Edge enforcement path | `implemented`; automatic TTL release scheduler **not proven** per #400 G1 | Nexus must not assume automatic release |
| Device-specific network installer | **`retired`** | `installer/internal/install_internal_network.sh` | Edge-owned compatibility path; Edge's own x86_64 boundary document forbids running it on a generic host | **not inherited.** Successor: [commissioning](commissioning.md). A Nexus package or profile must not be able to select it |
| Fixed NIC names, addressing, unit defaults | **`retired`** | Edge device profiles | — | **not inherited.** Successor: composite identity plus operator confirmation |

### 5.2 M.I.O. cognitive plane

Every Edge M.I.O. module below has an **open** completion issue, so none is
`verified`. The Nexus tier column is a **Nexus-side eligibility assertion**,
not an Edge statement, and is conditional on the gates in §6.

| M.I.O. capability | Class | Edge module | Open Edge issue | Nexus tier |
| --- | --- | --- | --- | --- |
| No-model fallback / deterministic explanation | `reference-core` | `model_adapter.py` | [#385](https://github.com/01rabbit/Azazel-Edge/issues/385) | **CORE** — must work with no model asset present |
| SituationFrame construction | `reference-core` | `frame_builder.py` | [#383](https://github.com/01rabbit/Azazel-Edge/issues/383) | **CORE** — deterministic, built from evidence |
| Read-only typed Capability Broker | `reference-core` | `broker.py` | [#384](https://github.com/01rabbit/Azazel-Edge/issues/384) | **CORE** — read-only by contract; never an actuator |
| Reasoning Trace lifecycle | `reference-core` | `trace.py` | [#389](https://github.com/01rabbit/Azazel-Edge/issues/389) | **CORE** — provenance, not inference |
| Grounding and playbook provenance | `reference-core` | `grounding.py`, `playbook.py` | [#386](https://github.com/01rabbit/Azazel-Edge/issues/386) | **CORE** |
| Hypothesis and falsification | `reference-core` | `reasoning.py` | [#385](https://github.com/01rabbit/Azazel-Edge/issues/385) | **LITE** — local model required |
| Local model inference | `integrated` | `model_adapter.py`, `resource_profile.py` | [#383](https://github.com/01rabbit/Azazel-Edge/issues/383), [#372](https://github.com/01rabbit/Azazel-Edge/issues/372) | **LITE** — needs `lite` envelope **and** a verified model asset |
| Replay and evaluation harness | `integrated` | `replay.py` | [#372](https://github.com/01rabbit/Azazel-Edge/issues/372) | **LITE** — offline harness merged; Pi-class HIL measurements still required |
| Remote cognition, sanitizer, merger | `integrated` | Nexus-side; Fabric `mio_contracts` **not released** | — | **FULL-eligible** — needs commissioned egress topology and a valid sanitizer decision |

Resource tier never grants a cognition capability on its own. A `standard` host
with no verified model asset reports `CORE ONLY`; see
[capability model](capability-model.md) §6.2.

The remaining M.I.O.-plane capabilities are classified elsewhere in this
ledger, so that every one has exactly one classification: the
Outcome-as-Evidence reasoning loop is `experimental` (§5.3), and the Belief
State, counterfactual planner, strategic council, and Operator Doctrine /
Team Memory work — Edge issues #395–#398, all M.I.O.-plane — is `rejected`
for inheritance at this time (§5.4). None of these changes Edge authority in
any class: each remains advisory, and no classification in this ledger can
turn an advisory result into an authority.

### 5.3 Outcome-as-Evidence

| Capability | Class | Status | Notes |
| --- | --- | --- | --- |
| Action / AppliedMechanism / Outcome / TacticalEffect as separate contracts | `experimental` | `implemented` per [#400](https://github.com/01rabbit/Azazel-Edge/issues/400) G2 | not a production claim |
| Shadow execution receipt normalization | `experimental` | `implemented` | shadow modes `OFF`/`SHADOW_RECORD`/`SHADOW_ASSESS` gain no execution authority |
| Independent mechanism postcondition observation | `experimental` | **not implemented** (#400 G1 unresolved) | without it, `throttle` cannot prove `DELAY` |
| Automatic Outcome collection | `experimental` | **contract only** (#400 G3) | no automatic collector |
| Tactical effect assessment | `experimental` | fail-closed helper only (#400 G4) | `inconclusive` is first-class |
| Replay execution boundary | `reference-core` | `implemented`, read-only (#400 G5 partial) | `ReplayExecutionProvider.execute()` raises; replay never mutates live state |
| Pi/HIL evidence | `experimental` | **PENDING** (#400 G6, [#372](https://github.com/01rabbit/Azazel-Edge/issues/372)) | Edge's own R0 is open |

Nexus MUST NOT present any Outcome-as-Evidence result as verified tactical
effect, and MUST NOT enable a mode that turns a shadow assessment into an
enforcement input. Command success is not proof of effect.

### 5.4 Not inherited

Azazel-Edge [#408](https://github.com/01rabbit/Azazel-Edge/issues/408) is the
execution-order source of truth for Edge and places the following behind gates
D0–D4; [#400](https://github.com/01rabbit/Azazel-Edge/issues/400) additionally
parks them explicitly until its own G1–G6 close. Edge
[#399](https://github.com/01rabbit/Azazel-Edge/issues/399) may `DEMOTE` or
`KILL` any of them.

| Concept | Edge issue | Class for Nexus | Rationale |
| --- | --- | --- | --- |
| Defensive Effect Protocol | [#392](https://github.com/01rabbit/Azazel-Edge/issues/392) | `rejected` for now | Gate D0 not reached |
| Adversary Tempo / Defensive Initiative | [#393](https://github.com/01rabbit/Azazel-Edge/issues/393) | `rejected` for now | Gate D0 not reached |
| Real / Presented Terrain | [#394](https://github.com/01rabbit/Azazel-Edge/issues/394) | `rejected` for now | Gate D1 |
| Adversary Belief State | [#395](https://github.com/01rabbit/Azazel-Edge/issues/395) | `rejected` for now | Gate D1; attribution overclaim risk |
| Counterfactual planner | [#396](https://github.com/01rabbit/Azazel-Edge/issues/396) | `rejected` for now | Gate D2; replay/shadow only |
| Strategic council | [#397](https://github.com/01rabbit/Azazel-Edge/issues/397) | `rejected` for now | Gate D3 |
| Operator Doctrine / Team Memory | [#398](https://github.com/01rabbit/Azazel-Edge/issues/398) | `rejected` for now | Gate D3 |

"Rejected for now" means **not eligible for Nexus inheritance at this time**.
It is not a judgment on the Edge research. Eligibility changes only when the
relevant Edge gate closes and a Nexus issue records the adoption under §2.5.

## 6. Adoption gates

A capability moves from a lower class to `integrated` only when all of the
following exist and are linked from its ledger row:

1. an exact source contract version or released package digest;
2. a stated authority boundary and what remains advisory;
3. resource, topology, verified-asset, and trust/health gates stated
   **separately**;
4. declared behavior for timeout, restart, resource exhaustion, signature
   failure, link loss, and failed update;
5. degradation behavior in `CORE`, `LITE`, and `FULL`, and what is unavailable
   in each;
6. audit, rollback, recovery, and failure-injection evidence;
7. a Nexus issue that records the adoption.

Missing any item leaves the capability where it is. A capability is never
promoted because it works in a demonstration.

## 7. Initial integrated capability set

Azazel-Nexus issues #2–#6 are the first integration workstreams. None is
complete; all are `target contract`.

| Nexus issue | Capability | Depends on |
| --- | --- | --- |
| [#2](https://github.com/01rabbit/Azazel-Nexus/issues/2) | Fabric source of truth and product-local provisioning boundary | Fabric `v0.8.0` observed; `provisioning_contracts` not released |
| [#3](https://github.com/01rabbit/Azazel-Nexus/issues/3) | Signed offline M.I.O. Mission Pack lifecycle | admission policy (§6), signed model assets |
| [#4](https://github.com/01rabbit/Azazel-Nexus/issues/4) | Rugged x86_64 M.I.O. HIL and degraded-mode validation | physical hardware; Edge [#372](https://github.com/01rabbit/Azazel-Edge/issues/372) Pi-class results |
| [#5](https://github.com/01rabbit/Azazel-Nexus/issues/5) | Runtime profiles, local/remote routing, `FULL -> LITE -> CORE` | [capability model](capability-model.md); Fabric `mio_contracts` for the remote path |
| [#6](https://github.com/01rabbit/Azazel-Nexus/issues/6) | Embedded Knowledge Lite and optional AZ-04 integration | Azazel-Knowledge [#73](https://github.com/01rabbit/Azazel-Knowledge/issues/73) signed Lite bundle |

Issue [#2](https://github.com/01rabbit/Azazel-Nexus/issues/2) is the only one
whose documentation work has landed; the rest have not started.

## 8. Backport register

A Nexus capability returns to Edge only through a new Edge issue. No entries
yet.

| Date | Capability | New Edge issue | Minimal reference-core benefit | Compatibility and evidence record |
| --- | --- | --- | --- | --- |
| — | — | — | — | — |

A row may be added only when the new Edge issue exists. Reopening a closed Edge
issue to host a backport is prohibited by §2.4.

## 9. Maintenance

Update this ledger in the same change that adopts, promotes, demotes, or
retires a capability. When an entry's linked Edge issue materially changes its
gate status, re-audit the row rather than leaving a stale classification — a
ledger that lags its sources is worse than no ledger, because it looks like
evidence.
