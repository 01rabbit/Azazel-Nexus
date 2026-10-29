# Contract Ownership and Admission Records

Status: **target contract**. This document states where each record used by
Azazel-Nexus is defined. It does not assert that Nexus implements any of them.
It carries a package (`pyproject.toml`, `src/azazel_nexus/`) with a
deliberately empty required-dependency list, a unit suite, and an exact
**Azazel-Fabric pin as an optional extra** (`v0.9.0rc5`, ADR-0001), consumed
through one boundary module. One mapping is attested by that boundary —
capability/mode publication, which production `azazel-nexus status` now calls
(integrated loop I3). The Edge evidence pointer has a tested projection onto
`schema.evidence.EvidenceRef` with no production caller (I1). Every other
contract mapping remains a design assertion awaiting a conformance attestation,
not verified evidence. See [the integrated defensive loop](integration-loop.md).

Related: [Azazel program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md) ·
[R0 baseline](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-r0-baseline.md) ·
[Capability model](capability-model.md) · [Commissioning and activation](commissioning.md)

## 1. Ownership rule

> **Azazel-Fabric describes. Azazel-Knowledge advises. Azazel-Edge decides and
> enforces. Azazel-Deception materializes an Edge-approved environment.
> Azazel-Nexus integrates released components without creating another
> decision authority.**

Azazel-Fabric owns every shared record that crosses a product boundary,
together with its canonical serialization, digests, validation, and golden
fixtures. Nexus MUST NOT define a local canonical form for a shared record, and
MUST NOT fork a Fabric model into a Nexus-local copy.

Nexus owns what it performs on the host: product admission, installation,
commissioning, activation, rendering, service confinement, storage layout,
audit anchoring, update, and recovery. These are product-local because they
have side effects; Fabric contracts are descriptive and side-effect free.

A record is therefore classified exactly one of:

- **Fabric-owned (available)** — a model observed in Azazel-Fabric `main`
  during the R0 audit. Nexus consumes it behind an exact release pin.
  "Available" means the model exists in Fabric. It does **not** mean the
  mapping in §3 has been tested: unless its row names a projection and the
  test that checks it against the pin, no Nexus adapter or conformance run
  covers it, so every stated fit is a design assertion awaiting a conformance
  attestation, not verified evidence. A mapping that fails conformance is
  corrected here, not worked around with a Nexus-local copy.
- **Fabric-owned (target, R1)** — a model the program plan assigns to Fabric
  but which does not exist yet. Nexus MUST NOT invent a local canonical form
  or a provisioning pin for it before Fabric releases it.
- **Nexus-local** — a product-local record that never crosses a product
  boundary as a contract.

The rc3/rc4 fixes to `effect_contracts` references and authority classes are
already relied on by Edge and Deception; rc2 → rc5 changes only
`effect_contracts`, which Nexus does not import yet.

## 2. Observed Fabric state

These modules were observed in `01rabbit/Azazel-Fabric` at **`v0.8.0`** during
the R0 baseline audit. This is an observation of one tag's source tree, not a
statement that every model below is release-verified for Nexus use — and,
because Nexus declares no Fabric dependency, not something this repository's
tests can re-check. An observation is therefore written against a named tag and
stays valid for that tag only.

**The observation is already out of date, and two of its conclusions have been
overtaken.** `provisioning_contracts` and `mio_contracts` were absent at
`v0.8.0` and are present from `v0.9.0rc1` onward. Azazel-Boot, which does pin
Fabric, records that directly: its `PLANNED_FABRIC_MODULES` names both and its
projection reports nothing missing at `v0.9.0rc1` (ADR-0007). Nexus now pins
`v0.9.0rc5` (ADR-0001), where both are present. §3.3 records `mio_contracts` as
**published, not adopted**: the one record Nexus produces in that family is an
internal `ClaimSet` projection of its own explanation ledger, kept in that
ledger and never sent (§3.3). §3.4 records `provisioning_contracts`. A module
existing in the pin is still not a verified mapping; each row says what was
attested and where.

| Fabric module | Records observed |
| --- | --- |
| `schema.action` | `ActionIntent`, `ActionPlan` and the `Observe`/`Notify`/`Throttle`/`Redirect`/`Isolate`/`Decoy`/`Release` plans |
| `schema.decision` | `DecisionExplanation` |
| `schema.evidence` | `EvidenceRef` |
| `schema.audit`, `audit.events`, `audit.jsonl` | `AuditEvent` and its serialization |
| `schema.state`, `schema.mode` | `StateSnapshot`, `ModeState` |
| `schema.trust` | `TrustCapsule` |
| `view.status` | `StatusView`, `HealthDimension` |
| `notify.model` | `NotificationEvent` |
| `cti_contracts.context`, `.advisory` | `CtiContextRequest`, `CtiContextResponse`, `IocMatch`, `BehavioralCtiBlock` |
| `deception_contracts.models` | `DeceptionPackage`, `EnvironmentActivationDecision`, `EnvironmentTransitionDecision`, `EnvironmentTerminationDecision`, `EnvironmentEvent`, `EnvironmentOutcome`, `HostCapabilities`, `RuntimeRequirements`, `ResourceBudget`, `SafetyPolicy` |
| `engagement_contracts.models` | `EngagementAdvisory`, `EngagementCandidate`, `EngagementOutcome`, `EngagementEvent` |
| `outcome_contracts.models` | `OutcomeObservationV0`, `MechanismObservationV0`, `ExecutionRefV0` |

`provisioning_contracts` and `mio_contracts` were **not** present. Every record
that the program plan assigns to those modules is therefore a target contract.

## 3. Record ownership map

### 3.1 Decision, evidence, and audit path

| Nexus usage | Owner | Fabric artifact | Status |
| --- | --- | --- | --- |
| enforcement intent issued by the arbiter | Fabric | `schema.action.ActionIntent` + plan variants | Fabric-owned (available) |
| operator-facing decision explanation | Fabric | `schema.decision.DecisionExplanation` | Fabric-owned (available) |
| evidence citation carried by any advisory record | Fabric | `schema.evidence.EvidenceRef` | Fabric-owned (available); Edge evidence pointer projected by `fabric_boundary.project_edge_evidence` and checked against the pin in `tests/unit/test_edge_intake_fabric.py`. `project_explanation` (§3.3) turns given evidence records into `EvidenceRef`s and cites them from the Edge claim (`tests/unit/test_fabric_explanation_projection.py`), but **the explainer gives it none**: its durable pending queue carries no evidence digests by design (`incident_explain.explanation_input`), so the stored Edge claim says `evidence_refs_not_carried`. Carrying evidence digests into the explanation path is an owner decision. Intake stores its own digest and never needs Fabric |
| audit envelope and canonical bytes | Fabric | `schema.audit.AuditEvent`, `audit.jsonl` | Fabric-owned (available) |
| capability/mode publication to the UI | Fabric | `schema.mode.ModeState`, `schema.state.StateSnapshot`, `view.status.StatusView` | Fabric-owned (available); `ModeState` and `StatusView` **attested** by `fabric_boundary.project_capability` (`tests/unit/test_fabric_boundary.py`) and called by production `azazel-nexus status` (`fabric status view:` line, `edge_loop_status.render_fabric_status`); `StateSnapshot` not projected |
| trust material presentation | Fabric | `schema.trust.TrustCapsule` | Fabric-owned (available) |
| operator alert payload | Fabric | `notify.model.NotificationEvent` | Fabric-owned (available) |
| hash-chain ledger segments, checkpoint signing, ledger genesis linkage | **Nexus-local** | — | Nexus performs chain enforcement; Fabric supplies the event projection only |
| enforcement receipt persistence and lease timer state | **Nexus-local** | — | product-local durable state |

The chain enforcement split is deliberate: Fabric defines what an audit event
*is*; whether a chain is continuous, anchored, or broken is a product-local
trust decision that Fabric MUST NOT make.

### 3.2 Knowledge and Deception path

| Nexus usage | Owner | Fabric artifact | Status |
| --- | --- | --- | --- |
| Knowledge Lite lookup and cited response | **Nexus-local** | — (`cti_contracts.context`/`.advisory` exist in the pin and are **not** the shape used) | `knowledge.lookup` over the local Unix socket returns `lite_import.KnowledgeRef` rows (claim id, verified bundle digest, generation, freshness, `as_of`, dataset citation). Neither this nor the real Knowledge `/v1/context` uses the `CtiContextRequest`/`CtiContextResponse` shape (Knowledge `api/contracts.py` adopts only Fabric's advisory-only check on its own response), and `cti_contracts.SourceProduct` is `edge`/`gadget`, so Nexus cannot be the requester. Not adopted |
| cited Knowledge reference inside an explanation | Fabric | `mio_contracts.Claim` (`source="knowledge_advisory"`) | projected internally by `fabric_boundary.project_explanation` (one claim per `KnowledgeRef`: bundle digest as the only input reference, Lite freshness as freshness); kept in the explanation ledger only (§3.3) |
| Deception package description and host capability requirements | Fabric | `deception_contracts.models` | Fabric-owned (available) |
| Deception activation/transition/termination decision carried to a decoy runtime | Fabric | `deception_contracts.models` decision records | Fabric-owned (available) |
| decoy telemetry and environment outcome returned to Evidence | Fabric | `EnvironmentEvent`, `EnvironmentOutcome` | Fabric-owned (available) |
| engagement advisory and outcome export | Fabric | `engagement_contracts`, `outcome_contracts` | Fabric-owned (available) |
| signed Knowledge Lite bundle format and selection algorithm | **Azazel-Knowledge** | — | produced by AZ-04 (Knowledge #73); Nexus owns only the read-only reader and its storage |
| tactical cache database, eviction, and freshness labeling | **Nexus-local** | — | product-local storage |
| decoy bridge, namespace, and container confinement | **Nexus-local** | — | product-local execution |

### 3.3 M.I.O. cognition path

| Nexus usage | Owner | Fabric artifact | Status |
| --- | --- | --- | --- |
`mio_contracts` is present in the pinned `v0.9.0rc5` (and from `v0.9.0rc1`);
it is **published, not adopted** (`docs/mio-dual-cognition.md`). Nexus's own
frames (`azazel-nexus/sanitized-envelope/1`, `advisory_response`,
`local_advisory`) keep their Nexus-local shapes and are not published as the
interoperable form.

| Nexus usage | Owner | Fabric artifact | Status |
| --- | --- | --- | --- |
| local situation record | Fabric | `mio_contracts.SituationFrame` | published, **not adopted** (Nexus builds its own frame, `incident_explain.build_frame`) |
| sanitized remote frame | Fabric | `mio_contracts.SanitizedRemoteFrame` | published, **not adopted**; see the redaction row and the owner decision below |
| advisory result returned by a local or remote model | Fabric | `mio_contracts.AdvisoryResult` | published, **not adopted** (`advisory_response`, `local_advisory`) |
| provenance-preserving merge output and disagreement marking | Fabric | `mio_contracts.MergedAdvisory`, `Disagreement` | published, **not adopted** (Nexus merges nothing) |
| explanation claims: the Edge decision and each cited Knowledge reference | Fabric | `mio_contracts.ClaimSet`, `Claim` | **projected internally**: `fabric_boundary.project_explanation` builds a `ClaimSet` from each explanation-ledger record (Edge decision `deterministic_core`, each `KnowledgeRef` `knowledge_advisory`), and `incident_explaind` keeps Fabric's own JSON dump beside the record in its ledger when the pinned Fabric is present. Never sent, displayed or served; `read_record` refuses a stored projection that drifted from its record. The M.I.O. advice in the record is not projected: the ledger names the route, not the model and generation a model-sourced `Claim` must carry. Tests: `tests/unit/test_fabric_explanation_projection.py` |
| sanitizer policy file, alias key material, redaction records | **Nexus-local** | — | product-local. Only the redaction record's id (`redaction_record_id`, a digest) travels in Nexus's sanitized envelope; the record (which fields were removed, aliased or bucketed) stays on the node |
| router state, request budget, deadline accounting | **Nexus-local** | — | product-local |
| model asset layout, sandbox, and cgroup budgets | **Nexus-local** | — | product-local execution |

Privacy classes. `fabric_boundary.FABRIC_PRIVACY_CLASS` holds the
correspondence and a test checks it against Fabric's own `PrivacyClass` and
`NON_EGRESSIBLE_PRIVACY_CLASSES`. It is a correspondence, not a wire mapping:
nothing is sent in Fabric's shape.

| Nexus (`sanitizer.PrivacyClass`) | Fabric (`mio_contracts.PrivacyClass`) | Leaves the node? | Note |
| --- | --- | --- | --- |
| `P0-public` | `public` | may, under policy | same meaning |
| `P1-sanitized` | `internal` | may, under policy | Nexus's word says the field was sanitized for this route; Fabric's says the data is internal to the operator. Both are the two classes a remote frame may carry |
| `P2-mission` | `sensitive` | never | Nexus `NEVER_REMOTE` = Fabric `NON_EGRESSIBLE_PRIVACY_CLASSES` |
| `P3-restricted` | `restricted` | never | as above |

Redaction actions. Nexus records `removed`, `aliased` and `bucketed`; Fabric's
`RedactionRecord.action` also has `truncated` and `generalized`, which Nexus
never does (an over-budget frame is refused, not truncated).

**Owner decision (redaction records).** Fabric's `SanitizedRemoteFrame`
*carries* its `redactions` (field reference, privacy class, action, reason) to
the remote side. Nexus's policy is the opposite: the record stays local and
only its id travels. Adopting `SanitizedRemoteFrame` therefore requires one of:
(a) send the redaction records, which tells the remote side which fields of a
mission frame existed and why they were withheld; (b) send `redactions=()` with
the id elsewhere, which would state "nothing was redacted" when something was;
or (c) ask Fabric for an additive reference-only field. Nexus has not chosen;
until it does, `SanitizedRemoteFrame` is not adopted and nothing is sent in it.

### 3.4 Provisioning path

Every record below is assigned to Fabric `provisioning_contracts` by the
program plan. That module **is published** — it shipped in `v0.9.0rc1` and the
tag this repository pins carries it, which `tests/unit/test_status_claims.py`
checks against the installed distribution rather than against this sentence.
This section said it was unreleased while the table below already described
`InterfaceIdentity` as consumed from it (#23).

Consumption below distinguishes tested projection from installed production
collection. Nexus MUST NOT restate Fabric records locally.

| Record | Owner | Status |
| --- | --- | --- |
| `InterfaceIdentity`, `InterfaceIdentitySelector` | Fabric | **consumed** — `src/azazel_nexus/fabric_boundary.py` projects a read-only interface inventory into `InterfaceIdentity` and resolves a selector with Fabric's own `resolve_interface_assignment`. Nexus defines no record for either, and does not restate the fail-closed matching rule |
| `HardwareInventory` | Fabric | sysfs observations and in-memory Fabric projection implemented; protected node binding/bootstrap, completeness and authenticated persistence remain incomplete |
| `ResourceProfile` | Fabric | measured observation projection implemented in `fabric_boundary.py`; descriptive only, requires complete inventory and available measurements; production pipeline remains incomplete |
| `TopologyProfile` | Fabric | reviewed-draft projection implemented against a complete matching interface snapshot; management/capture/isolation unverified, not a signed profile or admission |
| `InterfaceAssignment` | Fabric | consumed by `fabric_boundary.confirm_role` and reviewed-draft topology projection; production collection and persistence remain incomplete |
| `CommissioningRecord` | Fabric | assembled by `fabric_boundary.build_commissioning_record` as a linked unsigned proposal; a separate `commissioning_approval.verify_commissioning_proposal` verifies a new full-proposal signature under the `commissioning-proposal` purpose against independently supplied snapshots; verification grants no activation authority; production loaders, protected trust/bootstrap composition, freshness/state checks and persistence remain incomplete |
| `ProductManifest`, `AssetManifest`, `ModelManifest` | Fabric | target, R1 |
| `ProposedGenerationDescriptor` (observation-only) | Fabric | target, R1 |
| `ActivationReceipt` (observation-only projection) | Fabric | target, R1 |
| `CompatibilityManifest` | Fabric | target, R1 |
| admission policy, trust roots, delegated roles, security epoch | **Nexus-local** | target |
| generation counter, staging directory, renderer digest, systemd credential issue | **Nexus-local** | target |
| verified-asset set and trust/health state evaluation | **Nexus-local** | target |

A descriptive provisioning record MUST NOT carry a command, unit name, route,
firewall rule, device path, executor, boolean authorization, or trust decision.
A record that does is a product-local record, not a shared contract.

**The interface-role vocabularies do not agree, and nothing had ever compared
them.** Fabric registers `asset_acquisition`, `deception_bridge`, `management`,
`observation`, `unassigned`; [`commissioning.md`](commissioning.md) §4 names
`protected`, `observation`, `management`, `decoy`, `egress/module`; Azazel-Boot
holds `observe`, `internal`, `external`, `management`, `capture`, `decoy`.
**`management` is the only value all three share**, and two pairs are
near-misses that read as agreement — `observation`/`observe`,
`deception_bridge`/`decoy`. No product consumed Fabric's list, so the
divergence had never surfaced.

Nexus enumerates **no** interface role in code, and
`tests/unit/test_inventory.py` refuses one that appears. Writing this
document's five words into the package would create a fourth vocabulary and
settle the question by accident. Reconciling the three is a product decision;
the test records the measurement and fails when any of them moves.

## 4. Admission and compatibility records

Cryptographic authenticity is one input to admission, not admission itself.
Nexus evaluates the following gates **in order**, and every gate can reject:

```text
authenticity
  -> exact tested compatibility tuple
  -> semantic content policy
  -> resource/topology admission
  -> operator or policy-authority approval
  -> staged activation
```

### 4.1 Tested compatibility tuple

Field releases use a deny-by-default set of tested tuples. A tuple is exact;
a version range is a descriptive compatibility claim and MUST NOT authorize
activation. Each tuple records:

| Field | Meaning |
| --- | --- |
| `component_digest` | immutable digest of the released artifact (Edge, Knowledge bundle, Deception package, model, OS image) |
| `adapter_digest` | digest of the Nexus adapter that consumes it |
| `renderer_digest` | digest of the configuration renderer that produced the generation |
| `toolchain_digest` | compiler/build toolchain identity used for the payload |
| `os_abi` | distribution ABI and kernel series the tuple was tested against |
| `architecture` | the kernel name of the deployment-baseline profile's CPU (`x86_64`), read from `platform_profile.REVIEWED_PROFILES`; an `aarch64` tuple is accepted only as `purpose` `lab-software-verification` and never admits ([ADR-0006](adr/0006-tested-tuple-fabric-and-arm-lab.md)); other values are rejected |
| `cpu_features` | required instruction-set features (model admission in particular) |
| `fabric_version` | exact Fabric release pin |
| `fabric_features` | required Fabric feature IDs from the feature-to-minimum-version matrix |
| `schema_features` | required contract features beyond the version floor |
| `profile` | resource envelope the tuple was tested in |
| `overlay_schema` | deployment-overlay schema version |
| `security_epoch` | minimum acceptable security epoch |
| `max_rollback_version` | oldest version this generation may roll back to |
| `purpose` | the platform-profile purpose of `architecture`: `deployment-baseline` (the default, omitted from the record) or `lab-software-verification` (recorded; refused for every admission) |

Fabric's `TestedCompatibilityTuple` describes the same combination as a
descriptive claim; `fabric_boundary.project_tested_tuple` and
`check_tested_tuple` map and compare the two field by field (ADR-0006 D5).
A Fabric claim is never an admission input.

A correctly signed artifact that matches no tested tuple is rejected. A
correctly signed artifact from the wrong delegated role is rejected. A
correctly signed artifact below the minimum security epoch is rejected.

### 4.2 Delegated trust roles

Nexus provisions separate offline roots and delegated roles for OS images, Edge
packages, Knowledge bundles, Deception packages, models, and emergency
overlays. Signing roles are also separated by purpose: policy signing, intent
signing, update signing, commissioning approval, audit checkpoint, and
recovery. Only the Edge arbiter workload identity may use the intent-signing
credential; the activation controller may install that credential but MUST NOT
be able to read or reuse it.

An installation-generated device key proves local continuity only. It does not
establish site identity until a site or operator identity enrolls it.

## 5. Released-package boundary

Nexus consumes Edge, Knowledge, and Deception as **released, signed packages**.

- Nexus MUST NOT vendor, copy, or fork a product source tree.
- Nexus MUST NOT call Azazel-Edge's device-specific network installer, inherit
  its NIC fixed values, or reuse its unit defaults. That installer remains a
  compatibility path for constrained-device Edge deployments and is out of
  scope for Nexus. See [commissioning](commissioning.md) §1. Azazel-Edge's own
  `docs/X86_64_INTEGRATION_BOUNDARY.md` states the same prohibition; the
  [inheritance ledger](inheritance-ledger.md) §4.3 records what that package
  boundary does and does not yet establish.
- Nexus MUST NOT convert a configuration overlay, package manifest, model
  response, M.I.O. recommendation, or capability report into executable
  authority.
- A deployment overlay is a **monotonic reduction**: it may bind commissioned
  interfaces, select a subset of allowed components, reduce resource limits,
  and add labels. It MUST NOT change Edge action policy, approval requirements,
  lease ceilings, trust roots, signing-key locations, executable commands,
  routes, firewall rules, services, container mounts or capabilities, or any
  authority field.

## 6. Open bootstrap work

The following are absent from this repository and are recorded here as
subsequent bootstrap work rather than as satisfied requirements:

| Missing | Consequence today |
| --- | --- |
| conformance attestation for §3.1's remaining rows, §3.2, §3.3 and §3.4 | no check enforces those mappings |

**Closed since this section was written.** The package layout, `pyproject.toml`
and dependency manifest arrived with the Knowledge Lite consumer (#18), and the
repository runs a unit suite rather than the documentation link check alone.
The **Fabric pin** is now bound: `v0.9.0rc5` as the optional `fabric` extra,
consumed through one boundary module ([ADR-0001](adr/0001-fabric-pin.md)).

One §3.1 row is attested by that boundary — capability/mode publication through
`ModeState` and `StatusView`, checked in `tests/unit/test_fabric_boundary.py`
against the pinned models rather than asserted here. Since integrated-loop I3
production status calls that projection and prints only `projected (v0.9.0rc5)`,
`not available (extra not installed)` or `refused (projection_refused)`; an
absent extra never changes the capability shown. The Edge evidence pointer
(`project_edge_evidence`, I1) is tested against the pinned `EvidenceRef` but
has no production caller, so it is not counted as an attested row. The modules
a capability projection needs are `REQUIRED_FABRIC_MODULES` (`view`,
`schema.mode`, `schema.evidence`); `PLANNED_FABRIC_MODULES` (`cti_contracts`,
`deception_contracts`, `mio_contracts`) are mapped in §3 and consumed by no
Nexus code — the integrated loop's Knowledge citations and M.I.O. frames use
Nexus-local shapes, not those families. Every other row in §3 is unchanged:
**a bound pin is what makes an attestation possible, not an attestation.**

`tests/unit/test_repository_status_claims.py` exists because the two closed
rows above stayed in seven documents after they were closed — and it is what
named those documents when the pin landed, rather than leaving the sentences to
be found by a reader planning work from them.

Closed since this section was written: the package layout, `pyproject.toml` and
dependency manifest arrived with the Knowledge Lite consumer (#18), and the
repository now runs a unit suite rather than the documentation link check
alone. `tests/unit/test_repository_status_claims.py` exists because those two
rows stayed in five documents after they were closed — a status sentence that
nothing checks goes stale silently, and a reader planning work from it plans
around a repository that no longer exists.

Published since this section was written, and satisfying the *publication* half
of the corresponding R0 exit criterion only: the [license](../LICENSE), the
[security policy](../SECURITY.md), the [contribution guide](../CONTRIBUTING.md),
the [support matrix](support-matrix.md), the
[update channel](update-channel.md), and the [recovery procedure](recovery.md).
Each states what a release will have to carry; none is evidence that Nexus
carries it, and the support matrix's hardware list is empty.

Until the rows above are closed, every Nexus document is a **target contract**.
No statement in this repository may be cited as implementation or verification
evidence.
