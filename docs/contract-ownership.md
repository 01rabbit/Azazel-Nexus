# Contract Ownership and Admission Records

Status: **target contract**. This document states where each record used by
Azazel-Nexus is defined. It does not assert that Nexus implements any of them;
Nexus currently contains no package, dependency manifest, or Fabric pin.

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
  mapping in §3 has been tested: no Nexus adapter, pin, or conformance run
  exists yet, so every stated fit is a design assertion awaiting a conformance
  attestation, not verified evidence. A mapping that fails conformance is
  corrected here, not worked around with a Nexus-local copy.
- **Fabric-owned (target, R1)** — a model the program plan assigns to Fabric
  but which does not exist yet. Nexus MUST NOT invent a local canonical form
  or a provisioning pin for it before Fabric releases it.
- **Nexus-local** — a product-local record that never crosses a product
  boundary as a contract.

## 2. Observed Fabric state

These modules were observed in `01rabbit/Azazel-Fabric` on `main` during the R0
baseline audit; the package declares version `0.8.0`. This is an observation of
the source tree, not a statement that every model below is release-verified for
Nexus use.

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
| evidence citation carried by any advisory record | Fabric | `schema.evidence.EvidenceRef` | Fabric-owned (available) |
| audit envelope and canonical bytes | Fabric | `schema.audit.AuditEvent`, `audit.jsonl` | Fabric-owned (available) |
| capability/mode publication to the UI | Fabric | `schema.mode.ModeState`, `schema.state.StateSnapshot`, `view.status.StatusView` | Fabric-owned (available) |
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
| Knowledge Lite context query and cited response | Fabric | `cti_contracts.context`, `cti_contracts.advisory` | Fabric-owned (available) |
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
| `MioSituationFrame` (local situation record) | Fabric | `mio_contracts` | **Fabric-owned (target, R1)** |
| `MioRemoteFrame` (sanitized remote frame) | Fabric | `mio_contracts` | **Fabric-owned (target, R1)** |
| advisory result returned by a local or remote model | Fabric | `mio_contracts` | **Fabric-owned (target, R1)** |
| provenance-preserving merge output and disagreement marking | Fabric | `mio_contracts` | **Fabric-owned (target, R1)** |
| sanitizer policy file, alias key material, redaction records | **Nexus-local** | — | product-local; the redaction *record reference* is carried in the Fabric frame, the record itself is not exported |
| router state, request budget, deadline accounting | **Nexus-local** | — | product-local |
| model asset layout, sandbox, and cgroup budgets | **Nexus-local** | — | product-local execution |

Until `mio_contracts` is released, Nexus documentation MUST describe these
frames as target contracts and MUST NOT publish a Nexus-local canonical JSON
form as if it were the interoperable shape.

### 3.4 Provisioning path

Every record below is assigned to Fabric `provisioning_contracts` by the
program plan and is **not yet released**. Nexus MUST NOT adopt a provisioning
pin until R1 publishes one.

| Record | Owner | Status |
| --- | --- | --- |
| `HardwareInventory` | Fabric | target, R1 |
| `ResourceProfile` | Fabric | target, R1 |
| `TopologyProfile` | Fabric | target, R1 |
| `InterfaceAssignment` | Fabric | target, R1 |
| `CommissioningRecord` | Fabric | target, R1 |
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
| `architecture` | `x86_64` for Nexus; other values are rejected |
| `cpu_features` | required instruction-set features (model admission in particular) |
| `fabric_version` | exact Fabric release pin |
| `fabric_features` | required Fabric feature IDs from the feature-to-minimum-version matrix |
| `schema_features` | required contract features beyond the version floor |
| `profile` | resource envelope the tuple was tested in |
| `overlay_schema` | deployment-overlay schema version |
| `security_epoch` | minimum acceptable security epoch |
| `max_rollback_version` | oldest version this generation may roll back to |

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
| license | the repository states no license; use and contribution permissions are undefined |
| security policy and contribution guide | no disclosure or contribution path is published |
| package layout, `pyproject.toml`, dependency manifest | no installable Nexus artifact exists |
| Fabric pin | no contract version is bound; §3 mappings are unenforced |
| CI and conformance attestation | no automated check enforces any statement in this repository |
| support matrix, update channel, recovery procedure | R0 exit criteria for a supported release are unmet |

Until these exist, every Nexus document is a **target contract**. No statement
in this repository may be cited as implementation or verification evidence.
