# Azazel-Nexus Architecture

## 1. Purpose and doctrine

Azazel-Nexus is a portable defensive system built around a rugged Linux PC deployed at a network edge. It must provide situational awareness, bounded response, and a defensible explanation of every consequential action even when there is no upstream connection.

The architecture separates three concerns deliberately:

1. **Observation and evidence** capture what was seen without allowing analytics to overwrite it.
2. **Decision and enforcement** evaluate declared policy deterministically and apply only authorized controls.
3. **Cognition** helps humans understand and investigate the situation, but never becomes a direct actuator.

AZ-01 Azazel-Edge is the system of record for the first two concerns. A Nexus embeds Knowledge Lite and Deception Lite alongside Edge and M.I.O.; optional full nodes enrich those capabilities through constrained interfaces. The [Integrated-node doctrine](nexus-integrated-node.md) defines this baseline and extension model.

Shared contracts belong to AZ-05 Azazel-Fabric, not to this repository:
**Fabric describes, Knowledge advises, Edge decides and enforces, Deception
materializes an Edge-approved environment, and Nexus integrates released
components without creating another decision authority.**
[Contract ownership](contract-ownership.md) maps every record used here to
Fabric or to Nexus and marks which Fabric contracts do not exist yet.

Status: **target contract**. It carries a package (`pyproject.toml`,
`src/azazel_nexus/`) with a deliberately empty required-dependency list, a unit
suite, and an exact **Azazel-Fabric pin as an optional extra** (`v0.9.0rc2`,
ADR-0001), consumed through one boundary module. One mapping is attested by
that boundary — capability/mode publication; every other contract mapping
remains a design assertion awaiting a conformance attestation, not verified
evidence. Nothing below is implemented or
verified here.

## 2. Deployment topology

```text
                         operator plane
                    +-------------------+
                    | touch UI / audio  |
                    +---------+---------+
                              |
 +----------------------------+-----------------------------+
 | AZAZEL-NEXUS: rugged Linux integrated node                |
 |                                                            |
 |  capture adapters --> Observe --> Evidence Plane           |
 |                              |             |               |
 |                         Suricata      audit store          |
 |                              |             |               |
 |                       NOC / SOC evaluators                 |
 |                              |                             |
 |                         Action Arbiter --> Enforcement     |
 |                              |              nftables / tc  |
 |                       Decision Explanation                  |
 |                              |                             |
 |       Knowledge Lite / Deception Lite (embedded)            |
 |                  M.I.O. Cognitive Router                    |
 |                    |                 |                     |
 |                 local model       Sanitizer --> remote API  |
 |                    +-------- Cognition Merger --------+    |
 +----------------------------+-----------------------------+
              |                                     |
      AZ-04 Full Knowledge                  AZ-06 Full Deception
      optional deep-memory node              optional engagement host
```

The rugged PC is a class of hardware, not a named device dependency. A field build should use an x86_64 Linux-compatible unit with a TPM where available, hardware-backed or disk-encrypted storage, battery power, and an operator-accessible display. USB radios and adapters are treated as replaceable mission equipment, not part of the trusted computing base.

Network interfaces are a **topology** question, not a hardware checklist item.
The zones drawn above exist only where an interface has been commissioned to
that logical role by explicit operator confirmation against a composite
identity. A host with fewer usable interfaces than roles simply has fewer
capabilities; it does not fall back to sharing one interface between roles, and
it does not infer a role from an interface name, link state, or default route.
See [commissioning](commissioning.md) and [capability model](capability-model.md).

Nexus does not invoke or inherit Azazel-Edge's device-specific network
installer, its NIC fixed values, or its unit defaults. Edge is consumed as a
released, signed package behind an explicit adapter.

## 3. Core node: AZ-01 Azazel-Edge

### 3.1 Evidence Plane

The Evidence Plane consumes packet metadata, sensor alerts, system state, interface health, and operator annotations. It produces append-only, time-correlated artifacts:

- raw or retained capture references subject to the mission retention policy;
- normalized observations with source, timestamp, schema version, and integrity hash;
- alert and evaluator inputs;
- decision records, enforcement receipts, and operator acknowledgements.

It keeps observation distinct from conclusion. A later model summary may reference evidence IDs, but cannot rewrite raw observations or erase the chain of reasoning.

### 3.2 Deterministic Core

The Deterministic Core contains the NOC Evaluator, SOC Evaluator, Action Arbiter, and Decision Explanation service.

| Component | Responsibility | Must not do |
| --- | --- | --- |
| NOC Evaluator | Determine network health, reachability, path, capacity, and interface anomalies. | Treat a language-model statement as a measurement. |
| SOC Evaluator | Map detections and corroborated evidence to policy-relevant risk states. | Modify live policy from untrusted input. |
| Action Arbiter | Apply policy, prerequisites, scope limits, and approval requirements to select an action. | Accept a direct model command. |
| Decision Explanation | Render evidence, rule, confidence, scope, and outcome for the operator. | Conceal uncertainty or invent provenance. |

The arbiter is the sole authority that can issue enforcement intents. Every intent has an immutable identifier, bounded target/scope, expiry, policy version, reason/evidence references, and a result receipt.

### 3.3 Enforcement Plane

The enforcement adapter translates an approved intent into host controls such as `nftables`, `tc`, routing, bridge configuration, or a managed interface operation. It runs with narrowly scoped privileges and exposes idempotent operations:

```text
intent -> validate scope -> apply -> verify effective state -> receipt
```

Verification failure is a failed action, not a presumed success. Emergency controls are predeclared policies (for example, isolate a named segment or revoke a temporary route) rather than free-form administrative commands.

## 4. Embedded capabilities and external extensions

Nexus is normally operated in its self-contained configuration: AZ-01 Edge, M.I.O., Knowledge Lite, and Deception Lite are all available on the rugged Linux PC. External nodes are additive; losing them must return Nexus to its normal embedded capability rather than remove knowledge or redirection outright.

### 4.1 Embedded Tactical Knowledge Cache (Knowledge Lite)

Knowledge Lite is a bounded cache and short-term mission memory, not a replica of AZ-04. It retains the context required for standalone operation: recent high-confidence indicators, behavioural patterns, local allow/deny knowledge, minimal technique and vulnerability references, operator annotations, and recent incident/attacker-reaction history.

It emits a cited `ContextResult` such as `seen_before`, `behavior_hint`, `ioc_match`, `recent_history`, and confidence. Any recommended action is advisory-only. Its retention and size limits are mission-profile controlled.

### 4.2 Embedded Tactical Decoy Runtime (Deception Lite)

Deception Lite ensures a safe redirection destination exists without AZ-06. It hosts a deliberately small, isolated set of decoys—such as SSH, web, and an optional administration-facing service—on a dedicated decoy bridge. The default security rule is absolute: **decoy traffic cannot reach the protected network, host control plane, or Internet.**

Edge selects and enables redirection only through an arbiter-approved action. Lite telemetry is labeled separately in the Evidence Plane.

### 4.3 AZ-04 Azazel-Knowledge

Azazel-Knowledge supplies signed, versioned, mission-approved deep context: broader detection content, indicators, asset context, playbook references, retrieval material, and historical intelligence. It is an input to evaluators and M.I.O.; it has no enforcement authority.

The contract is pull-oriented where possible: Edge requests a content-addressed package, verifies signature and compatibility, merges eligible fresh context with Knowledge Lite, and records package version in its evidence ledger. Priority is fresh trusted AZ-04 context, then embedded cache, then no context. Important approved context is synchronized into a signed tactical bundle so loss of AZ-04 returns the node from `FULL` to `LITE`, not to an empty state.

### 4.4 AZ-06 Azazel-Deception

Azazel-Deception provides fuller, explicitly bounded decoy or engagement services in a segregated network zone. It receives only the configuration and event contracts needed for its mission. It cannot route to the protected network, issue Edge enforcement intents, or receive unrestricted evidence.

Deception telemetry returns to the Evidence Plane as a separately labeled source. Enabling, disabling, or reconfiguring a deception service requires an arbiter-approved policy action and an auditable receipt. Edge may select Lite for simple probes and AZ-06 for sustained or complex engagement. If AZ-06 becomes unavailable, it stops new full-node redirects and returns eligible redirect policy to Deception Lite.

## 5. M.I.O. dual cognition

M.I.O. is an explanatory and investigative assistant, not an enforcement mechanism. Its output schema is advisory: summary, confidence, cited evidence IDs, discrepancies, recommended next checks, and explicitly marked unknowns.

The detailed doctrine, operating states, route-selection modes, and data contracts are defined in [M.I.O. Dual Cognition](mio-dual-cognition.md). The governing invariant is simple: **M.I.O. may advise the Edge, but it never acquires authority to decide or enforce.**

### 5.1 Cognitive Router

The router selects a path based on connectivity, data classification, latency budget, model health, task type, and mission policy:

- **Local cognition:** an offline-capable, bounded local model processes locally available evidence and approved knowledge. It is the preferred path for sensitive data, disconnected operation, and fast operator assistance.
- **Remote cognition:** an online service is eligible only for a policy-permitted request after sanitization. It may provide deeper analysis or broader synthesis, but its answer is always advisory.
- **Dual path:** where policy allows, the router can obtain both views and ask the merger to expose agreement and disagreement.

### 5.2 Sanitizer

The sanitizer is a one-way boundary from the Edge trust zone to the remote cognition boundary. It enforces classification and minimization before any external request:

- allowlisted fields and structured task templates;
- removal or tokenization of identifiers, addresses, credentials, secrets, raw payloads, and location-sensitive fields;
- size and rate limits;
- policy-visible redaction log and request fingerprint;
- explicit deny on ambiguity or unavailable classification.

The remote path receives neither raw capture nor a management interface, secrets, enforcement intents, or write credentials. Remote responses are treated as untrusted content and cannot activate tools or alter policy.

### 5.3 Cognition Merger

The merger preserves provenance per claim and produces one operator-facing result:

```text
summary | confidence | evidence citations | disagreement | next checks | limitations
```

It never averages away disagreement. When local and remote views conflict, it highlights the conflict, favors evidence-backed deterministic findings for operational status, and proposes a bounded verification step.

## 6. Interface and backend abstraction

The user interface and service implementations are replaceable behind stable contracts.

| Boundary | Contract owner | Implementations may vary |
| --- | --- | --- |
| Sensor input | Nexus-local ingest envelope | Suricata, interface monitor, mission sensors |
| Evidence citation | **Fabric** `schema.evidence` | local encrypted store, replicated store |
| Evaluation | Nexus-local assessment; **Fabric** `schema.decision` for the operator-facing explanation | rules engine, approved analyzers |
| Enforcement | **Fabric** `schema.action` intent and plans; Nexus owns the receipt and lease state | nftables, tc, route/bridge adapter |
| Knowledge context | **Fabric** `cti_contracts` | Knowledge Lite cache, AZ-04 full node |
| Deception | **Fabric** `deception_contracts` | Deception Lite runtime, AZ-06 full host |
| Cognition | **Fabric** `mio_contracts` — *published in the pinned Fabric, not adopted here* | local model, remote provider, deterministic fallback |
| Operator UI | **Fabric** `view.status`; Nexus owns sessions and approval handling | touchscreen, external console, API client |
| Alerts | **Fabric** `notify.model`; Nexus owns the priority queue | local audio, visual UI, optional relay |
| Audit | **Fabric** `schema.audit` envelope; Nexus owns chain enforcement and anchoring | append-only ledger, signed checkpoints |
| Provisioning and commissioning | **Fabric** `provisioning_contracts` — *published in the pinned Fabric; `InterfaceIdentity` consumed, the rest not adopted*; Nexus owns admission, rendering, and activation | inventory, commissioning record, generation |

No interface allows a renderer, model, or module to bypass the arbiter. Backend selection is made at deployment configuration time and recorded in the system inventory.

## 7. Voice alert design

Voice alerts are concise, local, and acknowledgement-aware. The alert service subscribes only to arbiter outcomes and high-confidence health states, not raw model chatter.

- Severity levels have fixed cadence and interruption rules.
- Each message states condition, scope, and action/outcome; details remain in the UI.
- Repeats are suppressed by correlation key and escalation timer.
- An operator can acknowledge, silence a class for a bounded period, or choose visual-only mode.
- Audio failure is recorded and falls back to visual alerts; it never blocks enforcement.

Example: “Critical containment applied. Guest segment isolated. Verification pending.”

## 8. Security boundaries

```text
untrusted networks -> sensor boundary -> Edge evidence zone
                                            |
operator UI -> authenticated command boundary -> arbiter -> privileged enforcement zone
                                            |
mission modules -> signed/segmented module boundary
                                            |
remote cognition <- sanitized egress-only boundary
```

Key controls include secure boot or measured boot where hardware supports it; disk encryption; unique operator identities; role-based approval; signed policy and knowledge packages; separate service accounts; default-deny firewalling; encrypted transport; secrets held outside logs; clock-health monitoring; and append-only audit records with tamper-evident linkage.

## 9. Non-goals

- Autonomous, unbounded response generated by an AI model.
- A mission module gaining implicit control of the Edge node.
- Cloud availability as a prerequisite for local protection.
