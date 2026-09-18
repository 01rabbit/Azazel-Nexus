# Azazel-Nexus Architecture

## 1. Purpose and doctrine

Azazel-Nexus is a portable defensive system built around a rugged Linux PC deployed at a network edge. It must provide situational awareness, bounded response, and a defensible explanation of every consequential action even when there is no upstream connection.

The architecture separates three concerns deliberately:

1. **Observation and evidence** capture what was seen without allowing analytics to overwrite it.
2. **Decision and enforcement** evaluate declared policy deterministically and apply only authorized controls.
3. **Cognition** helps humans understand and investigate the situation, but never becomes a direct actuator.

AZ-01 Azazel-Edge is the system of record for the first two concerns. Mission modules and M.I.O. enrich the third concern through constrained interfaces.

## 2. Deployment topology

```text
                         operator plane
                    +-------------------+
                    | touch UI / audio  |
                    +---------+---------+
                              |
 +----------------------------+-----------------------------+
 | AZ-01 Azazel-Edge: rugged Linux PC                        |
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
 |                  M.I.O. Cognitive Router                    |
 |                    |                 |                     |
 |                 local model       Sanitizer --> remote API  |
 |                    +-------- Cognition Merger --------+    |
 +----------------------------+-----------------------------+
              |                                     |
      AZ-04 Azazel-Knowledge                AZ-06 Azazel-Deception
      signed intelligence/context            isolated engagement services
```

The rugged PC is a class of hardware, not a named device dependency. A field build should use an x86_64 Linux-compatible unit with at least two independently manageable network interfaces, a TPM where available, hardware-backed or disk-encrypted storage, battery power, and an operator-accessible display. USB radios and adapters are treated as replaceable mission equipment, not part of the trusted computing base.

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

## 4. Mission modules

### 4.1 AZ-04 Azazel-Knowledge

Azazel-Knowledge supplies signed, versioned, mission-approved context: detection content, indicators, asset context, playbook references, and local retrieval material. It is an input to evaluators and M.I.O.; it has no enforcement authority.

The contract is pull-oriented where possible: Edge requests a content-addressed package, verifies signature and compatibility, then records the package version in its evidence ledger. If unavailable, Edge retains its currently active, verified package and exposes the resulting freshness state.

### 4.2 AZ-06 Azazel-Deception

Azazel-Deception provides explicitly bounded decoy or engagement services in a segregated network zone. It receives only the configuration and event contracts needed for its mission. It cannot route to the protected network, issue Edge enforcement intents, or receive unrestricted evidence.

Deception telemetry returns to the Evidence Plane as a separately labeled source. Enabling, disabling, or reconfiguring a deception service requires an arbiter-approved policy action and an auditable receipt.

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

| Boundary | Contract | Implementations may vary |
| --- | --- | --- |
| Sensor input | versioned normalized event envelope | Suricata, interface monitor, mission sensors |
| Evidence | append-only artifact and correlation API | local encrypted store, replicated store |
| Evaluation | evidence in; assessment with citations out | rules engine, approved analyzers |
| Enforcement | scoped idempotent intent and receipt | nftables, tc, route/bridge adapter |
| Cognition | advisory request/result schema | local model, remote provider, deterministic fallback |
| Operator UI | read model plus approval/acknowledgement commands | touchscreen, external console, API client |
| Alerts | severity, message, repeat and acknowledgement contract | local audio, visual UI, optional relay |

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

- Android platform support.
- Autonomous, unbounded response generated by an AI model.
- A mission module gaining implicit control of the Edge node.
- Cloud availability as a prerequisite for local protection.
