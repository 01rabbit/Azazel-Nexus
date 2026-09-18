# Implementation Roadmap

This roadmap prioritizes proof of control and evidence integrity before richer assistance. Each phase has a demonstrable boundary and a safe rollback path.

## Phase 0 — Foundation

- Define the versioned event, evidence, assessment, enforcement-intent, receipt, and cognition-result schemas.
- Establish a reproducible rugged Linux PC baseline: disk encryption, service identities, network default deny, audited configuration, and recovery process.
- Build a lab topology that represents protected, observation, management, module, and egress zones.

**Exit criterion:** a fresh device can be provisioned, verified, and recovered using the written procedure.

## Phase 1 — Evidence and deterministic evaluation

- Integrate packet/sensor ingestion and normalized evidence storage.
- Implement NOC and SOC evaluators with citations to immutable evidence IDs.
- Add the append-only audit ledger and operator evidence viewer.

**Exit criterion:** a recorded scenario can be replayed and yields a traceable assessment without any model dependency.

## Phase 2 — Bounded enforcement

- Implement the Action Arbiter with signed policy packages, approval gates, scope/expiry limits, and idempotent intents.
- Add `nftables`, `tc`, routing, and bridge enforcement adapters with post-apply verification and receipts.
- Test rollback and adapter-failure handling in the lab.

**Exit criterion:** every supported containment action is demonstrably bounded, verified, audited, and reversible where policy declares it reversible.

## Phase 3 — Field console and alerts

- Deliver the touch-first operator UI, acknowledgement flows, evidence/decision views, and health display.
- Add local voice alerts with severity, suppression, and visual fallback.
- Exercise the field workflow and recovery kit using a field-standard resource tier.

**Exit criterion:** an operator can identify a state change, inspect its evidence, approve or decline a permitted action, and confirm its result without a terminal session.

## Phase 4 — Integrated capabilities and external expansion

- Deliver Knowledge Lite as a bounded, signed tactical cache and short-term mission memory.
- Deliver Deception Lite as an isolated embedded decoy runtime with arbiter-controlled redirection and no route to the protected network.
- Deliver signed AZ-04 package retrieval, context merge, tactical-bundle synchronization, and freshness labeling.
- Deliver AZ-06 segmentation, Lite/full destination selection, safe enable/disable control, and Lite fallback through the arbiter.
- Validate that loss of an external node returns Nexus to its embedded capability and that loss of either embedded service has a declared safe state.

**Exit criterion:** a Nexus operates detect-to-explain-to-redirect without external nodes; module loss, stale content, and invalid signatures result in visible constrained states with no expansion of authority.

## Phase 5 — M.I.O. dual cognition

- Add local cognition with a strict advisory schema and resource governor.
- Implement sanitizer policy, egress boundary, remote connector, request log, and deny-safe behavior.
- Build the router and merger, including disagreement presentation and evidence citations.

**Exit criterion:** the system remains fully operational offline; remote responses cannot invoke control-plane actions; and local/remote disagreement is visible to the operator.

## Phase 6 — Hardening and readiness

- Threat-model every trust boundary and test module, UI, remote-response, and adapter abuse cases.
- Perform endurance, thermal, disk-pressure, battery, interface-loss, clock-anomaly, and recovery exercises for each resource tier.
- Produce deployment runbooks, policy-authoring guidance, evidence-custody procedure, and release compatibility matrix.

**Exit criterion:** the documented failure modes have passing exercises, a known residual-risk register, and an approved field release checklist.

## Delivery principles

- Keep model capability optional and replaceable.
- Ship policy and enforcement changes behind lab-tested compatibility checks.
- Treat signatures, versioning, evidence references, and receipts as product features rather than operational afterthoughts.
- Do not introduce a new adapter or module without a defined degradation state and owner-visible health signal.
