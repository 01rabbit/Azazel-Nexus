# Implementation Roadmap

This roadmap prioritizes proof of control and evidence integrity before richer assistance. Each phase has a demonstrable boundary and a safe rollback path.

Status: **target contract**. No phase below has started in this repository.

## Phase 0 — Repository and contract bootstrap

- Publish license, security policy, contribution guide, package layout,
  dependency manifest, and CI. **Done**: the license, the security policy, the
  contribution guide, the [support matrix](support-matrix.md),
  [update channel](update-channel.md) and [recovery](recovery.md) documents the
  R0 exit criteria name, and — with the Knowledge Lite consumer — the package
  layout, the dependency manifest, and a CI unit suite beside the
  documentation link check. See [contract ownership](contract-ownership.md) §6
  for what is left.
- Adopt an **exact Azazel-Fabric release pin** and build adapters against the
  Fabric-owned records that already exist. Nexus does not define shared
  schemas. This item is the one remaining bootstrap row and nothing else in
  Phase 0 waits on Fabric any more: `provisioning_contracts` and
  `mio_contracts` were the two missing families, and both have existed since
  `v0.9.0rc1`. What is unblocked is the *work*, not the mapping — a released
  module is something to write an adapter against, not evidence that any
  §3 mapping holds.
- Establish a reproducible rugged Linux PC baseline: disk encryption, service
  identities, network default deny, audited configuration, and recovery
  process.
- Build a lab topology that represents protected, observation, management,
  decoy, and egress zones.

**Exit criterion:** the repository can produce a pinned, signed artifact, and every record it exchanges is traceable to a Fabric release or is explicitly marked Nexus-local.

## Phase 0b — Inventory, commissioning, and activation

- Implement read-only hardware and interface inventory with composite identity
  and fail-closed ambiguity handling. **Interfaces done**
  (`src/azazel_nexus/inventory.py`): the nine composite components are read,
  the kernel name is recorded and excluded from identity, and an interface
  whose identity cannot be established is returned with its reasons rather than
  guessed. The matching rule is **not** restated here — it is applied by
  Fabric's `resolve_interface_assignment` through the boundary module. Hardware
  inventory beyond interfaces (`HardwareInventory`, `ResourceProfile`) is not
  started.

  The permanent MAC needs the `ETHTOOL_GPERMADDR` ioctl and no interface has
  been commissioned, so the default reader reads nothing and every interface
  resolves to `COMMISSIONING_REQUIRED`. That is the correct answer for a host
  whose identity has not been read, not a gap being papered over.
- Implement operator-confirmed logical role assignment and the signed
  commissioning record. No role is inferred from name, link state, or route.
  **Assignment done** (`src/azazel_nexus/commissioning.py`,
  `fabric_boundary.confirm_role`): a proposal reports which interfaces carry an
  unambiguous composite identity and what an operator can physically check
  about each, and pairs none of them with a role. One confirmation becomes a
  Fabric `InterfaceAssignment`; every argument is required, so Nexus cannot
  produce one without being told who confirmed, how, and when. The role
  vocabulary is Fabric's registered set — see
  [commissioning](commissioning.md) §4 for the four lists that preceded it.

  **The signed record is not producible yet, by measurement rather than by
  omission.** `CommissioningRecord` requires `resource_profile_digest` and
  `topology_profile_digest`; Nexus produces neither, and a placeholder would
  make the record's own digest vouch for profiles that do not exist. The
  boundary refuses and names what is missing. It becomes possible when
  `ResourceProfile` and `TopologyProfile` do.
- Implement the product admission policy: delegated trust roles, exact tested
  compatibility tuples, security epoch, and the bounded extractor.
- Implement the activation controller, verified generations, preset-disabled
  units, staged rendering, and the management failsafe.

**Exit criterion:** a fresh device can be inventoried, commissioned, activated, verified, and recovered using the written procedure; before a verified generation exists it starts no operational network service and transmits nothing outside the bounded asset-acquisition state.

## Phase 1 — Evidence and deterministic evaluation

- Integrate packet/sensor ingestion and normalized evidence storage.
- Implement NOC and SOC evaluators with citations to immutable evidence IDs.
- Add the append-only audit ledger, signed checkpoints, the independent anchor, and the operator evidence viewer.

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

- Add local cognition with a resource governor, using the Fabric `mio_contracts` advisory shape once it is adopted (it is published in the pinned Fabric, not adopted here).
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
