# Security Policy

Azazel-Nexus Gateway (`AZ-07`) is a persistent, self-contained installation on
a generic rugged x86_64 Linux PC. It integrates released Azazel components; it
is never a second decision or enforcement authority. Azazel-Edge's
deterministic arbiter holds that authority in every capability state.

## Reporting a vulnerability

Report privately via GitHub Security Advisories:
<https://github.com/01rabbit/Azazel-Nexus/security/advisories/new>

Do **not** open a public issue for a suspected vulnerability.

Include: the affected commit, the document and section concerned, the concrete
path by which the stated design fails, and the observed or derived impact.
Sanitize anything you attach — strip keys, passphrases, recovery material,
commissioning records, host and site identifiers, and real incident data.

No bounty program. Reporters are credited unless anonymity is requested.

## Response targets

- Acknowledgement: within 7 days
- Initial assessment (severity, affected documents): within 14 days
- Fix and disclosure are coordinated with the reporter.

## What a report against Nexus means today — read this first

This repository contains **no product code**. There is no package, no
dependency manifest, no Azazel-Fabric pin, no installer, and no release.
Nothing here is implemented or verified; see
[contract ownership](docs/contract-ownership.md) §6.

There is therefore no running Azazel-Nexus in which to find a runtime
vulnerability. What can be reported today is a **defect in the target
contract**: a documented design that, if built as written, would violate one of
the invariants below. Such a report is in scope and is handled as a security
report, because these documents are what an implementer will build from.

The remedy for an accepted report is correspondingly documentary:

1. a change to the Nexus document that states the defective design, in the
   section the report names; and
2. where the defect originates above this repository — in the authority model,
   the admission sequence, the RAM selector's numbers, or any other rule Nexus
   inherits rather than owns — a finding (`OF-xx`) raised against
   [§15 of the program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md#15-open-program-findings),
   using the fields that section requires: severity, evidence, affected
   requirement, proposed correction, owner, and verification.

Nexus MUST NOT correct an inherited rule by quietly diverging from it locally.
A finding stays open and unedited in substance until the owner decides, so that
no product silently implements a different rule.

## The authority boundary is a security property

> Fabric describes. Knowledge advises. **Edge decides and enforces.** Deception
> materializes an Edge-approved environment. Nexus integrates released
> components without creating another decision authority.

A defect that would let Azazel-Nexus — or M.I.O., a local or remote model, a
capability report, a deployment overlay, a package manifest, a module peer, or
the operator UI — **decide or enforce anything that Edge's arbiter did not
decide** is treated as **critical**, regardless of how narrow the path is or
how degraded Edge is at the time. The whole system's safety argument rests on
that single boundary, so a break in it is not weighed against operational
convenience.

Two corollaries, so that neither is argued as an exception:

- Nexus is never a fallback authority. Edge being absent, slow, or degraded
  removes capability from the intersection and grants Nexus nothing.
- `FULL`, `LITE`, and `CORE` are capability states, not authority levels.
  A report that a degraded state confers additional latitude is a report of a
  critical defect, not a description of intended behavior.

## In scope

Defect classes specific to this product's invariants, whether found in a future
implementation or in the documented design:

- **Authority escalation**: any path by which an advisory, a recommendation, a
  manifest, an overlay, a receipt, a capability report, or a UI action reaches
  enforcement without an arbiter decision; any design in which a service can
  hold the arbiter's intent-signing credential and an enforcement-adapter
  privilege at the same time.
- **Capability-gating bypass**: enabling capture, enforcement, Deception, a
  module link, or remote cognition from a resource measurement alone, or from
  any single dimension rather than the intersection of resource profile,
  topology profile, verified asset set, and trust/health state.
- **Role inference**: assigning a logical interface role from an interface
  name, carrier state, default route, autoconfigured address, or resource
  measurement rather than from read-only inventory plus explicit operator
  confirmation against a composite identity; accepting MAC-only matching;
  silently rebinding a changed or ambiguous identity instead of returning the
  affected capability to `COMMISSIONING_REQUIRED`.
- **Observation-path leakage**: any design under which an interface
  commissioned to the observation role can transmit a frame, or under which a
  nonzero transmit count does not withdraw the capture capability.
- **Activation and generation bypass**: an old-generation replay, a replaced
  renderer, a substituted path, a parallel boot race, or a service-default
  fallback that produces an operational packet or action; operational units
  reachable without a verified generation; an activation failure that leaves
  exposure in place rather than reporting `ROLLBACK_INCOMPLETE`.
- **Overlay privilege escalation**: a deployment overlay that can change Edge
  action policy, approval requirements, lease ceilings, trust roots,
  signing-key locations, commands, routes, firewall rules, services, container
  mounts or capabilities, or any authority field, instead of being the
  monotonic reduction it is specified to be.
- **Admission bypass**: acceptance of an artifact that matches no exact tested
  compatibility tuple, that is signed by the wrong delegated role, that is
  correctly signed but obsolete, or that is below the minimum security epoch;
  treating a broad version range as authorization; an extractor that accepts
  traversal paths, links, devices, nested archives, or undeclared output.
- **Asset-acquisition escape**: a design in which the bounded
  `ASSET_ACQUISITION` state can reach the protected, observation, decoy, or
  management zones, listen, forward, associate beyond its declared bound, or
  leave routes, credentials, DNS, proxy state, or wireless association behind.
- **Decoy containment failure**: a decoy path to the protected, management,
  control-plane, or Internet zones; isolation drift that does not withdraw the
  route within its declared bound; Deception eligible without continuous
  isolation attestation.
- **Sanitizer and egress defects**: unsanitized evidence, identifiers, or
  policy material reaching remote cognition; a remote response that can invoke
  a control-plane action; sensitive raw data queued for later upload after an
  egress failure.
- **Audit and custody defects**: a break in hash-chain continuity that is not
  visible; a `LOCAL_CONTINUITY_ONLY` session presented as rollback-verified; a
  recovery authority able to sign ordinary field checkpoints or hide a
  discontinuity; an export whose provenance or assurance label overstates what
  was demonstrated.
- **Lease and management-path defects**: a lease that survives reboot without
  reauthorization or that can be extended by a clock jump; an enforcement
  action able to sever the management path used to supervise it; a high-impact
  change that commits without the two-stage acknowledgement.

## Out of scope

- **Azazel-Edge's deterministic arbitration and enforcement semantics.**
  Report those to [Azazel-Edge](https://github.com/01rabbit/Azazel-Edge).
  Nexus states conditions on the Edge package it admits; it does not define
  arbitration.
- **Shared contract defects** — canonical form, serialization, digests,
  validation, or fixtures. Report those to
  [Azazel-Fabric](https://github.com/01rabbit/Azazel-Fabric), which owns every
  record that crosses a product boundary.
- **Defects in the deployed products Nexus merely integrates**: Azazel-Knowledge
  intelligence content, bundle production, and false positives;
  Azazel-Deception package behavior and lifecycle. Report those to their own
  repositories. What belongs here is Nexus's *admission, confinement, and
  degradation* of those products.
- **The absence of a feature.** Nothing is implemented; "Azazel-Nexus does not
  do X" is the current state, not a vulnerability.
- **Degraded operation when an optional component is absent.**
  `FULL -> LITE -> CORE` degradation is the designed behavior, and a node that
  reports observe-only because its topology does not permit enforcement is
  behaving correctly.
- **Hardware that no one has tested.** The hardware compatibility list is empty
  (see [support matrix](docs/support-matrix.md)), so a firmware quirk, driver
  problem, or measurement shortfall on a specific rugged PC is not a security
  defect today.

## Supported versions

None. There are no releases, no tags, no signing keys, and no supported
configuration. Only `main` exists; report against the commit you read. Nothing
in this repository may be described as operationally certified or supported.
