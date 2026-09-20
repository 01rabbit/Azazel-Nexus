# Azazel-Nexus

**Azazel-Nexus** is the architecture and implementation space for a field-deployable Azazel system: a rugged Linux PC that can observe a network boundary, make deterministic defensive decisions locally, enforce approved actions, and explain what it did.

The system is designed around a simple operational rule:

> The field node remains safe and useful when disconnected.

Azazel-Edge is the core decision and enforcement node. Every Nexus contains an embedded tactical knowledge cache and an embedded decoy runtime, so it is a complete field node rather than a dependent controller. AZ-04 Azazel-Knowledge and AZ-06 Azazel-Deception extend retained context and engagement capacity when present. M.I.O. (Mission Intelligence Operator) provides a dual-cognition layer: local/offline assistance is always available within provisioned capacity, while remote/online assistance is an optional, sanitized enhancement.

## What this repository contains

- [System architecture](docs/architecture.md) — components, data paths, trust boundaries, and interface contracts.
- [Integrated-node doctrine](docs/nexus-integrated-node.md) — the self-contained Nexus baseline, embedded Lite services, and external expansion model.
- [M.I.O. dual cognition doctrine](docs/mio-dual-cognition.md) — the local/remote cognition model, safety invariants, operating states, and data contracts.
- [Operational design](docs/operations.md) — deployment kit, degradation states, resource envelopes, and failure handling.
- [Implementation roadmap](docs/roadmap.md) — staged delivery plan and acceptance criteria.
- [Implementation specification](docs/IMPLEMENTATION_SPEC.md) — deployable service boundaries, contracts, configuration, data, health, security, and recovery requirements.
- [Contract ownership](docs/contract-ownership.md) — which records belong to Azazel-Fabric, which are Nexus-local, which Fabric contracts do not exist yet, and the product admission sequence.
- [Capability model](docs/capability-model.md) — why effective capability is the intersection of resource, topology, verified assets, and trust/health, with worked examples.
- [Commissioning and activation](docs/commissioning.md) — composite interface identity, operator-confirmed roles, verified generations, and the management failsafe.
- [M.I.O. runtime control plane](docs/mio-runtime.md) — Nexus-owned provider admission, confinement, routing, deterministic sanitizer, fallback, and the per-dimension reasons published with each capability state.
- [Edge-to-Nexus inheritance ledger](docs/inheritance-ledger.md) — what Nexus inherits from Azazel-Edge, on what evidence, what is explicitly not inherited, and the gates a capability passes before adoption.
- [Support matrix](docs/support-matrix.md) — the platform envelope a release will have to declare, why the hardware compatibility list is empty, and what the program's documents leave undeclared.
- [Update channel](docs/update-channel.md) — signed online manifests and encrypted offline bundles, product-local release admission, and why no channel exists.
- [Knowledge Lite consumer](docs/knowledge-lite-consumer.md) — what the node does when a Lite artifact is missing, corrupt, or expired, and why that is a degradation to `CORE` rather than a fault.
- [Recovery](docs/recovery.md) — what a failed update, a failed activation, a lost asset, or a changed interface leaves behind, and what recovery may never restore.
- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) — how to report a defect in the target contract, and the review rules a change is judged against.

## System at a glance

```text
                         Mission operator
                                |
                        Touch UI / voice alerts
                                |
     +---------------------------------------------------------+
     | AZAZEL-NEXUS — rugged Linux integrated node            |
     |                                                         |
     |  AZ-01 Edge: Observe -> Evidence -> Core -> Arbiter     |
     |                                   |             |       |
     |                            M.I.O. cognition    Enforce  |
     |                              local / remote    tc/nft   |
     |              Knowledge Lite / Deception Lite            |
     +-----------------------+--------------------+------------+
                             |                    |
                    optional mission links   protected boundary
                             |                    |
             +---------------+---+          WAN / LAN / Wi-Fi
             |                   |
   AZ-04 Azazel-Knowledge   AZ-06 Azazel-Deception
```

## Design commitments

- **Linux-first field appliance.** The target is a generic rugged x86_64 Linux PC with serviceable storage, battery power, touchscreen or external display support, and controllable network interfaces.
- **Deterministic control plane.** Models may summarize, prioritize, or recommend; only policy-bound deterministic logic can authorize enforcement.
- **Offline-safe default.** Loss of cloud access, a mission module, or an AI service never disables local evidence collection, policy evaluation, audit, or configured containment.
- **Evidence before interpretation.** Raw artifacts, normalized events, decisions, and enforcement results are correlated and retained with provenance.
- **Least disclosure.** External cognition receives only data produced by a mission-specific sanitizer and never gets enforcement credentials or direct control-plane access.
- **Self-contained first.** Knowledge Lite and Deception Lite are normal embedded capabilities, not external prerequisites. Full external nodes expand depth and endurance through explicit contracts and cannot expand the core node's authority.
- **Fabric owns the shared contracts.** Nexus does not define a canonical form for any record that crosses a product boundary; it consumes Azazel-Fabric behind an exact release pin and owns only what it performs on the host.
- **Capacity is not capability.** RAM selects a resource envelope and nothing more. Capture, enforcement, and Deception additionally require commissioned interfaces, verified assets, and current trust — evaluated independently and intersected.
- **Roles are confirmed, never inferred.** An interface gets a logical role only through read-only inventory plus explicit operator confirmation against a composite identity, never from an interface name, link state, or default route.

## Azazel role model

> **Fabric describes. Knowledge advises. Edge decides and enforces. Deception materializes an Edge-approved environment. Nexus integrates released components without creating another decision authority.**

Or, from the operator's side of the console:

> **Edge decides. M.I.O. understands and explains. Knowledge remembers. Deception provides the engagement space.**

This division is intentional. It keeps the authority to change the field boundary in one deterministic place, while allowing the operator to benefit from richer context and analysis. `CORE`, `LITE`, and `FULL` describe how much capability is currently available; they never describe how much authority anything holds.

## Status

**Target contract.** It carries a package (`pyproject.toml`,
`src/azazel_nexus/`) with a deliberately empty required-dependency list, a unit
suite, and an exact **Azazel-Fabric pin as an optional extra** (`v0.9.0rc2`,
ADR-0001), consumed through one boundary module. One mapping is attested by
that boundary — capability/mode publication; every other contract mapping
remains a design assertion awaiting a conformance attestation, not verified
evidence. It now publishes
a license, a security policy, a contribution guide, a
[support matrix](docs/support-matrix.md), an
[update channel](docs/update-channel.md) description, and a
[recovery procedure](docs/recovery.md) — each of which describes what a release
will have to carry, and none of which is exercised or evidenced.

**What is implemented, in this repository's own vocabulary** (code and focused
tests exist — not *verified*, which requires a declared evidence gate to have
passed): the CORE path from inventory to activation. Hardware inventory,
resource-profile selection, the commissioning record, generations with a
re-derivable digest, the hash-chain audit ledger, the activation controller and
its privilege boundary, the filesystem layout the installer applies, and the
`azazel-nexus` operator CLI (`inventory`, `profile`, `commission`, `status`,
`health`) — every subcommand answerable with no network — and the
[degradation matrix](docs/degradation-matrix.md): 8 conditions × 5 failure
modes, each asserting that no optional component's failure subtracts a core
capability.

**What is not.** No daemon executable is built, so nothing here runs as a
service — and because reading an interface's permanent MAC needs a privileged
driver query this package does not make, commissioning cannot be completed on a
real host by this build alone (`HG-04`). The wizard says so rather than falling
back to the current MAC. The claims that depend on a real host — that installation leaves the
operational units masked, that only the activation controller can unmask one,
that an observation interface transmits nothing — are open and registered in
[hardware gates](docs/hardware-gates.md). A green pipeline is evidence about
Python. No statement in this repository may be cited as operational evidence,
and a simulated result is never a measured one.

The outstanding bootstrap work is listed in
[contract ownership](docs/contract-ownership.md) §6 and sequenced as Phase 0 of
the [roadmap](docs/roadmap.md). Production components should be implemented
incrementally according to that roadmap, with each enforcement capability
tested first in a controlled lab topology.

Terms used for status across these documents have fixed meanings: *target
contract* (intended behavior, no release evidence), *implemented* (code and
focused tests exist), *verified* (a declared evidence gate has passed),
*supported* (documented release, security posture, and operational evidence
exist), *experimental* (bounded concept or HIL work), and *retired*
(intentionally not inherited).

## License

MIT — see [LICENSE](LICENSE).
