# Azazel-Nexus

**Azazel-Nexus** is the architecture and implementation space for a field-deployable Azazel system: a rugged Linux PC that can observe a network boundary, make deterministic defensive decisions locally, enforce approved actions, and explain what it did.

The system is designed around a simple operational rule:

> The field node remains safe and useful when disconnected.

Azazel-Edge is the core decision and enforcement node. Every Nexus contains an embedded tactical knowledge cache and an embedded decoy runtime, so it is a complete field node rather than a dependent controller. AZ-04 Azazel-Knowledge and AZ-06 Azazel-Deception extend retained context and engagement capacity when present. M.I.O. (Mission Intelligence Operator) provides a dual-cognition layer: local/offline assistance is always available within provisioned capacity, while remote/online assistance is an optional, sanitized enhancement.

## What this repository contains

- [System architecture](docs/architecture.md) — components, data paths, trust boundaries, and interface contracts.
- [Integrated-node doctrine](docs/nexus-integrated-node.md) — the self-contained Nexus baseline, embedded Lite services, and external expansion model.
- [M.I.O. dual cognition doctrine](docs/mio-dual-cognition.md) — the local/remote cognition model, safety invariants, operating states, and data contracts.
- [Operational design](docs/operations.md) — deployment kit, degradation states, resource tiers, and failure handling.
- [Implementation roadmap](docs/roadmap.md) — staged delivery plan and acceptance criteria.
- [Implementation specification](docs/IMPLEMENTATION_SPEC.md) — deployable service boundaries, contracts, configuration, data, health, security, and recovery requirements.

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

## Azazel role model

> **Edge decides. M.I.O. understands and explains. Knowledge remembers. Deception provides the engagement space.**

This division is intentional. It keeps the authority to change the field boundary in one deterministic place, while allowing the operator to benefit from richer context and analysis.

## Status

The repository currently captures the architecture and delivery plan. Production components should be implemented incrementally according to the roadmap, with each enforcement capability tested first in a controlled lab topology.

## License

No license has been selected yet. Do not assume permission to use, redistribute, or contribute code until a license is added.
