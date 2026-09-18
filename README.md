# Azazel-Nexus

**Azazel-Nexus** is the architecture and implementation space for a field-deployable Azazel system: a rugged Linux PC that can observe a network boundary, make deterministic defensive decisions locally, enforce approved actions, and explain what it did.

The system is designed around a simple operational rule:

> The field node remains safe and useful when disconnected.

Azazel-Edge is the core decision and enforcement node. Azazel-Knowledge and Azazel-Deception are optional mission modules that extend the node without becoming prerequisites for safe local operation. M.I.O. (Mission Intelligence Operator) provides a dual-cognition layer: local/offline assistance is always available within provisioned capacity, while remote/online assistance is an optional, sanitized enhancement.

## What this repository contains

- [System architecture](docs/architecture.md) — components, data paths, trust boundaries, and interface contracts.
- [Operational design](docs/operations.md) — deployment kit, degradation states, resource tiers, and failure handling.
- [Implementation roadmap](docs/roadmap.md) — staged delivery plan and acceptance criteria.

## System at a glance

```text
                         Mission operator
                                |
                        Touch UI / voice alerts
                                |
     +---------------------------------------------------------+
     | AZ-01  Azazel-Edge — rugged Linux PC                   |
     |                                                         |
     |  Observe -> Evidence -> Deterministic Core -> Arbiter   |
     |                                   |             |       |
     |                            M.I.O. cognition    Enforce  |
     |                              local / remote    tc/nft   |
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
- **Modular missions.** Knowledge and deception capabilities connect through explicit contracts, are independently degradable, and cannot expand the core node's authority.

## Explicit scope boundaries

This architecture does **not** support Android platforms. It also contains no event-specific deployment or marketing assumptions; the system is documented as an operational field capability.

## Status

The repository currently captures the architecture and delivery plan. Production components should be implemented incrementally according to the roadmap, with each enforcement capability tested first in a controlled lab topology.

## License

No license has been selected yet. Do not assume permission to use, redistribute, or contribute code until a license is added.
