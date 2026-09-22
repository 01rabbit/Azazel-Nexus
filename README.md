# Azazel-Nexus

**Azazel-Nexus** is the architecture and implementation space for a field-deployable Azazel system: a rugged Linux PC that can observe a network boundary, make deterministic defensive decisions locally, enforce approved actions, and explain what it did.

The system is designed around a simple operational rule:

> The field node remains safe and useful when disconnected.

Azazel-Edge is the core decision and enforcement node. Every Nexus contains an embedded tactical knowledge cache and an embedded decoy runtime, so it is a complete field node rather than a dependent controller. AZ-04 Azazel-Knowledge and AZ-06 Azazel-Deception extend retained context and engagement capacity when present, and neither adds authority the node did not already have.

## Where the product stands

Each row says what exists **today**, in this repository's own vocabulary. The
words are fixed: *target contract* (intended behavior, no release evidence),
*implemented* (code and focused tests exist), *verified* (a declared evidence
gate has passed), *supported* (documented release, security posture and
operational evidence exist). See the
[support matrix](docs/support-matrix.md) §7.

| Capability | State today |
| --- | --- |
| **Edge Core verification and activation** | software implementation complete; hardware-unverified. The package check, the generation, the audit chain and the activation controller with its privilege boundary are implemented and tested; no claim about what systemd enforces has been evidenced ([hardware gates](docs/hardware-gates.md)) |
| **Knowledge Lite** | functional: a correct bundle is imported offline by an operator and its claims served read-only. Not a release, and not a statement about this node's cryptographic implementation ([the consumer](docs/knowledge-lite-consumer.md)) |
| **Deception Lite** | **loopback-only.** The lifecycle and a functional layer bound to a private Unix socket are implemented. External reachability, redirection and field engagement are **not demonstrated** ([Deception Lite](docs/deception-lite.md)) |
| **M.I.O. (Mission Intelligence Operator)** | M.I.O. routing and commissioning control plane implemented; provider execution unavailable pending hardware evidence and provider integration ([runtime control plane](docs/mio-runtime.md)) |
| **Platform baseline** | **Debian 13 / amd64**, fixed for v1 ([program plan §15 OF-07](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md), adopted in [ADR-0002](docs/adr/0002-debian-13-baseline.md)). Nothing has been installed from it: no host, no image, no measurement. Ubuntu, Fedora and the RHEL family are a [future evaluation profile](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/future-platform-profiles.md), not a v1 support target |
| **Installer and HIL preflight** | target-local preflight implemented (`azazel-nexus hil-preflight`), and it refuses a host off the baseline; **8 GiB target evidence pending** ([HIL preflight](docs/hil-preflight.md), [Nexus #115](https://github.com/01rabbit/Azazel-Nexus/issues/115)) |
| **AZ-04 Knowledge / AZ-06 Deception** | optional expansion. They extend depth and endurance through explicit contracts and **do not increase the baseline node's authority** ([integrated-node doctrine](docs/nexus-integrated-node.md)) |

**What this does not say.** No measurement of the Core reserve exists on any
memory class, so every local model provider is refused at the resource gate
([`HG-05`](docs/hardware-gates.md)). Nothing here has been run on the target
hardware — a generic rugged x86_64 Linux PC at the resource class deployed,
which is what every hardware gate means by the phrase. A green pipeline is
evidence about Python, and a simulated result is never a measured one.

## What runs on a node

The operator CLI, `azazel-nexus`, answers every subcommand with no network:

| subcommand | what it answers |
| --- | --- |
| `inventory` | the read-only hardware and interface list |
| `profile` | measured RAM and the resource envelope it selects |
| `commission` | role assignment, with explicit operator confirmation |
| `status` | everything above, as it currently stands |
| `health` | units and the audit chain |
| `hil-preflight` | whether the 8 GiB HG-05 campaign may start on this node. It takes **no arguments**, no sample, and reboots or activates nothing |

The privileged half is a **separate distribution**, `azazel-nexus-runtime`
(`runtime/`): daemons that speak Unix domain sockets, identify callers from
the kernel's peer credentials, and take no arbitrary command, unit name, path
or argument. The dependency runs one way — see
[the runtime boundary](docs/runtime-boundary.md).

Installation leaves every operational unit **masked**; the activation
controller is the one unit the preset enables, and it opens no socket and
reaches no interface. Whether systemd enforces that is `HG-01`/`HG-02` and is
open.

## Design commitments

- **Linux-first field appliance.** The target is a generic rugged x86_64 Linux PC with serviceable storage, battery power, touchscreen or external display support, and controllable network interfaces, running the program's platform baseline — **Debian 13 / amd64**, with LUKS2 required and Secure Boot enabled where the machine supports it.
- **Deterministic control plane.** Models may summarize, prioritize, or recommend; only policy-bound deterministic logic can authorize enforcement.
- **Offline-safe default.** Loss of cloud access, a mission module, or an AI service never disables local evidence collection, policy evaluation, audit, or configured containment.
- **Evidence before interpretation.** Raw artifacts, normalized events, decisions, and enforcement results are correlated and retained with provenance.
- **Least disclosure.** External cognition receives only data produced by a mission-specific sanitizer and never gets enforcement credentials or direct control-plane access.
- **Self-contained first.** Knowledge Lite and Deception Lite are normal embedded capabilities, not external prerequisites. Full external nodes expand depth and endurance through explicit contracts and cannot expand the core node's authority.
- **Fabric owns the shared contracts.** Nexus does not define a canonical form for any record that crosses a product boundary; it consumes Azazel-Fabric behind an exact release pin (`v0.9.0rc2`, ADR-0001) as an optional extra, through one boundary module.
- **Capacity is not capability.** RAM selects a resource envelope and nothing more. Capture, enforcement, and Deception additionally require commissioned interfaces, verified assets, and current trust — evaluated independently and intersected.
- **Roles are confirmed, never inferred.** An interface gets a logical role only through read-only inventory plus explicit operator confirmation against a composite identity, never from an interface name, link state, or default route.
- **Identity has one home.** Permanent MACs, serials, TPM identity and asset IDs live in the encrypted commissioning record and nowhere else — not the terminal, the journal, the audit or a report ([inventory confidentiality](docs/inventory-confidentiality.md)).

## Azazel role model

> **Fabric describes. Knowledge advises. Edge decides and enforces. Deception materializes an Edge-approved environment. Nexus integrates released components without creating another decision authority.**

Or, from the operator's side of the console:

> **Edge decides. M.I.O. understands and explains. Knowledge remembers. Deception provides the engagement space.**

This division is intentional. It keeps the authority to change the field boundary in one deterministic place, while allowing the operator to benefit from richer context and analysis. `CORE`, `LITE`, and `FULL` describe how much capability is currently available; they never describe how much authority anything holds.

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

## Documents

**Start here**

- [System architecture](docs/architecture.md) — components, data paths, trust boundaries, and interface contracts.
- [Integrated-node doctrine](docs/nexus-integrated-node.md) — the self-contained Nexus baseline, embedded Lite services, and external expansion model.
- [Capability model](docs/capability-model.md) — why effective capability is the intersection of resource, topology, verified assets, and trust/health.

**What the node does on a host**

- [Commissioning and activation](docs/commissioning.md) — composite interface identity, operator-confirmed roles, verified generations, and the management failsafe.
- [HIL preflight](docs/hil-preflight.md) — one command on the target that answers whether the 8 GiB campaign may begin, and what it refuses to print.
- [Inventory confidentiality](docs/inventory-confidentiality.md) — what is collected, where it is kept, and what may leave.
- [Runtime boundary](docs/runtime-boundary.md) · [Operational design](docs/operations.md) · [Recovery](docs/recovery.md).

**Cognition**

- [M.I.O. dual cognition doctrine](docs/mio-dual-cognition.md) · [M.I.O. runtime control plane](docs/mio-runtime.md) · [the sanitizer](docs/mio-sanitizer.md) · [remote inference](docs/remote-inference.md) · [remote commissioning](docs/remote-commissioning.md).

**Evidence and gates**

- [Hardware gates](docs/hardware-gates.md) — the claims that need a real host, and which of them are open.
- [Deployment candidates](docs/deployment-candidates.md) — what a target machine has to be, and why no machine is named.
- [Core reserve measurement](docs/core-reserve-measurement.md) — the procedure that would close `HG-05`, and the shape the result has to take.
- [Integration evidence](docs/integration-evidence.md) · [Edge package verification](docs/edge-package-verification.md) · [degradation matrix](docs/degradation-matrix.md).

**Contracts and release**

- [Contract ownership](docs/contract-ownership.md) · [Implementation specification](docs/IMPLEMENTATION_SPEC.md) · [Support matrix](docs/support-matrix.md) · [Update channel](docs/update-channel.md) · [Inheritance ledger](docs/inheritance-ledger.md).

**Plan**

- [Implementation roadmap](docs/roadmap.md) — the staged delivery plan. It describes what is intended, not what exists; this page's table is what exists.

**Project**

- [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
