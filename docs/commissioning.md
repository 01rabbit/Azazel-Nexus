# Commissioning and Activation

Status: **target contract**. No commissioning or activation code exists in this
repository.

Related: [Capability model](capability-model.md) ·
[Contract ownership](contract-ownership.md) ·
[Inventory confidentiality](inventory-confidentiality.md) ·
[Implementation specification](IMPLEMENTATION_SPEC.md)

Commissioning is how an Azazel-Nexus learns what its network actually is.
Activation is how a commissioned node is allowed to run operational services.
Both are product-local: they have side effects, so Azazel-Fabric describes
their records but never performs them.

## 1. What Nexus does not inherit

Azazel-Edge ships a device-specific network installer for constrained-device
deployments. That installer encodes fixed interface names, fixed addressing,
and device-specific unit defaults.

Nexus MUST NOT invoke it, import it, reimplement it, or inherit its values.
Nexus targets generic rugged x86_64 hardware whose interface layout is unknown
until inventory, so any inherited fixed value would be a guess presented as a
fact. Edge's installer remains a supported compatibility path for its own
constrained-device profiles; a Nexus package or profile MUST NOT be able to
select it.

Nexus consumes Edge as a released, signed package with an explicit adapter.
See [contract ownership](contract-ownership.md) §5.

## 2. Inventory is read-only

Inventory runs before any role exists. It reads hardware and interface facts
and writes nothing to the network.

During inventory and until activation completes, the node MUST NOT:

- transmit any frame on any interface outside the bounded `ASSET_ACQUISITION`
  state described in §6;
- associate with a wireless network;
- forward, bridge, or route;
- start capture, enforcement, Deception, module links, or remote cognition;
- run DHCP clients, router-solicitation, mDNS, LLDP, or any autoconfiguration.

Operational units are installed **preset disabled** and remain unavailable
until §7 unmasks them for a verified generation.

## 3. Composite interface identity

An interface is identified by a **composite identity**, never by a kernel name
and never by MAC address alone:

| Component | Purpose |
| --- | --- |
| bus path (PCI path or USB topology path) | physical slot continuity |
| permanent MAC (`ethtool -P`, not the current MAC) | adapter continuity |
| VID/PID or PCI vendor/device identity | adapter model |
| serial number where the device exposes one | individual adapter |
| driver and firmware version | behavior continuity |
| wireless PHY identity where applicable | radio continuity |
| physical label recorded by the operator | human continuity |

Matching rules are fail-closed:

- **exactly one** match: the interface is identified;
- **zero** matches: the affected capability returns to
  `COMMISSIONING_REQUIRED`;
- **more than one** match: ambiguity. The node refuses to choose, returns the
  affected capability to `COMMISSIONING_REQUIRED`, and reports the competing
  candidates to the operator.

MAC-only matching is insufficient and MUST NOT be accepted as an identity.

**These rules are applied by Fabric, not restated by Nexus.**
`azazel_nexus.fabric_boundary.identify_interface` calls
`azazel_fabric.provisioning_contracts.resolve_interface_assignment`, which
treats zero matches and several as the same fail-closed answer. A MAC-only
selector cannot even be constructed: `InterfaceIdentitySelector` refuses one
at validation, a layer earlier than the resolver's own guard. A third
statement of the rule in this repository would be a third thing to keep in
step.

A changed composite identity — adapter swap, driver change, slot move — returns
the affected capability to `COMMISSIONING_REQUIRED`. It does not silently
rebind, and it does not fall back to a kernel name or a default route.

## 4. Roles come from the operator, not from inference

Logical roles are **Azazel-Fabric's registered set**: `asset_acquisition`,
`deception_bridge`, `management`, `observation`, and `unassigned`
(`azazel_fabric.provisioning_contracts.INTERFACE_ROLES`). An operator may
confirm any of them except `unassigned`, which is what an interface is before
anyone confirms anything. `azazel_nexus.commissioning` mirrors the list locally
because commissioning is a `CORE` path and Fabric reaches this package through
one boundary module only ([ADR-0001](adr/0001-fabric-pin.md)); a test pins the
mirror against Fabric's list.

**This paragraph previously named a different set**, and the correction is
recorded rather than quietly applied. It read `protected`, `observation`,
`management`, `decoy`, `egress/module`. There were four lists in play —
Fabric's, this one, Azazel-Boot's `commissioning.py` (`observe`, `internal`,
`external`, `management`, `capture`, `decoy`) and Azazel-Boot's own
`architecture.md`, which agreed with this document and not with its own code.
**`management` was the only value all four shared**, and no product consumed
Fabric's list, so nothing had ever compared them.

The old lists mixed two questions. *What does the node do on this interface?*
is the **role**: it is what another product needs to know, and it is what
Fabric registers. *Which side of the boundary does this interface face?* —
`protected`, `egress/module` — is **topology**: it is Nexus's own, and it never
crosses a product boundary as a role. Nexus assigns no zone today and names
none in code; a second local vocabulary to hold one would repeat the mistake.

Fabric's published vocabulary did not change. The reconciliation closed
entirely on the consumer side, because the words that did not fit were never
roles.

A role is assigned only by explicit operator confirmation against the
inventory.

Nexus MUST NOT infer a role from:

- an interface name (`eth0`, `enp4s0`, `wlan0`);
- carrier or link state;
- the presence of a default route;
- an address learned by autoconfiguration;
- RAM capacity or any other resource measurement.

The operator reviews a proposal, confirms each role, and the result is recorded
as a signed commissioning record. Unassigned interfaces stay unassigned; an
unassigned interface has no capability.

"Proposal" is narrower than it sounds, and `azazel_nexus.commissioning` is
built so that it cannot be otherwise. It reports which interfaces carry an
unambiguous composite identity, what an operator can physically check about
each, and which roles exist. **It pairs no interface with a role** — not as a
default, not as a suggestion, not as an ordering. Every fact that would make a
pairing possible is a fact this section forbids reading, and none of them is
read by `azazel_nexus.inventory` at all, so there is nothing to infer from.

`azazel_nexus.fabric_boundary.confirm_role` turns one operator confirmation
into a Fabric `InterfaceAssignment`. Every argument is required and none has a
default: a confirmation Nexus could produce without being told who confirmed,
how, and when is a confirmation Nexus made on the operator's behalf.

**The signed record itself is not yet producible, and the reason is worth
stating rather than deferring.** Fabric's `CommissioningRecord` requires
`hardware_inventory_digest`, `resource_profile_digest` and
`topology_profile_digest`; Nexus produces the first and has neither
`ResourceProfile` nor `TopologyProfile`. A placeholder for the other two would
make the record claim to cover profiles that do not exist, and its own
`record_digest` would then vouch for that claim. The boundary refuses and names
what is missing.

## 5. Zero-transmit observation

An interface commissioned to the `observation` role is Layer-3 unnumbered and
transmits nothing. It MUST emit zero DHCP, router solicitation, mDNS, LLDP,
Wi-Fi probe, or any other frame.

This is verified, not assumed: the observation interface is held under a
transmit-count check across link flap, suspend/resume, and driver reload. A
nonzero transmit count withdraws the capture capability and returns the role to
`COMMISSIONING_REQUIRED`.

## 6. Bounded asset acquisition

Fetching signed assets needs network access that commissioning otherwise
forbids. `ASSET_ACQUISITION` is a separate, bounded state, not an early start
of operations. It uses **one operator-selected interface** in an outbound-only
namespace with:

- endpoint allowlists with metadata and certificate pinning;
- no forwarding and no listening service;
- bounded download size, count, and duration;
- no path to the protected, observation, decoy, or management zones;
- cleanup of routes, credentials, DNS state, proxy state, and wireless
  association on exit.

Offline installation from an encrypted bundle is the alternative and is subject
to the same admission sequence. Asset acquisition never assigns a role and
never grants a capability.

## 7. Verified generations and the activation controller

A **generation** is a complete, validated, rendered configuration state. The
activation controller is the only component permitted to unmask operational
services and issue generation-scoped systemd credentials.

On every boot and before every activation it validates:

- the operator/site signature over the commissioning record;
- the hardware inventory digest;
- the policy digest and security epoch;
- the generation counter and expiry;
- the renderer digest;
- the digest of every generated file.

Any mismatch leaves operational units masked. An old generation, a replaced
renderer, a substituted path, a parallel boot race, and a service-default
fallback MUST each produce **zero operational packets and zero actions**.

Activation order is fixed:

1. validate inputs and the product admission policy;
2. render into a private versioned staging directory using bounded
   unprivileged extractors;
3. preflight the configuration and establish a local-console or independent
   management failsafe;
4. install a deny exposure barrier, then atomically switch policy-owned kernel
   objects;
5. start passive sensors and verify actual state;
6. enable bounded routes, and Deception last;
7. persist the authoritative receipt and required audit checkpoint before
   reporting completion.

Failure withdraws exposure, expires affected leases, stops or quarantines
Deception, restores only owned last-known-good resources, and reports
`ROLLBACK_INCOMPLETE` until observed state matches. Software rollback never
restores obsolete trust state, policy, or hardware bindings.

## 8. Rendering from logical roles only

Suricata configuration, capture configuration, nftables policy objects, and
every other generated file are rendered **from commissioned logical roles**.

There is no fallback. If a role is unassigned or its interface identity is
ambiguous or changed, rendering fails and the dependent capability stays
unavailable. Nexus MUST NOT substitute a physical interface name, a kernel
device number, a default route, or a "first available" interface for a missing
role.

Generated files are disposable output under `/run`. An operator edits the
deployment overlay, never a generated file. A generated file that does not
match its recorded digest invalidates the generation.

## 9. Management failsafe and two-stage commit

Management paths are excluded from ordinary action scope: an enforcement action
MUST NOT be able to sever the path used to supervise it.

A high-impact network change requires an independent management path or a
physical local console, and a two-stage commit:

1. the change is applied with a lease;
2. the operator must acknowledge verified reachability within the lease window.

Without that acknowledgement the enforcement supervisor rolls the change back.
A node with no independent management path has enforcement eligibility withheld
and is reported as observe-only; see [capability model](capability-model.md)
§6.1.

## 10. Closing and re-entering commissioning

The commissioning service closes after activation. Re-entry requires **all** of:

- a physical local action at the node;
- strong administrator authentication;
- an explicit maintenance state;
- explicit handling of every active lease before any role may change.

A remote request, a configuration overlay, a package update, and a module
manifest MUST NOT reopen commissioning or change a role.

## 11. Recommissioning triggers

| Trigger | Result |
| --- | --- |
| composite interface identity changed or ambiguous | affected capability to `COMMISSIONING_REQUIRED` |
| observation interface transmitted a frame | capture capability withdrawn; role to `COMMISSIONING_REQUIRED` |
| commissioning record signature or digest invalid | operational units stay masked |
| hardware inventory digest mismatch | activation refused |
| security epoch below the tuple minimum | activation refused |
| decoy isolation attestation failed | decoy route withdrawn, then runtime cleanup; Deception ineligible |

None of these returns the node to a lower *authority*. They return it to a
lower *capability*, which is the correct and expected behavior.
