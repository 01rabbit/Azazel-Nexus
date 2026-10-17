# Commissioning and Activation

Status: **partially implemented contract**. Read-only inventory, commissioning
records, generation verification, and the activation decision model exist.
The production activation composition connects the one-shot controller to
systemd over D-Bus and revalidates protected full commissioning evidence.
Authenticated lease loading, authoritative commissioning admission and the
bootstrap path required to reach the commissioning service from a fresh
install remain incomplete. This document remains the
target contract; the implementation does not satisfy all of it.

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

Runtime hardware-snapshot scope clarification (2026-10-13): kernel loopback
may be excluded only when both its observed ARPHRD type is exactly 772 and its
resolved sysfs location is beneath `/sys/devices/virtual/net`. The collector
records `kernel-loopback-excluded` and its count, and checks the excluded set
on both reads. Names such as `lo`, or virtual placement alone, never justify
exclusion. Other interfaces—including virtual Ethernet, bridges and tunnels—
remain in scope and incomplete identities still refuse complete projection.
The fresh commissioning proposal must come from the same scoped observations
(`HardwareObservation.commissioning_proposal()`); an independently collected
unscoped proposal is not interchangeable. General library inventory output is
unchanged and still retains all exposed entries. This is a declared collection
scope, not proof of interface silence, trust or activation eligibility.

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

`fabric_boundary.build_commissioning_record` can assemble a complete linked
Fabric `CommissioningRecord` when supplied a complete, digest-consistent
`HardwareInventory`, a matching `ResourceProfile`, and a matching
`TopologyProfile`. Resource observations can be projected to the Fabric profile
when complete measurements and inventory are available. Reviewed draft roles
can be projected into a descriptive topology profile against that same
snapshot; management, capture, and isolation remain explicitly unverified.
Assembly returns the constituent records and Fabric record in an
**unsigned proposal**. The draft signature alone does not cover the new
resource/topology profiles or the full record wrapper.

`commissioning_approval.verify_commissioning_proposal` is a separate check: it
requires a new signature under the `commissioning-proposal` approval purpose,
rebuilds the expected proposal from independently supplied snapshots, and
requires exact canonical payload equality. Successful verification attributes
operator approval of that proposal only. It returns no activation grant and
does not establish freshness, trusted time, high-water state, health, product
admission, or durable storage. The activation-time full evidence loader is
implemented, but authoritative admission, authenticated lease loading,
bootstrap admission, those state and freshness checks, and promotion into signed
record persistence remain incomplete. Inconsistent or incomplete inputs still
make proposal assembly unavailable; the remaining gap is the production path,
not an unconditional inability to assemble the record.

The runtime now exposes `az-nexus-commission proposal-export --operator LABEL`:
it connects the protected signed role draft, declared node and current
inventory/resource collectors to those projections, then exports a complete
unsigned proposal after explicit confirmation and input rechecks. It first
retains an independent protected expected copy, then creates the signing view
`commissioning-proposal.json`; existing proposal state is never overwritten.
`proposal-review --operator LABEL` validates a detached signature against those
retained expectations and current node/trust, then rereads the protected inputs
before reporting historical approval. There is no authoritative-record import
or activation and no raw identity output. Old exports without retained context
are refused, not migrated. See the [runtime adapter](../runtime/README.md) for
prerequisites and the local privileged-owner/rollback limitations.

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

Implementation boundary (2026-10-13): activation currently consumes Nexus's
local `CommissioningRecord`, whose digest covers role composites, profile
names and confirmation metadata. The retained Fabric proposal binds full
inventory/profile contents and limitations. These are not interchangeable:
copying three profile names into a local record would discard the newly
verified bindings and must not confer enforcement readiness. The current
`Generation.commissioning_digest` meaning remains unchanged. The controller
now accepts a separate `CommissioningEvidence` containing the complete signed
payload, signature and current inventory. An additional
`commissioning_evidence_binding` must agree across that evidence, generation
and signed activation approval for enforcement. A bound lease alone cannot
fall back to legacy enforcement. Local roles, identities and confirmation
provenance must also match the full proposal; three profile names alone do not
provide this evidence. Supporting/Edge-baseline tiers retain their existing gates.
HIL `commissioning.json` is not the specified production
`commissioning/active.record` promotion path.

The binding is HMAC-SHA-256 of
`b"azazel-nexus/commissioning-evidence/v1\x00" + payload`, using the existing
fixed `/var/lib/azazel/secrets/commissioning.key` (32–4096 bytes, private
root-owned directory and single-link ordinary file). No key is generated.
Signature and present hardware are independently reverified on each pass;
the binding is not a cached verification flag or rollback anchor. Key rotation
requires new bound state and approval; existing metadata is not rewritten.
Absent binding fields are omitted from legacy generation metadata and approval
bytes. Bound-state rollback currently refuses when either latest or target
generation has a binding: a new validated forward render and approval are
required, and that production workflow remains incomplete.

The actual activation entrypoint first attempts to mask every governed unit,
then loads fixed protected evidence and passes it to the controller. A masking
failure follows the existing retry/escalation path before evidence collection.
Missing or changed evidence never grants a service. Lease, authoritative record
and measured health are still absent in this composition; it cannot activate
services merely because the full evidence loader succeeds.

The runtime review's optional `--check-current-hardware` now compares all
retained/current inventory content apart from the three snapshot metadata
fields (ID, collection time, digest), without rewriting either snapshot.
This supplies a tested hardware-content comparison rule, not current resource
admission or an activation grant. Renderer, policy/epoch/high-water, trusted
clock and node-health producers remain incomplete. Generation directory
numbering and local audit chains are not independent rollback anchors. The
existing Edge probe carries an unsigned-manifest caveat and must not be
silently repurposed as authenticated package admission.

A **generation** is a complete, validated, rendered configuration state. The
activation controller is the only component permitted to unmask operational
services and issue generation-scoped systemd credentials.

Generation publication now stages ordinary files and metadata in a private
hidden directory, reads them back, syncs them, and renames the complete
directory into its generation number under a nonblocking directory writer
lock. No numbered partial tree is exposed by `create()`. Staging failures leave
hidden private files for explicit inspection, not automatic reuse or deletion.
New store directories also sync their entries in their respective parents.
Numeric directory aliases, numeric symlinks and numeric non-directory entries
are refused for inspection rather than silently selected as a generation.
If the final parent-directory sync fails after publication,
`GenerationCommitUncertain` reports the published number; inspect the complete
visible state before any retry. This is not a successful activation or proof
of power-loss recovery. Locks coordinate cooperating writers on trusted local
storage, not a privileged owner or a distributed filesystem. A rollback also
rechecks its source generation under that lock and refuses a concurrent advance.
Content integrity/publication do not replace semantic admission, authoritative
commissioning promotion, or the still-missing operational role renderer.

The fixed-file activation approval reader is separate from those producers.
It verifies `/etc/azazel/activation/approval.json` and `approval.sig` with
current enrolled trust only against an independently supplied expected context,
operator, time and local lease limit. It has no path override or signing/key
operation. The production entrypoint must not call it with an expected context
copied from the candidate approval. See the
[remaining runtime connections](runtime-activation-remaining.md) for input
ownership, package-consumer gaps and the conditions for wiring this reader.

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
