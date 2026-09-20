# Support Matrix

Status: **target contract**. Azazel-Nexus has never produced a release. This
document states what a Nexus release will have to declare support for, and
marks — explicitly, in §7 — every place where the program's documents are
silent and nothing may be filled in by inference.

Nothing below may be cited as evidence that any platform, distribution,
runtime, or machine has been tested. None has.

Related: [Capability model](capability-model.md) ·
[Contract ownership](contract-ownership.md) ·
[Commissioning and activation](commissioning.md) ·
[Update channel](update-channel.md) · [Recovery](recovery.md) ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§5 R2/R3, §8 ·
[R0 baseline](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-r0-baseline.md)

## 1. Nothing is supported

*supported* has a fixed meaning in this series: "documented release, security/
support posture, and operational evidence exist for the declared environment"
([status vocabulary](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/third-party-development-handoff.md)
§7). Azazel-Nexus has no release, no operational evidence, and — as §3 records
— no fully declared environment. It therefore supports nothing, and no
configuration of it may be described as supported or operationally certified.

The R0 exit criteria require that "Nexus and Boot publish their own security
policy, support matrix, license, update channel, and recovery procedure before
a release is called supported". Publishing this document satisfies one of those
five items. It does not move Nexus toward *supported*, because publishing a
matrix and having evidence for its rows are different things.

## 2. The hardware compatibility list is empty

> **There is no supported rugged PC. There is no tested rugged PC. There is no
> machine on which Azazel-Nexus has ever been installed, commissioned, or
> activated.**

The table in §6 has no rows, and that is its correct content. An entry cannot
be produced by reading a specification sheet: every field of a qualified entry
(§5) is a measurement or an artifact, and the program treats a broad
compatibility claim as descriptive only — "a version range is a descriptive
compatibility claim and MUST NOT authorize activation"
([contract ownership](contract-ownership.md) §4.1). Field releases admit
artifacts against a **deny-by-default set of exact tested tuples**, so a
hardware family name would authorize nothing even if it were written down.

Adding a row requires owner ratification recorded against the program plan and
a linked hardware-in-the-loop evidence record. Neither exists.

## 3. Declared platform envelope

These constrain what may eventually be qualified. None of them is itself a
qualification, and a machine satisfying all of them is still untested.

| Boundary | Value | Source |
| --- | --- | --- |
| Product and deployment | `AZ-07` Azazel-Nexus Gateway — persistent, self-contained installation on a generic rugged x86_64 Linux PC | R0 baseline, product definitions |
| Architecture | `x86_64`; other values are rejected by product admission | [contract ownership](contract-ownership.md) §4.1 |
| Init and service model | systemd; the packaging target is "x86_64 systemd deployment" | program plan §5 R3 |
| Reference OS | "a supported long-term-support Linux distribution with systemd, nftables, `tc`, cgroup v2, TPM 2.0 tools, LUKS2, and a current kernel" — **no distribution, release, or kernel series is named anywhere** | [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §2; see §7 |
| Console | a headless console MUST be supported; a touchscreen is an optional presentation device | [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §2 |
| Platform security assumption | UEFI Secure Boot where supported, TPM 2.0 measured boot, LUKS2-encrypted system and data volumes; with no TPM, a boot-time operator secret and measured-boot evidence labeled unavailable | [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12 |
| Language and runtime matrix | **undeclared** — see §7 | — |
| Capability rule | `resource profile ∩ topology profile ∩ verified asset set ∩ current trust/health state`; RAM alone enables nothing | [capability model](capability-model.md) §1 |

Nothing in this table says any particular machine, distribution, or kernel
satisfies it.

### 3.1 Resource classes

The resource profile is selected from usable RAM in MiB after firmware
reservation. The boundaries are `7168`, `15360`, and `31744` MiB, each the
nominal size it admits minus a 1024 MiB firmware-reservation allowance. They
are owned by [capability model](capability-model.md) §2, which holds the
derivation, the measured case behind it, and the residual risk that a host
reserving more than the allowance still selects one envelope low. They are
inherited from program plan §5 R2 and **must not be restated with different
numbers anywhere**.

Performance and retention targets are recorded separately for the **8, 16, 32,
and 64 GB classes** (program plan §8; [capability model](capability-model.md)
§2). These are measurement classes, not selector outputs: a 64 GB host selects
`standard`, and there is no `extended` tier. **No measurement exists for any
class.** The quantitative objectives those classes will be measured against —
Core ready within 120 seconds after encrypted-volume unlock, source/interface
failure visible within 10 seconds, and the rest — are stated in program plan
§8 as initial targets. Nexus has measured none of them.

Companion hardware is described per envelope in [field operations](operations.md)
§1 and [integrated-node doctrine](nexus-integrated-node.md). Those figures
describe a hardware class; they are not a support claim, and meeting them
remains subject to the measured Core reserve, which for Nexus is **unmeasured**.

### 3.2 Topology is not part of the resource class

A support row will never be "this machine is supported" on its own. Capture,
enforcement, Deception Lite, module links, and remote cognition each have a
topology precondition that commissioning establishes per deployment
([capability model](capability-model.md) §3). A qualified machine with an
uncommissionable interface layout is observe-only, and that is the correct
outcome rather than a compatibility defect.

## 4. Azazel-Fabric pin discipline

Azazel-Fabric owns every record that crosses a product boundary. Nexus MUST
consume it behind an **exact release pin** — a git tag, never a branch and
never a development commit — and MUST NOT fork a Fabric model into a
Nexus-local copy
([contract ownership](contract-ownership.md) §1).

| Fact | State |
| --- | --- |
| Nexus's Fabric pin | **`v0.9.0rc2`, as the optional `fabric` extra** ([ADR-0001](adr/0001-fabric-pin.md)). An exact tag, never a branch or a development commit. It satisfies the R0 baseline's "explicit, tested Fabric pin before an implementation release" for the pin itself; the *tested* half is one mapping, not §3 as a whole |
| Which tag the other products pin | **not restated here.** Azazel-Fabric's [release compatibility](https://github.com/01rabbit/Azazel-Fabric/blob/main/docs/release-compatibility.md) carries the consumer pin table, and a test in that repository keeps it agreeing with the repository's own README. A copy in this document would be a second statement of somebody else's record, free to drift — and it did: this row previously named a tag that four of the five consumers had moved off |
| Program-wide locked baseline | **not reached.** No cross-repository conformance run is linked from the program plan, and the products do not agree on one tag |
| `provisioning_contracts`, `mio_contracts` | **released, unadopted.** Both exist from `v0.9.0rc1`; see [contract ownership](contract-ownership.md) §2. Existing is not the same as mapped, so §3.3 and §3.4 still classify every record in them as a target, and Nexus MUST NOT adopt a pin for them without a conformance attestation |
| Conformance attestation | **none.** Every record mapping in [contract ownership](contract-ownership.md) §3 is a design assertion awaiting attestation, not verified evidence |

A release will additionally pin each integrated product — the Edge package, any
Knowledge Lite bundle, any Deception package, and any model — by exact version
and digest, with the SBOM references program plan §4 rule 6 requires. The
product versions observed on `main` during the R0 audit (Edge: no single
product package version; Knowledge `0.1.0`; Deception `0.2.0.dev0`) are
observations of source trees, not a supported combination.

## 5. The shape of a qualified entry

An entry may be added only when **every** field below is present and evidenced.
A partial entry is not a provisional qualification; it is not an entry.

### 5.1 Composite identity

The machine and its relevant devices are identified by composite identity — the
same discipline [commissioning](commissioning.md) §3 requires for interfaces —
never by a marketing model name alone and never by a MAC address alone:

- system vendor, product name, family, and firmware-reported SKU;
- firmware vendor, version, and release date; TPM presence and version;
- CPU model and the CPU feature set relied on;
- usable RAM in MiB **after firmware reservation**, the measured firmware
  reservation itself, and the resource profile it selects;
- storage controller and device identities, and the encrypted-volume layout;
- each network interface by bus path, permanent MAC obtained from the adapter,
  vendor/device identity, serial where exposed, driver and firmware version,
  and wireless PHY identity where applicable;
- the operator-recorded physical label for each externally visible port.

A machine whose firmware version differs is a **different** entry until tested.

### 5.2 Software identity

- the exact OS distribution, release, and kernel series tested, recorded as the
  `os_abi` field of the tested compatibility tuple
  ([contract ownership](contract-ownership.md) §4.1);
- the exact Fabric pin, and the component, adapter, renderer, and toolchain
  digests the tuple names;
- the security epoch and the maximum rollback version the entry admits;
- the deployment-overlay schema version.

### 5.3 Observed result

- the resource profile selected, and the capability the four-dimension
  intersection actually produced on this machine — including which capabilities
  were **unavailable** and why;
- the interface inventory as observed, and which logical roles were
  commissionable;
- the observation interface's transmit count across link flap, suspend/resume,
  and driver reload — the required value is **zero**
  ([commissioning](commissioning.md) §5);
- measured values for the program §8 objectives at this machine's resource
  class;
- the recovery and rollback drills of [recovery](recovery.md) §6, executed on
  this machine by an operator who did not build it.

### 5.4 Evidence link

- a link to the hardware-in-the-loop record containing the measurements above;
- the date of the test and the exact artifact versions tested;
- who performed it, and the independent confirmation the program requires;
- the owner ratification record in which the entry was accepted;
- the conditions under which the entry expires — a firmware update, a driver
  change, or a hardware revision each invalidate it.

## 6. Qualified hardware

*(empty)*

| System | Firmware | OS / kernel | Resource class | Capability observed | Evidence |
| --- | --- | --- | --- | --- | --- |
| — | — | — | — | — | — |

No rows. See §2.

There is no candidate list either. Naming a candidate before a test program
exists creates the same expectation an empty table is meant to prevent.

## 7. Undeclared — do not fill these in by inference

Each row below is something a support matrix would normally state and that
**no document in this program declares**. They are recorded as undeclared
rather than guessed, and each is resolved by an owner decision or a
measurement, not by a contributor choosing a plausible value.

| Undeclared | What is actually written | How it gets declared |
| --- | --- | --- |
| Language and runtime matrix | Nothing. Neither program plan §5 R2/R3 nor any Nexus document names a Python version, interpreter, or runtime for Nexus. R3 states only "x86_64 systemd deployment" | with the package layout and dependency manifest of Phase 0 ([contract ownership](contract-ownership.md) §6) |
| OS distribution and release | "a supported long-term-support Linux distribution" — no distribution or version ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §2) | as the `os_abi` of the first tested compatibility tuple |
| Kernel series | "a current kernel" — no series or minimum ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §2) | as above |
| Minimum versions of systemd, nftables, `tc`, cgroup v2 tooling, TPM 2.0 tooling, LUKS2 | The components are named; no version floor is stated anywhere | with the first tested tuple |
| Required CPU feature set | The tuple carries `cpu_features` ([contract ownership](contract-ownership.md) §4.1); no values are declared, and model admission is expected to constrain them | with the first admitted model and the first tuple |
| Measured Core reserve | Explicitly **unmeasured** for Nexus ([capability model](capability-model.md) §2) | by measurement on real hardware |
| Supported NIC, capture, and storage device families | Nothing. Commissioning identifies interfaces by composite identity; no device family is declared compatible | per qualified entry, §5.1 |
| Firmware/boot path requirements | "UEFI Secure Boot where supported" ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12); the roadmaps state no UEFI, Secure Boot, or legacy-BIOS requirement | by owner decision, recorded here |
| Security epoch values and `max_rollback_version` policy | The fields exist in the tested tuple; no values or numbering scheme are declared | with the release-admission policy ([update channel](update-channel.md) §3) |
| Support window, release cadence, and end-of-support policy | None. Program releases are "capability gates rather than calendar commitments" (program plan §5), so no window exists to declare | by owner decision, if a release ever makes one meaningful |
| Which Edge x86_64 package is admissible | Edge has "no single product package version" (R0 baseline), and Nexus requires that an admitted Edge package declare a single authoritative decision and enforcement boundary ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §1) | by Azazel-Edge, then by a tested tuple here |

## 8. What this document does not establish

- That Azazel-Nexus installs, commissions, activates, or runs on anything.
- That any distribution, kernel, or runtime has been tested with it.
- That any rugged PC is compatible, or that a class of machines can be
  qualified together. Until evidence says otherwise, qualification is per
  system **and** per firmware version.
- That the §8 program objectives are achievable on rugged-PC hardware. None has
  been measured.
