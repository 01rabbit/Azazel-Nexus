# Recovery Procedure

Status: **target contract**. **None of this is implemented, and none of it has
ever been tested.** No Azazel-Nexus has been installed, so no update has
failed, no commissioning has been re-entered, and no rollback has been
exercised. This document states what recovery will have to do; it is not a
runbook an operator can follow today, because there is nothing to run it
against.

Nothing below may be cited as evidence that Azazel-Nexus recovers from
anything.

Related: [Commissioning and activation](commissioning.md) §7, §10, §11 ·
[Capability model](capability-model.md) §4, §5, §7 ·
[Update channel](update-channel.md) · [Support matrix](support-matrix.md) ·
[Implementation specification](IMPLEMENTATION_SPEC.md) §12 ·
[Program plan](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md)
§4.3, §4.5, §5 R2/R3/R7

## 1. What recovery is for

Recovery restores **capability**. It never restores, transfers, or creates
**authority**. Azazel-Edge's deterministic arbiter is the only decision and
enforcement authority before a failure, during recovery, and after it; a node
in a recovery state has exactly the authority it had when healthy, which is
none of its own.

Three rules follow, and every procedure below is an application of them:

1. **The safe state is masked, not degraded-but-running.** Operational units
   are preset disabled and remain unavailable without a verified generation
   ([commissioning](commissioning.md) §7). A node that cannot prove its
   configuration does not fall back to a best-effort configuration; it runs
   nothing operational.
2. **Recovery is per capability, not per node.** A failure withdraws the
   capability whose precondition it broke, and nothing else. A node that loses
   its decoy isolation keeps observing; a node whose model asset fails
   verification keeps evaluating, deciding, and auditing.
3. **Recovery never relaxes trust to make progress.** "Software rollback never
   restores obsolete trust state, policy, or hardware bindings"
   ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12). A recovered node runs
   older software under current trust, or it does not run.

## 2. What a failure leaves behind

| Failure | State it leaves | Source |
| --- | --- | --- |
| Activation fails (bad signature, digest mismatch, expired or replayed generation, replaced renderer) | operational units stay masked; exposure withdrawn; affected leases expired; Deception stopped or quarantined; only owned last-known-good resources restored; the node reports `ROLLBACK_INCOMPLETE` until observed state matches | [commissioning](commissioning.md) §7 |
| Update fails during trial or health check | return to the prior slot without deleting evidence; the R7 exit gate requires return "to the prior verified generation without losing the last valid audit checkpoint" | [IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12; program plan §5 R7 |
| Model download or signature verification fails | **a working Core environment** — see §3 | program plan §5 R2 exit gate |
| Composite interface identity changed, ambiguous, or absent | the affected capability returns to `COMMISSIONING_REQUIRED` — see §4 | [commissioning](commissioning.md) §3, §11; program plan §5 R2 exit gate |
| Observation interface transmitted a frame | capture capability withdrawn; the role returns to `COMMISSIONING_REQUIRED` | [commissioning](commissioning.md) §5, §11 |
| Decoy isolation attestation fails | decoy route withdrawn within the declared bound, then runtime cleanup; Deception ineligible | [capability model](capability-model.md) §7 |
| Independent audit anchor receipt fails | audit assurance drops to `LOCAL_CONTINUITY_ONLY`: live Deception and new disruptive actions are fenced, observation and evaluation continue, existing leases run to their predeclared safe expiry, and a visible custody exception is raised | [capability model](capability-model.md) §5; program plan §4.5 |
| Power loss or I/O failure mid-apply | zero unjournaled kernel mutation: the supervisor persists and syncs intent, lease, owned-resource record, expiry, and release task before the first disruptive mutation, in the order `prepare + fsync -> apply -> verify -> persist receipt`. On restart, recovery reconciles every tagged kernel object to a durable owner/release record **before** accepting new work | program plan §4.3 |
| Enforcement adapter cannot verify effective state | new automated enforcement through that adapter stops; evidence, evaluation, and operator guidance continue; the node holds safe and requires acknowledgement | [field operations](operations.md) §2 |

A restart alone never restores a capability. Restoration above `CORE` requires
a passing health window, revalidation of signatures and segmentation, and an
audited transition; restoring a module route or a failed enforcement adapter
additionally requires operator acknowledgement
([capability model](capability-model.md) §7).

## 3. Asset failure leaves a working Core

> model download or verification failure leaves a working Core environment
> — program plan §5 R2 exit gate

This is a hard requirement on the design, not a quality goal. A missing or
rejected asset "removes its capability and nothing else"
([capability model](capability-model.md) §4). A node whose local model fails
signature verification keeps collecting evidence, evaluating signed policy,
presenting deterministic explanations, auditing, and applying already-supported
bounded controls; M.I.O. reports `CORE ONLY` and deterministic explanations and
voice continue.

There is no recovery step here beyond making the loss visible. Retrying an
asset fetch is ordinary [update-channel](update-channel.md) work in the bounded
`ASSET_ACQUISITION` state, and a node that never retries is still a working
node. Nexus MUST NOT treat a failed asset as a reason to defer, weaken, or
bypass any Core function — that would convert an optional component into the
baseline dependency the product exists to avoid.

## 4. Changed interface identity returns to `COMMISSIONING_REQUIRED`

An adapter swap, a driver change, a slot move, a firmware change, or an
ambiguous match returns the **affected capability** to
`COMMISSIONING_REQUIRED`. The node does not silently continue, does not rebind
by kernel name, index, or default route, and does not fall back to a "first
available" interface. Zero matches and more than one match are both
fail-closed: with multiple candidates the node refuses to choose and reports
the competing candidates to the operator
([commissioning](commissioning.md) §3).

Rendering has no fallback either: if a role is unassigned or its identity is
ambiguous, rendering fails and the dependent capability stays unavailable
([commissioning](commissioning.md) §8).

**Re-entering commissioning requires all of** ([commissioning](commissioning.md)
§10; program plan §5 R2):

- a **physical local action at the node**;
- **strong administrator authentication**;
- an explicit **maintenance state**; and
- **explicit handling of every active lease** before any role may change.

A remote request, a configuration overlay, a package update, and a module
manifest MUST NOT reopen commissioning or change a role. This is what keeps a
network-reachable fault — or an attacker who can produce one — from becoming a
path to reassigning what the node is allowed to do to the network.

None of these returns the node to a lower *authority*. They return it to a
lower *capability*, which is the correct and expected behavior
([commissioning](commissioning.md) §11).

## 5. Management lockout and two-stage rollback

Management paths are excluded from ordinary action scope: an enforcement action
MUST NOT be able to sever the path used to supervise it
([commissioning](commissioning.md) §9; program plan §4.3).

A high-impact network change therefore requires **an independent management
path or a physical local console**, and a two-stage commit:

1. the change is applied with a lease;
2. the operator acknowledges verified reachability within the lease window.

Without that acknowledgement the enforcement supervisor **rolls the change
back**. The R3 exit gate requires that this be proven, not assumed:
"management lockout tests prove two-stage rollback through an independent path
or physical console."

A node with no independent management path has enforcement eligibility withheld
and is reported observe-only — the recovery property is obtained by not
granting the capability in the first place
([capability model](capability-model.md) §6.1).

Lease behavior during recovery is deliberately conservative: leases use a
boot/session-bound monotonic deadline and a durable trusted absolute deadline,
and the earlier safe deadline wins; persisted leases never resume after reboot
without reauthorization; and when time is untrusted, new disruptive actions
stop while existing ones follow their predeclared safe expiry or fence behavior
(program plan §4.3).

## 6. Recovery media and offline execution

Recovery media is **encrypted, signed, and versioned**. It can boot
diagnostics, verify signatures and audit segments, unlock data through
controlled custody, export evidence, and restore a known software slot. It
**MUST NOT** bypass audit verification, silently reset policy, or erase mission
data ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12).

The R7 exit gate sets the standard the procedure is measured against:

> recovery procedures are executable from offline media by an operator who did
> not build the system

That is the test this document cannot yet pass. It has never been attempted,
and no recovery media has been built.

## 7. Audit continuity and custody

Recovery must not be able to launder a break in the evidence chain.

- A repair that breaks audit continuity **creates a new ledger genesis
  explicitly linked to the last valid checkpoint**, and requires an operator
  custody record ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12).
- **Recovery authority cannot sign ordinary field checkpoints or hide a
  discontinuity** (program plan §4.5). Recovery is its own credential role,
  separate from policy signing, intent signing, update signing, commissioning
  approval, and audit checkpointing (program plan §4.3).
- While audit assurance is `LOCAL_CONTINUITY_ONLY`, exports are labeled locally
  consistent and **not** rollback verified, and no claim of rollback-verified
  finalized evidence may be made
  ([capability model](capability-model.md) §5).

A recovered node whose custody record shows a discontinuity is a node with a
visible, documented gap. That is the intended outcome; a recovery that produced
an unbroken-looking chain would be the defect.

## 8. Undeclared — not decided here

| Question | State |
| --- | --- |
| Recovery media build, format, and image identity | **undeclared.** No builder is selected and no media has been built |
| The operator-facing step sequence (what to press, in what order, with what prompts) | **undeclared.** It cannot be written before there is a console to write it against; R7's "operator who did not build the system" is the standard it must eventually meet |
| Custody procedure for the LUKS recovery passphrase and the TPM-sealed key option | **undeclared** beyond "a recovery passphrase held under mission custody" ([IMPLEMENTATION_SPEC](IMPLEMENTATION_SPEC.md) §12) |
| Recovery credential role's key hierarchy, holders, and provisioning ceremony | **open** — the same open item as [update channel](update-channel.md) §8 |
| Time bounds: how long `ROLLBACK_INCOMPLETE` may persist, and the soak window before an update is promoted | **undeclared** |
| Evidence retention and export bounds during a restore | **undeclared** beyond "without deleting evidence" and the retention domains of [integrated-node doctrine](nexus-integrated-node.md) |
| Which failures require a full reinstall rather than a slot restore | **undeclared** |

## 9. What this document does not establish

- That Azazel-Nexus recovers from a failed update, a failed activation, a
  changed interface, or a management lockout. No such event has occurred,
  because no node exists.
- That recovery media can be built, or that an operator who did not build the
  system can execute anything from it.
- That the two-stage rollback of §5 has been tested. The R3 exit gate requires
  a test; none has been run.
- That any of the properties above hold on any hardware. The hardware
  compatibility list is empty ([support matrix](support-matrix.md) §2).
