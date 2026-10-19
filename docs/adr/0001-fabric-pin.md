# ADR-0001 — Azazel-Fabric is pinned to an exact tag, as an optional extra

Status: **accepted** · Supersedes nothing · Revises
[`inheritance-ledger.md`](../inheritance-ledger.md) §4.1

## Context

Phase 0 of the [roadmap](../roadmap.md) has one row left: "adopt an **exact
Azazel-Fabric release pin** and build adapters against the Fabric-owned records
that already exist". Every other Phase 0 row is closed. The row was also
blocked on two Fabric families that did not exist; both have existed since
`v0.9.0rc1`, so nothing in Phase 0 waits on Fabric any more.

Two decisions already recorded in this repository disagreed about what shape
the dependency should take:

- `pyproject.toml` declares an empty dependency list, with the reason stated
  inline: Nexus must be useful as `CORE` with no external Knowledge, no
  Deception, no remote cognition and no cloud connectivity, so "a dependency
  added here is a dependency the CORE path can fail on". The CI job "CORE
  imports with nothing installed" checks it.
- [`inheritance-ledger.md`](../inheritance-ledger.md) §4.1 said the opposite:
  "Edge treats Fabric as an optional extra. Nexus cannot: integration across
  products *is* the Nexus product, so Nexus requires a Fabric pin as a hard
  dependency."

## Decision

**Fabric is declared as the optional `fabric` extra, pinned to the exact tag
`v0.9.0rc5`, and imported in exactly one module.**

1. **Optional, not required.** §4.1's reasoning holds for a Nexus *release*;
   it does not describe `CORE`. Integration across products is what a release
   delivers, and `CORE` is what survives when every one of those products is
   gone. A `CORE` path that fails because a contract library is absent is not a
   `CORE` path. §4.1 has been revised rather than left to contradict this.

2. **An exact tag, never a branch or a development commit.** Inherited from
   Azazel-Edge's pin policy, which §4.1 already recorded as inherited. A
   release candidate is still an exact tag; it promises no stability, so the
   pin moves to `v0.9.0` when Fabric cuts it.

3. **`v0.9.0rc5` (I0, #191).** rc3/rc4 fix `effect_contracts`
   references and authority classes that Edge and Deception already rely on;
   rc2 → rc5 changes only `effect_contracts`, which Nexus does not import yet.
   The initial decision selected rc2; this revision retains the exact-tag
   policy and does not attest new contract mappings.

4. **One import site.** `azazel_nexus.fabric_boundary` is the only module that
   may import `azazel_fabric`, enforced by a static scan over the package
   (`tests/unit/test_boundary_static.py`). Containing the import is what makes
   Fabric's absence a bounded, testable condition rather than an ImportError
   wherever the interpreter reaches first. The import inside it is deferred to
   call time, checked separately, because a module-scope import would make the
   boundary itself the crash it exists to prevent.

5. **The boundary cannot add anything.** It renders a capability state; it
   cannot raise one, cannot populate `StatusView.current_action` (an arbiter's
   enforcement intent), and cannot publish a capability state as an operating
   mode. Each is a test, not a convention.

## Alternatives considered

**Fabric as a required dependency**, per §4.1 as written. Rejected: it would
delete the "CORE imports with nothing installed" job, which is an *implemented*
invariant, in favour of a *target-contract* sentence. Where an implemented
check and a target document disagree about the current artifact, the check is
the one describing something real.

**Pinning `v0.9.0rc1`**, as Azazel-Boot does. Rejected: rc2 contains rc1
additively, is equally signed, and three of the five consumers are already on
it. Pinning the older tag would add a fourth distinct pin to the series for no
gain.

**Waiting for the stable `v0.9.0`.** Rejected: it is blocked on evidence that
does not exist yet (Azazel-Fabric's R1 exit gate), and waiting would leave
Phase 0's last row open indefinitely while the work it unblocks sits idle. A
candidate promises no stability, which is why the pin is exact and why moving
it is expected.

## Consequences

- One mapping in `contract-ownership.md` §3.1 — capability/mode publication
  through `ModeState` and `StatusView` — is now **attested** against the pinned
  models. Every other row in §3 is unchanged. **A bound pin is what makes an
  attestation possible; it is not one.**

- Installing the extra needs network access to GitHub. The `dev` install and
  the `CORE` path do not, and CI keeps both facts separate: one job installs
  `.[dev]`, one installs `.[dev,fabric]`, and one installs nothing at all.

- Moving Fabric into `dependencies` later is a change of product posture, not a
  packaging tidy-up. It would require, at minimum: a Nexus release artifact
  that vendors its dependencies (so "missing at runtime" stops being a real
  state), a successor to this ADR, and a revision of
  `test_the_fabric_pin_is_an_optional_extra_and_not_a_required_dependency`,
  which fails on the move by design.

- A missing or broken Fabric degrades presentation and nothing else. The node's
  capability state is unchanged and is what a caller should read. Azazel-Edge's
  deterministic arbiter remains the only decision and enforcement authority in
  every case.
