# ADR-0008 — Knowledge Lite trust operations on the ordinary path: a loop audit writer and root's narrowed maintenance transaction

Status: **proposed (2026-10-30), a technical decision delegated by the owner's
2026-10-30 direction** ("complete the Lite operating entry"; technical
decisions delegated). It changes decisions 2 and 8 of
[activation-observe-baseline §6](../activation-observe-baseline.md#6-owner-decisions)
and records why. Survey items S-02 and S-14; owner-decisions M10, M11 and
M12 (the enrollment entry; K7, the mapping of Knowledge's `anchors.revoked`,
stays open).

## Context

On 2026-10-20 the owner decided (§6, decisions 2 and 8) that the activation
pass grants only the integrated loop's SUPPORTING units and that auditd and
commissiond stay bootstrap-only: the supporting-only bootstrap starts them,
bound to the controller (`BindsTo=azazel-activated.service`), and the
ordinary pass masks them. That left the ordinary path without three things
the Lite operating entry needs (checked in the code at `cdd326a`):

1. **Import.** `knowledge.import` (`az-knowledge-lited`, a loop unit) appends
   `knowledge.lite.import_started` to az-auditd before touching the store
   (`lite_audit.ImportAudit`) and refuses without it. With auditd masked, every
   import on a normally started node was refused with `audit_unavailable`.
2. **Trust changes.** `trust-repin` and `knowledge-revocation-accept` were
   requests to `az-commissiond`'s socket, which does not exist on the ordinary
   path.
3. **First registration.** `TrustStore.pin` had no shipped caller. A fresh node
   reached a trust root only by the hand procedure of
   [knowledge-lite-consumer §11](../knowledge-lite-consumer.md#11-first-enrollment-from-a-fresh-install-to-available)
   (anchors written twice, a root-run library call, `chown`, then a repin
   for the revocation authority), and nothing checked the commissioning
   binding or the threshold.

`tools/vm_integration.py` hid (1): it started a hand-made copy of the auditd
unit with the controller dependencies removed, and wrote the grant markers
itself.

Two facts constrain any fix:

* **The bootstrap pins the helper's lifetime.** The bootstrap's loaded-unit
  policy requires `BindsTo=` of auditd and commissiond to be exactly the
  controller (`bootstrap_loaded._dependency_policy`), and the bootstrap
  publishes those units' rendered bytes as its overlay. The ordinary
  controller exits right after READY, so a unit bound to it stops with it
  ([§8 "Residual window"](../activation-observe-baseline.md#8-p4-supporting-wired-into-the-pass)).
  `azazel-auditd.service` cannot serve the integrated loop without changing
  the bootstrap's lifetime invariant.
* **A same-boot restart of a controller dependent re-runs the pass**
  (§10.2 M-5), which removes every marker and fails closed while granted
  units run. Starting a unit "for a moment" on the ordinary path therefore
  either needs a new unit-start authority or ends in that narrowing.

## Options

* **(a) auditd as a resident SUPPORTING unit of the loop.** With the existing
  unit: impossible without rewriting the bootstrap's pinned lifetime (above).
  With a second unit that runs the same daemon with a loop unit's lifetime:
  possible, and every check the pass already makes (policy scope, signed
  generation over the unit file, loaded-unit and content checks, marker)
  applies to it unchanged.
* **(b) A fixed maintenance transaction that starts audit and commissioning
  briefly.** Needs either a unit-start verb (refused: no arbitrary or new unit
  operation API) or root's `systemctl start` of controller dependents, which
  re-runs the pass (M-5). It would also run the full commissioning daemon
  (inventory, netlink) for a trust edit.
* **(c) Chosen: (a) for the audit writer, and the trust changes as root's own
  narrowed transaction.** The trust changes never needed a daemon: root asks,
  a signed or confirmed input is the authority, and the change is the
  commissioning account's. The transaction narrows itself to that account
  before reading its input.

## Decision

**D1. The loop's audit writer, `azazel-auditd-loop.service`.** The same
program (`az-auditd-loop`, the same callable as `az-auditd`), account
(`azaudit`), address family, writable leaves, chain and sockets as the
bootstrap helper; the lifetime of a loop unit: `Requires=`/`After=` the
controller, `ConditionPathExists=` on its own grant marker, no `BindsTo=`.
It is in `ACTIVATION_UNIT_ALLOWLIST`, `GRANTABLE_UNITS` and `CORE_UNITS`
(SUPPORTING), so a policy may name it and the pass grants it only with a
verified approval, generation and health like the other loop units. The
installer masks it and the preset disables it. The helper unit is unchanged.

**D2. One writer, by lock.** az-auditd takes an exclusive `flock` on the
ledger directory itself before reading the chain or binding a socket, and
exits 1 if another instance holds it. The two units can therefore never
write the chain at once, whatever is enabled or queued; no file is added
to the ledger directory (the bootstrap check requires every entry there to
be a segment). There is no `Conflicts=` between them: the bootstrap's
loaded-unit policy refuses any other `azazel-*` name in the helper's
inverse dependency sets.

**D3. Trust changes are fixed root transactions of `az-nexus-commission`.**
`trust-enroll` (new), `trust-repin --reason R` and
`knowledge-revocation-accept` run in `lite_trust_ops`:

1. as root: refuse a non-root caller; for enrollment and repin, require a
   local terminal and fresh confirmation words; for enrollment, verify the
   node's commissioning evidence the way the pass does
   (`load_commissioning_evidence`) and keep only its digest;
2. in a forked child that has irrevocably become `azcommission` (groups
   `azknowledge` and `azaudit-submit` exactly as the commissiond unit,
   umask `0027`, `no_new_privs`, root unreachable, all read back): take the
   commissioning lock, append the `..._requested` record to az-auditd and
   **refuse before any change if that append fails**, run the same library
   code commissiond runs, append the outcome.

Inputs are fixed leaves in `/etc/azazel/commissioning` (root installs them
`root:azcommission 0640`); no command takes a path, key, policy, flag or
environment variable. `az-commissiond` keeps its two trust verbs for a
bootstrap boot; they take the same lock. The CLI's socket client for them
is removed, not kept unused.

**D4. First enrollment is one checked request** (`lite_enrollment`,
schema `azazel-nexus/lite-enrollment/v1`, closed shape): bundle-signing keys
by id, optional key roles, `threshold`, optional `required_signer_role`,
`minimum_security_epoch` and `accepted_export_policy_digests`, the revocation
authority (keys, threshold, generation) and `commissioning_digest`.

* `threshold` must be an `int` (not a bool) with
  `1 <= threshold <= keys that can meet it` (the keys holding the required
  role, when one is named); the revocation threshold likewise against the
  revocation keys. This is the rule Knowledge is adopting for its anchors
  in a separate change (S-15).
* No key holds both roles (by material or id); a bundle key cannot carry the
  role `revocation-signing`.
* The published fixture key (`lab_keys.PUBLIC_FIXTURE_KEYS`) is refused in
  either role off a marked lab host.
* `commissioning_digest` must equal the digest of the evidence verified in
  step 1 of D3 (`binding_mismatch`); no verified evidence, no write
  (`evidence_unavailable`).
* A root that holds a trust record (`trust.json`, `trust-current`) is
  refused (`already_enrolled`); one that holds anything but enrollment
  residue is refused (`trust_root_not_empty`).
* Writes go `trust/anchors.toml`, `revocation-policy.json`, then
  `trust.json` -- the commit point; every reader treats the root as
  untrusted until it exists. Each file is synced, renamed, `0640`
  (directory `2750`), owned by `azcommission`, group `azknowledge` from the
  root's setgid. An enrollment interrupted before the commit leaves only
  residue nobody trusts, and running the same request again replaces exactly
  that residue and completes.

**D5. A repin may replace the anchor with the keys.** The repin document
may carry `anchors` (the anchor fields of D4 plus boolean `sealed`, checked by the same code,
naming exactly the proposed keys). The repin then writes
`trust-generations/N.anchors.toml` beside its generation record and marks the
record `"anchors": true`; the pointer move switches keys and anchor
together, and every reader takes the anchor that goes with the record it
read (`TrustStore.anchors_path_for`). A key change whose kept anchor no
proposed key could meet is refused instead of leaving a root that verifies
nothing.

Replacement anchors preserve an explicit seal; omission inherits the current
seal (and refuses if it cannot be read). Only explicit `sealed: false` requests
unsealing through the existing authorised repin. Unknown nested fields are
refused rather than silently discarded.

**D6. Audit.** auditd binds `knowledge.lite.trust_*` (new: enroll requested,
enrolled, refused; repin requested, promoted, refused) and
`knowledge.lite.revocation_*` to `azcommission`; one account may now hold two
prefixes and still nothing else. Records carry digests, counts and fixed
codes. Repin keeps its own commissioning ledger; the auditd record names the
promoted generation, which the ledger's `trust.repin.promoted` names too, so
the two are matched by generation (M11: a shared key, not a merged ledger).
The accepted-revocation record's list sequence is now `list_sequence`: the
field was named `sequence`, which auditd assigns itself and refuses in a
payload, so every accepted list had gone unrecorded (found by the real
process run of this change).

**D6a. Past the commit point is never "refused" (review R390-02).** The
enrollment reads `trust.json` back when its write fails: absent is a refusal;
present with the request's record is an enrollment in force with
`durability: unsynced`; anything else is `unknown`. A repin failing at or
after the pointer move raises `lite_trust.RepinUncertain` with the pointer
read back (`pointer_unsynced`, `ledger_incomplete`, `unknown`). Replies and
auditd records carry that state (`trust_enrolled.durability`,
`trust_repin_promoted.state`, `trust_enroll_unconfirmed`,
`trust_repin_unconfirmed`).

**D6b. Both repin entries record the same way (R390-03).** The auditd records
of a repin are `RepinConfirmation.confirm`'s, so commissiond's socket entry
also needs auditd's receipt before any change. A kept anchor is checked with
the verifier's own count (`lite_bundle.meetable_keys`: pinned, not revoked,
holding the required role; R390-01).

**D6c. The narrowed child inherits nothing but its terminal and result pipe**
(R390 §3): every other descriptor is closed and the environment replaced by
a fixed `PATH`/`LANG` before it changes identity. The descriptors are
enumerated from `/proc/self/fd`, not taken as a range up to the open-file
limit, so one above a lowered limit is closed too; anything still open
afterwards, or no `/proc`, makes the child refuse (R390b-01).

**D7. Fail-closed, and nothing new to approve.** A stopped auditd refuses an
import, an enrollment, a repin and a revocation before any change. No
approval boolean, environment variable, unit operation or flag is added; the
loop's audit writer is granted only by the existing approval chain.

## Change to owner decisions 2 and 8 (2026-10-30, delegated)

* **Decision 2 (scope)**: the loop's scope adds
  `azazel-auditd-loop.service`. Commissiond, the bootstrap helpers, watchdog,
  fetchd, locald and remoted stay excluded.
* **Decision 8 (audit for loop daemons)**: "auditd stays bootstrap-only"
  becomes "the bootstrap helper `azazel-auditd.service` stays
  bootstrap-only; the loop has its own writer of the same chain". The
  decision's own condition ("confirm sink behaviour before P4") is answered
  by the loop's need: an import and a trust change must be recorded before
  they happen, and the ordinary path could record neither.

**Impact.**

* A policy that does not name the new unit behaves exactly as before: imports
  and trust changes are refused (`audit_unavailable`). To use the Lite entry,
  name it in the policy, publish a generation over its unit file and sign an
  approval (the existing chain; nothing is granted by this change alone).
* The ordinary path now appends to the chain: the explainer's incident
  records land instead of being dropped and counted. The bootstrap's
  pre-start policy pins the chain head exactly, so the next bootstrap is
  signed against the head as it is then -- as after any earlier bootstrap.
  Capacity planning ([operations](../operations.md)) applies to the ordinary
  path too.
* If the loop's writer stops, it is not restarted in the same boot: a
  `systemctl start` re-runs the pass, which fails closed (§10.2 M-5). Imports
  and trust changes are refused until the next boot's pass grants it again.
* The store-local `knowledge/trust/anchors.toml` (read only by
  `azazel-nexus pack` and the library import without commissioned trust) is
  not written by the enrollment; §11 step 8 copies it when a Mission Pack
  uses that store.

## Not decided here

* K7 (M12): how Knowledge's `anchors.revoked` reaches Nexus's signed
  cumulative revocation list. A producer/consumer contract; unchanged.
* Re-binding trust after a re-commissioning: the daemons still read the
  binding from the trust record and do not compare it with fresh evidence.

## Verification (2026-10-30)

Recorded in the implementing PR, by environment: unit tests (mocks and
in-process production code), the real-process stages of `tools/e2e.py` as
root in a Debian 13 container (`tools/e2e_lite_trust.py`), and a systemd
check of the unit file. None of it is VM or hardware evidence.
