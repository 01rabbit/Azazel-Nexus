# Observe-baseline activation — design proposal (#206)

Owner: [#206](https://github.com/01rabbit/Azazel-Nexus/issues/206) (parent
[#190](https://github.com/01rabbit/Azazel-Nexus/issues/190)).
Status: **accepted with the recommended defaults of §6 (owner, 2026-10-20);
P0, P1 (library only), P2 (readers, §7), P3a (the off-host signer's
`activation` purpose), P3b (the node's `az-activation` tool:
`generation-publish`, `request`, `install`), P4 (SUPPORTING wired into the
pass, §8) and P5 (§3.4: probe contract v2, the boot preflight and edge-core
in the pass's scope, §8.1) implemented; P6 rehearsed once on the VM on
2026-10-23 (mechanics only, not evidence:
[activation rehearsal §0.1](hil-runbooks/activation-rehearsal.md#01-run-of-2026-10-23-mechanics-only))**.
Phases land as separate PRs (§4).

Before P4 no regular path admitted the integrated loop's units: `az-activated`
composed its production pass with `lease=None` and `healthy=False`, granted
nothing and recorded `activation.inputs_incomplete`
(`runtime/src/azazel_nexus_runtime/activated.py`). Since P4 the pass can grant
the five SUPPORTING loop units (§8) from the generation, approval and high
water that `az-activation` (P3b) produces. The boot sequence (P6) was
rehearsed once on the VM on 2026-10-23, signed with a VM-only rehearsal key;
that is mechanics only, never hardware evidence. The integrated loop rehearsal
([#195](https://github.com/01rabbit/Azazel-Nexus/issues/195)) started the
loop by the rehearsal-only procedure, and its result says *activation
admission: not exercised*. This document proposes the smallest set of
producers that lets the regular pass admit the loop's units, under the
existing invariants, and the order in which to build them.

It adds no decision or enforcement authority, no approval boolean, no
environment-variable or flag bypass and no unit operation. Every new input can
only narrow what the pass grants, and every failure leaves the pass exactly as
it is today: `lease=None` or `healthy=False`, everything masked.

## 1. Findings that shape the design

1. **Nothing publishes an operational generation.**
   `ActivationController.activate` (`src/azazel_nexus/activation.py`) withholds
   everything with `no_generation` unless `/var/lib/azazel/generations` holds a
   verified generation, and no production code writes there (the mission pack
   uses its own store; a bootstrap generation is a distinct variant ordinary
   readers refuse). A valid lease alone therefore grants nothing. The
   generation publisher is missing from `missing_producers` and is added as
   `operational_generation_publisher` (§3.2).
2. **A boot-bound approval cannot serve "a grant enables a later boot".**
   `ActivationContext.boot_id` (`src/azazel_nexus/activation_approval.py`)
   binds today's approval to the boot it was signed for, while a grant only
   enables a unit (the manager has no `StartUnit`,
   `runtime/src/azazel_nexus_runtime/units.py`). The units would start at the
   next boot, whose `boot_id` nobody can sign in advance.
3. **Edge evidence is never fresh when the boot pass runs.**
   `azazel-edge-probed.service` is ordered after and requires the controller,
   and a probe result from before a kernel reboot is stale
   (`src/azazel_nexus/edge_package.py`). The #198 wiring in `activated.py` is
   correct, but with this ordering the boot pass always withholds edge-core
   with `edge_not_ready`. Addressed by E1 (§3.4, P5 probe half).
4. **auditd cannot run under the ordinary pass.** It has
   `BindsTo=azazel-activated.service`; the ordinary pass exits, which would
   stop it. auditd stays with the supporting-only bootstrap supervisor and is
   out of scope here.

## 2. Producers: required and not

Scope: `azazel-edge-intaked`, `azazel-incident-explaind`,
`azazel-edge-probed`, `azazel-mio-entryd`, `azazel-knowledge-lited`
(SUPPORTING) and `azazel-edge-core` (EDGE_BASELINE, phase P5).

| producer | for this scope | note |
| --- | --- | --- |
| `activation_approval_loader` | required | wire `load_activation_approval` with a boot-free v2 payload (§3.1) |
| `node_identity` | required | the declared node digest, cross-checked against the administrator deployment declaration |
| `activation_policy` | required | protected `/etc/azazel/activation/policy.json`: authorized operators, `max_lease_seconds`, exact unit scope, health floors, clock skew, and optionally `require_clock_synchronized` (§10.1) |
| `epoch_high_water` | required | anti-replay and rollback floor (§3.5) |
| `trusted_clock` | required | a persisted monotonic time floor (§3.5); with `require_clock_synchronized`, also this boot's synchronization (§10.1) |
| `node_health` | required | controller-owned local prerequisites only (§3.3) |
| `operational_generation_publisher` (new) | required | observe-baseline generation (§3.2) |
| `edge_evidence` | edge-core only | #198, boot-bound by the preflight (§3.4); withholds edge-core only, never the pass (§8.1) |
| `authenticated_commissioning`, `inventory_binding` | required | already satisfied by `load_commissioning_evidence()` on a commissioned node |
| `authoritative_commissioning_admission` | not required | only ENFORCEMENT consumes the record |
| `renderer_measurement` | not required | no renderer exists; no ENFORCEMENT unit is in scope |

Unimplemented producers stay named in `missing_producers`. A v2 approval
cannot express ENFORCEMENT scope, so ENFORCEMENT units stay withheld.

## 3. Producer designs

### 3.1 Activation approval (schema v2, boot-free)

- **Files.** `/etc/azazel/activation/approval.json` and `approval.sig`, read by
  the existing reader in `activation_store.py` (directory root `0700`, files
  `0600`, single link).
- **Payload** `azazel-nexus/activation-approval/v2`, canonical JSON:
  `approval_id`, `operator`, `node_digest`, `generation`, `generation_digest`,
  `commissioning_digest`, `commissioning_evidence_binding` (the HMAC binding,
  so no raw inventory digest leaves the node), `policy_digest`,
  `security_epoch`, `approval_seq`, `units` (sorted, a subset of the policy
  scope), `granted_at`, `expires_at`. No `boot_id`, no `renderer_digest`; v2 is
  valid only for SUPPORTING and EDGE_BASELINE units. v1 is unchanged, and
  neither version is accepted as the other.
- **Signing** stays on the operator's workstation: `tools/operator_sign.py`
  gains an `activation` purpose using the existing
  `ApprovalPurpose.ACTIVATION` transcript. No seed reaches the node, Git or a
  log.
- **Signer (P3a).** `tools/operator_sign.py --purpose activation` keeps the
  existing checks (payload SHA-256 typed from the node, derived public key
  equal to the enrolled one, owner-only single-link seed file, create-only
  `0600` signature, nothing else written or logged). Before signing it also
  requires the payload to be a well-formed v2 document that re-encodes to
  exactly the same bytes, with a validity window of at most 72 hours, so v1
  or arbitrary bytes are refused and not signed. Since #251 L-4 it also
  refuses, without signing, a payload whose `units` leave the node's
  code-fixed `ACTIVATION_UNIT_ALLOWLIST` (`activation_policy.py`), the same
  set every node policy must be a subset of. It prints the operator,
  approval id, units, generation and its digest, node digest, epoch,
  sequence and validity window; the commissioning evidence binding is
  checked but not printed. This is a shape check only: the node verifier
  still decides against its own context, policy and floors. The payload
  comes from `az-activation request` (below).

  ```sh
  PYTHONPATH=src uv run --no-project --with 'pynacl>=1.5' python -m tools.operator_sign \
    --purpose activation --payload approval.json \
    --expect-payload-sha256 NODE_PRINTED_SHA256 --expect-public ENROLLED_PUBLIC_HEX \
    --seed /path/outside/any/checkout/operator.seed --out approval.sig
  ```
- **Request and install (P3b).** The runtime operator tool `az-activation`
  (console script of `azazel-nexus-runtime`, like `az-nexus-bootstrap`; no
  unit, no libexec wrapper) has no path, root or context override.

  ```sh
  # read-only; root in practice, since the protected inputs are root-only
  az-activation request --operator LABEL --approval-id ID --seq N \
    --valid-for SECONDS [--units UNIT,UNIT] --out request.json
  # off-host: tools/operator_sign.py --purpose activation (above)
  sudo az-activation install --payload request.json --signature approval.sig \
    --confirm-sha256 PAYLOAD_SHA256 [--replace] [--recover-high-water NAME]
  ```

  `request` collects the context independently: the declared node digest
  (`/etc/azazel/node.yaml` cross-checked against the administrator deployment
  declaration), the current generation verified as an observe baseline
  against freshly measured unit files (§3.2), the commissioning digest and
  evidence binding from `load_commissioning_evidence()`, the activation
  policy digest, and `security_epoch` from the declaration. `units` is the
  policy scope or a `--units` subset, `granted_at` is now (UTC, whole
  seconds) and `expires_at` is `now + --valid-for`, which must be within the
  policy's `max_lease_seconds`. The operator must be named by the policy and
  hold an active enrolled key. It writes the canonical payload, without a
  trailing newline, to a create-only `0600` `--out` file, and a summary with
  `payload_sha256` to stderr. The summary omits the evidence binding and the
  commissioning digest, but the payload itself contains both (the operator
  signs them), so since #251 L-4 the payload goes only to `--out`: the file
  is created through a parent reached without following any link and not
  writable by group or others (a shared directory such as `/tmp` is
  refused). Without `--out` it prints the summary only, writes nothing to
  stdout or anywhere else and exits 1, so the bytes never reach a terminal
  or a redirect with the caller's umask. It never signs and never writes an
  approval file.

  `install` (root) reads the payload and the 64-byte signature (regular,
  single-link files, never followed links), requires `--confirm-sha256` to
  equal the payload SHA-256, collects the same context again and verifies
  with `verify_observe_baseline_approval` against the activation policy, the
  current high-water floors and the OS clock (refusing a clock behind
  `time_floor - skew`); an approved generation below the floor also
  refuses. Once a floor exists (a high-water file, or the floors a §7
  recovery takes), `install` also requires `approval_seq` **above** the
  floor's (#251 L-3): a sequence at the floor is spent, so a different
  approval with the same sequence is refused. The one exception is the
  byte-identical installed pair (payload and signature) installed again
  with `--replace`, which is idempotent; that equality is checked again
  under the directory's exclusive lock before anything is renamed. The
  pass's own check (`approval_seq` below the floor refuses) is unchanged,
  so an installed approval whose sequence the floor now equals still
  verifies at the next boot. It shows what was verified, then re-collects and compares
  everything before writing. Order: the high water is raised to the approved
  epoch, sequence and generation with `time_floor = now` (never lowered,
  bounded by `now + skew`), or initialized as below; `approval.json` and
  `approval.sig` are written as private temporary files, fsynced, renamed
  under an exclusive lock, the directory fsynced and the pair read back; then
  `activation.approval_installed` is appended to
  `/var/lib/azazel/state/activation.jsonl`. An installed pair is replaced only
  with `--replace` **and** typing `REPLACE`; the presence of a pair is checked
  again after confirmation and once more under the directory's exclusive lock,
  and a pair that appeared in between refuses. `/etc/azazel/activation` is
  created root `0700` by `packaging/install.sh`; the policy is placed there by
  the administrator. A crash between the two renames
  leaves a pair whose signature does not verify, which every reader refuses.
  Exit 1 means nothing changed; exit 2 means a step after the first write did
  not complete (inspect, do not retry blindly). It creates no key and enables
  nothing; the next boot's pass (§8) is what may grant.
- **Verification** on every pass: the existing trust verification and
  canonical re-encoding against independently collected context; the operator
  must be authorized by the activation policy (enrollment alone is not
  enough); duration ≤ `max_lease_seconds`; `approval_seq` ≥ high water;
  `units` ⊆ policy scope.
- **Lease.** The existing `ActivationLease` gains an optional `units`. In the
  library's withholding check, a unit outside `lease.units` is withheld as
  `outside_lease_scope`. A lease can only remove units; this is what keeps the
  rest of SUPPORTING (commissiond, watchdog, fetchd, model hosts) out.
- **Revocation.** Operator keys: the existing revoked set, re-read each pass.
  Approvals: raise `security_epoch` (§11) or the `approval_seq` floor. Expiry:
  `expires_at` against the time floor (§3.5).
- **Failure.** Any error → `ApprovalRefused` (already redacted) → `lease=None`.
- **Library (P1).** `src/azazel_nexus/activation_approval_v2.py`:
  `observe_baseline_payload` builds the canonical bytes and
  `verify_observe_baseline_approval` checks them against an
  `ObserveBaselineContext`, an `ActivationApprovalPolicy` (authorized
  operators, `max_lease_seconds` capped at 72 h, unit scope) and the epoch and
  sequence floors, all supplied by the caller; it returns the scoped lease
  plus the `approval_seq` and `security_epoch` a later pass raises its floors
  to. `tests/unit/test_activation_approval_v2.py` uses in-memory keys only.

### 3.2 Observe-baseline generation

A generation in `/var/lib/azazel/generations` whose tree is one canonical
`baseline.json` (`azazel-nexus/observe-baseline-generation/v1`): the exact unit
list, the Edge pin (version and digest), and the SHA-256 of each scoped unit
file as installed, including the observe-only `Environment=` lines of
`azazel-edge-core.service`. Its metadata carries the commissioning digest and
the evidence binding the pass already checks. A root `az-activation
generation-publish` writes it after a printed SHA-256 and typed confirmation.
Publishing is not admission; the operator's signature over
`generation_digest` is. The pass re-verifies it every time; a missing or
altered tree withholds everything (`no_generation`, `generation_unverified`).

`sudo az-activation generation-publish` (P3b, interactive terminal only)
reads the scope from the activation policy and measures each scoped unit file
in `/usr/lib/systemd/system` through descriptors (root-owned, not group or
other writable, single link, no symbolic link at any component; the profile's
`/lib/systemd/system` is the merged-/usr link to it). When edge-core is in
scope it adds the installed package digest and the digests of the extracted
files the unit actually uses -- `bin/azazel-edge-core` (executed) and
`config/redirect_policy.yaml` (named by its observe-only `Environment=`) --
as `edge_pin.components`, and only if the package's own checks pass and the
components agree (`edge_package.installed_package_components`: present,
observe-only, unsigned, pinned version, artifact digest equal to the
manifest; then, for each component, the manifest's component digest, the
digest of that member of the verified archive (read bounded, never
extracted) and the digest of the extracted file (opened without following
links at any component, root-owned, not group or other writable, single
link, bounded) must be equal). The manifest is unsigned: the equality is
integrity at publication, and the operator's signature over the generation
is what binds the values afterwards. The
commissioning digest is the SHA-256 of the signed full proposal that
`load_commissioning_evidence()` verified, and the binding is its HMAC; without
verified evidence it refuses. It prints the units, the next generation number
and the generation digest, requires the digest to be re-entered and
`PUBLISH` typed, measures everything again, publishes through the ordinary
`GenerationStore`, re-verifies the published generation and appends
`activation.generation_published` (with `verified`) to the activation ledger.
Any failure after the store accepted the generation exits 2 and names it as
published but not verified, so it is never reported as "nothing published".
If the current generation already is that baseline it publishes nothing.

The hash describes the loaded unit only if nothing else contributes to it, so
measuring refuses overrides
(`runtime/src/azazel_nexus_runtime/activation_unit_files.py`, the same check
P4's pass makes every boot; `request` and `install` make it too). Across the
reviewed Debian 13 systemd search path it refuses: a same-name entry in any
directory other than `/usr/lib/systemd/system`, unless it is a symbolic link
to exactly `/dev/null` (a mask, the governed state before a grant); and any
entry in a drop-in directory -- `<unit>.d/`, the dashed-prefix forms
(`azazel-.service.d/`, `azazel-edge-.service.d/`) and the global
`service.d/` -- in every search-path directory, the vendor one included. An
`/etc` or `/run` drop-in changing, for example, edge-core's `Environment=` or
`ExecStart=` therefore refuses rather than passing under an unchanged hash.

The hash alone would also accept a vendor file that never waits for a grant
(#251 H-1): the grant marker of §5 is safe only if the unit carries its
`ConditionPathExists=`, `Requires=` and `After=` on the controller. So the
same measurement also checks each file's text
(`require_governed_unit_content`) before it is hashed; §8.2 lists the rules.
A file that fails refuses `generation-publish`, `request` and `install`
("lacks its grant-marker lines or changed a start condition") and fails the
pass's generation producer, like a changed file.

### 3.3 node_health

`healthy` is computed by the controller, after its preflight narrowing, from
fixed checks whose thresholds come from the activation policy:

1. the activation ledger appends and its chain verifies;
2. state-volume capacity meets the policy floors (reusing the bootstrap
   capacity and resource checks; absent floors mean unhealthy);
3. operator trust loads with at least one active key;
4. no lab marker;
5. the watchdog fence store is readable and holds no fence.

It does not claim that services respond, that Edge is healthy, or anything a
service reports about itself. Any exception or absence is unhealthy.

### 3.4 Edge evidence ordering

- **E1 (recommended).** A non-governed, read-only
  `azazel-edge-probe-preflight.service` runs the same `az-edge-probed` as
  `azprobe` with the same sandbox, ordered before the controller, and writes a
  result bound to the current boot (probe contract v2 adds `boot_id`, so a
  result from the previous boot is never reused within its TTL).
- **E2.** Keep edge-core out of scope; record `edge_evidence: not fresh at pass`.

In both, `running` is not required to launch, `edge-baseline-ready` still
needs all five checks, and stale or unreadable evidence is a failed check.

**Status (P5, probe half): E1 implemented.** Probe contract
`azazel-nexus/edge-probe/v2` adds `boot_id`, read by the probe from
`/proc/sys/kernel/random/boot_id` with `edge_package.read_current_boot_id`
(no symlink, root-owned regular file, bounded, canonical UUID); when it cannot
be read the probe writes nothing. Readers (`installed_baseline_state`, which
the pass already calls, and `azazel-nexus status`) use a result only when its
`boot_id` equals the current boot's, in addition to the TTL; otherwise health
and running are `not-checked` with `stale: from another boot`. A v1 result
names no boot and is always stale; an unreadable current boot id makes every
result stale. `azazel-edge-probe-preflight.service` is generated by
`hardening.py` from the governed probe's profile (same binary, `azprobe`,
`AF_UNIX` only, `IPAddressDeny=any`, same result leaf), runs at every boot
before any approval is consulted, executes the digest-verified package's
`bin/azazel-edge-core --health` as `azprobe` and grants nothing; it is ordered
`Before=azazel-activated.service`, `WantedBy=multi-user.target`, installed
and enabled (never masked) by `install.sh` and the preset, and absent from
every governed list. At boot its `running` is `failed`, since edge-core has
not started; launch needs only the four package checks with fresh health.

**Status (P5, edge-core in scope): implemented (§8.1).** The pass reads the
preflight's result through `installed_baseline_state` and grants edge-core
only when the four package checks pass with fresh health from this boot and
the installed package is the one the generation pins. The controller does not
require the preflight (`Before=` on the preflight, nothing on the
controller): when the preflight failed, timed out or wrote nothing, the pass
runs as usual, edge-core is withheld with `edge_not_ready:
health_endpoint_healthy`, and the SUPPORTING units are decided without it.

### 3.5 Clock floor and high water

`/var/lib/azazel/state/activation/high-water.json` (root `0600`, written
atomically) holds `security_epoch`, `approval_seq`, `generation` and
`time_floor`. A node that already has an activation ledger but no high-water
file refuses; first initialization happens only through `az-activation
install`. Each pass requires the declared and approved epochs to match and be
at or above the floor, `approval_seq` and `generation` at or above the floor,
and the OS clock at or above `time_floor − skew`; then raises the floor after
recording its decision. A fast clock only expires leases early; a slow clock
is caught by the floor. This is local trust, not authenticated time or a
tamper-proof record, and the documentation says so.

`az-activation install` initializes a missing floor only when the activation
ledger records no floor: no `activation.approval_installed`,
`activation.high_water_recovered` or `activation.unit_granted` event (the
pass's `activation.inputs_incomplete` records and generation publications are
not floors, since every booted node has them). The ledger must be a
protected, single-link file whose chain verifies; an unreadable or broken
ledger refuses rather than reading as empty. P4 adds the events its pass
records when it raises the floor. The initial floor is the approved epoch,
sequence and generation with `time_floor = now`. With a floor history and no
file, only the §7 recovery applies.

Limits, stated rather than solved: root can truncate the tail of the
hash-chained ledger (a shorter chain still verifies) **and** delete
`high-water.json`, after which `install` initializes a low floor; only an
external record of the chain head would catch that. The rule also differs
from P2's `require_high_water_for_pass`, which refuses a missing file whenever
the ledger exists at all: a pass never initializes, so on a booted node it
refuses until `install` has written the first floor. `install` and
`generation-publish` append to the same ledger as `az-activated` without a
shared lock (`AuditLedger` re-reads the head on each append but offers no
cross-process lock); an interleaving would break the chain, which every
reader then refuses. Run them while no pass is running.

### 3.6 Composition

In order: preflight remask; commissioning evidence; independent context (node,
generation, evidence, policy, epoch); approval → lease; clock and high water;
health; `activate(lease, healthy, record=None,
require_commissioning_evidence=True)`. The grant tripwire changes from "any
grant raises" to "a grant outside `lease.units`, or any grant without a lease
and health, remasks and raises". `az-activated` still takes no arguments.

## 4. Phases

Each phase is one small PR. P0–P3 do not change production behaviour: the
pass keeps `lease=None`.

| phase | content |
| --- | --- |
| P0 | this document; owner answers recorded; generation publisher added to `missing_producers` |
| P1 | library only: v2 payload and verifier (ephemeral-key tests for every mismatch, expiry, revocation, non-canonical bytes, v1/v2 cross-refusal); `ActivationLease.units` and `outside_lease_scope` |
| P2 | inert readers: activation policy, high-water store, health collector, observe-baseline verifier (file-race, symlink and permission refusals) |
| P3 | operator tooling, still no grant path: `operator_sign.py` `activation` purpose; `az-activation request`, `install`, `generation-publish` |
| P4 | wire SUPPORTING in `_run_once` (fake manager tests: only scoped units granted; each absent producer refuses; epoch, clock, expiry and tree tampering refuse; tripwire on out-of-scope grant) |
| P5 | EDGE_BASELINE: probe preflight (E1), probe v2 boot binding (§3.4), edge-core in scope (§8.1); all implemented |
| P6 | VM rehearsal with a VM-only rehearsal key: publish → request → sign on the workstation → install → reboot → granted → reboot → started; negative runs (approval removed, epoch raised, operator revoked, clock moved back, tree altered, probe stale) each leave units masked **and not started**. Recorded as rehearsal, never evidence; procedure: [activation rehearsal](hil-runbooks/activation-rehearsal.md) |

## 5. Risks

- **Same-boot masking does not stop a queued start (VM-confirmed,
  2026-10-20).** On the rehearsal VM (Debian 13, systemd 257) a harmless
  enabled unit ordered after a oneshot that masked it during boot still
  started, both with `systemctl mask --runtime --no-reload` and with a mask
  followed by a daemon reload (the reload ran, `Reloading finished`, and the
  unit, which had a pending start job, stayed loaded and started right after).
  So masking at the pass can never withhold a unit the previous pass enabled
  in the same boot. **Resolution adopted for P4:** every governed loop unit
  carries `ConditionPathExists=/run/azazel-activation/granted/<unit>`, and the
  controller writes that marker (root-owned, under a root `0755` directory on
  the volatile `/run`) only for the units granted by this boot's pass, after
  recording the decision. A unit without its marker is skipped
  (`unmet condition check`) rather than started; with it, it starts normally
  (both VM-confirmed with the same harmless test units). The marker grants
  nothing by itself: absence only withholds, it is cleared at every kernel
  boot (not at a soft-reboot: §10.2, L-7), the controller still never
  starts a unit, and masking remains for the next boot.
  This replaces default 9's fallback (reusing the bootstrap reload), which the
  VM showed would not work. The test units were removed afterwards; this is
  VM rehearsal, not hardware evidence.
- **Local trust.** The high-water mark and time floor are protected by local
  trust only.
- **Keys.** Rehearsal keys are VM-only and never enrolled on a real node; test
  fixtures use in-memory ephemeral keys.
- **No refusal becomes success.** Existing refusals (`no_generation`,
  `generation_unverified`, `lease_*`, `edge_not_ready`) are untouched; exit 0
  still means "pass recorded", not "granted".
- **Edge stays the sole decider.** Nexus decides only whether the package may
  launch; the Edge evidence is read-only; the edge-core unit file, with its
  observe-only environment, is hashed into the generation.

## 6. Owner decisions

The owner accepted every recommended default (in brackets) on 2026-10-20.
A later change to one of them is recorded here with its date.

1. Boot binding: keep v1 (re-sign and start by hand every boot) or boot-free
   v2 with a short cap? **[v2, `max_lease_seconds` ≤ 72 h]**
2. Scope? **[the five SUPPORTING loop units; edge-core in P5; auditd,
   commissiond, watchdog, fetchd, locald and remoted excluded]**
3. Clock? **[OS clock + persisted monotonic floor + policy skew; the
   per-boot administrator time anchor as an optional stronger mode]**
4. Source of epoch and node identity? **[the administrator deployment
   declaration; high water under `/var/lib/azazel/state/activation/`]**
5. Do watchdog fences make the node unhealthy? **[yes, any fence or an
   unreadable store]**
6. Edge evidence ordering? **[E1]**
7. Generation content and publisher? **[§3.2; requires completed full
   commissioning evidence]**
8. Audit for loop daemons when auditd runs only under the bootstrap path?
   **[confirm sink behaviour before P4; auditd stays bootstrap-only]**
9. Same-boot mask semantics? **[P4 does not go live until P6 confirms it]**
   Answered by the VM on 2026-10-20: masking does not stop a queued start;
   P4 uses the per-boot grant marker of §5 instead.

**Proposed change to decision 2, 2026-10-28 (pending owner ratification in
review; not yet accepted).** Add `azazel-mio-referenced.service`, the model-free
playbook reference service, to the scope (`ACTIVATION_UNIT_ALLOWLIST` and
`activation_markers.GRANTABLE_UNITS`). Reason: the deterministic handoff's
playbook reference was served by `azazel-mio-locald.service`, which this decision
excludes and which is withheld anyway without `local_model_provider` wiring, so no
node in the loop could show verified playbook text when no AI answered. The new
unit runs no model, holds no model path, needs no wiring and is SUPPORTING; locald
and remoted stay excluded, and no enforcement, commissioning, watchdog or fetch
unit is added. A policy still has to name the unit for a pass to grant it: an
existing policy file is unchanged by this, and a node whose policy does not name
it keeps working without references (the handoff then reports
`reference_service_unavailable`). If the owner declines, the allowlist and grantable
set revert and the service stays installed, masked and unused.

**Change to decisions 2 and 8, 2026-10-30 変更（委任された技術判断）.**
Recorded by [ADR-0008](adr/0008-lite-trust-operations.md) under the owner's
2026-10-30 direction, which delegates technical decisions and asks for the
Knowledge Lite operating entry to be completed.

- *Decision 2 (scope)* adds `azazel-auditd-loop.service`, the integrated
  loop's audit writer, to `ACTIVATION_UNIT_ALLOWLIST`,
  `activation_markers.GRANTABLE_UNITS` and `CORE_UNITS` (SUPPORTING). The
  bootstrap helpers auditd and commissiond, watchdog, fetchd, locald and
  remoted stay excluded; a policy naming either helper is still refused.
- *Decision 8* changes from "auditd stays bootstrap-only" to "the bootstrap
  helper `azazel-auditd.service` stays bootstrap-only, and the loop has its
  own writer of the same chain". The helper unit is unchanged: the
  bootstrap's loaded-unit policy pins its `BindsTo=` to the controller, which
  exits right after READY on the ordinary path, so the helper could never
  serve the loop. The new unit runs the same program, account, chain and
  sockets with a loop unit's lifetime (marker, `Requires=`/`After=`, no
  `BindsTo=`), and az-auditd's one-writer lock keeps the two from ever
  writing at once.
- **Reason.** On the ordinary path no Knowledge Lite import could start
  (its start record is required) and no trust change could be recorded; the
  decision's own condition ("confirm sink behaviour before P4") is answered
  by that need. Trust changes do not bring commissiond back: they run as
  root's narrowed transaction (ADR-0008 D3).
- **Impact.** Nothing changes for a policy that does not name the unit. A
  policy that names it gets the chain on the ordinary path: the explainer's
  records are kept rather than dropped, the next bootstrap is signed against
  the head as it is then, and if the writer stops it is back only at the next
  boot (a same-boot `systemctl start` re-runs the pass, §10.2 M-5).

**Change to decision 2, 2026-11-12 (A1, #395 preparation).** Adds
`azazel-knowledge-contextd.service`, the optional Knowledge Context egress
broker, to `ACTIVATION_UNIT_ALLOWLIST` and `activation_markers.GRANTABLE_UNITS`
(`NON_GRANTABLE_MARKER_UNITS` stays, empty). It is SUPPORTING, loses its
`knowledge_context_transport` wiring requirement, and is granted by the same
lease, health, policy and commissioning-evidence checks as the other
SUPPORTING units; `wired_capabilities()` is unchanged. Locald, remoted and
fetchd stay excluded and a policy naming them is still refused as a whole.

- *The bundle is not a grant input.* A grant only lets the unit start. With
  no commissioned bundle (or a defective one) the broker starts and stays
  closed (`knowledge-context-consumer.md`). The unit stays masked, preset
  disabled and without an address allowance until a policy names it.
- *Closing.* The controller can stop this one unit and no other (§8.3).
  Removing the unit from the policy (re-signed), a lease that does not list
  it, an expired approval, a revoked operator, or failed health or
  commissioning evidence ends the grant: the next pass, or the periodic
  recheck within about 30 s, removes the marker, masks the unit, reloads the
  manager and stops it. A broker that cannot be confirmed stopped is
  reported (`activation.withdrawal_unconfirmed`, non-zero exit) and stays
  masked.
- *Order.* Introduce: install the release that carries this change first,
  then sign a policy that names contextd. Withdraw: remove contextd from the
  policy and re-sign, check on the next pass that it is closed, and only then
  go back to an older release. An older release given a policy that names
  contextd refuses that policy as a whole (allowlist), which makes the other
  SUPPORTING units lose their grant too (they are not stopped; they cannot
  be started again).
- *Dropping only contextd.* Changing the policy's `units` alone no longer
  matches the published generation, so that pass grants nothing, the other
  SUPPORTING units included. To keep them, republish a generation built for
  the reduced unit list and sign a new approval for it (higher sequence).
- *After a rollback.* Markers are removed and rewritten by every pass (they
  live under `/run`), so a stale contextd marker does not survive a pass.
  Masks are different: a unit the pass withholds stays masked, which is the
  safe state; only granted units are unmasked and enabled.

## 7. P2 readers (inert)

Phase P2 adds the readers of §3 without wiring them; `az-activated` imports
none of them (P4 then wired them, §8; `tests/unit/test_activation_p4_wiring.py`).

- `src/azazel_nexus/activation_policy.py`: `/etc/azazel/activation/policy.json`
  (`azazel-nexus/activation-policy/v1`), read like the approval (root `0700`
  directory, root `0600` single-link file, read twice). Closed canonical shape;
  `policy_digest` is the SHA-256 of the exact bytes. The file must be the
  canonical bytes themselves (sorted keys, no whitespace, **no trailing
  newline**); anything else is refused rather than normalized. `units` must be a subset
  of the code-fixed `ACTIVATION_UNIT_ALLOWLIST` (the five SUPPORTING loop
  units, edge-core, the reference service, the loop audit writer and, since
  A1, the Knowledge Context broker); `max_lease_seconds` ≤ 72 h and
  `max_clock_skew_seconds` ≤ 300 are capped in code. `state_floors` and
  `resource_floors` use the field names of the bootstrap capacity and resource
  checks. Reusing them means the capacity floors measure
  `state/bootstrap` and `state/audit`, not a dedicated activation volume.
  Since #251 M-1 one field is optional: `require_clock_synchronized`
  (`true` or `false`; absent and `false` change nothing, §10.1). It is kept
  as written, so a policy without it keeps its bytes and `policy_digest`.
  The schema stays `v1`: the shape is closed, so a reader from before the
  field refuses a policy that carries it as a whole instead of ignoring a
  `true`, and existing policies stay valid without a migration. A `v2`
  would have bought nothing but a second accepted schema.
- `src/azazel_nexus/observe_baseline.py`: builder and verifier of the
  `baseline.json` tree, against a caller-supplied scope and installed unit
  file bytes. `edge_pin` holds the pin `version`, a `contract_digest` (the
  SHA-256 of the canonical `edge_package.PIN` record, which carries no
  artifact digest of its own) and, exactly when `azazel-edge-core.service` is
  in scope, the caller-supplied `package_digest` of the installed archive (the
  value the manifest check compares) and, since P5, `components`: the SHA-256
  of exactly `bin/azazel-edge-core` and `config/redirect_policy.yaml` as
  extracted. The operator's signature over `generation_digest` therefore
  binds one specific Edge package and the extracted files the unit uses;
  outside that scope both fields are forbidden. A generation published
  before P5 with edge-core in scope lacks `components` and is refused; it
  was never admissible (P4 refused edge-core) and is re-published. The tree is refused by the bootstrap verifier
  and refuses every other tree.
- `runtime/src/azazel_nexus_runtime/activation_high_water.py`: read
  (absent is `None`, anything malformed refuses), initialize once, raise-only
  update (temporary file, fsync, rename, directory fsync, read-back), and
  `require_high_water_for_pass`, which refuses a missing file when
  `/var/lib/azazel/state/activation.jsonl` exists. Initializing and raising
  take the caller's `now` and the policy skew and refuse a `time_floor`
  beyond `now + skew`, so one pass with a fast clock cannot set a floor the
  node then never reaches.
- `runtime/src/azazel_nexus_runtime/activation_health.py`: the five checks of
  five prerequisites of §3.3 as `(healthy, findings)`, with six findings
  (capacity and resources reported separately), capacity first. The ledger
  check is read-only: the file, if present, must be a single-link regular file
  owned by root and writable by its owner only, and its chain is verified
  once. It never creates or appends; a missing ledger is an empty chain, and
  writability is proven by the controller's own decision record. A missing `fences.json` inside the
  watchdog's own directory is the watchdog's "never fenced" state and reads as
  no fence; a missing directory, a foreign owner or a malformed file is a
  fence.

### Recovering from a time floor set too far ahead

The code never lowers a floor. If `time_floor` is nonetheless ahead of the
real time (a clock that was wrong when the floor was raised within its skew,
or a file written by hand), every pass refuses on the clock check, which is
the safe state. Recovery is an explicit, root-only administrator act, not a
flag or an environment variable:

1. Keep the node masked; confirm the real time from an independent source.
2. Record the decision in the audit trail (who, why, the old floor) before
   touching anything.
3. Move `high-water.json` aside (keep it for the record). The pass then
   refuses on "high water absent on a node with an activation ledger", so
   nothing is admitted in between.
4. Re-initialize through `az-activation install` (P3), which writes a fresh
   floor no lower in `security_epoch`, `approval_seq` and `generation` than
   the retained file, with `time_floor` from the confirmed clock, and appends
   its own audit event. Approvals signed against the old floor remain valid
   only if their sequence still meets it; `install` itself accepts only a
   sequence above the recovered floor, or the byte-identical installed pair
   again (§3.1).

   Concretely: keep the moved-aside file inside
   `/var/lib/azazel/state/activation/` (root `0600`, single link, for example
   `high-water.json.retained-YYYYMMDD`) and run
   `sudo az-activation install --payload … --signature … --confirm-sha256 …
   --recover-high-water high-water.json.retained-YYYYMMDD` (with `--replace`
   if an approval is installed). It is refused while `high-water.json`
   exists. It decodes the retained file, takes the highest counters of that
   file and of every floor the activation ledger records, verifies the
   approval against those floors, prints the retained floor and the node's
   clock, and requires `RECOVER` to be typed. It appends
   `activation.high_water_recovered` (retained floor, ledger floors, new
   floor) **before** writing the new floor, then installs as usual. The
   retained file is left in place.

## 8. P4: SUPPORTING wired into the pass

`_run_once` (`runtime/src/azazel_nexus_runtime/activated.py`) composes §3.6
through `runtime/src/azazel_nexus_runtime/activation_pass.py`, which the
controller imports only inside the pass, after narrowing; importing the
controller loads no reader (`tests/unit/test_activation_p4_wiring.py`).

1. **Grant markers reset**, then the unchanged preflight remask. Stale markers
   that cannot be removed are recorded (`activation.grant_markers_unclean`)
   and the pass fails after narrowing.
2. **Producers**, in order: full commissioning evidence; node identity
   (`declared_node_binding`: the protected `/etc/azazel/node.yaml` label
   hashed with `declared_node_digest` must equal the administrator
   deployment declaration's `node_digest`, whose `security_epoch` is the
   declared epoch); the activation policy; the high water
   (`require_high_water_for_pass`; absent refuses, since only the operator's
   install initializes it) with the declared epoch at or above its floor; the
   clock (`now ≥ time_floor − max_clock_skew_seconds` and, only when the
   policy says `require_clock_synchronized`, this boot's synchronization,
   §10.1); the current
   generation verified as an observe-baseline tree against the policy scope
   and the unit files **measured now**, its evidence binding equal to the
   evidence's and its `commissioning_digest` equal to the SHA-256 of the
   signed commissioning proposal (`evidence_commissioning_digest`), at or above
   the generation floor; what the running manager loaded for the same units
   (`systemd_loaded_units`, §8.2); the v2 approval
   (`load_observe_baseline_approval` in `activation_store.py`) against that
   context with the epoch and sequence floors; and node health
   (`collect_node_health`).
3. **All or nothing.** Unless every producer verified, the decision gets
   `lease=None` and `healthy=False`, exactly as before.
   `activation.inputs_incomplete` (kept as the event name) now names only the
   producers that failed, plus the two not required or not built for this
   scope (`authoritative_commissioning_admission`, `renderer_measurement`)
   and, unless edge-core is in scope with launchable bound evidence (§8.1),
   `edge_evidence`; producers that could not run because an earlier one
   failed read `not_attempted` in `observed_inputs.producers`. No identity,
   digest or reader message is written.
4. **Decision**: `activate(lease, healthy, record=None,
   require_commissioning_evidence=True)`; the library withholds every unit
   outside `lease.units` as `outside_lease_scope`.
5. **Tripwire**: any grant without lease and health, outside `lease.units`,
   or outside `activation_markers.GRANTABLE_UNITS` (the five SUPPORTING loop
   units and, since P5, edge-core: the one set the policy check, the tripwire
   and the marker writer share), and edge-core granted without launchable
   evidence bound to the signed package (§8.1), removes every marker, masks
   every governed unit and raises.
6. **High water** is raised after the decision is recorded, only when the
   approval verified: each counter to the maximum of floor and approval,
   `time_floor` to `max(floor, now)` (so at most `now + skew`). The raise is
   recorded as `activation.high_water_raised` with the floors nested under
   `high_water`, like `az-activation`'s own records; it is one of
   `FLOOR_EVENTS`, so a node with it never re-initializes a missing
   high-water file, and recovery counts its floors. The floors follow the
   accepted approval, not the number of grants: a verified approval raises
   them even on a pass whose units were all withheld. A refused raise
   remasks everything and raises.
7. **Markers** for exactly the granted units, unless the pass rolled back.
   A marker that cannot be written remasks everything and raises.
8. `main` prints `granted=N` and, because the controller is `Type=notify`,
   sends `READY=1` after the pass, then waits (bounded, 5 s) on the
   `BARRIER=1` protocol of `sd_notify_barrier(3)` so that systemd has
   processed READY before the process exits. Without READY the controller's
   start fails and every unit with `Requires=`/`After=` on it fails as a
   dependency. Since #251 L-2 a refused READY, or a barrier that fails or
   times out, withdraws this pass's grants before exiting 1: every grant
   marker is removed and every governed unit masked (the emergency
   narrowing of the tripwire), because it is then unknown whether systemd
   counted the start as successful. The failure is recorded as
   `activation.readiness_unconfirmed` when the ledger can be written; an
   unwritable ledger records nothing and the withdrawal still runs. The
   withdrawal is **best effort, not a guarantee**: if systemd had already
   processed READY, the dependents' `ConditionPathExists=` can be evaluated
   concurrently with it. A start job evaluated after its marker is gone is
   skipped; a unit that started inside that window is not stopped (the stop
   authority covers the Knowledge Context broker alone), and its remask fails with `masked unit has no confirmed
   inactive state`, which also exits 1. `completed safely` is printed only
   after READY and the barrier succeeded. From the first marker to the final
   `activation.inputs_incomplete` record, any failure -- a marker that cannot
   be written, the record failing to assemble, or failing to append (for
   example `AuditUnavailable`) -- removes the markers and remasks before
   failing, so a failed pass never leaves a marker behind. A pass that fails
   never sends READY; a pass that completed sends it, and if READY or the
   barrier then fails, the pass is withdrawn as above and exits 1. The
   selected bootstrap path keeps its own READY protocol unchanged.

**What READY releases.** Every governed unit `Requires=` the controller:
those that carry the marker condition (`hardening.GRANT_MARKER_UNITS`, the
loop's audit writer among them since ADR-0008) and auditd and commissiond. READY would
release a start job queued at boot for any of them still enabled (a manual
unmask, an older build), and §5 showed that masking at the pass cannot stop
such a job. So every governed unit except the bootstrap pair carries the
marker condition: the six loop units, and the watchdog, the fetch service and
the two model hosts, for which no pass writes a marker (`write_grant_markers`
refuses any unit outside the six grantable ones), so they stay unstartable
on the ordinary path.

**Residual window (auditd, commissiond).** They carry no condition because
the supporting-only bootstrap starts them and writes no marker; its
behaviour is unchanged. On the ordinary path, if either was left unmasked
when the boot began, its start job is already queued, the preflight mask
does not cancel it, and READY releases it: the unit then runs until the
controller exits and `BindsTo=` stops it, which is at most the bounded
barrier wait (about 5 s) after READY. Observed on the VM in P6
(2026-10-23, auditd left enabled, not hardware evidence): auditd began to
start right after READY, never reached `active`, and `BindsTo=` stopped it
about 25 ms after READY; the pass masked it again.

**Edge-core was refused in P4.** A policy naming `azazel-edge-core.service`
failed `activation_policy` as a whole. P5 lifts that refusal (§8.1); the
edge-core unit already carried its marker condition.

**Marker path.** The markers live under `/run/azazel-activation/granted/`, not
`/run/azazel/activation/`: systemd chowns a runtime directory to the starting
unit's account and removes it when that unit stops, so the markers stay out of
every runtime-directory tree. `/run/azazel` itself is no unit's
`RuntimeDirectory=` any more (P6 VM rehearsal: when the controller and several
loop units shared it, the controller's exit right after READY removed it as
the granted loop units set up their execution directories, and they failed
with `233/RUNTIME_DIRECTORY`); only nested leaves such as `azazel/mio` remain,
for which systemd creates `/run/azazel` root-owned `0755` and removes only the
leaf (`test_no_unit_shares_the_bare_runtime_directory_with_the_controller`).
`/run/azazel-activation` is a root `0755` directory created at boot by the
packaged tmpfiles rule; the controller has it as an optional
`ReadWritePaths=-`, so a node without it still narrows and simply cannot
grant. `ConditionPathExists=` is on every governed unit except auditd and
commissiond, which the bootstrap path starts
(`tests/unit/test_runtime_hardening.py`).

**One derivation for the pass and `az-activation`.** The pass measures unit
files with `measure_scoped_unit_files` (`activation_unit_files.py`, P3b): the
vendor file in `/usr/lib/systemd/system`, bracketed by
`require_no_unit_overrides` over all twelve directories of the reviewed
Debian 13 unit search path (same-name files other than a `/dev/null` mask,
and any non-empty `<unit>.d`, dash-prefix or `service.d` drop-in; an empty
drop-in directory changes nothing and is accepted by both). The
`commissioning_digest` is `observe_baseline.evidence_commissioning_digest` and
the node digest is `bootstrap_deployment.declared_node_binding`, called by
both. `tests/unit/test_runtime_activation_cli.py` runs `generation-publish` →
`request` → `operator_sign` → `install` → one pass on one temporary root and
checks that exactly the requested units are granted and marked.

Tests (`tests/unit/test_runtime_activation_pass.py`, fake manager, tmp root,
in-memory ephemeral key): only scoped units are granted and only they get
markers; each absent or failed producer refuses and is named alone; epoch
bump, epoch and generation floors, clock rollback beyond the skew, expiry,
a unit file changed after publishing, an altered tree, other evidence,
sequence below the floor and a revoked or unauthorized operator all refuse;
the tripwire fires on an out-of-scope grant; stale markers are removed before
any decision; the high water is raised after the decision and never lowered.
None of these tests is VM or hardware evidence. The VM rehearsal of P6
(2026-10-23, mechanics only, not hardware evidence) showed reboot → granted →
reboot → started, and the negative runs it could exercise left the units
masked and not started.

### 8.1 P5: edge-core in the pass

`activation_markers.GRANTABLE_UNITS` now holds the five SUPPORTING loop units,
`azazel-edge-core.service` and (A1) `azazel-knowledge-contextd.service`; it is still the one set behind the pass's
policy check (`activation_pass.UNIT_SCOPE` is the same object), the tripwire
and the marker writer, and it equals the policy's `ACTIVATION_UNIT_ALLOWLIST`.
(Since #196 P1 it also holds the Deception Lite exposure units, tier
`DECEPTION_EXPOSURE` (three since option (a): the namespace unit, the network
helper and the decoy), so that §8.2's file and loaded-unit checks cover them;
the allowlist does not name them, so it is now the grantable set minus those
three, and the library withholds their tier on every pass. The tier is
granted, scoped and marked together or not at all:
[prerequisites §10](deception-redirect-prerequisites.md#10-p1-as-implemented).)
No new authority, approval field, flag or environment variable is added: the
policy names edge-core, the generation pins its package, the operator's
approval names it, and the library decides it like any other
`EDGE_BASELINE` unit (`edge_not_ready` unless `launchable`).

**The signed package.** When the policy names edge-core the generation
step derives the installed package digest
(`edge_package.installed_package_digest`: present, observe-only, unsigned,
pinned version, artifact equal to its manifest) and re-measures the
extracted binary and redirect policy
(`edge_package.measure_extracted_components`, the same protected no-follow
reads as at publication), and compares them with the tree's
`edge_pin.package_digest` and `edge_pin.components`. The archive digest alone
would not do: the unit executes the extracted binary and reads the extracted
policy, which root could rewrite after extraction while the archive stays
intact.

- all equal: the tree is verified with them (`edge_package_binding:
  bound`);
- readable and different (a self-consistent package other than the signed
  one, or an extracted binary or policy rewritten after publication): the
  generation is refused (`operational_generation_publisher`) and nothing is
  granted, as for a changed unit file. The operator's signature over
  `generation_digest` binds one package and its extracted files; another one
  needs a new `generation-publish`, `request` and signature;
- unreadable (the package checks fail, the package is absent, or an extracted
  component is missing, a link or not protected): the tree is verified
  against its own pin so the SUPPORTING units can still be granted, and
  edge-core is withheld (`package_refused`). A revoked version or digest, a
  version below the Edge rollback floor, a replayed manifest at the floor's
  version, or a revocation state that cannot be established makes the
  package checks fail here too
  ([Edge package verification](edge-package-verification.md) §3b).

The same step reads `edge_package.installed_issuer_verification` and records
its fixed labels as `observed_inputs.edge_issuer` (`digest_verified` and
`issuer_authenticated` separately). Issuer authentication is not required to
grant edge-core. After edge-core is granted, its marker written and the pass
record appended, the daemon passes it to
`edge_issuer_floor.raise_floor_after_grant`, which raises the rollback floor
only for an issuer-authenticated, digest-verified, unrevoked package bound to
the launch evidence, and records the outcome as an
`activation.edge_issuer_floor` event; a failure to raise or to record grants
and withdraws nothing, and a grant withdrawn because its record failed never
raises the floor.

The edge-core unit file, with its observe-only `Environment=` lines, is in
the measured set like every scoped unit; a changed line refuses the
generation.

**This boot's health.** After the all-or-nothing producers, and only when a
lease was formed, the pass reads `installed_baseline_state` (the four
package checks, and health and running from the probe result only when it is
v2, names this boot, is within its TTL and describes the installed package).
Unless the package was bound and the probe's package digest is exactly the
pinned one (a state naming no probed package is never accepted),
`edge_package.bound_to_signed_package` reports `digest_matches` false (it only
narrows; `edge_package` stays the only module that produces an Edge state, and
a reader failure becomes `edge_package.nothing_established()`). The result is
passed to `activate(edge=...)`; the daemon's own host read is not used on this
path.
`running` is not required (the preflight runs before edge-core can start), and
`edge-baseline-ready` is not claimed.

**Edge evidence never refuses the pass.** It is not one of the all-or-nothing
producers: a stale result (another boot, a v1 result, expired), failed or
unchecked health, an unreadable boot id, a failing package check or a reader
error withholds edge-core with `edge_not_ready: <checks>`, while the five
SUPPORTING units are decided as before. `activation.inputs_incomplete` records
`observed_inputs.edge_package_binding` (`not_in_scope`, `bound`,
`package_refused`, `not_attempted`), `observed_inputs.edge_evidence`
(`not_in_scope`, `launchable`, `not_launchable`, `not_attempted`) and, when
not launchable, `edge_missing_for_launch` (check names only, no digest).

**Ordering.** `azazel-edge-probe-preflight.service` is `Before=` the
controller and the controller names it nowhere (no `Requires=`, `Wants=` or
`After=`; `tests/unit/test_runtime_hardening.py`). The controller only reads
its result file. If the preflight failed, timed out (`TimeoutStartSec=60s`)
or wrote nothing, the controller still runs; the pass finds no result from
this boot, withholds edge-core with `edge_not_ready:
digest_matches,health_endpoint_healthy` (no result names no probed package)
and grants the SUPPORTING units it otherwise would. The next boot's
preflight is the retry; nothing is started to recover.

**Health is trust in `azprobe`.** The health check is what
`az-edge-probed` wrote, as `azprobe`, into its result leaf. That account can
write a fresh, same-boot, healthy result for the bound package without having
run anything; it cannot make another package launchable, because the result
must name the package digest the pass derived and the operator signed, and
the package and its extracted files are measured by the pass itself. A
compromised `azprobe` can therefore admit the signed package early, never a
different one.

**Residual windows.** Two checks precede the launch they admit:

- *probe → pass*: the preflight's result is read at the pass, up to its TTL
  after it was observed (and only in the same boot); Edge health can change
  in between;
- *pass → launch*: the package, the extracted binary and redirect policy and
  the unit file are measured at the pass; edge-core starts later in the boot.
  A file replaced between the two is not caught by this pass (the next boot's
  pass refuses it, the whole lease when it is readable and different).

Both are local-trust limits like the high water's (§3.5); closing the second
would need the launch itself to verify the binary, which is Edge's side.
Edge remains observe-only and the sole decider: Nexus decides only whether
the package may launch.

Tests (`tests/unit/test_runtime_activation_pass.py`, real `edge_package`
readers over a package, probe result and boot id in the tmp root): edge-core
granted and marked with package and fresh health (running failed); withheld,
with the SUPPORTING units still granted and marked, on a probe from another
boot, a v1 probe, an expired probe, failed or unchecked health, no result (a
failed or timed-out preflight), an unreadable boot id, a reader error, a
damaged, enforcing or absent package, no digest for the pass and a probe of
another package, and an extracted binary that is absent, a link or group
writable; the lease refused for a self-consistent package other than the
signed one, for an extracted binary or redirect policy rewritten after
publication, for a changed edge-core `Environment=` line and for a
generation without the package pin; edge-core outside a narrower approval;
the edge tripwire. `tests/unit/test_runtime_activation_cli.py` runs
`generation-publish` → `request` (including edge-core) → `operator_sign` →
`install` → pass on one temporary root, then a boot with no preflight result
and a boot with another package.

### 8.2 Unit content and the loaded units (#251 H-1, M-3)

The grant marker (§5) withholds a unit only if the unit carries the marker
condition and waits for the controller. Hashing the file did not establish
that: a unit file without the condition (an older build, a version skew)
measured, was signed and, with a start job queued before the pass, started
together with the grant. Two checks now establish it. Both only narrow: no
authority, approval field, flag or environment variable is added, and no
refusal becomes a grant.

**Scope.** The file check runs in two places:

- on the policy's units, inside `measure_scoped_unit_files` (so
  `generation-publish`, `request`, `install` and the pass's generation
  producer make it); a missing vendor file refuses, as before;
- on **every** unit in `activation_markers.GRANTABLE_UNITS`, in the pass's
  `systemd_loaded_units` producer (`require_grantable_unit_files`), whether
  or not the policy names it. A grantable unit outside the policy is never
  granted, but if it was left enabled with a start job queued, READY
  releases that job unless the unit waits for its marker. Here a vendor file
  that does not exist is accepted (systemd has no definition to start); a
  present one must pass the content check, and no grantable unit may have an
  override or drop-in.

The loaded-unit check below also covers every grantable unit.

**The file text** (`activation_unit_files.require_governed_unit_content`).
The vendor file must:

- consist of printable ASCII, tab and newline only. A BOM, NUL, CR, any
  other control character and any non-ASCII character (Unicode whitespace
  such as U+00A0 or U+3000 included) refuse. Only space and tab are
  stripped around a line. Otherwise Python and systemd could disagree on a
  line: `str.strip()` would read `\xa0[Unit]` as a section header that
  systemd ignores, and the required lines would land in the previous
  section. All packaged units are plain ASCII;
- contain, as exact lines in `[Unit]`,
  `ConditionPathExists=/run/azazel-activation/granted/<unit>`,
  `Requires=azazel-activated.service` and `After=azazel-activated.service`
  (spacing inside the line, a `!` or `|` prefix, or the line in another
  section does not count);
- have exactly the `Condition*=`, `Assert*=` and `ExecCondition=`
  assignments, in every section, of `hardening.render_unit` for that unit --
  none added, none removed. For the six grantable units that is the marker
  condition alone;
- have no empty assignment in `[Unit]` (an empty `ConditionPathExists=`,
  `Requires=` or `After=` resets the list);
- have no continued line (trailing backslash), no assignment before a
  section and no line that is not blank, a comment, a section header or an
  assignment. These are refused rather than parsed.

The rest of the file (comments, `ExecStart=`, edge-core's observe-only
`Environment=` lines) is not compared with the declaration here: for the
policy's units the hash in the generation and the operator's signature bind
it, as before. All six packaged units pass
(`tests/unit/test_runtime_activation_unit_files.py`).

**The loaded units** (`activation_loaded_units.verify_loaded_units`, run by
the `systemd_loaded_units` producer after the generation producer). The file
check says what systemd *would* load. A unit loaded earlier in the boot runs
its loaded definition until a daemon-reload, and the preflight mask does not
reload. So the pass reads the manager over the controller's own D-Bus
session (the same `SystemdBusSession` that masks). The reads are read-only:
`GetUnit`, then one `Properties.GetAll` of the `org.freedesktop.systemd1.Unit`
interface. The session accepts `GetAll` only on the six grantable units'
objects and only for that interface. The pass checks:

- the manager's `Version` and `UnitPath`, through
  `observe_bootstrap_systemd_profile` -- the bootstrap path's gate, now also
  on the ordinary path (M-3). Anything but the reviewed Debian 13 systemd
  257 profile refuses, so the twelve directories the override check walks
  are the ones this manager searches. The profile is read before the units
  and again after them. The second read detects a manager re-executed
  (daemon-reexec, an upgrade) while the units were read: it must succeed and
  be equal to the first;
- for each grantable unit:
  - `NoSuchUnit` (no unit object, so no queued job; a later load reads the
    checked file) and `LoadState=masked` are accepted;
  - `loaded` is accepted only with all of these:
    - `Id` is the unit;
    - `FragmentPath` is exactly `/usr/lib/systemd/system/<unit>`;
    - `DropInPaths` is empty;
    - `Conditions` and `Asserts` (type, trigger, negate, parameter; the
      state field ignored) equal the rendered unit's -- that is, the marker
      condition alone;
    - `azazel-activated.service` is among `Requires` and among `After`.
      These lists are not compared whole, because systemd adds implicit
      dependencies.
  - Any other state, a missing or mistyped property, or an unreadable reply
    refuses.

A failure marks `systemd_loaded_units` failed: the pass is incomplete, the
decision gets no lease, everything stays masked, no marker is written, and
the high water is not raised. The ledger names the producer only. Without
the controller's session (any manager other than the D-Bus one), the check
refuses.

**Compatibility.** The generation format and its hash are unchanged; a
published generation whose unit files pass these checks verifies as before.
The following nodes now have every unit withheld until the files are
reinstalled (and, if the policy's bytes change, a new generation is
published):

- a node whose installed grantable unit files lack the lines, contain
  anything but printable ASCII, or have an override;
- a node whose manager is not the reviewed profile.

**Residual risk.**

- The loaded definition's `ExecStart=` (and the rest of its `Service`
  section, `ExecCondition=` included) is not compared. A unit loaded before
  its file was replaced can therefore run an older command line than the one
  the generation hashed. It still starts only with this boot's marker and
  after the controller, which the checks above establish, and `ExecCondition=`
  can only skip a start.
- `NeedDaemonReload` is not required false: the preflight mask itself changes
  the unit file state, and the loaded definition is what is compared.
- The watchdog, the fetch service and the model hosts are outside
  `GRANTABLE_UNITS`. No pass ever writes their marker, and their marker
  condition is the hardening test's to keep
  (`tests/unit/test_runtime_hardening.py`).
- The `Conditions`, `Requires`, `After` and `FragmentPath` that systemd
  reports for these units, before and after the preflight mask, still have
  to be observed on the VM.

Tests:

- `tests/unit/test_runtime_activation_unit_files.py`:
  - each required line removed, spaced, negated, made triggering or moved;
  - each added or reset guard;
  - continuation, CR, NUL and syntax;
  - Unicode whitespace, a BOM and other controls at the start or end of a
    header or line;
  - every grantable file, absent, broken, overridden or unprotected.
- `tests/unit/test_runtime_activation_cli.py`: `generation-publish` refuses a
  unit without its marker condition.
- `tests/unit/test_runtime_activation_pass.py`:
  - each of these refuses everything:
    - a loaded unit without the condition;
    - a loaded unit with an extra condition or assert;
    - a loaded unit without the controller in `Requires` or `After`;
    - a fragment in `/etc`, or a drop-in;
    - another load state or id;
    - a grantable unit outside the policy loaded that way;
    - an unreviewed manager profile, a failing or changed second profile
      read, or an unreadable unit;
  - not loaded and masked are accepted;
  - a policy narrower than the grantable set still has every grantable unit
    checked, and grants only its own.
- `tests/unit/test_runtime_systemd_bus.py`: the single `GetAll`, refused
  outside the grantable units or the `Unit` interface.

### 8.3 Stopping a granted Knowledge Context broker

This section describes the stop contract for `azazel-knowledge-contextd.service`.
It is the only unit the controller can stop.

**Reload (F2, F1).** `MaskUnitFiles`, `UnmaskUnitFiles` and `EnableUnitFiles`
change files; a manager that loaded a unit earlier keeps its loaded
definition until it is reloaded, so a granted unit could still start as
`masked`. Each batch of such changes now ends with one argument-less
`Manager.Reload`: after the preflight masks, after the controller's grant
batch, after a rollback or wider narrowing, and after an emergency narrowing
and a recheck's mask. A failed reload is fail-closed (grant unconfirmed,
everything masked, non-zero exit). After the grant batch's reload, and before
the floors are raised, any marker is written or READY is sent, the loaded
definitions of the guarded units are verified again (§8.2: loaded, vendor
`FragmentPath`, no drop-in); a unit that does not verify is withdrawn.

**Authority.** `ContextdStopAuthority` is a separate type, not a method of the
unit manager adapter. It sends `StopUnit` with the constant body
`azazel-knowledge-contextd.service`, `replace`, and reads that unit's `Job`
property. Both layers refuse any other unit before a D-Bus exchange. `StartUnit`
is still never sent; there is no shell and no unit name or command from a
caller.

**Withdrawal.** `withdraw_contextd(reason)` runs with the pass lock held:
1. unlink the broker's marker (no-follow) and confirm it is gone (`t_marker`);
   other markers are not touched;
2. mask the broker and reload the manager (`t_reload`);
3. if its `ActiveState` is not `inactive` or it has a job, send `StopUnit`
   (`replace`) (`t_stop`);
4. wait until the broker is quiet, that is `ActiveState` is `inactive` and the
   job is `(0, "/")` (`t_inactive`), at most 20 s and within the remaining
   budget. `failed` with no job also counts as quiet, for this confirmation
   only: after a SIGKILL final kill systemd keeps the unit loaded as `failed`
   and `StopUnit` does not return it to `inactive`, although the process is
   gone. The record carries `quiet_state`. Elsewhere exact `inactive` is the rule,
with one exception. A broker left `failed` is a trigger for the recheck and is
withdrawn (no `StopUnit` is needed for it), and the main pass's preflight
withdraws it too, unless it is already withdrawn: `failed`, no job, the
unit-file state exactly `masked` and no marker. That shape is left alone: the
recheck does not trigger on it (no new record every period) and the preflight's
mask check accepts it instead of reporting a containment failure. A `failed`
broker that is unmasked, has a job or has a marker is not that shape;
5. record `activation.grant_withdrawn` with the reason, the timings in
   milliseconds since the withdrawal started (`t_marker_ms` and the others are
   offsets from the start of the withdrawal, not from detection) and the
   invocation id.

The mask is confirmed by the exact unit-file state: `masked`, not
`masked-runtime`, which does not survive a reboot. A step that cannot be
confirmed first runs a finalizer for this one unit (marker removed, mask,
reload, one stop if it is not quiet), then records
`activation.withdrawal_unconfirmed` with what the finalizer reached
(`final_masked`, `final_quiet`; the record failing changes nothing); the exit
is non-zero. The recheck does not narrow other units in that case. A step is
not started after its budget has ended.

**Timeline.** `t_loss` is when the condition is lost (an expiry instant, a
revocation, a health change); it is not observed. `t_detect` is when a pass or
recheck notices it, and the withdrawal starts right after. `t_marker`,
`t_reload`, `t_stop` and `t_inactive` follow as above; the recorded `t_*_ms`
fields are offsets from the start of the withdrawal, so `t_detect` to the start
of the withdrawal is not in them. The recheck runs 30 s after boot and 30 s after each start
(`OnBootSec=30s`, `OnUnitActiveSec=30s`, `AccuracySec=1s`); that is a
configured value, not a bound: a run that finds the lock held changes nothing,
and a run can be late. The recheck has one budget of 18 s for its bus work,
counted from before it connects to the bus. Retirement and input collection
end by 6 s; the withdrawal's steps end at 11 s; the finalizer of an
unconfirmed withdrawal runs until 16 s. Every bus call is refused once its
deadline has passed and is otherwise limited to the time that is left (at most
its usual 10 s), the finalizer's included, and the poll sleeps never run past a
deadline. Bus work and finalizer therefore end by 16 s of the 18 s budget, and
the 2 s that remain are for the records.

**What the lock hold is, honestly.** Two parts. The recheck's bus work and its
containment finalizer are time-bounded and enforced: at most 20 s, below the
25 s a main pass waits for the lock. Everything else done under the lock is
local filesystem I/O and is not time-bounded: the ledger appends, the
retirement's state files and high-water commit (reads, writes, renames and
fsyncs), the marker reads and the input reads; collection and retirement end by
their cooperative deadline only as far as they check it. The recheck writes
its records inside `pass.lock`, in the order the transitions happen (the
withdrawal or its unconfirmed outcome, and the approval retirement):
`AuditLedger.append` reads the head and then writes with no lock of its own
(`src/azazel_nexus/audit.py`, `append`), so only `pass.lock` stops a recheck and
a main pass from extending the same head and writing duplicate sequence links.
If filesystem I/O stalls, nothing interrupts it; the main pass's 25 s lock wait
expires and the main pass narrows: every marker removed, every governed unit
masked, nothing granted (fail-closed; see
`test_a_pass_that_cannot_take_the_lock_narrows_and_fails` and
`test_the_lock_failure_narrows_after_second_37`). A record that cannot be
appended is not swallowed: the recheck's exit status is non-zero, although the
state change it describes has been made. A recheck killed by
`TimeoutStartSec=40s` in the middle of an append can leave a torn last line.
Nothing repairs that: the ledger repairs only a write that failed inside a
running process (`_withdraw`, `audit.py:346-363`), while `head()`
(`audit.py:138-190`) cannot parse a torn last line, so every later append
refuses (`AuditChainBroken`, shown by
`test_a_torn_tail_makes_the_next_append_refuse_and_nothing_repairs_it`) until an
operator repairs the ledger. That is fail-closed for the controller (a pass
that cannot record narrows) and costs availability.

**One rule for the ledger.** Every ledger append by the main pass and by the
recheck is made while `pass.lock` is held. The main pass's budget-expired
record (`activation.pass_budget_expired`) is appended inside the lock, and so is
the narrowing that follows it. A main pass that never obtained the lock (its
wait expired) appends nothing: it prints
`az-activated: the activation pass lock was not held; nothing was written to the
ledger; narrowing and failing` to the journal, narrows, and exits non-zero. That
failure is therefore visible in the journal and in the unit's exit status, not
in the ledger.

A budget that ends mid-withdrawal gives `activation.withdrawal_unconfirmed`; the
marker is already removed (a local step) and the finalizer masks the broker
where it still can. Collection that does not finish is a withhold. The stop wait is at most 20 s and
never more than the time that is left. `t_loss` to `t_detect` has no bound.

**Adoption contract (weakened).** The broker reads its marker when it accepts a
request and again before it adopts the peer's answer
(`knowledge-context-consumer.md`). No answer is adopted after `t_marker`. An
answer adopted earlier may still be on its way to the caller until the broker
is inactive (`t_inactive`), because delivery is not undone. A marker removed
and written again inside one kernel timestamp tick could keep the identity
`(st_dev, st_ino, st_ctime_ns)`; a real re-grant is a later pass, far longer
than a tick (推測です, not measured on a node).

**Recovery after a withdrawal.** A withdrawn broker is masked, with its marker
removed. A plain `systemctl start azazel-knowledge-contextd.service` of that MASKED
broker is refused (`Unit ... is masked`) and pulls in no pass, so it changes
nothing. (Starting an UNMASKED, granted broker is different: see step 3.)
To bring the broker back, in this order:


1. `systemctl start azazel-activated.service`, which runs a pass. It grants
   the broker again only if the approval, the policy, health and evidence
   still allow it (an approval retired after an explicit revocation does not,
   and a new approval with a higher sequence is needed).
2. Confirm that the pass granted it: the newest `activation.inputs_incomplete`
   record in `/var/lib/azazel/state/activation.jsonl` lists the broker in
   `grant_markers`, and `/run/azazel-activation/granted/azazel-knowledge-contextd.service`
   exists. If the pass failed or did not grant it, do not go on.
3. `systemctl start azazel-knowledge-contextd.service`.

What step 3 does. The broker has `Requires=azazel-activated.service`, and
the controller has exited after step 1 (it has no `RemainAfterExit`), so
starting the broker queues a second controller pass first. The second pass is
designed to keep the broker's queued start job and to re-grant it:

- its preflight removes the markers and masks and reloads every governed unit
  except a broker that is inactive with a start job queued, which it leaves as
  it is (masking and reloading would make systemd fail that job; the job cannot
  run before READY, because the broker is ordered after the controller);
- it decides: if the broker is granted again (unmask, enable, reload, marker
  written) the queued job runs once READY is sent and finds its marker; if it is
  withheld (the approval, the policy, health or evidence no longer allow it, or a
  retirement is pending, which makes the pass withhold every unit), or the pass
  narrows for any reason or runs out of budget, the broker is masked, the manager
  is reloaded and the queued job is replaced with `StopUnit` before the pass ends.
  Every narrowing of the pass runs the full broker withdrawal afterwards (marker,
  mask, reload, `StopUnit` if it is not quiet or a job is present, confirm quiet),
  not only a job clear: when READY or its barrier failed, READY may already have
  released the held job and started the broker, and `Requires=` does not bind its
  lifetime afterwards;
- if the pass dies, `Requires=` fails the job, which is the fail-closed side.

Other conditions can also make the second pass withhold or narrow, for example a
governed unit that is running (a containment failure). This sequence is the
design; it counts as confirmed only once the same-boot procedure has been run on
a clone (unit 45 S1) and its result recorded there. If the queued job is
instead cancelled or failed on a host, the supported recovery is a reboot after
the grant of step 1: the broker is enabled, and the boot pass writes its marker
before the broker's start job is evaluated.

**Main pass.** The pass takes `/run/azazel-activation/pass.lock` (root `0600`,
no-follow, `flock`), waiting at most 25 s, and holds it until READY's barrier;
without the lock it narrows and exits non-zero. One budget of 45 s covers the
whole pass, counted from before the bus connects (connecting counts, each of
its steps limited to the time that is left). The phases of the pass end 8 s
before it (at 37 s); the 8 s reserve is kept for the narrowing a failed pass
needs and its record. `azazel-activated.service` has `TimeoutStartSec=60s`
(was 30 s): 37 s of phases + 8 s of reserve = 45 s, plus 15 s of margin for
READY, its barrier and the exit.

The budget is kept by the code, not by interrupting it. The pass checks it
between its phases (before input collection, after it, after the decision,
before READY), and every D-Bus call is refused once the phase deadline has
passed and is otherwise limited to the time that is left. A call that times out
has finished its session: pending work is cancelled with a bounded moment to
unwind, the bus is disconnected, and no further call is sent on it, ever.
Narrowing then opens a new session, connecting inside the same deadline (the
cleanup after a failed connection is charged to it too). Every way out that
narrows does so under the end of the whole 45 s: the lock failing, the budget
ending, READY or its barrier failing, an emergency narrowing in the pass, and
a finished session. Nothing is raised asynchronously, so a ledger append or a
high-water commit always completes. When the budget ends the pass writes
`activation.pass_budget_expired`, removes every marker, masks every governed
unit, reloads, spending the reserve, and exits non-zero. What this cannot bound
is work that is neither a bus call nor between two checks, for example a file
read that blocks in the kernel, or the READY barrier's own wait. An earlier
version armed a `SIGALRM`; it was removed because it could stop a ledger write
or a high-water rename half way. At preflight a broker that is running is withdrawn before the masks
are confirmed; an inactive broker with a queued start job is neither stopped
nor masked there (see the recovery text above): it is decided at the verdict. If the pass does not
grant the broker and a start job is queued for it, the job is replaced with
`StopUnit` (`replace`) and `Job` is confirmed `(0, "/")`. Any other governed
unit that is running is still a containment failure, and re-granting the
broker still needs every other governed unit to be inactive.

**Recheck.** `azazel-activation-recheck.service` (root, the controller's
sandbox without its writes to `/etc/systemd/system` and
`/run/systemd/system.control`, `TimeoutStartSec=40s`, no `[Install]`) is run by
its timer, which the installer and the preset enable. It takes the pass lock
without waiting; if the lock is held it changes nothing, writes no ledger
record and exits 0. It acts only if the broker has a marker, is not masked, or
is not inactive or has a job. It collects the pass inputs (read-only), and the
pure function `contextd_verdict` says whether the pass would grant the broker
(the library's wiring, health, lease, validity, generation and scope
conditions); a failed collection withholds. If the verdict is withhold, the
recheck withdraws the broker. It never grants, never masks another unit and
never calls the controller's pass. A grant that never started (marker present,
unmasked, inactive) is withdrawn with marker removal, mask and reload and no
`StopUnit`.

**Approval retirement.** A grant records the approval it was made under in
`state/activation/accepted-grant.json` (root `0600`) before any marker or
READY. When a freshly loaded operator trust lists that approval's operator in
`revoked` (an explicit entry; a loader failure proves nothing), the recheck
retires the approval: it writes `retirement-pending.json` (with the clock skew
the floor raise needs), raises the approval sequence floor to
`approval_seq + 1` (other fields kept), reads the floor back, and removes the
accepted record and the pending file. A pending file is resumed by the next
recheck before any trust or policy is loaded, so a trust store that cannot be
read does not stop it. While one is pending, or a retirement failed, the
recheck's verdict is withhold and the main pass grants nothing. The main pass
also reads an existing accepted-grant record before admission and withholds if
it is not exactly what a grant writes (canonical SHA-256, a sorted unique
subset of the grantable units, a sequence that can be advanced); it never
overwrites such a record, so the operator has to look at it. The same
approval is then refused for every unit it names. Expiry, health and evidence
loss retire nothing: when the condition returns, the same approval can grant
again.

## 9. Review #251: low findings L-1–L-4, L-6

The cross-cutting review of the activation path
([#251](https://github.com/01rabbit/Azazel-Nexus/issues/251)) listed low
findings; these changes only tighten. No authority, approval field, flag,
environment variable or unit operation is added, and no refusal becomes a
success.

- **L-2 (notification and exit, §8 item 8).** A refused READY, or a barrier
  that fails or times out, removes every grant marker and masks every
  governed unit, then exits 1; it is recorded as
  `activation.readiness_unconfirmed` when the ledger can be written (not a
  floor event, so not in `FLOOR_EVENTS`). Any failure between the first
  marker and the final pass record (writing a marker, assembling the record,
  appending it) does the same before failing. `completed safely` is printed
  after READY and the barrier. *Why the barrier is treated like READY:* §8
  used to keep exit 0 after a failed barrier because the pass was recorded;
  but a failed or timed-out barrier means systemd may not have processed
  READY, so whether the start succeeded and whether the dependents run is
  unknown. The safe side is the failed-pass state. It is best effort, not a
  guarantee: when READY had been processed, a dependent's marker condition
  may be evaluated concurrently with the withdrawal, and a unit that started
  inside that window keeps running (no `StopUnit` except for the Knowledge
  Context broker, §8.3); its remask then fails
  with `masked unit has no confirmed inactive state` and the exit is 1. The
  cost is availability: the units granted by that pass are masked again, so
  they start only after a later boot's pass grants them anew.
- **L-3 (§3.1).** `install` requires `approval_seq` above an existing floor,
  except for the byte-identical installed pair; the pass is unchanged.
- **L-4 (§3.1).** The signer refuses units outside
  `ACTIVATION_UNIT_ALLOWLIST`; `az-activation request` writes the payload
  only to `--out` and otherwise prints the summary alone and exits 1.
- **L-6.** `DbusUnitManager.state` reads only `enabled` as ENABLED;
  `enabled-runtime`, `linked`, `linked-runtime` and `alias` read as DISABLED,
  so the activation path's postcondition after `EnableUnitFiles` refuses
  them and rolls back. The only other production caller, the bootstrap
  manager, compares the result with `MASKED` only and is unaffected, so the
  change is not split by path.
- **L-1 (kept).** The controller keeps `ReadWritePaths=/etc/systemd/system`
  and `/run/systemd/system.control`. The ordinary path writes neither
  directly (it masks, unmasks and enables through PID1 over D-Bus, and its
  own files are the markers under `/run/azazel-activation`), but the same
  unit runs the selected bootstrap path: it creates and removes the helper
  overlay pair in `/run/systemd/system.control`
  (`bootstrap_overlay_files.py`, `bootstrap_withdraw_files.py`), so that
  path is required. For `/etc/systemd/system` no direct write was found on
  either path (the bootstrap code only inspects the masks there), but the
  bootstrap path's sandbox was qualified on the VM with it and the unit file
  belongs to the installed systemd unit closure the bootstrap context pins
  (`unit_closure_digest`), so it is not removed without a VM run of both
  paths with it read-only. `packaging/systemd` is therefore not re-rendered.

## 10. Review #251: ordering and residual risks

The rest of [#251](https://github.com/01rabbit/Azazel-Nexus/issues/251)
after §8.2 and §9. Two unit files gain `After=` lines and nothing else;
everything below that is not an ordering change is a residual risk, stated
rather than solved. No authority, approval field, flag, environment variable
or unit operation is added, and no refusal becomes a success. The one later
addition, M-1's opt-in policy field (§10.1), can only add a refusal.

### 10.1 Ordering (M-7, M-1, L-9)

- **M-7: the controller is `After=data.mount`**
  (`hardening.MISSION_STORAGE_MOUNTS`). The pass's node-health producer
  checks the `resources` floor (`activation_health` →
  `bootstrap_resources.require_bootstrap_resources` →
  `resource_assessment.assess_resources`), and its `mission_available_mib`
  opens `/data`, refuses a `/data` on the root filesystem, and compares the
  free space with the policy's `min_mission_available_mib`. Without the
  ordering a `nofail` `/data` mount could race the pass; measured before the
  mount, the floor refuses and every unit is withheld for that boot
  (fail-closed, an availability loss). The rule is #242's for the
  commissioning storage (`COMMISSIONING_STORAGE_MOUNTS`): `After=` only,
  never `Requires=`, `Wants=`, `BindsTo=` or `RequiresMountsFor=`, and no
  controller path setting below `/data` (which would add an implicit
  `RequiresMountsFor=`). An absent, locked or failed `/data` therefore never
  stops the controller: it still remasks, and its pass refuses the floor.
  While a `/data` mount job is pending, the controller waits for it, up to
  that job's timeout. `After=` on a mount that does not exist has no effect.
  How an encrypted mission volume is opened at boot is outside #242 and not
  decided. Tests: `tests/unit/test_mission_storage_ordering.py`
  (declarations only; the boot order itself is for the VM).
- **M-1: the controller is `After=time-sync.target`**
  (`hardening.TIME_SYNC_TARGET`). `time-sync.target` is a passive target.
  On the rehearsal VM (Debian 13, systemd 257.13) it has only
  `After=time-set.target`, its `Before=` lists the timers and
  `azazel-activated.service`, and `systemd-time-wait-sync.service` is
  disabled. An enabled timesyncd pulls the target in, so the controller is
  ordered after it, but reaching the target does not wait for
  synchronization to complete. Only a wait-sync service (such as
  `systemd-time-wait-sync.service`, which this package neither ships nor
  enables) holds it until the clock is synchronized. Without one **the
  controller does not wait for synchronization**, and the residual risk in
  §10.2 stays. No `Wants=` or `Requires=` is added, so the line never pulls
  the target in by itself, and no packaged unit orders `time-sync.target`
  after the controller. An administrator who enables a wait-sync service
  makes the controller (and every unit ordered after it, the selected
  bootstrap path included) wait until the clock is synchronized. Nothing
  bounds that wait: the controller's `TimeoutStartSec=60s` (§8.3) counts from the
  start of its `ExecStart=`, not while its start job waits on an ordering
  dependency, and the controller sets no `JobTimeoutSec=`. On an offline
  node with such a service enabled, the controller may therefore wait
  indefinitely. That is fail-closed: every governed unit waits with it, and
  none starts. It is also why `edge_intaked.py` (`CLOCK_SETTLE_S`) avoids
  ordering the intake after `time-sync.target`: on an offline node the wait
  would hold back the intake that Edge writes to. For the controller, this
  package does not enable a wait-sync service, so the line costs nothing by
  default. Enabling one is a deliberate trade of availability for clock
  assurance, and its length must be observed on the VM before anyone relies
  on it.

  **The policy option (owner decision: selectable, off by default).** The
  activation policy may say `"require_clock_synchronized":true` (§7). The
  `trusted_clock` producer then requires, after the floor check, proof that
  the clock was synchronized in this boot
  (`runtime/src/azazel_nexus_runtime/activation_clock_sync.py`); unproven or
  unreadable fails `trusted_clock`, the approval is not attempted and nothing
  is granted. The ledger's `observed_inputs.clock_synchronization` says
  `synchronized` or `not_proven` (only when the field is `true` and the
  floor check passed; absent otherwise, as before). With the field absent or
  `false` the pass behaves exactly as before: the reader is never called.
  The field is part of the policy, so turning it on or off changes
  `policy_digest`; the installed approval then no longer verifies, and the
  usual request, signature and install follow. The pass itself does not
  wait or retry; it reads the marker once. It adds no flag, approval field,
  environment variable or unit operation, and no unit dependency.

  *A node that sets the field `true` must enable
  `systemd-time-wait-sync.service`.* Otherwise the pass races the first
  synchronization and is likely to refuse. On the rehearsal VM (Debian 13,
  systemd 257.13, 2026-10-21) timesyncd's first synchronization came about
  33 s after boot, while the controller, when no LUKS passphrase holds it
  back, runs about 10 s after boot: the pass then finds no marker, reads
  `not_proven` and grants nothing for that boot. The controller is already
  `After=time-sync.target` (above), so an enabled wait-sync service holds
  it until timesyncd has synchronized, and the marker exists when the pass
  reads it. The two cases:
  - **wait-sync disabled** (this package's default): the controller does not
    wait; a pass before the first synchronization refuses (`not_proven`),
    and a node that never synchronizes (offline, no timesyncd) refuses every
    boot;
  - **wait-sync enabled**: the controller waits for synchronization. On a
    node that cannot synchronize it waits **indefinitely**, for the reasons
    given in the M-1 ordering bullet above (`TimeoutStartSec=` does not
    count an ordering wait, and the controller sets no `JobTimeoutSec=`).
    That is fail-closed, since every governed unit waits with it, but
    availability is lost until the clock synchronizes.

  *The proof is systemd-timesyncd's marker*
  `/run/systemd/timesync/synchronized`, which timesyncd touches on each
  successful synchronization and documents for exactly this purpose
  (systemd-time-wait-sync reads it). A read-only inspection of the VM
  found it as an empty regular file on 2026-10-14
  ([runtime-activation-remaining](runtime-activation-remaining.md)). It is checked read-only: each directory opened
  with `O_NOFOLLOW`, the marker `lstat`ed relative to it, and only a
  regular file in a real directory, neither group- nor world-writable,
  counts (the VM has the marker `systemd-timesync` `0644` in a `0755`
  directory; the owner is not checked). The
  controller reads it with what it has: `/run` stays readable under
  `ProtectSystem=strict`, and no path, capability, system call or bus
  permission is added. The alternatives were rejected for that reason:
  - `adjtimex(2)` without `STA_UNSYNC` is in systemd's `@clock` group,
    which the controller's `SystemCallFilter=@system-service` excludes; the
    call would kill the controller (and Python has no binding);
  - timedated's `NTPSynchronized` is another bus name. The controller's
    session sends only to the admitted owner of `org.freedesktop.systemd1`,
    and asking timedated bus-activates `systemd-timedated.service`: a start,
    not a read, and a new destination in the controller's allowlist.

  Limits, stated rather than solved: only timesyncd writes the marker, so a
  node that keeps time with chrony or another daemon never has it and
  refuses every boot whether or not a wait-sync service is enabled (one
  that releases on the kernel's synchronized state still leaves no marker);
  a node with no reachable time source behaves as in the two cases above;
  the marker
  proves that a synchronization happened in this boot (`/run` is a tmpfs; a
  soft-reboot keeps `/run` and the running clock alike), not that the clock
  is still synchronized or that the source was authenticated; and whoever
  can write `/run/systemd/timesync` (root and timesyncd) can forge it, as
  they can set the clock. That, **with `systemd-time-wait-sync.service`
  enabled**, the marker is present before the pass on a synchronizing VM
  (its mtime earlier than the controller's start), and that the controller
  waits on a node that cannot synchronize, is **要確認** on the VM before a
  node relies on the field. Tests:
  `tests/unit/test_activation_policy.py`,
  `tests/unit/test_runtime_activation_clock_sync.py`,
  `tests/unit/test_runtime_activation_pass.py`.
- **L-9: the watchdog is `After=azazel-activated.service`.** It already
  `Requires=` the controller and carries the marker condition, but was the
  only `Requires=` dependent without the ordering, so its condition could be
  evaluated in parallel with the controller instead of after its marker
  reset and READY. No existing design depends on the watchdog running before
  or beside the controller: the supporting-only bootstrap starts only auditd
  and commissiond (`BOOTSTRAP_UNITS`), the bootstrap's loaded-unit inspection
  reads only those two units, and no pass writes the watchdog's marker
  (`write_grant_markers` refuses any unit outside `GRANTABLE_UNITS`), so it
  still never starts on either path. The ordering does change one thing:
  with `Requires=` and `After=` together, a failed start job of the
  controller now fails the watchdog's job as a dependency, where before the
  two ran in parallel and the watchdog's start did not depend on the
  controller's outcome. Today that changes no start, but only because no
  marker is ever written for the watchdog, so it is skipped either way. If a
  future change makes the watchdog grantable, this is the intended
  behaviour: it then starts only after a controller start that succeeded,
  like the fetch service, the model hosts and the loop units. The watchdog is outside `GRANTABLE_UNITS`, so the §8.2 content and
  loaded-unit checks do not cover it; the hardening and ordering tests do.

`packaging/systemd` is re-rendered (`tools/render_units.py`): the controller
and the watchdog files change. Like any re-render, an older install differs
from them until it is reinstalled. A generation hashes only the policy's
units, and neither file is one of them.

### 10.2 Residual risks

- **M-1: a node without a trustworthy clock can pass an expired approval.**
  The approval is valid when `granted_at ≤ now < expires_at` with `now` the
  OS clock at the pass, and the only lower bound on that clock is the high
  water's `now ≥ time_floor − skew` (§3.5), where `time_floor` is at most
  the clock reading of the last verified pass. A node without an RTC, or one
  whose clock has not been synchronized yet at the pass, runs behind real
  time; an approval that has already expired in real time is then accepted
  while the node's clock is still before its `expires_at` and not below the
  floor less the skew. `After=time-sync.target` (§10.1) does not close this:
  with no wait-sync service it waits for nothing, and even with one it orders
  the start, it does not prove that the clock was synchronized. Options
  (owner decision: the first is selectable in the policy, off by default):
  - require proof of this boot's synchronization in the pass: adopted as
    the opt-in policy field `require_clock_synchronized` (§10.1), proven by
    timesyncd's marker. Every node without a time source (offline, the
    intended field case) or without timesyncd then refuses every boot, which
    is why it is not the default. With the field absent or `false` this
    risk stays as described;
  - enable a wait-sync service (`systemd-time-wait-sync.service`, or
    `chrony-wait.service` with chrony) so that the ordering takes effect:
    the same availability cost, and still not a check inside the pass;
  - shorter approvals (`max_lease_seconds`) narrow the window; an RTC with a
    battery narrows it further;
  - accept it as local trust, like the high water itself (§3.5).
- **M-2: a grant lasts for the boot, except the Knowledge Context broker's.**
  Expiry and revocation are checked by a pass. Once a pass has granted, a
  unit's marker stays under `/run/azazel-activation/granted/` until the boot
  ends, the controller has no `StopUnit` for it, and nothing re-reads the
  approval, the operator trust or the policy during the boot. An approval
  that expires, an operator key that is revoked or a policy that is narrowed
  after the pass therefore stops nothing that is running and does not
  withhold a restart of a granted unit in the same boot (its own `Restart=`
  or an operator's `systemctl start`, which still finds its marker). It takes
  effect at the next boot's pass, which refuses and remasks. Stopping a unit
  at once is an operator action (`systemctl stop` and `mask`), outside
  activation. The Knowledge Context broker is the exception: the recheck of
  §8.3 withdraws and stops it.
- **M-4: what a generation does not bind.** The observe-baseline tree
  (§3.2, §8.1) binds the vendor unit files of the policy's units and, when
  edge-core is in scope, the Edge package and its extracted binary and
  redirect policy. It does not bind:
  - the support daemons' executables and their wrappers: the fixed
    `/usr/libexec/azazel/az-*` entrypoints staged by
    `tools/stage_runtime_entrypoints.py` that the unit files' `ExecStart=`
    name;
  - the Python runtime behind them: the interpreter, the environment and the
    installed `azazel_nexus` and `azazel_nexus_runtime` packages, the
    controller's own code included;
  - the preflight unit `azazel-edge-probe-preflight.service` (ungoverned and
    outside `ACTIVATION_UNIT_ALLOWLIST`, so never measured), whose result the
    pass reads as Edge health (§8.1);
  - grantable unit files outside the policy: §8.2 checks their content, but
    their bytes are not hashed.

  Replacing any of them after the operator signed is not detected by the
  pass; the unit files and the Edge package are. This is root-level local
  trust, like the *pass → launch* window of §8.1.
- **M-5 (VM-observed 2026-10-23): a second pass in the same boot.** The once-claim
  `/run/azazel-nexus-bootstrap/controller-used` is written only by the
  selected bootstrap path, so on the ordinary path the controller can be
  started again after its first pass exited (an operator's
  `systemctl start`). The second pass removes every marker and remasks every
  governed unit first. A unit the first pass granted and that is now running
  stays running (no `StopUnit`; the Knowledge Context broker is stopped at
  preflight, §8.3), so its remask fails with `masked unit has no
  confirmed inactive state`, and the pass is expected to end in the
  emergency narrowing or `RollbackFailed` and exit 1 rather than grant. That
  is fail-closed (nothing new starts; a granted unit that stops cannot
  restart this boot without a marker) but costs availability. The exact
  outcome on systemd 257 was observed on the VM (status below).
  Status: observed on the VM on 2026-10-23 after a granting boot, signed
  with a VM-only rehearsal key (not hardware evidence), and it matches: the
  two records, `RollbackFailed` with exit 1, every marker removed, every
  governed unit masked, and the two units that were running kept running.
  The unit tests are done. `tests/unit/test_runtime_activated_second_pass.py`
  pins, through a fake system bus answered below `SystemdBusSession` (so the
  client's translation of error replies, calls that do not complete and a
  foreign reply owner is included), the preflight remask, the two records
  `activation.evidence_preflight_masked` and `activation.rollback_failed`
  holding unit names and fixed reasons only, `RollbackFailed`, and the first
  pass's markers removed. Ledger lines written before this change may hold
  free exception text in `still_unreachable` and `could_not_mask`. A VM
  rehearsal without a grant (2026-10-22) showed that path; it is not
  hardware evidence.
- **M-6: Edge health is trust in `azprobe`** (§8.1). The probe result is
  accepted when it is owned by `azprobe` (or root) and not group or world
  writable, so
  whoever controls that account (or the preflight's `ExecStart=`, M-4) can
  write a fresh, healthy result for this boot. That admits nothing by
  itself: edge-core is granted only by a pass with every producer verified,
  an operator-signed approval naming edge-core over a generation that pins
  the package, and a probe result naming exactly that package, which the
  pass measures itself. A forged result can admit the signed package before
  it is actually healthy, never another one, and never without the signed
  lease.
- **L-5: the watchdog's fence store belongs to `azwatch`.** The
  `watchdog_fences` health check (`activation_health.read_watchdog_fences`)
  requires every path component above `/var/lib/azazel/state/watchdog` to be
  root-owned and not group or world writable, and the store directory and
  `fences.json` to be owned by `azwatch`. A missing `fences.json` is the
  watchdog's own "never fenced" state. So `azwatch` (or root) can remove its
  fences, and the health check then stops withholding; it cannot satisfy any
  other producer or the lease. Like M-6, a compromised service account can
  undo a narrowing it owns, not create a grant.
- **L-7: soft-reboot keeps `/run` and the boot id.** `systemctl
  soft-reboot` restarts userspace without a kernel boot. The packaged
  tmpfiles rules create `/run/azazel-activation` and
  `/run/azazel-nexus-bootstrap` with `d` lines (no removal), so the grant
  markers and the once-claim survive it; §5's "cleared at every boot" holds
  for a kernel boot only.

  *VM check (2026-10-21, main 09a6f18, Debian 13, systemd 257.13; a check of
  the mechanism, not hardware evidence).* No marker was created; a harmless
  probe file was placed directly under `/run/azazel-activation/` (outside
  `granted/`) and `systemctl soft-reboot` was run. The boot id was the same
  before and after; the probe file survived (`/run` is kept); the controller
  ran again (a new InvocationID) and ended `completed safely: granted=0,
  withheld=12, reasons=no_generation`. The probe file was removed
  afterwards.

  *When the controller runs,* nothing changes: the ordinary pass removes
  the markers before any decision (`_run_once`), and every marker unit
  waits for its READY (`After=`).

  *When it does not run.* The controller carries
  `ConditionPathExists=!/run/azazel-nexus-bootstrap/controller-used`
  (`hardening.py`), and systemd treats a condition-skipped unit as not
  failed, so its `Requires=`/`After=` dependents still run their jobs. The
  once-claim is written only by the selected bootstrap path
  (`bootstrap_controller_once`, from `run_selected_bootstrap`), and a
  bootstrap selection is bound to the current boot id. In normal operation
  it is published after the boot's controller has already run its ordinary
  pass, so the sequence "ordinary pass writes markers → the administrator
  publishes a selection for this boot and starts the controller again →
  the bootstrap path writes the once-claim" is an expected one. (A
  selection published while the boot's controller is still waiting makes
  its first run the bootstrap path; no ordinary pass has written a marker
  in that boot id then.) Before this change the bootstrap path did not
  remove the ordinary pass's markers. After a
  soft-reboot (same boot id, `/run` kept), or a manual restart of the
  controller in the same boot, the controller is skipped and those markers
  stay in front of the dependents' `ConditionPathExists=`. The bootstrap
  path's broad narrowing masks every governed unit, which normally still
  withholds a start, but it does not hold when that narrowing failed or a
  unit was unmasked later.

  *Closed (#251 L-7):* the selected bootstrap path removes every grant
  marker inside its transaction lock and **before** it writes the
  once-claim (`run_selected_bootstrap`); a refusal to remove them refuses
  the attempt without writing the claim and still runs the emergency
  narrowing. The bootstrap broad narrowing (`_narrow_bootstrap_core_units`,
  also used for an invalid selection and for the emergency narrowing)
  removes them first as well, like `_emergency_narrow`, and fails if it
  cannot, after the remask still runs; either refusal prints a fixed line
  on stderr, so the journal names the marker removal as the cause. (No
  ledger record: before the claim the bootstrap path has no writer of its
  own yet, its audit client comes later in the attempt, and opening the
  ordinary pass's activation ledger there would add a second writer to
  that path.) The bootstrap lock guards the gap between the reset and the
  claim; an ordinary pass is excluded because it runs in the same unit,
  `azazel-activated.service`, whose invocations systemd serializes. Only
  the ordinary pass writes markers, and while the claim exists it cannot
  run as a start of that unit (the condition skips it), so from the claim
  to the next kernel boot no marker exists. Not changed: a node whose
  controller is masked, and a running granted unit, which no marker
  removal stops (M-2).

  *Reviewed in [#258](https://github.com/01rabbit/Azazel-Nexus/issues/258)
  (read-only, main 85a6d6e; premise checked on the VM, systemd 257.13:
  soft-reboot keeps the boot id and `/run`, and every unit starts again).*
  Anything bound to the boot id treats a soft-reboot as the same boot. No
  confirmed fail-open was found: most bindings refuse under that premise
  (availability, not authority). Intended and refusing, no change: the
  once-claim `controller-used` (a bootstrap retry needs a kernel reboot),
  the grant transaction `grant-<boot_id>.json` (asks for manual review),
  the bootstrap selection (an intent, not a permission), the deadline and
  its time anchor (`CLOCK_BOOTTIME` continues across a soft-reboot), the
  HIL and service-objective evidence (each requires distinct boots), the
  grant markers (closed above), and approval v1 (not on the production
  path).

  - *Done (#258 item 7): the Edge probe result.* The boot id did not tell a
    result from before a soft-reboot apart, so a preflight that failed
    before writing left that result readable as this boot's until its TTL
    (default 300 s). `az-edge-probed` now removes the previous result
    first, before it reads the boot id or probes anything
    (`clear_previous_result` in `edge_probed.py`: the fixed name only,
    relative to its directory opened with `O_NOFOLLOW`); if it cannot, it
    probes and writes nothing and fails. A run that fails after that leaves
    no result, which reads as `not-checked`.
  - *Done (#258 item 6): wording.* The approval-request output of
    `az-nexus-bootstrap` now says a *kernel* reboot changes the boot id.
  - *Documented, not changed (#258 item 5): the bootstrap overlay journal.*
    A journal is retired only at a later boot's publication; one with the
    same boot id is not (`_retire_prior_boot_journal` in
    `bootstrap_manager.py`). After a soft-reboot that left a journal, every
    publication is refused in that boot id, and clearing it needs a kernel
    reboot. This refuses (availability only); allowing a `closed` journal
    to retire in the same boot id is a possible later change.
  - *Closed (#258 item A): the overlay `/run/systemd/system.control`.* A
    soft-reboot in the middle of a bootstrap attempt (phase `published`)
    may leave the overlay that unmasks auditd and commissiond, while the
    controller is skipped by its `controller-used` condition. The pair
    still cannot start: both carry `Requires=`, `BindsTo=` and `After=`
    `azazel-activated.service`, and with `BindsTo=` plus `After=` a unit
    bound to a condition-skipped unit is not started. VM check (Debian 13,
    systemd 257.13, throwaway units, a mechanism check and not hardware
    evidence): a service with `ConditionPathExists=!<flag>`, skipped
    (`ConditionResult=no`), and a second service with
    `Requires=`/`BindsTo=`/`After=` on it; starting the second failed with
    "A dependency job ... failed" and it stayed inactive. With the flag
    absent both became active. Without the condition skip the controller
    runs and the bootstrap path handles the overlay as before. No change is
    needed; the dependency lines on the pair are load-bearing for this and
    must not be relaxed to `Wants=` or lose `After=`.
- **L-8: the generation store is read without owner or link checks.**
  `GenerationStore.read` and `read_tree` follow links and do not check
  owners or modes under `/var/lib/azazel/generations`. Every byte read is
  re-hashed (`verify`) and compared with the digest the operator signed, so
  a substituted tree or metadata cannot produce a lease for content other
  than the signed one; the most it can cause is a refusal (fail-closed, a
  denial of service by someone who can already write there as root).

The regular path to raise the declared epoch is §11; the optional
`commissioning_storage` diagnostic label was added in #262.

## 11. Raising the declared security epoch (#251)

Owner decision (2026-10-21): build a regular path, operator-signed and
raise-only. Before it, the only way to raise the epoch was to move
`/etc/azazel/bootstrap/deployment.json` aside and publish a new declaration
with `bootstrap-deployment-initialize`, which also accepts any other field.

**Where the epoch lives today.**

- *Declared:* `deployment.json` (`azazel-nexus/bootstrap-deployment/v1`,
  `bootstrap_deployment.py`) holds `security_epoch` with the node digest and
  policy digests. Its store (`bootstrap_deployment_store.py`) publishes once
  and never replaces (create-only with a pending marker; recovery finishes
  only the exact retained bytes), so that a declaration cannot be swapped
  through the store.
- *Node identity* (`/etc/azazel/node.yaml`) holds only the label; the
  declaration's `node_digest` binds it (`declared_node_binding`). It holds no
  epoch.
- *Approval v2 context:* `az-activation request`, `install` and the pass take
  `security_epoch` from the declaration; the approval must name exactly that
  epoch (canonical re-encoding against the context), and the context must
  not be below the high-water epoch floor.
- *High water* (§3.5): `security_epoch` is raised by `install` and by the
  pass to the approved epoch. The pass also refuses a declared epoch below
  the floor (`epoch_high_water`).

**Design.** Two `az-activation` commands; no new approval boolean, flag,
environment variable or unit operation, and no refusal becomes a success.

- `az-activation epoch-request --operator LABEL --to-epoch N --out FILE`
  (read-only) writes the unsigned canonical payload
  `azazel-nexus/activation-epoch-raise/v1` (`src/azazel_nexus/activation_epoch.py`):
  `operator`, `node_digest` (the declaration's, checked against `node.yaml`),
  `deployment_digest` (SHA-256 of the whole current declaration),
  `from_epoch` (the declared epoch) and `to_epoch`, which must be above
  `from_epoch` and not below the high-water epoch floor. The operator must
  be named by the activation policy and hold an active enrolled key.
- The operator signs it off-host with `tools/operator_sign.py --purpose
  activation-epoch-raise`, a new `ApprovalPurpose.ACTIVATION_EPOCH_RAISE`.
  The transcript differs from every other purpose, so an activation
  approval signature cannot raise the epoch and an epoch-raise signature
  cannot approve anything. The signer refuses anything but a canonical
  raise (`to_epoch` above `from_epoch`).
- `sudo az-activation epoch-raise --payload FILE --signature FILE` (root,
  interactive terminal) verifies the signature against the operator trust
  store, the policy's operator set and the exact current declaration
  (`verify_epoch_raise`); refuses without a high-water file (it is
  initialized only by `install`, §3.5, or recovered, §7), with a new epoch
  below the floor, or with the OS clock behind the time floor less the skew.
  It prints what will change, requires the payload SHA-256 to be re-entered
  and `RAISE` to be typed, re-collects and compares everything, then:
  1. raises the high water's `security_epoch` to `to_epoch` (sequence and
     generation floors unchanged, `time_floor = max(stored, now)`);
  2. replaces the declaration with the same one at `to_epoch`
     (`raise_bootstrap_deployment_epoch`: compare-and-swap on the exact
     current bytes, only `security_epoch` may differ and only upwards, under
     the store's exclusive lock and its pending marker, temporary file,
     rename, directory fsync and read-back);
  3. appends `activation.epoch_raised` (operator, node digest, declaration
     digest, both epochs, payload SHA-256, the new floor under `high_water`)
     to `/var/lib/azazel/state/activation.jsonl`. It is a floor event
     (`FLOOR_EVENTS`), so a §7 recovery never goes below the raised epoch.

  Exit 1 means nothing changed, exit 2 that a step after the first write did
  not complete.

**Why old approvals stop verifying.** After step 1 the pass refuses the old
declared epoch (below the floor) and the verifier refuses any approval whose
epoch is below the floor; after step 2 the context names the new epoch, so an
approval for the old one no longer matches. The installed approval is left in
place and fails as `activation_approval_loader`; a new one needs a new
request at the new epoch, a signature and `install --replace`, with a
sequence above the (unchanged) sequence floor. Putting the old declaration
back (root) does not revive it: the floor stays raised.

**Single use and resumption.** The payload is bound to `from_epoch` and the
whole declaration, so once applied the same payload is refused (the
declaration now names `to_epoch`). If step 2 fails after step 1, the node
refuses every approval (fail-closed); running the same signed payload again
resumes (the floor is already at `to_epoch`, which a raise-only write
accepts). An interruption inside step 2 leaves the pending marker, which
every reader refuses until `azazel-nexus bootstrap-deployment-recover`
finishes whichever declaration `deployment.json` holds; then run
`epoch-raise` again if it still names the old epoch.

**A missing ledger record is an audit gap.** If step 3 fails (exit 2,
"activation ledger record missing") or the declaration's durability is
unconfirmed (`DeploymentDurabilityUncertain`, exit 2), the floor and the
declaration may already be raised while `activation.epoch_raised` is absent.
Running `epoch-raise` again cannot add it: the payload no longer matches the
declaration, and there is deliberately no path that writes the record on its
own. Treat it as a gap in the audit trail: record outside the node who raised
the epoch, when and why, and the payload SHA-256. The floor itself is not
affected: the pass still refuses every approval below it.

**Signed but not applied.** A signed payload has no expiry; it stays
applicable while the declaration still names its `from_epoch`. An operator
who signs one and then decides not to apply it deletes the payload and its
signature together (on the workstation and on the node), like any other
unused approval.

**A large step is warned, not refused.** `epoch-request` and `epoch-raise`
print a `WARNING` line in the summary when `to_epoch − from_epoch` exceeds
1000 (`LARGE_EPOCH_STEP`), since a mistyped epoch can never be lowered.

**Bootstrap selection and bootstrap approvals.** The bootstrap path binds the
declaration too:

- a bootstrap selection (`/etc/azazel/bootstrap/selection.json`) carries the
  `deployment_digest` of the declaration it was published against
  (`bootstrap_selection.py`). After a raise the digest differs, so a selection
  still present is refused ("deployment binding differs") and every pass fails
  closed before the ordinary pass. The selection store never replaces a
  selection: an administrator (root) moves `selection.json` (and
  `selection.pending`, if present) aside into a root-only directory, kept for
  the record, with the controller not running. A later bootstrap needs a new
  bootstrap approval (it binds the declared epoch) and a new selection;
- do **not** raise the epoch while a bootstrap lease is valid. The
  bootstrap approval behind it binds the declared epoch, so after a raise
  its revalidation and any renewal are refused; nothing new starts, but the
  bootstrap stays refused until the lease expires (fail-closed, an
  availability cost). Raise after it has expired or been closed.

**Not covered.** The epoch can never be lowered by this path; a mistaken
raise is permanent (approvals are simply signed at the new epoch). Root can
still replace both files by hand (local trust, §3.5). This path issues no
new bootstrap approval or selection (above).
