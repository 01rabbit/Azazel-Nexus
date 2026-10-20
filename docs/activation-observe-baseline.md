# Observe-baseline activation — design proposal (#206)

Owner: [#206](https://github.com/01rabbit/Azazel-Nexus/issues/206) (parent
[#190](https://github.com/01rabbit/Azazel-Nexus/issues/190)).
Status: **accepted with the recommended defaults of §6 (owner, 2026-10-20);
P0, P1 (library only), P2 (inert readers, §7), P3a (the off-host signer's
`activation` purpose) and the probe half of P5 (§3.4: probe contract v2 and
the boot preflight) implemented, nothing wired into the pass**. Phases land
as separate PRs (§4).

Today no regular path admits the integrated loop's units. `az-activated`
composes its production pass with `lease=None` and `healthy=False`, grants
nothing and records `activation.inputs_incomplete`
(`runtime/src/azazel_nexus_runtime/activated.py`). The VM rehearsal
([#195](https://github.com/01rabbit/Azazel-Nexus/issues/195)) therefore starts
the loop by the rehearsal-only procedure, and the result says *activation
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
   and a probe result from before a reboot is stale
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
| `activation_policy` | required | protected `/etc/azazel/activation/policy.json`: authorized operators, `max_lease_seconds`, exact unit scope, health floors, clock skew |
| `epoch_high_water` | required | anti-replay and rollback floor (§3.5) |
| `trusted_clock` | required | a persisted monotonic time floor (§3.5) |
| `node_health` | required | controller-owned local prerequisites only (§3.3) |
| `operational_generation_publisher` (new) | required | observe-baseline generation (§3.2) |
| `edge_evidence` | edge-core only | exists (#198); needs the ordering fix (§3.4) |
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
  or arbitrary bytes are refused and not signed. It prints the operator,
  approval id, units, generation and its digest, node digest, epoch,
  sequence and validity window; the commissioning evidence binding is
  checked but not printed. This is a shape check only: the node verifier
  still decides against its own context, policy and floors. Until
  `az-activation request` exists nothing on the node produces the payload.

  ```sh
  PYTHONPATH=src uv run --no-project --with 'pynacl>=1.5' python -m tools.operator_sign \
    --purpose activation --payload approval.json \
    --expect-payload-sha256 NODE_PRINTED_SHA256 --expect-public ENROLLED_PUBLIC_HEX \
    --seed /path/outside/any/checkout/operator.seed --out approval.sig
  ```
- **Request and install.** A runtime CLI `az-activation request` collects the
  independent context and prints the canonical payload and its SHA-256; it
  never signs or writes approval files. `az-activation install --payload
  --signature --confirm-sha256` re-verifies against freshly collected context,
  places the files atomically, refuses to replace without a separate
  confirmation, and appends an audit event. It creates no key.
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
  Approvals: raise `security_epoch` or the `approval_seq` floor. Expiry:
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
Bringing edge-core into the activation scope is the rest of P5 and depends on
P4's wiring.

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
| P5 | EDGE_BASELINE: probe preflight (E1), probe v2 boot binding (both implemented, §3.4), edge-core in scope |
| P6 | VM rehearsal with a VM-only rehearsal key: publish → request → sign on the workstation → install → reboot → granted → reboot → started; negative runs (approval removed, epoch raised, operator revoked, clock moved back, tree altered, probe stale) each leave units masked **and not started**. Recorded as rehearsal, never evidence |

## 5. Risks

- **Same-boot masking does not stop a queued start (VM-confirmed,
  2026-10-20).** On the rehearsal VM (Debian 13, systemd 257) a harmless
  enabled unit ordered after a oneshot that masked it during boot still
  started, both with `systemctl mask --runtime --no-reload` and with a mask
  followed by a daemon reload (the reload ran, `Reloading finished`, and the
  unit, which had a pending start job, stayed loaded and started right after).
  So masking at the pass can never withhold a unit the previous pass enabled
  in the same boot. **Resolution adopted for P4:** every governed loop unit
  carries `ConditionPathExists=/run/azazel/activation/granted/<unit>`, and the
  controller writes that marker (root-owned, under a root `0755` directory on
  the volatile `/run`) only for the units granted by this boot's pass, after
  recording the decision. A unit without its marker is skipped
  (`unmet condition check`) rather than started; with it, it starts normally
  (both VM-confirmed with the same harmless test units). The marker grants
  nothing by itself: absence only withholds, it is cleared at every boot, the
  controller still never starts a unit, and masking remains for the next boot.
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

## 7. P2 readers (inert)

Phase P2 adds the readers of §3 without wiring them; `az-activated` imports
none of them (`tests/unit/test_activation_p2_inert.py`).

- `src/azazel_nexus/activation_policy.py`: `/etc/azazel/activation/policy.json`
  (`azazel-nexus/activation-policy/v1`), read like the approval (root `0700`
  directory, root `0600` single-link file, read twice). Closed canonical shape;
  `policy_digest` is the SHA-256 of the exact bytes. The file must be the
  canonical bytes themselves (sorted keys, no whitespace, **no trailing
  newline**); anything else is refused rather than normalized. `units` must be a subset
  of the code-fixed `ACTIVATION_UNIT_ALLOWLIST` (the five SUPPORTING loop
  units and edge-core); `max_lease_seconds` ≤ 72 h and
  `max_clock_skew_seconds` ≤ 300 are capped in code. `state_floors` and
  `resource_floors` use the field names of the bootstrap capacity and resource
  checks. Reusing them means the capacity floors measure
  `state/bootstrap` and `state/audit`, not a dedicated activation volume.
- `src/azazel_nexus/observe_baseline.py`: builder and verifier of the
  `baseline.json` tree, against a caller-supplied scope and installed unit
  file bytes. `edge_pin` holds the pin `version`, a `contract_digest` (the
  SHA-256 of the canonical `edge_package.PIN` record, which carries no
  artifact digest of its own) and, exactly when `azazel-edge-core.service` is
  in scope, the caller-supplied `package_digest` of the installed archive (the
  value the manifest check compares). The operator's signature over
  `generation_digest` therefore binds one specific Edge package; outside that
  scope the field is forbidden. The tree is refused by the bootstrap verifier
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
   only if their sequence still meets it.
