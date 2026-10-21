# Observe-baseline activation — design proposal (#206)

Owner: [#206](https://github.com/01rabbit/Azazel-Nexus/issues/206) (parent
[#190](https://github.com/01rabbit/Azazel-Nexus/issues/190)).
Status: **accepted with the recommended defaults of §6 (owner, 2026-10-20);
P0, P1 (library only), P2 (readers, §7), P3a (the off-host signer's
`activation` purpose), P3b (the node's `az-activation` tool:
`generation-publish`, `request`, `install`), P4 (SUPPORTING wired into the
pass, §8) and P5 (§3.4: probe contract v2, the boot preflight and edge-core
in the pass's scope, §8.1) implemented; the P6 VM confirmation pending**.
Phases land as separate PRs (§4).

Before P4 no regular path admitted the integrated loop's units: `az-activated`
composed its production pass with `lease=None` and `healthy=False`, granted
nothing and recorded `activation.inputs_incomplete`
(`runtime/src/azazel_nexus_runtime/activated.py`). Since P4 the pass can grant
the five SUPPORTING loop units (§8) from the generation, approval and high
water that `az-activation` (P3b) produces, but no VM has confirmed the boot
sequence (P6). The VM rehearsal
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
  or arbitrary bytes are refused and not signed. It prints the operator,
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
    --valid-for SECONDS [--units UNIT,UNIT] [--out request.json]
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
  trailing newline, to stdout or to a create-only `0600` `--out` file, and a
  summary with `payload_sha256` to stderr. The summary omits the evidence
  binding and the commissioning digest, but the payload itself contains both
  (the operator signs them), so prefer `--out`: the file is created through
  a parent reached without following any link and not writable by group or
  others (a shared directory such as `/tmp` is refused), instead of leaving
  the bytes in a terminal or a redirect with the caller's umask. It never
  signs and never writes an approval file.

  `install` (root) reads the payload and the 64-byte signature (regular,
  single-link files, never followed links), requires `--confirm-sha256` to
  equal the payload SHA-256, collects the same context again and verifies
  with `verify_observe_baseline_approval` against the activation policy, the
  current high-water floors and the OS clock (refusing a clock behind
  `time_floor - skew`); an approved generation below the floor also
  refuses. It shows what was verified, then re-collects and compares
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
  carries `ConditionPathExists=/run/azazel-activation/granted/<unit>`, and the
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
none of them (P4 then wired them, §8; `tests/unit/test_activation_p4_wiring.py`).

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
   only if their sequence still meets it.

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
   clock (`now ≥ time_floor − max_clock_skew_seconds`); the current
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
   dependency; a refused notification or barrier is logged and leaves exit 0
   (the pass was recorded), and the dependent units then simply do not start.
   READY is never sent on a failed pass, and the selected bootstrap path
   keeps its own READY protocol unchanged.

**What READY releases.** Twelve units `Requires=` the controller: the ten
that carry the marker condition and auditd and commissiond. READY would
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
barrier wait (about 5 s) after READY. P6 must observe this window on the VM.

**Edge-core was refused in P4.** A policy naming `azazel-edge-core.service`
failed `activation_policy` as a whole. P5 lifts that refusal (§8.1); the
edge-core unit already carried its marker condition.

**Marker path.** The markers live under `/run/azazel-activation/granted/`, not
`/run/azazel/activation/`: `/run/azazel` is the shared `RuntimeDirectory=` of
several units, which systemd chowns to the starting unit's account and
removes when that unit (including the controller itself) stops.
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
None of this is VM or hardware evidence: P6 still has to show reboot →
granted → reboot → started, and every negative run masked and not started.

### 8.1 P5: edge-core in the pass

`activation_markers.GRANTABLE_UNITS` now holds the five SUPPORTING loop units
and `azazel-edge-core.service`; it is still the one set behind the pass's
policy check (`activation_pass.UNIT_SCOPE` is the same object), the tripwire
and the marker writer, and it equals the policy's `ACTIVATION_UNIT_ALLOWLIST`.
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
  edge-core is withheld (`package_refused`).

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
