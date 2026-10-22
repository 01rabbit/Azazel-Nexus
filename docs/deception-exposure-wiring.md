# Wiring the exposure grant (G6) — design proposal (#196)

Owner: [#196](https://github.com/01rabbit/Azazel-Nexus/issues/196) (the grant
phase G6).
Status: **proposed. Not to be merged as code before G5 (`HG-06`, `HG-09`,
`HG-10` accepted on the real host) and before the owner answers R6
([reachability §9](deception-exposure-reachability.md#9-conditions-added-by-this-design))
and the questions of §9 below.** This document changes no code.
Related: [granting the exposure tier](deception-exposure-grant.md) (§4.3,
§4.4, §5, §6.3, §7, §9, §10, §11) ·
[how outside peers reach the decoy](deception-exposure-reachability.md) (§6,
§8, §9, §11) ·
[observe-baseline activation](activation-observe-baseline.md) (§3.1, §3.2,
§8, §8.2) · [operations](operations.md#deception-lite-decoy-network-196)

## 1. Problem

G6 is the step that makes the `DECEPTION_EXPOSURE` tier grantable
([grant §9](deception-exposure-grant.md#9-phases)). Its parts are built and
called by nothing (G6 preparations A, C and D, and the v3 decoder):

| part | module | judges |
| --- | --- | --- |
| approval v3 | `src/azazel_nexus/activation_approval_v3.py` | §5 C1 condition 1 |
| generation exposure section | `runtime/.../exposure_generation.py` | condition 2 |
| role resolution | `src/azazel_nexus/exposure_interfaces.py` (`resolve_role_interfaces`) | condition 3 |
| LSM, loaded profile, kernel hash | `runtime/.../decoy_apparmor.py` (`exposure_lsm_withholding`) | condition 4 |
| host firewall coexistence | `runtime/.../exposure_withholding.py` (`host_firewall_refusal`) | condition 5 |
| `fb_tunnels_only_for_init_net` | `exposure_withholding.py` (`fb_tunnels_refusal`) | condition 6, static half |
| forwarding, K1, routes | `runtime/.../decoy_reachability.py` (`pass_reachability_departures`) | condition 6, forwarding half |
| masked-and-running units, leftovers | `runtime/.../decoy_residue.py` (`exposure_residue_departures`) | §6.3 G6 item (a) |
| enforcement exclusivity | `src/azazel_nexus/exposure_exclusivity.py` | §6.2 |
| scope file | `src/azazel_nexus/decoy_scope.py` (`render_scope_file`) | §4.3 |

`ActivationController._withholding_reason` still returns
`isolation_evidence_absent` for the tier on every pass
(`src/azazel_nexus/activation.py`), and the runtime's tripwire narrows
everything if an exposure unit is ever granted
(`runtime/src/azazel_nexus_runtime/activated.py`, `_run_once`).

This document says how the parts are connected: in which order the pass asks
them, how the v3 approval is accepted, what the generation records, how the
scope file is written, what changes in the allowlists and the tripwire, which
tests and which VM rehearsal G6 carries, and what the owner decides first. It
is written so that the G6 pull request is a review of code against this
text, not a design made in code.

## 2. What is established, and what is inferred

Read at `main` 7bdf724.

| fact | reference |
| --- | --- |
| The pass runs once per boot: markers reset, preflight remask of every governed unit, producers, the library decision, high water, markers, record, `READY` | `activated.py` `_run_once`, `main`; [observe-baseline §8](activation-observe-baseline.md#8-p4-supporting-wired-into-the-pass) |
| The preflight remask requires each governed unit confirmed inactive; a unit that stays active makes the whole pass fail (`activation.rollback_failed`, `RollbackFailed`, exit 1) | `activated.py` `_mask_and_confirm_inactive`, `_remask_all`, `_narrow_everything`; [grant §11](deception-exposure-grant.md#second-g4-rehearsal-2026-10-22-vm-mechanism-check-not-hardware-evidence) "rehearsal error" |
| Producers are all-or-nothing for the lease; Edge evidence is outside `complete` and withholds only edge-core | `activation_pass.py` `PassInputs.complete`, step 9 |
| The library imports nothing of the runtime; facts about the host reach it as values passed to `activate` (`edge`, `wired`, `commissioning_evidence`) | `activation.py` `ActivationController.activate` |
| `ActivationApprovalPolicy` refuses a unit scope holding an exposure unit (it uses v2's unit rule) | `src/azazel_nexus/activation_approval_v2.py` `ActivationApprovalPolicy.__post_init__` |
| The v3 verifier signs under `ApprovalPurpose.ACTIVATION` and returns `ActivationApprovalV3`, a type the pass refuses | `activation_approval_v3.py` |
| `ACTIVATION_UNIT_ALLOWLIST` omits the exposure units; `POLICY_UNIT_SCOPE` is `GRANTABLE_UNITS` minus them; `GRANTABLE_UNITS` holds them (for the file and loaded-unit checks) | `src/azazel_nexus/activation_policy.py`; `activation_pass.py`; `activation_markers.py` |
| The observe-baseline generation (`observe-baseline-generation/v1`) limits its scope to `ACTIVATION_UNIT_ALLOWLIST` | `src/azazel_nexus/observe_baseline.py` `_scope` |
| The verified commissioning evidence carries the signed proposal bytes and this boot's inventory | `src/azazel_nexus/commissioning_evidence.py` `CommissioningEvidence` |
| The controller's unit: root, `CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `ReadWritePaths=-/run/azazel-activation`, no network ordering | `packaging/systemd/azazel-activated.service` |
| The helper refuses to build when the bridge or its table already exists (`HELPER_ABSENT`) | `runtime/src/azazel_nexus_runtime/decoy_network.py` |
| The installer compiles the four profiles (`--skip-kernel-load --skip-cache`) and records nothing | `packaging/install.sh` |
| The kernel's `raw_sha256` equals the SHA-256 of `apparmor_parser -Q -o` output (one VM, parser 4.1.0) | [grant §11](deception-exposure-grant.md#fifth-g4-rehearsal-2026-10-22-vm-mechanism-check-not-hardware-evidence), fifth rehearsal |

*Inferred, to be checked in G6's VM rehearsal (§8):* that `nft -j list
tables` needs `CAP_NET_ADMIN` (grant §2), so the controller cannot read the
table; that the Service interface's `AppArmorProfile` is `(bs)`; that
`ip -j` run by the controller under its sandbox reads the rules, routes,
namespaces and links without a capability; that a profile compiled by the
installer still equals the kernel's after a reboot through
`apparmor.service` and its cache.

## 3. Invariants

The invariants of [grant §3](deception-exposure-grant.md#3-invariants) and
[reachability §3](deception-exposure-reachability.md#3-invariants) hold. In
particular, for this wiring:

- **No authority beyond the grant design.** The only new permission is the
  one the grant design already decided: a verified v3 approval may name the
  three exposure units, and the pass may then grant them when every condition
  of §5 C1 holds. No unit operation is added (no `StartUnit`, no
  `StopUnit`; §9 Q-B is a question, not a proposal), no capability or
  address family is added to the controller, and nothing is written outside
  `/run/azazel-activation`.
- **Narrowing only.** Every stage of §4 can only withhold the exposure tier.
  None of them can withhold the SUPPORTING units or edge-core, and none of
  them can grant anything by itself.
- **No bypass.** No approval field, policy field, flag, environment variable
  or file makes a stage skip.
- **No name or address in a record.** Ledger entries carry fixed codes and
  labels, as today.

## 4. The order inside one pass

### 4.1 Where each stage runs

The library cannot read the host, so the conditions are split into two
halves:

- the **runtime half**, a new pass step after the lease is formed
  (`activation_pass.collect_pass_inputs`, step 10, after step 9's Edge
  evidence), which reads the host and asks the parts in a fixed order and
  produces one value, the **exposure evidence**;
- the **library half**, in `_withholding_reason`'s exposure branch, which
  consumes that value at one fixed position and decides.

The exposure evidence is a new frozen library type (proposed
`azazel_nexus.exposure_admission.ExposureEvidence`): `generation_digest`
(the generation it was measured against), `scope_digest` (the rendered
scope file's digest, or None) and `refusal` (None, or the first stage's
`"<code>: <phrase>"`). Like `EdgeBaselineState` it is a statement the
runtime makes; the tripwire (§6) re-checks it after the decision. It is
**outside `complete`**, as Edge evidence is: a refusal withholds the three
exposure units and nothing else.

Step 10 runs only when the lease names the three exposure units; otherwise
it reads nothing and records `not_in_scope`. Each stage runs only when every
earlier one held, so a pass records exactly one reason for the tier, and a
host that fails an early, cheap check is not read further. Inside each stage
the "unreadable" code comes first, as each part already orders its codes.

### 4.2 The library half (`_withholding_reason`)

After the checks every tier shares (wiring, `health_not_established`, the
lease refusals, `outside_lease_scope`), the exposure branch reads, in order:

| # | check | input | reader | reason code |
| --- | --- | --- | --- | --- |
| L1 | the lease names all three or none | `lease.units` | existing branch | `exposure_tier_partial` (existing) |
| L2 | no enforcement unit governed with the tier (§6.2) | `self.definitions` | `exposure_exclusivity.exposure_enforcement_conflict` | `exposure_enforcement_exclusive` |
| L3 | the pass handed exposure evidence | `activate(..., exposure=)` | type check | `exposure_evidence_absent` (new; replaces `isolation_evidence_absent`) |
| L4 | the evidence describes this generation | `evidence.generation_digest` against the verified generation | equality | `exposure_evidence_mismatch` (new) |
| L5 | every runtime stage held | `evidence.refusal` | the first stage that failed (§4.3) | that stage's code |

L2 is first among the new checks because it is a property of the build, as
wiring is: no operator action on the node changes it. It withholds the tier
rather than refusing the controller's construction, so the other tiers keep
their verdicts; with today's `CORE_UNITS` it never holds. L3's default is
the shipped one: `activate` without `exposure=` withholds, so every caller
written before G6 keeps withholding.

### 4.3 The runtime half (pass step 10)

| # | condition | input | reader (existing part) | reason codes, in order |
| --- | --- | --- | --- | --- |
| P1 | §5 C1 1: the lease came from a verified v3 approval | `inputs.approval` | type check: exactly `ActivationApprovalV3` naming the three | `exposure_approval_not_v3` (new) |
| P2 | §5 C1 6, static half | `/proc/sys/net/core/fb_tunnels_only_for_init_net` | `exposure_withholding.read_fb_tunnels`, `fb_tunnels_refusal` | `fb_tunnels_not_init_net_only` |
| P3 | §5 C1 4, first half: AppArmor on, the four profiles in enforce mode | `/sys/kernel/security/lsm`, `.../apparmor/profiles` | `decoy_apparmor.read_exposure_lsm`, `exposure_lsm_refusal` | `lsm_apparmor_disabled`, `lsm_profiles_unreadable`, `lsm_profiles_absent`, `lsm_profiles_not_enforced` |
| P4 | §5 C1 5: no ruleset loader enabled or active | `UnitFileState`, `ActiveState` of `nftables.service`, `firewalld.service`, `netfilter-persistent.service` (bus) | new bus reader (§4.4), `host_firewall_refusal` | `host_firewall_unreadable`, `host_firewall_enabled`, `host_firewall_active` |
| P5 | §6.3 G6 item (a): no definition-less running unit, no leftovers | `LoadState`, `UnitFileState`, `ActiveState` of the three units (bus); `ip -j netns list`, `ip -j link show` | new bus reader, fixed `ip` reads (§4.4), `decoy_residue.exposure_residue_departures` | `exposure_state_unreadable`, `exposure_unit_masked_running`, `exposure_leftovers_present` |
| P6 | §5 C1 3: a v3 proposal with a valid scope, its roles resolved to this boot's names | `inputs.evidence` (payload, current inventory) | `fabric_boundary.restore_commissioning_inputs`, `deception_scope_assignments`, `decoy_scope.decode_deception_scope`, `exposure_interfaces.resolve_role_interfaces` | `deception_scope_absent` (new: a v2 proposal), `deception_scope_refused` (new), then `role_evidence_unavailable`, `role_scope_mismatch`, `role_inventory_changed`, `role_interface_unresolved`, `role_interface_ambiguous`, `role_interface_name_refused` |
| P7 | §5 C1 6, forwarding half (R1, R2, R5) | `/proc/sys/net/ipv{4,6}/conf`; `ip -j -4 rule show`, `ip -j -4 route show table main`; P6's names | `decoy_reachability.read_sysctls`, `pass_reachability_departures`, `reachability_refusal` | `forwarding_unreadable` alone, or the first of `forwarding_ingress_off`, `forwarding_role_on`, `forwarding_host_wide`, `forwarding_other_on`, `forwarding_ipv6_on`, `proxy_arp_on`, `ingress_containment_absent`, `decoy_prefix_routed` |
| P8 | §4.3: the scope file renders | P6's `DeceptionScope` and ingress names | `decoy_scope.render_scope_file`, `parse_scope_file` (round trip) | `decoy_scope_unrenderable` (new) |
| P9 | §5 C1 2: the generation's exposure section describes this node | the generation's section (§5.1); the unit, watch and profile files measured now; P8's bytes | `exposure_generation.measure_exposure_section_inputs`, `verify_exposure_section` | `exposure_generation_absent` (new: no section), `exposure_files_unreadable` (new), `exposure_generation_differs` (new) |
| P10 | §5 C1 4, second half: the loaded units name their profiles; the kernel's policy is the compiled one | `LoadState` and `AppArmorProfile` of the four units (bus); `.../apparmor/policy/profiles/*/raw_sha256`; the section's compiled hashes | `decoy_apparmor.loaded_unit_profile_refusal`, `read_policy_hashes`, `policy_hash_refusal` | `lsm_unit_profile_differs`, `lsm_policy_unverifiable`, `lsm_policy_differs` |

Why this order:

- **P1** first: it costs nothing, and without it nothing else matters. It
  should never fail (a v2 approval cannot name the units); it is there so
  that a later change to the decoders cannot make a v2 lease carry the tier.
- **P2 to P5** are host facts that need no commissioning material: single
  `/proc` and `/sys` files, then the bus, then `ip`. A host that is not a
  decoy host (no AppArmor, a firewall loader enabled) is told so at once.
  P3 is the half of condition 4 that needs nothing from the generation.
- **P5 before P6**: leftovers are an operator action on this node, not a
  commissioning matter. As built today it is mostly defence in depth: a
  governed unit still running at the preflight already fails the whole pass
  (§2), and `/run/netns` and the links vanish at reboot, so P5 holds unless
  something before the controller made a leftover in this boot.
- **P6 before P7**: P7 needs the names P6 resolves.
- **P8 before P9**: the section's `scope_digest` is compared with the bytes
  this pass rendered.
- **P10 last**: its expected hashes come from the section P9 verified.

The cost of a slow stage is one boot's withheld tier, never a
grant; there is no retry loop
([reachability §6](deception-exposure-reachability.md#6-the-pass-condition-g6-implemented-not-wired),
"When the pass runs relative to networkd").

### 4.4 The readers G6 adds

Each is read-only and fixed. None is a new authority, but each is new code
in the controller and is listed so the review can find it.

- **Bus reads.** `GetUnitFileState` and the Unit interface's `ActiveState`
  for the three firewall units (they are not governed units, so the
  `DbusUnitManager` unit allowlist gains them for reads only, and no write
  verb accepts them); `LoadState`, `UnitFileState` and `ActiveState` of the
  three exposure units; the Service interface's `AppArmorProfile` of the four
  units of `DECOY_APPARMOR_PROFILES`. A unit with no object maps to None only
  for `NoSuchUnit` from `GetUnit` and the unit-file lookup's not-found;
  every other error refuses (grant §9, "Open until G6").
- **Fixed `ip` reads.** Exactly four argument lists, `ip -j -4 rule show`,
  `ip -j -4 route show table main`, `ip -j netns list`, `ip -j link show`,
  run as `/usr/bin/ip` with an empty environment, a bounded output and a
  deadline, by a runner that refuses any other list (the shape of
  `decoy_network.capture_fixed`). They need `AF_NETLINK`, which the
  controller has, and no capability (*inferred*, §10 item 5). Why not a
  netlink parser of Nexus's own: the verify unit reads the same dumps with
  the same `ip`, so the pass and the verify judge one format
  (`_rules_exact`).
- **No table read.** `exposure_residue_departures` also takes
  `nft -j list tables`. The controller has no `CAP_NET_ADMIN` and gains
  none, so the pass cannot list the table (*inferred*, §10 item 5). G6
  changes the residue judgement so that the pass passes no table listing
  and judges the namespace, the veth end and the bridge only; a leftover
  table alone is left to the helper, which refuses to build over it
  (`HELPER_ABSENT`) and so fails its start closed. If the VM shows the
  listing works without the capability, the table is read as designed.

### 4.5 What the pass records

`activation.inputs_incomplete` gains `observed_inputs.exposure_evidence`, a
fixed label: `not_attempted`, `not_in_scope`, `established`, or
`withheld` with `exposure_stage` (`P1` to `P10`) and the code (no phrase,
no name, no value). `missing_producers` names `exposure_evidence` unless it
is `established` or `not_in_scope`, as `edge_evidence` is named; it never
makes the pass incomplete.

## 5. The approval, the generation and the scope file

### 5.1 Accepting approval v3

**Files.** The same pair, `/etc/azazel/activation/approval.json` and
`approval.sig`, read by the same protected reader. A second pair for v3 is
rejected: two approvals on one node would raise the question of which one
the floors follow.

**Reading.** `activation_store` gains one loader for both schemas. It reads
the pair once, decodes only enough to read `schema` (exactly one of the two
names; anything else refuses), then hands the same bytes to that schema's
own strict verifier (`verify_observe_baseline_approval` or
`verify_activation_approval_v3`), which parses everything again. Neither
schema is accepted as the other. The two share their field set, so what
keeps them apart is that `schema` is inside the signed bytes: a signature
over a v2 document never verifies the same fields under the v3 name, and
each verifier refuses the other's name and unit rule.

**The pass.** `PassProducers.approval` returns either verified type; the
check after it (`activation_pass.py`, step 7) accepts exactly
`ObserveBaselineApproval` or `ActivationApprovalV3`, with the same lease
checks; `raised_high_water` accepts both. v2 and v3 share the
`approval_seq` and `security_epoch` floors: one sequence, one epoch.

**The policy scope.**

- `ACTIVATION_UNIT_ALLOWLIST` gains the three exposure units; the policy
  decoder adds the rule "the three or none", as the approval does, so a
  policy naming one or two is refused as a whole. The policy schema stays v1:
  an older package refuses a policy naming them (closed allowlist), which
  withholds everything, the closed side.
- `POLICY_UNIT_SCOPE` becomes `GRANTABLE_UNITS` (the subtraction goes).
- `ActivationApprovalPolicy` keeps v2's rule. v3 gets its own policy value
  (proposed `ActivationApprovalPolicyV3` in `activation_approval_v3.py`,
  with v3's unit rule); the pass builds the v2 policy from the policy's
  units minus the exposure units and the v3 policy from all of them, so a v2
  approval keeps working on a node whose policy names the tier.
- `observe-baseline-generation/v1` is changed to refuse the exposure units
  explicitly: today it refuses them only because the allowlist does, and the
  allowlist is what G6 widens.

**A dedicated purpose (grant §9 note).** Recommended: a new
`ApprovalPurpose.ACTIVATION_EXPOSURE` (`"activation-exposure"`), the only
purpose under which a v3 approval verifies. What it adds: the payload's
`schema` already keeps a v2 signature from verifying as v3, so the purpose
is not what stops cross-schema reuse. It separates the **act**: an operator
signing an ordinary activation cannot produce an exposure approval by the
same command, the signer's refusal rules for exposure live in one place, and
the trust store can later restrict which enrolled keys may sign exposure
without a new schema. The cost is one enum value and one transcript label.
Owner decision Q-C (§9).

**What the signer may do** (`tools/operator_sign.py`, `--purpose
activation-exposure`): sign a payload only if it is a well-formed canonical
v3 document that **names the three exposure units** (a v3 without them is
refused; v2 stays the way to approve the other units), whose units are
inside `ACTIVATION_UNIT_ALLOWLIST`, with a validity of at most 72 hours. It
prints what `--purpose activation` prints plus a fixed line that the
Deception Lite exposure tier is named. `--purpose activation` keeps refusing
v3. Nothing else changes in the signer: the seed stays off the node, and
the signature is create-only.

**What the operator sees before signing.** Grant §4.4 item 5 has the
signer print the scope digest and the number of prefixes and interfaces.
The v3 payload does not carry them (they are in the generation, bound by
`generation_digest`). Two ways:

| option | idea | verdict |
| --- | --- | --- |
| V1 | `az-activation request` prints them (and the payload SHA-256) on the node; the signer prints `generation_digest`; the operator compares | no decoder change; the comparison is the operator's |
| V2 | v3 gains `exposure_scope_digest`, `exposure_prefix_count`, `exposure_ingress_count`; the verifier compares them with the generation's section and P8's rendering; the signer prints them | the operator signs exactly what they read; a change to the not yet wired v3 decoder |

**Recommended: V2.** It only adds a binding, and the decoder is not wired
yet, so no signed document exists to migrate.

**`az-activation`.** `request --units` may name the three exposure units
(all three or none, and only with the policy naming them); it then writes a
v3 payload and prints the exposure lines. `install` verifies v3 with the
same steps as v2 (high water, sequence above the floor, the lock, the read
back).

### 5.2 The generation's exposure section

**Schema.** `azazel-nexus/observe-baseline-generation/v2`: v1's document
plus a key `exposure`, **required exactly when** the scope names the three
units and forbidden otherwise (the rule `edge_pin.package_digest` follows).
v1 stays the schema of a generation without the tier. The name is the
implementation's choice (grant §4.4 item 5); this one is proposed because
the document is a strict superset and the publisher, `request` and the pass
already decode it.

**Content.** `EXPOSURE_SECTION_KEYS` gains one key, `apparmor_compiled`:
for each of the four profiles, `sha256:<hex>` of the installer's compiled
output (below). The section is then: the three exposure unit files, the
three watch unit files, the four profile files, the scope digest and the
four compiled-policy digests.

**The installer records the compiled hash** (grant §7, "Left to G6"):

1. After placing the four profiles in `/etc/apparmor.d` (root, `0644`),
   with the service manager only, for each profile:
   `apparmor_parser -Q -o <private temporary file> /etc/apparmor.d/<name>`,
   with no other flag, so `/etc/apparmor/parser.conf` applies as it does to
   `apparmor.service`'s load (the form observed equal to the kernel's
   `raw_sha256`, grant §11).
2. The SHA-256 of each output goes into one record,
   `/etc/azazel/activation/apparmor-compiled.json`: canonical JSON with a
   contract name (proposed `azazel-nexus/apparmor-compiled/v1`), the four
   digests and, for diagnosis only, the parser's version line. Written as a
   private temporary file in the same directory, fsynced, renamed, the
   directory fsynced (root `0600` in the root `0700` directory the
   installer already creates). A failed compilation refuses the install, as
   today.
3. A `DESTDIR` or `--without-service-manager` run writes no record; then
   `generation-publish` cannot build an exposure generation and says so.

The record is an input of `generation-publish`, never of the pass. The
pass trusts only what the operator signed: the section in the generation.

**`az-activation generation-publish`**, when the policy names the tier:
collects the verified commissioning evidence (as now), runs P6 and P8 to
render the scope bytes in memory, measures the files with
`measure_exposure_section_inputs`, reads the compiled record (root's, one
link, no link followed, bounded), builds the section, and prints, before
the typed confirmation, the scope digest, the number of prefixes and
ingress interfaces and the four compiled digests. `request` and `install`
re-measure and re-render the same way.

**The pass compares** (P9, P10): `verify_exposure_section` with the files
measured now and P8's bytes; then `policy_hash_refusal(read_policy_hashes(),
expected)` with `expected` the section's `apparmor_compiled` values without
the `sha256:` prefix. A kernel that loaded another compilation (a changed
include, another file defining the same name, another parser, other kernel
features) differs and withholds as `lsm_policy_differs` until the exposure
is installed again, a new generation published and a new approval signed.
That is the closed side, and §10 lists what is still *inferred* about it.

### 5.3 Writing the scope file

The pass writes `/run/azazel-activation/decoy-scope.json` (grant §4.3) only
when the decision granted the three exposure units and the tripwire (§6)
accepted it, **before** the grant markers:

1. **Removal first, with the markers.** At the start of the pass,
   `reset_grant_markers` also removes `decoy-scope.json` and any temporary
   file of the fixed prefix; a directory or other non-regular object at that
   name refuses, as an unexpected `granted/` does
   (`activation.grant_markers_unclean`, then the pass fails after
   narrowing). So a pass that withholds the tier leaves no scope file, and a
   helper started later in the boot fails at `LoadCredential=` (closed).
2. **Write.** Open `/run/azazel-activation` without following a link and
   require it root-owned and not group or other writable (the markers'
   rule). Create `decoy-scope.json.tmp` with `O_CREAT|O_EXCL|O_NOFOLLOW`,
   mode `0600`, owner root; write P8's bytes; `fsync`; rename onto
   `decoy-scope.json` relative to the directory descriptor; `fsync` the
   directory.
3. **Read back.** `parse_scope_file` over the file as read (the helper's
   rules: regular, one link, root's, not group or other writable, bounded)
   and require its digest equal to the evidence's `scope_digest`.
4. **Then the markers**, for exactly the granted units, as now.

Any failure in 2 or 3 is recorded (`activation.decoy_scope_unwritten`) and
answered like an unwritable marker: the emergency narrowing removes the
markers **and the scope file** and masks every governed unit. The
emergency narrowing removes the scope file in every case.

## 6. The allowlist, the grantable set and the tripwire

| item | today | G6 |
| --- | --- | --- |
| `ACTIVATION_UNIT_ALLOWLIST` | six units | six plus the three exposure units (three or none in a policy) |
| `POLICY_UNIT_SCOPE` | `GRANTABLE_UNITS` minus the three | `GRANTABLE_UNITS` |
| `GRANTABLE_UNITS` | holds the three | unchanged; the watch's three units stay out (grant §6.3: no marker, no allowlist) |
| `write_grant_markers` | three or none | unchanged |
| `observe-baseline-generation/v1` | scope inside the allowlist | refuses the exposure units explicitly; v2 required for them (§5.2) |
| `_withholding_reason` | `isolation_evidence_absent` always | L1 to L5 (§4.2) |
| `activate` | no exposure input | `exposure=` (default None, which withholds) |

**The tripwire** in `_run_once` changes from "any exposure grant narrows" to
"an exposure grant narrows unless all of these hold":

- all three are granted, or none (a partial grant narrows);
- the lease names all three, and `inputs.approval` is exactly
  `ActivationApprovalV3`;
- `inputs.exposure` is an `ExposureEvidence` with `refusal` None, its
  `generation_digest` the outcome's generation, and a `scope_digest`;
- the pass rolled nothing back;
- (after writing) the scope file read back has that digest.

Any other exposure grant removes the markers and the scope file, masks
every governed unit and raises, as today. The existing checks (lease and
health, scope, edge-core's evidence) are unchanged.

**The decoy and the record.** Grant §9's G6 row asks that an isolation
record whose `scope_digest` is `none` (a helper run without a scope) is
refused. The decoy (`decoyd.py`, `decoy_isolation.py`) gains that refusal:
under its unit the helper always has the credential, so `none` means a run
outside the unit. Whether the decoy should also compare the record's digest
with the pass's file is §10 item 6.

## 7. Tests G6 carries

Unit tests (fake manager, temporary root, keys generated per test, in the
style of `tests/unit/test_runtime_activation_pass.py`):

1. **The order.** For each stage P1 to P10, a pass in which only that stage
   fails withholds exactly the three exposure units with that stage's first
   code, grants the SUPPORTING units and edge-core as before, writes no
   scope file and no exposure marker, and does not call any later stage
   (each later part replaced by one that fails when called, as
   `tests/unit/test_exposure_g6_parts.py` does today).
2. **The library.** L1 to L5 each withhold with their code; `activate`
   without `exposure=` withholds as `exposure_evidence_absent`; evidence for
   another generation is `exposure_evidence_mismatch`; an exposure verdict
   never differs between the three units.
3. **A full grant.** Every stage holds: the three are granted, the scope
   file is written `0600` root before the markers, its bytes equal P8's
   rendering, the markers are the granted units, the record carries
   `exposure_evidence: established`.
4. **Approval.** v2 and v3 from one pair, dispatched by schema; v3 signed
   under `activation` refused when the purpose is dedicated; v2 naming an
   exposure unit refused; v3 naming one or two refused; v3 without the three
   refused by the signer; a v3 whose exposure fields (V2) differ from the
   section refused; the floors shared and raised by either.
5. **Policy.** A policy naming one or two exposure units refused; naming the
   three accepted; a v2 approval still verifies under a policy naming the
   three.
6. **Generation.** v1 refusing the exposure units; v2 requiring the section
   exactly with them; each section digest changed refused with its label;
   the compiled record absent, unprotected or malformed refuses
   `generation-publish`.
7. **Installer.** With a stub `apparmor_parser`, the record holds the
   SHA-256 of what `-Q -o` wrote, is written atomically and refuses on a
   failed compilation; no record under `DESTDIR`.
8. **Scope file.** Removed at the start of every pass (also a stale
   temporary); a non-regular object at the name refuses the pass; written
   only on a grant; a failed write or read back narrows everything and
   removes markers and file; never written when the tier is withheld.
9. **Tripwire.** Each condition of §6 violated alone (a partial grant, a v2
   approval, evidence with a refusal, another generation, no scope digest, a
   rolled-back pass, a read back that differs) narrows everything.
10. **Readers.** The bus reader's None only for `NoSuchUnit` and not-found;
    the `ip` runner refuses any other argument list and any environment; the
    residue judgement without a table listing.
11. **Boundaries.** The library still imports no runtime module; the
    controller's unit file gains no capability, address family or writable
    path (only, if §10 item 3 is decided, an `After=`); the import-closure
    pins of the pass list exactly the parts above; the tests of the G6
    preparations that assert "called by nothing" are replaced by tests of
    the order, not deleted silently.
12. **`az-activation`.** The CLI end to end (`generation-publish` →
    `request` → `operator_sign --purpose activation-exposure` → `install` →
    one pass) grants exactly the three plus the requested units, as
    `tests/unit/test_runtime_activation_cli.py` does for v2.

## 8. The VM rehearsal (on the G6 branch, before merge)

A check of the mechanism on a VM, **not hardware evidence**, and no record
for `HG-06`, `HG-09` or `HG-10` (grant §3). Debian 13 VM as in the G4
rehearsals, with the G6 branch installed; no unit copy, no hand-placed
marker: the grant comes from the pass.

**Signatures are the operator's.** Three steps need an operator signature:
the v3 commissioning proposal (`commissioning-proposal`), and the v3
approval (`activation-exposure`, or `activation` if Q-C is declined), once
for the grant and again for each refusal that changes the generation. They
are made by the operator with a **rehearsal key generated for this run and
enrolled only on the VM**, never with an enrolled production key, and no
agent signs on the operator's behalf. A rehearsal key never becomes a real
one.

**Rehearsal rule** (grant §11): the controller runs once per boot; nothing
re-runs it in the same boot, and every refusal below is a change followed by
a reboot.

1. **Prepare.** Install; check that `/etc/azazel/activation/apparmor-compiled.json`
   exists (`0600` root). Commission with a v3 proposal whose
   `deception_scope` confirms one test ingress (operator signs). Place the
   operator's host configuration of
   [reachability §8](deception-exposure-reachability.md#8-the-operators-part-outline)
   (`.link`, `.network`, the `az-decoy0` sysctl). Reboot.
2. **Publish and approve.** Policy naming the three plus the SUPPORTING
   units; `az-activation generation-publish` (record the printed scope
   digest and counts); `az-activation request --units ...` (v3);
   `operator_sign --purpose activation-exposure` off the VM (operator
   signs); `az-activation install`.
3. **Grant (boot 1).** Reboot. Expect: the ledger's `unit_granted` for the
   three, `exposure_evidence: established`; `decoy-scope.json` present,
   root `0600`, its SHA-256 the published scope digest; the markers; the
   three units enabled, not started in this boot (a grant enables for a
   later boot; observe and record what actually happens).
4. **Start (boot 2).** Reboot. Expect: the pass grants again; the namespace
   unit, the helper and the decoy start in that order, the verify and its
   timer run; the isolation record v2 passes all nine checks with
   `scope_digest` equal to the file's; an approved source reaches the decoy
   on its three ports and an unapproved one does not. Measure the time from
   `READY` to the decoy's listen.
5. **Each refusal**, one at a time, a change then a reboot. For each:
   the ledger names the expected code and stage, the three exposure units
   are masked and not started, no scope file exists, and the SUPPORTING
   units and edge-core are granted as without the change.

   | change | expected |
   | --- | --- |
   | `net.core.fb_tunnels_only_for_init_net` not `2` | `fb_tunnels_not_init_net_only` (P2) |
   | boot with `apparmor=0` | `lsm_apparmor_disabled` (P3) |
   | one profile loaded in complain mode | `lsm_profiles_not_enforced` (P3) |
   | `nftables.service` enabled; then disabled but started by a `Wants=` | `host_firewall_enabled`; `host_firewall_active` (P4) |
   | a rehearsal unit `Before=azazel-activated.service` that runs `ip netns add azazel-decoy` | `exposure_leftovers_present` (P5) |
   | the v2 proposal (no scope) | `deception_scope_absent` (P6) |
   | the ingress's `.link` changed so its kernel name differs | `role_inventory_changed` (P6) |
   | the ingress's `.network` without `IPv4Forwarding=yes` | `forwarding_ingress_off` (P7) |
   | `net.ipv4.ip_forward=1` | `forwarding_host_wide` (P7) |
   | one extra rule before `main`; a K1 rule removed | `ingress_containment_absent` (P7) |
   | a route `10.255.196.2/32` via the management side | `decoy_prefix_routed` (P7) |
   | IPv6 forwarding on one interface | `forwarding_ipv6_on` (P7) |
   | a watch unit or a profile file edited after publishing | `exposure_generation_differs` (P9) |
   | a policy without the tier, with the v3 approval | the approval refused at the scope; nothing granted (all-or-nothing producers) |
   | a v3 signed under `activation` (Q-C adopted) | the approval refused; nothing granted |
   | an include of a profile (`tunables/global`) changed, then a reboot | `lsm_policy_differs` (P10) |
   | the `apparmor` package reinstalled at another version, if one is available | record what P10 says (§10 item 2) |

6. **Restore** each change and reboot: the tier is granted again (boot 1)
   and starts (boot 2).
7. **Inferred items of §2** recorded as observed: the `ip` reads and the bus
   reads under the controller's sandbox; whether `nft -j list tables` works
   without `CAP_NET_ADMIN` (§10 item 5); the `AppArmorProfile` value's form; the
   kernel hash after a reboot through `apparmor.service`'s cache; the
   controller's timing against networkd (§10 item 3).

## 9. Owner decisions before G6

- **Q-R6. R6** ([reachability §9](deception-exposure-reachability.md#9-conditions-added-by-this-design)):
  is forwarding switched on for the ingress before activation compatible
  with commissioning §2, given K1 and the name pin? G6 is not merged before
  the answer. If §2 forbids the switch itself, Q11 is revisited and this
  design waits.
- **Q-B. G6(b), the controller masks but does not stop** (grant §6.3). The
  options:

  | option | idea | adds authority |
  | --- | --- | --- |
  | B0 | no stop: the preflight already fails the whole pass while a governed unit runs (§2), P5 withholds the tier on leftovers, the trip stops the units on a failed verify, and [operations](operations.md#deception-lite-decoy-network-196) tells the operator how to stop and clean by hand | no |
  | B1 | the controller may stop the three exposure units only, when the preflight finds one running without a grant | yes: a `StopUnit` on three named units, a new unit operation |

  **Recommended: B0.** This document does not propose B1; it records it as
  the owner's question. Under B0 the cost is the state the second G4
  rehearsal showed (a unit masked and running until the trip or the
  operator stops it), reported by the failed pass.
- **Q-C. A dedicated `ApprovalPurpose`** (§5.1). Recommended: yes,
  `ACTIVATION_EXPOSURE`. Declined, v3 verifies under `ACTIVATION` as the
  G6-prep verifier does.

Also for the owner, with recommended defaults that only narrow:

- **Q-V. The exposure fields in v3** (§5.1): recommended V2.
- **Q-E. Exclusivity as a withhold** (§4.2 L2) rather than refusing the
  controller's construction: recommended, so the other tiers keep their
  verdicts.

## 10. Open points

1. **The flow label.** On kernel 6.12 a rule added with `flowlabel` showed no
   flow label in any `ip` output, *inferred* dropped
   ([reachability §6](deception-exposure-reachability.md#6-the-pass-condition-g6-implemented-not-wired)).
   Before G6 is wired, the target host's kernel is checked: a rule with
   `flowlabel` either refused by the kernel, or printed by iproute2 (and then
   refused by `_rules_exact`). If the target kernel keeps it unprinted, the
   kernel version is fixed for the decoy host or K1's comparison is given
   another source. Recorded with the `HG-06` run.
2. **The parser's version and the compiled hash.** One VM, parser 4.1.0:
   the installer's `-Q -o` output equalled the kernel's hash and the cache.
   Still *inferred*: whether kernel features, `parser.conf`, a parser update
   (a Debian point release), a cache compiled by another version, load
   flags, or a file with several profiles change the output. Each makes the
   tier withhold (`lsm_policy_differs`) until reinstall, new generation and
   new approval: closed, but an `apparmor` package update would silently
   withhold the tier until the operator acts. G6 records the parser version
   in the compiled record so the operator can see why; whether the installer
   should also compare its compilation with the cache file
   `apparmor.service` loads (grant §7, "A G6 requirement") is measured in
   §8 step 5.
3. **The controller's `After=` and networkd.** The pass does not wait for
   networkd; early in a boot it may read the ingress not yet forwarding or
   K1 not yet installed and withhold for that boot. Options:
   `After=systemd-networkd-wait-online.service` (a no-op where that unit is
   not in the transaction, so it may not order anything unless something
   pulls it in), or `After=network-online.target` with or without
   `Wants=`; each delays every tier's pass, and `wait-online` waits up to its
   own timeout when a link is down. Measured in §8 (reachability §11 item
   11) before a choice; the choice is one `After=` (and possibly one
   `Wants=`) in the controller's rendered unit, measured like the rest, and
   no loop. Until then a slow networkd costs a withheld tier.
4. **The rule order networkd uses** (reachability §5, §11 items 8 and 10):
   whether K1 is installed before the link forwards, at boot and after a
   link flap, and how long the ingress forwards without K1 when the name pin
   fails. Part of R6.
5. **The table listing at the pass** (§4.4): if `nft` needs
   `CAP_NET_ADMIN` for a listing, the pass judges leftovers without the
   table and relies on the helper's `HELPER_ABSENT`.
6. **The decoy and the pass's scope.** The decoy refuses a record with
   `scope_digest` `none` (§6). Comparing the record's digest with the
   pass's file would need the decoy to read a root `0600` file or a second,
   readable digest file under `/run/azazel-activation`; the verify already
   compares the live table with the scope every period. Proposed: no second
   file; revisit if `HG-06` shows a gap.
7. **Evidence is a statement, not a proof.** `ExposureEvidence`, like
   `EdgeBaselineState`, could be constructed by any caller of `activate`.
   The production caller is the pass, and the tripwire re-checks the
   evidence and the scope file after the decision. A mint like
   `ActivationAuthorization`'s is not proposed: it would protect against
   code in the same process, which can already call the unit manager.
8. **The `AppArmorProfile` property's form** (`(bs)`, *inferred* from
   org.freedesktop.systemd1(5)) and the reader's None mapping (grant §9,
   "Open until G6") are fixed from the VM's reading in §8.
9. **What a refusal costs the operator.** Every change to the exposure
   files, profiles, includes or the parser needs a new generation and a new
   v3 signature, as a changed unit file does for the observe baseline.
   Intended; [operations](operations.md#deception-lite-decoy-network-196)
   gains the procedure when G6 lands.
