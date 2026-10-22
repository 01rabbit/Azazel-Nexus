# Wiring the exposure grant (G6) — design proposal (#196)

Owner: [#196](https://github.com/01rabbit/Azazel-Nexus/issues/196) (the grant
phase G6).
Status: **proposed; revised after the cross review of the G6 parts and the
independent review of #301. Not to be merged as code before G5 (`HG-06`, `HG-09`,
`HG-10` accepted on the real host) and before the owner answers R6
([reachability §9](deception-exposure-reachability.md#9-conditions-added-by-this-design))
(the questions of §9 below were answered on 2026-10-23, each as
recommended).** This document changes no code.
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
| scope file | `src/azazel_nexus/decoy_scope.py` (`render_scope_file`) | grant §4.3 |

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
| The controller starts no process: in the runtime only `decoy_network.py` may spawn one (`SPAWN_EXEMPT`) | `tests/unit/test_runtime_boundary.py` |
| What the controller can read: `/proc/sys/net`, the service manager's bus, `/sys/kernel/security`, `/etc/apparmor.d`, `/run/azazel-activation`, and route netlink without a capability; today's netlink reader sends one request, an `RTM_GETLINK` dump | `runtime/src/azazel_nexus_runtime/netlink.py` |
| A listing of nftables needs `CAP_NET_ADMIN` (nfnetlink checks it per message, a listing included), which the controller does not have | grant §2; the controller's unit above |
| The helper refuses to build when the bridge or its table already exists (`HELPER_ABSENT`) | `runtime/src/azazel_nexus_runtime/decoy_network.py` |
| The isolation record accepts `scope_digest` `none`, and the decoy's gate does not compare the digest with anything | `src/azazel_nexus/decoy_isolation.py` (`NO_SCOPE`, `require_isolation_for_decoy`) |
| The installer compiles the four profiles (`--skip-kernel-load --skip-cache`) and records nothing | `packaging/install.sh` |
| `netlink.py` is the commissioning reader of permanent MACs: one request (`RTM_GETLINK`), pinned by its docstring and `tests/unit/test_runtime_netlink.py`; `LinkRecord.name` may be None | `runtime/src/azazel_nexus_runtime/netlink.py` |
| The residue judgement reads the namespace from `/run/netns` (`read_netns`), takes the host's links as the names `netlink.read_links` yields (None for a failed dump), and takes no table listing (A1, §4.4) | `runtime/src/azazel_nexus_runtime/decoy_residue.py` (#302, #308) |
| `measure_scoped_unit_files` limits its scope to `ACTIVATION_UNIT_ALLOWLIST`; the loaded-unit check (step 6b) already covers every grantable unit, the exposure units included | `runtime/src/azazel_nexus_runtime/activation_unit_files.py`; `activation_pass.py` step 6b |

*Observed on a VM* (Debian 13, systemd 257; a mechanism check, not read
from code and not hardware evidence):

- the kernel's `raw_sha256` equalled the SHA-256 of `apparmor_parser -Q -o`
  output for the four profiles (one VM, parser 4.1.0;
  [grant §11](deception-exposure-grant.md#fifth-g4-rehearsal-2026-10-22-vm-mechanism-check-not-hardware-evidence),
  fifth rehearsal);
- `GetUnitFileState` of a unit with no file (`firewalld.service`,
  `netfilter-persistent.service`) answers the error
  `org.freedesktop.DBus.Error.FileNotFound` ("No such file or directory"),
  **not** `NoSuchUnit`; of `nftables.service` it answers `s "disabled"`;
- `GetUnit("firewalld.service")` answers
  `org.freedesktop.systemd1.NoSuchUnit` ("Unit firewalld.service not
  loaded."); after a `LoadUnit` its `LoadState` is `"not-found"` (the pass
  never calls `LoadUnit`, which would load a unit);
- the Service interface's `AppArmorProfile` is `(bs)`; for
  `azazel-decoyd.service`, loaded and masked, it read `false ""`.

*Inferred, to be checked in G6's VM rehearsal (§8):* that `RTM_GETRULE`
and `RTM_GETROUTE` dumps need no capability under the controller's sandbox
(reachability §6, "Reads"); that a profile compiled by the installer still
equals the kernel's after a reboot through `apparmor.service` and its
cache.

## 3. Invariants

The invariants of [grant §3](deception-exposure-grant.md#3-invariants) and
[reachability §3](deception-exposure-reachability.md#3-invariants) hold. In
particular, for this wiring:

- **No authority beyond the grant design.** The only new permission is the
  one the grant design already decided: a verified v3 approval may name the
  three exposure units, and the pass may then grant them when every condition
  of §5 C1 holds. No unit operation is added (no `StartUnit`, no
  `StopUnit`; §9 Q-B is a question, not a proposal), no capability or
  address family is added to the controller, and the controller gains no
  write outside `/run/azazel-activation` (what it writes today, the ledger,
  the high water and the unit masks, is unchanged). The installer gains one
  write, the compiled-hash record under `/etc/azazel/activation` (§5.2).
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
scope file's digest, or None), `refusal` (None, or the first stage's
`"<code>: <phrase>"`) and `stages` (the stages that held, in order). Its
`__post_init__` refuses an inconsistent value: with `refusal` None,
`scope_digest` must be a `sha256:<hex>` digest and `stages` exactly `P1` to
`P11`; with a refusal, `stages` is a strict prefix of them. Like
`EdgeBaselineState` it is a statement the runtime makes; the tripwire (§6)
re-checks it after the decision, every stage included. It is **outside
`complete`**, as Edge evidence is: a refusal withholds the three exposure
units and nothing else.

**Step 10 never raises** (review of #301, finding 3). `_run_once` turns any
exception out of `collect_pass_inputs` into `inputs=None`, which withholds
every tier. So step 10 is wrapped whole in its own `try`/`except`: any
exception in any stage (a reader, a part, the construction of the evidence)
becomes evidence with the fixed refusal `exposure_stage_unreadable` (new)
and the stages that held before it. Nothing of step 10 reaches the
producers' `complete` or the lease.

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
| L2 | no enforcement unit governed with the tier (§6.2) | `self.definitions` | `exposure_exclusivity.exposure_enforcement_conflict` | `exposure_enforcement_unreadable`, `exposure_enforcement_exclusive` |
| L3 | the pass handed exposure evidence | `activate(..., exposure=)` | type check | `exposure_evidence_absent` (new; replaces `isolation_evidence_absent`) |
| L4 | the evidence describes this generation | `evidence.generation_digest` against the verified generation | equality | `exposure_evidence_mismatch` (new) |
| L5 | every runtime stage held | `evidence.refusal`, `evidence.stages` | the first stage that failed (§4.3) | that stage's code, or `exposure_stage_unreadable` |

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
| P2 | §5 C1 6, static half | `/proc/sys/net/core/fb_tunnels_only_for_init_net` | `exposure_withholding.read_fb_tunnels`, `fb_tunnels_refusal` | `fb_tunnels_unreadable`, `fb_tunnels_not_init_net_only` |
| P3 | §5 C1 4, first half: AppArmor on, the four profiles in enforce mode | `/sys/kernel/security/lsm`, `.../apparmor/profiles` | `decoy_apparmor.read_exposure_lsm`, `exposure_lsm_refusal` | `lsm_apparmor_disabled`, `lsm_profiles_unreadable`, `lsm_profiles_absent`, `lsm_profiles_not_enforced`, `lsm_profile_child_present` |
| P4 | §5 C1 5: no ruleset loader enabled or active | `UnitFileState`, `ActiveState` of `nftables.service`, `firewalld.service`, `netfilter-persistent.service` (bus) | the bus reads of §4.5, `host_firewall_refusal` | `host_firewall_unreadable`, `host_firewall_enabled`, `host_firewall_active` |
| P5 | §6.3 G6 item (a): no definition-less running unit, no leftovers | `LoadState`, `UnitFileState`, `ActiveState` of the three units (bus); the entries of `/run/netns`; the links (`RTM_GETLINK`) | the bus reads of §4.5, `decoy_residue.read_netns`, `netlink.read_links` (names only), `decoy_residue.exposure_residue_departures` without the table (§4.4) | `exposure_state_unreadable`, `exposure_unit_masked_running`, `exposure_leftovers_present` |
| P6 | §5 C1 3: a v3 proposal with a valid scope, its roles resolved to this boot's names | `inputs.evidence` (payload, current inventory) | `fabric_boundary.restore_commissioning_inputs`, `deception_scope_assignments`, `decoy_scope.decode_deception_scope`, `exposure_interfaces.resolve_role_interfaces` | `deception_scope_absent` (new: a v2 proposal), `deception_scope_refused` (new), then `role_evidence_unavailable`, `role_scope_mismatch`, `role_inventory_changed`, `role_interface_unresolved`, `role_interface_ambiguous`, `role_interface_name_refused` |
| P7 | §5 C1 6, forwarding half (R1, R2, R5) | `/proc/sys/net/ipv{4,6}/conf`; the IPv4 rules and the routes of `main` (`RTM_GETRULE`, `RTM_GETROUTE` dumps, §4.4); P6's names | `decoy_reachability.read_sysctls`, the netlink dumps, `pass_reachability_departures`, `reachability_refusal` | `forwarding_unreadable` alone, or the first of `forwarding_ingress_off`, `forwarding_role_on`, `forwarding_host_wide`, `forwarding_other_on`, `forwarding_ipv6_on`, `proxy_arp_on`, `ingress_containment_absent`, `decoy_prefix_routed` |
| P8 | grant §4.3: the scope file renders | P6's `DeceptionScope` and ingress names | `decoy_scope.render_scope_file`, `parse_scope_file` (round trip) | `decoy_scope_unrenderable` (new) |
| P9 | §5 C1 2: the generation's exposure section describes this node | the generation's section (§5.1); the unit, watch and profile files measured now; P8's bytes | `exposure_generation.measure_exposure_section_inputs`, `verify_exposure_section` | `exposure_generation_absent` (new: no section), `exposure_files_unreadable` (new), `exposure_generation_differs` (new) |
| P10 | §5.1 V2: the approval's exposure fields are this pass's | the verified v3's `exposure_scope_digest`, `exposure_prefix_count`, `exposure_ingress_count`; the section's `scope_digest`; P8's file | equality, in the pass | `exposure_approval_binding_differs` (new) |
| P11 | §5 C1 4, second half: the loaded units name their profiles; the kernel's policy is the compiled one | `LoadState` and `AppArmorProfile` of the four units (bus); `.../apparmor/policy/profiles/*/raw_sha256`; the section's `apparmor_policy_hashes` | `decoy_apparmor.loaded_unit_profile_refusal`, `read_policy_hashes`, `policy_hash_refusal` | `lsm_unit_profile_differs`, `lsm_policy_unverifiable`, `lsm_policy_differs` |

Why this order:

- **P1** first: it costs nothing, and without it nothing else matters. It
  should never fail (a v2 approval cannot name the units); it is there so
  that a later change to the decoders cannot make a v2 lease carry the tier.
- **P2 to P5** are host facts that need no commissioning material: single
  `/proc` and `/sys` files, then the bus, then `/run/netns` and one
  netlink dump. A host that is not a
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
- **P10 after P8 and P9** (review of #301, finding 2): it compares the
  approval's exposure fields with what P8 rendered and P9 verified. It is a
  stage here, not a check in the v3 verifier: in the verifier a difference
  would refuse the approval, so `lease=None` and every tier withheld; here
  it withholds the three units only. The verifier checks the fields' shape
  alone (types, the digest's form, the counts' bounds of grant §4.2).
- **P11 last**: its expected hashes come from the section P9 verified.

The cost of a slow stage is one boot's withheld tier, never a
grant; there is no retry loop
([reachability §6](deception-exposure-reachability.md#6-the-pass-condition-g6-implemented-not-wired),
"When the pass runs relative to networkd").

### 4.4 What the controller can read (cross-review finding H1)

The parts were written against the verify unit's inputs: `ip -j` output for
the rules, the routes and the links, and `nft -j list tables` for the
table. The controller has neither means. It starts no process (only
`decoy_network.py` may spawn one), and its bounding set is
`CAP_DAC_READ_SEARCH` alone, while an nftables listing needs
`CAP_NET_ADMIN`. What it can read is `/proc/sys/net`, the bus,
`/sys/kernel/security`, `/etc/apparmor.d`, `/run/azazel-activation`, and
route netlink without a capability (§2). So each input is placed:

| input | option | idea | verdict |
| --- | --- | --- | --- |
| (a) the table `inet azazel_decoy` (P5) | A1 | the controller does not read it; the residue judgement takes no table listing and judges the namespace, the veth end and the bridge; a leftover table alone is the helper's to refuse (`HELPER_ABSENT` fails its start closed) | **done** (this PR; owner decision Q-A = A1). A1 **removes a judgement** from the pass; it is not a narrowing default. §10 item 5 states what is lost |
| | A2 | a verify-type one-shot with `CAP_NET_ADMIN`, ordered before the controller, records "no table" for this boot and the pass reads the record | a fourth `CAP_NET_ADMIN` holder and a new unit and record for one bit the helper already checks; **not chosen** |
| | A3 | `CAP_NET_ADMIN` for the controller | a new privilege in the one root daemon that can unmask units; **rejected** |
| (b) the rules and routes (P7) | B1 | read-only route netlink dumps, `RTM_GETRULE` (IPv4) and `RTM_GETROUTE` (table 254, `main`), in a **new module of their own** (proposed `exposure_route_dump`), not in `netlink.py`; its parser yields the dictionaries `ip -j` prints, so `_rules_exact` and `_routes_clear` stay the one comparison; no capability | **recommended; owner decision** (§9 Q-N): it is the netlink parser G2 avoided |
| | B2 | let the controller spawn `/usr/bin/ip` with fixed argument lists only | a new permission (a second spawning module, an executable in the controller's closure); **owner decision** (§9 Q-N) |
| (c) the links (P5) | | `netlink.read_links`, names only (the existing `RTM_GETLINK` dump) | no change to `netlink.py` |
| (d) the namespaces (P5) | C1 | read `/run/netns` directly (`decoy_residue.read_netns`) | **done** (#302) |

**Why a new module for B1** (review of #301, finding 4). `netlink.py` is the
commissioning reader of permanent MACs: its docstring and
`tests/unit/test_runtime_netlink.py` pin it to one request, and it drops
the routes and addresses that commissioning §4 forbids it to use. Widening
it would put the default route inside the module whose job is not to know
it. B1 therefore lives in its own module, imported only by the pass, with a
boundary test both ways: the route dump imports nothing of commissioning's
role judgement (`netlink`, `exposure_interfaces`, `fabric_boundary`,
`commissioning_evidence`), and none of those imports it. The links P5 needs
come from `netlink.read_links` unchanged (the pass reads names, no MAC).

**What B1's parser must hold.**

- **The same dictionaries.** For a rule: `priority`, `src`/`srclen`,
  `dst`/`dstlen`, `iif` (from `FRA_IFNAME`), `table`, `action`,
  `suppress_prefixlen`, and every selector `ip -j` prints. Table numbers are
  named as `ip` names them by default: 253 `default`, 254 `main`, 255
  `local`, any other number as a number; `/etc/iproute2/rt_tables` is never
  read (the output would then depend on an editable file). `protocol` is
  parsed and dropped, as `_rules_exact` ignores it.
- **Closed on the unknown.** A rule attribute the parser does not translate
  makes the whole dump unreadable (`forwarding_unreadable`), never a key
  that drops out of the comparison: the flow label of §10 item 1 is exactly
  such an attribute.
- **Routes of table 254 only.** A route's table is `RTA_TABLE` when present,
  else the header's; anything but 254 is skipped. A route inside
  `10.255.196.0/24` is reduced to `dst`, `dev` (the output link's name from
  the link dump), `gateway`, `type` and, for `RTA_MULTIPATH`, `nexthops`
  (one entry per hop, which `_routes_clear` refuses as it refuses a
  gateway); a route there with a nexthop object (`RTA_NH_ID`) or an
  attribute the parser does not know is unreadable. A route outside the /24
  is reduced to its destination and prefix length, all `_routes_clear`
  needs of it.
- **A link without a name** (`LinkRecord.name` None) makes the link list
  unreadable for P5 (`exposure_state_unreadable`), and makes a route whose
  output link it is unreadable for P7 (`forwarding_unreadable`).
- **Fixtures.** The VM's `ip -j` dumps of reachability §11 item 8 and the
  raw netlink messages recorded on the same host; a test runs both readers
  over them and requires equal output.

**The parts' inputs change** (review of #301, finding 5). Each part keeps
its judgement; only what it is handed changes:

| part | today's input | G6 |
| --- | --- | --- |
| `decoy_residue.exposure_residue_departures` | `netns` from `read_netns` (#302); `links` and `tables` as `(status, ip/nft JSON)` | **done** (this PR): `tables` removed (A1); `links` a tuple of names from `netlink.read_links` (`tuple(r.name for r in records)`), None for a failed dump; a None name or a failed dump is `exposure_state_unreadable` |
| `decoy_reachability.pass_reachability_departures` | `rules`, `routes` as `(status, ip -j JSON bytes)` | lists of dictionaries from B1, or a failed dump (under B2, unchanged) |
| `decoy_reachability._rules_exact`, `_routes_clear` | lists of dictionaries | unchanged: the one comparison of the pass and the verify |
| `decoy_watch` (the verify) | `ip -j` through the helper's plan, `parse_json_list` | unchanged |
| `decoy_apparmor.loaded_unit_profile_refusal` | `LoadState`, `AppArmorProfile` | unchanged; fed by §4.5 |
| `exposure_withholding.host_firewall_refusal` | file state and active state, None when neither exists | unchanged; fed by §4.5 |
| `exposure_generation` | the section has `apparmor_policy_hashes` (implemented, #303), which nothing fills | `generation-publish` fills it from the installer's record (§5.2) |
| `activation_approval_v3` | the v2 fields and V2's three fields (shape only) under `ACTIVATION_EXPOSURE`, the purpose of §9 Q-C (implemented, this PR; not wired) | its own policy type (§5.1); the pass compares the three fields (P10) |
| `activation_unit_files.measure_scoped_unit_files` | scope inside `ACTIVATION_UNIT_ALLOWLIST` | scope inside the observe scope, the allowlist without the exposure units (§5.2) |

### 4.5 The bus reads G6 adds (cross-review finding M3)

Read-only, through the controller's existing session; no write verb accepts
any unit below that it does not already govern. `LoadUnit` is never called
(it would load a unit).

| read | units | value | maps to None |
| --- | --- | --- | --- |
| `GetUnit`, then the Unit interface's `LoadState` | the three exposure units and the verify unit (P5, P11) | string | `org.freedesktop.systemd1.NoSuchUnit` from `GetUnit` |
| `GetUnitFileState` | `nftables.service`, `firewalld.service`, `netfilter-persistent.service` (P4); the three exposure units (P5) | string, as given (`"disabled"` observed) | `org.freedesktop.DBus.Error.FileNotFound` from `GetUnitFileState` |
| `GetUnit`, then the Unit interface's `ActiveState` | the same six | string, as given | `org.freedesktop.systemd1.NoSuchUnit` from `GetUnit` |
| `GetUnit`, then the Service interface's `AppArmorProfile` | the four units of `DECOY_APPARMOR_PROFILES`, the verify unit included (P11) | `(bs)`, kept as a pair (VM: a masked unit reads `false ""`) | `org.freedesktop.systemd1.NoSuchUnit` from `GetUnit` |

These two error names, each from the one call named, are the **whole set**
that maps to None (observed on the VM, §2; review of #301, finding 7). Any
other error, `NoSuchUnit` from `GetUnitFileState` included, a reply of
another type, or a value outside the closed sets of the parts is unreadable
(`host_firewall_unreadable`, `exposure_state_unreadable`,
`lsm_unit_profile_differs`), never None. A firewall unit is None as a whole
only when both its reads are None (`host_firewall_refusal`'s rule). A
masked unit's `false ""` passes `loaded_unit_profile_refusal` because that
function accepts `masked` without reading the profile; a loaded, unmasked
unit must read `(false, <its profile>)`. The three firewall units are not
governed, so the reader's unit allowlist gains them for these reads only.

### 4.6 What the pass records

`activation.inputs_incomplete` gains `observed_inputs.exposure_evidence`, a
fixed label: `not_attempted`, `not_in_scope`, `established`, or
`withheld` with `exposure_stage` (`P1` to `P11`) and the code (no phrase,
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
- **Two scopes, so the tier cannot withhold the rest** (review of #301,
  finding 1). Widening the allowlist must not put the exposure unit files
  into step 6, the generation producer inside `complete`: a one-byte change
  to an exposure unit file would then refuse the generation and withhold
  every tier. So the **observe scope**, the policy's units without the three
  exposure units, is what step 6 measures and what the generation's body
  (`units`, `unit_files`) lists; `measure_scoped_unit_files` takes its bound
  from a constant of its own (the allowlist without the exposure units), no
  longer from `ACTIVATION_UNIT_ALLOWLIST`. The exposure unit files are
  measured only by P9, inside the section, where a departure withholds the
  tier alone. See §5.2 for the generation's side.

**A dedicated purpose (grant §9 note).** Recommended: a new
`ApprovalPurpose.ACTIVATION_EXPOSURE` (`"activation-exposure"`), the only
purpose under which a v3 approval verifies. What it adds: the payload's
`schema` already keeps a v2 signature from verifying as v3, so the purpose
is not what stops cross-schema reuse. It separates the **act**: an operator
signing an ordinary activation cannot produce an exposure approval by the
same command, the signer's refusal rules for exposure live in one place, and
the trust store can later restrict which enrolled keys may sign exposure
without a new schema. The cost is one enum value and one transcript label. The G6-prep
verifier used `ACTIVATION`, the purpose of v2; no v3 approval had been
signed yet, so this was the cheapest moment to change it: afterwards every
signed v3 would have had to be signed again. Owner decision Q-C (§9).
**Done** (this PR, #196): `ApprovalPurpose.ACTIVATION_EXPOSURE` exists and
is the only purpose `verify_activation_approval_v3` accepts; a v3 signed
under `ACTIVATION` is refused, and v2's verifier refuses the new purpose.
The signer does not offer it yet (`--purpose activation-exposure` is
refused until G6 adds the rules below), and nothing is wired.

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
| V2 | v3 gains `exposure_scope_digest`, `exposure_prefix_count`, `exposure_ingress_count`; the verifier checks their shape only, and the pass compares them with the generation's section and P8's rendering in stage P10 (§4.3), so a difference withholds the tier and not the lease; the signer prints them | the operator signs exactly what they read; a change to the not yet wired v3 decoder |

**Recommended: V2.** It only adds a binding, and the decoder is not wired
yet, so no signed document exists to migrate. **Done in the decoder** (this
PR, #196; owner decision Q-V): the three fields are required in every v3,
`exposure_scope_digest` in the section's `scope_digest` form (`sha256:` and
64 lowercase hex digits), the counts integers from 1 to
`decoy_scope.MAX_PREFIXES` and `decoy_scope.MAX_INGRESS`; the verifier
checks their shape only and returns them for P10. The signer printing them
is G6's.

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
already decode it. In v2 the body's `units` and `unit_files` hold the
observe scope only (§5.1, "Two scopes"); the three exposure units are named
by the section, never by the body, so step 6 never measures them.

**Step 6b stays as it is.** The loaded-unit check (`systemd_loaded_units`,
inside `complete`) already covers every grantable unit, the exposure units
included, since #196 P1. It is **not** moved into the tier's stages: it
guards what the manager loaded, and an exposure unit loaded without its
marker condition or its controller ordering would start after `READY`
whether or not the tier is granted, so that departure endangers the whole
node and rightly withholds everything (#251 H-1). A change to an exposure
unit **file** that the manager has not loaded is P9's and withholds the tier
alone; once loaded at the next boot, a file without its guards is 6b's.

**Content.** `EXPOSURE_SECTION_KEYS` holds `apparmor_policy_hashes`
(implemented by #303, `exposure_generation`): exactly the four profile
names, each mapped to the SHA-256 of the installer's compiled output
(below) as **64 lowercase hex digits with no prefix**, the same form as the
content of the kernel's `raw_sha256` without its newline. The section is
then: the three exposure unit files, the three watch unit files, the four
profile files (each `sha256:<hex>`, digests of files), the scope digest
(`sha256:<hex>`) and the four policy hashes (bare hex, compared with the
kernel). `build_exposure_section` refuses a hash in any other form (a
`sha256:` prefix, upper case, another length) as
`exposure_section_unverifiable`.

**The installer records the compiled hash** (grant §7, "Left to G6").
**Implemented (record only; the reader is G6's)** by #196 G6 preparation K:
`packaging/install.sh` runs `tools/record_apparmor_compiled.py` (in the
offline bundle), and `runtime/.../apparmor_compiled.py`
(`decode_apparmor_compiled`) is the record's strict decoder, applying the
section's rule to the hashes; it is called by nothing but the tool, which
checks its own output with it before the rename. `generation-publish` and
the pass do not read the record in this build
(`tests/unit/test_apparmor_compiled_record.py`, and the shared table of
unwired parts, `tests/unit/test_g6_unwired.py`: `apparmor_compiled` may be
imported by the tool alone, its names appear nowhere else, and the
poisoned pass replaces `decode_apparmor_compiled` too). Two choices made in the
implementation, against the proposal below: the record is compiled right
after the profiles are placed, in the service-manager half, and the
earlier `--skip-kernel-load` check before anything is written stays as it
is (on the test container, parser 4.1.0, compiling the repository's file
and the placed copy gave the same output); and the record is `0644`, not
`0600`: it holds the hashes of compiled public policy, no secret, its
directory is root's `0700` anyway, and what matters to its reader is that
only root may write it. A run without the service manager, or one that
fails **before the rename**, leaves an earlier record as it was (and no
temporary file); once renamed the record is checked and in place, so a
failed fsync of the directory after it is a warning, not a refusal. A
stale record can only make the pass withhold as `lsm_policy_differs`
(closed). `parser_version` never refuses the install: the version line is
normalized (each character outside printable ASCII becomes `?`, at most
255 characters, `unknown` when empty or not read), and the decoder accepts
exactly what that normalization leaves unchanged. A failed compilation
shows the parser's first error lines, printable ASCII only. **Checked on
the VM** (Debian 13, parser 4.1.0; a mechanism check, not hardware
evidence): the four values the installer recorded equalled the kernel's
`raw_sha256` of the four profiles after `apparmor.service` loaded them.

1. After placing the four profiles in `/etc/apparmor.d` (root, `0644`),
   with the service manager only, for each profile:
   `apparmor_parser -Q -o <private temporary file> /etc/apparmor.d/<name>`,
   with no other flag, so `/etc/apparmor/parser.conf` applies as it does to
   `apparmor.service`'s load (the form observed equal to the kernel's
   `raw_sha256`, grant §11).
2. The SHA-256 of each output goes into one record,
   `/etc/azazel/activation/apparmor-compiled.json`: canonical JSON (sorted
   keys, no spaces, one trailing newline) with exactly three keys:
   `"contract"` (proposed `"azazel-nexus/apparmor-compiled/v1"`),
   `"apparmor_policy_hashes"`, an object of exactly the four profile names,
   each to 64 lowercase hex digits with no prefix (the section's field of
   the same name, so `generation-publish` copies it unchanged), and
   `"parser_version"`, the parser's version line, for diagnosis only and
   never compared. For example (hashes shortened):
   `{"apparmor_policy_hashes":{"azazel-decoy-netd":"3f…","azazel-decoy-nsd":"a1…","azazel-decoy-verify":"9c…","azazel-decoyd":"07…"},"contract":"azazel-nexus/apparmor-compiled/v1","parser_version":"AppArmor parser version 4.1.0"}`.
   A record with another key set, another name set or a hash in another
   form refuses `generation-publish`. Written as a
   private temporary file in the same directory, fsynced, renamed, the
   directory fsynced (root `0644`, as implemented, in the root `0700`
   directory the installer already creates). A failed compilation refuses
   the install, as today.
3. A `DESTDIR` or `--without-service-manager` run writes no record; then
   `generation-publish` cannot build an exposure generation and says so.

The record is an input of `generation-publish`, never of the pass. The
pass trusts only what the operator signed: the section in the generation.

**What `scope_digest` is (cross-review finding L3).** Grant §4.4 item 5 said "the decoded
scope" (its wording is corrected with this document); what `exposure_generation` digests is the **rendered scope file's
bytes** (`decoy_scope.parse_scope_file(...).scope_digest`), the file that
carries this boot's ingress names. So the publisher cannot digest the
proposal's section: it must render exactly the file the pass will render,
with the same resolution.

**`az-activation generation-publish`**, when the policy names the tier:
collects the verified commissioning evidence (as now), decodes the
proposal's `deception_scope`, resolves the roles with
`resolve_role_interfaces` over the same evidence and this boot's inventory,
and renders the file with `render_scope_file` (P6 and P8, the same
functions the pass calls, in memory), measures the files with
`measure_exposure_section_inputs`, reads the compiled record (root's, one
link, no link followed, bounded), builds the section, and prints, before
the typed confirmation, the scope digest, the number of prefixes and
ingress interfaces and the four policy hashes. `request` and `install`
re-measure and re-render the same way.

**The pass compares** (P9, P11): `verify_exposure_section` with the files
measured now and P8's bytes; then `policy_hash_refusal(read_policy_hashes(),
expected)` with `expected` the section's `apparmor_policy_hashes` as
`exposure_generation.expected_policy_hashes` gives them, bare hex compared
as they are with the kernel's `raw_sha256` (no prefix to strip). A kernel that loaded another compilation (a changed
include, another file defining the same name, another parser, other kernel
features) differs and withholds as `lsm_policy_differs` until the exposure
is installed again, a new generation published and a new approval signed.
That is the closed side, and §10 lists what is still *inferred* about it.

### 5.3 Writing the scope file

The pass writes `/run/azazel-activation/decoy-scope.json` (grant §4.3), and
under D2 (§6) the digest file `/run/azazel-activation/decoy-scope.digest`,
only when the decision granted the three exposure units and the tripwire
(§6) accepted it. Both are "the scope files" below; every step applies to
both.

1. **Removal first, before the markers.** At the start of the pass,
   `reset_grant_markers` removes the scope files (and any temporary file of
   their fixed names) **before** it removes `granted/`, so a failure while
   removing the markers never leaves a scope file behind; a directory or
   other non-regular object at either name refuses, as an unexpected
   `granted/` does (`activation.grant_markers_unclean`, then the pass fails
   after narrowing). So a pass that withholds the tier leaves no scope file,
   and a helper started later in the boot fails at `LoadCredential=`
   (closed).
2. **Order in `_run_once`.** After the decision and the tripwire, after the
   high water is raised (as today, the floors follow the verified approval
   and are not lowered by a later failure, the same as for an unwritable
   marker), then the scope files, then the markers, then the record.
3. **Write.** Open `/run/azazel-activation` without following a link and
   require it root-owned and not group or other writable (the markers'
   rule). For each file: create `<name>.tmp` with
   `O_CREAT|O_EXCL|O_NOFOLLOW` and mode `0600`, `fchmod` it to `0600`
   (the umask cannot widen it, and an inherited mode cannot either), write
   the bytes (P8's file; the digest file holds `sha256:<hex>\n`), `fsync`,
   rename onto the name relative to the directory descriptor; then `fsync`
   the directory. The scope file first, the digest file second.
4. **Read back.** Each file as read under the helper's rules (regular, one
   link, root's, `0600`, bounded): `parse_scope_file` over the scope file,
   its digest equal to the evidence's `scope_digest`; the digest file equal
   to that digest, byte for byte.
5. **Then the markers**, for exactly the granted units, as now.

Any failure in 3 or 4 is recorded (`activation.decoy_scope_unwritten`) and
answered like an unwritable marker: the emergency narrowing removes the
scope files and the markers and masks every governed unit. The emergency
narrowing removes the scope files in every case, in a `finally`, so an
exception while it removes the markers does not leave them.

**A second pass in the same boot** (the controller re-run by hand, or a
rehearsal copy that pulls it in; grant §11, "rehearsal rule"). Its step 1
removes the scope files while the units may run. The helper and the decoy
hold their credential copies for their run, but the verify unit is a
one-shot started again every 10 s, and each start loads its credential from
the source: with the source gone the start fails (`243/CREDENTIALS`), its
`OnFailure=` starts the trip target and the three units stop within one
period (grant §11 item 3). That is the intended, closed outcome; the
operator re-grants by rebooting. A second pass that grants the tier again
writes the files again before the next verify start, and nothing trips.

**`rolled_back` and the tier.** A pass rolls back when any unit's
`unmask_and_enable` fails: it masks again **everything** it widened,
SUPPORTING and edge-core included, as today. With the tier grantable,
three more units can fail that way, and such a failure also withdraws the
other tiers' grants for that boot. The scope files are not written on a
rolled-back pass, and the tripwire requires `rolled_back` false for an
exposure grant (§6).

## 6. The allowlist, the grantable set and the tripwire

| item | today | G6 |
| --- | --- | --- |
| `ACTIVATION_UNIT_ALLOWLIST` | six units | six plus the three exposure units (three or none in a policy) |
| `POLICY_UNIT_SCOPE` | `GRANTABLE_UNITS` minus the three | `GRANTABLE_UNITS` |
| `GRANTABLE_UNITS` | holds the three | unchanged; the watch's three units stay out (grant §6.3: no marker, no allowlist) |
| `write_grant_markers` | three or none | unchanged |
| `observe-baseline-generation/v1` | scope inside the allowlist | refuses the exposure units explicitly; v2 required for them (§5.2) |
| step 6, `measure_scoped_unit_files` | the policy's units, inside the allowlist | the observe scope only, bound by a constant of its own (§5.1) |
| step 6b, `systemd_loaded_units` | every grantable unit | unchanged (§5.2) |
| `_withholding_reason` | `isolation_evidence_absent` always | L1 to L5 (§4.2) |
| `activate` | no exposure input | `exposure=` (default None, which withholds) |

**The tripwire** in `_run_once` changes from "any exposure grant narrows" to
"an exposure grant narrows unless all of these hold":

- all three are granted, or none (a partial grant narrows);
- the lease names all three, and `inputs.approval` is exactly
  `ActivationApprovalV3`;
- `inputs.exposure` is an `ExposureEvidence` with `refusal` None, `stages`
  exactly `P1` to `P11`, its `generation_digest` the outcome's generation,
  and a `scope_digest`;
- the pass rolled nothing back;
- (after writing) the scope files read back carry that digest.

Any other exposure grant removes the markers and the scope files, masks
every governed unit and raises, as today. The existing checks (lease and
health, scope, edge-core's evidence) are unchanged.

**The decoy and the record (cross-review finding M4).** Grant §9's G6 row asks that an
isolation record whose `scope_digest` is `none` be refused, and that a
granted decoy require the digest of the scope the pass rendered. Today
`decoy_isolation` accepts `none` and `require_isolation_for_decoy` compares
the digest with nothing. G6 makes the decoy refuse `none` and compare the
record's digest with the pass's. The decoy must then learn that digest; two
ways:

| option | idea | unit file bytes | generation |
| --- | --- | --- | --- |
| D1 | `azazel-decoyd.service` gains `LoadCredential=decoy-scope:/run/azazel-activation/decoy-scope.json`; the decoy reads its own credential path by the helper's rules and digests the bytes | one line added to the decoy's rendered unit; the hardening check that keeps the credential to the helper and the verify unit admits the decoy; its AppArmor profile gains a read of its credential path | the decoy's unit file digest and its profile file digest change, and with the profile its compiled hash |
| D2 | the pass also writes `/run/azazel-activation/decoy-scope.digest` (`sha256:<hex>\n`, root `0600`, written, read back and removed with the scope file, §5.3), delivered as `LoadCredential=decoy-scope-digest:/run/azazel-activation/decoy-scope.digest`; the decoy compares the record with it | one line added to the decoy's rendered unit; a new credential name the hardening check admits for the decoy only; the profile gains a read of that path | as D1; and the pass writes, resets and reads back a second file |

Either way a missing source fails the decoy's start (closed), the decoy
reads an immutable snapshot for its whole run, and the change lands in G6
together with the first exposure generation, so no signed generation has
to be replaced. **Recommended: D2.** The decoy is the least privileged of
the units and the one that talks to peers; D1 would hand it the approved
prefixes and the ingress names, which it never needs, while D2 hands it
only a digest. The cost is one more file in the pass's write and reset
(§5.3 applies to both files). Under either option **the decoy's unit gains
a `LoadCredential=` line**: today only the helper and the verify unit hold
one, and the hardening check that keeps it so is widened for the decoy
alone (§9 Q-D).

## 7. Tests G6 carries

Unit tests (fake manager, temporary root, keys generated per test, in the
style of `tests/unit/test_runtime_activation_pass.py`):

1. **The order.** For each stage P1 to P11, a pass in which only that stage
   fails withholds exactly the three exposure units with that stage's first
   code, grants the SUPPORTING units and edge-core as before, writes no
   scope file and no exposure marker, and does not call any later stage
   (each later part replaced by one that fails when called, as
   `tests/unit/test_g6_unwired.py` does today). Also: an exception in
   any stage gives `exposure_stage_unreadable` and the other tiers
   unchanged; and **an exposure unit file changed by one byte withholds the
   tier alone** (P9 `exposure_generation_differs`), the SUPPORTING units and
   edge-core still granted, step 6 not refused (finding 1).
2. **The library.** L1 to L5 each withhold with their code; `activate`
   without `exposure=` withholds as `exposure_evidence_absent`; evidence for
   another generation is `exposure_evidence_mismatch`; an exposure verdict
   never differs between the three units; `ExposureEvidence` refuses a
   refusal-free value without a scope digest or without every stage, and a
   value whose stages are not a prefix of `P1` to `P11`.
3. **A full grant.** Every stage holds: the three are granted, the scope
   file is written `0600` root before the markers, its bytes equal P8's
   rendering, the markers are the granted units, the record carries
   `exposure_evidence: established`.
4. **Approval.** v2 and v3 from one pair, dispatched by schema; v3 signed
   under `activation` refused when the purpose is dedicated; v2 naming an
   exposure unit refused; v3 naming one or two refused; v3 without the three
   refused by the signer; a v3 with exposure fields (V2) of the wrong shape
   refused by the verifier, and one whose fields differ from the section
   accepted by the verifier and withheld by P10
   (`exposure_approval_binding_differs`) with the other tiers granted; the
   floors shared and raised by either.
5. **Policy.** A policy naming one or two exposure units refused; naming the
   three accepted; a v2 approval still verifies under a policy naming the
   three.
6. **Generation.** v1 refusing the exposure units; v2 requiring the section
   exactly with them and its body never naming them;
   `measure_scoped_unit_files` refusing an exposure unit; each section digest
   changed refused with its label;
   the compiled record absent, unprotected or malformed refuses
   `generation-publish`.
7. **Installer.** With a stub `apparmor_parser`, the record holds the
   SHA-256 of what `-Q -o` wrote, is written atomically and refuses on a
   failed compilation; no record under `DESTDIR`.
8. **Scope files.** Removed at the start of every pass, before `granted/`
   (also a stale temporary), and in the emergency narrowing even when the
   marker removal raises; a non-regular object at either name refuses the
   pass; written only on a grant, after the high water and before the
   markers, `0600` whatever the umask; a failed write or read back narrows
   everything and removes markers and files; never written when the tier is
   withheld or the pass rolled back; the decoy refusing a record whose
   `scope_digest` is `none` or differs from its credential.
9. **Tripwire.** Each condition of §6 violated alone (a partial grant, a v2
   approval, evidence with a refusal, a stage missing, another generation,
   no scope digest, a rolled-back pass, a read back that differs) narrows
   everything.
10. **Readers.** The bus reads of §4.5: None only for
    `org.freedesktop.DBus.Error.FileNotFound` from `GetUnitFileState` and
    `org.freedesktop.systemd1.NoSuchUnit` from `GetUnit`, every other error
    (that `NoSuchUnit` from `GetUnitFileState` included) unreadable;
    `AppArmorProfile` as `(bs)`, a masked unit's `false ""` accepted. Under
    B1: the rule and route dumps yield, over the recorded objects, exactly
    what the verify's `ip -j` reading yields; table numbers named as `ip`
    names them without `rt_tables`; an unknown rule attribute, a route in the
    /24 with `RTA_NH_ID` or an unknown attribute, and a link without a name
    unreadable; multipath routes in the /24 carry `nexthops`. The controller
    still spawns nothing (`SPAWN_EXEMPT` unchanged under B1); the residue
    judgement without a table listing (A1).
11. **Boundaries.** The library still imports no runtime module; the
    controller's unit file gains no capability, address family or writable
    path (only, if §10 item 3 is decided, an `After=`); the import-closure
    pins of the pass list exactly the parts above; the route dump and
    commissioning's role judgement (`netlink`, `exposure_interfaces`,
    `fabric_boundary`, `commissioning_evidence`) import nothing of each
    other; `netlink.py` keeps its one request; the tests of the G6
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
one: at the end of the run its seed is destroyed, its enrolment is removed
from the VM's trust store, and the VM image is discarded, never reused or
copied as a base for a node.

**No back door in the production signer.** The one row below that needs a
v3 signed under `activation` (to show the dedicated purpose refuses it) is
signed by a test-only script kept outside the package and the installed
tree, which calls `operator_trust.approval_message` with the rehearsal key;
`tools/operator_sign.py` itself keeps refusing v3 under `activation`.

**Not checked here.** The flow label (§10 item 1) is checked on the target
host's kernel and recorded with `HG-06`; a VM result is not mixed into that
record.

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
   | a watch unit, an exposure unit or a profile file edited after publishing (no `daemon-reload`) | `exposure_generation_differs` (P9); the other tiers granted |
   | a v3 whose exposure fields name another scope digest (signed by the test-only script) | `exposure_approval_binding_differs` (P10); the other tiers granted |
   | a policy without the tier, with the v3 approval | the approval refused at the scope; nothing granted (all-or-nothing producers) |
   | a v3 signed under `activation` by the test-only script (Q-C adopted) | the approval refused; nothing granted |
   | an include of a profile (`tunables/global`) changed, then a reboot | `lsm_policy_differs` (P11) |
   | the `apparmor` package reinstalled at another version, if one is available | record what P11 says (§10 item 2) |

6. **Restore** each change and reboot: the tier is granted again (boot 1)
   and starts (boot 2).
7. **Inferred items of §2** recorded as observed: the netlink dumps, the
   `/run/netns` read and the bus reads under the controller's sandbox; the
   rules and routes read by the pass equal, key for key, what the verify's
   `ip -j` prints on the same host; the kernel hash after a reboot through
   `apparmor.service`'s cache; the controller's timing against networkd
   (§10 item 3).
8. **A second pass in the same boot**, once, deliberately, at the end: the
   verify's next start fails on the missing credential and the trip stops
   the three units (§5.3).
9. **Clean up**: destroy the rehearsal seed, remove its enrolment, discard
   the VM image.

## 9. Owner decisions before G6

**Answered 2026-10-23** for Q-B to Q-E below, each as recommended: **B0**
(no stop), **Q-C yes** (`ACTIVATION_EXPOSURE`), **Q-N B1** (the route
dump module), **V2**, **D2**, **A1**, and exclusivity **as a withhold**
(Q-E). Q-R6 is still open, and G6 is still not merged before it and G5.
The questions are kept below as they were asked.

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
- **Q-C. A dedicated `ApprovalPurpose`** (§5.1; cross-review finding L4). The v3 verifier as
  built signs under `ACTIVATION`, the same purpose as v2. No v3 approval has
  been signed yet, so changing it now costs nothing to migrate; after the
  first signed v3 it costs a re-signing. Recommended: yes,
  `ACTIVATION_EXPOSURE`. Declined, v3 verifies under `ACTIVATION`.
- **Q-N. How the controller reads the rules and routes** (§4.4; cross-review
  finding H1 (b), review of #301 finding 4). Do you approve **B1**: a new
  module of read-only `RTM_GETRULE` and `RTM_GETROUTE` dumps with Nexus's own
  parser, outside `netlink.py`? It needs no new permission and no
  capability, but it is the netlink parser G2 chose to avoid, and its
  parser becomes part of K1's containment check. If B1 is declined, the
  alternative is **B2**, a new permission for the controller to spawn
  `/usr/bin/ip` with fixed argument lists. Recommended: B1.

Also for the owner, with recommended defaults that only narrow:

- **Q-V. The exposure fields in v3** (§5.1): recommended V2.
- **Q-D. How the decoy learns the scope digest** (§6; cross-review finding
  M4): recommended D2. Either option adds a `LoadCredential=` line to
  `azazel-decoyd.service`, which holds none today, and widens the hardening
  check that keeps the credential to the helper and the verify unit.
- **Q-A. The table at the pass** (§4.4; cross-review finding H1 (a)):
  recommended A1. A1 removes a judgement rather than narrowing (§10 item 5).
- **Q-E. Exclusivity as a withhold** (§4.2 L2) rather than refusing the
  controller's construction: recommended, so the other tiers keep their
  verdicts. That means an enforcement unit in the governed set **stays
  granted** (on its own conditions) while the exposure tier is withheld;
  refusing the construction would withhold the enforcement unit too.

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
5. **The table at the pass** (§4.4 A1): the pass judges leftovers without
   the table and relies on the helper's `HELPER_ABSENT`. A leftover table
   with no leftover bridge therefore passes P5, the tier is granted, and the
   helper's start later in the same boot fails on it: closed, but noticed at
   the helper and not at the pass. The operator's procedure for a crash
   already removes it (reachability §8 item 4).
6. **The decoy and the pass's scope** are decided in §6 (cross-review finding M4); what stays
   open is only the VM check that the credential reaches the decoy under
   its profile.
7. **Evidence is a statement, not a proof.** `ExposureEvidence`, like
   `EdgeBaselineState`, could be constructed by any caller of `activate`.
   The production caller is the pass, and the tripwire re-checks the
   evidence and the scope file after the decision. A mint like
   `ActivationAuthorization`'s is not proposed: it would protect against
   code in the same process, which can already call the unit manager.
8. **The bus answers** were read on a VM (§2): `(bs)` for
   `AppArmorProfile`, `FileNotFound` and `NoSuchUnit` as the two None cases
   (§4.5). Still to see on the G6 branch: the same answers through the
   controller's own session and allowlist (§8 step 7).
9. **What a refusal costs the operator.** Every change to the exposure
   files, profiles, includes or the parser needs a new generation and a new
   v3 signature, as a changed unit file does for the observe baseline.
   Intended; [operations](operations.md#deception-lite-decoy-network-196)
   gains the procedure when G6 lands.
