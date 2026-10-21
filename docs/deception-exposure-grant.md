# Granting the Deception Lite exposure tier — design proposal (#196)

Owner: [#196](https://github.com/01rabbit/Azazel-Nexus/issues/196) (the grant
phase; the review findings are those of
[#276](https://github.com/01rabbit/Azazel-Nexus/issues/276)).
Status: **decided (2026-10-22): the owner adopted every recommended default
of §10 (Q1–Q12); G1–G3 in progress; the tier stays withheld until G6.**
Related: [Deception Lite prerequisites](deception-redirect-prerequisites.md)
(§7 Q9, Q10; §9; §10 "Before any grant"; §13; §14) ·
[observe-baseline activation](activation-observe-baseline.md) ·
[commissioning](commissioning.md) ·
[commissioning storage at boot](commissioning-storage-at-boot.md) ·
[hardware gates](hardware-gates.md)

## 1. Problem

The three units of the `DECEPTION_EXPOSURE` tier (`azazel-decoy-nsd`,
`azazel-decoy-netd`, `azazel-decoyd`) are built, tested and never granted:
`ActivationController._withholding_reason` returns
`isolation_evidence_absent` for the tier unconditionally
(`src/azazel_nexus/activation.py:1069-1097`). The prerequisites document lists
what must exist before that line may change: the approved prefixes of §7 Q9
and the five fixed places they touch (F2), the generation measurement, a
watch over the decoy table (F1), an LSM gate (§9, F6), a decoy-sandbox gate
(§7 Q10, F7) and `HG-06`. It also records, in §14, that the pass can never
hold this boot's isolation evidence.

This document proposes how each of those is done, and in what order, so that
the change to `_withholding_reason` is a small, reviewed step at the end and
not a design decision made in code. It changes no code.

## 2. What is established, and what is inferred

Read at `main` 921c4f5. *Inferred* marks what was not confirmed by reading
code or by a recorded run and must be checked in the phase named.

| fact | reference |
| --- | --- |
| The tier is withheld on every pass; `activate` takes no isolation evidence | `src/azazel_nexus/activation.py:1069-1097` |
| The three units are granted together or not at all, in three places | `activation.py:820-829`, `:1069-1082`; `runtime/src/azazel_nexus_runtime/activation_markers.py:81`, `:186-188` |
| A policy may not name them: the pass's scope is the grantable set without them; the code allowlist omits them | `runtime/src/azazel_nexus_runtime/activation_pass.py:108`, `:293`; `src/azazel_nexus/activation_policy.py:62-69` |
| A v2 approval can name only `SUPPORTING` and `EDGE_BASELINE` units | `src/azazel_nexus/activation_approval_v2.py:61-63`, `:80` |
| Generation measurement is limited to the code allowlist | `runtime/src/azazel_nexus_runtime/activation_unit_files.py:329-353` (`_scope(units, ACTIVATION_UNIT_ALLOWLIST)`) |
| The ruleset is a constant; `approved_v4` has no element; the forward accept names no input interface | `runtime/src/azazel_nexus_runtime/decoy_network.py:117-139` |
| Every argument list the helper may run is a constant; `run_fixed` refuses others | `decoy_network.py:218-225`, `:253-254` |
| The isolation check compares the text listing exactly and requires an empty set | `runtime/src/azazel_nexus_runtime/decoy_isolation_check.py:72-96`, `:109-117`, `:176-179` |
| The record's checks are a fixed tuple under contract `decoy-isolation/v1` | `src/azazel_nexus/decoy_isolation.py:79`, `:105-114` |
| The decoy refuses to listen without this boot's passing record | `runtime/src/azazel_nexus_runtime/decoyd.py:316-327`; `decoy_isolation.py:319` |
| The decoy's only `IPAddressAllow=` is the fixed /30, pinned by `ServiceProfile` | `runtime/src/azazel_nexus_runtime/hardening.py:364-384`, `:1410`; `runtime/src/azazel_nexus_runtime/decoy_addresses.py:34` |
| The library's `Commissioning` has a `bridge_prefix` and no default | `src/azazel_nexus/decoy.py:167-191` |
| The full commissioning proposal is a Nexus wrapper around Fabric's record; v2 added `mio_profile` to the signed bytes | `src/azazel_nexus/commissioning_approval.py:12-32`; `src/azazel_nexus/fabric_boundary.py:822-830` |
| A commissioned node cannot re-propose in place | [commissioning](commissioning.md#4-roles-come-from-the-operator-not-from-inference) |
| Fabric's roles include `deception_bridge` | `src/azazel_nexus/commissioning.py:69-75` |
| A unit already receives commissioning material by `LoadCredential=` from a fixed path | `hardening.py:1238-1243` (M.I.O. entryd) |
| The grant markers live in `/run/azazel-activation/granted` | `activation_markers.py:89` |

*Inferred, to be checked:* that `nft` needs `CAP_NET_ADMIN` for a listing as
well as for a change (nfnetlink checks the capability per message); that
systemd's `IPAddressAllow=` filter sees the address after NAT (§4.4); that a
`Requires=` on a one-shot without `RemainAfterExit=` does not stop the
requiring unit when the one-shot exits (§6); that `AppArmorProfile=` without
`-` fails the start when the profile is not loaded (§7); that Debian 13 loads
AppArmor by default (§7).

## 3. Invariants

These hold for every option below. An option that needs one relaxed is
rejected, and is listed as rejected.

- **No new decision authority.** Edge alone decides every redirect,
  activation and termination. Nexus admits units once per boot from evidence.
  The approved prefixes are the operator's, confirmed at commissioning. A
  watch that stops the units only narrows; it judges no traffic.
- **No bypass.** No approval boolean, environment variable, drop-in, manifest
  field, CLI flag or file that skips a check. The tier becomes grantable by a
  deliberate change in `_withholding_reason`, with tests.
- **A test key never becomes a real one.** Tests and VM rehearsals use keys
  generated for the run; production loads only enrolled operator keys and the
  fixed key on the LUKS volume.
- **A VM run is not hardware evidence.** Every VM step below is a mechanism
  check. `HG-06` and the new gates close only on the real host.
- **Edge is the only decider.** Nothing here reads, re-derives or acts on an
  Edge decision; the exposure is operator-commissioned, not a redirect.
- **Fail closed without touching the deterministic path.** Every refusal
  withholds the tier or stops the three units. Edge Core and the supporting
  units are unaffected (the F11 caveat of the prerequisites document §10
  still applies to unit-file departures).
- **No secret in the record.** Prefixes and interface names are site network
  data, not secrets, but no record, journal line or status field carries them
  in clear: the isolation record and status show a digest and a count.

## 4. Q9: bringing the commissioned scope in

### Current state

`approved_v4` is empty and nothing can fill it. The bridge prefix is a fixed
/30 (`decoy_addresses.py:34`). The ingress side of the forward rule names no
interface. The helper takes no input of any kind (§13 of the prerequisites
document), and five fixed places assume that (F2).

### 4.1 Where the operator's confirmation lives

| option | idea | verdict |
| --- | --- | --- |
| S1 | a `deception_scope` section in the full commissioning proposal, a v3 Nexus wrapper, as v2 added `mio_profile` | **recommended** |
| S2 | a separate signed "deception scope" document with its own approval purpose, bound to the commissioning digest | a second record that can drift from commissioning, and one that can be re-signed without commissioning's re-entry rules (physical action, maintenance state; [commissioning §10](commissioning.md#10-closing-and-re-entering-commissioning)); widening exposure would become easier than changing a role; **not chosen** |
| S3 | in the activation approval (per lease) | the scope would be re-signed every 72 h and changeable at each signing; a lease is permission to run, not the place to define the network; **rejected** |
| S4 | in `/etc/azazel/activation/policy.json` | administrator-placed and unsigned; **rejected** |

**S1 in detail.** `commissioning-proposal/v3` carries everything v2 carries
plus:

```
"deception_scope": {
  "bridge_prefix": "10.255.196.0/30",
  "approved_v4": ["10.20.0.0/24", ...],
  "ingress_role": "deception_bridge"
}
```

- `bridge_prefix` is **confirmed, not chosen**: in this phase it must equal
  `decoy_addresses.DECOY_SUBNET`, and any other value refuses. A
  commissioned bridge prefix that changes the units' addresses is a later
  change (it touches the namespace unit's argument lists too).
- `approved_v4` lists the sources that may reach the decoy.
- Interfaces are named **by role, never by name or identity**: the ingress
  interfaces are those the same proposal confirms with the role
  `deception_bridge` (the role exists in Fabric's set; commissioning §8
  forbids substituting a name). The proposal already binds each role to a
  composite identity, so no raw identity is added.

The operator signs the whole wrapper under the existing
`commissioning-proposal` purpose. Cost: an already commissioned node must be
re-commissioned to gain the section, as for v2. No node grants the tier today,
so nothing is lost.

### 4.2 Validation (closed form, bounds, address classes)

A strict decoder, in the library, refuses the whole section on any departure
(there is no partial scope):

- exactly the three keys; `ingress_role` exactly `deception_bridge`;
- `approved_v4`: 1 to 16 entries; each a strict IPv4 network
  (`ipaddress.IPv4Network(..., strict=True)`, no host bits), written in its
  canonical form, sorted, no duplicate, **no overlap and no adjacency**
  (nftables merges or rejects those in an interval set, which would make the
  listing differ from the input; *inferred*, to be container-checked);
- every entry inside RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`); refused: loopback, link-local, multicast, `0.0.0.0/8`,
  broadcast, shared address space (`100.64.0.0/10`), documentation and
  benchmarking ranges, every other reserved block, and any public address.
  A Lite decoy is for the protected network, never the Internet;
- no entry overlapping the bridge prefix, and none overlapping
  `10.255.196.0/24` (headroom for a later commissioned bridge prefix);
- at least one interface confirmed `deception_bridge`, at most four; one also
  confirmed `management` or `observation` is impossible by construction (one
  role per interface), and the decoder checks it again;
- the payload stays within the existing approval size bound.

A re-rendering of the decoded section must equal the signed bytes, as every
other decoder here does.

### 4.3 How the helper receives it

| option | idea | verdict |
| --- | --- | --- |
| H1 | the helper reads the proposal on the LUKS volume and verifies the signature | raw identity (serials, MACs) in the helper; operator trust, Ed25519 and Fabric in its import closure (the problem #278 F3 just fixed); a second verifier; **rejected** |
| H2 | the pass, having verified the proposal, renders a closed scope file into `/run/azazel-activation/decoy-scope.json` (root `0600`); the helper reads it | the pass already verifies the proposal and writes grant markers there; rendering is not deciding |
| H3 | H2, delivered to the helper by `LoadCredential=decoy-scope:/run/azazel-activation/decoy-scope.json`, read from the fixed path `/run/credentials/azazel-decoy-netd.service/decoy-scope` | **recommended**: the helper gets an immutable snapshot for its whole run; a missing file fails the unit's start (fail closed); there is a precedent (`hardening.py:1238`) |
| H4 | a rendered unit file, drop-in or `ExecStart=` argument per node | drop-ins are refused on every grantable unit (#253); vendor unit files are package-owned and compared byte for byte; **rejected** |
| H5 | an environment variable | **rejected** (invariant) |

The rendered file is a closed form: `{"approved_v4": [...], "contract":
"azazel-nexus/decoy-scope/v1", "ingress": ["<ifname>", ...]}`, canonical
JSON, at most 2048 bytes. The pass resolves the `deception_bridge` role to
this boot's interface names from the commissioning evidence and the current
inventory it already compares; an ambiguous or missing identity withholds the
tier (commissioning §8: no fallback). Interface names are checked against
`[A-Za-z0-9_.-]{1,15}` and must not begin with `az-decoy`; nothing else may
reach the nftables text. The pass writes the file **before** the grant
markers, only when it grants the tier, and removes any earlier one first, as
it does the markers.

The helper's reader: the fixed credential path only, opened without
following links, a regular file within the bound, parsed and re-rendered to
the same bytes, then re-validated with the library's rules of §4.2. Its
containment no longer rests on "no input"; it rests on "one closed, bounded
input, written by root after verification, decoded by one function". That is
the design decision F2 asks for.

### 4.4 The five fixed places (F2)

1. **`NFT_RULESET`.** One transaction stays one argument: the constant text
   plus `elements = { ... }` in the set and an `iifname { ... }` match on
   the forward accept, rendered by one function from the decoded scope.
   Only `str(IPv4Network)` and the validated names reach the text, never an
   input string. Rejected: a second `nft add element` command (two
   transactions, a window with a table that does not match the record).
2. **The isolation check.** `EXPECTED_NFT_LISTING` is computed from the same
   scope by the same renderer. The text listing wraps long element lists,
   so the comparison moves to the structure of `nft -j list table` (the
   change §14 already names). `approved_v4_empty` becomes
   `approved_v4_matches` (exactly the scope's elements) and `ingress_matches`
   is added. A change to `CHECKS` is a new contract,
   `decoy-isolation/v2`, which also records `scope_digest` (SHA-256 of the
   rendered scope file, no address); a v1 record is refused by the new
   reader.
3. **`_ALLOWED`.** Becomes a plan built once per run from the decoded scope:
   the constant argument lists plus exactly the one ruleset argument list
   rendered from it. `run_fixed` refuses anything outside the plan, as now.
   No caller passes an argument list.
4. **The decoy's `IPAddressAllow=`.** Three ways:

   | option | idea | verdict |
   | --- | --- | --- |
   | A1 | render the decoy unit per node with the approved prefixes | per-node vendor files, outside the byte-compared rendering; **rejected** |
   | A2 | a static, coarse allowance (`10.0.0.0/8 172.16.0.0/12 192.168.0.0/16` plus the /30) | static, but the second wall becomes "any private address", and if the table is lost every private source reaches the decoy; **fallback** |
   | A3 | the table masquerades approved traffic to the bridge address on its way into `az-decoy0`; the decoy sees every peer as `10.255.196.1`, and its allowance stays the fixed /30 (or narrows to `10.255.196.1/32`) | **recommended** |

   A3 keeps the unit file static and the `ServiceProfile` pin unchanged, and
   it has a fail-closed property the others lack: if the table is flushed,
   the masquerade goes with it, forwarded packets keep their real source and
   the decoy's own cgroup filter drops them. The decoy loses the peer
   address, which §7 Q8 already keeps out of every record. Costs: a `nat`
   chain on the `postrouting` hook in the same table, `nf_nat` and conntrack.
   *Inferred, to be VM-checked:* that the cgroup filter sees the translated
   source, that replies are reverse-translated before the forward hook (so the
   reply rule still matches `@approved_v4`), and the unreachability after a
   flush.
5. **The generation and what the operator signs.** The scope is in the
   signed proposal, so it is inside `commissioning_digest`, which the
   generation metadata and the approval already carry. In addition the
   generation gains an exposure section: the digests of the exposure unit
   files (the three, and the verify and trip units of §6), of the AppArmor
   profiles of §7, and of the decoded scope (`scope_digest`). The operator's
   signer prints the scope digest and the number of prefixes and interfaces
   before signing. A new generation schema version is needed (the current
   one is named observe-baseline); its name is an implementation choice.

### 4.5 A gap this exposed: how outside peers reach the decoy

Nothing designed so far says how a host on the protected network reaches
`10.255.196.2`: the address is private to the node, so the LAN needs a route
to the /30 through the node (or the node translates a LAN address to it), and
the node must forward from the ingress interfaces to `az-decoy0`. The helper
cannot set forwarding (`ProtectKernelTunables=yes`), and a host-wide
`net.ipv4.ip_forward=1` would make the node a router for every interface.
This is outside Q9 but a prerequisite of a useful grant. **Proposed:** a
short separate design before G6 (§9), with the default "the LAN routes the
/30 to the node; Nexus sets no sysctl, and the pass withholds the tier unless
per-interface forwarding (`net.ipv4.conf.<ingress>.forwarding`) is already
on for the ingress interfaces and off on the management and observation
ones" (§10 Q11).

## 5. The grant condition

### Current state

§14 of the prerequisites document: the pass runs before the three units, so
this boot's record cannot exist at the pass; option B (granting on the
previous boot's record) was not chosen. What the pass may require instead was
left open.

### Options

| option | idea | verdict |
| --- | --- | --- |
| C1 | the pass grants on node-level inputs it can check before the units run (below); the per-start record (§14 A) stays the condition behind every listen | **recommended** |
| C2 | C1, plus the previous boot's passing record (continuity) | needs persistent root-written state; a previous network says nothing about this one; withholds exactly when the record is stale and grants exactly when it is old (§14 B); **not chosen** |
| C3 | C1, plus a fence: a watch trip (§6) in the previous boot withholds the tier until a new approval | narrowing only, but needs a persistent trip record written by a root unit; **owner choice**, default no (§10 Q6) |
| C4 | grant without the signed approval, on gates alone | an unsigned path to exposure; **rejected** |

**C1, what the pass requires for the tier**, in addition to what every tier
needs (health, lease, generation, clock, high water):

1. **a signed approval naming the three units**, under a new approval
   schema (v3) that may name `DECEPTION_EXPOSURE` units, all three or none;
   v2 stays limited to its two tiers. This is the existing signed-lease
   mechanism, not a boolean;
2. **the generation's exposure section verifies** (§4.4 item 5): the unit
   files, the AppArmor profiles and the scope digest as measured now;
3. **a v3 commissioning proposal with a valid `deception_scope`**, whose
   ingress role resolves to this boot's interfaces;
4. **the LSM is present** (§7): AppArmor enabled and the decoy profiles
   loaded in enforce mode, read from `/sys/kernel/security/apparmor`;
5. **coexistence holds** (§6.2): no unit that flushes the ruleset is enabled;
6. **the static preconditions**: `net.core.fb_tunnels_only_for_init_net` is
   `2` (§13 of the prerequisites document) and the forwarding condition of
   §4.5.

Each failure withholds the tier with its own reason code, and nothing else.

**Product-level gates are not pass inputs.** `HG-06`, the decoy-sandbox gate
(§8) and the LSM gate (§7) are hardware-gate records, which a pass cannot
verify. They gate the **change** that lifts the unconditional withhold: G6
(§9) is merged only after those records are accepted. No build that can
grant the tier exists before the hardware evidence.

The tripwire changes from "any exposure grant narrows" to "an exposure grant
without all of the above, or of only part of the tier, narrows".

## 6. Watching the table (F1, the remainder)

### Current state

The helper reads the table back once. A `flush ruleset` from
`nftables.service` (start, reload, stop), a `firewalld` reload, or a future
Edge enforce posture would remove it while the helper stays `active` and the
decoy listens. A decoy restarted later in the boot accepts the old record.

### 6.1 Detection and stop

| option | idea | verdict |
| --- | --- | --- |
| W1 | a resident `nft monitor` watcher with `CAP_NET_ADMIN` | a new resident privileged process and a new parser of untrusted-format output; lowest latency; **rejected** |
| W2 | a systemd path unit | path units watch files; the ruleset is kernel state; at best it sees `/etc/nftables.conf` change, not a flush; **rejected** |
| W3 | a decoy-side canary (the decoy probes `10.255.196.1` and stops when the host answers) | needs an `AF_INET` connect in the decoy, which the boundary forbids (§7 Q7), and sees only the input chain; **rejected** |
| W4 | a **periodic, read-only verify**: `azazel-decoy-verify.service` (one-shot) runs the helper's fixed `HELPER_VERIFY` commands and the same comparison against the scope; a timer runs it every 10 s; a failure starts `azazel-decoy-trip.service`, whose only content is `Conflicts=azazel-decoy-nsd.service` | **recommended** |

W4 adds no resident process. systemd's job engine does the stopping: starting
the trip unit stops the namespace unit, and through `Requires=` the helper
and the decoy first, so nothing needs D-Bus or a capability to stop them.
The verify unit:

- is `az-decoy-netd verify`, the same executable with one more fixed word,
  running only the read-back argument lists (a plan without build steps);
- has the helper's sandbox (root, `CAP_NET_ADMIN` bounding set, `AF_NETLINK`
  only, no writable path) because a listing needs `CAP_NET_ADMIN`
  (*inferred*). It is a third holder of `CAP_NET_ADMIN`; §10 Q7 asks the owner
  to accept that;
- writes nothing; the record stays the helper's;
- has `OnFailure=azazel-decoy-trip.service`, and also runs **before every
  decoy start**: the decoy gains `Requires=` and `After=` on it, which closes
  "a read-back on every decoy start" of F1.

The verify unit, its timer and the trip unit carry **no grant marker and no
`[Install]` section**: they start only because the decoy pulls them in
(`Requires=` on the verify unit and the timer). A marker would let systemd
skip them as a success, the n1 problem, leaving the decoy running unwatched.
They are measured in the generation, pinned by `ServiceProfile` and checked
like every governed unit file. Not being masked is safe: each can only read
or stop.

Window: up to one timer period plus one verify run between a flush and the
stop. The period is an owner choice (§10 Q6); 10 s keeps the load to one
`nft` and one `ip` listing per period.

### 6.2 Coexistence and ordering

- **Not enabled together.** The pass withholds the tier while
  `nftables.service`, `firewalld.service` or `netfilter-persistent.service` is
  enabled (read through the bus the pass already uses). A host that needs one
  of them is not a decoy host in this phase. Checking the content of
  `/etc/nftables.conf` for `flush ruleset` is rejected: includes and other
  loaders make it unreliable.
- **Ordering anyway.** The helper gains `After=` on those three units (a no-op
  when absent), so a boot-time load runs before the build.
- **Edge enforce posture.** Until Edge declares that its enforcement touches
  only its own table (Azazel-Edge#412), the exposure tier and an
  enforce-posture Edge unit are mutually exclusive in one generation; the
  controller refuses a governed set holding both.
- `iptables-restore` without `--noflush` replaces only the iptables-nft
  tables, not `inet azazel_decoy` (*inferred*; VM-check). The verify catches
  it either way.

## 7. LSM: AppArmor as a gate (F6)

### Current state

The namespace unit is root with `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `mount` and
no file-system sandbox; a compromised body is host root. The helper (and the
verify unit of §6) are root. §9 of the prerequisites document makes an LSM
profile, and a hardware-gate record of it, a condition of any grant.

### Options

| option | idea | verdict |
| --- | --- | --- |
| L1 | AppArmor profiles for the namespace unit, the helper, the verify unit and the decoy, attached with `AppArmorProfile=` (no `-`) | **recommended** |
| L2 | SELinux | not enabled by default on Debian; a policy module for the whole host; **not chosen** |
| L3 | Landlock, applied by each body to itself | a Landlock domain forbids mount topology changes, which the namespace unit needs; and it is set by the body it is meant to contain; **later supplement** for the helper and the decoy, not the gate |

### L1 in detail

- **What each profile must deny**, the gate's claims: writes to
  `/run/azazel-activation/**`, `/etc/systemd/**`, `/usr/lib/systemd/**`,
  `/etc/azazel/**`, `/var/lib/azazel/**` (the activation state, the grant
  markers, the unit files, the ledgers); `unix` access to
  `/run/dbus/system_bus_socket` and `/run/systemd/private`; `ptrace`;
  `capability mac_admin` (also outside the bounding set) and writes under
  `/sys/kernel/security`; `change_profile`.
- **What the namespace unit's profile allows**: `capability sys_admin
  net_admin`, `network netlink raw`, execution of `/usr/bin/ip` in a child
  profile, and only the mounts `ip` makes (the bind of
  `/proc/*/ns/net` onto `/run/netns/azazel-decoy`, the slave remount of `/`
  and the fresh `/sys` of `ip -n`), plus read access to the Python runtime
  and the package. The exact mount rules are VM work.
- **What it cannot do.** AppArmor's network rules mediate the family and the
  type, not the netlink protocol, on Debian's kernel (*inferred*): it cannot
  stop a compromised body from talking to nftables. That stays the body's
  property (fixed, no input) and the watch's (§6). The gate claims only what
  the profile denies.
- **Fail closed twice.** `AppArmorProfile=` without `-` makes a start without
  the loaded profile fail (*inferred*; VM-check), and the pass withholds the
  tier unless the profiles are listed in enforce mode (§5 item 4). Booting
  with `apparmor=0` or an `lsm=` list without AppArmor therefore withholds.
- **Measured.** The profile files are digested into the generation (§4.4
  item 5). They live in `/etc/apparmor.d/`, which an administrator can edit;
  an edit then fails the generation.

### Debian 13 prerequisites

Debian enables AppArmor by default since Debian 10 (*inferred* for Debian 13,
the release this repository targets; confirm on the VM): the kernel's default
LSM list includes it, the `apparmor` package provides `apparmor_parser` and
`apparmor.service` loads `/etc/apparmor.d` early in boot. The installer
would need the `apparmor` package (and not `apparmor-utils`, which is only
for authoring). The profiles must be loaded before the three units start;
`apparmor.service` runs before `sysinit.target`, well before the controller
(*inferred*; VM-check). systemd 257 supports `AppArmorProfile=`.

## 8. The decoy-sandbox gate (Q10, F7)

`HG-06` is the bridge gate: packets that fail to cross. Q10 adds a gate for
the **sandbox** of the units on the real host. Proposed claim: "on the target
hardware, each exposure unit runs with exactly the confinement its profile
declares, and none can reach the service manager or the activation state".

Measured on the real host, with the units as rendered and only the grant
markers placed by hand (then also through a real grant, after G6):

| item | how observed | passes when |
| --- | --- | --- |
| capabilities | `CapEff`, `CapPrm`, `CapBnd`, `CapAmb` in `/proc/<pid>/status` | decoy: all zero; helper and verify: bounding exactly `CAP_NET_ADMIN`, ambient zero; namespace unit: bounding exactly the two |
| no new privileges, seccomp | `NoNewPrivs`, `Seccomp` in `/proc/<pid>/status` | `1` and `2` for each |
| address families | a test probe run under a copy of each unit with only `ExecStart=` replaced, attempting each other family | refused (`EAFNOSUPPORT`/`EPERM`) |
| service manager | the same probe connecting to `/run/dbus/system_bus_socket` and `/run/systemd/private`, and `systemctl unmask` | refused for every unit |
| activation state | the probe writing under `/run/azazel-activation`, `/etc/systemd/system`, `/usr/lib/systemd/system`, `/var/lib/azazel/state` | refused for every unit (for the namespace unit, by the LSM) |
| IP filter | `bpftool cgroup show` on each unit's cgroup | the ingress and egress programs are attached; a kernel without cgroup BPF makes systemd skip the filter with only a warning, so absence is a failure |
| namespace | the decoy's `/proc/self/ns/net` against `/run/netns/azazel-decoy`; its links | same namespace; only `lo` and `az-decoy-ns0` |
| user namespace | the decoy's `uid_map` | a single mapping of its own account |
| limits | the decoy's cgroup `memory.max`, `pids.max` | `128M`, `16` |
| LSM | `/proc/<pid>/attr/current` (or `attr/apparmor/current`) | the unit's profile, `(enforce)` |
| exposure score | `systemd-analyze security <unit>` | recorded per unit, no threshold; a change between runs is reviewed |

Recorded as a HIL record under the virtualization negative filter, per
hardware class; a VM run of the same table is a rehearsal only. The probe
copies are removed after the run and never packaged.

**Gate bookkeeping.** `HG-08` is reserved by
[commissioning storage at boot](commissioning-storage-at-boot.md) §5 Q7.
Proposed: `HG-09` for this sandbox gate and `HG-10` for the LSM gate of §7
(its claim: under the profiles, the units cannot write the activation state,
the grant markers or the unit files, and cannot reach the service manager).
Numbers are provisional until added to [hardware gates](hardware-gates.md).

## 9. Phases

Each phase is one or more small PRs. Until G6 the tier stays withheld on every
pass and the existing tests that pin it stay.

| phase | content | needs |
| --- | --- | --- |
| G0 | this proposal; owner decisions (§10) | — |
| G1 | the scope: proposal v3 and its decoder (§4.1, §4.2); the rendered scope and its reader (§4.3); the ruleset, plan and `nft -j` check from the scope; isolation contract v2; masquerade (A3); unit tests only, nothing wired into the pass | Q1–Q4 |
| G2 | the watch: verify unit, timer, trip unit, decoy `Requires=`, helper `After=` (§6); unit tests | Q6, Q7 |
| G3 | AppArmor profiles, `AppArmorProfile=`, the pass's reading of enforce mode (as a withholding reason that is never reached yet); installer adds the package | Q8 |
| G4 | VM rehearsal of G1–G3 with markers placed by hand and a VM-only rehearsal key (never evidence); the items of §11 | G1–G3 |
| G5 | hardware: `HG-06`, `HG-09`, `HG-10` on the real host | G4, owner |
| G6 | the grant: approval v3, the allowlist and policy scope, the generation's exposure section, the pass rendering the scope, the conditions of §5 in `_withholding_reason`, the changed tripwire; a VM rehearsal of grant → reboot → start and of each refusal on the branch before merge; merged only after G5 is accepted | G5, Q5, Q10, Q11 |

P5 and P6 of the prerequisites document (decisions, redirect) are unchanged
and come after G6.

## 10. Owner decisions

Recommended defaults in brackets. **Decided 2026-10-22:** the owner adopted
every bracketed default below, Q1 to Q12, without change ("#280 の12件は
すべて推奨どおりで"). The fallbacks the defaults name (A2 if the VM check of
A3 fails) remain fallbacks, taken only on a recorded VM result.

1. Where are the approved prefixes and ingress interfaces confirmed? **[S1: a
   `deception_scope` section in a v3 commissioning proposal, signed with it;
   interfaces by the `deception_bridge` role; existing nodes re-commission]**
2. How does the helper receive them? **[H3: the pass renders a closed scope
   file under `/run/azazel-activation`; `LoadCredential=` from that fixed path;
   the helper never reads the proposal]**
3. Validation bounds? **[IPv4 only; 1–16 RFC 1918 prefixes, canonical, sorted,
   no overlap or adjacency, none in `10.255.196.0/24`; 1–4 ingress
   interfaces; the bridge prefix confirmed equal to the fixed /30]**
4. The decoy's `IPAddressAllow=`? **[A3: masquerade to the bridge address, the
   allowance stays static; A2 if the VM check of A3 fails]**
5. The grant condition? **[C1: v3 approval of all three, the generation's
   exposure section, a valid scope, AppArmor in enforce mode, coexistence,
   the static preconditions; the per-start record behind every listen;
   no previous-boot evidence]**
6. Watch period and fence? **[W4 every 10 s and before every decoy start; no
   persistent fence (C3) in this phase]**
7. A third `CAP_NET_ADMIN` holder (the verify unit)? **[yes, same executable
   and sandbox as the helper, read-only plan, confined by the LSM]**
8. LSM? **[AppArmor, `AppArmorProfile=` without `-`, the pass checks enforce
   mode; Landlock later as a supplement]**
9. Gate numbering? **[`HG-09` decoy sandbox, `HG-10` LSM confinement,
   provisional after the reserved `HG-08`]**
10. Order of G6 and the hardware gates? **[G6 merged only after `HG-06`,
    `HG-09` and `HG-10` records are accepted; VM rehearsal on the branch]**
11. How outside peers reach the decoy (§4.5)? **[a short separate design
    before G6; default: the LAN routes the /30 to the node, Nexus sets no
    sysctl, the pass withholds unless per-interface forwarding is on for the
    ingress interfaces and off for management and observation]**
12. Firewall coexistence? **[the tier is withheld while `nftables.service`,
    `firewalld.service` or `netfilter-persistent.service` is enabled; Edge
    enforce posture and the tier mutually exclusive until Edge agrees on
    table scope]**

## 11. To check on the VM (G4; a mechanism check, not hardware evidence)

1. masquerade (A3): a connect from an approved source on the ingress reaches
   the decoy and the banner returns; the decoy's cgroup filter sees
   `10.255.196.1`; after `nft flush ruleset` the same connect gets no answer;
2. the scope: elements and the `iifname` match load in one transaction;
   `nft -j list table` compares equal; a hand-added element fails the check;
3. the watch: `systemctl reload nftables` (with the service started by hand)
   stops the three units within one period; a decoy restart re-runs the
   verify; a verify that fails before the decoy start keeps it down; a
   successful one-shot verify does not stop the decoy through `Requires=`;
4. AppArmor: the four profiles load on Debian 13; a start with a profile
   unloaded fails; the namespace unit's `ip netns add` and `ip -n` work under
   its profile, and its writes to the paths of §7 are denied;
5. `nft list` refused without `CAP_NET_ADMIN` (confirms the verify unit's
   need);
6. every item of the §8 table, as a rehearsal of `HG-09`.
