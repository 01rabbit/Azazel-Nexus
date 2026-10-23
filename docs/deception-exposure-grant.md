# Granting the Deception Lite exposure tier — design proposal (#196)

Owner: [#196](https://github.com/01rabbit/Azazel-Nexus/issues/196) (the grant
phase; the review findings are those of
[#276](https://github.com/01rabbit/Azazel-Nexus/issues/276)).
Status: **decided (2026-10-22): the owner adopted every recommended default
of §10 (Q1–Q12); G1–G3 in progress (G3's profiles and enforce-mode check
are in, §7 "G3 as implemented"; G2's watch is in, §6.3 "G2 as
implemented"); the tier stays withheld until G6.**
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
| The ruleset is a constant; `approved_v4` has no element; the forward accept names no input interface. *Since G1b:* rendered from the scope, the constant only without one | `runtime/src/azazel_nexus_runtime/decoy_network.py:304` (`render_ruleset`), `:363` (`NFT_RULESET`) |
| Every argument list the helper may run is a constant; `run_fixed` refuses others. *Since G1b:* a per-run `Plan`, the constants plus one rendered ruleset | `decoy_network.py:454` (`Plan`), `:486` (`helper_plan`), `:511`, `:548` |
| The isolation check compares the text listing exactly and requires an empty set. *Since G1b:* the `nft -j` structure against the rendered ruleset | `runtime/src/azazel_nexus_runtime/decoy_isolation_check.py:122` (`_table`), `:160`, `:194`, `:275` (`evaluate`) |
| The record's checks are a fixed tuple under contract `decoy-isolation/v1`. *Since G1b:* `decoy-isolation/v2`, nine checks and `scope_digest`; v1 refused | `src/azazel_nexus/decoy_isolation.py:84`, `:119-129`, `:230` (`parse_evidence`) |
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

A boot in which an interface has another kernel name than at commissioning
withholds the tier; the role is never moved to another interface. The pass
compares this boot's inventory with the commissioned one whole, kernel names
included (the comparison the commissioning evidence already makes), so every
name it renders is the name the interface had when it was commissioned
(`exposure_interfaces.resolve_role_interfaces`, G6 preparation D).

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
   input string, and every name is written **quoted** (`iifname { "<name>",
   ... }`) even though the decoder already refuses names that nftables could
   read otherwise (G1a: `lo`, `all`, `default`, `.`, `..` and the `az-decoy`
   prefix in any case, a leading `-`, an all-digit name, which could be taken
   for an interface index). Rejected: a second `nft add element` command (two
   transactions, a window with a table that does not match the record).
2. **The isolation check.** The expected listing (`Ruleset.expected`, G1b)
   is computed from the same scope by the same renderer as the loaded text
   (it replaced the text listing `EXPECTED_NFT_LISTING`). The text listing
   wraps long element lists, so the comparison moved to the structure of
   `nft -j list table` (the change §14 named). The check
   `approved_v4_matches` (exactly the scope's elements) replaced
   `approved_v4_empty`, and `ingress_matches` (the set of ingress names and
   how many matches carry it; where they sit is `nft_table`'s) was added.
   A change to `CHECKS` is a new contract, `decoy-isolation/v2`, which also
   records `scope_digest` (SHA-256 of the rendered scope file, no address);
   a v1 record is refused by the new reader. It sees only this table, not
   what other tables do (prerequisites §14).
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
   profiles of §7, and of the rendered scope file (`scope_digest`, the
   SHA-256 of the file's bytes, which carry this boot's ingress names; the
   publisher renders the same file as the pass,
   [wiring §5.2](deception-exposure-wiring.md#52-the-generations-exposure-section)).
   The operator's signer prints the scope digest and the number of prefixes and interfaces
   before signing. A new generation schema version is needed (the current
   one is named observe-baseline); its name is an implementation choice.
   The section's computation and comparison are **implemented, not wired**
   (§9, "G6 preparation C"); the schema version that carries it is
   introduced in G6.

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
ones" (§10 Q11). That design is
[how outside peers reach the decoy](deception-exposure-reachability.md): it
keeps the default, and adds what writing it out showed, notably that
forwarding is a property of the receiving interface, so the ingress needs
containment of its own, and that the replies need forwarding on `az-decoy0`
(its §5, §7, §9 and §10).

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
   §4.5, specified in
   [reachability §6](deception-exposure-reachability.md#6-the-pass-condition-g6-implemented-not-wired)
   (only its rows in bold were decided by the owner; the others are that
   design's narrowing defaults, required before G6, which the owner may
   overturn). The forwarding part is **implemented, not wired** (#196 G6
   preparation A): `decoy_reachability.pass_reachability_departures` judges
   it from values passed in and nothing calls it; the
   `fb_tunnels_only_for_init_net` read is not part of it and is G6's.
   **This condition is not yet met:** a rule selector that `ip -j` does not
   print would let a discard rule look right and discard less. On the VM
   (kernel 6.12) `dscp`, `tos`, `fwmark`, `ipproto`, `dport`, `uidrange`
   and `l3mdev` are printed and refused; the flow label was not shown and
   is *inferred* dropped by that kernel. Its effect on the target kernel
   (or a fixed target kernel), the head of
   [reachability §6](deception-exposure-reachability.md#6-the-pass-condition-g6-implemented-not-wired),
   is checked before G6 wires this in. The networkd rules' attributes were
   observed on the VM (reachability §11 item 8) and the comparison, shared
   with the verify, accepts them.

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
(Since the G4 follow-up the trip unit names all three in `Conflicts=`
rather than relying on `Requires=`; §6.3, "The trip after G4".)
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

### 6.3 G2 as implemented

The watch exists; **nothing is granted by it**: `_withholding_reason` still
withholds the tier as `isolation_evidence_absent` on every pass, so on a node
the decoy, and with it the watch, never starts in this build. Everything
below is unit-tested; nothing of it has run under systemd yet (§11 item 3).

- **The verify unit** `azazel-decoy-verify.service` (one-shot), declared in
  `hardening.DECOY_WATCH_PROFILES` and pinned whole by
  `ServiceProfile._check_verify_unit`: `ExecStart=/usr/libexec/azazel/az-decoy-netd
  verify` (the helper's wrapper; `ServiceProfile.arguments`, which only this
  unit may set), root, `CapabilityBoundingSet=CAP_NET_ADMIN`,
  `RestrictAddressFamilies=AF_NETLINK`, the shared sandbox, and
  `DECOY_VERIFY_SANDBOX`: the helper's settings without `RemainAfterExit=`
  (it runs again every period), `ExecStop=` and a runtime directory (it
  writes nothing). It receives the scope by the same
  `LoadCredential=decoy-scope:/run/azazel-activation/decoy-scope.json` and
  reads it from its own fixed path
  (`decoy_scope.read_verify_scope_credential`,
  `/run/credentials/azazel-decoy-verify.service/decoy-scope`, the helper's
  rules); the hardening check that kept the credential to the helper now
  keeps it to the helper and this unit. `After=azazel-decoy-netd.service`,
  `OnFailure=azazel-decoy-trip.target`, `AppArmorProfile=azazel-decoy-verify`
  and `AssertSecurity=apparmor`; no `Requires=`, no condition, no
  `[Install]` (`ServiceProfile.wanted_by` is empty for it and only for it).
- **What it runs** (`decoy_watch.verify`): the plan
  `decoy_network.verify_plan` holds no step, no absence check and no undo,
  only the four read-backs of `WATCH_READS` (the helper's `nft -j list table`
  and `ip -j -d address show`, then `ip -j -4 rule show` and
  `ip -j -4 route show table main`); `run_fixed` refuses every other
  argument list. The table and links are judged by the helper's own
  `decoy_isolation_check.evaluate` against the ruleset rendered from the
  verify unit's copy of the scope (the nine checks; no record is written,
  the `Recorder` is never constructed), and reachability R4 by
  `decoy_watch.reachability_departures` (below). Exit 0 when everything
  holds, 1 otherwise (a departure, a missing or flushed table, a read that
  fails, a refused scope, an **absent** scope, an error while evaluating),
  2 for any other argument. Unlike the helper, the verify has no
  scope-less mode: with no credential directory it compares nothing and
  exits 1 (review of #287 F1). One journal line of fixed check names and reason codes.
- **The timer** `azazel-decoy-verify.timer`: `OnActiveSec=10s`,
  `OnUnitActiveSec=10s`, `AccuracySec=1s` (the default of a minute would
  stretch the period), `Unit=azazel-decoy-verify.service`, and
  `PartOf=azazel-decoyd.service`, so that stopping or restarting the decoy
  stops or restarts the watch with it. No `[Install]`.
- **The trip unit is a target**, `azazel-decoy-trip.target`, not the
  `.service` §6.1 names: as G2 built it, its whole content was
  `Conflicts=azazel-decoy-nsd.service` (since the G4 follow-up, the three
  units; next item), and systemd 257 refuses a service with
  no `ExecStart=`, `ExecStop=` or `SuccessAction=` ("Service has no
  ExecStart=, ExecStop=, or SuccessAction=. Refusing", container-checked
  with `systemd-analyze verify`; a target with the same content verifies
  clean). A target runs nothing and holds nothing, which is what the design
  asked of the trip unit; a service would have needed a program
  (`/bin/true`) only to exist. A conflict holds both ways, so starting the
  namespace unit again stops the target and a later failure trips again.
- **The trip after G4** (#196 G4 follow-up). The second G4 rehearsal (§11,
  "Second G4 rehearsal"; a VM check of the mechanism, not hardware
  evidence) showed a trip that stopped only the namespace unit: after a
  mask and a `daemon-reload` the running units' definitions were
  `/dev/null`, their `Requires=` and `After=` were gone, and the helper and
  the decoy stayed `active`. The trip unit now reads
  `Conflicts=azazel-decoy-nsd.service`, `Conflicts=azazel-decoy-netd.service`,
  `Conflicts=azazel-decoyd.service` (one line each, as `render_unit` writes
  `Conflicts=`; `hardening.DECOY_TRIP_CONFLICTS`), and nothing else: no
  ordering, no dependency, no command. Starting it queues a stop job for
  each of the three directly, with no `Requires=` in between.
  - *Both ways.* Starting the helper or the decoy now also stops the
    target. That changes nothing in practice: each pulls in the namespace
    unit by `Requires=` (the decoy through the helper), and starting the
    namespace unit already stopped the target. So any start of the chain
    re-arms the trip, as before. A trip started while a start of the decoy
    is queued (a verify failing before the decoy's first start) replaces
    those start jobs with stop jobs under `OnFailureJobMode=replace`, as the
    namespace unit's conflict already did through `Requires=`.
  - *Stop order.* `Conflicts=` orders nothing itself; within one
    transaction systemd runs stop jobs in the reverse of `After=`. The
    decoy is `After=` the helper and the helper `After=` the namespace unit,
    so the decoy stops first, then the helper (its `ExecStop=` cuts the path
    and removes the table), then the namespace unit, whose `ExecStopPost=`
    (the veth pair and the namespace) runs last. That is the order the G2
    trip had through `Requires=`, kept while the definitions are intact
    (pinned by `tests/unit/test_decoy_watch.py`; observed on the VM, §11,
    "Third G4 rehearsal").
  - *What it covers when the definitions are gone.* After a mask and a
    `daemon-reload`, the three are still stopped by the job engine: a mask
    refuses a start, not a stop (VM-checked on this branch, §11, "Third
    G4 rehearsal"). But with the
    definitions replaced by `/dev/null` there is no `After=` to order the
    stops, no `ExecStop=` for the helper and no `ExecStopPost=` for the
    namespace unit: the processes are killed, the decoy no longer listens,
    and the namespace, the veth pair and the helper's table (if a flush
    had not already removed it) may be left behind. The `Conflicts=` lines
    close the "still running" part, not the clean-up and not the ordering;
    that is G6 item (a) below.
- **For G6** (open, from the second G4 rehearsal):
  - (a) **Not resting on the trip alone after a mask.** When a mask and a
    `daemon-reload` remove the units' dependencies, the trip is the only
    thing that stops them, and only after a verify fails. G6 decides how
    that state is handled **with no new authority**, for example: the pass
    refuses the grant while an exposure unit is masked and still running,
    or while a leftover of a definition-less stop (the namespace, the veth
    pair, the bridge) is present; the operator stops such a unit by hand
    (operations); the leftovers are detected and reported. The `Conflicts=`
    above stops the three processes in that state (VM-checked, §11); the
    clean-up and the stop order are not covered by it.
    **The detection is implemented, not wired** (#196 G6 preparation A):
    `decoy_residue.exposure_residue_departures`, a pure function over
    values the caller read (each exposure unit's `LoadState`,
    `UnitFileState` and `ActiveState` from the service manager's bus,
    `decoy_residue.read_netns`'s `(error, mode)` for `/run/netns/azazel-decoy`,
    and the host's link names as `netlink.read_links` yields them, None
    for a failed dump), returns `exposure_unit_masked_running` (no
    definition: `LoadState` `masked` or `not-found`, or `UnitFileState`
    `masked` or `masked-runtime`, while `ActiveState` is neither `inactive`
    nor `failed`), `exposure_leftovers_present` (judged per owner: the
    namespace `azazel-decoy` or the veth end `az-decoy-host0` present while
    the namespace unit is `inactive` or `failed`, or the bridge `az-decoy0`
    present while the helper is; so the
    decoy running alone over its owners' leftovers is refused, review of
    #293) and
    `exposure_state_unreadable`, in that order, with fixed phrases that
    name no object. It reads nothing, stops nothing and removes nothing; it
    adds no unit operation and no `DbusUnitManager` method. Nothing calls
    it: `_withholding_reason` still withholds the tier as
    `isolation_evidence_absent`, and a test fails the day anything imports
    the module. Which bus call reads the three properties (the controller
    has `GetUnitFileState` and `GetActiveState` today, not `LoadState`) is
    part of wiring it, in G6.
    **The namespace is read from `/run/netns`, not from `ip netns list`**
    (#196 cross review L2, H1(c)). iproute2 prints nothing and exits 0
    when it cannot open `/run/netns`, so an unreadable directory passed as
    "no namespace"; and the pass that calls this in G6 runs in the
    controller, which starts no process (only the network helper may
    spawn one, `tests/unit/test_runtime_boundary.py`). `read_netns` opens
    `/run/netns` with `O_DIRECTORY|O_NOFOLLOW` and `lstat`s the one name
    `azazel-decoy` in it; the judgement stays pure over what it returns:
    no `/run/netns` (`ENOENT`) or no such entry is no namespace, any other
    error (`EACCES`, `ENOTDIR`, a link in the directory's place) is
    `exposure_state_unreadable`, and the entry must be the regular file
    `ip netns add` binds the nsfs file onto (a link or anything else under
    that name is `exposure_state_unreadable`). Nothing calls `read_netns`
    either. **The table is not read by the pass** (A1, decided
    2026-10-23; [wiring](deception-exposure-wiring.md) §4.4 and §10
    item 5): in the controller's sandbox `nft` needs `CAP_NET_ADMIN`, so
    the judgement takes no table listing, and a leftover
    `inet azazel_decoy` alone is the helper's to refuse (`HELPER_ABSENT`
    fails its start closed), noticed at the helper and not at the pass.
    The links come from the route-netlink dump `netlink.read_links`
    (names only, no capability); a link without a name, an empty dump (a
    host always has `lo`) or a failed dump is `exposure_state_unreadable`.
  - (b) **The controller masks but does not stop.** The controller's
    preflight masks an exposure unit that is running without a grant, and
    leaves it running (seen in the second G4 rehearsal). It has no
    authority to stop a unit (`activated.py`: "no StopUnit authority").
    Making it stop one would need a new unit operation, which is itself a
    decision about authority. G6 treats whether to allow that as a design
    decision that adds authority, not as a fix. This PR adds nothing.
- **The decoy** gains `Requires=azazel-decoy-verify.service
  azazel-decoy-verify.timer` and `After=azazel-decoy-verify.service`
  (pinned in the listener check); **the helper** gains `After=` on
  `firewalld.service` and `netfilter-persistent.service`
  (`hardening.HOST_FIREWALL_UNITS`; `nftables.service` was #281).
- **Pinned and compared, not measured yet.** The three files are rendered
  by `hardening` (the service by `render_unit`, the timer and the target by
  `render_verify_timer` and `render_trip_target`) and compared byte for byte
  with `packaging/systemd/` like every unit; the installer places them and
  never masks or enables them. `activation_unit_files.require_watch_unit_files`
  is the "checked like every governed unit file" part of §6.1: each of the
  three must be in the vendor directory, protected as a measured file, equal
  **byte for byte** to the rendering (nothing in them is site-specific), with
  no drop-in and no file of the same name elsewhere **including a mask**
  (a masked trip target would let a failed verify stop nothing; for a
  governed unit a mask only withholds, so it is accepted there). **The pass
  does not call it in this build**, and the generation does not digest the
  files: `ACTIVATION_UNIT_ALLOWLIST`, `GRANTABLE_UNITS`, the policy scope and
  the observe-baseline generation are unchanged. Adding the watch to the
  allowlist would let a policy or a lease name units that are not granted,
  adding them to `GRANTABLE_UNITS` would make them unmaskable by a pass and
  give them markers (the n1 problem), and calling the check from today's
  pass could only withhold the **other** tiers, since this one is already
  withheld. Both the call and the digests belong to the generation's
  exposure section of §4.4 item 5, which is G6. **Until G6, a change to
  the three watch units (a mask, a drop-in, a `--runtime` mask) is not
  detected; the tier is withheld unconditionally, so the decoy does not
  start.**
- **R4 in G2** (`decoy_watch`; [reachability](deception-exposure-reachability.md)
  §6 and §9 R4). The verify reads, in the host namespace and through
  `/proc/sys/net/ipv4/conf` and `ipv6/conf` opened without following a link
  (each entry opened by name relative to the `conf/` directory, so the
  directory is the exact parent; an entry gone since the listing is skipped,
  a value file missing or not exactly `0\n`/`1\n` is unreadable, more than
  4096 entries is unreadable, a missing `/proc/sys/net/ipv6` is IPv6 off):
  every ingress forwards; `all` and `default` do not; no other interface
  does but `az-decoy0`, whose value is not read (its forwarding is the
  operator's, and off only makes the decoy unreachable); no IPv6 forwarding
  anywhere; `proxy_arp` off on `all` and each ingress. The verify knows the
  ingress from the scope and not the management and observation roles, so
  `forwarding_role_on` is the pass's (G6) and "every other interface off"
  (`forwarding_other_on`) covers those interfaces here. Rules (since #196
  R4's remainder; G2 compared only priority, `iif` and the K1 pair's
  defining attributes): compared **whole** by the pass's one comparison,
  `decoy_reachability._rules_exact`
  ([reachability §6](deception-exposure-reachability.md#6-the-pass-condition-g6-implemented-not-wired)).
  Below the main table's priority exactly the local rule
  `{"priority":0,"src":"all","table":"local"}` and, per ingress, the K1
  pair as `ip -j -4 rule show` prints it: priority 1960 with that `iif`,
  `src` all, `dst` `10.255.196.0`, `dstlen` 30, table `main`,
  `suppress_prefixlen` 29; priority 1961 with that `iif`, `src` all and
  action `blackhole`, with no table (`ip rule add`) or table `main`
  (networkd 257's form, observed on the VM, reachability §11 item 8) and no
  other; no other key (`oif`, `fwmark`, `tos`, `dscp`, `uidrange`, `l3mdev`,
  IP protocol, port, ...), `protocol` never compared (networkd prints
  `static` even without `-d`); and at priority 32766 exactly one rule,
  `from all lookup main`. Anything else is `ingress_containment_absent`.
  Stricter than G2's, it trips on more (the closed side); the rehearsal's
  K1 added with `ip rule add` and networkd's K1 both pass (pinned by
  `tests/unit/test_decoy_reachability.py` with the VM's output). Routes:
  no route of `main` whose destination lies inside `10.255.196.0/24` but one
  `10.255.196.0/30 dev az-decoy0` without gateway or next hops
  (`decoy_prefix_routed`); a wider route (a default, a /16) is suppressed by
  K1 and not counted. The rule and route dumps go through two fixed `ip -j`
  read-backs rather than a netlink parser of our own: the helper's modules
  may not name a socket (`tests/unit/test_runtime_boundary.py`), and `ip`
  is already the program its profile runs.
- **AppArmor** `azazel-decoy-verify` (`packaging/apparmor/`): the helper's
  profile without its writable place (no rule on
  `/run/azazel-decoy-isolation` but a `deny`, and no boot id), with its own
  credential path and read-only rules for `forwarding` and `proxy_arp`
  under `/proc/sys/net/ipv{4,6}/conf/*/`; it is in
  `decoy_apparmor.DECOY_APPARMOR_PROFILES`, so the enforce-mode judgement
  requires it (five blocks; four since the G4 follow-up removed the
  namespace unit's child, §7) and the installer compiles and places it.
- **Import closure.** `az-decoy-netd` gains the runtime module `decoy_watch`
  and no library module; the namespace unit and the decoy load nothing new.
  Since #196 G6 preparation A it also loads `decoy_reachability` (the reads
  and judgements of reachability §6 moved out of `decoy_watch`, under the
  helper's rules), and still no new library module.

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
  **The `unix` item is defence in depth, not the wall (G4, §11).** On
  Debian 13's kernel (6.12.111, AppArmor 4.1.0) an `AF_UNIX` connect to
  `/run/dbus/system_bus_socket` succeeded under each of the three profiles
  whose units can make such a socket (run with `aa-exec`, outside the
  units): this kernel does not mediate a connect to a path socket by the
  file rules (`deny ... rw`). Keeping the units from the service manager
  is, by design, systemd's sandbox's part: the namespace unit's
  `RestrictAddressFamilies=AF_NETLINK` (no `AF_UNIX` socket can be made)
  and the `InaccessiblePaths=` over the two sockets on the helper, the
  verify unit and the decoy. **A connect under the units' sandbox** was run
  in the second G4 rehearsal for the decoy and the verify unit only (probe
  copies, §11): refused for both (`PermissionError` under the decoy's
  `InaccessiblePaths=`, `OSError` under the verify unit's
  `RestrictAddressFamilies=AF_NETLINK`); the namespace unit and the helper
  are still unchecked. The profiles keep the two `deny` rules
  for a kernel that mediates path `unix`; that claim belongs to the sandbox
  gate (`HG-09`, §8), not to the LSM gate. (The profiles' result is
  VM-checked; a mechanism check, not hardware evidence.)
- **What the namespace unit's profile allows**: `capability sys_admin
  net_admin`, `network netlink raw`, `/usr/bin/ip` itself (systemd runs it
  under the profile; since the G4 follow-up there is no Python body and no
  child profile, below), and only the mounts `ip` makes (the bind of
  `/proc/*/ns/net` onto `/run/netns/azazel-decoy`, the slave remount of `/`
  and the fresh `/sys` of `ip -n`). The exact mount rules are VM work.
- **What it cannot do.** AppArmor's network rules mediate the family and the
  type, not the netlink protocol, on Debian's kernel (*inferred*): it cannot
  stop a compromised `ip` from talking to nftables. That stays the unit's
  property (fixed command lines, no input) and the watch's (§6). The gate claims only what
  the profile denies.
- **Fail closed twice.** `AppArmorProfile=` without `-` makes a start without
  the loaded profile fail (VM-checked in G4: `231/APPARMOR`; not hardware evidence), and the pass withholds the
  tier unless the profiles are listed in enforce mode (§5 item 4). Booting
  with `apparmor=0` or an `lsm=` list without AppArmor therefore withholds,
  and the units' `AssertSecurity=apparmor` refuses their start (both seen
  on the VM with `apparmor=0`, 2026-10-24, §11; the reading is not yet
  wired into the pass; not hardware evidence).
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
(*inferred*; VM-check). systemd 257 supports `AppArmorProfile=`. The VM
has since shown AppArmor 4.1.0 enabled on Debian 13 (a mechanism check, not
hardware evidence).

### G3 as implemented

The profiles, the units' attachment and the pass's reading exist; **nothing
is granted by them**: `_withholding_reason` still withholds the tier as
`isolation_evidence_absent` on every pass, and the new reasons below are not
reached until G6. Revised after the review of #285.

- **Profiles** (`packaging/apparmor/`): `azazel-decoy-nsd` (with a child
  `azazel-decoy-nsd//ip` in G3; **removed in the G4 follow-up**, below, where
  the child's rules became the profile's), `azazel-decoy-netd` and
  `azazel-decoyd`, named, not attached by path. Every block, the child included, states each claim
  above as an explicit `deny` (a child inherits nothing), plus
  `/lib/systemd` (the installer's unit directory) and the runtime unit paths
  under `/run/systemd`, with **one exception**: the decoy has no `deny` over
  `/var/lib/azazel` (next item). Allowed: the Python body
  (`/usr/bin/python3.13`, code under `/usr/lib/python3.13` and
  `/opt/azazel-nexus/venv` only); `ip` (namespace unit, into the child), `ip`
  and `nft` (helper); the helper's runtime directory as its one writable
  place. In G3 the namespace unit's Python body held **no capability and no
  network**: it only spawned the fixed `ip` commands (`decoy_nsd` never
  called `setns`, `unshare` or `mount`); its child `ip` held `CAP_SYS_ADMIN`,
  `CAP_NET_ADMIN` and netlink, mapped its libraries, and alone could mount
  (since the G4 follow-up these are the one profile's rules, below): only
  what `ip netns add`, `ip netns delete` and `ip -n` make (§13 of the
  prerequisites document; the first bind of `/run/netns` onto itself is
  allowed both as `rbind`, iproute2's `MS_BIND|MS_REC`, and as `bind` until
  the VM shows which). The decoy has `deny capability,`. Rules not confirmed
  on a kernel are marked `INFERRED` in the files. All three compile with
  `apparmor_parser` 4.1.0 (Debian 13 container, without a kernel; not a
  load).
- **The decoy's report.** Its connect to the intake's socket
  `/var/lib/azazel/run/decoy-intake/decoy-intake.sock` is mediated as a
  write to the socket file on a kernel that mediates path `unix` (on
  Debian 13's kernel it is not, G4: see "What each profile must deny"
  above; the intake connect itself was not run on the VM). A `deny` over `/var/lib/azazel` would outrank any
  allow and drop every report, so the decoy's profile has none: its writes
  under `/var/lib/azazel` are refused by the profile's default, and its one
  allow there is `rw` on that socket (pinned by a test). Its AF_UNIX rule is
  a stream client only (no `bind`, `listen` or `accept`); AppArmor 4.1's
  `unix` rules cannot name a path address (`addr=` with a path does not
  compile), so the file rule is what narrows it.
- **The verify unit of §6** has its own profile since G2,
  `azazel-decoy-verify` (§6.3): it runs the helper's executable but writes
  nothing, so it does not share the helper's profile, which may write the
  record.
- **Units:** `ServiceProfile.apparmor_profile`, exactly
  `decoy_apparmor.apparmor_profile_for(unit)`: each of the three names its
  own, rendered `AppArmorProfile=<name>` without `-`, **and
  `AssertSecurity=apparmor`** in `[Unit]`. With AppArmor enabled, a start
  without the profile loaded fails; with AppArmor disabled systemd ignores
  `AppArmorProfile=`, and the assertion fails the start instead, so none of
  the three runs unconfined (seen on the VM with `apparmor=0`, 2026-10-24,
  for copies of the namespace and verify units: `AssertResult=no`, nothing
  started, no namespace created; §11). A failed assertion fails the start
  job and leaves the unit's `Result=success`, so it never starts
  `OnFailure=` (observed the same day; §6.3, §11 item 3). Every other unit names no profile and asserts
  nothing; `AppArmorProfile` is a reserved key of `extra`.
- **The unit-content check** (`activation_unit_files`): an exposure unit's
  `AppArmorProfile=` lines must be exactly the rendered unit's (one line,
  the name, no `-`; removed, doubled, reset or moved is refused, and no
  other unit may gain one); `AssertSecurity=apparmor` is a start guard and
  compared with the others. The loaded-unit check compares the manager's
  `Asserts`, so a unit loaded without the assertion is refused too.
- **The pass's reading:** `decoy_apparmor.exposure_lsm_refusal`, pure, over
  `/sys/kernel/security/lsm` and `/sys/kernel/security/apparmor/profiles`
  (`read_exposure_lsm`, bounded, no link followed). A file that does not
  exist is None (AppArmor absent); one that exists and cannot be read
  (EACCES, EIO, a link) is `UNREADABLE`. Reasons, first that holds:
  `lsm_apparmor_disabled`, `lsm_profiles_unreadable` (an unreadable or
  oversized file, or a required profile's line not in the kernel's form),
  `lsm_profiles_absent`, `lsm_profiles_not_enforced` (the four blocks, each
  only `(enforce)`). Only the lines of the four required names are read
  strictly; other lines do not matter. Only the unit renderer and the
  install plan import the module; a test keeps the pass, the controller and
  the library from doing so before G6.
- **Installer:** `apparmor_parser` (package `apparmor`, not
  `apparmor-utils`) is a required tool with the service manager; the three
  profiles are compiled (`--skip-kernel-load`) before anything is written
  and placed in `/etc/apparmor.d/` 0644; nothing is loaded. With AppArmor
  not among the kernel's LSMs it warns (the units' assertion is the wall).
  After staging, `tools/check_decoy_apparmor_wrappers.py` parses the decoy
  wrappers (three in G3; two since the G4 follow-up, which removed
  `az-decoy-nsd`) and refuses the install unless each interpreter resolves to
  `/usr/bin/python3.13` and each import path under `/usr/lib/python3.13` or
  `/opt/azazel-nexus/venv`; `/usr/local/lib/python3*` and
  `/usr/lib/python3/dist-packages` are not allowed (the wrappers replace
  `sys.path` and never need them). A `DESTDIR` staging run, whose
  interpreter is not the node's, only warns. The offline bundle carries the
  profiles and the check.
- **Tests and containers.** No container or E2E run starts the three units
  (E2E runs the installer with `--without-service-manager` and
  `DESTDIR`), so nothing there needs a loaded profile; no test copy of a
  unit drops `AppArmorProfile=`.
- **Left to G6.** (a) The loaded unit's `AppArmorProfile` is a property of
  the Service interface, which the pass does not read (`loaded_unit` reads
  the Unit interface only); G6 adds that read and compares it. (b) That the
  policy loaded in the kernel is the one placed in `/etc/apparmor.d/`: the
  generation's exposure section digests the files (§4.4 item 5), and G6
  compares the kernel's per-profile policy hash
  (`/sys/kernel/security/apparmor/policy/profiles/*/raw_sha256`) with an
  expected hash recorded at install. **How the expected hash is derived**
  (from the fifth G4 rehearsal, §11; a VM check of the mechanism, not
  hardware evidence): for each of the four decoy profiles the kernel's
  `raw_sha256` equalled both the SHA-256 of the entry's `raw_data` and the
  SHA-256 of `apparmor_parser -Q -o <out> /etc/apparmor.d/<name>`; the
  entry's `sha256` is another value and equals neither, nor the SHA-256 of
  the profile file. So in G6 the installer compiles each placed profile
  with `apparmor_parser -Q -o`, records the SHA-256 of that output in the
  generation's exposure section (the field `apparmor_policy_hashes`: each
  of the four profile names to 64 lowercase hex digits, §9 "G6 preparation
  C"), and the pass compares it with the kernel's `raw_sha256`. The compiled output carries the includes
  (`tunables/global`, `abstractions/base`) as they were when the installer
  compiled, so a later change to an include, or another profile of the same
  name loaded after ours, no longer matches.
  **Checked on that VM only** (AppArmor parser 4.1.0, one VM, the four
  profiles): three compilations with `apparmor_parser -Q -o` gave the same
  output each time, equal to the kernel's `raw_sha256` and to the cache
  file `/var/cache/apparmor/979b3ac6.0/<name>` that `apparmor.service`
  loads at boot. **Still *inferred*, not checked**: what changes the
  compiled output, and with it the kernel's hash, beyond the placed files
  and their includes: the kernel's features and policy ABI (the cache
  directory's name, `979b3ac6.0`, is *inferred* to be a hash of the
  features), `/etc/apparmor/parser.conf`, the `apparmor_parser` version, a
  load through a cache in `/var/cache/apparmor` other than the
  installer's compilation, the flags of the load, and a file holding more
  than one profile. Whichever changes, the honest load no longer matches
  the recorded hash and the tier withholds as `lsm_policy_differs` (closed)
  until the exposure is installed again and the hash re-recorded. **A G6
  requirement**: the installer compiles under the same conditions as the
  load (the same features, `parser.conf` and flags; without the cache, or
  checking that the cache file it loads equals its compilation). Both
  comparisons are
  **implemented, not wired** (§9, "G6 preparation C"); (b) withholds as
  `lsm_policy_unverifiable` until G6 carries the expected hash into the
  generation. The
  receiving half exists: the exposure section carries
  `apparmor_policy_hashes`, and `exposure_generation.expected_policy_hashes`
  gives it in the form `decoy_apparmor.exposure_lsm_withholding` takes as
  `expected`. **The installer's record is implemented (record only; the
  reader is G6's)** (#196 G6 preparation K,
  [wiring §5.2](deception-exposure-wiring.md#52-the-generations-exposure-section)):
  with the service manager, after placing the four profiles,
  `packaging/install.sh` runs `tools/record_apparmor_compiled.py`, which
  compiles each placed file with `apparmor_parser -Q -o <private temporary
  file>` (no other flag) and writes the SHA-256 of each output to
  `/etc/azazel/activation/apparmor-compiled.json` (canonical JSON, contract
  `azazel-nexus/apparmor-compiled/v1`, root `0644`, written atomically);
  `apparmor_compiled.decode_apparmor_compiled` is its strict decoder, with
  the section's rule for the hashes. **Checked on the VM** (Debian 13,
  parser 4.1.0; a mechanism check, not hardware evidence): the four values
  this installer recorded equalled the kernel's `raw_sha256` of the four
  profiles once `apparmor.service` had loaded them. Nothing is loaded, and nothing reads
  the record but the tool checking its own output: `generation-publish`
  copying it into the section is G6's, and nothing in this build writes
  the section's field or calls either function. **The record is
  only as good as what covers it** (review of #303, finding 3): nothing at
  the pass re-derives the hashes, so they are trusted only because the
  exposure section is part of the generation document that
  `generation_digest` covers, and the approval's context binds
  `generation_digest`, so the operator's signature covers the whole
  section. G6 must keep it so; today `verify_exposure_section` checks the
  field's form only.

  **A stale child profile.** Replacing a parent profile does not remove a
  child the kernel already holds: on the VM (Debian 13, AppArmor 4.1; a
  mechanism check, not hardware evidence) `azazel-decoy-nsd//ip`, the child
  of before the G4 follow-up, stayed listed after `apparmor_parser -r` of its
  parent, and was gone after `apparmor_parser -R` of the parent followed by
  `apparmor_parser -r -W`, with the units stopped. That it is gone after a
  reboot is *inferred* (not checked). After G4's runs of the decoy units
  (the helper running `nft` and `ip` repeatedly), no `//null-` child was
  listed. While a child or hat of a required profile is listed, the tier
  withholds as `lsm_profile_child_present`; the installer says so and loads
  nothing; the operator reboots or, with the units stopped, removes the
  parent and loads it again (`operations.md`, "Removing a stale decoy child
  profile"). `aa-remove-unknown` is not used: it removes other tools'
  profiles too.

### The namespace unit after G4 (G4 follow-up, as implemented)

G4 (§11) found that the namespace unit could not start as G3 built it, and
that the verify unit's profile refused `/dev/null`. The owner chose to
change the structure rather than give the Python body `ip`'s rights (`ix`).
Nothing is granted by this either: the tier stays withheld as
`isolation_evidence_absent`, `GRANTABLE_UNITS` and
`ACTIVATION_UNIT_ALLOWLIST` are unchanged, and the bounding set is still
exactly `CAP_SYS_ADMIN CAP_NET_ADMIN`.

- **The unit runs `ip` and nothing else.** `azazel-decoy-nsd.service` has no
  Python body: its six steps are six `ExecStart=` lines and its undo two
  `ExecStopPost=` lines, every one `/usr/bin/ip` with fixed words
  (`hardening.DECOY_NAMESPACE_START` and `DECOY_NAMESPACE_UNDO`, rendered and
  compared byte for byte; `ServiceProfile` pins the executable, the first
  line's words and the rest of the extra whole; a word outside
  `[A-Za-z0-9./_-]`, with at most a leading `-`, is refused, so no `%`
  specifier, `$` variable, quote or space reaches systemd's parser).
  `az-decoy-nsd`, `decoy_nsd.py`, `decoy_network.NAMESPACE_STEPS` and its
  plan are removed; the console script, the installer's required wrapper,
  the wrapper check's target and the import-closure pins go with them.
- **One profile.** `azazel-decoy-nsd` now holds exactly what the `ip` child
  held: `capability sys_admin` and `net_admin`, `network netlink raw`, `ip`'s
  libraries and data, the fixed mounts of `ip netns add`, `ip netns delete`
  and `ip -n`, and the gate's denies. No Python, no interpreter, no `x`
  rule, no child, so the enforce-mode judgement requires four profiles,
  not five. systemd attaches it on exec (`AppArmorProfile=`), so there is no
  transition for `NoNewPrivileges=yes` to refuse (*inferred*; VM item 4).
- **What the body did, and where it is now:**

  | property of the body | in the unit |
  | --- | --- |
  | fixed arguments, no input | the unit file's lines; no `Environment=`, no file, no socket, no argument from anyone |
  | 2 s per step (`STEP_SECONDS`) | `TimeoutStartSec=30s` for the six together, and `TimeoutStopSec=30s` for the undo, which systemd re-arms for each `ExecStopPost=` command (observed on the VM, 2026-10-24, systemd 257.13; §11), so up to 30 s per undo command. **Weaker**: one stuck `ip` may now take the whole 30 s before systemd kills it; the start then fails and the undo runs. systemd has no per-command deadline for the start. **And an undo command that exceeds `TimeoutStopSec=` ends the undo** (observed the same day): systemd terminates the stop-post state with `Result=timeout` and does not run the `ExecStopPost=` lines after it, `-` or not. If `ip link delete az-decoy-host0` hangs, `ip netns delete azazel-decoy` never runs: the namespace stays, and with it the decoy's end of the pair, so `az-decoy-host0` too unless the hung command removed it first; the unit ends `failed`. That is a leftover for the residue judgement (`exposure_leftovers_present`, §6.3 "For G6" (a); implemented, wired in G6), which then withholds the tier: closed, but cleaned by hand ([operations](operations.md#deception-lite-decoy-network-196)) |
  | a failed step undoes the earlier ones | `ExecStopPost=`: a one-shot unit stops at the first `ExecStart=` that fails, and systemd runs `ExecStopPost=` after a start that failed or timed out, and after every stop; `ExecStop=` only after a start that succeeded (systemd.service(5), systemd 257) |
  | stop runs every undo in reverse | the same two `ExecStopPost=` lines: the pair, then the namespace. `-` on the first only: a failing command skips the ones after it (so does one that times out, `-` or not; the row above), and the pair is absent whenever the start failed before step 2; the namespace's removal keeps its status |
  | something already present | `ip netns add` fails (`File exists`), the start fails at step 1 and nothing else runs: **closed**. **Changed**: the undo then removes the namespace and pair of those names, which the body left alone ("not ours to remove") |
  | empty environment, `SIGPIPE` at its default | systemd's environment for a system unit (none set here), signals reset on exec; *inferred* that `ip` reads nothing from it that changes these commands |

  **Why the one change is accepted.** systemd cannot make an undo depend
  on which `ExecStart=` failed without a shell or a program of ours, and
  either would bring back a body. The names are the decoy's own
  (`azazel-decoy`, `az-decoy-host0`; the scope decoder already refuses
  interface names with the `az-decoy` prefix), so an object of that name is
  a leftover of an earlier run or a conflicting use of a reserved name.
  Removing it removes a path and opens none, and the start has already
  failed, so nothing is built on top of it. A stale namespace is therefore
  cleaned by the failed start, and the next start can succeed.
- **`attach_disconnected` on all four profiles.** Under systemd's sandbox a
  path can be disconnected from the process's root (the verify unit's
  `/dev/null` under `PrivateDevices=`); without the flag its lookup fails and
  the access is refused. With it the path is named from its own mount's root
  as if that were `/`. **What it weakens:** nothing that the rules state,
  every rule, the denies included, still applies to the name; what it could
  alias is a file reached through a detached mount that names itself as
  something else (a bind of `/etc/azazel` detached and named `/x`). Making
  such a mount needs `CAP_SYS_ADMIN` and a `mount` rule: the helper, the
  verify unit and the decoy have neither, and the namespace unit's mounts
  are only `ip`'s fixed ones (none of them a bind from the denied paths).
  This rests on an assumption, stated here: the namespace unit's `rbind`
  and `bind` of `/run/netns/` onto itself only carry what is under
  `/run/netns/`, and the profile gives no means of placing a denied path
  there (no other mount or bind rule, and no write to `/run/netns` but the
  directory and the one handle).
  **`attach_disconnected.path=/.azazel-nsfs/` on the namespace
  unit's profile alone (G4).** The network namespace `ip netns add` opens
  is an nsfs file, itself a disconnected path. With `attach_disconnected`
  alone it is named `/`: the VM refused its open (`operation="open"
  name="/"`) and its bind onto the handle (`operation="mount" info="failed
  srcname match" srcname="/" flags="rw, bind"`). Allowing that bind would
  take `mount options=(rw, bind) / -> /run/netns/azazel-decoy`, and that
  rule would equally let the host's real, connected `/` be bound onto the
  handle, where every denied path is reached again under another name
  (`/run/netns/azazel-decoy/etc/azazel/...`), escaping the denies by
  aliasing. With the prefix, only what is disconnected is named
  `/.azazel-nsfs/`, and the real `/` keeps its own name; the profile
  allows `/.azazel-nsfs/ r` (the prefix alone, nothing under it) and
  `mount options=(rw, bind) /.azazel-nsfs/ -> /run/netns/azazel-decoy`,
  and no rule names `/` as a source. The earlier bind rule from
  `@{PROC}/@{pid}/{,task/@{tid}/}ns/net` was not used on the VM; it is
  kept, because another kernel may name the source by its `/proc` path.
  The VM also showed that `ip netns add` flocks `/run/netns/`
  (`operation="file_lock" requested_mask="k"`), so that directory's rule is
  `rwk`. The other three profiles carry `attach_disconnected` alone; no
  other flag; a test pins both. The VM ran the prefix as
  `/azazel-disconnected/`; after the review of #289 it is
  `/.azazel-nsfs/` (a dot name, less likely to collide), re-checked in the
  second G4 rehearsal: the namespace unit, the helper, the decoy and the
  verify unit started with no denial (§11; a VM check, not hardware
  evidence). **Assumption:** no real `/.azazel-nsfs` exists on the host.
  A connected path of that name would carry the same name as the
  disconnected nsfs, and the two prefix rules (a read of the directory
  itself, its bind onto the handle) would apply to it as well. Nothing in
  the installer creates it.
- **The decoy's `/proc/<pid>/net/dev` (G4).** The decoy reads it without
  `owner`: `/proc/<pid>/net` is owned by root, not by the decoy's account,
  and the `owner` rule was refused (`operation="open" fsuid=979 ouid=0`).
  **What that widens:** without `owner` the rule matches every pid, PID 1's
  included, whose `net/dev` lists the host namespace's links. **What
  closes it (review of #289 F1):** `azazel-decoyd.service` has
  `ProtectProc=invisible`, so other users' processes are not in the
  decoy's `/proc` at all and only its own pids remain for the rule to
  match (pinned in `ServiceProfile` and by tests). Not `ProcSubset=pid`:
  it hides `/proc/sys`, and the decoy reads
  `/proc/sys/kernel/random/boot_id` for its isolation check
  (`decoy_isolation_check`, `azazel_nexus.boot_id`). The decoy's own
  namespace check already treats `/proc/1/ns/net` as unreadable. Under a
  probe copy of the unit with `ProtectProc=invisible` (second G4
  rehearsal, §11; a VM check, not hardware evidence) `/proc/self/net/dev`
  and the boot id were readable and `/proc/1/net/dev` was not there
  (`FileNotFoundError`).
- **Checked so far, without AppArmor** (a privileged Debian 13 container
  with systemd 257.13 as PID 1 on colima's kernel; the rendered unit with
  only its `AppArmorProfile=`, `AssertSecurity=`, grant-marker and controller
  lines removed; a mechanism check of systemd's sequencing, **not VM or
  hardware evidence**): `systemd-analyze verify` accepts the unit; a clean
  start built the namespace, the pair, the address and the default route,
  and a stop removed both; with `/run/netns/azazel-decoy` already present
  the start failed at step 1 (`File exists`) and `ExecStopPost=` removed it;
  with a link `az-decoy-host0` already present the start failed at step 2
  (`RTNETLINK answers: File exists`) and `ExecStopPost=` removed it and the
  namespace; a start after each failure succeeded. The four profiles
  compile with `apparmor_parser` 4.1.0 (no kernel load). Everything under
  AppArmor, and the timeout path, is §11 item 4; the G4 rehearsal results in §11 record which parts were since seen on a VM.

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
| service manager | the same probe connecting to `/run/dbus/system_bus_socket` and `/run/systemd/private`, and `systemctl unmask` | refused for every unit; by design **the sandbox's part**: no `AF_UNIX` socket for the namespace unit (`RestrictAddressFamilies=AF_NETLINK`), the two sockets absent under `InaccessiblePaths=` for the others (observed refused under probe copies of the decoy and the verify unit in the second G4 rehearsal, a VM check; not yet for the namespace unit and the helper). Not credited to AppArmor: on Debian 13's kernel the profiles' `deny ... rw` did not refuse a path connect (G4 with `aa-exec`, §7) |
| activation state | the probe writing under `/run/azazel-activation`, `/etc/systemd/system`, `/usr/lib/systemd/system`, `/var/lib/azazel/state` | refused for every unit (for the namespace unit, by the LSM) |
| IP filter | `bpftool cgroup show` on each unit's cgroup | the ingress and egress programs are attached; a kernel without cgroup BPF makes systemd skip the filter with only a warning, so absence is a failure |
| namespace | the decoy's `/proc/self/ns/net` against `/run/netns/azazel-decoy`; its links | same namespace; only `lo` and `az-decoy-ns0` |
| user namespace | the decoy's `uid_map` | a single mapping of its own account (see the note below the table) |
| limits | the decoy's cgroup `memory.max`, `pids.max` | `128M`, `16` |
| LSM | `/proc/<pid>/attr/current` (or `attr/apparmor/current`) | the unit's profile, `(enforce)` |
| exposure score | `systemd-analyze security <unit>` | recorded per unit, no threshold; a change between runs is reviewed |

Recorded as a HIL record under the virtualization negative filter, per
hardware class; a VM run of the same table is a rehearsal only. The probe
copies are removed after the run and never packaged.

**Note on the user namespace row (G4).** The VM rehearsal (§11) showed the
decoy's `uid_map` as two lines, `0 0 1` and `979 979 1`: systemd 257's
`PrivateUsers=yes` maps root as well as the unit's own account. The row's
"a single mapping of its own account" does not match that. Which one the
gate accepts (the row amended to "root and its own account, each to
itself, nothing else", or a change of the unit) is decided in `HG-09`; until
then a run that shows the two lines is recorded as it is, not as a pass.

**Gate bookkeeping.** `HG-08` is reserved by
[commissioning storage at boot](commissioning-storage-at-boot.md) §5 Q7.
Proposed: `HG-09` for this sandbox gate (its claim includes that no unit
can reach the service manager, which the address families and
`InaccessiblePaths=` are designed to hold; observed on the VM under the decoy's and the verify unit's copies, still to be observed for the namespace unit and the helper) and `HG-10` for the LSM gate of §7 (its claim: under
the profiles, the units cannot write the activation state, the grant
markers or the unit files). "Cannot reach the service manager" is not an
AppArmor claim: on Debian 13's kernel the profiles did not refuse a path
connect to the D-Bus socket (G4, §7, §11); their `deny` rules for the two
sockets are defence in depth. Numbers are provisional until added to
[hardware gates](hardware-gates.md).

## 9. Phases

Each phase is one or more small PRs. Until G6 the tier stays withheld on every
pass and the existing tests that pin it stay.

| phase | content | needs |
| --- | --- | --- |
| G0 | this proposal; owner decisions (§10) | — |
| G1 | the scope: proposal v3 and its decoder (§4.1, §4.2); the rendered scope and its reader (§4.3); the ruleset, plan and `nft -j` check from the scope; isolation contract v2; masquerade (A3); the reply accept's `oifname { <ingress> }` and the ingress drop of [reachability](deception-exposure-reachability.md) R3; unit tests only, nothing wired into the pass | Q1–Q4 |
| G1a *(implemented)* | the first half of G1: `commissioning-proposal/v3` (v2 plus a required `deception_scope`, `src/azazel_nexus/commissioning_approval.py`, `fabric_boundary.restore_commissioning_inputs`; M.I.O. reads its signed `mio_profile` from v2 and v3 alike), the strict decoder, the rendered scope file and its reader (`src/azazel_nexus/decoy_scope.py`, a standard-library leaf under the helper's boundary rules); tests only (`tests/unit/test_decoy_scope.py`, `tests/unit/test_commissioning_approval.py`); nothing calls it from the pass or the helper, no unit file changes. The ruleset, `nft -j`, isolation v2, masquerade and `LoadCredential=` are G1b | Q1–Q3 |
| G1b *(implemented)* | the second half of G1: the helper's input (`LoadCredential=decoy-scope:/run/azazel-activation/decoy-scope.json` on `azazel-decoy-netd.service`, pinned in `DECOY_HELPER_SANDBOX`, no `SetCredential=` fallback, no other unit may load it; `decoy_scope.read_scope_credential`, read after the previous isolation record is removed; a scope present and refused builds nothing and leaves no record); the ruleset from the scope, one transaction (`decoy_network.render_ruleset`: `elements`, quoted `iifname { ... }` on the accept, `oifname { ... }` on the reply and the ingress drop of [reachability](deception-exposure-reachability.md) R3, the A3 masquerade in a `postrouting` `nat` chain; without a scope the table of the first build); `_ALLOWED` replaced by a per-run `Plan` (the constants plus exactly the one ruleset); the check moved to `nft -j list table` against the expected listing rendered with the ruleset; `decoy-isolation/v2` with `approved_v4_matches`, `ingress_matches` (the ingress name set and its count; placement is `nft_table`'s) and `scope_digest`, v1 refused by the decoy; the check sees only its own table; the helper's import closure gains `azazel_nexus.decoy_scope` only. Container-checked with nftables 1.1.3 (a mechanism check): an anonymous set of names is listed reordered and, with one name, as the name; a /32 element as a bare address; adjacent prefixes are kept apart, overlapping ones refuse the whole transaction, duplicates are merged; the real helper loaded and checked scopes of 1 and 2 ingress, 3 and 16 prefixes, and an approved forwarded connect reached the decoy as `10.255.196.1`. Until G6 nothing writes the scope file, so a granted helper would fail to start; the tier stays withheld | Q1–Q4 |
| G2 *(implemented)* | the watch (§6.3): `azazel-decoy-verify.service` (one-shot, `az-decoy-netd verify`, the helper's executable, sandbox and scope credential, read-only plan `decoy_network.verify_plan`, `OnFailure=` the trip unit, no marker, no `[Install]`); `azazel-decoy-verify.timer` (10 s, `AccuracySec=1s`, `PartOf=` the decoy); the trip unit as `azazel-decoy-trip.target` (only `Conflicts=azazel-decoy-nsd.service`; since the G4 follow-up `Conflicts=` on all three, §6.3; a service with no command is refused by systemd); the decoy's `Requires=` on the verify unit and the timer and `After=` on the verify unit; the helper's `After=` on `firewalld.service` and `netfilter-persistent.service`; the verify's re-reading of [reachability](deception-exposure-reachability.md) R4 (forwarding and `proxy_arp`, the rules before `main` down to priority, `iif` and the K1 pair's defining attributes, the routes of `main` in the /24; since #196 R4's remainder the rules are compared whole by the pass's comparison, §6.3); its own AppArmor profile `azazel-decoy-verify`, required in enforce mode; the three files rendered and compared byte for byte, and `require_watch_unit_files` (byte-exact, no drop-in, no mask) defined but not called by the pass and not digested by the generation until G6; unit tests only, nothing run under systemd | Q6, Q7 |
| G3 | AppArmor profiles, `AppArmorProfile=`, the pass's reading of enforce mode (as a withholding reason that is never reached yet); installer adds the package | Q8 |
| G4 | VM rehearsal of G1–G3 with markers placed by hand and a VM-only rehearsal key (never evidence); the items of §11 | G1–G3 |
| G5 | hardware: `HG-06`, `HG-09`, `HG-10` on the real host | G4, owner |
| G6 prep: the v3 decoder, not wired *(implemented)* | condition 1 of §5 C1 as a part only: `azazel-nexus/activation-approval/v3` (`src/azazel_nexus/activation_approval_v3.py`), the v2 fields under the v3 schema name plus the three `DECEPTION_EXPOSURE` units, all three or none (a document naming one or two of them cannot be encoded, decoded or verified); the strict decoder (exact field set, no duplicate key, canonical re-encoding) and a verifier through the existing operator trust and the `ACTIVATION` purpose, returning its own result type. **Not connected:** the pass still reads v2 only and requires an `ObserveBaselineApproval`; `tools/operator_sign.py` cannot sign v3; `ACTIVATION_UNIT_ALLOWLIST`, `GRANTABLE_UNITS`, the policy scope and `_withholding_reason` are unchanged, so a v3 approval naming the tier is refused at the scope check. Tests with keys generated per test pin each of these (`tests/unit/test_activation_approval_v3.py`, `tests/unit/test_runtime_activation_pass.py`), and `tests/unit/test_g6_unwired.py` that nothing outside the tests imports or names the module. Wiring it into the pass and the signer is G6 | G5 not required (grants nothing) |
| G6 | the grant: approval v3, the allowlist and policy scope, the generation's exposure section, the pass rendering the scope, the conditions of §5 in `_withholding_reason`, the changed tripwire; the two open items of §6.3 "For G6" (a running exposure unit whose definition a mask removed, and whether the controller stops what it masks, with no new unit operation); an isolation record whose `scope_digest` is `none` (a helper run without a scope) is refused by the pass and the grant path, and a granted decoy requires the digest of the scope the pass rendered; a VM rehearsal of grant → reboot → start and of each refusal on the branch before merge; merged only after G5 is accepted. **Preparation A (implemented, not wired):** the pass's judgement of [reachability](deception-exposure-reachability.md) §6 (R1, R2, R5; `decoy_reachability.pass_reachability_departures`, with the reads and the verify's R4 judgement moved into the same module, the verify unchanged) and the detection of item (a) of §6.3 (`decoy_residue.exposure_residue_departures`); both pure, called by nothing, the tier still withheld as `isolation_evidence_absent`. When G6 uses approval v3, a dedicated `ApprovalPurpose` (for example `ACTIVATION_EXPOSURE`) is to be considered, so that a signature made for the observe-baseline purpose cannot be reused for the exposure tier. **Preparation D (implemented, not wired):** the resolution of §4.3 and of [reachability](deception-exposure-reachability.md) §6 "Interfaces" (`src/azazel_nexus/exposure_interfaces.py`, `resolve_role_interfaces`): from the verified v3 proposal (`fabric_boundary.restore_commissioning_inputs` and `deception_scope_assignments`), this boot's inventory (compared whole with the retained one by `assert_current_inventory_matches`) and the decoded `DeceptionScope`, each assignment is resolved by `identify_interface` and only the one interface it resolves to gives a kernel name: the `deception_bridge` names, sorted, for `decoy_scope.render_scope_file`, and the `management` and `observation` names for the pass's reachability judgement (either may be empty: such an interface is "every other interface" there). A proposal that cannot be restored or carries no scope, a scope that is not the proposal's, an inventory that is not the commissioned one (a rename included), an identity matching no interface, several or one without a name, an interface in two roles or a name of two interfaces, and a name outside §4.3 (`interface_name_allowed`) each withhold with a fixed `role_*` code and phrase that carries no name or identity; no name substitutes for a role. G6 passes it only a proposal whose signature the pass has verified; the function verifies none. Pure, called by nothing: nothing writes `/run/azazel-activation/decoy-scope.json`, and the tier is still withheld as `isolation_evidence_absent` (`tests/unit/test_exposure_interfaces.py`, `tests/unit/test_g6_unwired.py`). **Not wired, pinned in one place** (#196 L1): `tests/unit/test_g6_unwired.py` holds one table of every part above (approval v3 and preparations A, C and D, and preparation K's record decoder `apparmor_compiled`, which the installer's tool alone may import, §7 "Left to G6"): `IMPORTERS`, each part's module and the exact files that may import it, and `NAME_FILES`, each public name and reason code and the exact files that may contain it. One scan of every file the repository tracks outside `tests/` and `docs/` (`git ls-files`; static imports, and the strings of `importlib`, `__import__` and `runpy` calls) is compared with it, and fails without git or with an empty listing; a pass with every part replaced by one that fails when called still withholds the tier as `isolation_evidence_absent`. **G6 changes only that table** (the pass, the controller or the library added to the files of what it calls); the scan, the poisoned pass and the check of `_withholding_reason`'s branch are replaced, not loosened, only when the tier is granted | G5, Q5, Q10, Q11 |

P5 and P6 of the prerequisites document (decisions, redirect) are unchanged
and come after G6.

How G6 connects these parts (the order in the pass, approval v3, the
generation's exposure section, the scope file, the tripwire, its tests and
VM rehearsal) is proposed in
[wiring the exposure grant](deception-exposure-wiring.md).

### G6 preparation C (implemented, not wired)

Parts of G6 built ahead of it as pure functions and bounded readers.
**Nothing calls them**: no module of the pass, the controller or the library
imports them, `_withholding_reason` still withholds the tier as
`isolation_evidence_absent` on every pass, and `GRANTABLE_UNITS`,
`ACTIVATION_UNIT_ALLOWLIST`, the policy scope and the observe-baseline
generation schema are unchanged. No bus call, unit operation, approval field,
flag or environment variable is added. `tests/unit/test_exposure_g6_parts.py`
pins each part; `tests/unit/test_g6_unwired.py` pins that none is reached (a
pass with every part replaced by one that fails when called still withholds
the tier, and calls none), for every G6 part at once (§9, G6).

- **The generation's exposure section** (§4.4 item 5, §5 C1 condition 2;
  `exposure_generation`). `build_exposure_section` digests (`sha256:<hex>`)
  the three exposure unit files, the watch's three (§6.3), the four profile
  files of `/etc/apparmor.d` (§7) and the rendered scope file
  (`scope_digest`, accepted only as `decoy_scope.parse_scope_file` accepts
  it); `verify_exposure_section` compares a recorded section with a fresh
  measurement, one fixed label per difference.
  `measure_exposure_section_inputs` reads them the way the observe-baseline
  generation reads its unit files: the exposure units through
  `activation_unit_files.measure_exposure_unit_files` (content, override
  and drop-in checks, over `EXPOSURE_UNITS`, outside the allowlist), the
  watch through `require_watch_unit_files`, which now returns the bytes it
  compared so the digest is of exactly what it accepted, and the profiles
  with the same file protections. The scope file is not read: the pass
  renders it in G6. Not digested: Debian's `tunables/global` and
  `abstractions/base`, which the profiles include; the kernel-hash
  comparison below is what would catch a change there. The section also
  records `apparmor_policy_hashes` (review of the G6 preparation, M2): each
  of the four profile names to the 64 lowercase hex digits the kernel
  should show as `raw_sha256`. It is a record, not a measurement:
  `build_exposure_section` takes it as given and checks its form,
  `verify_exposure_section` checks its form and does not compare it with
  the files, and `expected_policy_hashes` hands it to the LSM judgement
  below as `expected` (G6 treats its `GenerationRefused` as
  `exposure_section_unverifiable`, never as an expectation to skip). The
  installer records the hashes it is to hold (§7, "Left to G6", G6
  preparation K); no generation this build writes carries the section, and
  `generation-publish` copying the record into it is G6's. The record
  is trusted only because the section is inside the generation document
  that `generation_digest` covers and the approval's context binds that
  digest, so the operator's signature covers the whole section (review of
  #303, finding 3); the form check here is all this build does. A section, set, scope or file not in its closed form is
  `exposure_section_unverifiable`; a recorded digest that is not the
  measured one is `exposure_section_differs`; the readers keep their
  exception types with that code. **The generation schema version that
  carries the section is introduced in G6.**
- **Coexistence** (§6.2, §10 Q12; `exposure_withholding.host_firewall_refusal`).
  Input: the unit-file state and the `ActiveState` of each of
  `nftables.service`, `firewalld.service` and `netfilter-persistent.service`
  as the bus gives them, None when systemd has neither a unit file nor a
  unit object. A unit passes only when its file state is `disabled`,
  `masked` or `masked-runtime` **and** it is `inactive`, or when it is None.
  Every other file state, `static` and `indirect` included, is
  `host_firewall_enabled`; a disabled or masked unit in any state but
  `inactive` (`failed` and `activating` included) is `host_firewall_active`;
  a value not read or unknown is `host_firewall_unreadable`. The active
  state is required because a `disabled` unit still starts through another
  unit's `Wants=` or `Requires=`, by hand or by D-Bus activation (review of
  #294 F1).
- **`fb_tunnels_only_for_init_net`** (§5 C1 condition 6;
  `exposure_withholding.fb_tunnels_refusal`, `read_fb_tunnels`): only the
  bytes `2\n` pass; absent or unreadable is `fb_tunnels_unreadable`, any
  other value `fb_tunnels_not_init_net_only`. The forwarding half of condition 6 is
  [reachability](deception-exposure-reachability.md)'s and not here.
- **The LSM** (§5 C1 condition 4, §7 "Left to G6";
  `decoy_apparmor.exposure_lsm_withholding`, reader
  `read_exposure_lsm_policy`): G3's `exposure_lsm_refusal` (after its own
  codes, a line of a child profile or hat of a required profile,
  `<name>//...`, in any mode, is `lsm_profile_child_present`: none is
  expected, review of the G6 preparation, L5, and of #303, finding 5; §7
  "A stale child profile"), then
  `loaded_unit_profile_refusal` (each of the four units not loaded, an
  exposure unit `masked`, or `loaded` with `AppArmorProfile` exactly
  `(false, <its profile>)`; otherwise `lsm_unit_profile_differs`; the
  property is the Service interface's `(bs)`, *inferred* from
  org.freedesktop.systemd1(5) until read on the VM; passing `masked` does
  not look at `ActiveState`: "masked and still running", §6.3 (a), is
  `decoy_residue`'s judgement, a separate PR, #293), then
  `policy_hash_refusal` over `read_policy_hashes`, which lists
  `/sys/kernel/security/apparmor/policy/profiles/*/{name,raw_sha256}`.
  On the VM (fifth G4 rehearsal, §11; a mechanism check, not hardware
  evidence) each entry held `attach mode name raw_abi raw_data raw_sha256
  sha256`, no `sha1`; `raw_sha256` is the SHA-256 of the compiled policy
  (equal to that of `raw_data` and of `apparmor_parser -Q -o` output), and
  `sha256`, another value, is not read: an entry with `sha256` and no
  `raw_sha256` withholds. On that kernel `raw_sha256` is a symbolic link,
  `../../raw_data/<n>/sha256` (checked, §11). The reader does not follow
  it: it reads the link (`readlink` relative to the entry), accepts only
  exactly that form with `<n>` a decimal number (an absolute path, `..`
  elsewhere, a name that is not a number all withhold), and opens
  `/sys/kernel/security/apparmor/policy/raw_data/<n>/sha256` from that
  fixed directory, each step without following a link; a target that does
  not exist withholds. Only the observed form is accepted: a regular file
  `raw_sha256`, or any error reading the link, withholds. Whether `<n>` is
  the entry's own number is not checked: the link is the kernel's, and it
  is trusted. A required profile listed not exactly once, a hash absent,
  empty or not one lowercase hex digest, or no expected hash is
  `lsm_policy_unverifiable`; a different hash is `lsm_policy_differs`.
  The expected hashes are the exposure section's `apparmor_policy_hashes`
  (`exposure_generation.expected_policy_hashes`). **This build records no
  expected hash**, so the comparison fails closed; G6 records it at install
  (§7, "Left to G6").
- **An enforcing unit and the exposure tier** (§6.2;
  `azazel_nexus.exposure_exclusivity.exposure_enforcement_conflict`, input
  the governed set). A set holding the exposure tier and any
  `UnitTier.ENFORCEMENT` unit is `exposure_enforcement_exclusive`; anything
  that is not a sequence of unit definitions is
  `exposure_enforcement_unreadable`. A
  `UnitDefinition` carries no Edge posture, so every enforcement unit is
  counted, not only Edge's (the wider choice); today's `CORE_UNITS` hold
  none, and Edge Core is `EDGE_BASELINE`, observe-only. G6 makes the
  controller refuse such a set.

Each part has its own reason codes; the order in which G6 asks them, and
where in `_withholding_reason`, is G6's. **One form for all** (review of the
G6 preparation, M1): every part, as preparations A and D already did, says
`"<code>: <phrase>"` with a fixed phrase per code from its `*_PHRASES`
dictionary (`HOST_FIREWALL_PHRASES`, `FB_TUNNELS_PHRASES`, `LSM_PHRASES`,
`EXPOSURE_ENFORCEMENT_PHRASES`, `EXPOSURE_SECTION_PHRASES`, and approval
v3's `APPROVAL_V3_PHRASES`, whose phrases are its former wording and whose
exception type, shared with v2, is unchanged); no phrase holds a count, a
name or a value, and a value not read has its own code, never the code of
the judgement it could not make. `tests/unit/test_exposure_reason_codes.py`
pins that the codes of all parts are distinct, that none is a string
elsewhere in the product (the activation reason codes among them), and that
each phrase is a constant. The verify (G2) and the pass share the
reachability codes `forwarding_other_on` and `decoy_prefix_routed` with
narrower meanings in the verify (the bridge `az-decoy0` and the one
connected /30 are allowed there); the names are kept for the records
already written, the verify journals the codes alone, and the phrases say
the pass's meaning (`decoy_reachability.REACHABILITY_CODES`).

**Open until G6** (review of #294):

- **None means "not there" only through the G6 reader.** The coexistence
  and loaded-unit judgements pass None (no unit file and no unit object;
  no unit object). The G6 reader turns into None only the specific errors
  that mean exactly that (`NoSuchUnit` from `GetUnit`, the unit-file
  lookup's not-found) and refuses every other error; that reader and its
  tests are G6's, not this PR's.
- **The coexistence check is a snapshot.** `disabled` and `inactive` at the
  pass do not stop a loader started later in the boot by another unit's
  `Wants=`, by hand or by D-Bus activation; the watch (§6.1) is what sees
  its flush.
- **Another profile file of the same name.** The section digests
  `/etc/apparmor.d/<name>` only. Another file in `/etc/apparmor.d` (or a
  file it includes) may define a profile of the same name and, loaded after
  ours, replace it. The enforce-mode listing does not see that; the
  kernel-hash comparison would.
- **The kernel hash closes these holes only if the expected hash covers
  the includes.** An expected hash computed from the placed file alone
  would differ from the kernel's for every honest load (the kernel hashes
  the compiled policy, `tunables/global` and `abstractions/base` included)
  or, if computed at the pass from a compilation that reads the current
  includes, would accept an include changed before the pass. **There is now
  a way to close it** (fifth G4 rehearsal, §11; a VM check of the
  mechanism): the kernel's `raw_sha256` equals the SHA-256 of
  `apparmor_parser -Q -o` output, so G6's installer records that digest in
  the generation's exposure section when it compiles, which fixes the
  includes' content at that moment, and the pass compares the kernel's
  `raw_sha256` with the record (§7, "Left to G6"). Still open: nothing
  records the digest yet (G6), and what besides the files changes the
  compiled output (features, `parser.conf`, the parser's version, a cache,
  load flags, several profiles in one file; *inferred*, §7) then needs a
  reinstall.

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
    ingress interfaces and off for management and observation]** Written
    out in [how outside peers reach the decoy](deception-exposure-reachability.md),
    which adds five narrowing conditions (its §9, R1–R5), adopted as
    defaults the owner may overturn, and one open question for the owner
    (R6, its reading of commissioning §2).
12. Firewall coexistence? **[the tier is withheld while `nftables.service`,
    `firewalld.service` or `netfilter-persistent.service` is enabled; Edge
    enforce posture and the tier mutually exclusive until Edge agrees on
    table scope]**

## 11. To check on the VM (G4; a mechanism check, not hardware evidence)

**G4 findings (2026-10-22, Debian 13, AppArmor 4.1; a VM check of the
mechanism, not hardware evidence).** Two of item 4's questions were
answered, both against G3:

- **The namespace unit could not start.** Its Python body, confined as
  `azazel-decoy-nsd` under `NoNewPrivileges=yes`, executed `/usr/bin/ip` with
  `Cx -> ip`, and the kernel refused the transition into the wider child:
  `apparmor="DENIED" operation="exec" info="no new privs"
  profile="azazel-decoy-nsd" name="/usr/bin/ip"
  target="azazel-decoy-nsd//ip"`. The first step returned 127 (the body's
  "could not start") and the start stopped there, so it failed closed. Under
  `NoNewPrivileges=yes` a process may not move to a profile wider than its
  own. Resolved by the G4 follow-up (§7, "The namespace unit after G4"): no
  body, `ip` run by systemd under one profile; the `ix` fallback was not
  taken.
- **The verify unit's profile refused `/dev/null`:**
  `operation="getattr" info="Failed name lookup - disconnected path"
  profile="azazel-decoy-verify" name="dev/null"`, under systemd's sandbox
  (`PrivateDevices=` and the like make mounts disconnected from the
  process's root). Resolved by `flags=(attach_disconnected)` on all four
  profiles (§7; what that does and does not weaken is stated there).

### G4 rehearsal results (2026-10-22, VM; mechanism check, not hardware evidence)

Debian 13 VM, kernel 6.12.111+deb13-arm64, AppArmor 4.1.0, systemd 257;
`main` c11c4a5 with the two candidate profile changes now in
`packaging/apparmor/` (the namespace unit's `attach_disconnected.path`, its
prefix rules and `rwk` on `/run/netns/`; the decoy's `net/dev` without
`owner`; §7). The VM ran the prefix as `/azazel-disconnected/`; it was
renamed to `/.azazel-nsfs/` after the review of #289, and the decoy's
`ProtectProc=invisible` was added after the run (§7); both were checked in
the second rehearsal below. The grant markers were placed by hand, the
scope was a VM-only file, and the units ran as copies without
`Requires=`/`After=azazel-activated.service`. Nothing was granted by the
pass. **This is a check of the mechanism on a VM, not hardware evidence**,
and it is no record for `HG-06`, `HG-09` or `HG-10`.

| what | observed | result |
| --- | --- | --- |
| start | `azazel-decoy-nsd`, `-netd`, `azazel-decoyd`, `azazel-decoy-verify` and its timer all `active` | ok |
| isolation record v2 | all nine checks `pass`, `scope_digest` present | ok |
| verify, R4 included | "the table, the host's links, forwarding, the routing rules and the routes match", every 10 s | ok |
| masquerade (A3), item 1 | approved source `172.31.250.2/32` (ingress `azin0`, the two K1 rules, `forwarding=1` on `azin0` and `az-decoy0`): the fake banner on 2222, 2323 and 8080; unapproved `172.31.250.3`: all three timed out. The decoy's cgroup allows only `10.255.196.0/30`, so the approved source arriving shows the masquerade indirectly | ok |
| decoy confinement (§8 rows) | `attr/current` `azazel-decoyd (enforce)`; `CapPrm`, `CapEff`, `CapBnd`, `CapAmb` all 0; `NoNewPrivs` 1; `Seccomp` 2 | ok |
| decoy `uid_map` (§8 row) | two lines, `0 0 1` and `979 979 1` (`PrivateUsers=yes` maps root and the account) | **differs from the §8 row**; noted there, decided in `HG-09` |
| trip (item 3) | `nft delete table inet azazel_decoy`: about 2 s later the verify failed, `OnFailure=` started `azazel-decoy-trip.target`, and the three units stopped in order; nothing left behind. Starting the namespace unit again stopped the target (`Conflicts=`) and all three came back `active` | ok (closed) |
| helper after the trip | `azazel-decoy-netd` ended `failed` after its stop (inferred: its `ExecStop=` cleanup failed because the table was already gone) | closed-side; recorded in [operations](operations.md) |
| AppArmor, writes (item 4) | under the decoy's, the helper's and the verify unit's profiles (`aa-exec` with `python3.13`), writes to `/etc/azazel`, `/run/azazel-activation/granted`, `/etc/systemd/system` and `/var/lib/azazel` all refused | ok |
| AppArmor, profile missing (item 4) | the decoy started with its profile unloaded: `231/APPARMOR` ("Failed at step APPARMOR") | ok (fails closed) |
| AppArmor, service manager sockets | with `aa-exec` (outside the units), under each of the three profiles an `AF_UNIX` connect to `/run/dbus/system_bus_socket` **succeeded**: this kernel does not mediate a path connect by the file rules | **AppArmor does not hold this**; by design the sandbox does (namespace unit: `AF_NETLINK` only; the others: `InaccessiblePaths=`), **not observed under the units in G4**. §7 and §8 corrected |
| AppArmor, new denials | the namespace unit: `file_lock` on `/run/netns/`, `open` of `/` (the nsfs file) and the nsfs bind's `srcname="/"`; the decoy: `owner` on `/proc/<pid>/net/dev` (`fsuid=979 ouid=0`). The verify unit's `/dev/null` denial is gone with `attach_disconnected`. The helper and the verify unit showed no denial | fixed by the candidate rules (§7) |

**Not checked in G4** (still open, listed in the items below): the
namespace unit's `TimeoutStartSec=` path and whether `TimeoutStopSec=`
bounds each `ExecStopPost=` command on its own (timings not measured;
measured 2026-10-24, below); the
roll-back at a later step and with the handle already present, under
AppArmor; the decoy's report to the intake (P2's send; the intake was not
run, so its connect under the profile is not shown either); a trip from
a `firewalld` reload (`nft delete table`, in the second rehearsal
`systemctl start nftables.service` and in the fifth `systemctl reload
nftables.service` were used); whether a failed `AssertSecurity=apparmor`
on the verify unit makes it failed so that `OnFailure=` trips (it does
not; observed 2026-10-24, below); a verify
already running during an ordinary stop; a name taken over by something
else between runs (item 2's hand-added element and the names of §7's
table); a start with AppArmor disabled (`apparmor=0`; observed
2026-10-24, below); the full §8 table
for every unit, and `systemd-analyze security`. Added by the
review of #289:

- that a connect to `/run/dbus/system_bus_socket` and to
  `/run/systemd/private` is refused **under the namespace unit's and the
  helper's sandbox** (the second rehearsal checked the decoy and the verify
  unit; the first tried it only with `aa-exec` outside the units);
- the profiles on a kernel that mediates path `unix` (there the two
  `deny ... rw` rules should refuse the connect, and the decoy's intake
  allow should let its report through);
- the rules still marked `INFERRED` in the profiles: which of `rbind` and
  `bind` the first bind of `/run/netns/` is, the peer label of PID 1 in the
  `signal (receive) peer=unconfined` rules, the `rslave` remount of `/` and
  the `sysfs` mount of `ip -n` as AppArmor sees their flags, and the
  decoy's `rw` (rather than `w`) on the intake socket.

**Checked in G4 and not**, in short: checked on the VM were the start of
all five units, the isolation record v2, the verify with R4, the masquerade
(indirectly), the decoy's capabilities, `NoNewPrivs`, seccomp and LSM
label, the trip by a deleted table and the recovery, the profiles' write
denials (with `aa-exec`), a start with a profile unloaded, and the denials
fixed by the candidate rules; in the second rehearsal, the trip by
`systemctl start nftables.service`, the decoy's and the verify unit's
sandbox under probe copies (service manager, `/proc`, writes), and the
renamed prefix. Everything in the list above, and every item below not
named here, is unchecked.

### Second G4 rehearsal (2026-10-22, VM; mechanism check, not hardware evidence)

The same VM (Debian 13, kernel 6.12, systemd 257, AppArmor 4.1), with the
content of `main` 7e0402d (the renamed prefix `/.azazel-nsfs/` and the
decoy's `ProtectProc=invisible` included). Markers by hand, a VM-only scope,
nothing granted by the pass. **A VM check of the mechanism, not hardware
evidence**; no record for `HG-06`, `HG-09` or `HG-10`.

| what | observed | result |
| --- | --- | --- |
| start with the renamed prefix | `azazel-decoy-nsd`, `-netd`, `azazel-decoyd` and `azazel-decoy-verify` started with **no** AppArmor denial; all nine isolation checks `pass`; reachability as in the first run (approved `.2` answered on the three ports, unapproved `.3` timed out) | ok |
| trip by `systemctl start nftables.service`, definitions intact | Debian's default `/etc/nftables.conf` holds `flush ruleset`. The unit started at 21:19:58, the verify failed and the trip started at 21:20:04 (about 6–7 s, inside one period); all three units stopped; the helper ended `failed` as before | ok (closed) |
| trip by `nft delete table` (first run, definitions intact) | the three units stopped about 2 s after the trip (first table above) | ok (closed) |
| **rehearsal error**: a probe copy with `Requires=azazel-activated.service` left in | starting that copy started the controller. Its preflight found the three exposure units running without a grant and masked them again; the controller then recorded `activation.rollback_failed` and failed, with `still_unreachable` "masked unit has no confirmed inactive state". **It masked them and did not stop them** | a rehearsal fault; the controller's behaviour is G6 item (b), §6.3 |
| **trip weakness**: the trip after that mask | the `daemon-reload` after the mask replaced the three running units' definitions with `/dev/null`, so their `Requires=` and `After=` were gone. Starting `nftables.service` flushed the table; the verify failed after about 7 s and `OnFailure=` started the trip target. Only the namespace unit stopped (its `Conflicts=`); its `ExecStopPost=` did not run (no definition), so the namespace and the veth pair were left. The helper and the decoy stayed `active` for more than 20 s: the `Requires=` chain the trip relied on was gone. The decoy's cgroup `IPAddressAllow=` (`10.255.196.0/30` only) still held, so with the masquerade gone nothing outside could reach it (*inferred*, not observed); but the design's "the trip stops all three" did not hold | **fixed in part** by the trip naming all three (§6.3, "The trip after G4"); the rest is G6 item (a) |
| decoy sandbox, probe copy | a copy of `azazel-decoyd.service` with only `ExecStart=` replaced by the test probe (§8's method; profile `azazel-decoyd`, `ProtectProc=invisible`, `PrivateUsers=`, uid 979): `/proc/self/net/dev` and the boot id readable; `/proc/1/net/dev` `FileNotFoundError`; listing `/proc` refused by AppArmor; connects to `/run/dbus/system_bus_socket` and `/run/systemd/private` refused (`PermissionError`, `InaccessiblePaths=`); writes to `/etc/azazel` and `/run/azazel-activation` refused | ok |
| verify sandbox, probe copy | the same for `azazel-decoy-verify.service` (profile `azazel-decoy-verify`, `AF_NETLINK` only): both connects refused (`OSError`: no `AF_UNIX` socket); `/proc/*/net/dev`, the boot id and the `/proc` listing refused by AppArmor (the verify needs none of them); writes refused | ok |

So "the sandbox keeps the unit from the service manager" (§7, §8) is
observed on the VM under the units for the decoy and the verify unit; for
the namespace unit and the helper it is still unchecked. The decoy's
`ProtectProc=invisible` row of §7 is checked.

**What the trip change covers, and what it does not.** Naming the three
units in the trip unit's `Conflicts=` makes the job engine stop each one
directly, so the helper and the decoy stop even when the `Requires=` chain
is gone (checked in the third rehearsal below). It does not bring back the
clean-up or the order in that state (no `ExecStop=`, no `ExecStopPost=`, no
`After=`), and it still waits for a verify to fail. Both remain G6 items
(§6.3, "For G6").

### Third G4 rehearsal (2026-10-22, VM; mechanism check, not hardware evidence)

The same VM, with this change (#290, a6393f9) installed: the trip unit with
the three `Conflicts=` lines. **A VM check of the mechanism, not hardware
evidence.**

| what | observed | result |
| --- | --- | --- |
| trip, definitions intact | `nft delete table inet azazel_decoy`: the trip within one period (about 9 s); the units stopped in the order decoy, helper (its `ExecStop=` ended `status=1`, `failed`, as before), namespace unit (its `ExecStopPost=` last); nothing left (links 0, namespaces 0, tables 0) | ok (closed) |
| re-arm by the decoy | starting `azazel-decoyd.service` stopped the trip target (`Conflicts=`) and all three came back `active` | ok |
| trip after a mask and a `daemon-reload` | the three masked while running, `daemon-reload`, the table deleted: the trip after about 11 s and **all three stopped** (before this change, only the namespace unit). With the definitions `/dev/null` no clean-up ran: two veth links and one namespace were left (the table was already gone) | the stop: ok; the leftovers: G6 item (a) |

**Still open** (added to the items below): that starting the helper alone
stops the trip target; the namespace unit's and the helper's sandbox under
probe copies.

### Fourth G4 rehearsal (2026-10-22, VM; mechanism check, not hardware evidence)

The same VM with `main` 7492940 installed, to close items left open above.
Probe and timeout copies were made from the rehearsal copies (no
`Requires=azazel-activated.service`). **A VM check of the mechanism, not
hardware evidence.**

| what | how | observed | result |
| --- | --- | --- | --- |
| the helper's sandbox | probe copy of the helper (`ExecStart=` replaced, AppArmor kept) | `AF_UNIX` connects to `/run/dbus/system_bus_socket` and `/run/systemd/private` refused (`OSError`: no `AF_UNIX`); writes to `/etc/azazel` and `/run/azazel-activation` refused | ok (closed) |
| the namespace unit's sandbox | probe copy of the namespace unit **with `AppArmorProfile=` dropped** (its profile executes nothing but `ip`, so a probe cannot run under it) | `socket(AF_UNIX)` and `socket(AF_INET)` refused with errno 97 (`EAFNOSUPPORT`); `AF_NETLINK` allowed. The address-family filter alone keeps it from the service manager's sockets | ok (closed); the profile's own part not probed |
| starting the helper alone | `systemctl start azazel-decoy-netd.service` with the trip target active | the trip target stopped; the namespace unit and the helper came back `active`, the decoy stayed down | ok |
| the start timeout | copy of the namespace unit with `ExecStart=/usr/bin/sleep 5` after step 2 and `TimeoutStartSec=2s`, **`AppArmorProfile=` dropped** (`sleep` is not `ip`) | "start operation timed out. Terminating."; `Failed with result 'timeout'`; the `ExecStopPost=` undo ran: no veth link, no namespace left | ok (closed); per-command `TimeoutStopSec=` still not measured |
| the decoy's report to the intake (P2) | rehearsal copy of `azazel-edge-intaked.service` (marker by hand), the decoy under its profile, a connection from the approved source to port 2323 | one line appended to `edge-intake/decoy-evidence/<day>.jsonl` (`azintake:azintake 0640`): a closed `EnvironmentEvent` (`environment_id` `telnet-decoy`, `event_type` `interaction`, metadata `bytes_received`, `responder`, `truncated` only); no address and no payload in any line; no AppArmor denial | ok |

A first attempt at the report recorded nothing: the script stopped the
intake about three seconds after the connections, before the decoy reports
(at the connection's close). Not a defect; noted so the next rehearsal waits
for the close.

### Fifth G4 rehearsal (2026-10-22, VM; mechanism check, not hardware evidence)

The same VM (Debian 13, kernel 6.12.111+deb13-arm64, AppArmor 4.1,
systemd 257). **A VM check of the mechanism, not hardware evidence**; no
record for `HG-06`, `HG-09` or `HG-10`, and nothing granted by the pass.

| what | how | observed | result |
| --- | --- | --- | --- |
| the kernel's per-profile files | listing `/sys/kernel/security/apparmor/policy/profiles/<name>.<n>/` | `attach mode name raw_abi raw_data raw_sha256 sha256`; no `sha1` | the reader now reads `raw_sha256` (§9, "G6 preparation C") |
| their form | the entry `azazel-decoyd.122/` | `attach`, `mode`, `name` and `sha256` are regular files; `raw_abi -> ../../raw_data/122/abi`, `raw_data -> ../../raw_data/122/raw_data` and `raw_sha256 -> ../../raw_data/122/sha256` are symbolic links | the reader reads the link, accepts only that form and opens `policy/raw_data/<n>/sha256` itself (§9) |
| which hash the kernel shows | for each of the four decoy profiles, the kernel's `raw_sha256` against the SHA-256 of `raw_data` and of `apparmor_parser -Q -o <out> /etc/apparmor.d/<name>` | all three equal, for all four; `sha256` is another value, equal to neither and not to the SHA-256 of the profile file | the expected hash can be derived at install (§7, "Left to G6") |
| the pass's reads under the controller's sandbox | a copy of `azazel-activated.service` with only `ExecStart=` replaced by a test Python, its dependencies and conditions removed; its sandbox (`ProtectSystem=` and the rest) kept | `/sys/kernel/security/apparmor/profiles`, `/sys/kernel/security/lsm`, the policy directory and `sha256` all readable; no AppArmor denial | ok |
| compiling again, and the cache | `apparmor_parser -Q -o` three times per profile (parser 4.1.0); the cache file `/var/cache/apparmor/979b3ac6.0/<name>` that `apparmor.service` loads at boot | for all four, the three outputs equal, and equal to the kernel's `raw_sha256` and to the cache file | ok on this VM and this version; other features, `parser.conf`, versions and several profiles per file stay *inferred* (§7) |
| trip by `systemctl reload nftables.service` | Debian's default `/etc/nftables.conf` (it holds `flush ruleset`) | about 11 s later the verify failed, the trip ran and the three units stopped | ok (closed) |
| trip by `systemctl start nftables.service` (again) | the same file | the same, about 9 s later | ok (closed) |
| reading `raw_data/<n>/sha256` under the controller's sandbox | the same controller copy (only `ExecStart=` replaced, `ProtectSystem=` and the rest of its sandbox kept), running the reader's steps: `readlink` of `raw_sha256` relative to the entry, the check of the form `../../raw_data/<n>/sha256`, then the fixed `policy/raw_data` opened and `<n>` and `sha256` opened in turn with `O_NOFOLLOW` | for all four profiles (`azazel-decoy-netd.124`, `azazel-decoy-nsd.122`, `azazel-decoy-verify.126`, `azazel-decoyd.127`) 64 hex digits read, each equal to the kernel's `raw_sha256`; no AppArmor denial | ok |

That `raw_sha256` is a link is checked (row "their form"); before this
check the reader opened it without following a link and would have
withheld on every pass. That the pass can read `raw_data/<n>/sha256`
through the link's form under the controller's sandbox is checked (the
last row): the copy replaced only `ExecStart=` and kept the sandbox. The
comparison itself stays unwired and withholds until G6 records the
expected hash. One VM, one run, four profiles: none of this is hardware
evidence.

### Two open items checked (2026-10-24, VM; mechanism check, not hardware evidence)

Debian 13, kernel 6.12, systemd 257.13. Throwaway units and rehearsal
copies (no `Requires=azazel-activated.service`). **A VM check of the
mechanism, not hardware evidence**; no record for `HG-06`, `HG-09` or
`HG-10`, and nothing granted by the pass.

| what | how | observed | result |
| --- | --- | --- | --- |
| `TimeoutStopSec=` per `ExecStopPost=` command | a throwaway unit with two `ExecStopPost=` lines and `TimeoutStopSec=12s`; each line a command of 8 s | the stop took about 16 s and both commands ran to the end (`Result=success`): the timer is re-armed for each command | ok; §7's *inferred* reading confirmed |
| one command over `TimeoutStopSec=` | the same unit with the first command at 20 s | after about 12 s `State 'stop-post' timed out. Terminating.`, `Result=timeout`; **the second `ExecStopPost=` command did not run** | **new**: a hung undo command skips the rest of the undo (§7 timing row); for the namespace unit, a hung `ip link delete az-decoy-host0` leaves the namespace (and the pair with it), a leftover the residue judgement withholds on (`exposure_leftovers_present`, wired in G6): closed, cleaned by hand |
| `apparmor=0`: the LSMs | boot with `apparmor=0` | `apparmor` not in `/sys/kernel/security/lsm`; `/sys/module/apparmor/parameters/enabled` is `N` | as expected |
| `apparmor=0`: the namespace unit | start of a rehearsal copy | `AssertResult=no`, not started; no namespace created | ok (fails closed) |
| `apparmor=0`: the verify unit and `OnFailure=` | start of a rehearsal copy | `Assertion failed`, not started; the unit kept `Result=success` and **its `OnFailure=` did not run**: an assertion failure is a job result, not a unit failure | as *inferred* in item 3: a failed assertion never trips (§6.3) |
| `apparmor=0`: the pass's reading | the unwired `decoy_apparmor.exposure_lsm_refusal` over the live reads | `lsm_apparmor_disabled` (withhold) | ok |
| restore | GRUB put back, reboot | AppArmor enabled, the four profiles loaded | ok |

**Still open after G4:** the namespace unit's AppArmor profile on a
probe (it cannot run one); a trip from a `firewalld` reload; a kernel with fine-grained `AF_UNIX` mediation; what
besides the files changes the compiled output (features, `parser.conf`,
the parser's version, load flags, several profiles in one file; §7,
"Left to G6");
the full §8 table and `systemd-analyze security` per unit. These are G5
(`HG-09`, `HG-10`) or G6 work.

**Rehearsal rule** (also in [operations](operations.md)): every unit copy,
probe copies included, is made from a copy **with
`Requires=azazel-activated.service` (and its `After=`) already removed**,
never from the packaged file. A copy that keeps it starts the controller,
which acts on the rehearsal's hand-placed state.

### The items

The items below are what was to check; item 4 is rewritten for the
G4 follow-up, and the table above records which of them G4 answered.

1. masquerade (A3): a connect from an approved source on the ingress reaches
   the decoy and the banner returns; the decoy's cgroup filter sees
   `10.255.196.1`; after `nft flush ruleset` the same connect gets no answer;
2. the scope: elements and the `iifname` match load in one transaction;
   `nft -j list table` compares equal; a hand-added element fails the check;
3. the watch (G2, §6.3): `systemctl reload nftables` (with the service
   started by hand) and a `firewalld` reload stop the three units within one
   period; a decoy restart re-runs the verify; a verify that fails before
   the decoy start keeps it down; a successful one-shot verify does not stop
   the decoy through `Requires=`; the verify's `OnFailure=` starts
   `azazel-decoy-trip.target` and its `Conflicts=` stops the three units
   (since the G4 follow-up each by name; the decoy, then the helper, then
   the namespace unit by the reverse of `After=`), with the default
   `OnFailureJobMode=replace`, also after a mask and a `daemon-reload` have
   removed the units' dependencies; starting the helper or the decoy stops
   the target as starting the namespace unit does; starting the namespace unit again stops the
   target, and a second failure trips again; the timer fires every 10 s
   with `AccuracySec=1s` (`systemctl list-timers`) and stops with the decoy
   (`PartOf=`); a verify start refused for a missing credential source
   (243/CREDENTIALS) also counts as a failure and trips; whether the timer
   and the verify keep running when the decoy was pulled in but skipped by
   its grant-marker condition (`Requires=` pulls them in before the
   decoy's condition is evaluated: an unmasked, ungranted decoy, which only
   a hand-placed rehearsal makes), and how loud that is; that a verify run
   (four read-backs) stays well inside the period; during an ordinary
   stop of the three units, whether a verify already running reads the
   table after the helper removed it and trips (the order of the stop jobs
   against a running verify, and what the journal then shows; a trip there
   only stops what is stopping, review of #287 F6); whether a failed
   `AssertSecurity=apparmor` on the verify unit (AppArmor disabled, or a
   profile not loaded) leaves the unit **failed**, so that `OnFailure=`
   starts the trip unit, or only fails the start job, in which case it does
   not (an assertion failure is a job result, not a unit failure; *inferred*,
   **observed 2026-10-24** with `apparmor=0`: `Result=success`, `OnFailure=`
   not run, above; the decoy's own start still fails through `Requires=`, but a verify
   started by the timer while the decoy runs would stop nothing; review of
   #287 F2);
4. AppArmor: the four profiles load on Debian 13; a start with a profile
   unloaded fails, and with AppArmor disabled (`apparmor=0`)
   `AssertSecurity=apparmor` fails it (observed 2026-10-24, above); the namespace unit as rebuilt after
   G4 (§7): `ip` started by systemd directly under `azazel-decoy-nsd` with
   `NoNewPrivileges=yes` (no transition, so no `no new privs` denial), its
   six `ExecStart=` lines and `ip -n` working under the profile (which of
   `rbind` and `bind` the first bind is, the nsfs bind source, the
   propagation flags), `ip`'s output reaching the journal (an inherited
   socket under the profile), and its writes to the paths of §7 denied; the
   roll-back: a start failing at a later step (for example the veth name
   taken by hand) running both `ExecStopPost=` lines and leaving no pair
   and no namespace, a start with `/run/netns/azazel-decoy` already present
   failing at step 1 and then removing it (the accepted change of §7), a
   start timing out (`TimeoutStartSec=`) running the undo, whether
   `TimeoutStopSec=` bounds each `ExecStopPost=` command on its own or the
   two together (observed 2026-10-24, above: each on its own, up to 30 s per
   command, and a command over it ends the undo without the rest), and
   `systemctl stop` removing both; with `attach_disconnected` on the four
   profiles, the verify unit's `/dev/null` access no longer denied and no
   new denial in a passing run of any of the four; the decoy's connect to the intake's socket
   succeeds and a write anywhere else under `/var/lib/azazel` is refused;
   the pass, as root under the controller's sandbox, can read
   `/sys/kernel/security/apparmor/profiles`;
5. `nft list` refused without `CAP_NET_ADMIN` (confirms the verify unit's
   need); the verify unit under its profile: the four read-backs, the
   credential and the `/proc/sys/net` reads allowed, any write refused, no
   denial logged in a passing run;
6. every item of the §8 table, as a rehearsal of `HG-09`.
