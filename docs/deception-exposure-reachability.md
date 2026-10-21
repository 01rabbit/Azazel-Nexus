# How outside peers reach the decoy — design (#196, Q11)

Owner: [#196](https://github.com/01rabbit/Azazel-Nexus/issues/196) (the grant
phase).
Status: **proposal. The default of Q11 was decided on 2026-10-22 (§4); the
points this design raises (§9, R1–R5) await the owner. Nothing here is
implemented; the pass's part lands in G6.**
Related: [granting the exposure tier](deception-exposure-grant.md) (§4.3,
§4.4, §4.5, §5, §10 Q11) ·
[Deception Lite prerequisites](deception-redirect-prerequisites.md) (§10, §13,
§14) · [commissioning](commissioning.md) (§4, §5, §8) ·
[operations](operations.md#deception-lite-decoy-network-196)

## 1. Problem

The decoy listens on `10.255.196.2`, inside the namespace `azazel-decoy`,
behind the bridge `az-decoy0` (`10.255.196.1/30`) that the helper builds
(`decoy_addresses.py`, `decoy_network.py`). That /30 is private to the node:
no host on the protected network has a route to it, and a packet that does
arrive on a node interface for `10.255.196.2` is not local to the host, so
the kernel forwards it to `az-decoy0` only if forwarding allows it. Two things
are missing, and neither is the helper's to provide:

1. **a route on the LAN** that sends `10.255.196.0/30` to the node;
2. **forwarding on the node** from the ingress interfaces (the role
   `deception_bridge`) to `az-decoy0`, and for the replies back.

The helper cannot change forwarding (`ProtectKernelTunables=yes`, and it runs
only fixed `ip` and `nft` argument lists), and a host-wide
`net.ipv4.ip_forward=1` would make the node a router for every interface,
the management one included. This document settles how both are provided, by
whom, and what the pass checks before it grants the tier. It changes no code.

## 2. What is established, and what is inferred

Read at `main` 66ba040.

| fact | reference |
| --- | --- |
| The /30, the bridge and the decoy address are constants | `runtime/src/azazel_nexus_runtime/decoy_addresses.py:34-36` |
| The decoy's default route is `10.255.196.1` on its veth | `decoy_network.py` `NAMESPACE_STEPS` (last step) |
| The forward accept toward the decoy names `oifname "az-decoy0"`, `@approved_v4`, the address and the ports; the reply accept names `iifname "az-decoy0"`, `ct state established` and no output interface; the input chain drops everything from `az-decoy0` | `decoy_network.py` `NFT_RULESET` |
| The table only drops (`policy accept` everywhere); it opens nothing another table closes | `decoy_network.py` `NFT_RULESET` docstring |
| The helper sets no sysctl and reads none; nothing in the runtime writes `/proc/sys` | `decoy_network.py` (`_ALLOWED`); `hardening.py:97` (`ProtectKernelTunables=yes` in the shared sandbox) |
| The activation controller runs in the host network namespace, with `AF_UNIX AF_NETLINK`, under the shared sandbox (so `/proc/sys` is readable and not writable), after `sysinit.target` | `hardening.py:825-846` |
| The pass resolves the `deception_bridge` role to this boot's interface names; no name, default route or "first" interface substitutes for a role | [grant §4.3](deception-exposure-grant.md#43-how-the-helper-receives-it); [commissioning §8](commissioning.md#8-rendering-from-logical-roles-only) |
| An interface has one role; `observation` is unnumbered and transmits nothing | [commissioning §4, §5](commissioning.md#5-zero-transmit-observation) |
| A3: the table masquerades approved traffic to `10.255.196.1` on its way into `az-decoy0` | [grant §4.4](deception-exposure-grant.md#44-the-five-fixed-places-f2) item 4 |

**From the kernel documentation** (`Documentation/networking/ip-sysctl.rst`)
and `sysctl.d(5)`; not yet observed in a recorded run of this repository, so
each is also a VM item (§10):

- `net.ipv4.conf.<if>.forwarding` "controls whether packets received _on_
  this interface can be forwarded". It is a property of the **receiving**
  interface. The interface the packet leaves by is not consulted: a packet
  received on an interface with forwarding on is forwarded out of an
  interface whose own value is `0`.
- `conf.all.*` is special: a write to `conf.all.forwarding` sets every
  existing interface's value (and `conf.default`'s). `conf.default.*` is the
  value a **newly created** interface starts with.
- `net.ipv4.ip_forward` writes the same switch as `conf.all.forwarding`, and
  its change also resets the host/router parameters (RFC 1122 / RFC 1812
  behaviour, for example accepting redirects).
- In `sysctl.d`, an interface name containing a dot (a VLAN such as
  `eth0.100`) must be written with `/` separators
  (`net/ipv4/conf/eth0.100/forwarding`).

***Inferred*, to be checked on the VM** (§10):

- the forwarding decision reads **only** the receiving interface's value
  (`IN_DEV_FORWARD(in_dev)` in the input route lookup), so `conf.all` at `0`
  with `conf.<ingress>` at `1` forwards from the ingress and nowhere else;
  `ip_forward` and `conf.all.forwarding` always read the same value;
- the replies need forwarding **on `az-decoy0`** as well: they are received
  on the bridge (the veth is a bridge port, so the layer-3 receiving
  interface is `az-decoy0`) and routed out of the ingress interface. With
  `az-decoy0` at `0` the connection is accepted by the decoy and its replies
  are dropped (unreachable, not exposed);
- a new `az-decoy0` takes `conf.default.forwarding`, and systemd's udev rule
  re-applies `sysctl.d` entries naming the interface when it appears (the
  `systemd-sysctl --prefix=/net/ipv4/conf/$name` call in
  `99-systemd.rules`), shortly **after** the helper creates it;
- systemd-networkd's `IPMasquerade=` and the older `IPForward=` in a
  `.network` file turn on forwarding for the whole host;
- `ip rule ... iif <if> blackhole` and `suppress_prefixlength` behave as §5
  uses them on Debian 13's kernel and iproute2.

## 3. Invariants

The invariants of [grant §3](deception-exposure-grant.md#3-invariants) hold,
and two are made concrete here:

- **Nexus writes no sysctl, no route and no routing rule.** Forwarding, the
  LAN route and the containment rules (§5) are the operator's static host
  configuration. Nexus only **reads** them, at the pass, and withholds the
  tier when they depart from §6. No unit gains `ProtectKernelTunables=no`,
  a capability, a writable `/proc/sys` path, or a new argument list for this.
- **No bypass.** There is no approval boolean, environment variable, flag or
  file that makes the pass skip the forwarding check, and no "router mode"
  setting. A host that cannot meet §6 does not get the tier.

## 4. Options, and the decided default

| option | idea | verdict |
| --- | --- | --- |
| P1 | the LAN routes `10.255.196.0/30` to the node's address on an ingress interface; the operator turns on `conf.<ingress>.forwarding` (and `conf.az-decoy0.forwarding`, §7) in `sysctl.d`; Nexus sets nothing and the pass checks it | **decided** (Q11, 2026-10-22) |
| P2 | Nexus (the helper, or a new unit) writes the per-interface sysctls at start and resets them at stop | needs `ProtectKernelTunables=no` and a writable `/proc/sys` in a root unit: a new privilege and a writer of kernel state; a crash leaves forwarding on with no table; **rejected** |
| P3 | the operator sets `net.ipv4.ip_forward=1` (host-wide) | every interface forwards, `management` and `observation` included, and every interface created later (`conf.default`); the node becomes a router between all its networks; **rejected** |
| P4 | proxy ARP: the node answers ARP on the ingress for `10.255.196.2`, so LAN hosts reach it on-link | the decoy's address would have to sit inside the LAN prefix, which conflicts with the fixed /30 and with §4.2 of the grant design (no approved prefix may touch `10.255.196.0/24`); proxy ARP answers for whatever the routing table holds (the `proxy_arp` switch is per interface, not per address); forwarding is still needed; **rejected** |
| P5 | DNAT: the node owns a LAN address on the ingress and translates it to `10.255.196.2` | Nexus would choose or be given a LAN address and answer ARP for it (address management Nexus does not do); a second NAT in the table, before routing, and a second translation the isolation check would have to compare; forwarding is still needed; the decoy's address would appear as an ordinary host on the LAN, and a lost table would leave that address answering for the host's own services; **rejected** |
| P6 | the bridge enslaves the ingress interface (layer 2), with the decoy on the LAN segment | the decoy would be on the protected segment itself, with an address in it; all LAN broadcast reaches the namespace; the routed /30 and the table's `oifname`/`iifname` structure would no longer hold; **rejected** |

Under P1 the operator also chooses where the route lives (the LAN router, or
each host that is meant to reach the decoy). That is the operator's network,
not Nexus's; §8 only shows the shape.

## 5. What forwarding on the ingress opens, and what contains it

Per-interface forwarding is **directional**: it lets packets *received on*
the ingress be forwarded anywhere the routing table points, and not only to
`az-decoy0`. The decided check ("off on `management` and `observation`")
stops traffic received on those interfaces from being forwarded; it does not
stop a LAN host that uses the node as its gateway from being forwarded **out
of** the management interface, the uplink or any other route. The decoy
table cannot close this alone: it exists only while the helper runs, and is
gone before the helper starts, after a stop or trip, and after any flush
(grant §6) — exactly when forwarding on the ingress is still on.

| option | idea | verdict |
| --- | --- | --- |
| K1 | the operator adds two routing rules per ingress interface (below), so that a packet received on it is forwarded only toward the /30 and is otherwise discarded, whether or not the table exists; the pass reads them | **recommended** (R2 of §9) |
| K2 | a drop in the decoy table: `iifname { <ingress> } oifname != "az-decoy0" drop` in the forward chain | holds only while the table exists; **kept as a second wall** (§7), not the containment |
| K3 | an operator-written nftables ruleset that drops other forwarding from the ingress | needs `nftables.service` (or similar) enabled, which withholds the tier (grant §6.2), and it can flush the decoy table; **rejected** |
| K4 | a VRF holding the ingress and `az-decoy0` | the helper would have to enslave the bridge to a VRF (a new step and a new object to check); heavy for one /30; **not chosen** |

**K1 in detail.** For each ingress interface, with priority numbers below
the main table's rule (32766), so they are evaluated before it, and before
any site rule that could match the interface:

```
ip rule add priority 1960 iif <ingress> to 10.255.196.0/30 lookup main suppress_prefixlength 29
ip rule add priority 1961 iif <ingress> blackhole
```

- The local table (priority 0) still comes first, so packets for the node's
  own addresses are delivered as before. That includes `10.255.196.1`: a LAN
  host can reach the host's services on it as it can on the ingress's own
  address. That is the host's input policy, which this design does not
  change (the decoy table's input chain drops only what arrives on
  `az-decoy0`).
- The first rule looks up the /30 in `main` but ignores any route shorter
  than /30 (`suppress_prefixlength 29`): only the connected route of
  `az-decoy0` can answer. When the bridge does not exist, a default or a
  `10.0.0.0/8` route does **not** carry the packet elsewhere; the lookup
  falls through to the second rule.
- The second rule discards silently (no ICMP from the node, which would only
  tell a scanner a router is there).

Configured with the operator's network tool (systemd-networkd
`[RoutingPolicyRule]`, or `ip rule` in an ifupdown `post-up`); the shape is
in §8. *Inferred:* both selectors and `blackhole` as a rule action (§10).

## 6. The pass condition (G6; not implemented here)

Condition 6 of [grant §5](deception-exposure-grant.md#5-the-grant-condition)
("the forwarding condition of §4.5") is this section. The pass reads; it never
writes.

**Interfaces.** The ingress names come from the `deception_bridge` role, and
the `management` and `observation` names from their roles, resolved exactly
as in [grant §4.3](deception-exposure-grant.md#43-how-the-helper-receives-it):
from the commissioning evidence and the current inventory, an ambiguous or
missing identity withholds, no name substitutes for a role. Each name passes
the §4.3 check (`[A-Za-z0-9_.-]{1,15}`, not beginning with `az-decoy`), and
must not be `all`, `default` or `lo`, before any path is built from it.

**Reads.** `/proc/sys/net/ipv4/conf/<name>/forwarding` per interface, and
`/proc/sys/net/ipv4/conf/all/forwarding` and `.../default/forwarding`.
Opened without following links, read within a small bound; the content must
be exactly `0\n` or `1\n`, anything else (absent, unreadable, another value)
is unreadable and withholds. These are the host namespace's values, which is
where the controller runs. The routing rules of K1 are read through a route
netlink dump (`RTM_GETRULE`; the controller has `AF_NETLINK`; *inferred*
that a dump needs no capability).

**Holds when** (decided items in bold; the others are R1, R2 and R5 of §9):

| item | value | reason code when not |
| --- | --- | --- |
| **every ingress interface** | `forwarding` is `1` | `forwarding_ingress_off` |
| **every `management` and `observation` interface** | `forwarding` is `0` | `forwarding_role_on` |
| `conf.all` and `conf.default` (R1) | `0` | `forwarding_host_wide` |
| every other interface present except the ingress (R1) | `0` | `forwarding_other_on` |
| `net.ipv6.conf.all.forwarding` (R5) | `0` | `forwarding_host_wide` |
| each ingress interface's two K1 rules (R2) | present as in §5, and no rule with a lower priority (other than the local rule) matches that interface | `ingress_containment_absent` |
| any read above | readable, in the closed form | `forwarding_unreadable` |

Each code is a fixed word followed by a fixed phrase, in the form the
controller already uses; none carries an interface name, a prefix or a
value. Every failure withholds the tier and nothing else.

**What it is not.** A reading at one moment, before the units start. A later
change is not seen by the pass. Turning the ingress off later only makes the
decoy unreachable. Turning forwarding on elsewhere later is a host change the
watch of grant §6 does not see; reading these values in the verify unit is
possible without a capability and is left as R4.

`az-decoy0` is **not** in the pass's reads: it does not exist when the pass
runs, and its forwarding being off fails closed (§7).

## 7. The return path, masquerade (A3) and conntrack

The path of one connection, with A3 and the decided default:

1. A LAN host sends to `10.255.196.2:2222`; its route (§8) delivers the
   packet to the node's ingress address.
2. The ingress has forwarding on, rule 1960 finds the connected /30, and
   the packet is routed to `az-decoy0`. The table's forward chain accepts it
   only from `@approved_v4` (and, after G1, only from the ingress); conntrack
   creates the entry.
3. On the way out to `az-decoy0` the `postrouting` NAT chain masquerades the
   source to `10.255.196.1` and records the mapping in the same entry. The
   decoy's cgroup filter sees `10.255.196.1`, inside its `IPAddressAllow=`.
4. The decoy answers to `10.255.196.1`. The reply is received on
   `az-decoy0`; in `prerouting` conntrack reverses the translation, so the
   destination is the LAN host again **before** the route lookup.
5. The route lookup for that reply reads forwarding on **`az-decoy0`**
   (§2, inferred): it must be on, or the reply is dropped. It is then routed
   by the main table toward the LAN host, and must leave by the ingress.
6. The forward chain's reply rule accepts it (`iifname "az-decoy0"`, source
   the decoy, destination `@approved_v4` after the reverse translation,
   `ct state established`).

Consequences:

- **`az-decoy0` needs forwarding on**, and this is the operator's too: a
  per-name entry in `sysctl.d` (§8), applied by udev when the helper creates
  the bridge. Forwarding on `az-decoy0` only concerns packets the decoy
  sends; every one of them except the established replies is dropped by the
  table, and if the table is gone, by the decoy's own cgroup filter
  (`IPAddressDeny=any`). It is **not** a pass item (the bridge does not
  exist yet) and not an isolation check (its absence only makes the decoy
  unreachable). The operator's procedure tells how to see it (§8). Using
  `conf.default.forwarding=1` instead is rejected: every interface created
  later would forward.
- **A reply must leave by the ingress.** Today's reply rule names no output
  interface, so an asymmetric route (the LAN host reachable through the
  management interface) would carry decoy replies out of it. Proposed for
  the G1 renderer (R3 of §9): the reply accept also matches
  `oifname { <ingress> }`, so such a reply falls to `iifname "az-decoy0"
  drop`; and the second wall of K2. Strict reverse-path filtering
  (`rp_filter=1`) on the ingress would drop the request itself in the same
  case; loose mode (`2`, systemd's default, *inferred* for Debian 13) does
  not.
- **A packet with no conntrack entry** to `10.255.196.1` from the decoy is
  local to the host and goes to the input chain, which drops everything from
  `az-decoy0`. A reply never bypasses the reverse translation into the host.
- **After a flush** (grant §6) the NAT chain is gone, but conntrack entries
  keep their mappings until they expire: established connections keep
  working until the watch stops the units; new ones arrive untranslated and
  the decoy's cgroup filter drops them (grant §4.4, inferred there too). K1
  still holds, so nothing received on the ingress is forwarded anywhere but
  the /30.
- The masquerade needs `nf_conntrack` and `nf_nat`; it is the same
  translation A3 already brings, and this design adds none.

## 8. The operator's part (outline)

For [operations](operations.md#deception-lite-decoy-network-196), written
when G6 lands. Nexus installs none of these files and edits none of them.

1. **On the LAN**: a static route `10.255.196.0/30 via <the node's address on
   the ingress>`, on the LAN router or on each host meant to reach the decoy.
   Nothing on the LAN may use `10.255.196.0/24`. A stateful LAN router that
   sees only one direction of the conversation may need the route on the
   hosts instead.
2. **On the node, forwarding** (example, one ingress `enp3s0`):

   ```
   # /etc/sysctl.d/61-azazel-decoy-forwarding.conf
   net.ipv4.conf.enp3s0.forwarding = 1
   net.ipv4.conf.az-decoy0.forwarding = 1
   ```

   `conf.all` and `conf.default` stay at their default `0` and are not
   written: a write to `conf.all.forwarding` or `ip_forward` sets every
   interface, the per-interface lines included. Never `net.ipv4.ip_forward =
   1`, and no `IPMasquerade=` or `IPForward=` in a systemd-networkd
   `.network` file (§2, inferred: they turn on host-wide forwarding). The
   file names kernel interface names, so a renamed interface is left at `0`
   and the pass withholds (`forwarding_ingress_off`); it never moves
   forwarding to another interface.
3. **On the node, containment** (K1), per ingress interface, for example in
   systemd-networkd's `.network` file of that interface:

   ```
   [RoutingPolicyRule]
   Priority=1960
   IncomingInterface=enp3s0
   To=10.255.196.0/30
   Table=main
   SuppressPrefixLength=29

   [RoutingPolicyRule]
   Priority=1961
   IncomingInterface=enp3s0
   Type=blackhole
   ```

4. **To see it**: `sysctl net.ipv4.conf.enp3s0.forwarding
   net.ipv4.conf.az-decoy0.forwarding` (the second only while the decoy units
   run), `ip rule show`, and from an approved LAN host a connect to
   `10.255.196.2:2222`. A withheld tier names the reason code of §6.

## 9. Owner questions raised by this design

The decided default of Q11 stands as written. Writing it out raised the
following; recommended defaults in brackets. Until the owner decides, G6
implements only the decided items (bold in §6). R2 is the one whose absence
leaves a gap rather than a weaker check: without it, a granted tier implies a
node that routes whatever its ingress receives (§5). Recommended: G6 is not
merged without a decision on R2.

1. **R1.** Host-wide and other interfaces: should the pass also require
   `conf.all` and `conf.default` at `0`, and every interface other than the
   ingress at `0` (`asset_acquisition`, unassigned interfaces, container
   bridges)? **[yes: a host where anything else forwards is not a decoy host
   in this phase; `default` at `0` also keeps an interface added after the
   pass from forwarding]**
2. **R2.** Containment of the ingress (§5): **[K1, operator-configured
   routing rules, checked by the pass as `ingress_containment_absent`]**
3. **R3.** The G1 ruleset: **[the reply accept gains `oifname { <ingress> }`;
   the forward chain gains K2's drop; both rendered from the scope and
   compared by the isolation check like the rest]**
4. **R4.** Re-reading the forwarding values and K1's rules after the pass:
   **[not in this phase; a candidate for the verify unit of grant §6, which
   can read them without a capability]**
5. **R5.** IPv6 forwarding (the decoy is IPv4 only): **[the pass also requires
   `net.ipv6.conf.all.forwarding` at `0`; IPv6 per-interface semantics are
   not relied on]**

## 10. To check on the VM (G4; a mechanism check, not hardware evidence)

1. With `conf.all` `0` and only `conf.<ingress>` `1`: a packet received on
   the ingress for the /30 is forwarded to `az-decoy0`; a packet received on
   the management interface is not; writing `ip_forward` changes
   `conf.all.forwarding` and every interface's value (the reason P3 is
   rejected);
2. with `conf.az-decoy0.forwarding` `0`: the decoy accepts, the replies are
   dropped on the node; with `1` the banner returns;
3. the `sysctl.d` entry for `az-decoy0` is applied by udev when the helper
   creates the bridge, and how long after; whether a connect in that window
   fails (an availability cost only);
4. K1: with the decoy units stopped, a LAN host using the node as its gateway
   reaches nothing beyond the node (blackholed, no ICMP); with them running,
   only the /30; a `10.0.0.0/8` route in `main` does not capture the /30;
5. A3 together with forwarding: the cgroup filter sees `10.255.196.1`, the
   reverse translation happens before the reply's route lookup (the reply
   rule matches `@approved_v4`), and after `nft flush ruleset` an established
   connection survives until the watch trips while a new one is not answered;
6. with the reply route pointing at the management interface: the reply is
   dropped (after R3), and with `rp_filter=1` on the ingress the request is;
7. the pass's reads under the controller's sandbox: `/proc/sys/net/ipv4/conf/*`
   readable, a write refused, the `RTM_GETRULE` dump without a capability;
8. systemd-networkd 257 on Debian 13: `IPMasquerade=` and `IPForward=` turn
   on host-wide forwarding, `[RoutingPolicyRule]` produces exactly the two
   rules of §5.
