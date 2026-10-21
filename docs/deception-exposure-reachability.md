# How outside peers reach the decoy — design (#196, Q11)

Owner: [#196](https://github.com/01rabbit/Azazel-Nexus/issues/196) (the grant
phase).
Status: **proposal. The default of Q11 was decided by the owner on
2026-10-22 (§4). The further conditions this design adds (§9, R1–R5) only
withhold or stop, and are adopted as defaults the owner may overturn; R1, R2,
R4 and R5 are required before G6. R6, the reading of commissioning §2, is
**open** and returned to the owner. Nothing here is implemented; the pass's
part lands in G6, the re-reading in G2.**
Related: [granting the exposure tier](deception-exposure-grant.md) (§4.3,
§4.4, §4.5, §5, §6, §10 Q11) ·
[Deception Lite prerequisites](deception-redirect-prerequisites.md) (§10, §13,
§14) · [commissioning](commissioning.md) (§2, §3, §4, §5, §8) ·
[hardware gates](hardware-gates.md) (`HG-06`) ·
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
| The table is `inet` (IPv4 and IPv6) and only drops (`policy accept` everywhere); it opens nothing another table closes | `decoy_network.py` `NFT_RULESET` and its docstring |
| The helper sets no sysctl and reads none; nothing in the runtime writes `/proc/sys` | `decoy_network.py` (`_ALLOWED`); `hardening.py:97` (`ProtectKernelTunables=yes` in the shared sandbox) |
| The activation controller runs in the host network namespace, with `AF_UNIX AF_NETLINK`, under the shared sandbox (so `/proc/sys` is readable and not writable), after `sysinit.target` | `hardening.py:825-846` |
| The pass resolves the `deception_bridge` role to this boot's interface names; no name, default route or "first" interface substitutes for a role | [grant §4.3](deception-exposure-grant.md#43-how-the-helper-receives-it); [commissioning §8](commissioning.md#8-rendering-from-logical-roles-only) |
| Until activation completes the node must not forward, bridge or route | [commissioning §2](commissioning.md#2-inventory-is-read-only) |
| An interface has one role; `observation` is unnumbered and transmits nothing | [commissioning §4, §5](commissioning.md#5-zero-transmit-observation) |
| A3: the table masquerades approved traffic to `10.255.196.1` on its way into `az-decoy0` | [grant §4.4](deception-exposure-grant.md#44-the-five-fixed-places-f2) item 4 |

**From the kernel documentation** (`Documentation/networking/ip-sysctl.rst`)
and `sysctl.d(5)`; not yet observed in a recorded run of this repository, so
each is also a VM item (§11):

- `net.ipv4.conf.<if>.forwarding` "controls whether packets received _on_
  this interface can be forwarded". It is a property of the **receiving**
  interface. The interface the packet leaves by is not consulted: a packet
  received on an interface with forwarding on is forwarded out of an
  interface whose own value is `0`.
- `conf.all.*` is special: a write to `conf.all.forwarding` sets every
  existing interface's value (and `conf.default`'s). `conf.default.*` is the
  value a **newly created** interface starts with.
- `net.ipv4.ip_forward` is documented as resetting "all configuration
  parameters" to their host or router defaults when it changes.
- `rp_filter`: the value used is the maximum of `conf.all.rp_filter` and
  `conf.<if>.rp_filter`. `proxy_arp` is on when either `conf.all` or
  `conf.<if>` has it.
- In `sysctl.d`, an interface name containing a dot (a VLAN such as
  `eth0.100`) must be written with `/` separators
  (`net/ipv4/conf/eth0.100/forwarding`).

***Inferred*, to be checked on the VM** (§11):

- the forwarding decision reads **only** the receiving interface's value
  (`IN_DEV_FORWARD(in_dev)` in the input route lookup), so `conf.all` at `0`
  with `conf.<ingress>` at `1` forwards from the ingress and nowhere else;
- `ip_forward` and `conf.all.forwarding` are one value, and a write to it
  (`inet_forward_change` in `devinet.c`) sets `forwarding` on `all`,
  `default` and every interface and turns `conf.all.accept_redirects` to the
  opposite; despite the documentation's wording, nothing else is reset;
- the replies need forwarding **on `az-decoy0`** as well: they are received
  on the bridge (the veth is a bridge port, so the layer-3 receiving
  interface is `az-decoy0`) and routed out of the ingress interface. With
  `az-decoy0` at `0` the connection is accepted by the decoy and its replies
  are dropped (unreachable, not exposed);
- a new `az-decoy0` takes `conf.default.forwarding`, and systemd's udev rule
  re-applies `sysctl.d` entries naming the interface when it appears (the
  `systemd-sysctl --prefix=/net/ipv4/conf/$name` call in
  `99-systemd.rules`), shortly **after** the helper creates it;
- systemd-networkd (257 on Debian 13): since systemd 256 a `.network` file's
  `IPv4Forwarding=` sets the per-link `conf.<if>.forwarding` of the links it
  matches; the older `IPForward=` is deprecated, and `IPForward=` or
  `IPMasquerade=` turn on forwarding for the whole host;
  `ManageForeignRoutingPolicyRules=yes` (the default) removes routing rules
  networkd did not create;
- `ip rule ... iif <if> blackhole` and `suppress_prefixlength` behave as §5
  uses them on Debian 13's kernel and iproute2.

## 3. Invariants

The invariants of [grant §3](deception-exposure-grant.md#3-invariants) hold,
and three are made concrete here:

- **Nexus writes no sysctl, no route and no routing rule.** Forwarding, the
  LAN route and the containment rules (§5) are the operator's static host
  configuration. Nexus only **reads** them, at the pass and in the verify
  unit (§6), and withholds the tier or stops the units when they depart. No
  unit gains `ProtectKernelTunables=no`, a capability, a writable `/proc/sys`
  path, or a new argument list for this.
- **No bypass.** There is no approval boolean, environment variable, flag or
  file that makes the pass skip a check of §6, and no "router mode" setting.
  A host that cannot meet §6 does not get the tier.
- **The operator's host configuration is not in the signed generation.** The
  files that set forwarding and the rules (§8) are not measured: an edit to
  them does not fail the generation, and the operator's signature does not
  cover them. What Nexus relies on is the **kernel state** they produce, read
  at the pass and re-read by the verify unit (§6), never the files. Measuring
  the files would add nothing those reads do not already check, and would
  bind Nexus to one network tool.

## 4. Options, and the decided default

| option | idea | verdict |
| --- | --- | --- |
| P1 | the LAN routes `10.255.196.0/30` to the node's address on an ingress interface; the operator turns on forwarding for the ingress interfaces (and for `az-decoy0`, §7); Nexus sets nothing and the pass checks it | **decided** (Q11, 2026-10-22) |
| P2 | Nexus (the helper, or a new unit) writes the per-interface sysctls at start and resets them at stop | needs `ProtectKernelTunables=no` and a writable `/proc/sys` in a root unit: a new privilege and a writer of kernel state; a crash leaves forwarding on with no table; **rejected** |
| P3 | the operator sets `net.ipv4.ip_forward=1` (host-wide) | every interface forwards, `management` and `observation` included, and every interface created later (`conf.default`); the node becomes a router between all its networks; **rejected** |
| P4 | proxy ARP: the node answers ARP on the ingress for `10.255.196.2`, so LAN hosts reach it on-link | the decoy's address would have to sit inside the LAN prefix, which conflicts with the fixed /30 and with §4.2 of the grant design (no approved prefix may touch `10.255.196.0/24`); proxy ARP answers for whatever the routing table holds (the `proxy_arp` switch is per interface, not per address); forwarding is still needed; **rejected**, and `proxy_arp` must be off (§6) |
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
(grant §6), which is exactly when forwarding on the ingress is still on.

| option | idea | verdict |
| --- | --- | --- |
| K1 | the operator adds two routing rules per ingress interface (below), so that a packet received on it is forwarded only toward the /30 and is otherwise discarded, whether or not the table exists; the pass and the verify unit read them | **adopted** (R2 of §9) |
| K2 | a drop in the decoy table: `iifname { <ingress> } oifname != "az-decoy0" drop` in the forward chain | holds only while the table exists; **adopted as a second wall** (R3) |
| K3 | an operator-written nftables ruleset that drops other forwarding from the ingress | needs `nftables.service` (or similar) enabled, which withholds the tier (grant §6.2), and it can flush the decoy table; **rejected** |
| K4 | a VRF holding the ingress and `az-decoy0` | the helper would have to enslave the bridge to a VRF (a new step and a new object to check); heavy for one /30; **not chosen** |
| K5 | K1 with a dedicated table: the helper adds `10.255.196.0/30 dev az-decoy0` to its own table, and rule 1960 looks up only that table | removes the dependence on `main` described below, but makes the helper write routing state (a new step, undo and read-back check) against the invariant of §3; **not chosen in this phase**; reconsidered if the VM shows the route check below to be fragile |

**K1 in detail.** For each ingress interface, with priority numbers below
the main table's rule (32766), so they are evaluated before it:

```
ip rule add priority 1960 iif <ingress> to 10.255.196.0/30 lookup main suppress_prefixlength 29
ip rule add priority 1961 iif <ingress> blackhole
```

- The local table (priority 0) still comes first, so packets for the node's
  own addresses are delivered as before. That includes `10.255.196.1` and
  the management interface's address: under Linux's weak-host model a LAN
  host can reach the host's services on any of the node's addresses through
  the ingress. That is the host's **input** policy, a separate matter this
  design neither relies on nor changes (the decoy table's input chain drops
  only what arrives on `az-decoy0`).
- The first rule looks up the /30 in `main` and ignores any route of prefix
  length 29 or shorter (`suppress_prefixlength 29`), so a default or a
  `10.0.0.0/8` route does not carry the packet elsewhere; the lookup falls
  through to the second rule, which discards silently (no ICMP, which would
  only tell a scanner a router is there).
- **What K1 does not cover.** A route in `main` of prefix length 30, 31 or
  32 inside the /30 that points at another interface (a stray
  `10.255.196.2/32 via` the management side, say) is not suppressed: while
  `az-decoy0` does not exist it would carry ingress traffic out of that
  interface. K1 therefore rests on a **precondition**: no route in `main`
  inside `10.255.196.0/24` points anywhere but `az-decoy0`. The pass checks
  it, and the verify unit re-checks it (§6). Between those reads, while the
  table exists, **K2 is the only thing that stops such a route being used**;
  while the table does not exist, nothing does, and the operator's procedure
  (§8) forbids routing the /24 anywhere on the node.
- **IPv4 only.** `ip rule` here is IPv4; K1 does nothing for IPv6. IPv6
  forwarding must be off on every interface (R5, checked in §6). K2 matches
  interface names in an `inet` table, so it drops IPv6 from the ingress as
  well, but again only while the table exists.

Configured with the operator's network tool, systemd-networkd's
`[RoutingPolicyRule]` in the ingress's `.network` file (§8), because
networkd removes rules it did not create. *Inferred:* both selectors and
`blackhole` as a rule action (§11).

**Ordering, and commissioning §2.** Commissioning §2 forbids the node to
forward or route until activation completes, and §3 and §8 forbid binding to
a kernel name. Under P1 the forwarding switch of the ingress is on from boot,
before the pass. The reading this design proposes, **not decided** (R6,
returned to the owner): §2 is about what the node **does**, and with K1 installed **before** forwarding comes on, every
packet the ingress receives before a grant is either local or discarded,
because the only path K1 leaves is the connected route of `az-decoy0`, which
exists only after the tier is granted and the helper has run. So:

- the rules must be in place before forwarding is turned on, in every boot;
  whether networkd installs a link's `[RoutingPolicyRule]` before it writes
  the same link's `IPv4Forwarding=` is a VM item (§11). If it does not, the
  measured window goes back to the owner; no workaround is proposed blind;
- the §8 configuration is installed only after commissioning has closed with
  a v3 scope, never during inventory or commissioning;
- forwarding is turned on by networkd's per-link `IPv4Forwarding=yes` in a
  `.network` file that matches the ingress by `Path=` and
  `PermanentMACAddress=`, not by `Name=`, so a different NIC that inherits
  the kernel name does not inherit forwarding. A `sysctl.d` line naming the
  interface is not used for the ingress: it would. The rules of K1 still
  name the interface (a rule's `iif` is a name). A rule that follows the name
  to another NIC only discards more, and the pass checks that their name is
  the resolved ingress;
- **the name is pinned** by a `.link` file matching the same `Path=` and
  `PermanentMACAddress=` (§8), so that forwarding (bound to the NIC) and K1
  (bound to the name) stay on one interface. **What remains:** if the pin
  does not take (the name is already taken, or the `.link` file does not
  match after a change), the ingress NIC forwards under another name that
  K1 does not cover, from the moment networkd configures it until the pass
  reads the rules and withholds. The pass closes the grant, not that window;
  it is a VM item (§11) and part of R6.

## 6. The pass condition (G6; not implemented here)

Condition 6 of [grant §5](deception-exposure-grant.md#5-the-grant-condition)
("the forwarding condition of §4.5") is this section. The pass reads; it never
writes. The same reads are repeated by the verify unit of
[grant §6](deception-exposure-grant.md#6-watching-the-table-f1-the-remainder)
(R4): every period and before every decoy start, and a departure trips the
units as a table departure does. Read once, at the pass, K1 could be lost
afterwards (a networkd reload, a link flap that re-configures the link) with
nothing noticing.

**Interfaces.** The ingress names come from the `deception_bridge` role, and
the `management` and `observation` names from their roles, resolved exactly
as in [grant §4.3](deception-exposure-grant.md#43-how-the-helper-receives-it):
from the commissioning evidence and the current inventory, an ambiguous or
missing identity withholds, no name substitutes for a role. Each name passes
the §4.3 check (`[A-Za-z0-9_.-]{1,15}`, not beginning with `az-decoy`) and
is not `all`, `default`, `lo`, `.` or `..`; the path built from it must have
`/proc/sys/net/ipv4/conf` (or `.../ipv6/conf`) as its exact parent, compared
before it is opened. "Every other interface" means the entries the kernel
lists under `/proc/sys/net/ipv4/conf` and `/proc/sys/net/ipv6/conf`, checked
the same way.

**Reads.** Files under `/proc/sys/net/ipv4/conf/` and
`/proc/sys/net/ipv6/conf/`, opened without following links, read within a
small bound; the content must be exactly `0\n` or `1\n`, anything else
(absent, unreadable, another value) is unreadable and withholds. If
`/proc/sys/net/ipv6` does not exist at all (IPv6 disabled at boot), IPv6
forwarding counts as off; a single missing file under an existing directory
is unreadable (*inferred* layout). These are the host namespace's values,
which is where the controller runs. The routing rules and the routes of
`main` are read through route netlink dumps (`RTM_GETRULE`,
`RTM_GETROUTE`; the controller has `AF_NETLINK`; *inferred* that a dump needs
no capability).

**Holds when** (the owner's decided items in bold; the others are this
design's defaults, R1, R2 and R5 of §9, required before G6):

| item | value | reason code when not |
| --- | --- | --- |
| **every ingress interface** | `forwarding` is `1` | `forwarding_ingress_off` |
| **every `management` and `observation` interface** | `forwarding` is `0` | `forwarding_role_on` |
| IPv4 `conf.all` and `conf.default` (R1) | `forwarding` is `0` | `forwarding_host_wide` |
| every other interface present, except the ingress (and, in the verify, `az-decoy0`) (R1) | `forwarding` is `0` | `forwarding_other_on` |
| IPv6 `conf.all`, `conf.default` and every interface (R5) | `forwarding` is `0` | `forwarding_ipv6_on` |
| `conf.all` and every ingress interface (R1) | `proxy_arp` is `0` | `proxy_arp_on` |
| the IPv4 rules (R2) | every rule with a priority below 32766 is either the local rule (priority 0, `lookup local`, no selector) or one of the K1 pair of a resolved ingress interface, matching it exactly: priority, `iif`, destination, table, action, `suppress_prefixlength`, and no other selector (no source, `oif`, `fwmark`, `tos`, `uidrange`, `l3mdev`, IP protocol or port selector); each ingress has exactly its pair | `ingress_containment_absent` |
| the routes of `main` (R2) | no route inside `10.255.196.0/24` (at the pass, before the bridge exists, none at all; in the verify, only the connected `10.255.196.0/30 dev az-decoy0`) | `decoy_prefix_routed` |
| any read above | readable, in the closed form | `forwarding_unreadable` |

The rule check is deliberately blunt: any other rule before `main` withholds,
whatever it matches, so the check never has to reason about which rules could
match an interface. A site that needs its own policy routing is not a decoy
host in this phase. That includes a VPN that installs rules (Tailscale,
`wg-quick` with its `fwmark` rules): with one, the tier is always withheld,
and that is intended.

The exact attribute set compared is **fixed from the dump observed on the
VM** (§11), not from this table's wording: the kernel and networkd may add
attributes this design does not foresee. The rule's `protocol` field (who
installed it: *inferred* `static` for networkd's rules, `kernel` for the
local rule) is **left out of the comparison**: it says who wrote the rule,
not what it matches.

**When the pass runs relative to networkd.** The pass does not wait for
networkd to finish configuring the ingress, so early in a boot it can read
forwarding still `0` or the rules not yet there, and withhold. Policy: **no
new re-evaluation loop**. A withhold at the pass stands for that boot, with
its reason code, as every other withhold does (the controller runs once per
boot); a later boot evaluates again. To keep it from withholding by mere
timing, G6 measures on the VM whether ordering the controller
`After=systemd-networkd-wait-online.service` (a no-op where that unit is not
in the boot) or `After=network-online.target` brings the reads in order, and
what it delays for every other tier; the chosen ordering is an `After=` on
the controller's unit file, measured in the generation like the rest, and
adds no privilege, unit or loop. Until then the cost of a slow networkd is
a withheld tier, never a grant on a half-configured host.

Each code is a fixed word followed by a fixed phrase, in the form the
controller already uses; none carries an interface name, a prefix or a
value. Every failure withholds the tier (at the pass) or trips the units (in
the verify), and nothing else.

`az-decoy0` is **not** in the pass's reads: it does not exist when the pass
runs, and its forwarding being off fails closed (§7). Whether the verify
should read it is left out: off only makes the decoy unreachable.

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
  `sysctl.d` entry naming `az-decoy0` (§8), applied by udev when the helper
  creates the bridge. Unlike the ingress, `az-decoy0` is a name Nexus fixes
  for a virtual device it creates, so naming it binds to no hardware; and a
  networkd `.network` matching it is avoided, because networkd would then
  manage a link the helper owns. Forwarding on `az-decoy0` concerns only
  packets received from the decoy's namespace; every one of them except the
  established replies is dropped by the table, and if the table is gone, by
  the decoy's own cgroup filter (`IPAddressDeny=any`). K1 does not apply to
  it (its rules match the ingress), and a rule set for `iif az-decoy0` would
  have to repeat the approved prefixes in the operator's configuration, so
  none is proposed; what is open when both the table and the cgroup filter
  are lost is measured by `HG-06` (§10). It is **not** a pass item (the
  bridge does not exist yet) and not an isolation check (its absence only
  makes the decoy unreachable). Using `conf.default.forwarding=1` instead is
  rejected: every interface created later would forward.
- **A reply must leave by the ingress.** Today's reply rule names no output
  interface, so an asymmetric route (the LAN host reachable through the
  management interface) would carry decoy replies out of it. R3: the reply
  accept also matches `oifname { <ingress> }`, so such a reply falls to
  `iifname "az-decoy0" drop`. Reverse-path filtering in strict mode on the
  ingress (the value used is the larger of `conf.all.rp_filter` and the
  interface's; `1` is strict) would drop the request itself in the same
  case; loose mode (`2`, systemd's default, *inferred* for Debian 13) does
  not.
- **A packet with no conntrack entry** to `10.255.196.1` from the decoy is
  local to the host and goes to the input chain, which drops everything from
  `az-decoy0`. A reply never bypasses the reverse translation into the host.
- **After an `nft` flush** (grant §6) the NAT chain is gone, but conntrack
  entries keep their mappings until they expire: established connections
  keep working until the watch stops the units; new ones arrive
  untranslated and the decoy's cgroup filter drops them (grant §4.4,
  inferred there too). A flush does not touch routing rules, so K1 still
  holds against it. This is true of an `nft` flush only: a networkd reload
  or a re-configured link can remove K1 as well, which is why the verify
  re-reads it (R4).
- The masquerade needs `nf_conntrack` and `nf_nat`; it is the same
  translation A3 already brings, and this design adds none.

## 8. The operator's part (outline)

For [operations](operations.md#deception-lite-decoy-network-196), written
when G6 lands. Nexus installs none of these files and edits none of them,
and none of them is in the signed generation (§3). Installed only after
commissioning has closed with a v3 scope. **When the node returns to
`COMMISSIONING_REQUIRED` or is re-commissioned**, the operator removes the
node-side files of items 2 and 3 before inventory runs (commissioning §2
applies again), and installs them again only after commissioning closes.

1. **On the LAN**: a static route `10.255.196.0/30 via <the node's address on
   the ingress>`, on the LAN router or on each host meant to reach the decoy.
   Nothing on the LAN may use `10.255.196.0/24`. A stateful LAN router that
   sees only one direction of the conversation may need the route on the
   hosts instead.
2. **On the node, the ingress** (example, one ingress; a `.link` file that
   pins its name, and one `.network` file, so that the rules and forwarding
   come from one place):

   ```
   # /etc/systemd/network/40-azazel-decoy-ingress.link
   [Match]
   Path=<the ingress's bus path>
   PermanentMACAddress=<the ingress's permanent MAC>

   [Link]
   Name=azin0
   ```

   ```
   # /etc/systemd/network/40-azazel-decoy-ingress.network
   [Match]
   Path=<the ingress's bus path>
   PermanentMACAddress=<the ingress's permanent MAC>

   [Network]
   IPv4Forwarding=yes

   [RoutingPolicyRule]
   Priority=1960
   IncomingInterface=azin0
   To=10.255.196.0/30
   Table=main
   SuppressPrefixLength=29

   [RoutingPolicyRule]
   Priority=1961
   IncomingInterface=azin0
   Type=blackhole
   ```

   The addressing of the ingress (its LAN address) goes in the same file and
   is the operator's. Never `IPForward=` or `IPMasquerade=` in any `.network`
   file, never `net.ipv4.ip_forward = 1`, never a write to `conf.all` or
   `conf.default`, and no IPv6 forwarding anywhere (§2: each turns on more
   than one interface, or IPv6). networkd applies, per link, the first
   `.network` file in lexical order that matches; if another file sorts
   earlier and matches the ingress, this one is ignored and forwarding stays
   `0`, so the pass withholds (it fails closed). The pinned name is chosen
   not to collide with a kernel-assigned one and passes the name check of §6.
3. **On the node, the bridge's forwarding**:

   ```
   # /etc/sysctl.d/61-azazel-decoy-forwarding.conf
   net.ipv4.conf.az-decoy0.forwarding = 1
   ```

4. **On the node, nothing else**: no route into `10.255.196.0/24` on any
   interface, no other routing rule before `main`, `proxy_arp` off. **After a
   crash**, remove the leftovers first: a stale `az-decoy0` (with it goes its
   `10.255.196.0/30 dev az-decoy0` route, which would otherwise withhold the
   tier as `decoy_prefix_routed`) and a stale `inet azazel_decoy` table, as
   [operations](operations.md#deception-lite-decoy-network-196) already says
   for the helper.
5. **To see it**: `sysctl net.ipv4.conf.azin0.forwarding
   net.ipv4.conf.az-decoy0.forwarding` (the second only while the decoy units
   run), `ip rule show`, `ip route show table main 10.255.196.0/24`, and from
   an approved LAN host a connect to `10.255.196.2:2222`. A withheld tier, or
   a trip, names the reason code of §6.

## 9. Conditions added by this design

The decided default of Q11 stands as written. Writing it out showed the
following. Each only withholds the tier or stops the units, so each is
**adopted as a default the owner may overturn**, as the owner directed for
narrowing conditions; R1, R2 and R5 are required before G6 is merged, R4 in
G2 (and wired in G6), R3 in G1. R6 is different: it is a reading of a
commissioning rule, not a narrowing, and stays **open** for the owner.

1. **R1.** IPv4 `conf.all` and `conf.default` at `0`, every interface other
   than the ingress at `0` (`asset_acquisition`, unassigned interfaces,
   container bridges), and `proxy_arp` off. A host where anything else
   forwards is not a decoy host in this phase; `default` at `0` also keeps an
   interface added after the pass from forwarding. *Required before G6.*
2. **R2.** Containment of the ingress by K1, with the route precondition of
   §5, checked as `ingress_containment_absent` and `decoy_prefix_routed`.
   *Required before G6.* Without it a granted tier implies a node that routes
   whatever its ingress receives.
3. **R3** (implemented in G1b). The G1 ruleset: the reply accept gains `oifname { <ingress> }`;
   the forward chain gains K2's drop; both rendered from the scope and
   compared by the isolation check like the rest.
4. **R4.** The verify unit of grant §6 repeats every read of §6 (it needs no
   capability for them: `/proc/sys` is readable under its sandbox and it has
   `AF_NETLINK`) and trips on a departure. *Required in G2, and part of the
   grant condition in G6.*
5. **R5.** IPv6 forwarding off on `all`, `default` and every interface (the
   decoy is IPv4 only, and K1 does not cover IPv6). *Required before G6.*
6. **R6 (open, returned to the owner).** The reading of commissioning §2 in
   §5: forwarding switched on for the ingress before activation is
   compatible with "must not forward" only because K1 discards everything
   the ingress receives until a grant, and only while the name pin holds
   (§5, the remaining window). If the owner reads §2 as forbidding the switch
   itself, P1 conflicts with it and Q11 must be revisited. G6 is not merged
   before the owner answers.

## 10. `HG-06`

`HG-06` (the bridge refuses to forward) is measured on the real host **under
§8's configuration**: forwarding on for the ingress and `az-decoy0`, K1 in
place. A run with forwarding off would pass trivially and prove nothing about
the deployed node. Its cases include, besides the denied paths with the
table in place:

- from a LAN host using the node as its gateway, every destination other
  than the decoy, with the decoy units running and stopped (K1);
- from the decoy namespace, a probe outside the decoy's cgroup filter
  sending toward the LAN, the management side and the uplink, with the table
  present and after `nft flush ruleset`: what `az-decoy0`'s forwarding opens
  once the table and the cgroup filter are both gone, recorded as the
  residual it is;
- a stray `/32` route into the /30 toward another interface, with and
  without the table (the precondition of §5 and K2).

The gate's claim and record format stay as in
[hardware gates](hardware-gates.md); this adds cases, not a gate.

## 11. To check on the VM (G4; a mechanism check, not hardware evidence)

1. With `conf.all` `0` and only `conf.<ingress>` `1`: a packet received on
   the ingress for the /30 is forwarded to `az-decoy0`; a packet received on
   the management interface is not; writing `ip_forward` changes
   `conf.all.forwarding` and every interface's value and only
   `accept_redirects` besides (the reason P3 is rejected);
2. with `conf.az-decoy0.forwarding` `0`: the decoy accepts, the replies are
   dropped on the node; with `1` the banner returns;
3. the `sysctl.d` entry for `az-decoy0` is applied by udev when the helper
   creates the bridge, and how long after; whether a connect in that window
   fails (an availability cost only); networkd leaves `az-decoy0` unmanaged;
4. K1: with the decoy units stopped, a LAN host using the node as its gateway
   reaches nothing beyond the node (blackholed, no ICMP); with them running,
   only the /30; a `10.0.0.0/8` route in `main` does not capture the /30;
   **a `/30`, `/31` or `/32` route inside `10.255.196.0/24` toward another
   interface does**, and K2 then drops it while the table exists, and the
   pass and verify report `decoy_prefix_routed`;
5. A3 together with forwarding: the cgroup filter sees `10.255.196.1`, the
   reverse translation happens before the reply's route lookup (the reply
   rule matches `@approved_v4`), and after `nft flush ruleset` an established
   connection survives until the watch trips while a new one is not answered;
6. with the reply route pointing at the management interface: the reply is
   dropped (after R3), and with `rp_filter=1` on the ingress the request is;
7. the pass's and verify's reads under their sandboxes: `/proc/sys/net/ipv4/conf/*`
   and `ipv6/conf/*` readable, a write refused, the `RTM_GETRULE` and
   `RTM_GETROUTE` dumps without a capability; the IPv6 tree absent under
   `ipv6.disable=1`;
8. systemd-networkd 257 on Debian 13: per-link `IPv4Forwarding=yes` sets
   only that link's value; `IPForward=` and `IPMasquerade=` turn on host-wide
   forwarding; `[RoutingPolicyRule]` accepts `Table=main` and produces
   exactly the two rules of §5; **the attributes of the actual
   `RTM_GETRULE` dump** of those rules and of the local rule (including
   `protocol`) are recorded, and the comparison of §6 is fixed from them;
   **whether the rules are installed before the link's forwarding is turned
   on**, at boot and after `networkctl reload` and a link down/up; whether a
   reload or link flap removes the rules for a moment (the verify's window);
9. a replacement NIC that takes the ingress's kernel name does not match the
   `.network` file, keeps forwarding `0`, and the pass withholds;
10. **name swaps**: with the `.link` pin, and with the pin made to fail (its
    name already taken), which interface carries forwarding `1` and which the
    K1 rules, from boot to the pass; how long the ingress forwards without K1
    in the failing case;
11. the controller's timing: with and without an `After=` on
    `systemd-networkd-wait-online.service` or `network-online.target`,
    whether the pass reads the ingress configured, and what each ordering
    delays.
