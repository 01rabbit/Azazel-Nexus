# Read-only NOC observation

Status: **implemented, not verified; wired to an operator snapshot (U3).**
`az-nexus-noc` (`runtime/src/azazel_nexus_runtime/noc_observe.py`) and its
focused tests exist. The same collection now also runs as the passive
observer `az-noc-observe` (§7a), whose snapshot `azazel-nexus status --json`
reads; no daemon imports it, and no target-hardware evidence exists for it.
The Edge NOC Evaluator stays in Edge (below), so this page describes an
observation tool, not an evaluator.

Related: [Architecture](architecture.md) §3.2 ·
[Commissioning](commissioning.md) §4, §5 ·
[Service objectives](service-objectives.md) SO-10 ·
[Inventory confidentiality](inventory-confidentiality.md) ·
[Hardware gates](hardware-gates.md)

## 1. What it is for

An operator on the node asks "what does this node's network look like right
now": uplink (the default route), DNS resolver configuration, DHCP leases,
routes, interfaces, and quality and capacity. `az-nexus-noc` answers with one
JSON object (`azazel-nexus/noc-observation-local/v1`). Every item says what it
was derived from, when it was read, and how fresh the reading is:

```json
{"state": "observed", "value": "up",
 "evidence": {"source": "netlink:RTM_GETLINK dump (NETLINK_ROUTE)",
              "read_monotonic_ns": 0, "read_wall": "…Z",
              "age_s": 0.2, "freshness": "fresh"}}
```

A reading older than `FRESH_WITHIN_SECONDS` (10 s) at render time is `stale`.
The collection reads a first link dump and the first counter values, waits
the counter interval (`--interval`, 0.2 to 10 s), and only then reads the
whole snapshot, so the interval itself never makes the output stale.
An item that could not be read is `unknown`, with a fixed reason code and a
fixed phrase (`UNKNOWN_REASONS`), never a guess and never a value read from
the host.

The output is Nexus-local operator output. It is **not** a Fabric record and
**not** an input to Edge (§6).

## 2. Passive only

[Commissioning](commissioning.md) §5 forbids any frame on an
`observation` interface. The collector does not transmit on any interface:

| it does | it does not |
| --- | --- |
| open `AF_NETLINK` / `NETLINK_ROUTE` sockets, in one function | open any other socket family; a socket of another family offered to it is refused before anything is sent (`socket_not_netlink`) |
| send `RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE` dump requests to the local kernel | bind, connect, `sendto`, `sendmsg`, `setsockopt`, resolve a name, ping, or start a process |
| read `/sys/class/net/*/statistics/*` and `/sys/class/net/*/speed` twice, an interval apart | send any probe to derive quality |
| read `/etc/resolv.conf` and systemd-resolved's upstream `resolv.conf` | send a DNS query |
| read systemd-networkd and dhclient lease files | talk to a DHCP server |

A netlink request goes to the local kernel; it is not bound to an interface
and nothing it carries leaves the host. Reading sysfs is not entirely inert:
a driver may query its own hardware to answer (an MDIO or USB control
transfer, for example). That puts no frame on the wire, but "touches
nothing" would overstate it.

**What enforces this at run time** is the module itself: the family check
that refuses any socket other than `AF_NETLINK` before the one send, and
`_request`, which builds only the three dump types and refuses any other.

**What guards it against regression** is `tests/unit/test_noc_observe.py`:

- an AST scan of the module: imports are an allowlist with no process or
  network-client module, and nothing is imported from `socket` under another
  name; no `connect`, `bind`, `sendto`, `sendmsg`, `getaddrinfo`, spawn or
  `AF_INET*` name, and no `getattr`, `__import__`, `importlib`, `eval` or
  `exec` that could reach one indirectly; no `async def`; exactly one `send`,
  inside the netlink dump (functions, async functions and lambdas are all
  scanned), of a message built by `_request`; exactly one socket constructor,
  `AF_NETLINK`;
- an in-process collection against the kernel, with `socket.socket` replaced
  by a guard that fails any non-netlink family;
- a real-process run of the command under the same guard.

The scan is a regression guard over this source, not a proof: Python can
reach an API by routes no scan models, which is why the run-time checks above
exist.

Azazel-Edge's `noc_monitor` sends ICMP, DNS, TCP and HTTP probes. That is
why it is not reused here.

## 3. What each item reads

| item | source | derived how |
| --- | --- | --- |
| interfaces: admin up, lower up, loopback, operstate, carrier, MTU | `RTM_GETLINK` dump | read as reported |
| interfaces: address count by family and scope | `RTM_GETADDR` dump | counted; no address kept |
| interfaces: link speed | `/sys/class/net/{ifname}/speed` | as reported; `-1`, `0` or `EINVAL` is `speed_not_reported`, any other read error `read_failed` |
| interfaces: counters | `/sys/class/net/{ifname}/statistics/*` | second read; a value that is not a non-negative decimal of at most 20 digits is `file_unparsable` |
| quality and capacity | the two counter reads | deltas over the monotonic interval: bit rates, error and drop deltas, utilisation against link speed. Each counter is judged on its own: one that went backwards (reset or wrap) is listed in `reset_counters` and has no delta, and the rates that depend on it are `null` |
| uplink | `RTM_GETROUTE` dump, **every table** | default routes in the main table and in all other tables, kept apart: count, egress ifindex, gateway present, and the kernel's `linkdown` and `dead` flags. A nexthop-object default is `nexthop_object_not_resolved`. Policy rules are not read (`policy_rules_evaluated: false`), so the output does not say which default a packet would take, and "none in `table_main`" does not mean "no default" |
| routes | `RTM_GETROUTE` dump, every table | counted per family, main table and other tables apart |
| DNS | `/etc/resolv.conf`, `/run/systemd/resolve/resolv.conf` | nameservers counted, loopback (stub) nameservers counted, search domains counted, whether the file is systemd-resolved's link |
| DHCP | `/run/systemd/netif/leases/{ifindex}`, `/var/lib/dhcp/*.leases`, `/var/lib/dhclient/*.leases` | remaining lease time against the wall clock (networkd: file mtime + `LIFETIME`; dhclient: the lease with the latest expiry, not the last in the file), with `expired` marked. A wall clock earlier than `WALL_CLOCK_FLOOR_S` (no RTC, no NTP yet) gives `wall_clock_implausible`. A lease block that cannot be read (an impossible date, an over-long epoch) is `file_unparsable` for its own interface only, and only if no readable lease exists for it |
| uplink reachability, DNS resolution | — | always `unknown`, `active_check_not_performed` (§7) |

Files are opened non-blocking and read only if they are regular files
(`file_not_regular` otherwise). The kernel's own operstate "unknown" is shown
as `kernel_unknown`, so it is not read as this tool's `unknown` state. If the
collection itself fails, the command prints only the fixed line
`az-nexus-noc: collection_failed` to standard error and exits 1: never an
exception's text, which could carry a lease line, a path or a name.

The interface `tx_packets_delta` is shown because an operator will look for it.
It is a host counter on the device under test, and
[SO-10](service-objectives.md#so-10-field-exercise--hardware-only) states that
such counters prove nothing about zero transmission.

## 4. What it does not print

[Inventory confidentiality](inventory-confidentiality.md) classes interface
names and MAC addresses as raw identity. The output carries no interface name,
no MAC, no IP address, no gateway, no nameserver and no search domain.
Interfaces are keyed by kernel ifindex; addresses, nameservers and routes are
counted. Evidence paths are written from templates (`{ifname}`, `{ifindex}`,
`<dhclient lease file>`), never from a real path. The command writes to
standard output only: nothing to the journal and nothing to the audit.

## 5. Roles

Roles come from verified commissioning evidence, never from inference
([commissioning](commissioning.md) §4). The collector does not resolve one
and imports nothing that does. The one resolver of commissioned roles to this
boot's interfaces in this repository, `exposure_interfaces`, belongs to the
Deception exposure tier and is deliberately unwired
(`tests/unit/test_g6_unwired.py` pins that nothing else names it). So the
collector takes a resolution only as a caller-supplied `roles` argument
(kernel name to role, or a withholding reason, which stays withheld as
`role_withheld`). The command as shipped supplies none, so every role reads
`role_evidence_not_provided`.

Fabric's role set has no "uplink" role. The default route's egress ifindex is
an observation about a route, and nothing here turns it into a role.

## 6. Not the NOC Evaluator

[Architecture](architecture.md) §3.2 places the NOC Evaluator in Edge's
Deterministic Core. This collector does not call anything healthy or degraded,
applies no threshold, drives nothing, and its output is not an Edge input.
A contract for ingesting Edge NOC results (or for Edge consuming this output)
needs owner agreement and a Fabric-owned record first
([contract ownership](contract-ownership.md)).

## 7. Implementation status

| item | status | evidence |
| --- | --- | --- |
| passive collector with per-item evidence and freshness | implemented | mock: fixture `/sys`, `/etc`, `/run`, `/var` trees and constructed netlink replies |
| route parsing on a real kernel dump | implemented | recorded container dump (`tests/fixtures/route_dump/full-routes.bin`) |
| no non-netlink socket, no send other than the netlink dump | implemented | AST scan; in-process guard in the Linux test container |
| `az-nexus-noc` reads real netlink state | implemented | **container evidence, not hardware**: a real process in the Linux test container |
| redaction of names, MACs and addresses | implemented | mock: output scanned for the fixture values |
| roles from verified commissioning evidence in the command | not wired | the collector accepts a caller-supplied resolution (mock-tested); the command supplies none |
| SO-10 zero-transmit on the observation interface | **not verified** | needs an independent capture on the target device ([SO-10](service-objectives.md#so-10-field-exercise--hardware-only)); nothing in this repository's CI can satisfy it |
| Edge NOC result ingestion | not started | needs owner agreement (§6) |
| active checks (DNS query, ICMP, TCP, HTTP) | not implemented | owner decision (§8) |
| operator snapshot `noc-status/v1` and the `noc` section of `status --json` | implemented | mock: projection and strict reader against the fixture trees; **container evidence, not hardware**: `az-noc-observe` in a real process in the Linux test container |
| `azazel-noc-observe.service` / `.timer` under systemd | **not run** | unit generated and compared with its declaration; no systemd or VM run yet |

The target-hardware procedure, including the independent capture inside an
SO-10 run, is the [NOC observation runbook](hil-runbooks/noc-observation.md)
(not run).

## 7a. The operator snapshot (U3)

`azazel-noc-observe.timer` runs `azazel-noc-observe.service` every 60 s: a
oneshot of `az-noc-observe` (`noc_snapshot.py`) as its own unprivileged
account `aznoc` (in no socket group, not a service principal of any daemon),
with `RestrictAddressFamilies=AF_NETLINK AF_UNIX`, `IPAddressDeny=any` and
no `PrivateNetwork=` (the host's links are what it reads). It calls the same
`collect` as `az-nexus-noc` and writes `noc_status.project` of it
(`azazel-nexus/noc-status/v1`) into `/var/lib/azazel/run/noc-status`
(`2750 aznoc:azazel-operator`) by temp file and rename.

The snapshot is a closed projection: interfaces by ifindex only (link flags,
operstate, carrier, MTU, speed, address **counts** per family, counters and
their deltas -- traffic, errors, drops -- and the DHCP lease client and
remaining time), the default routes per family and table (count, egress
ifindexes, gateway, linkdown/dead), route counts, resolver **counts**, and
each field's age at observation with its fixed `unknown` reason. No name, MAC,
address, gateway, nameserver or search domain. At most 32 interfaces are
listed; more are counted in `interfaces_omitted`. A collection that fails is
written as `failed` / `collection_failed`, a projection the reader would
refuse as `failed` / `projection_refused`.

`status --json` shows it as the `noc` section (stale after 300 s, its own
`freshness` item). A fresh snapshot makes the section `observed`, never
`running` or healthy; a failed collection makes it `unknown` with the fixed code. Reachability
and name resolution are always `not_measured` with `active_check_not_performed`:
this build sends no probe, so "not measured" is never shown as "down". No unit
requires or binds to the observer; it is installed but neither enabled nor
masked (`systemctl enable --now azazel-noc-observe.timer`).

## 8. Owner decisions

1. **Active checks.** Whether any active check (DNS query, ICMP to the
   gateway, TCP or HTTP) is wanted at all; if so, which, and on **which
   interface**. An `observation` interface is excluded by
   [commissioning](commissioning.md) §5 in any case. A check would need a
   socket family this module refuses, so it would be a separate, separately
   reviewed module, not an option of this one.
2. **Edge NOC result ingestion.** Whether Nexus ingests Edge NOC Evaluator
   results, or Edge consumes this output, and under which Fabric record.
3. **Wiring roles into the command.** Whether `az-nexus-noc` may read the
   protected commissioning evidence to label roles, with which privilege, and
   through which resolver: the existing one is part of the unwired G6
   exposure tier, and using it here would be a G6 wiring change.
4. **Interface names on the operator's terminal.** The output withholds them
   under [inventory confidentiality](inventory-confidentiality.md) §6
   ("default is closed"). Whether a local-only view may show them is the
   responsible operator's classification, not this tool's.
