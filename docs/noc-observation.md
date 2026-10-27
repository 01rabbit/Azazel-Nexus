# Read-only NOC observation

Status: **implemented, not verified, not wired.** `az-nexus-noc`
(`runtime/src/azazel_nexus_runtime/noc_observe.py`) and its focused tests
exist. Nothing on a node runs it by itself, no daemon imports it, and no
target-hardware evidence exists for it. The Edge NOC Evaluator stays in Edge
(below), so this page describes an observation tool, not an evaluator.

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
and nothing it carries leaves the host.

This is enforced in `tests/unit/test_noc_observe.py` three ways: an AST scan of
the module (imports are an allowlist with no process or network-client
module; no `connect`, `bind`, `sendto`, `sendmsg`, `getaddrinfo`, spawn or
`AF_INET*` name; exactly one `send`, inside the netlink dump, of a message
built by the function that admits only the three dump types; exactly one socket
constructor, `AF_NETLINK`), an in-process collection against the kernel with
`socket.socket` replaced by a guard that fails any non-netlink family, and a
real-process run of the command under the same guard.

Azazel-Edge's `noc_monitor` sends ICMP, DNS, TCP and HTTP probes. That is
why it is not reused here.

## 3. What each item reads

| item | source | derived how |
| --- | --- | --- |
| interfaces: admin up, lower up, loopback, operstate, carrier, MTU | `RTM_GETLINK` dump | read as reported |
| interfaces: address count by family and scope | `RTM_GETADDR` dump | counted; no address kept |
| interfaces: link speed | `/sys/class/net/{ifname}/speed` | as reported; `-1` or `EINVAL` is `speed_not_reported` |
| interfaces: counters | `/sys/class/net/{ifname}/statistics/*` | second read |
| quality and capacity | the two counter reads | deltas over the monotonic interval: bit rates, error and drop deltas, utilisation against link speed; a counter that went backwards is `counter_reset` |
| uplink | `RTM_GETROUTE` dump, main table | default route present, count, egress ifindex, whether it has a gateway; a nexthop-object default is `nexthop_object_not_resolved` |
| routes | `RTM_GETROUTE` dump, main table | counted per family |
| DNS | `/etc/resolv.conf`, `/run/systemd/resolve/resolv.conf` | nameservers counted, loopback (stub) nameservers counted, search domains counted, whether the file is systemd-resolved's link |
| DHCP | `/run/systemd/netif/leases/{ifindex}`, `/var/lib/dhcp/*.leases`, `/var/lib/dhclient/*.leases` | remaining lease time against the wall clock (networkd: file mtime + `LIFETIME`) |
| uplink reachability, DNS resolution | — | always `unknown`, `active_check_not_performed` (§7) |

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
