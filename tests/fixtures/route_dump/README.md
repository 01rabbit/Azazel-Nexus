# Recorded route-netlink dumps and `ip -j` output

Raw `RTM_GETRULE` and `RTM_GETROUTE` dumps (`*.bin`, the bytes
`exposure_route_dump` received, sequence numbers 1 and 2) and, taken in the
same network namespace a moment later, `ip -j -4 rule show`,
`ip -j -4 route show table main` and the link names (`netlink.read_links`).
`tests/unit/test_exposure_route_dump.py` reads both and requires equal
output (`docs/deception-exposure-wiring.md` §4.4, B1).

Recorded by that test's live check (`AZ_ROUTE_DUMP_RECORD=<dir>`) as root in
a fresh network namespace of the privileged test container (Debian 13,
iproute2 6.15, kernel 6.8 of the Colima VM), on dummy links `lan0` and
`eth9`; addresses are documentation and decoy ranges only.

* `k1-*`: the K1 pair on two ingress, in both forms (`ip rule add` on
  `lan0`; networkd's `table main` and `protocol static` on `eth9`), and no
  route inside `10.255.196.0/24`.
* `full-*`: the same plus selector-bearing rules and routes into the /24
  (connected, gateway, multipath, IPv6 `via`, blackhole, unreachable,
  throw, local), a route of another table, and a nexthop-object route
  outside the /24.

This is not the VM's evidence of reachability §11 item 8; it shows the
parser reads what a Linux kernel actually emits.
