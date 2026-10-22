"""The Deception Lite watch: `az-decoy-netd verify` (#196 G2).

`docs/deception-exposure-grant.md` §6.1 (W4, decided as §10 Q6 and Q7) and
`docs/deception-exposure-reachability.md` §6 and §9 R4. The verify unit
(`azazel-decoy-verify.service`) runs the helper's executable with the one
word `verify`, before every decoy start and every 10 s while the decoy runs.
It reads, compares and exits: 0 when everything matches, 1 otherwise. A
non-zero exit fails the unit, and its `OnFailure=` starts the trip unit,
which stops the namespace unit and, through `Requires=`, the helper and the
decoy. It only narrows: it judges no traffic, decides nothing for Edge, and
stops nothing itself.

**What it reads.** Only the four fixed read-backs of
`decoy_network.WATCH_READS`, through `decoy_network.capture_fixed` (its plan,
`decoy_network.verify_plan`, holds no command that changes anything), and
the files under `/proc/sys/net/ipv4/conf` and `/proc/sys/net/ipv6/conf`
that hold `forwarding` and `proxy_arp`. Its scope is its own credential
(`azazel_nexus.decoy_scope.read_verify_scope_credential`: the same source
file as the helper's, by the same rules). Unlike the helper it has no
scope-less mode: no credential directory compares nothing and exits 1.

**What it compares.**

1. The table and the host's links, with the helper's own judgement
   (`decoy_isolation_check.evaluate`) against the ruleset rendered from the
   scope: the same nine checks the helper records, but nothing is written.
   A table that is missing or was flushed is `unreadable`, and fails.
2. Reachability R4, the reads of reachability §6 that a verify can make
   (`decoy_reachability.reachability_departures`, re-exported here). The verify knows the ingress interfaces from
   the scope, and not the management and observation ones, so "off on those
   roles" is covered by "off on every interface but the ingress and the
   bridge" (`forwarding_other_on`); the pass of G6 reads the roles.
   The routing rules are checked as far as G2 goes: below the main table's
   priority there is exactly the local rule and, per ingress, the K1 pair
   with its defining attributes (destination, table, `suppress_prefixlength`,
   `blackhole`). That no rule carries another selector, and the exact
   attribute set, wait for the dump observed on the VM (reachability §11
   item 8) and are G6's.

**What it says.** One journal line of fixed check names and fixed reason
codes, never an interface name, a prefix, an address or a value.
"""

from __future__ import annotations

import sys
from typing import Optional

from azazel_nexus.decoy_scope import read_verify_scope_credential

from .decoy_isolation_check import evaluate
from .decoy_network import HELPER_VERIFY, Capture, capture_fixed, verify_plan
# The reads and judgements of reachability §6 live in `decoy_reachability`
# (#196 G6 preparation A), shared with the pass's judgement there; the
# verify's names are re-exported here and its behaviour is G2's.
from .decoy_reachability import (
    DECOY_PREFIX_ROUTED,
    FORWARDING_HOST_WIDE,
    FORWARDING_INGRESS_OFF,
    FORWARDING_IPV6_ON,
    FORWARDING_OTHER_ON,
    FORWARDING_UNREADABLE,
    INGRESS_CONTAINMENT_ABSENT,
    IPV6_ABSENT,
    PROXY_ARP_ON,
    REACHABILITY_CODES,
    _rules_contained,  # noqa: F401 - the G2 tests (#287 F3) call it through here
    reachability_departures,
    read_sysctls,
)

__all__ = [
    "DECOY_PREFIX_ROUTED",
    "FORWARDING_HOST_WIDE",
    "FORWARDING_INGRESS_OFF",
    "FORWARDING_IPV6_ON",
    "FORWARDING_OTHER_ON",
    "FORWARDING_UNREADABLE",
    "INGRESS_CONTAINMENT_ABSENT",
    "IPV6_ABSENT",
    "PROXY_ARP_ON",
    "REACHABILITY_CODES",
    "read_sysctls",
    "reachability_departures",
    "verify",
]


def _say(text: str) -> None:
    print(f"az-decoy-netd verify: {text}", file=sys.stderr, flush=True)


#: The names of the helper's two read-backs, which the table checks read.
_TABLE_READS = tuple(name for name, _ in HELPER_VERIFY)


def verify(*, capture: Optional[Capture] = None, read_scope=None,
           sysctls=None) -> int:
    """Read everything, compare, exit 0 when it all matches and 1 otherwise.

    `capture`, `read_scope` and `sysctls` are private test seams;
    `az-decoy-netd verify` passes none of them. Nothing is written, nothing
    is changed, no record is touched: a refused scope, a read-back that
    fails or cannot be read, a table check that does not pass and a
    reachability departure each make the exit 1.
    """

    try:
        scope = (read_verify_scope_credential if read_scope is None else read_scope)()
        if scope is None:
            # No credential directory (review of #287 F1): unlike the
            # helper, the verify has no scope-less mode. Comparing with the
            # table of the first build would let a verify pass with nothing
            # to compare against; it refuses instead.
            _say("the decoy scope is absent; nothing was compared")
            return 1
        plan = verify_plan(scope)
    except ValueError:
        _say("the decoy scope could not be read; nothing was compared")
        return 1
    ruleset = plan.ruleset
    if ruleset is None:  # pragma: no cover - verify_plan always renders one
        return 1
    try:
        outputs = {name: (capture_fixed(command, plan=plan) if capture is None
                          else capture(command))
                   for name, command in plan.verify}
        table = evaluate({name: outputs[name] for name in _TABLE_READS}, ruleset)
        ipv4, ipv6 = (read_sysctls if sysctls is None else sysctls)(ruleset.ingress)
        departures = reachability_departures(ipv4, ipv6, outputs["host_rules"],
                                             outputs["main_routes"], ruleset.ingress)
    except Exception:  # noqa: BLE001 - an error here is a verify that did not pass
        _say("the read-back could not be evaluated")
        return 1
    failed = [f"{name} {result}" for name, result in table.items() if result != "pass"]
    if not failed and not departures:
        _say("the table, the host's links, forwarding, the routing rules and the "
             "routes match")
        return 0
    _say("departed: " + ", ".join(failed + list(departures)))
    return 1
