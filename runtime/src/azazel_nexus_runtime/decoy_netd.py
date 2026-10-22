"""`az-decoy-netd`: the Deception Lite network helper's fixed executable (#196).

Design D1 (`docs/deception-redirect-prerequisites.md` §5, §10, §13, §14). A
one-shot unit, root with exactly `CAP_NET_ADMIN` as a bounding set, in the
host network namespace, that runs `decoy_network.HELPER_STEPS` and nothing
else: it checks that neither the bridge nor the table exists (and changes
nothing if either does), loads the decoy table, then creates the bridge
`az-decoy0`, gives it the host's fixed address, attaches the host end of the
veth pair the namespace unit created, and brings both up. It never enters the
decoy namespace (it cannot: `setns` needs `CAP_SYS_ADMIN`).

**Its one input** (`docs/deception-exposure-grant.md` §4.3 H3, G1b). At
start, right after removing the previous isolation record and before it
checks or builds anything, it reads the exposure scope from the fixed
credential path its unit's `LoadCredential=decoy-scope:...` provides
(`azazel_nexus.decoy_scope.read_scope_credential`: no link, root's, bounded,
canonical, re-validated), and builds the run's plan from it
(`decoy_network.helper_plan`): the constant argument lists and exactly one
ruleset rendered from the scope. The previous isolation record is removed
before the scope is read, so a scope that is present and refused builds
nothing, leaves no record behind (no earlier pass survives it) and exits 1.
With no credential directory at all (the executable run
outside its unit, as in a container check) it has no scope and loads the
table of the first build, with nothing approved. Under its unit a missing
source file fails the start before this runs.

**Isolation evidence** (§14). Before it checks or builds anything it removes
the previous isolation record and reads this boot's id; after it has built
the host side it reads it back with the two fixed commands of
`decoy_network.HELPER_VERIFY` and writes this boot's record
(`decoy_isolation_check.Recorder`), compared against the same rendered
ruleset and carrying the scope's digest, never its content. The decoy
requires that record before it listens. If a check does not pass or the
record cannot be written, it undoes what it built and exits 1.

Started with no argument it builds; `ExecStop=` starts it with exactly
`stop`, and it removes the record, takes the host end down, deletes the
bridge and then the table, so the path is cut before the rules go; if cutting
the path fails, the table stays and it exits 1. `stop` reads no scope: its
undo lists are constants. `azazel-decoy-verify.service` starts it with
exactly `verify` (#196 G2, `docs/deception-exposure-grant.md` §6.1): it
reads back and compares, changes nothing and writes no record
(`decoy_watch.verify`), and exits 1 on any departure, which trips the decoy
units. Anything else is refused (exit 2). It reads no
decoy observation, no Edge decision, no environment and no socket. A failed
step undoes what the earlier ones made and exits 1.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

from azazel_nexus.decoy_scope import read_scope_credential

from .decoy_isolation_check import Recorder
from .decoy_network import HELPER_PLAN, Capture, Plan, Runner, helper_plan, main_for
from .decoy_watch import verify

__all__ = ["main"]


def _start_plan() -> Plan:
    """The run's plan from its scope; `ValueError` (a fixed phrase) when refused."""

    return helper_plan(read_scope_credential())


def main(argv: Optional[Sequence[str]] = None, *, run: Optional[Runner] = None,
         capture: Optional[Capture] = None, recorder: Optional[Recorder] = None) -> int:
    """Build (no argument), remove (`stop`) or check (`verify`) the host side."""

    if list(sys.argv[1:] if argv is None else argv) == ["verify"]:
        # The verify unit (#196 G2): read-backs only, no recorder, no step.
        return verify(capture=capture)
    return main_for("az-decoy-netd", HELPER_PLAN, argv, run,
                    recorder=Recorder() if recorder is None else recorder,
                    capture=capture, start_plan=_start_plan)


if __name__ == "__main__":  # pragma: no cover - the wrapper calls main()
    raise SystemExit(main())
