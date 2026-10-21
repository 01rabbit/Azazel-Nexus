"""`az-decoy-netd`: the Deception Lite network helper's fixed executable (#196).

Design D1 (`docs/deception-redirect-prerequisites.md` §5, §10, §13). A
one-shot unit, root with exactly `CAP_NET_ADMIN` as a bounding set, in the
host network namespace, that runs `decoy_network.HELPER_STEPS` and nothing
else: it checks that neither the bridge nor the table exists (and changes
nothing if either does), loads the fixed nftables table, then creates the bridge
`az-decoy0`, gives it the host's fixed address, attaches the host end of the
veth pair the namespace unit created, and brings both up. It never enters the
decoy namespace (it cannot: `setns` needs `CAP_SYS_ADMIN`).

Started with no argument it builds; `ExecStop=` starts it with exactly
`stop`, and it takes the host end down, deletes the bridge and then the
table, so the path is cut before the rules go; if cutting the path fails,
the table stays and it exits 1. Anything else is refused
(exit 2). It reads no decoy observation, no Edge decision, no file, no
environment and no socket; the commands and their arguments are constants of
`decoy_network`. A failed step undoes what the earlier ones made and exits 1.
"""

from __future__ import annotations

from typing import Optional, Sequence

from .decoy_network import HELPER_ABSENT, HELPER_STEPS, Runner, main_for

__all__ = ["main"]


def main(argv: Optional[Sequence[str]] = None, *, run: Optional[Runner] = None) -> int:
    """Build (no argument) or remove (`stop`) the host side of the decoy network."""

    return main_for("az-decoy-netd", HELPER_STEPS, argv, run, HELPER_ABSENT)


if __name__ == "__main__":  # pragma: no cover - the wrapper calls main()
    raise SystemExit(main())
