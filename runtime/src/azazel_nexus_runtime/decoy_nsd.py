"""`az-decoy-nsd`: the Deception Lite namespace unit's fixed executable (#196).

Design D1, option (a) (`docs/deception-redirect-prerequisites.md` §5, §10):
a one-shot unit that holds `CAP_SYS_ADMIN` as a bounding set, and only it,
to create the decoy network namespace at the fixed path
`/run/netns/azazel-decoy`, and to do nothing else. The network helper
(`az-decoy-netd`, `CAP_NET_ADMIN`) then configures the bridge, the veth pair
into that namespace and the rules, and the decoy joins it with no capability.

**This build ships the unit profile and this boundary, not the body.** This
executable creates nothing: it takes no argument, reads nothing, calls no
`unshare` or `mount`, runs no `ip`, opens no socket and exits non-zero, so a
start of `azazel-decoy-nsd.service` fails rather than appearing to have
created a namespace it did not create. The activation pass never grants the
unit in this build (`UnitTier.DECEPTION_EXPOSURE` is withheld as
`isolation_evidence_absent`).

When the body is written it stays in this one fixed module: the namespace
path is fixed in code, never a caller's, and no other runtime module gains a
path to creating or removing a namespace.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

__all__ = ["REFUSAL", "main"]

#: What a start of the namespace unit prints, and the whole of what it does.
REFUSAL = (
    "az-decoy-nsd: the decoy namespace unit has no body in this build "
    "(#196); no namespace was created"
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Refuse and exit 1. Takes no argument; any argument is also refused."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        print("az-decoy-nsd: takes no argument", file=sys.stderr)
        return 2
    print(REFUSAL, file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover - the wrapper calls main()
    raise SystemExit(main())
