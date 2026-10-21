"""`az-decoy-netd`: the Deception Lite network helper's fixed executable (#196 P1).

Design D1 (`docs/deception-redirect-prerequisites.md` §5): a one-shot unit
that holds `CAP_NET_ADMIN` as a bounding set, and only it, to build the decoy
network namespace, the `az-decoy0` bridge, the veth pair and the
forwarding-deny rules from the commissioning render. It reads no decoy
observation and no Edge decision.

**Phase P1 ships the unit profile and this boundary, not the body.** This
executable configures nothing: it takes no argument, reads nothing, runs no
`ip` or `nft`, opens no netlink socket and exits non-zero, so a start of
`azazel-decoy-netd.service` fails rather than appearing to have built an
isolation it did not build. The activation pass never grants the unit in
this build (`UnitTier.DECEPTION_EXPOSURE` is withheld as
`isolation_evidence_absent`).

When the body is written it stays in this one fixed module: the commands it
runs are fixed in code, never a caller's, and no other runtime module gains
a path to the network configuration.
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

__all__ = ["REFUSAL", "main"]

#: What a start of the helper prints, and the whole of what it does.
REFUSAL = (
    "az-decoy-netd: the decoy network helper has no body in this build "
    "(#196 P1); no namespace, bridge, link or rule was configured"
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Refuse and exit 1. Takes no argument; any argument is also refused."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        print("az-decoy-netd: takes no argument", file=sys.stderr)
        return 2
    print(REFUSAL, file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover - the wrapper calls main()
    raise SystemExit(main())
