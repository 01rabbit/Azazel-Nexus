"""`az-decoyd`: the Deception Lite decoy's fixed executable (#196 P1).

Design D1 (`docs/deception-redirect-prerequisites.md` §5): the decoy runs
under its own account with no capability, inside the decoy network
namespace, and accepts connections on the catalogued address and port with
the in-code responders of `decoy_loopback.py`. It never initiates.

**Phase P1 ships the unit profile and the listener boundary, not the
daemon.** This executable listens on nothing: it takes no argument, opens no
socket and exits non-zero. The only module allowed an internet address
family for listening is `decoy_listener.py`, and only to bind and listen
(`tests/unit/test_runtime_boundary.py`). The activation pass never grants the
unit in this build (`UnitTier.DECEPTION_EXPOSURE` is withheld as
`isolation_evidence_absent`).
"""

from __future__ import annotations

import sys
from typing import Optional, Sequence

__all__ = ["REFUSAL", "main"]

#: What a start of the decoy prints, and the whole of what it does.
REFUSAL = (
    "az-decoyd: the Deception Lite decoy has no daemon in this build "
    "(#196 P1); nothing is listening"
)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Refuse and exit 1. Takes no argument; any argument is also refused."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        print("az-decoyd: takes no argument", file=sys.stderr)
        return 2
    print(REFUSAL, file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover - the wrapper calls main()
    raise SystemExit(main())
