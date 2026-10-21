"""`az-decoy-nsd`: the Deception Lite namespace unit's fixed executable (#196).

Design D1, option (a) (`docs/deception-redirect-prerequisites.md` §5, §10,
§13). A one-shot unit, root with exactly `CAP_SYS_ADMIN` and `CAP_NET_ADMIN`
as a bounding set, that runs `decoy_network.NAMESPACE_STEPS` and nothing
else: it creates `/run/netns/azazel-decoy`, creates the veth pair with the
decoy's end inside it, and configures the inside (`lo` up, the decoy's fixed
address, link up, default route). The network helper (`az-decoy-netd`) then
builds the host side.

Started with no argument it builds; `ExecStop=` starts it with exactly
`stop`, and it removes the pair and the namespace. Anything else is refused
(exit 2). It reads no file, no environment and no socket; the commands and
their arguments are constants of `decoy_network`. A failed step undoes what
the earlier ones made and exits 1.

It does not change `net.core.fb_tunnels_only_for_init_net` or any other
sysctl, and does not delete fallback tunnel devices: a host that creates them
in every new namespace is refused by the decoy itself (`decoy_netns`), and
the operator sets that sysctl (§13).
"""

from __future__ import annotations

from typing import Optional, Sequence

from .decoy_network import NAMESPACE_ABSENT, NAMESPACE_STEPS, Runner, main_for

__all__ = ["main"]


def main(argv: Optional[Sequence[str]] = None, *, run: Optional[Runner] = None) -> int:
    """Build (no argument) or remove (`stop`) the decoy namespace side."""

    return main_for("az-decoy-nsd", NAMESPACE_STEPS, argv, run, NAMESPACE_ABSENT)


if __name__ == "__main__":  # pragma: no cover - the wrapper calls main()
    raise SystemExit(main())
