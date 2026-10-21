"""Bind and listen for one catalogued decoy; never connect (#196 P1).

The first **ingress** exemption of the runtime boundary test
(`tests/unit/test_runtime_boundary.py`, `LISTENER_EXEMPT`). It is allowed an
internet address family by file name, and in exchange it may only bind and
listen: `connect`, `connect_ex`, `create_connection`, `sendto`, `sendmsg` and
`AF_PACKET` are refused in this file by the same scan. A decoy accepts and
never initiates (`docs/deception-redirect-prerequisites.md` §5, D1).

What it binds is not a parameter of its own. It takes a catalogued
`DecoyEntry` (port 1024-65535, neither loopback nor unspecified, refused by
the library) and the operator's `Commissioning`, and binds only an address
inside the commissioned bridge prefix. There is no default prefix.

Nothing in this build calls it: `az-decoyd` has no daemon yet, and the unit
it would run in is never granted. The tests drive it with a fake socket and
open no real one.
"""

from __future__ import annotations

import ipaddress
import socket

from azazel_nexus.decoy import Commissioning, DecoyEntry, DecoyRefused

__all__ = ["BACKLOG", "open_listener"]

#: A decoy answers a handful of probes, not a service's load.
BACKLOG = 8

#: Private test seam: the socket constructor. Production is `socket.socket`.
_SOCKET = socket.socket


def open_listener(entry: DecoyEntry, commissioning: Commissioning):
    """A stream socket bound to `entry`'s address and port, listening.

    Refuses (`DecoyRefused`) an entry or commissioning of the wrong type and
    an address outside the commissioned bridge prefix. The socket is closed
    if bind or listen fails.
    """

    if type(entry) is not DecoyEntry or type(commissioning) is not Commissioning:
        raise DecoyRefused("a listener needs a catalogued entry and its commissioning")
    if not commissioning.contains(entry.listen_address):
        raise DecoyRefused(
            f"{entry.listen_address} is outside the commissioned bridge prefix "
            f"{commissioning.bridge_prefix}"
        )
    version = ipaddress.ip_address(entry.listen_address).version
    family = socket.AF_INET6 if version == 6 else socket.AF_INET
    listener = _SOCKET(family, socket.SOCK_STREAM)
    try:
        listener.bind((entry.listen_address, entry.port))
        listener.listen(BACKLOG)
    except BaseException:
        listener.close()
        raise
    return listener
