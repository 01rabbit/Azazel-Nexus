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

`open_listener` is still called by nothing: the catalogue and the
commissioned prefix do not reach the decoy in this build.

`open_namespace_listener` is what `az-decoyd` calls (#196 decoy body,
`docs/deception-redirect-prerequisites.md` §12). It binds the IPv4 wildcard
**of the decoy network namespace** on a fixed port, and only with a
`decoy_netns.DecoyNamespace` that is still current when it binds: inside that
namespace the wildcard is the namespace's own interfaces (loopback and the
decoy's end of the veth pair), never a host interface. Outside it the check
refuses before a socket exists. The one socket option it sets is
`SO_REUSEADDR`, so that a restart is not refused for the minute a closed
connection spends in `TIME_WAIT`.

The unit it runs in is granted only with the whole exposure tier, on a
verified v3 approval and the pass's exposure evidence (#196 G6).
"""

from __future__ import annotations

import ipaddress
import socket

from azazel_nexus.decoy import MIN_PORT, Commissioning, DecoyEntry, DecoyRefused

from .decoy_netns import DecoyNamespace

__all__ = ["BACKLOG", "NAMESPACE_BIND_ADDRESS", "open_listener", "open_namespace_listener"]

#: A decoy answers a handful of probes, not a service's load.
BACKLOG = 8

#: The IPv4 wildcard, bound only inside the verified decoy namespace.
NAMESPACE_BIND_ADDRESS = "0.0.0.0"

#: Private test seams: the socket constructor and the namespace bind
#: address. Production is `socket.socket` and `NAMESPACE_BIND_ADDRESS`.
_SOCKET = socket.socket
_BIND_ADDRESS = NAMESPACE_BIND_ADDRESS


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


def open_namespace_listener(namespace: DecoyNamespace, port: int):
    """A stream socket on the decoy namespace's IPv4 wildcard and `port`, listening.

    Refuses (`DecoyRefused`) anything but a `DecoyNamespace` that is still
    this process's namespace, and a port outside `MIN_PORT`-65535, before a
    socket exists. The socket is closed if an option, bind or listen fails.
    """

    if type(namespace) is not DecoyNamespace or not namespace.still_current():
        raise DecoyRefused("a namespace listener binds only inside the decoy namespace")
    if type(port) is not int or not MIN_PORT <= port <= 65535:
        raise DecoyRefused(f"port {port!r} is outside {MIN_PORT}-65535")
    listener = _SOCKET(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((_BIND_ADDRESS, port))
        listener.listen(BACKLOG)
    except BaseException:
        listener.close()
        raise
    return listener
