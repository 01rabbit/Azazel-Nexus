"""The decoy's one way out: one line to the intake's decoy socket (#196 decoy body).

`az-decoyd` accepts and never initiates traffic toward the network. It has
one outgoing path, and it is this module: an `AF_UNIX` stream connection to
the fixed socket `DECOY_INTAKE_SOCKET`, where the intake receives P2's
closed `EnvironmentEvent` (`docs/deception-redirect-prerequisites.md` §11),
one line per connection. Nothing is read back.

The runtime boundary test holds this file to exactly that
(`tests/unit/test_runtime_boundary.py`, `DECOY_SENDER`): it is the only
module the decoy process loads that may name `connect`; it may name
`AF_UNIX` and no other family; its one `connect` takes `_PATH`, which is
assigned only `DECOY_INTAKE_SOCKET`, a literal equal to the path the layout
declares. No environment variable or argument changes it. (`AZAZEL_ROOT`,
which moves `runtime_paths` for the integration harness, does not reach this
path: the decoy runs only under systemd, which sets none.) The tests move
`_PATH` in-process, as `decoy_listener._SOCKET` is moved.

A line that does not parse as the closed interaction shape is not sent:
the channel carries P2's event and nothing else. A failure to connect or
send at once (the intake is not running, its backlog or buffer is full) is
returned as `False` for the daemon to count; the interaction is dropped, not
queued or retried.
"""

from __future__ import annotations

import socket

from azazel_nexus.decoy_interaction import (
    DecoyEventRefused,
    DecoyInteraction,
    parse_interaction,
)

__all__ = ["DECOY_INTAKE_SOCKET", "send_interaction"]

#: `runtime_paths.socket_path("decoy-intake")` under `/` (a test keeps them
#: equal). A literal, so that what the decoy can reach is read from source.
DECOY_INTAKE_SOCKET = "/var/lib/azazel/run/decoy-intake/decoy-intake.sock"

#: Private test seam. Production is exactly `DECOY_INTAKE_SOCKET`.
_PATH = DECOY_INTAKE_SOCKET


def send_interaction(interaction: DecoyInteraction) -> bool:
    """Send one closed interaction as one line; `True` if it was written.

    **Never waits** (review of #272): the socket is non-blocking, so an
    intake whose backlog is full refuses the connect at once (`EAGAIN`), and
    a line that does not fit the socket buffer at once is not sent. The
    decoy's accept loop calls this, and an intake that is slow or stuck must
    not hold it. A connect the intake has not accepted yet still succeeds
    (it waits in the backlog with the line), as it does for Edge's lines.
    """

    if type(interaction) is not DecoyInteraction:
        return False
    try:
        line = parse_interaction(interaction.encoded).line
    except DecoyEventRefused:
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.setblocking(False)
            connection.connect(_PATH)
            connection.sendall(line)
    except OSError:
        return False
    return True
