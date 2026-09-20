"""The accept loop every daemon shares (#43).

One connection, one request, one reply. No threads and no fork: these daemons
answer bounded questions about local state, and a concurrency model is
something to get wrong before it is something that helps.

**Nothing here blocks indefinitely.** `accept` runs under a timeout so the
loop can notice it has been asked to stop, and each connection carries the
transport's own read deadline. A daemon that could not be stopped except by a
signal is a daemon whose shutdown path is never exercised.

`stop` is a predicate rather than a flag so that a test can end the loop on a
condition it controls -- a count of requests served, a file appearing -- and
finish in bounded time without a timer.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any, Callable, Optional

from .principal import PrincipalPolicy
from .protocol import VerbRegistry
from .transport import SocketServer, bind_socket

__all__ = ["ACCEPT_TIMEOUT_SECONDS", "serve_forever"]

#: How long `accept` waits before the loop re-checks whether to stop.
ACCEPT_TIMEOUT_SECONDS = 0.25


def serve_forever(
    *,
    path: Path,
    registry: VerbRegistry,
    policy: PrincipalPolicy,
    audit: Callable[[dict], Any],
    handler: Callable[[Any], Any],
    stop: Callable[[], bool] = lambda: False,
    ready: Optional[Callable[[], None]] = None,
) -> int:
    """Serve on `path` until `stop()` answers true. Returns the exit code.

    The socket is removed on the way out. A stale socket file left behind is
    the next start's problem, and it arrives as a bind failure that looks
    like the address being in use when nothing holds it.
    """

    listener = bind_socket(path)
    listener.settimeout(ACCEPT_TIMEOUT_SECONDS)
    engine = SocketServer(registry=registry, policy=policy, audit=audit)
    if ready is not None:
        ready()
    try:
        while not stop():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                # The listener was closed under us, which is how a signal
                # handler would stop this loop.
                break
            with connection:
                try:
                    engine.serve_connection(connection, handler)
                except OSError:
                    # A peer that vanished mid-exchange is not this daemon's
                    # failure, and the refusal (if any) is already recorded.
                    continue
    finally:
        listener.close()
        try:
            path.unlink()
        except OSError:
            pass
    return 0
