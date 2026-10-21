"""`az-decoyd`: the Deception Lite decoy (#196, design D1).

`docs/deception-redirect-prerequisites.md` §5 D1, §11 and §12. The decoy runs
under its own account with no capability, inside the decoy network namespace
systemd gives it (`NetworkNamespacePath=`), and answers with the in-code
responders of `decoy_loopback.py`. It accepts and never initiates toward the
network.

What one start does:

1. **Refuse outside the decoy namespace** (`decoy_netns`). It listens on the
   namespace's IPv4 wildcard, which in the host namespace would be every host
   interface, so the check comes before any socket and is repeated before
   every bind. Exit 1, nothing bound.
2. **Listen on fixed ports** (`SERVED`, fixed in code like the responders;
   the catalogue does not reach the decoy in this build): one listener per
   decoy, through `decoy_listener.open_namespace_listener`, the only module
   allowed to bind an internet family.
3. **Serve each connection** with its responder's constant banner, then count
   (never keep) at most `MAX_READ_BYTES` the peer sends, for at most
   `CONNECTION_SECONDS`. What arrived is read into one scratch buffer that is
   zeroed after each read and never stored, logged or forwarded.
4. **Report each served connection** as P2's closed `EnvironmentEvent`
   (`decoy_report.interaction_from_observation`), one line to the intake's
   decoy socket (`decoy_sender`, the decoy's only outgoing path). If the
   intake does not take it, the interaction is dropped and only counted.

Bounds: `MAX_CONCURRENT` connections at once, `ACCEPTS_PER_MINUTE` served
connections per rolling minute (the intake's own decoy rate), and the
per-connection deadline. A connection over a bound is accepted and closed at
once, unanswered and unreported, and counted. One thread and one selector:
the unit's `TasksMax=16` is never approached.

**No address leaves the kernel.** The peer address `accept` returns is
discarded at the call; the observation has no field for it (§7 Q8); nothing
here logs a peer, and the log lines carry only ports and counts.

Takes no argument and reads no environment variable. The activation pass
never grants the unit in this build (`DECEPTION_EXPOSURE` is withheld as
`isolation_evidence_absent`), so on a node nothing starts it yet.
"""

from __future__ import annotations

import selectors
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from azazel_nexus.decoy import DecoyRefused
from azazel_nexus.decoy_interaction import DecoyEventRefused

from . import decoy_listener, decoy_netns, decoy_sender
from .decoy_loopback import MAX_READ_BYTES, READ_TIMEOUT_SECONDS, RESPONDERS, Observation
from .decoy_report import interaction_from_observation

__all__ = [
    "ACCEPTS_PER_MINUTE",
    "CONNECTION_SECONDS",
    "MAX_CONCURRENT",
    "SERVED",
    "DecoyServer",
    "ServedDecoy",
    "main",
]

#: How many connections may be open at once, across every decoy.
MAX_CONCURRENT = 8
#: Served connections per rolling minute, across every decoy. Equal to the
#: intake's decoy rate (`edge_intaked.DECOY_PER_MINUTE`; a test keeps them
#: equal): a reach the intake would refuse is not served either.
ACCEPTS_PER_MINUTE = 30
#: How long one connection may hold the decoy, from accept to close.
CONNECTION_SECONDS = READ_TIMEOUT_SECONDS
#: One recv at most; the scratch buffer is this size.
_CHUNK = 1024
#: Not an observation: what the event would carry is never sent (§11).
_UNBOUND_GENERATION = "unbound"


@dataclass(frozen=True)
class ServedDecoy:
    """One decoy this daemon serves: a name the intake knows, a responder, a port."""

    name: str
    responder: str
    port: int


#: The decoys this build serves. Three, the ceiling in every envelope
#: (`azazel_nexus.decoy.MAX_DECOYS`); every name is in the intake's
#: `DECOY_NAMES`, every responder in `RESPONDERS`, every port 1024 or above
#: and distinct (a test checks each). The SMTP responder stays in the table,
#: and in the loopback runtime, without a port here.
SERVED: tuple[ServedDecoy, ...] = (
    ServedDecoy("ssh-decoy", "ssh-banner", 2222),
    ServedDecoy("telnet-decoy", "telnet-banner", 2323),
    ServedDecoy("http-decoy", "http-banner", 8080),
)


def _utc_second() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class _Connection:
    __slots__ = ("decoy", "sock", "deadline", "banner", "received", "truncated")

    def __init__(self, decoy: ServedDecoy, sock, deadline: float):
        self.decoy, self.sock, self.deadline = decoy, sock, deadline
        self.banner = RESPONDERS[decoy.responder]
        self.received, self.truncated = 0, False


class DecoyServer:
    """Serve already-bound listeners until `stop()` is true. Never raises for a peer."""

    def __init__(
        self,
        listeners: Sequence[tuple[ServedDecoy, object]],
        *,
        send: Callable[[object], bool] = decoy_sender.send_interaction,
        clock: Callable[[], str] = _utc_second,
        monotonic: Callable[[], float] = time.monotonic,
        max_concurrent: int = MAX_CONCURRENT,
        per_minute: int = ACCEPTS_PER_MINUTE,
        seconds: float = CONNECTION_SECONDS,
    ):
        self.listeners = list(listeners)
        self._send, self._clock, self._monotonic = send, clock, monotonic
        self.max_concurrent, self.per_minute, self.seconds = max_concurrent, per_minute, seconds
        self._selector = selectors.DefaultSelector()
        self._connections: dict[object, _Connection] = {}
        self._window: deque = deque()
        self._scratch = bytearray(_CHUNK)
        self.counts = {
            "served": 0, "sent": 0, "send_failed": 0, "dropped_busy": 0,
            "dropped_rate": 0, "accept_errors": 0, "connection_errors": 0,
        }

    # -- the loop -----------------------------------------------------------

    def serve(self, stop: Callable[[], bool], ready: Optional[Callable[[], None]] = None) -> None:
        for decoy, listener in self.listeners:
            listener.setblocking(False)
            self._selector.register(listener, selectors.EVENT_READ, decoy)
        if ready is not None:
            ready()
        try:
            while not stop():
                for key, events in self._selector.select(self._timeout()):
                    if key.fileobj in self._connections:
                        self._step(self._connections[key.fileobj], events)
                    else:
                        self._accept(key.fileobj, key.data)
                self._expire()
        finally:
            for connection in list(self._connections.values()):
                self._finish(connection, report=False)
            for _, listener in self.listeners:
                try:
                    self._selector.unregister(listener)
                except (KeyError, ValueError):
                    pass
                listener.close()
            self._selector.close()

    def _timeout(self) -> float:
        if not self._connections:
            return 0.5
        nearest = min(c.deadline for c in self._connections.values())
        return max(0.0, min(0.5, nearest - self._monotonic()))

    def _expire(self) -> None:
        now = self._monotonic()
        for connection in [c for c in self._connections.values() if c.deadline <= now]:
            self._finish(connection)

    # -- admission ----------------------------------------------------------

    def _room_this_minute(self) -> bool:
        now = self._monotonic()
        while self._window and now - self._window[0] >= 60:
            self._window.popleft()
        return len(self._window) < self.per_minute

    def _accept(self, listener, decoy: ServedDecoy) -> None:
        try:
            # The peer address is discarded here and never held (§7 Q8).
            sock, _ = listener.accept()
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self.counts["accept_errors"] += 1
            return
        if len(self._connections) >= self.max_concurrent:
            self.counts["dropped_busy"] += 1
            sock.close()
            return
        if not self._room_this_minute():
            self.counts["dropped_rate"] += 1
            sock.close()
            return
        self._window.append(self._monotonic())
        try:
            sock.setblocking(False)
            connection = _Connection(decoy, sock, self._monotonic() + self.seconds)
            self._selector.register(sock, selectors.EVENT_READ | selectors.EVENT_WRITE)
        except (OSError, ValueError):
            self.counts["connection_errors"] += 1
            sock.close()
            return
        self._connections[sock] = connection

    # -- one connection -----------------------------------------------------

    def _step(self, connection: _Connection, events: int) -> None:
        try:
            if events & selectors.EVENT_WRITE and connection.banner:
                sent = connection.sock.send(connection.banner)
                connection.banner = connection.banner[sent:]
                if not connection.banner:
                    self._selector.modify(connection.sock, selectors.EVENT_READ)
            if events & selectors.EVENT_READ:
                room = min(_CHUNK, MAX_READ_BYTES - connection.received)
                count = connection.sock.recv_into(self._scratch, room)
                # Counted, then overwritten: what was sent is not kept.
                self._scratch[:count] = bytes(count)
                if count == 0:
                    self._finish(connection)
                    return
                connection.received += count
                if connection.received >= MAX_READ_BYTES:
                    connection.truncated = True
                    self._finish(connection)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            # Reset, broken pipe: the peer left. It still reached the decoy.
            self._finish(connection)

    def _finish(self, connection: _Connection, *, report: bool = True) -> None:
        self._connections.pop(connection.sock, None)
        try:
            self._selector.unregister(connection.sock)
        except (KeyError, ValueError):
            pass
        connection.sock.close()
        if not report:
            return
        self.counts["served"] += 1
        observation = Observation(
            decoy_name=connection.decoy.name,
            at=self._clock(),
            generation_digest=_UNBOUND_GENERATION,
            bytes_received=connection.received,
            responder=connection.decoy.responder,
            truncated=connection.truncated,
        )
        try:
            delivered = self._send(interaction_from_observation(observation))
        except (DecoyEventRefused, OSError):
            delivered = False
        self.counts["sent" if delivered else "send_failed"] += 1


# -- the executable -----------------------------------------------------------


def _say(message: str) -> None:
    print(f"az-decoyd: {message}", file=sys.stderr, flush=True)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Listen in the decoy namespace and serve until SIGTERM. Takes no argument."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        _say("takes no argument")
        return 2
    try:
        namespace = decoy_netns.confirm_decoy_namespace()
    except decoy_netns.NotInDecoyNamespace as exc:
        _say(f"refusing to listen: {exc}")
        return 1
    listeners = []
    try:
        for decoy in SERVED:
            listeners.append(
                (decoy, decoy_listener.open_namespace_listener(namespace, decoy.port)))
    except (DecoyRefused, OSError) as exc:
        for _, listener in listeners:
            listener.close()
        reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
        _say(f"refusing to listen: {reason}")
        return 1
    stopping = []

    def stop(signum, _frame):
        stopping.append(signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server = DecoyServer(listeners)
    _say("listening in the decoy namespace on ports "
         + ", ".join(f"{d.port} ({d.name})" for d in SERVED))
    server.serve(lambda: bool(stopping))
    _say("stopped; " + ", ".join(f"{k} {v}" for k, v in server.counts.items()))
    return 0


if __name__ == "__main__":  # pragma: no cover - the wrapper calls main()
    raise SystemExit(main())
