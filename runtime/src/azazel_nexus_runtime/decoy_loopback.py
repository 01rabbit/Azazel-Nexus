"""Deception Lite's functional layer: decoys that actually listen (#69, E3-F).

[#54](https://github.com/01rabbit/Azazel-Nexus/issues/54) delivered the
**control plane** -- lifecycle, isolation requirement, disable, quarantine --
and `azazel_nexus.decoy` still starts nothing and binds nothing, by design and
by static scan. This module is the other half, and it lives in the runtime
distribution because binding anything is a privilege the library does not have.

## This is not external exposure, and it cannot become it

Every decoy here listens on an `AF_UNIX` socket inside a private directory.
**Nothing here can bind an address or a port at all.**
`tests/unit/test_runtime_boundary.py` scans this whole distribution for
`AF_INET`, `AF_INET6`, `AF_PACKET` and `create_connection` and refuses to find
any of them, so "it only binds loopback" is not a promise this module makes --
it is a shape the distribution has.

A Unix socket under a `0700` directory is stricter than `127.0.0.1`: there is
no IP stack in the path, no port to scan, nothing an interface can carry, and
reaching it needs filesystem permission on this host. That is what
[#69](https://github.com/01rabbit/Azazel-Nexus/issues/69) means by "an
equivalent local-only namespace".

**An operator's exposure request does not reach further.** Commissioning, a
verified generation and a passing isolation check are what the control plane
needs before a decoy may be `EXPOSED`; none of them is an input here, and all
three together still produce a Unix socket. External exposure is a different
stage with a different type.

## A separate type, so that one permission is not the other

`azazel_nexus.decoy.DecoyEntry` **refuses** loopback -- correctly, because a
decoy an attacker cannot reach is not an externally exposed decoy. That is the
discipline for the exposed kind, and it is not inverted here.
`LoopbackDecoy` is a different type with different fields: it has no address
and no port to refuse, and an entry of one kind can never be read as an entry
of the other.

## Nothing arbitrary, and nothing that is data

    No API exposes shell command execution, arbitrary policy upload,
    arbitrary container start, packet capture retrieval, or a general
    network-control primitive.
    -- docs/IMPLEMENTATION_SPEC.md §7

A catalogue entry names a **responder** from `RESPONDERS`, which is defined
here in code. It is not a command, not an image, not a path and not a
template: it is a key into a fixed table of constant byte strings. There is no
input by which a caller supplies behaviour -- only by which it selects among
behaviours that already exist.

## What is observed, and what is never kept

A decoy exists to be reached by someone hostile. What they send is not this
node's to keep. An `Observation` records **that** a decoy was reached, which
one, when, under which generation, and how many bytes arrived. It does not
record the bytes, and a static scan refuses a field that could hold them.

## A crash stops one decoy, and stops nothing else

A responder that raises quarantines that decoy: its socket is closed and
unlinked, the reason is recorded, and every other decoy keeps listening. The
exception does not leave this module. The deterministic path in Azazel-Edge
and everything CORE provides are untouched -- they do not know this module
exists, which is the strongest form of "it does not stop them".
"""

from __future__ import annotations

import errno
import re
import socket
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from azazel_nexus.decoy import MAX_DECOYS

__all__ = [
    "LOOPBACK_ONLY",
    "LoopbackCatalogue",
    "LoopbackDecoy",
    "LoopbackRefused",
    "LoopbackRuntime",
    "MAX_READ_BYTES",
    "Observation",
    "RESPONDERS",
    "ResponderState",
]

#: The word this runtime reports. It is not `available`: nothing outside this
#: host can reach a decoy here, so a supplier row that said the capability was
#: being supplied would be describing a deception nobody can be deceived by.
LOOPBACK_ONLY = "loopback-only"

#: A name is a filename component, so it is constrained like one. No dot, no
#: slash, no leading dash: a catalogue entry must not be able to name a path.
_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")

#: The ceiling on what one connection may send before the decoy stops reading.
#: A decoy is bait, not an ingestion path; a peer that streams forever is the
#: cheapest denial of service there is.
MAX_READ_BYTES = 4096

#: How long one connection may hold a decoy. Real seconds -- this is the
#: layer that touches the world.
READ_TIMEOUT_SECONDS = 5.0

#: The fixed table. **Defined in code, selected by name, never supplied.**
#:
#: Each value is a constant byte string a real service would print on
#: connect. Nothing formats, templates or interpolates: a responder that took
#: an argument would be a command with extra steps.
RESPONDERS: Mapping[str, bytes] = {
    "ssh-banner": b"SSH-2.0-OpenSSH_8.4p1 Debian-5\r\n",
    "smtp-banner": b"220 mail.invalid ESMTP ready\r\n",
    "http-banner": b"HTTP/1.1 401 Unauthorized\r\nServer: nginx\r\nConnection: close\r\n\r\n",
    "telnet-banner": b"\r\nlogin: ",
}


class LoopbackRefused(Exception):
    """The entry, the catalogue or the root is not admissible."""


class ResponderState(str, Enum):
    """Where one loopback decoy is."""

    #: Bound to its socket and accepting.
    LISTENING = "listening"
    #: It was listening, something went wrong, and it was stopped and unlinked.
    QUARANTINED = "quarantined"
    #: Never started, or stopped deliberately.
    STOPPED = "stopped"


@dataclass(frozen=True)
class LoopbackDecoy:
    """One decoy in the fixed allowlist.

    Two fields, and deliberately no more. There is no address, no port, no
    image and no command here -- not refused, **absent**. A field that does
    not exist cannot be validated wrongly.
    """

    name: str
    responder: str

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise LoopbackRefused(
                f"{self.name!r} is not a decoy name: lower-case letters, digits "
                "and dashes, starting with a letter or digit. A name becomes a "
                "filename, and a name that could contain a path separator or a "
                "dot could name a socket outside the runtime's directory"
            )
        if self.responder not in RESPONDERS:
            raise LoopbackRefused(
                f"{self.responder!r} is not one of {sorted(RESPONDERS)}. A "
                "responder is selected from a table defined in code; it is "
                "never supplied, because behaviour supplied as data is a "
                "command with extra steps"
            )

    @property
    def banner(self) -> bytes:
        return RESPONDERS[self.responder]


@dataclass(frozen=True)
class LoopbackCatalogue:
    """The fixed allowlist. Nothing outside it can be started."""

    entries: tuple[LoopbackDecoy, ...]

    @classmethod
    def of(cls, entries: Sequence[LoopbackDecoy]) -> "LoopbackCatalogue":
        if not entries:
            raise LoopbackRefused(
                "an empty catalogue starts nothing; that is the correct state "
                "for a node with no decoys and is expressed by having no "
                "catalogue, not by having an empty one"
            )
        if len(entries) > MAX_DECOYS:
            raise LoopbackRefused(
                f"{len(entries)} decoys were named and the ceiling is "
                f"{MAX_DECOYS} in every envelope; a larger set is refused "
                "rather than truncated"
            )
        names = [entry.name for entry in entries]
        if len(set(names)) != len(names):
            raise LoopbackRefused(f"two decoys share a name: {sorted(names)}")
        return cls(tuple(entries))

    def entry(self, name: str) -> LoopbackDecoy:
        for candidate in self.entries:
            if candidate.name == name:
                return candidate
        raise LoopbackRefused(
            f"{name!r} is not in the catalogue; the runtime starts what the "
            "catalogue names and nothing else"
        )


@dataclass(frozen=True)
class Observation:
    """That a decoy was reached. Never what was sent to it.

    The field list is the whole record, and
    `tests/unit/test_decoy_loopback.py` asserts it: a field able to hold a
    payload is how a decoy's audit becomes a credential store.
    """

    decoy_name: str
    at: str
    generation_digest: str
    bytes_received: int
    responder: str
    #: Whether the peer sent more than the decoy was willing to read. Recorded
    #: because a truncated read is a different observation from a short one.
    truncated: bool

    def as_event(self) -> dict:
        return {
            "event_type": "deception.lite.loopback.observation",
            "decoy_name": self.decoy_name,
            "at": self.at,
            "generation_digest": self.generation_digest,
            "bytes_received": self.bytes_received,
            "responder": self.responder,
            "truncated": self.truncated,
        }


class LoopbackRuntime:
    """Binds, serves and quarantines. One directory, one socket per decoy."""

    def __init__(
        self,
        root: Path,
        *,
        catalogue: LoopbackCatalogue,
        generation_digest: str,
        clock: Callable[[], str],
        recorder: Optional[Callable[[Mapping[str, object]], None]] = None,
    ) -> None:
        if not generation_digest.strip():
            raise LoopbackRefused(
                "a decoy runs under a verified generation or it does not run; "
                "an observation nobody can attribute to a generation is an "
                "observation nobody can replay"
            )
        self.root = Path(root)
        self.catalogue = catalogue
        self.generation_digest = generation_digest
        self._clock = clock
        self._record = recorder or (lambda event: None)
        self._sockets: dict[str, socket.socket] = {}
        self._states: dict[str, ResponderState] = {
            entry.name: ResponderState.STOPPED for entry in catalogue.entries
        }
        self._reasons: dict[str, str] = {}
        self.observations: list[Observation] = []

    # -- lifecycle --------------------------------------------------------

    def path_for(self, name: str) -> Path:
        """The socket path, derived from the root and a validated name.

        `LoopbackDecoy` already refuses a name that could carry a separator or
        a dot, so no input reaches this method that could leave the root --
        which makes the containment check below **unreachable today**. A
        mutation that removes it survives the suite, and that is recorded
        rather than papered over with a test that constructs a
        `LoopbackDecoy` the constructor would have refused: such a test would
        exercise a state the product cannot be in.

        It is kept because it guards the one thing here that binds. If the
        name rule is ever loosened, this is the barrier that is already in
        place rather than the one somebody has to remember to add.
        """

        self.catalogue.entry(name)
        candidate = (self.root / f"{name}.sock").resolve()
        root = self.root.resolve()
        if root not in candidate.parents:
            raise LoopbackRefused(
                f"{candidate} is not inside {root}; a decoy binds inside the "
                "runtime's directory and nowhere else"
            )
        return candidate

    def start(self) -> tuple[str, ...]:
        """Bind every decoy in the catalogue. Returns the names now listening."""

        self.root.mkdir(parents=True, exist_ok=True)
        # 0700 on the directory is what makes this a private namespace rather
        # than a local one. Set after mkdir so an inherited umask cannot widen
        # it.
        self.root.chmod(stat.S_IRWXU)
        for entry in self.catalogue.entries:
            if self._states[entry.name] is ResponderState.QUARANTINED:
                continue
            self._bind(entry)
        return tuple(
            name
            for name, state in sorted(self._states.items())
            if state is ResponderState.LISTENING
        )

    def _bind(self, entry: LoopbackDecoy) -> None:
        path = self.path_for(entry.name)
        self._unlink(path)
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(path))
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            server.listen(1)
        except OSError as exc:
            server.close()
            self._quarantine(entry.name, f"the socket could not be bound: {exc}")
            return
        self._sockets[entry.name] = server
        self._states[entry.name] = ResponderState.LISTENING
        self._record(
            {
                "event_type": "deception.lite.loopback.listening",
                "decoy_name": entry.name,
                "responder": entry.responder,
                "generation_digest": self.generation_digest,
                "namespace": "unix-socket",
                "at": self._clock(),
            }
        )

    def stop(self) -> None:
        for name in sorted(self._sockets):
            self._close(name)
            if self._states[name] is ResponderState.LISTENING:
                self._states[name] = ResponderState.STOPPED

    # -- serving ----------------------------------------------------------

    def serve_once(self, name: str) -> Optional[Observation]:
        """Accept one connection, answer it, and record that it happened.

        Returns `None` when the decoy is not listening or the connection
        produced nothing to record. **It never raises for a responder's
        failure**: a decoy that crashed the node it is protecting would be a
        better weapon than a lure.
        """

        server = self._sockets.get(name)
        if server is None or self._states[name] is not ResponderState.LISTENING:
            return None
        entry = self.catalogue.entry(name)
        try:
            connection, _ = server.accept()
        except OSError as exc:
            self._quarantine(name, f"accept failed: {exc}")
            return None
        try:
            with connection:
                connection.settimeout(READ_TIMEOUT_SECONDS)
                connection.sendall(entry.banner)
                received, truncated = self._read_bounded(connection)
        except Exception as exc:  # noqa: BLE001 - see the docstring
            self._quarantine(name, f"the responder failed: {exc!r}")
            return None
        observation = Observation(
            decoy_name=name,
            at=self._clock(),
            generation_digest=self.generation_digest,
            bytes_received=received,
            responder=entry.responder,
            truncated=truncated,
        )
        self.observations.append(observation)
        self._record(observation.as_event())
        return observation

    def _read_bounded(self, connection: socket.socket) -> tuple[int, bool]:
        """Count what arrived. The bytes are counted and dropped, not kept."""

        total = 0
        while total < MAX_READ_BYTES:
            try:
                chunk = connection.recv(min(1024, MAX_READ_BYTES - total))
            except (TimeoutError, socket.timeout):
                return total, False
            except OSError as exc:
                if exc.errno in (errno.ECONNRESET, errno.EPIPE):
                    return total, False
                raise
            if not chunk:
                return total, False
            total += len(chunk)
        return total, True

    # -- failure ----------------------------------------------------------

    def quarantine(self, name: str, reason: str) -> None:
        """Stop and isolate one decoy. Every other decoy keeps listening."""

        self.catalogue.entry(name)
        self._quarantine(name, reason)

    def _quarantine(self, name: str, reason: str) -> None:
        self._close(name)
        self._states[name] = ResponderState.QUARANTINED
        self._reasons[name] = reason
        self._record(
            {
                "event_type": "deception.lite.loopback.quarantined",
                "decoy_name": name,
                "reason": reason,
                "generation_digest": self.generation_digest,
                "at": self._clock(),
                "deterministic_path_affected": False,
            }
        )

    def _close(self, name: str) -> None:
        server = self._sockets.pop(name, None)
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        try:
            self._unlink(self.path_for(name))
        except LoopbackRefused:  # pragma: no cover - name validated on entry
            pass

    @staticmethod
    def _unlink(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass

    # -- reporting --------------------------------------------------------

    def state(self, name: str) -> ResponderState:
        self.catalogue.entry(name)
        return self._states[name]

    def reason(self, name: str) -> str:
        self.catalogue.entry(name)
        state = self._states[name]
        if state is ResponderState.QUARANTINED:
            return (
                f"stopped and isolated: {self._reasons.get(name, 'no reason recorded')}. "
                "Telemetry is kept; the deterministic path is untouched"
            )
        if state is ResponderState.LISTENING:
            return (
                f"listening on a private Unix socket under {self.root} as "
                f"{self.catalogue.entry(name).responder}. This is reachable from "
                "this host alone: it is an observation surface on a local-only "
                "namespace, not an exposed decoy and not an enforcement one"
            )
        return "not started; a decoy in the catalogue is not a decoy that is listening"

    def listening(self) -> tuple[str, ...]:
        return tuple(
            name
            for name, state in sorted(self._states.items())
            if state is ResponderState.LISTENING
        )

    @property
    def redirect_eligible(self) -> bool:
        """Always False, derived, and for the same reason as in the library.

        Redirect is the arbiter's to issue. A decoy on a private Unix socket
        has nothing to redirect to it in any case, but the answer would be no
        regardless.
        """

        return False

    def as_event(self) -> dict:
        return {
            "event_type": "deception.lite.loopback.runtime",
            "root": str(self.root),
            "generation_digest": self.generation_digest,
            "namespace": "unix-socket",
            "externally_reachable": False,
            "redirect_eligible": self.redirect_eligible,
            "decoys": [
                {
                    "decoy_name": name,
                    "state": self._states[name].value,
                    "reason": self.reason(name),
                }
                for name in sorted(self._states)
            ],
        }
