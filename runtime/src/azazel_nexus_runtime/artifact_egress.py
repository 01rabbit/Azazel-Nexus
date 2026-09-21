"""The one module in this distribution that may open a connection (#105).

Everything else in `azazel_nexus_runtime` speaks `AF_UNIX` or reads the
kernel. This speaks TCP and TLS, to exactly one kind of peer, for exactly one
kind of payload: a **model artifact** whose digest was declared before the
connection was made.

`tests/unit/test_runtime_boundary.py` used to assert that *nothing* in this
package could reach an internet address family. That assertion is now scoped
to "nothing **except this module**", and the test records the exemption by
name so that the loosening is visible in the suite rather than implied by its
absence. A boundary that moved and left no trace is a boundary nobody can
audit.

## What this is not

**It is not the M.I.O. request transport.** That carries situation frames
this node observed -- data with a privacy class, needing a sanitiser, where
`P2-mission` and `P3-restricted` never leave at all. This carries public
weights whose content owes nothing to anything this node saw, whose digest is
known in advance, and which are verified after arrival by the same path an
offline import takes.

Reusing one for the other would turn *the route that fetches weights* into
*the route that sends observations*. Different service, different identity,
different policy, and `tests/unit/test_artifact_egress.py` asserts that no
privacy-class vocabulary appears here at all -- if this module cannot name a
privacy class, it cannot carry one.

## What it refuses

| refusal | why |
| --- | --- |
| a peer whose certificate does not verify | issuer, dates and name, against the **commissioned** anchor -- never the host's own store |
| a peer whose public key does not match the pin | and this on top: CA trust alone is one compromised issuer away from any host |
| an empty pin | not "any key". A fetch with nothing to compare against does not happen |
| a redirect | a fetcher that follows one is a fetcher whose allowlist is bypassed in a single hop |
| a resolved address outside the allowlist | DNS is an attack surface, and "the name was right" is not "the address was" |
| a response larger than declared | a file that grew is not the file that was planned for |
| a response that does not begin where resume asked | a server that ignores `Range` and restarts would silently corrupt a resumed file |
| a deadline passed | a fetch with no deadline is one nobody learns has stopped |
| a status other than the one expected | 200 for a whole fetch, 206 for a resumed one, and nothing else |

## What it never emits

No credential, no private key material, no token, no request body, and no
assembled URL reach a return value, an exception message or an event. The
pin and the identity name are inputs; neither is echoed. There is no
command line here at all -- this is a function, not a process -- which is
deliberate: an argument vector is readable by every user on the host.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Sequence

from azazel_nexus.spki import CertificateRefused
from azazel_nexus.spki import spki_pin as _spki_pin

__all__ = [
    "EgressRefused",
    "EgressResult",
    "MAX_HEADER_BYTES",
    "MAX_STATUS_LINE_BYTES",
    "Outcome",
    "fetch_artifact",
    "spki_pin",
    "tls_context",
]

#: A response header block larger than this is refused before it is parsed.
#: A ceiling enforced after reading everything is a ceiling on nothing.
MAX_HEADER_BYTES = 16 * 1024
MAX_STATUS_LINE_BYTES = 1024

#: Read granularity. Also the unit the bandwidth ceiling is applied over.
_READ_CHUNK = 64 * 1024


class Outcome(str, Enum):
    """How a fetch ended. None of these is `VERIFIED` or `PROMOTED`."""

    COMPLETE = "complete"
    REFUSED = "refused"
    TIMED_OUT = "timed_out"
    INTERRUPTED = "interrupted"


class EgressRefused(Exception):
    """Refused. Nothing was written, or what was written is the caller's to
    discard -- this never promotes and never verifies."""


@dataclass(frozen=True)
class EgressResult:
    """Bytes moved and how it ended. Never a verdict about the bytes."""

    outcome: Outcome
    received: int
    status: int
    reason: str

    @property
    def complete(self) -> bool:
        return self.outcome is Outcome.COMPLETE

    def as_event(self) -> dict:
        """No host, no path, no pin, no identity, no URL."""

        return {
            "event_type": "mio.model.artifact.transferred",
            "outcome": self.outcome.value,
            "received": self.received,
            "status": self.status,
            "reason": self.reason,
        }


def spki_pin(certificate_der: bytes) -> str:
    """`sha256:` over the certificate's SubjectPublicKeyInfo.

    The walk lives in `azazel_nexus.spki`, which imports neither `ssl` nor
    `socket`. Two egress boundaries pin a peer's key -- this one and the
    remote inference transport (#98) -- and two copies of a certificate-key
    extraction is one copy that gets a fix and one that does not. Sharing a
    parser is not sharing an egress exception.

    Re-raised as `EgressRefused` so that a caller of this module handles one
    failure type. The distinction "the certificate was unreadable" versus
    "the pin did not match" is kept by the message, not by the class: both
    end the connection, and a caller that treated them differently would be
    a caller deciding to continue on one of them.
    """

    try:
        return _spki_pin(certificate_der)
    except CertificateRefused as exc:
        raise EgressRefused(str(exc)) from exc


def tls_context(
    *,
    ca_certificate: str,
    client_certificate: Optional[str] = None,
    client_key: Optional[str] = None,
) -> ssl.SSLContext:
    """A client context that checks the issuer, the dates, the name -- and
    then `fetch_artifact` checks the pin on top.

    **The pin does not replace verification; it is layered on it.** An earlier
    version turned CA verification and hostname checking off on the grounds
    that a pin is stronger, which is true and beside the point: the pin
    answers "is this the key I was told to expect", and it answers nothing
    about whether the certificate has expired, whether it was issued for the
    name being contacted, or whether the issuer is one this node was
    commissioned to accept. Four questions, four checks, and dropping three
    of them because the fourth is good is how a chain ends up one check long.

    `ca_certificate` is required and has no default. A context with no trust
    anchor would fall back to the system store, and the system store is
    whatever the host happens to trust -- which is not what this node was
    commissioned to trust.
    """

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    # Only the commissioned anchor. `load_default_certs` is never called, so
    # the host's own store -- and anything an administrator added to it -- has
    # no bearing on what this service will talk to.
    context.load_verify_locations(cafile=ca_certificate)
    if client_certificate:
        # mTLS: the node shows who it is. The key never appears in a return
        # value, an exception or an event -- only here, where ssl reads it.
        context.load_cert_chain(certfile=client_certificate, keyfile=client_key)
    return context


def fetch_artifact(
    *,
    host: str,
    port: int,
    path: str,
    expected_pin: str,
    expected_size: int,
    resume_from: int = 0,
    allowed_addresses: Sequence[str],
    deadline_seconds: int,
    bandwidth_bytes_per_second: int,
    sink: Callable[[bytes], None],
    context: ssl.SSLContext,
    clock: Optional[Callable[[], float]] = None,
    sleeper: Optional[Callable[[float], None]] = None,
) -> EgressResult:
    """One attempt. Every bound is an argument; none has a permissive default.

    `allowed_addresses` is what the resolved peer address must be one of. It
    is passed in rather than resolved-and-trusted here because "the name was
    right" is not "the address was", and a fetcher that accepted whatever DNS
    returned would treat the resolver as an authority nobody commissioned.
    """

    if resume_from < 0 or resume_from > expected_size:
        raise EgressRefused("a resume offset outside the artifact")
    if not allowed_addresses:
        raise EgressRefused(
            "no address is allowed, so none is contacted. An empty allowlist "
            "is a refusal, never 'anything'"
        )
    if deadline_seconds < 1 or bandwidth_bytes_per_second < 1:
        raise EgressRefused("a deadline and a bandwidth ceiling are positive")
    if not expected_pin:
        raise EgressRefused(
            "an empty pin is not 'any key'. A fetch with nothing to compare "
            "the peer against does not happen"
        )

    now = clock or __import__("time").monotonic
    rest = sleeper or __import__("time").sleep
    started = now()

    def remaining() -> float:
        return deadline_seconds - (now() - started)

    address = _resolve_one(host, port, allowed_addresses)
    raw = socket.create_connection(address, timeout=max(remaining(), 0.001))
    try:
        stream = context.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise
    try:
        # The first act after the handshake, before a single request byte is
        # sent: an unpinned connection never carries anything, in either
        # direction.
        observed = spki_pin(stream.getpeercert(binary_form=True) or b"")
        if observed != expected_pin:
            raise EgressRefused(
                "the peer's public key does not match the commissioned pin. "
                "Nothing was requested"
            )
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "Connection: close\r\n"
            "Accept: application/octet-stream\r\n"
        )
        if resume_from:
            request += f"Range: bytes={resume_from}-\r\n"
        stream.sendall((request + "\r\n").encode("ascii"))

        status, headers, spill = _read_head(stream, remaining)
        expected_status = 206 if resume_from else 200
        if status in (301, 302, 303, 307, 308):
            raise EgressRefused(
                f"the peer answered {status}. A redirect is not followed: a "
                "fetcher that follows one is a fetcher whose allowlist is "
                "bypassed in a single hop"
            )
        if status != expected_status:
            raise EgressRefused(
                f"the peer answered {status}; {expected_status} was the only "
                "acceptable answer for this request"
            )
        if resume_from:
            _check_resume_start(headers, resume_from)

        received = resume_from
        budget = expected_size - resume_from
        for chunk in _body(stream, spill, budget, remaining):
            sink(chunk)
            received += len(chunk)
            # Throttle, but never past the deadline: sleeping through a budget
            # that is already spent buys nothing and is indistinguishable from
            # a hung transfer.
            rest(min(len(chunk) / bandwidth_bytes_per_second, max(remaining(), 0.0)))
            # Checked **after** the write and the wait, because both spend the
            # budget. Checking only before the next read let a single-chunk
            # transfer sleep far past its deadline and still report success --
            # the deadline bounded nothing in exactly the case where the
            # throttle mattered most.
            if remaining() <= 0 and received < expected_size:
                return EgressResult(
                    Outcome.TIMED_OUT,
                    received,
                    status,
                    f"the {deadline_seconds}s deadline passed with "
                    f"{expected_size - received} bytes outstanding",
                )
        if received != expected_size:
            return EgressResult(
                Outcome.INTERRUPTED,
                received,
                status,
                f"{received} of {expected_size} bytes arrived; resumable, and "
                "the digest is still checked afterwards",
            )
        return EgressResult(
            Outcome.COMPLETE,
            received,
            status,
            "every declared byte arrived. Whether they are the right bytes is "
            "decided by the same verification an offline import goes through",
        )
    finally:
        try:
            stream.close()
        except OSError:
            pass


# -- internals -------------------------------------------------------------


def _resolve_one(host: str, port: int, allowed: Sequence[str]) -> tuple:
    """Resolve, then refuse anything the allowlist does not carry."""

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EgressRefused(f"the name did not resolve: {exc}") from None
    for *_ignored, sockaddr in infos:
        if sockaddr[0] in allowed:
            return (sockaddr[0], port)
    raise EgressRefused(
        "the name resolved only to addresses the allowlist does not carry. "
        "DNS is an attack surface, and a right name is not a right address"
    )


def _read_head(stream, remaining) -> tuple:
    """Status line and headers, bounded, before any body is considered."""

    buffer = b""
    while b"\r\n\r\n" not in buffer:
        if remaining() <= 0:
            raise EgressRefused("the deadline passed before the headers arrived")
        if len(buffer) > MAX_HEADER_BYTES:
            raise EgressRefused(
                f"the header block exceeded {MAX_HEADER_BYTES} bytes and was "
                "refused without being parsed"
            )
        stream.settimeout(max(remaining(), 0.001))
        piece = stream.recv(4096)
        if not piece:
            raise EgressRefused("the peer closed before sending headers")
        buffer += piece
    head, spill = buffer.split(b"\r\n\r\n", 1)
    line, _, rest = head.partition(b"\r\n")
    if len(line) > MAX_STATUS_LINE_BYTES:
        raise EgressRefused("the status line is longer than any status line is")
    parts = line.split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/1."):
        raise EgressRefused("the peer did not answer HTTP/1.x")
    try:
        status = int(parts[1])
    except ValueError:
        raise EgressRefused("the peer's status code is not a number") from None
    headers = {}
    for raw_line in rest.split(b"\r\n"):
        name, _, value = raw_line.partition(b":")
        if name:
            headers[name.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")
    return status, headers, spill


def _check_resume_start(headers: dict, resume_from: int) -> None:
    """A server that ignored `Range` and restarted would corrupt the file.

    The bytes would append to what is already staged, the length would come
    out right often enough to look fine, and only the digest would notice --
    after the whole transfer. Refuse at the header instead.
    """

    content_range = headers.get("content-range", "")
    marker = f"bytes {resume_from}-"
    if not content_range.startswith(marker):
        raise EgressRefused(
            f"the peer answered 206 with Content-Range {content_range!r}, "
            f"which does not start at the requested byte {resume_from}"
        )


def _body(stream, spill: bytes, budget: int, remaining) -> Iterator[bytes]:
    """Yield at most `budget` bytes, refusing the one that exceeds it."""

    if spill:
        if len(spill) > budget:
            raise EgressRefused(
                "more than the declared size arrived. A file that grew is not "
                "the file that was planned for"
            )
        budget -= len(spill)
        yield spill
    while budget > 0:
        if remaining() <= 0:
            return
        stream.settimeout(max(remaining(), 0.001))
        try:
            chunk = stream.recv(min(_READ_CHUNK, budget + 1))
        except (socket.timeout, TimeoutError):
            return
        if not chunk:
            return
        if len(chunk) > budget:
            raise EgressRefused(
                "more than the declared size arrived. A file that grew is not "
                "the file that was planned for"
            )
        budget -= len(chunk)
        yield chunk






