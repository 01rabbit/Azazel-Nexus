"""The second egress boundary, and it is not the first one (#98).

`artifact_egress` pulls **public bytes in** against a digest declared before
the connection was made. This pushes **what this node observed out**. They
are different acts with different blast radii, so they are different
modules, run by different services, under different accounts, resolving
through different commissioned registries, with different egress exceptions.

Nothing here is reused from the fetcher but a DER walk (`azazel_nexus.spki`),
which decides nothing.

| | `az-model-fetchd` / `azfetch` | `az-mio-remoted` / `azremote` |
| --- | --- | --- |
| direction | in | **out** |
| carries | published weights | what this node saw |
| resolves through | Source Registry | **Provider Registry** |
| client identity | the fetcher's | **its own, never the fetcher's** |
| socket | `fetch` | `remote` |

A node that reused the fetcher's identity here would be a node where the
credential that pulls a file also pushes a report.

## mTLS is mutual or it is not this

`tls_context` takes a client certificate and key and **refuses without
them**. The artifact fetcher's context accepts them optionally, because a
public mirror may not ask; a provider that does not ask who this node is is
not a provider this node was commissioned to talk to. One-way TLS is TLS. It
is not mTLS, and calling it that is how the second half stops being checked.

## There is no retry in here

One attempt, one result. `route_selection` decides whether a failure falls
back, and it decides **once**. A retry inside this module would spend the
router's single fallback silently and report the slower result as though the
first attempt had gone that way -- which is the shape of a failure nobody
sees, refused by name in `test_acquisition_prohibitions.py` for the fetch
path and refused here for this one.

## What it never says

No frame content, no response body, no credential, no private key, no token,
no assembled URL. `EgressReport.as_event` carries an outcome, counts and a
structured reason, and there is no field on it that could hold any of them.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Sequence

from azazel_nexus.spki import CertificateRefused
from azazel_nexus.spki import spki_pin as _spki_pin

__all__ = [
    "InferenceRefused",
    "MAX_RESPONSE_HEADER_BYTES",
    "MAX_STATUS_LINE_BYTES",
    "TransportOutcome",
    "EgressReport",
    "send_inference",
    "spki_pin",
    "tls_context",
]

#: A response header block larger than this is refused before it is parsed.
MAX_RESPONSE_HEADER_BYTES = 8 * 1024

#: A status line larger than this is refused before it is split.
MAX_STATUS_LINE_BYTES = 1024


class InferenceRefused(Exception):
    """A request that will not be sent, or a response that will not be read."""


class TransportOutcome(str, Enum):
    """How one attempt ended.

    There is deliberately **no `COMPLETED`** and no `ANSWERED`. Whether the
    request was answered is `route_selection`'s word, decided from the
    advisory that came back and whether it validated -- not this module's,
    which knows only that bytes arrived. A transport that could say
    "answered" would be a transport whose TLS failure, timeout or truncated
    body could be reported as a reply.
    """

    #: Bytes came back within every bound. Says nothing about their content.
    RECEIVED = "received"
    #: Refused before anything was sent.
    NOT_SENT = "not_sent"
    #: The handshake, the chain, the name or the pin did not hold.
    TLS_FAILED = "tls_failed"
    #: The deadline passed.
    TIMED_OUT = "timed_out"
    #: The peer closed, or the body exceeded its ceiling.
    INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class EgressReport:
    """One attempt's result. Counts, an outcome and a structured reason."""

    outcome: TransportOutcome
    #: Bytes of response body read. Never the body.
    received: int
    status: int
    reason: str

    def as_event(self) -> dict:
        return {
            "event_type": "mio.remote.transport.attempt",
            "outcome": self.outcome.value,
            "received": self.received,
            "status": self.status,
            "reason": self.reason,
        }


def spki_pin(certificate_der: bytes) -> str:
    """`sha256:` over the peer's SubjectPublicKeyInfo.

    The same walk the artifact fetcher uses, from the same pure module, so
    that a fix to it reaches both boundaries. Re-raised as
    `InferenceRefused` so a caller of this module handles one failure type.
    """

    try:
        return _spki_pin(certificate_der)
    except CertificateRefused as exc:
        raise InferenceRefused(str(exc)) from exc


def tls_context(
    *, ca_certificate: str, client_certificate: str, client_key: str
) -> ssl.SSLContext:
    """A **mutual** TLS context. All three arguments are required.

    The artifact fetcher's equivalent takes the client pair optionally: a
    public mirror may not ask who is pulling. Here it is not optional, and
    the difference is the point. A provider that does not ask who this node
    is has not established the thing `remote_trust.TrustSignal.MUTUAL_TLS`
    stands for, and a context that could be built without a client identity
    is a context that will be.

    `ca_certificate` has no default either. A context with no trust anchor
    falls back to the system store, and the system store is whatever the host
    happens to trust -- which is not what this node was commissioned to
    trust. The pin is layered on top of chain, dates and hostname; it does not
    replace them.
    """

    for label, value in (
        ("ca_certificate", ca_certificate),
        ("client_certificate", client_certificate),
        ("client_key", client_key),
    ):
        if not value:
            raise InferenceRefused(
                f"{label} is required. One-way TLS is TLS; it is not mutual "
                "TLS, and a transport that could be built without a client "
                "identity is one that will be"
            )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # No `load_default_certs`. See above.
    context.load_verify_locations(cafile=ca_certificate)
    # The key never appears in a return value, an exception or an event --
    # only here, where `ssl` reads it from a path this account can open.
    context.load_cert_chain(certfile=client_certificate, keyfile=client_key)
    return context


def send_inference(
    *,
    host: str,
    port: int,
    path: str,
    frame: bytes,
    expected_pin: str,
    allowed_addresses: Sequence[str],
    max_request_bytes: int,
    max_response_bytes: int,
    deadline_seconds: int,
    context: ssl.SSLContext,
    clock: Optional[Callable[[], float]] = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> tuple:
    """One attempt. Every bound is an argument; none has a permissive default.

    Returns `(EgressReport, body)`. The body is bytes and is **not**
    interpreted here: `advisory_response.read_advisory` is the untrusted
    content boundary, and a transport that parsed a response would be a
    transport deciding what a provider meant.

    `allowed_addresses` is what the resolved peer address must be one of.
    Passed in rather than resolved-and-trusted here, because "the name was
    right" is not "the address was": a transport that accepted whatever DNS
    returned would treat the resolver as an authority nobody commissioned.

    `cancelled` is consulted before the connection, after the handshake and
    between reads. A cancelled request stops where it is and is reported as
    `NOT_SENT` or `INTERRUPTED`; it is never reported as having received
    anything it did not finish reading.
    """

    now = clock or time.perf_counter
    started = now()

    def remaining() -> float:
        return deadline_seconds - (now() - started)

    if not allowed_addresses:
        raise InferenceRefused(
            "no address is allowed, so none is contacted. An empty allowlist "
            "is a refusal, never 'anything'"
        )
    if len(frame) > max_request_bytes:
        # Checked **before** the connection. A request refused after the
        # handshake is a request whose size the peer already learned.
        return (
            EgressReport(
                TransportOutcome.NOT_SENT,
                0,
                0,
                f"the frame is {len(frame)} bytes and this provider's ceiling "
                f"is {max_request_bytes}; nothing was sent and no connection "
                "was opened",
            ),
            b"",
        )
    if not frame:
        return (
            EgressReport(
                TransportOutcome.NOT_SENT, 0, 0, "there is nothing to send"
            ),
            b"",
        )
    if cancelled():
        return (
            EgressReport(
                TransportOutcome.NOT_SENT, 0, 0, "the request was cancelled "
                "before anything was sent"
            ),
            b"",
        )

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        return (
            EgressReport(
                TransportOutcome.NOT_SENT, 0, 0, f"the name did not resolve: {exc}"
            ),
            b"",
        )
    addresses = {info[4][0] for info in infos}
    outside = sorted(addresses - set(allowed_addresses))
    if outside or not addresses:
        # The resolver is not an authority. A name that resolves outside the
        # commissioned set is a name that has been moved.
        return (
            EgressReport(
                TransportOutcome.NOT_SENT,
                0,
                0,
                "the name resolved outside the addresses this node was "
                "commissioned to reach; DNS is an attack surface, not a "
                "permission",
            ),
            b"",
        )

    # One address, chosen deterministically, and the family derived from
    # **that** address. Picking a family from one and connecting to another
    # is how a v6-only allowlist ends up contacted over v4.
    target = sorted(addresses)[0]
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    raw = socket.socket(family)
    raw.settimeout(max(remaining(), 0.001))
    try:
        try:
            raw.connect((target, port))
            tls = context.wrap_socket(raw, server_hostname=host)
        except ssl.SSLError as exc:
            return (
                EgressReport(
                    TransportOutcome.TLS_FAILED, 0, 0,
                    f"the TLS handshake did not hold: {exc.reason or 'refused'}",
                ),
                b"",
            )
        except (socket.timeout, TimeoutError):
            return (
                EgressReport(
                    TransportOutcome.TIMED_OUT, 0, 0,
                    f"the deadline of {deadline_seconds}s passed during connect",
                ),
                b"",
            )
        except OSError as exc:
            return (
                EgressReport(
                    TransportOutcome.NOT_SENT, 0, 0, f"the peer was not reached: {exc}"
                ),
                b"",
            )

        with tls:
            peer = tls.getpeercert(binary_form=True)
            if not peer:
                return (
                    EgressReport(
                        TransportOutcome.TLS_FAILED, 0, 0,
                        "the peer presented no certificate",
                    ),
                    b"",
                )
            if spki_pin(peer) != expected_pin:
                # Layered on chain, dates and hostname, which `ssl` already
                # checked. Four questions, four checks.
                return (
                    EgressReport(
                        TransportOutcome.TLS_FAILED, 0, 0,
                        "the peer's key is not the pinned key for this "
                        "provider",
                    ),
                    b"",
                )
            if cancelled():
                return (
                    EgressReport(
                        TransportOutcome.NOT_SENT, 0, 0,
                        "the request was cancelled after the handshake and "
                        "before anything was sent",
                    ),
                    b"",
                )

            request = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(frame)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii") + frame
            try:
                tls.settimeout(max(remaining(), 0.001))
                tls.sendall(request)
            except (socket.timeout, TimeoutError):
                return (
                    EgressReport(
                        TransportOutcome.TIMED_OUT, 0, 0,
                        f"the deadline of {deadline_seconds}s passed while sending",
                    ),
                    b"",
                )
            except ssl.SSLError as exc:
                # Not INTERRUPTED, and the branch has to be above `OSError`
                # because `ssl.SSLError` derives from it. The read path below
                # gives the reason; it applies here unchanged. Under TLS 1.3
                # the server's verdict on our client certificate arrives after
                # we consider the handshake finished, and whether it reaches us
                # while we are still writing or on the first read is a matter
                # of timing. One fact -- this node's identity was not accepted
                # -- must not be reported as two different outcomes.
                return (
                    EgressReport(
                        TransportOutcome.TLS_FAILED,
                        0,
                        0,
                        f"mutual TLS did not hold: {exc.reason or 'alert'}",
                    ),
                    b"",
                )
            except OSError as exc:
                # A server that rejects our client certificate sends its alert
                # and closes. If the alert and the close both land before our
                # write, the write fails with a plain reset and OpenSSL never
                # reads the alert -- but the alert is still sitting in the
                # receive buffer (#232). Look before calling it a network
                # fault. Only an alert the peer actually sent turns this into
                # TLS_FAILED; anything else stays INTERRUPTED, and neither is
                # ever RECEIVED.
                verdict = _pending_alert(tls, remaining)
                if verdict is not None:
                    return (
                        EgressReport(
                            TransportOutcome.TLS_FAILED,
                            0,
                            0,
                            f"mutual TLS did not hold: {verdict.reason or 'alert'}",
                        ),
                        b"",
                    )
                return (
                    EgressReport(
                        TransportOutcome.INTERRUPTED, 0, 0, f"the send failed: {exc}"
                    ),
                    b"",
                )

            return _read_response(
                tls,
                remaining=remaining,
                deadline_seconds=deadline_seconds,
                max_response_bytes=max_response_bytes,
                cancelled=cancelled,
            )
    finally:
        try:
            raw.close()
        except OSError:
            pass


#: How long a failed write may wait for the alert that explains it. The alert,
#: when there is one, is already in the receive buffer; this only bounds a
#: socket that has nothing to say.
_ALERT_GRACE_SECONDS = 0.25


def _pending_alert(tls, remaining: Callable[[], float]):
    """The TLS alert the peer sent before a write failed, or None.

    One bounded read. Bytes, EOF, a timeout or another socket error are not an
    alert, and return None -- the caller then reports what it saw, which is an
    interruption. Never consumed as a response.
    """

    try:
        tls.settimeout(max(min(remaining(), _ALERT_GRACE_SECONDS), 0.001))
        tls.recv(1)
    except ssl.SSLError as alert:
        return alert
    except (OSError, ValueError):
        return None
    return None


def _read_response(
    tls,
    *,
    remaining: Callable[[], float],
    deadline_seconds: int,
    max_response_bytes: int,
    cancelled: Callable[[], bool],
) -> tuple:
    """Status line, bounded headers, bounded body. No redirect is followed.

    A transport that followed a redirect would be a transport whose provider
    allowlist is one hop wide.
    """

    buffer = b""
    while b"\r\n\r\n" not in buffer:
        if remaining() <= 0:
            return (
                EgressReport(
                    TransportOutcome.TIMED_OUT, 0, 0,
                    f"the deadline of {deadline_seconds}s passed while reading "
                    "the response head",
                ),
                b"",
            )
        if len(buffer) > MAX_RESPONSE_HEADER_BYTES:
            return (
                EgressReport(
                    TransportOutcome.INTERRUPTED, 0, 0,
                    f"the response head exceeded {MAX_RESPONSE_HEADER_BYTES} bytes",
                ),
                b"",
            )
        try:
            tls.settimeout(max(remaining(), 0.001))
            chunk = tls.recv(4096)
        except (socket.timeout, TimeoutError):
            return (
                EgressReport(
                    TransportOutcome.TIMED_OUT, 0, 0,
                    f"the deadline of {deadline_seconds}s passed while reading",
                ),
                b"",
            )
        except ssl.SSLError as exc:
            # Not INTERRUPTED. Under TLS 1.3 the server's verdict on our
            # client certificate arrives *after* the client considers the
            # handshake finished, so a rejected identity surfaces here as an
            # alert on the first read. Reporting that as an interruption
            # sends an operator to look at the network when the fact is that
            # this node's identity was not accepted.
            return (
                EgressReport(
                    TransportOutcome.TLS_FAILED,
                    0,
                    0,
                    f"mutual TLS did not hold: {exc.reason or 'alert'}",
                ),
                b"",
            )
        except OSError as exc:
            return (
                EgressReport(
                    TransportOutcome.INTERRUPTED, 0, 0, f"the read failed: {exc}"
                ),
                b"",
            )
        if not chunk:
            return (
                EgressReport(
                    TransportOutcome.INTERRUPTED, 0, 0,
                    "the peer closed before the response head was complete",
                ),
                b"",
            )
        buffer += chunk

    head, body = buffer.split(b"\r\n\r\n", 1)
    line, _, header_block = head.partition(b"\r\n")
    if len(line) > MAX_STATUS_LINE_BYTES:
        return (
            EgressReport(
                TransportOutcome.INTERRUPTED, 0, 0, "the status line is oversized"
            ),
            b"",
        )
    parts = line.split(b" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        return (
            EgressReport(
                TransportOutcome.INTERRUPTED, 0, 0, "the status line is malformed"
            ),
            b"",
        )
    if 300 <= status < 400:
        # Not followed, and the target is never read. A transport that
        # followed one would be a transport whose provider allowlist is one
        # hop wide, and one that logged the target would leak where it was
        # being sent.
        return (
            EgressReport(
                TransportOutcome.INTERRUPTED, 0, status,
                "the provider answered with a redirect, which this transport "
                "does not follow and does not read",
            ),
            b"",
        )

    while True:
        if len(body) > max_response_bytes:
            return (
                EgressReport(
                    TransportOutcome.INTERRUPTED, len(body), status,
                    f"the response exceeded this provider's ceiling of "
                    f"{max_response_bytes} bytes and was stopped",
                ),
                b"",
            )
        if cancelled():
            return (
                EgressReport(
                    TransportOutcome.INTERRUPTED, len(body), status,
                    "the request was cancelled while the response was being "
                    "read; a partial answer is not an answer",
                ),
                b"",
            )
        if remaining() <= 0:
            return (
                EgressReport(
                    TransportOutcome.TIMED_OUT, len(body), status,
                    f"the deadline of {deadline_seconds}s passed; a response "
                    "that arrives after its deadline is discarded, never merged",
                ),
                b"",
            )
        try:
            tls.settimeout(max(remaining(), 0.001))
            chunk = tls.recv(8192)
        except (socket.timeout, TimeoutError):
            return (
                EgressReport(
                    TransportOutcome.TIMED_OUT, len(body), status,
                    f"the deadline of {deadline_seconds}s passed while reading",
                ),
                b"",
            )
        except ssl.SSLError as exc:
            # Not INTERRUPTED. Under TLS 1.3 the server's verdict on our
            # client certificate arrives *after* the client considers the
            # handshake finished, so a rejected identity surfaces here as an
            # alert on the first read. Reporting that as an interruption
            # sends an operator to look at the network when the fact is that
            # this node's identity was not accepted.
            return (
                EgressReport(
                    TransportOutcome.TLS_FAILED,
                    0,
                    0,
                    f"mutual TLS did not hold: {exc.reason or 'alert'}",
                ),
                b"",
            )
        except OSError as exc:
            return (
                EgressReport(
                    TransportOutcome.INTERRUPTED, len(body), status,
                    f"the read failed: {exc}",
                ),
                b"",
            )
        if not chunk:
            break
        body += chunk

    if len(body) > max_response_bytes:
        return (
            EgressReport(
                TransportOutcome.INTERRUPTED, len(body), status,
                f"the response exceeded this provider's ceiling of "
                f"{max_response_bytes} bytes",
            ),
            b"",
        )
    return (
        EgressReport(
            TransportOutcome.RECEIVED,
            len(body),
            status,
            "bytes arrived within every bound; whether they are advice is "
            "decided by the content boundary, not here",
        ),
        body,
    )
