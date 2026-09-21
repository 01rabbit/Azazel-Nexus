"""The one module that may open a connection, driven against a real one (#105).

A local TLS server, a certificate generated for the run, and every failure
path the design names -- pin mismatch, redirect, an address outside the
allowlist, an oversized response, a deadline, an interruption and a resume.

Nothing here reaches a real network. The server listens on loopback, the
certificate is generated into `tmp_path` and discarded, and no fixture
carries a key that exists anywhere else.
"""

from __future__ import annotations

import ast
import hashlib
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "runtime" / "src"))
from azazel_nexus_runtime import artifact_egress  # noqa: E402
from azazel_nexus_runtime.artifact_egress import (  # noqa: E402
    MAX_HEADER_BYTES,
    EgressRefused,
    EgressResult,
    Outcome,
    fetch_artifact,
    spki_pin,
    tls_context,
)

openssl = shutil.which("openssl")
requires_openssl = pytest.mark.skipif(
    openssl is None,
    reason="a certificate for the run is generated with the openssl CLI",
)

BODY = b"weights, not a program -- " + bytes(range(256)) * 32
LOOPBACK = "127.0.0.1"


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    """A self-signed certificate generated for this run and nothing else."""

    if openssl is None:
        pytest.skip("openssl is not available")
    room = tmp_path_factory.mktemp("tls")
    key = room / "server.key"
    cert = room / "server.crt"
    subprocess.run(
        [
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=artifact-source.invalid",
            "-addext", "subjectAltName=IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    return key, cert


def openssl_spki_pin(cert: pathlib.Path) -> str:
    """What OpenSSL says the public key's digest is.

    A differential check: the walker in `artifact_egress` is a minimal DER
    traversal, and the only thing worth comparing it against is an
    independent implementation rather than a fixture this suite wrote.
    """

    pub = subprocess.run(
        [openssl, "x509", "-in", str(cert), "-pubkey", "-noout"],
        check=True, capture_output=True,
    ).stdout
    der = subprocess.run(
        [openssl, "pkey", "-pubin", "-outform", "DER"],
        input=pub, check=True, capture_output=True,
    ).stdout
    return "sha256:" + hashlib.sha256(der).hexdigest()


class Server:
    """A loopback TLS server that answers exactly how a test tells it to."""

    def __init__(self, key, cert, *, responder):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile=str(cert), keyfile=str(key))
        self.responder = responder
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((LOOPBACK, 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.requests = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            raw, _ = self.listener.accept()
        except OSError:
            return
        try:
            stream = self.context.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        try:
            stream.settimeout(5)
            request = b""
            while b"\r\n\r\n" not in request:
                piece = stream.recv(4096)
                if not piece:
                    return
                request += piece
            self.requests.append(request.decode("latin-1"))
            self.responder(stream, request.decode("latin-1"))
        except (OSError, ssl.SSLError, BrokenPipeError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def close(self):
        try:
            self.listener.close()
        except OSError:
            pass


def whole_body(stream, request, body=BODY):
    stream.sendall(
        f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii")
    )
    stream.sendall(body)


def partial_from(offset, body=BODY, *, start=None):
    def responder(stream, request):
        begin = offset if start is None else start
        rest = body[begin:]
        stream.sendall(
            (
                "HTTP/1.1 206 Partial Content\r\n"
                f"Content-Range: bytes {begin}-{len(body) - 1}/{len(body)}\r\n"
                f"Content-Length: {len(rest)}\r\n\r\n"
            ).encode("ascii")
        )
        stream.sendall(rest)

    return responder


def status_only(code, extra=""):
    def responder(stream, request):
        stream.sendall(
            f"HTTP/1.1 {code} X\r\n{extra}Content-Length: 0\r\n\r\n".encode("ascii")
        )

    return responder


def run_fetch(server, cert, **overrides):
    written = bytearray()
    arguments = {
        "host": LOOPBACK,
        "port": server.port,
        "path": "/artifacts/" + "a" * 64,
        "expected_pin": openssl_spki_pin(cert),
        "expected_size": len(BODY),
        "allowed_addresses": [LOOPBACK],
        "deadline_seconds": 10,
        "bandwidth_bytes_per_second": 100 * 1024 * 1024,
        "sink": written.extend,
        "sleeper": lambda seconds: None,
    }
    arguments.update(overrides)
    return fetch_artifact(**arguments), bytes(written)


# -- the pin, checked against OpenSSL rather than a fixture ----------------


@requires_openssl
def test_the_pin_agrees_with_openssls_own_extraction(certificate) -> None:
    """The DER walk is minimal; the only worthwhile comparison is an
    independent implementation."""

    _key, cert = certificate
    der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    assert spki_pin(der) == openssl_spki_pin(cert)


@requires_openssl
def test_the_pin_is_over_the_key_not_the_certificate(certificate) -> None:
    """A pin over the whole certificate turns every ordinary renewal into an
    outage indistinguishable from an attack, which is how pinning gets
    switched off."""

    _key, cert = certificate
    der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    assert spki_pin(der) != "sha256:" + hashlib.sha256(der).hexdigest()


@pytest.mark.parametrize(
    "rubbish", [b"", b"\x30", b"\x30\x03\x02\x01\x00", b"not der at all"]
)
def test_a_certificate_that_is_not_one_is_refused(rubbish) -> None:
    with pytest.raises(EgressRefused):
        spki_pin(rubbish)


# -- the happy path, over a real handshake --------------------------------


@requires_openssl
def test_a_pinned_peer_serves_the_declared_bytes(certificate) -> None:
    key, cert = certificate
    server = Server(key, cert, responder=whole_body)
    try:
        result, written = run_fetch(server, cert)
    finally:
        server.close()
    assert result.outcome is Outcome.COMPLETE
    assert written == BODY
    assert result.received == len(BODY)
    # And it asked for what it was told to ask for, over HTTP/1.1, with no
    # credential smuggled into the request line.
    assert server.requests[0].startswith("GET /artifacts/" + "a" * 64 + " HTTP/1.1")
    assert "Authorization" not in server.requests[0]


# -- every refusal the design names ---------------------------------------


@requires_openssl
def test_a_peer_whose_key_does_not_match_the_pin_is_refused(certificate) -> None:
    """And nothing is requested: the check is the first act after the
    handshake."""

    key, cert = certificate
    server = Server(key, cert, responder=whole_body)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, cert, expected_pin="sha256:" + "0" * 64)
    finally:
        server.close()
    assert "does not match the commissioned pin" in str(caught.value)
    assert "Nothing was requested" in str(caught.value)
    assert server.requests == [], "a request was sent to an unpinned peer"


@requires_openssl
@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed(certificate, code) -> None:
    """A fetcher that follows one is a fetcher whose allowlist is bypassed in
    a single hop."""

    key, cert = certificate
    server = Server(
        key, cert, responder=status_only(code, "Location: https://elsewhere.invalid/x\r\n")
    )
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, cert)
    finally:
        server.close()
    assert "redirect is not followed" in str(caught.value)
    # Nothing about where it was going, and nothing about where it was: the
    # refused `Location` is not echoed, and neither is the request target.
    message = str(caught.value)
    for leak in ("elsewhere.invalid", LOOPBACK, "/artifacts/", "a" * 64):
        assert leak not in message, leak


@requires_openssl
def test_an_address_outside_the_allowlist_is_never_contacted(certificate) -> None:
    """A right name is not a right address."""

    key, cert = certificate
    server = Server(key, cert, responder=whole_body)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, cert, allowed_addresses=["198.51.100.7"])
    finally:
        server.close()
    assert "the allowlist does not carry" in str(caught.value)
    assert server.requests == []


def test_an_empty_allowlist_is_a_refusal_never_anything() -> None:
    with pytest.raises(EgressRefused) as caught:
        fetch_artifact(
            host=LOOPBACK, port=1, path="/x", expected_pin="sha256:" + "0" * 64,
            expected_size=1, allowed_addresses=[], deadline_seconds=1,
            bandwidth_bytes_per_second=1, sink=lambda chunk: None,
        )
    assert "never 'anything'" in str(caught.value)


@requires_openssl
def test_a_response_larger_than_declared_is_stopped(certificate) -> None:
    key, cert = certificate

    def too_much(stream, request):
        body = BODY + b"and more that nobody declared"
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii")
        )
        stream.sendall(body)

    server = Server(key, cert, responder=too_much)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, cert)
    finally:
        server.close()
    assert "A file that grew" in str(caught.value)


@requires_openssl
def test_an_overrun_that_arrives_with_the_headers_is_stopped(certificate) -> None:
    """The first bytes, not just later ones.

    A body that arrives in the same read as the header block takes a
    different path through the reader -- it is already in hand when the
    headers are split off. Testing only the later chunks leaves the very
    first bytes, which are the ones a server controls most easily, unchecked.
    """

    key, cert = certificate
    body = BODY + b"and more that nobody declared"

    def one_write(stream, request):
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )

    server = Server(key, cert, responder=one_write)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, cert)
    finally:
        server.close()
    assert "A file that grew" in str(caught.value)


@requires_openssl
def test_a_header_block_that_will_not_end_is_refused_unparsed(certificate) -> None:
    key, cert = certificate

    def endless_headers(stream, request):
        stream.sendall(b"HTTP/1.1 200 OK\r\n")
        for index in range(MAX_HEADER_BYTES // 16 + 64):
            stream.sendall(f"X-Filler-{index}: padding\r\n".encode("ascii"))

    server = Server(key, cert, responder=endless_headers)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, cert)
    finally:
        server.close()
    assert "without being parsed" in str(caught.value)


@requires_openssl
def test_a_status_that_is_not_the_expected_one_is_refused(certificate) -> None:
    key, cert = certificate
    server = Server(key, cert, responder=status_only(404))
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, cert)
    finally:
        server.close()
    assert "404" in str(caught.value)


@requires_openssl
def test_an_interrupted_transfer_reports_how_far_it_got(certificate) -> None:
    key, cert = certificate

    def half(stream, request):
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(BODY)}\r\n\r\n".encode("ascii")
        )
        stream.sendall(BODY[: len(BODY) // 2])

    server = Server(key, cert, responder=half)
    try:
        result, written = run_fetch(server, cert)
    finally:
        server.close()
    assert result.outcome is Outcome.INTERRUPTED
    assert result.received == len(BODY) // 2
    assert written == BODY[: len(BODY) // 2]
    assert "digest is still checked afterwards" in result.reason


@requires_openssl
def test_a_resumed_transfer_continues_and_completes(certificate) -> None:
    key, cert = certificate
    offset = len(BODY) // 2
    server = Server(key, cert, responder=partial_from(offset))
    try:
        result, written = run_fetch(server, cert, resume_from=offset)
    finally:
        server.close()
    assert result.outcome is Outcome.COMPLETE
    assert result.received == len(BODY)
    assert written == BODY[offset:]
    assert f"Range: bytes={offset}-" in server.requests[0]


@requires_openssl
def test_a_peer_that_ignores_range_and_restarts_is_refused(certificate) -> None:
    """The bytes would append to what is staged, the length would often come
    out right, and only the digest would notice -- after the whole transfer."""

    key, cert = certificate
    offset = len(BODY) // 2
    server = Server(key, cert, responder=partial_from(offset, start=0))
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, cert, resume_from=offset)
    finally:
        server.close()
    assert "does not start at the requested byte" in str(caught.value)


@requires_openssl
def test_the_deadline_stops_a_transfer_that_does_not(certificate) -> None:
    key, cert = certificate

    big = BODY * 40  # larger than one read, so there is a second iteration
    server = Server(key, cert, responder=lambda stream, request: whole_body(
        stream, request, body=big
    ))
    written = bytearray()
    # Time spent writing and throttling counts against the deadline too --
    # which is the whole reason there is a check *after* a chunk and not only
    # before the next read. The throttle here is slow enough that one chunk's
    # wait spends the budget, so the outer check is the one that fires.
    elapsed = [0.0]

    def sleeper(seconds):
        elapsed[0] += seconds

    try:
        result = fetch_artifact(
            host=LOOPBACK,
            port=server.port,
            path="/artifacts/" + "a" * 64,
            expected_pin=openssl_spki_pin(cert),
            expected_size=len(big),
            allowed_addresses=[LOOPBACK],
            deadline_seconds=5,
            bandwidth_bytes_per_second=64,
            sink=written.extend,
            sleeper=sleeper,
            clock=lambda: elapsed[0],
        )
    finally:
        server.close()
    assert result.outcome is Outcome.TIMED_OUT
    assert 0 < result.received < len(big)
    assert "deadline passed" in result.reason
    assert "bytes outstanding" in result.reason
    assert elapsed[0] > 0, "the deadline was declared spent without being spent"
    # And it never slept past the budget it was given.
    assert elapsed[0] <= 5 + 1e-9, (
        f"it slept {elapsed[0]}s against a 5s deadline; sleeping through a "
        "spent budget buys nothing and looks like a hung transfer"
    )


@requires_openssl
def test_a_peer_that_stops_sending_is_interrupted_not_timed_out(certificate) -> None:
    """The other exit, and it is a different word.

    A peer that stops is resumable from where it stopped; a deadline that
    passed says the budget is gone. Reporting one as the other would send an
    operator looking in the wrong place.
    """

    key, cert = certificate

    def half_then_close(stream, request):
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(BODY)}\r\n\r\n".encode("ascii")
        )
        stream.sendall(BODY[:128])

    server = Server(key, cert, responder=half_then_close)
    try:
        result, _written = run_fetch(server, cert)
    finally:
        server.close()
    assert result.outcome is Outcome.INTERRUPTED
    assert result.received == 128


@requires_openssl
def test_the_bandwidth_ceiling_is_applied_to_what_arrives(certificate) -> None:
    """A ceiling so that an acquisition cannot starve a node whose whole job
    is to keep answering while it happens."""

    key, cert = certificate
    slept = []
    server = Server(key, cert, responder=whole_body)
    try:
        result, _written = run_fetch(
            server, cert,
            bandwidth_bytes_per_second=1024,
            sleeper=slept.append,
        )
    finally:
        server.close()
    assert result.complete
    assert slept, "no throttling was applied"
    assert sum(slept) == pytest.approx(len(BODY) / 1024, rel=0.01)


def test_a_resume_offset_outside_the_artifact_is_refused() -> None:
    for offset in (-1, 10_000):
        with pytest.raises(EgressRefused):
            fetch_artifact(
                host=LOOPBACK, port=1, path="/x",
                expected_pin="sha256:" + "0" * 64, expected_size=100,
                resume_from=offset, allowed_addresses=[LOOPBACK],
                deadline_seconds=1, bandwidth_bytes_per_second=1,
                sink=lambda chunk: None,
            )


@pytest.mark.parametrize("deadline, bandwidth", [(0, 1), (1, 0), (-1, 1), (1, -1)])
def test_a_permissive_bound_is_refused(deadline, bandwidth) -> None:
    """None of the bounds has a permissive default, and none may be zero."""

    with pytest.raises(EgressRefused):
        fetch_artifact(
            host=LOOPBACK, port=1, path="/x", expected_pin="sha256:" + "0" * 64,
            expected_size=1, allowed_addresses=[LOOPBACK],
            deadline_seconds=deadline, bandwidth_bytes_per_second=bandwidth,
            sink=lambda chunk: None,
        )


# -- what this module is not ----------------------------------------------


def test_the_tls_floor_is_pinned() -> None:
    """A context that would negotiate TLS 1.0 is a context that would
    negotiate it silently: nothing in a successful fetch says which version
    was used, so a floor that slipped would not show up anywhere else.
    """

    context = tls_context()
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert context.protocol is ssl.PROTOCOL_TLS_CLIENT
    # Hostname checking and CA verification are off **because the pin
    # replaces them**, and the pin is checked on every connection.
    assert context.check_hostname is False
    assert context.verify_mode is ssl.CERT_NONE


def test_this_is_not_the_inference_transport() -> None:
    """A module that cannot name a privacy class cannot carry one.

    Reusing this for M.I.O. requests would turn the route that fetches
    weights into the route that sends observations. Different service,
    different identity, different policy -- and this asserts the vocabulary
    is absent rather than merely unused.
    """

    source = pathlib.Path(artifact_egress.__file__).read_text(encoding="utf-8")
    body = source.split('"""', 2)[2]  # past the module docstring
    for forbidden in (
        "P0_PUBLIC", "P1_SANITIZED", "P2_MISSION", "P3_RESTRICTED",
        "PrivacyClass", "sanitize", "sanitise", "SituationFrame", "prompt",
    ):
        assert forbidden not in body, forbidden
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert "azazel_nexus" not in imported, (
        "the egress module reached into the library; it takes arguments, and "
        "a module that imported policy could apply its own"
    )


def test_it_emits_no_credential_no_url_and_no_pin() -> None:
    result = EgressResult(Outcome.COMPLETE, 10, 200, "done")
    event = repr(result.as_event()).lower()
    for forbidden in ("http", "://", "host", "path", "pin", "token", "key", "identity"):
        assert forbidden not in event, forbidden


def test_it_offers_no_verb_that_verifies_admits_or_promotes() -> None:
    tree = ast.parse(
        pathlib.Path(artifact_egress.__file__).read_text(encoding="utf-8")
    )
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert not any(
        name.lstrip("_").startswith(("verify", "admit", "activate", "promote", "install"))
        for name in names
    ), sorted(names)
    assert "VERIFIED" not in {o.name for o in Outcome}
    assert "PROMOTED" not in {o.name for o in Outcome}
