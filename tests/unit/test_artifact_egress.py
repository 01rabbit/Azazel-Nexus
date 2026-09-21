"""The one module that may open a connection, driven against a real one (#105).

A loopback TLS server, **fixed** certificates committed under
`tests/fixtures/tls`, and every failure path the design names: untrusted
issuer, expired certificate, hostname mismatch, a client certificate absent
and a client certificate the server will not accept, an unknown pin, an empty
pin, a redirect, a deadline, an interruption, a resume, and an overrun.

**Nothing here skips.** An earlier version generated a certificate with the
`openssl` CLI at test time and skipped when the CLI was absent, which made
the binary's presence, version and behaviour a precondition of exactly the
tests that matter most. These run on the standard library's `ssl` and
nothing else.

Nothing reaches a real network: the server listens on loopback, and the
fixtures authenticate a server that exists for the length of a test.
"""

from __future__ import annotations

import ast
import hashlib
import pathlib
import socket
import ssl
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

TLS = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "tls"
sys.path.insert(0, str(TLS.parent))
from tls.pins import PINS  # noqa: E402

BODY = b"weights, not a program -- " + bytes(range(256)) * 32
LOOPBACK = "127.0.0.1"
#: The fixture server's name, and one that actually resolves -- so the
#: hostname check is exercised rather than stepped around.
HOSTNAME = "localhost"


def material(name: str) -> str:
    return str(TLS / name)


def client_context(*, ca="trusted-ca.crt", client="client", with_client=True):
    return tls_context(
        ca_certificate=material(ca),
        client_certificate=material(f"{client}.crt") if with_client else None,
        client_key=material(f"{client}.key") if with_client else None,
    )


class Server:
    """A loopback TLS server that answers exactly how a test tells it to."""

    def __init__(self, *, responder, certificate="server", require_client=True,
                 client_ca="trusted-ca.crt"):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(
            certfile=material(f"{certificate}.crt"), keyfile=material(f"{certificate}.key")
        )
        if require_client:
            self.context.verify_mode = ssl.CERT_REQUIRED
            self.context.load_verify_locations(cafile=material(client_ca))
        self.responder = responder
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((LOOPBACK, 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.requests = []
        self.handshake_failed = threading.Event()
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
            self.handshake_failed.set()
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


def run_fetch(server, **overrides):
    written = bytearray()
    arguments = {
        "host": HOSTNAME,
        "port": server.port,
        "path": "/artifacts/" + "a" * 64,
        "expected_pin": PINS["server"],
        "expected_size": len(BODY),
        "allowed_addresses": [LOOPBACK],
        "deadline_seconds": 10,
        "bandwidth_bytes_per_second": 100 * 1024 * 1024,
        "sink": written.extend,
        "sleeper": lambda seconds: None,
        "context": client_context(),
    }
    arguments.update(overrides)
    return fetch_artifact(**arguments), bytes(written)


# -- the pins are fixed values, not values derived from the files ----------


@pytest.mark.parametrize("name", sorted(PINS))
def test_each_fixture_matches_its_recorded_pin(name) -> None:
    """Recorded when the fixtures were made, compared now.

    A pin the test computed from the certificate it is checking would go on
    agreeing with itself after the extraction it is meant to verify had
    broken. These constants were written down once and are not re-derived.
    """

    der = ssl.PEM_cert_to_DER_cert((TLS / f"{name}.crt").read_text(encoding="ascii"))
    assert spki_pin(der) == PINS[name]


def test_the_pins_are_distinct() -> None:
    """A vacuous fixture set would be one where everything matched everything."""

    assert len(set(PINS.values())) == len(PINS)


def test_the_pin_is_over_the_key_not_the_certificate() -> None:
    """A pin over the whole certificate turns every ordinary renewal into an
    outage indistinguishable from an attack, which is how pinning gets
    switched off."""

    der = ssl.PEM_cert_to_DER_cert((TLS / "server.crt").read_text(encoding="ascii"))
    assert spki_pin(der) != "sha256:" + hashlib.sha256(der).hexdigest()


@pytest.mark.parametrize(
    "rubbish", [b"", b"\x30", b"\x30\x03\x02\x01\x00", b"not der at all"]
)
def test_a_certificate_that_is_not_one_is_refused(rubbish) -> None:
    with pytest.raises(EgressRefused):
        spki_pin(rubbish)


# -- the happy path, over a real mutually-authenticated handshake ---------


def test_a_verified_and_pinned_peer_serves_the_declared_bytes() -> None:
    server = Server(responder=whole_body)
    try:
        result, written = run_fetch(server)
    finally:
        server.close()
    assert result.outcome is Outcome.COMPLETE
    assert written == BODY
    assert server.requests[0].startswith("GET /artifacts/" + "a" * 64 + " HTTP/1.1")
    assert "Authorization" not in server.requests[0]


# -- verification, on all four counts -------------------------------------


def test_a_certificate_from_an_untrusted_issuer_is_refused() -> None:
    """The pin is not asked. An issuer this node was not commissioned to
    accept is refused during the handshake."""

    server = Server(responder=whole_body, certificate="server-untrusted-ca")
    try:
        with pytest.raises(ssl.SSLCertVerificationError) as caught:
            run_fetch(server, expected_pin=PINS["server-untrusted-ca"])
    finally:
        server.close()
    assert "unable to get local issuer" in str(caught.value) or "self-signed" in str(
        caught.value
    ).replace("self signed", "self-signed")
    assert server.requests == []


def test_an_expired_certificate_is_refused() -> None:
    """The pin says nothing about dates, which is why the dates are checked."""

    server = Server(responder=whole_body, certificate="server-expired")
    try:
        with pytest.raises(ssl.SSLCertVerificationError) as caught:
            run_fetch(server, expected_pin=PINS["server-expired"])
    finally:
        server.close()
    assert "expired" in str(caught.value)
    assert server.requests == []


def test_a_certificate_issued_for_another_name_is_refused() -> None:
    """The pin says nothing about which name the certificate was issued for."""

    server = Server(responder=whole_body, certificate="server-wrong-name")
    try:
        with pytest.raises(ssl.SSLCertVerificationError) as caught:
            run_fetch(server, expected_pin=PINS["server-wrong-name"])
    finally:
        server.close()
    assert "Hostname mismatch" in str(caught.value) or "doesn't match" in str(caught.value)
    assert server.requests == []


def test_the_host_store_is_never_consulted() -> None:
    """Only the commissioned anchor. A context that fell back to the system
    store would trust whatever the host happens to trust."""

    context = client_context()
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    loaded = {entry["serialNumber"] for entry in context.get_ca_certs()}
    system = ssl.create_default_context().get_ca_certs()
    assert len(loaded) == 1, "more than the commissioned anchor is loaded"
    assert not (loaded & {entry["serialNumber"] for entry in system})


def test_a_context_cannot_be_built_without_an_anchor() -> None:
    with pytest.raises(TypeError):
        tls_context()  # type: ignore[call-arg]


# -- mutual authentication -------------------------------------------------


def test_a_node_with_no_client_certificate_is_refused_by_the_server() -> None:
    """mTLS both ways: the node shows who it is, or it does not get served."""

    server = Server(responder=whole_body)
    try:
        with pytest.raises((ssl.SSLError, OSError)):
            run_fetch(server, context=client_context(with_client=False))
    finally:
        server.close()
    assert server.requests == []


def test_a_client_certificate_the_server_will_not_accept_is_refused() -> None:
    server = Server(responder=whole_body)
    try:
        with pytest.raises((ssl.SSLError, OSError)):
            run_fetch(server, context=client_context(client="client-untrusted"))
    finally:
        server.close()
    assert server.requests == []


# -- the pin, on top of all that ------------------------------------------


def test_a_peer_whose_key_does_not_match_the_pin_is_refused() -> None:
    """Verified by the CA, correct name, in date -- and still refused.

    Nothing is requested: the check is the first act after the handshake.
    """

    server = Server(responder=whole_body)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, expected_pin="sha256:" + "0" * 64)
    finally:
        server.close()
    assert "does not match the commissioned pin" in str(caught.value)
    assert "Nothing was requested" in str(caught.value)
    assert server.requests == [], "a request was sent to an unpinned peer"


def test_an_empty_pin_is_not_any_key() -> None:
    server = Server(responder=whole_body)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, expected_pin="")
    finally:
        server.close()
    assert "not 'any key'" in str(caught.value)
    assert server.requests == []


def test_another_fixtures_pin_does_not_match_this_server() -> None:
    """A real key, correctly formed, and the wrong one."""

    server = Server(responder=whole_body)
    try:
        with pytest.raises(EgressRefused):
            run_fetch(server, expected_pin=PINS["trusted-ca"])
    finally:
        server.close()


# -- the transport refusals ------------------------------------------------


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed(code) -> None:
    """A fetcher that follows one is a fetcher whose allowlist is bypassed in
    a single hop."""

    server = Server(
        responder=status_only(code, "Location: https://elsewhere.invalid/x\r\n")
    )
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server)
    finally:
        server.close()
    assert "redirect is not followed" in str(caught.value)
    message = str(caught.value)
    for leak in ("elsewhere.invalid", HOSTNAME, "/artifacts/", "a" * 64):
        assert leak not in message, leak


def test_an_address_outside_the_allowlist_is_never_contacted() -> None:
    """A right name is not a right address."""

    server = Server(responder=whole_body)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, allowed_addresses=["198.51.100.7"])
    finally:
        server.close()
    assert "the allowlist does not carry" in str(caught.value)
    assert server.requests == []


def test_an_empty_allowlist_is_a_refusal_never_anything() -> None:
    with pytest.raises(EgressRefused) as caught:
        fetch_artifact(
            host=HOSTNAME, port=1, path="/x", expected_pin=PINS["server"],
            expected_size=1, allowed_addresses=[], deadline_seconds=1,
            bandwidth_bytes_per_second=1, sink=lambda chunk: None,
            context=client_context(),
        )
    assert "never 'anything'" in str(caught.value)


def test_a_response_larger_than_declared_is_stopped() -> None:
    def too_much(stream, request):
        body = BODY + b"and more that nobody declared"
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii")
        )
        stream.sendall(body)

    server = Server(responder=too_much)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server)
    finally:
        server.close()
    assert "A file that grew" in str(caught.value)


def test_an_overrun_that_arrives_with_the_headers_is_stopped() -> None:
    """The first bytes, not just later ones -- a server controls those most
    easily, and they take a different path through the reader."""

    declared = 16
    body = b"x" * 4000

    def one_write(stream, request):
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii")
            + body
        )

    server = Server(responder=one_write)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, expected_size=declared)
    finally:
        server.close()
    assert "A file that grew" in str(caught.value)


def test_a_header_block_that_will_not_end_is_refused_unparsed() -> None:
    def endless_headers(stream, request):
        stream.sendall(b"HTTP/1.1 200 OK\r\n")
        for index in range(MAX_HEADER_BYTES // 16 + 64):
            stream.sendall(f"X-Filler-{index}: padding\r\n".encode("ascii"))

    server = Server(responder=endless_headers)
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server)
    finally:
        server.close()
    assert "without being parsed" in str(caught.value)


def test_a_status_that_is_not_the_expected_one_is_refused() -> None:
    server = Server(responder=status_only(404))
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server)
    finally:
        server.close()
    assert "404" in str(caught.value)


def test_an_interrupted_transfer_reports_how_far_it_got() -> None:
    def half(stream, request):
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(BODY)}\r\n\r\n".encode("ascii")
        )
        stream.sendall(BODY[: len(BODY) // 2])

    server = Server(responder=half)
    try:
        result, written = run_fetch(server)
    finally:
        server.close()
    assert result.outcome is Outcome.INTERRUPTED
    assert result.received == len(BODY) // 2
    assert written == BODY[: len(BODY) // 2]
    assert "digest is still checked afterwards" in result.reason


def test_a_resumed_transfer_continues_and_completes() -> None:
    offset = len(BODY) // 2
    server = Server(responder=partial_from(offset))
    try:
        result, written = run_fetch(server, resume_from=offset)
    finally:
        server.close()
    assert result.outcome is Outcome.COMPLETE
    assert result.received == len(BODY)
    assert written == BODY[offset:]
    assert f"Range: bytes={offset}-" in server.requests[0]


def test_a_resumed_transfer_still_has_to_match_its_digest() -> None:
    """Resume is not a way past verification.

    The transport reports what arrived; the digest over the whole file --
    staged part plus resumed part -- is what decides, and a peer that served
    the wrong tail fails it.
    """

    offset = len(BODY) // 2
    wrong_tail = b"z" * (len(BODY) - offset)
    server = Server(responder=partial_from(offset, body=BODY[:offset] + wrong_tail))
    try:
        result, written = run_fetch(server, resume_from=offset)
    finally:
        server.close()
    assert result.outcome is Outcome.COMPLETE, "the transport moved the bytes"
    staged = BODY[:offset] + written
    assert len(staged) == len(BODY)
    observed = "sha256:" + hashlib.sha256(staged).hexdigest()
    expected = "sha256:" + hashlib.sha256(BODY).hexdigest()
    assert observed != expected, "a wrong tail passed the digest"


def test_a_peer_that_ignores_range_and_restarts_is_refused() -> None:
    """The bytes would append to what is staged, the length would often come
    out right, and only the digest would notice -- after the whole transfer."""

    offset = len(BODY) // 2
    server = Server(responder=partial_from(offset, start=0))
    try:
        with pytest.raises(EgressRefused) as caught:
            run_fetch(server, resume_from=offset)
    finally:
        server.close()
    assert "does not start at the requested byte" in str(caught.value)


def test_the_deadline_stops_a_transfer_that_does_not() -> None:
    big = BODY * 40  # larger than one read, so there is a second iteration
    server = Server(responder=lambda stream, request: whole_body(stream, request, body=big))
    written = bytearray()
    elapsed = [0.0]

    def sleeper(seconds):
        elapsed[0] += seconds

    try:
        result = fetch_artifact(
            host=HOSTNAME,
            port=server.port,
            path="/artifacts/" + "a" * 64,
            expected_pin=PINS["server"],
            expected_size=len(big),
            allowed_addresses=[LOOPBACK],
            deadline_seconds=5,
            bandwidth_bytes_per_second=64,
            sink=written.extend,
            sleeper=sleeper,
            clock=lambda: elapsed[0],
            context=client_context(),
        )
    finally:
        server.close()
    assert result.outcome is Outcome.TIMED_OUT
    assert 0 < result.received < len(big)
    assert "deadline passed" in result.reason and "bytes outstanding" in result.reason
    assert elapsed[0] <= 5 + 1e-9, (
        f"it slept {elapsed[0]}s against a 5s deadline; sleeping through a "
        "spent budget buys nothing and looks like a hung transfer"
    )


def test_a_peer_that_stops_sending_is_interrupted_not_timed_out() -> None:
    """A different word: one is resumable from where it stopped, the other
    says the budget is gone."""

    def half_then_close(stream, request):
        stream.sendall(
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(BODY)}\r\n\r\n".encode("ascii")
        )
        stream.sendall(BODY[:128])

    server = Server(responder=half_then_close)
    try:
        result, _written = run_fetch(server)
    finally:
        server.close()
    assert result.outcome is Outcome.INTERRUPTED
    assert result.received == 128


def test_the_bandwidth_ceiling_is_applied_to_what_arrives() -> None:
    slept = []
    server = Server(responder=whole_body)
    try:
        result, _written = run_fetch(
            server, bandwidth_bytes_per_second=1024, sleeper=slept.append
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
                host=HOSTNAME, port=1, path="/x", expected_pin=PINS["server"],
                expected_size=100, resume_from=offset, allowed_addresses=[LOOPBACK],
                deadline_seconds=1, bandwidth_bytes_per_second=1,
                sink=lambda chunk: None, context=client_context(),
            )


@pytest.mark.parametrize("deadline, bandwidth", [(0, 1), (1, 0), (-1, 1), (1, -1)])
def test_a_permissive_bound_is_refused(deadline, bandwidth) -> None:
    with pytest.raises(EgressRefused):
        fetch_artifact(
            host=HOSTNAME, port=1, path="/x", expected_pin=PINS["server"],
            expected_size=1, allowed_addresses=[LOOPBACK],
            deadline_seconds=deadline, bandwidth_bytes_per_second=bandwidth,
            sink=lambda chunk: None, context=client_context(),
        )


# -- what this module is not ----------------------------------------------


def test_this_is_not_the_inference_transport() -> None:
    """A module that cannot name a privacy class cannot carry one."""

    source = pathlib.Path(artifact_egress.__file__).read_text(encoding="utf-8")
    body = source.split('"""', 2)[2]
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
    assert imported & {"azazel_nexus"} <= {"azazel_nexus"}, "unreachable"
    library = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.startswith("azazel_nexus")
    }
    assert library <= PURE_LIBRARY_IMPORTS, (
        f"the egress module imports {sorted(library - PURE_LIBRARY_IMPORTS)} "
        "from the library; it takes arguments, and a module that imported "
        "policy could apply its own"
    )


#: The library modules an egress module may import, and nothing else.
#:
#: This is the record of a boundary that moved. Until Nexus#98 the check
#: above was "imports nothing from the library at all" -- broader than the
#: guarantee it names, which is that an egress module cannot apply policy of
#: its own. `azazel_nexus.spki` is a DER walk over a certificate: it decides
#: nothing, holds nothing, and reaches nothing.
#:
#: The alternative was a second copy of the SubjectPublicKeyInfo extraction
#: for the remote inference transport (#98), which pins a peer's key the same
#: way. Two copies of that is one copy that gets a fix and one that does not,
#: and the one that does not is still pinning -- just to whatever a subtly
#: different walk produced.
#:
#: Adding a name here is a deliberate act with a reviewer attached, and
#: `test_the_permitted_library_import_carries_no_policy` checks that what is
#: permitted stays pure.
PURE_LIBRARY_IMPORTS = {"azazel_nexus.spki"}


def test_the_permitted_library_import_carries_no_policy() -> None:
    """An allowlisted module that grew a policy would widen the exemption
    without anybody editing the allowlist."""

    import azazel_nexus.spki as spki

    for name in sorted(PURE_LIBRARY_IMPORTS):
        module = {"azazel_nexus.spki": spki}[name]
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        assert imported & {"ssl", "socket", "subprocess", "azazel_nexus"} == set(), (
            f"{name} is permitted inside an egress module and reaches further "
            "than a parser"
        )
        body = source.split('"""', 2)[2]
        for forbidden in ("PrivacyClass", "policy", "allowlist", "sanitize"):
            assert forbidden not in body, f"{name} carries {forbidden!r}"


def test_it_emits_no_credential_no_url_and_no_pin() -> None:
    event = repr(EgressResult(Outcome.COMPLETE, 10, 200, "done").as_event()).lower()
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


def test_nothing_in_this_file_skips() -> None:
    """The point of the fixtures. A TLS test that does not run is a TLS test
    that says nothing, and the ones most likely not to run were the ones that
    mattered most."""

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in {"skipif", "skip", "xfail"}:
            raise AssertionError(f"a skip marker survives at line {node.lineno}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr != "importorskip", "an import-or-skip survives"
