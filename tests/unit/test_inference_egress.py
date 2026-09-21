"""The second egress boundary, driven against a real TLS server (#98).

Same discipline as `test_artifact_egress.py` (#108), and for the same reason:
these are the checks that matter most, so they must not be the ones that
depend on a binary being installed. Fixed certificates are committed under
`tests/fixtures/tls/`, the pins are fixed constants in `tls/pins.py`, the
server is `ssl` from the standard library on loopback, and **nothing here
skips**. A check that runs only where some tool happens to exist is a check
that is not running where it is most needed.

No real provider, no real endpoint, no real credential, no inference. The
certificates are test-only material that signs nothing outside this suite.

What is different from the fetcher, and why:

| | fetcher | here |
| --- | --- | --- |
| client identity | optional -- a public mirror may not ask | **required** |
| direction | pulls public bytes in | pushes what the node observed out |
| a one-way handshake | is TLS, and allowed | is **not mTLS**, and refused |
"""

from __future__ import annotations

import json
import pathlib
import socket
import ssl
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "runtime" / "src"))
from azazel_nexus_runtime import inference_egress  # noqa: E402
from azazel_nexus_runtime.inference_egress import (  # noqa: E402
    InferenceRefused,
    TransportOutcome,
    send_inference,
    spki_pin,
    tls_context,
)

TLS = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "tls"
sys.path.insert(0, str(TLS.parent))
from tls.pins import PINS  # noqa: E402

LOOPBACK = "127.0.0.1"
HOSTNAME = "localhost"
FRAME = json.dumps({"observed": "scan", "count": "2-5"}, sort_keys=True).encode()
ADVICE = json.dumps({"advice": "Elevated scanning from one peer."}).encode()


def material(name: str) -> str:
    return str(TLS / name)


def client_context(*, ca="trusted-ca.crt", client="client"):
    return tls_context(
        ca_certificate=material(ca),
        client_certificate=material(f"{client}.crt"),
        client_key=material(f"{client}.key"),
    )


class Server:
    """A loopback TLS server that answers exactly how a test tells it to."""

    def __init__(
        self,
        *,
        responder,
        certificate="server",
        require_client=True,
        client_ca="trusted-ca.crt",
    ):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(
            certfile=material(f"{certificate}.crt"),
            keyfile=material(f"{certificate}.key"),
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
        self.peer_certificates = []
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
            self.peer_certificates.append(stream.getpeercert())
            stream.settimeout(5)
            request = b""
            while b"\r\n\r\n" not in request:
                piece = stream.recv(4096)
                if not piece:
                    return
                request += piece
            head, _, rest = request.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":", 1)[1])
            while len(rest) < length:
                piece = stream.recv(4096)
                if not piece:
                    break
                rest += piece
            self.requests.append((head.decode("latin-1"), rest))
            self.responder(stream, rest)
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


def answer(body=ADVICE, status=200):
    def responder(stream, frame):
        stream.sendall(
            (
                f"HTTP/1.1 {status} OK\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )
        stream.sendall(body)

    return responder


def run(server, **overrides):
    kwargs = dict(
        host=HOSTNAME,
        port=server.port,
        path="/v1/advisor/advise",
        frame=FRAME,
        expected_pin=PINS["server"],
        allowed_addresses=[LOOPBACK, "::1"],
        max_request_bytes=64 * 1024,
        max_response_bytes=64 * 1024,
        deadline_seconds=5,
        context=client_context(),
    )
    kwargs.update(overrides)
    return send_inference(**kwargs)


# -- mTLS is mutual or it is not this -------------------------------------


def test_a_context_without_a_client_identity_cannot_be_built():
    """One-way TLS is TLS. It is not mTLS, and a transport that could be
    built without a client identity is one that will be."""

    for missing in ("client_certificate", "client_key", "ca_certificate"):
        kwargs = dict(
            ca_certificate=material("trusted-ca.crt"),
            client_certificate=material("client.crt"),
            client_key=material("client.key"),
        )
        kwargs[missing] = ""
        with pytest.raises(InferenceRefused) as caught:
            tls_context(**kwargs)
        assert missing in str(caught.value)


def test_the_server_really_sees_the_client_certificate():
    """Asserted from the **server's** side. "We passed a certificate" is not
    "the peer authenticated us"."""

    server = Server(responder=answer())
    try:
        report, body = run(server)
        assert report.outcome is TransportOutcome.RECEIVED
        assert server.peer_certificates and server.peer_certificates[0], (
            "the server saw no client certificate; this was one-way TLS"
        )
    finally:
        server.close()


def test_a_server_that_demands_a_client_the_node_cannot_present_fails():
    server = Server(responder=answer(), client_ca="untrusted-ca.crt")
    try:
        report, _ = run(server)
        assert report.outcome is TransportOutcome.TLS_FAILED
    finally:
        server.close()


# -- the chain, the dates, the name, and then the pin --------------------


@pytest.mark.parametrize(
    "certificate,pin_name",
    [
        ("server-untrusted-ca", "server-untrusted-ca"),
        ("server-expired", "server-expired"),
        ("server-wrong-name", "server-wrong-name"),
    ],
    ids=["untrusted-issuer", "expired", "wrong-name"],
)
def test_a_certificate_that_fails_verification_is_refused_even_with_its_pin(
    certificate, pin_name
):
    """The pin is layered on verification, never a substitute for it.

    Each of these is given **its own correct pin**, so the only thing that
    can refuse it is the check the pin does not answer.
    """

    server = Server(responder=answer(), certificate=certificate)
    try:
        report, _ = run(server, expected_pin=PINS[pin_name])
        assert report.outcome is TransportOutcome.TLS_FAILED
    finally:
        server.close()


def test_a_verified_certificate_with_the_wrong_pin_is_refused():
    """The other direction: the chain is fine and the key is not the one this
    node was told to expect."""

    server = Server(responder=answer())
    try:
        report, _ = run(server, expected_pin=PINS["client"])
        assert report.outcome is TransportOutcome.TLS_FAILED
        assert "pinned key" in report.reason
    finally:
        server.close()


def test_the_pins_are_the_fixtures_own_keys():
    """So a fixture regenerated without its pin fails here rather than
    silently pinning to whatever was produced."""

    for name, pin in sorted(PINS.items()):
        der = ssl.PEM_cert_to_DER_cert((TLS / f"{name}.crt").read_text())
        assert spki_pin(der) == pin, name
    assert len(set(PINS.values())) == len(PINS), "two fixtures share a key"


# -- what it will not do --------------------------------------------------


def test_a_redirect_is_not_followed_and_its_target_is_not_read():
    """A transport that followed one is a transport whose provider allowlist
    is one hop wide."""

    def redirect(stream, frame):
        body = b""
        stream.sendall(
            (
                "HTTP/1.1 302 Found\r\n"
                "Location: https://elsewhere.example.test/collect\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
        )

    server = Server(responder=redirect)
    try:
        report, body = run(server)
        assert report.outcome is TransportOutcome.INTERRUPTED
        assert body == b""
        assert "elsewhere" not in report.reason, "the redirect target leaked"
    finally:
        server.close()


def test_a_name_resolving_outside_the_allowlist_is_not_contacted():
    """DNS is an attack surface, not a permission."""

    server = Server(responder=answer())
    try:
        report, _ = run(server, allowed_addresses=["203.0.113.9"])
        assert report.outcome is TransportOutcome.NOT_SENT
        assert server.requests == []
    finally:
        server.close()


def test_an_empty_allowlist_is_a_refusal_never_anything():
    server = Server(responder=answer())
    try:
        with pytest.raises(InferenceRefused):
            run(server, allowed_addresses=[])
    finally:
        server.close()


def test_a_frame_over_the_ceiling_is_refused_before_a_connection_is_opened():
    """A request refused after the handshake is a request whose size the peer
    already learned."""

    server = Server(responder=answer())
    try:
        report, _ = run(server, frame=b"x" * 5000, max_request_bytes=1024)
        assert report.outcome is TransportOutcome.NOT_SENT
        assert server.requests == [], "a connection was opened"
    finally:
        server.close()


def test_a_response_over_the_ceiling_is_stopped_and_discarded():
    server = Server(responder=answer(body=b"x" * 40000))
    try:
        report, body = run(server, max_response_bytes=1024)
        assert report.outcome is TransportOutcome.INTERRUPTED
        assert body == b"", "an over-long response was handed on anyway"
    finally:
        server.close()


def test_a_response_after_its_deadline_is_discarded_never_merged():
    def slow(stream, frame):
        import time

        time.sleep(1.5)
        stream.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    server = Server(responder=slow)
    try:
        report, body = run(server, deadline_seconds=1)
        assert report.outcome is TransportOutcome.TIMED_OUT
        assert body == b""
    finally:
        server.close()


def test_a_cancelled_request_sends_nothing_and_is_not_completed():
    server = Server(responder=answer())
    try:
        report, body = run(server, cancelled=lambda: True)
        assert report.outcome is TransportOutcome.NOT_SENT
        assert server.requests == []
        assert report.outcome.value not in {"answered", "completed", "received"}
    finally:
        server.close()


def test_a_request_cancelled_mid_response_is_not_an_answer():
    calls = []

    def cancel_after_send():
        calls.append(1)
        return len(calls) > 2

    server = Server(responder=answer(body=b"x" * 60000))
    try:
        report, body = run(
            server, cancelled=cancel_after_send, max_response_bytes=128 * 1024
        )
        assert report.outcome in {
            TransportOutcome.INTERRUPTED,
            TransportOutcome.RECEIVED,
        }
        if report.outcome is TransportOutcome.INTERRUPTED:
            assert body == b"", "a partial answer was handed on"
    finally:
        server.close()


# -- the happy path is a transport, not an answer ------------------------


def test_bytes_that_arrive_are_bytes_and_not_an_answer():
    """`RECEIVED` says bytes arrived within every bound. Whether they are
    advice is decided by the content boundary, not here."""

    server = Server(responder=answer())
    try:
        report, body = run(server)
        assert report.outcome is TransportOutcome.RECEIVED
        assert body == ADVICE
        assert report.outcome.value not in {"answered", "completed"}
    finally:
        server.close()


def test_the_frame_reaches_the_server_unaltered():
    server = Server(responder=answer())
    try:
        run(server)
        assert server.requests, "nothing arrived"
        head, sent = server.requests[0]
        assert sent == FRAME
        assert "POST /v1/advisor/advise " in head
    finally:
        server.close()


def test_no_outcome_is_named_answered_or_completed():
    """Absent vocabulary, not a guarded one."""

    names = {outcome.name for outcome in TransportOutcome}
    assert names & {"ANSWERED", "COMPLETED", "SUCCESS", "OK"} == set()


def test_a_report_carries_no_frame_no_body_and_no_credential():
    server = Server(responder=answer())
    try:
        report, _ = run(server)
        rendered = repr(report.as_event()).lower()
        for leak in ("observed", "scan", "elevated", "client.key", "://", "localhost"):
            assert leak not in rendered, leak
    finally:
        server.close()


# -- it is not the fetcher ------------------------------------------------


def test_it_shares_no_module_with_the_artifact_fetcher_but_a_parser():
    import ast

    source = pathlib.Path(inference_egress.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    library = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module
        and node.module.startswith("azazel_nexus")
    }
    assert library == {"azazel_nexus.spki"}, (
        f"the transport imports {sorted(library)}; only the pure DER walk is "
        "shared with the fetcher, and nothing that carries authority"
    )
    # Over the syntax tree, not the text: the module docstring explains the
    # separation by naming the other boundary, and a scan that could not tell
    # prose from an import would have to be silenced by whoever next writes
    # that explanation.
    runtime_imports = {
        alias.name.split(".")[-1]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[-1]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert "artifact_egress" not in runtime_imports, (
        "the transport reached into the fetcher; they are separate boundaries "
        "with separate accounts"
    )


def test_there_is_no_retry_inside_the_transport():
    """The router decides fallback once. A retry here would spend it
    silently."""

    import ast

    tree = ast.parse(pathlib.Path(inference_egress.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.While)):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    name = (
                        inner.func.attr
                        if isinstance(inner.func, ast.Attribute)
                        else getattr(inner.func, "id", "")
                    )
                    assert name not in {
                        "send_inference", "connect", "wrap_socket", "sendall"
                    }, f"line {inner.lineno}: {name} inside a loop"


def test_it_parses_no_response_content():
    """A transport that interpreted a response would be a transport deciding
    what a provider meant.

    Over the syntax tree. The docstring names `read_advisory` to say where
    that job lives, and a scan that confused the sentence with a call would
    be a scan somebody deletes.
    """

    import ast

    tree = ast.parse(
        pathlib.Path(inference_egress.__file__).read_text(encoding="utf-8")
    )
    called = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        called.add(".".join(reversed(parts)))
    assert called & {
        "json.loads", "json.load", "read_advisory", "eval", "exec", "pickle.loads"
    } == set(), f"the transport interprets a response: {sorted(called)}"
    used = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert used & {"AdvisoryText", "AdvisoryData", "Advisory"} == set()
