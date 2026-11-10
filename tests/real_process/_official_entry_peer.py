"""Synthetic Knowledge peer for the official-entry acceptance (U34).

A real TLS 1.2+ mTLS server on loopback. It verifies the client certificate
against the synthetic CA, counts every TCP accept / completed handshake / HTTP
request, and answers with a signed Knowledge Context envelope whose defect is
chosen by `mode`. The signature, TTL and binding checks it exercises are the
product's own (`read_signed_response`), nothing is monkeypatched.

modes: valid, bad-signature, wrong-key-id, wrong-request-id, wrong-correlation,
wrong-subject, wrong-provider, expired-envelope, expired-semantic, delay.
`delay` sleeps `delay_s` and then sends a *valid* envelope; `sent_after_delay`
records whether the late answer was actually written.
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from nacl.signing import SigningKey

from azazel_nexus.knowledge_context_adapter import (
    ENVELOPE_DOMAIN, ENVELOPE_SCHEMA, canonical_signed_payload)

PROVIDER_ID = "azazel-knowledge"


def ts(offset_s: float = 0.0) -> str:
    moment = datetime.now(UTC) + timedelta(seconds=offset_s)
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _http(status: str, body: bytes) -> bytes:
    return (f"HTTP/1.1 {status}\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n").encode("ascii") + body


class SyntheticPeer:
    def __init__(self, pki: Path, seed_hex: str, *, mode: str = "valid",
                 delay_s: float = 0.0, port: int = 0) -> None:
        self.key = SigningKey(bytes.fromhex(seed_hex))
        self.public_hex = bytes(self.key.verify_key).hex()
        self.key_id = "sha256:" + hashlib.sha256(bytes(self.key.verify_key)).hexdigest()
        self.mode = mode
        self.delay_s = delay_s
        self.accepted = 0          # TCP connections accepted
        self.handshakes = 0        # completed mTLS handshakes
        self.requests = 0          # HTTP requests fully read
        self.sent_after_delay = False
        self.answers_sent = 0      # signed answers fully written to the client
        self.request_bodies: list[bytes] = []
        self.lock = threading.Lock()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(pki / "server.pem"), str(pki / "server.key"))
        ctx.load_verify_locations(str(pki / "ca.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def counters(self) -> dict:
        with self.lock:
            return {"accepted": self.accepted, "handshakes": self.handshakes,
                    "requests": self.requests}

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with self.lock:
                self.accepted += 1
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            try:
                tls = self.ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                return
            with self.lock:
                self.handshakes += 1
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n")[1:]:
                name, _, value = line.partition(b":")
                if name.strip().lower() == b"content-length":
                    length = int(value.strip())
            while len(body) < length:
                chunk = tls.recv(65536)
                if not chunk:
                    return
                body += chunk
            with self.lock:
                self.requests += 1
                self.request_bodies.append(body)
            if self.mode == "delay":
                time.sleep(self.delay_s)
            answer = self._answer(body)
            try:
                tls.sendall(_http("200 OK", answer))
                with self.lock:
                    self.answers_sent += 1
                if self.mode == "delay":
                    self.sent_after_delay = True
            except OSError:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _answer(self, body: bytes) -> bytes:
        import azazel_fabric.knowledge_context as contract
        mode = self.mode
        request = contract.KnowledgeContextRequestV1.model_validate_json(body)
        subject = request.entities[0].model_dump(mode="json")
        if mode == "wrong-subject":
            subject = {**subject, "value": "198.51.100.77"}
        response = {
            "schema_version": contract.RESPONSE_SCHEMA_VERSION,
            "request_id": "another-request" if mode == "wrong-request-id" else request.request_id,
            "correlation_id": "another-correlation" if mode == "wrong-correlation" else request.correlation_id,
            "source_product": request.source_product,
            "source_ref": request.source_ref,
            "provider_id": "some-other-node" if mode == "wrong-provider" else PROVIDER_ID,
            "snapshot": {"ref": "snapshot:synthetic-1", "state": "partial", "as_of": ts()},
            "facts": [{
                "claim_class": "source_reported_fact", "fact_id": "fact-1",
                "subject": subject, "predicate": "listed_by",
                "value": "PRODUCER-FACT-VALUE-MUST-STAY-WITHHELD",
                "provenance": ["feed:synthetic"]}],
            "inferences": [],
            "unknowns": ["PRODUCER-UNKNOWN-PROSE"],
            "limitations": ["PRODUCER-LIMITATION-PROSE-MUST-STAY-WITHHELD"],
            "generated_at": ts(),
            "expires_at": ts(20),
            "authority": "advisory_only",
        }
        if mode == "expired-semantic":
            # Valid for the schema and the request binding (generated_at is not
            # earlier than requested_at, as_of <= generated_at < expires_at) but
            # the semantic validity window is 1 ms wide and has closed by the time
            # the signed answer is read. The envelope itself stays valid.
            requested = request.requested_at.isoformat().replace("+00:00", "Z")
            window_end = (request.requested_at + timedelta(milliseconds=1)
                          ).isoformat().replace("+00:00", "Z")
            response["generated_at"] = requested
            response["snapshot"]["as_of"] = requested
            response["expires_at"] = window_end
            time.sleep(0.05)
        typed = contract.KnowledgeContextResponseV1.model_validate(response)
        envelope = {
            "schema": ENVELOPE_SCHEMA,
            "key_id": "sha256:" + "0" * 64 if mode == "wrong-key-id" else self.key_id,
            "issued_at": ts(), "expires_at": ts(25),
            "payload": json.loads(contract.canonical_knowledge_context_bytes(typed)),
        }
        if mode == "expired-envelope":
            envelope["issued_at"], envelope["expires_at"] = ts(-120), ts(-60)
        canonical = canonical_signed_payload(envelope)
        signature = self.key.sign(ENVELOPE_DOMAIN + canonical).signature
        if mode == "bad-signature":
            signature = b"x" * 64
        return signature + canonical

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2)
