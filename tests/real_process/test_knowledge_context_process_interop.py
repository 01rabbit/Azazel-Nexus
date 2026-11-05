"""Nexus KnowledgeClient against the real Knowledge mTLS app in a child process.

This runs only in the isolated container runner. Its CA, keys, database and
Knowledge server process live under pytest's temporary directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import socket
import ssl
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus.spki import spki_pin
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient


def _openssl(args: list[str], cwd: Path) -> None:
    subprocess.run(
        ["openssl", *args], cwd=cwd, check=True, capture_output=True, timeout=30
    )


def _pki(root: Path) -> Path:
    root.mkdir()
    _openssl(
        ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
         "-out", "ca.pem", "-subj", "/CN=process-test-ca", "-days", "2"],
        root,
    )
    (root / "server.ext").write_text(
        "subjectAltName=DNS:knowledge.test\nextendedKeyUsage=serverAuth\n"
    )
    (root / "client.ext").write_text("extendedKeyUsage=clientAuth\n")
    for name, ext in (("server", "server.ext"), ("nexus", "client.ext")):
        _openssl(
            ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
             "-out", f"{name}.csr", "-subj", f"/CN={name}"],
            root,
        )
        _openssl(
            ["x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey",
             "ca.key", "-CAcreateserial", "-out", f"{name}.pem", "-days", "2",
             "-extfile", ext],
            root,
        )
    return root


def _ready(process: subprocess.Popen[str], timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    assert process.stdout is not None and process.stderr is not None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"Knowledge process exited rc={process.returncode}: "
                f"{process.stderr.read()[-1000:]}"
            )
        readable, _, _ = select.select([process.stdout], [], [], 0.2)
        if readable:
            return json.loads(process.stdout.readline())
    raise AssertionError("Knowledge process readiness timeout")


def test_nexus_client_interoperates_with_knowledge_mtls_process(tmp_path: Path):
    knowledge = Path(os.environ["KNOWLEDGE_TEST_SRC"]).resolve()
    server_script = knowledge / "tests/unit/_knowledge_context_mtls_server.py"
    assert server_script.is_file()
    pki = _pki(tmp_path / "pki")
    pythonpath = os.pathsep.join(
        [str(knowledge / "src"), str(knowledge / "tests/unit"),
         os.environ.get("PYTHONPATH", "")]
    )
    server = subprocess.Popen(
        [sys.executable, str(server_script), str(tmp_path / "knowledge-root"), str(pki)],
        cwd=server_script.parent,
        env={**os.environ, "PYTHONPATH": pythonpath},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    ready = None
    try:
        ready = _ready(server)
        assert ready["ready"] is True and ready["pid"] == server.pid != os.getpid()
        assert ready["host"] == "127.0.0.1"

        now = datetime.now(UTC)
        server_der = ssl.PEM_cert_to_DER_cert((pki / "server.pem").read_text())
        endpoint = ProviderRecord(
            provider_id="knowledge-process",
            host="knowledge.test",
            port=ready["port"],
            path_template="/knowledge/{model}",
            certificate_pin=spki_pin(server_der),
            client_identity="nexus-process-test",
            model_id="knowledge-v1",
            max_request_bytes=4096,
            max_response_bytes=8192,
            deadline_seconds=8,
            allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,),
        )
        public_key = bytes.fromhex(ready["public_key"])
        assert ready["key_id"] == "sha256:" + hashlib.sha256(public_key).hexdigest()
        peer = KnowledgePeer(endpoint, ("127.0.0.1",), public_key, 1)
        registry = KnowledgeRegistry(
            "sha256:" + "a" * 64,
            {endpoint.provider_id: peer},
            (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            1,
        )
        client = KnowledgeClient(
            registry=registry,
            peer_id=endpoint.provider_id,
            ca_certificate=(pki / "ca.pem").read_text(),
            identities={
                "nexus-process-test": (str(pki / "nexus.pem"), str(pki / "nexus.key"))
            },
            knowledge_context_enabled=True,
            knowledge_context_max_ttl_seconds=30,
            utc_now=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
        policy = SanitizerPolicy.from_mapping(
            {
                "version": "knowledge-process-test-1",
                "remote_default": "deny",
                "classes": {"P0-public": {"remote": "allow", "fields": ["ip"]}},
                "aliases": [],
                "redactions": ["secret"],
                "limits": {"max_bytes": 2048},
            }
        )
        response = client.request_context(
            frame={"ip": "203.0.113.7", "secret": "must-not-egress"},
            privacy_class=PrivacyClass.P0_PUBLIC,
            policy=policy,
            mission="synthetic-process-test",
            alias_key=b"process-test-only",
            deadline_s=8,
        )
        assert response.schema_version == "knowledge-context-response/v1"
        assert response.source_product == "azazel_nexus"
        assert response.authority == "advisory_only"
        assert response.provider_id == "azazel-knowledge"
        assert response.snapshot.state == "partial"
        assert response.request_id and response.correlation_id
        assert "must-not-egress" not in response.model_dump_json()
        assert server.poll() is None
    finally:
        if server.poll() is None:
            server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
            raise AssertionError("Knowledge process did not stop on SIGTERM")
        if server.stdout:
            server.stdout.close()
        if server.stderr:
            server.stderr.close()
    assert server.returncode == 0
    assert (tmp_path / "knowledge-root/data/local.db").exists()
    assert ready is not None
    with pytest.raises(OSError):
        socket.create_connection((ready["host"], ready["port"]), timeout=1).close()
