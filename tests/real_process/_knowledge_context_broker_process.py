"""Synthetic commissioned broker process for loopback-only integration tests."""
from __future__ import annotations

import json
import signal
import sys
import threading
import time
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus_runtime.knowledge_contextd import KnowledgeContextBroker
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.runtime_paths import socket_path
from azazel_nexus_runtime.serve import serve_forever
from azazel_nexus_runtime.knowledge_contextd import REGISTRY as VERBS
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient


root, pki, port, public_hex, pin = sys.argv[1:]
now = datetime.now(UTC)
endpoint = ProviderRecord(
    provider_id="azazel-knowledge", host="knowledge.test", port=int(port),
    path_template="/knowledge/{model}", certificate_pin=pin,
    client_identity="nexus-process-test", model_id="knowledge-v1",
    max_request_bytes=4096, max_response_bytes=8192, deadline_seconds=8,
    allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,),
)
peer = KnowledgePeer(endpoint, ("127.0.0.1",), bytes.fromhex(public_hex), 1)
registry = KnowledgeRegistry(
    "sha256:" + "a" * 64, {endpoint.provider_id: peer},
    (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
    (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"), 1,
)
client = KnowledgeClient(
    registry=registry, peer_id=endpoint.provider_id,
    ca_certificate=str(Path(pki) / "ca.pem"),
    identities={"nexus-process-test": (str(Path(pki) / "nexus.pem"),
                                       str(Path(pki) / "nexus.key"))},
    knowledge_context_enabled=True, knowledge_context_max_ttl_seconds=30,
    utc_now=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"),
)
policy = SanitizerPolicy.from_mapping({
    "version": "synthetic-process-test-v1", "remote_default": "deny",
    "classes": {"P0-public": {"remote": "allow", "fields": ["question", "context"]}},
    "aliases": [], "redactions": ["secret"], "limits": {"max_bytes": 2048},
})
# Optional acceptance-test hooks (all off unless the test sets them):
#   U29_EXCHANGE_DIR  record each real exchange (request body, raw envelope)
#   U29_REPLAY_FILE   while this file exists, the network edge (_post_path) returns
#                     its bytes instead of the producer's answer, so a previously
#                     captured envelope is offered for a *new* request. Everything
#                     after the network edge (signature, TTL, binding) is product code.
#   U29_AUDIT_FILE    append broker audit events (incl. kernel-derived principal
#                     fields on refusals) as JSON lines
_exchange_dir = os.environ.get("U29_EXCHANGE_DIR")
_replay_file = os.environ.get("U29_REPLAY_FILE")
_audit_file = os.environ.get("U29_AUDIT_FILE")
if _exchange_dir or _replay_file:
    _original_post = client._post_path
    _counter = [0]

    def _post_path(peer, path, body, deadline):
        if _replay_file and Path(_replay_file).exists():
            raw = Path(_replay_file).read_bytes()
            kind = "replayed"
        else:
            raw = _original_post(peer, path, body, deadline)
            kind = "live"
        if _exchange_dir:
            _counter[0] += 1
            stamp = f"{os.getpid()}-{time.time_ns()}-{_counter[0]}"
            base = Path(_exchange_dir)
            (base / f"{stamp}.{kind}.request").write_bytes(body)
            (base / f"{stamp}.{kind}.envelope").write_bytes(raw)
        return raw

    client._post_path = _post_path


def _audit(event):
    if _audit_file:
        with open(_audit_file, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")


broker = KnowledgeContextBroker(
    client=client, policy=policy, mission="synthetic-process-test",
    alias_key=b"p" * 32, enabled=True, audit=_audit,
)
stopping = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stopping.set())


def ready():
    print(json.dumps({"ready": True}), flush=True)


sys.exit(serve_forever(
    path=socket_path("knowledge-context"), registry=VERBS,
    policy=PrincipalPolicy.resolve(
        operator_group="azknowledge-context-client", service_accounts=("azmio",)),
    audit=_audit, handler=broker.handle, stop=stopping.is_set,
    ready=ready,
))
