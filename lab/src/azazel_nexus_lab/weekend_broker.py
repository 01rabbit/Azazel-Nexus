"""Synthetic commissioned broker process for loopback-only integration tests."""
from __future__ import annotations

import json
import os
import signal
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
import argparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ui-network', action='store_true', help='reserved internal bridge; no default route')
for name in ('root', 'pki', 'port', 'public_hex', 'pin'):
    parser.add_argument(name)
args = parser.parse_args()

from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus_runtime.knowledge_contextd import KnowledgeContextBroker
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.runtime_paths import socket_path
from azazel_nexus_runtime.serve import serve_forever
from azazel_nexus_runtime.knowledge_contextd import REGISTRY as VERBS
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient


from azazel_nexus_lab.weekend_process import require_container
require_container(root=False, ui_network=args.ui_network)
root, pki, port, public_hex, pin = (getattr(args, name) for name in ('root', 'pki', 'port', 'public_hex', 'pin'))
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
broker = KnowledgeContextBroker(
    client=client, policy=policy, mission="synthetic-process-test",
    alias_key=b"p" * 32, enabled=True,
)
stopping = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stopping.set())


def ready():
    print(json.dumps({"ready": True, "pid": os.getpid()}), flush=True)


def counted(request):
    # Count actual AF_UNIX handler ingress, not a caller's intended request.
    with (Path(root) / 'var/lib/azazel/state/knowledge-context/broker-ingress.jsonl').open('a') as log:
        log.write(json.dumps({'verb': request.verb.name}) + '\n')
    return broker.handle(request)


sys.exit(serve_forever(
    path=socket_path("knowledge-context"), registry=VERBS,
    policy=PrincipalPolicy.resolve(
        operator_group="azknowledge-context-client", service_accounts=("azmio",)),
    audit=lambda event: None, handler=counted, stop=stopping.is_set,
    ready=ready,
))
