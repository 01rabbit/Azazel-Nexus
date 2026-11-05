"""Run the normal locald service handler for broker composition tests."""
from __future__ import annotations

import json
import signal
import sys
import threading

from azazel_nexus_runtime.mio_locald import LocalRuntimeService, REGISTRY, SOCKET_NAME
from azazel_nexus_runtime.principal import PrincipalPolicy
from azazel_nexus_runtime.runtime_paths import socket_path
from azazel_nexus_runtime.serve import serve_forever


service = LocalRuntimeService()
# The focused interop request gives the loopback server a bounded but generous
# test budget; production remains capped at KNOWLEDGE_MAX_S (250 ms).
import azazel_nexus_runtime.mio_locald as locald
locald.KNOWLEDGE_MAX_S = 8.0
stopping = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stopping.set())


def ready():
    print(json.dumps({"ready": True}), flush=True)


sys.exit(serve_forever(
    path=socket_path(SOCKET_NAME), registry=REGISTRY,
    policy=PrincipalPolicy.resolve(service_accounts=("azmioentry",)),
    audit=lambda event: None, handler=service.handle, stop=stopping.is_set,
    ready=ready,
))
