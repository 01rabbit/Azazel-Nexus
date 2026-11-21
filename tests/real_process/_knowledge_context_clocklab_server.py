"""Test-only wrapper: Knowledge's own mTLS server process, v1 or lab-v2 configured.

Knowledge's `_knowledge_context_mtls_server.main` is run unmodified. This
wrapper only supplies the transport configuration a deployment would: in `v2`
mode the explicit lab ClockContract and Knowledge's real `LocalClockHealth`
reading a root-owned health file; in `v1` mode nothing (the shipped default).

Usage: _knowledge_context_clocklab_server.py <root> <pki> <v1|v2> <health_path>
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

root, pki, mode, health_path = sys.argv[1:]
import _knowledge_context_mtls_server as server  # noqa: E402  (PYTHONPATH set by the test)

if mode == "v2":
    from azazel_fabric.knowledge_context_clocklab import ClockContract
    from azazel_knowledge.api.knowledge_clock_health import LocalClockHealth

    _config = server.KnowledgeContextTransportConfig

    def _with_clock(**kwargs):
        return _config(**kwargs, clock_contract=ClockContract(5000),
                       clock_health=LocalClockHealth(health_path))

    server.KnowledgeContextTransportConfig = _with_clock
elif mode != "v1":
    raise SystemExit("mode must be v1 or v2")
sys.exit(server.main(Path(root), Path(pki)))
