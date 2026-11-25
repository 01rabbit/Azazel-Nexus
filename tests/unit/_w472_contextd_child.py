"""Child process for test_w472_contextd_recovery: the real `main()` of the Knowledge Context broker.

Run with cwd = a run directory and AZAZEL_ROOT=r. The file `stopat` (cwd), read
at each hook, names where the process kills itself with SIGKILL:

  a  inside the peer stand-in, before it records its call (the call has not happened)
  b  after the stand-in returned, immediately before the result row is appended
  c  right after the `commissioning` row was written
  r  right after a recovery row (`restart_unconfirmed`) was written

Every call that reaches the stand-in is appended and fsync'd to `log/calls.log`
(observer side, outside the product's ledger). Ledger faults come from
`_w467_child._install_faults` through `ctl.json`.
"""
from __future__ import annotations

import json
import os
import pathlib
import signal
import sys
import time
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def mode() -> str:
    try:
        with open("stopat") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def die() -> None:
    os.kill(os.getpid(), signal.SIGKILL)


def record_call() -> None:
    fd = os.open("log/calls.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (json.dumps({"pid": os.getpid(), "t": time.time()}) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def main() -> None:
    import _w467_child as base

    base._REAL["open"] = open
    base._install_faults("knowledge-contextd")
    base._install_transport()
    from azazel_nexus_runtime import knowledge_context_config as cfg
    from azazel_nexus_runtime import knowledge_contextd as kc
    from azazel_nexus_runtime.chain_guard import ChainGuard
    from stop_helpers import granted_marker
    from test_knowledge_context_observation_gate import write_rule
    from test_knowledge_contextd import _policy

    cfg._OWNER = os.getuid()
    if not pathlib.Path("r/etc/azazel/knowledge-context/observation-query.json").exists() \
            and not os.path.exists("no-rule"):
        write_rule(pathlib.Path("r"), 60)

    real = ChainGuard.append

    def append(self, event, *, performed=False):
        kind = event.get("event_type")
        if mode() == "b" and kind == "knowledge.context.completed" \
                and event.get("outcome") == "verified_advisory":
            die()
        result = real(self, event, performed=performed)
        if mode() == "c" and kind == "knowledge.context.commissioning":
            die()
        if mode() == "r" and event.get("reason_code") == kc.RESTART_UNCONFIRMED:
            die()
        return result

    ChainGuard.append = append

    from azazel_nexus.audit import AuditLedger
    real_iter = AuditLedger.__iter__

    def counted_iter(self):
        # One line in `reads.log` for every whole read of a ledger.
        with open("reads.log", "a") as handle:
            handle.write("read\n")
        return real_iter(self)

    AuditLedger.__iter__ = counted_iter
    class Peer:
        def request_context(self, **kw):
            if mode() == "a":
                die()
            record_call()
            return {"authority": "advisory_only"}

    commissioning = SimpleNamespace(status="commissioned", reason_code=None, registry_version=None,
                                    client=Peer(), policy=_policy(), mission="lab",
                                    alias_key=b"x" * 32)
    kc.load_commissioning = lambda: commissioning
    base_broker = kc.KnowledgeContextBroker

    class Broker(base_broker):
        def __init__(self, **kwargs):
            super().__init__(grant_marker=granted_marker, **kwargs)

    kc.KnowledgeContextBroker = Broker
    raise SystemExit(kc.main([], stop=base._stop, ready=base._ready))


if __name__ == "__main__":
    main()
