"""Child process for `test_mio_remote_consent_process.py` (not collected).

`send <state-dir> <generation>` runs the real `RemoteInferenceService` send
decision (signed envelope, send gate, consent refusal) against a counting
transport, in this process, over a separate `ConsentStore`, and prints JSON.

`writer <root> <ready-file>` runs entryd's real `mio.remote.opt_in.set` path
for the four prerequisites; its audit record of the completing grant signals
the parent and then blocks, so the parent can kill it while the store is
pending.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def send(state_dir: str, generation: int) -> None:
    import test_mio_remoted as helpers
    from azazel_nexus_runtime.mio_remote_consent import ConsentStore

    calls: list = []
    store = ConsentStore(Path(state_dir), owner=os.geteuid())
    service = helpers._service(transport=helpers._spy_transport(calls), consent=store)
    reply = service.handle(helpers.Request(
        frame=helpers.FRAME, envelope=helpers._seal(opt_in_generation=generation)))
    print(json.dumps({"calls": len(calls), "outcome": reply.get("outcome"),
                      "refusal": reply.get("refusal"),
                      "status": store.reading().status}))


def writer(root: str, ready: str) -> None:
    from azazel_nexus.mio_profile import PREREQUISITES
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import mio_socket_client as client
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus_runtime.principal import Principal, PrincipalClass

    os.environ["AZAZEL_ROOT"] = root
    runtime_paths.ROOT = Path(root)
    client.pwd.getpwnam = lambda _: SimpleNamespace(pw_uid=os.getuid())
    client.grp.getgrnam = lambda _: SimpleNamespace(gr_gid=os.getgid())
    runtime_paths.mio_state_dir().mkdir(parents=True)
    runtime_paths.mio_state_dir().chmod(0o700)
    service = entry.MioEntryService()
    operator = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))
    real = service.router._record

    def blocking(event, **kw):
        if event.get("event_type") == "mio.remote.opt_in":
            Path(ready).write_text(str(runtime_paths.mio_state_dir()))
            time.sleep(600)
        return real(event, **kw)

    service.router._record = blocking
    for prerequisite in PREREQUISITES:
        service.handle(SimpleNamespace(
            verb=entry.OPT_IN_SET_VERB, principal=operator,
            arguments={"prerequisite": prerequisite.value}))


if __name__ == "__main__":
    if sys.argv[1] == "send":
        send(sys.argv[2], int(sys.argv[3]))
    else:
        writer(sys.argv[2], sys.argv[3])
