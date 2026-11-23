"""Child for `test_mio_remote_consent_w465_baseline.py` (not collected).

`hold <state-dir> <generation> <reached-fifo> <release-fifo>` runs the real
`RemoteInferenceService.handle`. Inside the send gate, right after the
generation is read (`ConsentStore._after_send_read`), it signals `reached`
and blocks until `release` is written. Then the handle proceeds to the
counting transport. Prints JSON.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def hold(state_dir: str, generation: int, reached: str, release: str) -> None:
    import test_mio_remoted as helpers
    from azazel_nexus_runtime.mio_remote_consent import ConsentStore

    calls: list = []
    store = ConsentStore(Path(state_dir), owner=os.geteuid())

    def seam() -> None:
        deadline = time.monotonic() + 30
        while True:  # a bounded wait for the parent to read the notice
            try:
                fd = os.open(reached, os.O_WRONLY | os.O_NONBLOCK)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.01)
        os.write(fd, b"1")
        os.close(fd)
        fd = os.open(release, os.O_RDONLY | os.O_NONBLOCK)
        try:
            ready, _, _ = select.select([fd], [], [], 30)
            if not ready or os.read(fd, 1) != b"1":
                raise RuntimeError("no release from the parent")
        finally:
            os.close(fd)

    store._after_send_read = seam
    service = helpers._service(transport=helpers._spy_transport(calls), consent=store)
    reply = service.handle(helpers.Request(
        frame=helpers.FRAME, envelope=helpers._seal(opt_in_generation=generation)))
    print(json.dumps({"calls": len(calls), "outcome": reply.get("outcome"),
                      "refusal": reply.get("refusal"),
                      "status": store.reading().status}))


def faultset(root: str, ready: str, mode: str) -> None:
    """entryd's real `set` path, in this process, with faults injected on the
    completing set. Writes the reply (JSON) to `ready` and parks, so the parent
    can SIGKILL it after the reply and before anything else happens.

    mode `confirm_fails`: confirm publishes N+1 then fails (fsync), the
    narrowing fails, and the re-read hits EIO.
    mode `unsettled`: confirm succeeds and the seal is removed, then the
    read back hits EIO and both closing writes (withdraw, re-seal) fail (the
    reply is `unsettled`).
    """
    import time
    from types import SimpleNamespace

    from azazel_nexus.mio_profile import PREREQUISITES
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import mio_socket_client as client
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus_runtime.mio_remote_consent import _UNAVAILABLE, ConsentRefused
    from azazel_nexus_runtime.principal import Principal, PrincipalClass

    os.environ["AZAZEL_ROOT"] = root
    runtime_paths.ROOT = Path(root)
    client.pwd.getpwnam = lambda _: SimpleNamespace(pw_uid=os.getuid())
    client.grp.getgrnam = lambda _: SimpleNamespace(gr_gid=os.getgid())
    runtime_paths.mio_state_dir().mkdir(parents=True)
    runtime_paths.mio_state_dir().chmod(0o700)
    service = entry.MioEntryService()
    operator = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))

    def set_one(prerequisite):
        return service.handle(SimpleNamespace(
            verb=entry.OPT_IN_SET_VERB, principal=operator,
            arguments={"prerequisite": prerequisite.value}))

    for prerequisite in list(PREREQUISITES)[:-1]:
        set_one(prerequisite)
    consent = service.consent
    flag = {"eio": False}
    real_reading, real_confirm, real_unseal = consent.reading, consent.confirm, consent.unseal

    def withdraw(*a, **kw):
        raise ConsentRefused("fixture: withdraw busy")

    def reading():
        return _UNAVAILABLE if flag["eio"] else real_reading()

    def confirm(generation, **kw):
        record = real_confirm(generation, **kw)
        if mode == "confirm_fails":
            flag["eio"] = True
            raise OSError(5, "fixture: fsync after rename")
        return record

    seals = {"n": 0}
    real_seal = consent.seal

    def seal(generation):
        seals["n"] += 1
        if mode == "unsettled" and seals["n"] > 1:
            raise OSError(5, "fixture: seal write")
        return real_seal(generation)

    def unseal():
        real_unseal()
        flag["eio"] = True

    consent.withdraw, consent.reading, consent.confirm = withdraw, reading, confirm
    consent.seal = seal
    if mode == "unsettled":
        consent.unseal = unseal
    try:
        result = {"returned": set_one(list(PREREQUISITES)[-1])}
    except entry.RequestRefused as exc:
        result = {"refused": str(exc.args)}
    result["state"] = str(runtime_paths.mio_state_dir())
    tmp = Path(ready + ".tmp")
    tmp.write_text(json.dumps(result))
    os.replace(tmp, ready)
    time.sleep(600)


if __name__ == "__main__":
    if sys.argv[1] == "hold":
        hold(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
    else:
        faultset(sys.argv[2], sys.argv[3], sys.argv[4])
