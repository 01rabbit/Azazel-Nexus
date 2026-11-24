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
import stat
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
    from azazel_nexus_runtime.mio_remote_consent import ConsentRefused
    from azazel_nexus_runtime.principal import Principal, PrincipalClass

    os.environ["AZAZEL_ROOT"] = root
    runtime_paths.ROOT = Path(root)
    client.pwd.getpwnam = lambda _: SimpleNamespace(pw_uid=os.getuid())
    client.grp.getgrnam = lambda _: SimpleNamespace(gr_gid=os.getgid())
    runtime_paths.mio_state_dir().mkdir(parents=True)
    runtime_paths.mio_state_dir().chmod(0o700)
    service = entry.MioEntryService()
    operator = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))

    sets_done = [0]

    def set_one(prerequisite):
        # Each set names the generation the previous one made (#470).
        expected, sets_done[0] = sets_done[0], sets_done[0] + 1
        return service.handle(SimpleNamespace(
            verb=entry.OPT_IN_SET_VERB, principal=operator,
            arguments={"prerequisite": prerequisite.value,
                       "expected_generation": expected}))

    for prerequisite in list(PREREQUISITES)[:-1]:
        set_one(prerequisite)
    consent = service.consent
    flag = {"eio": False}
    hits = {"confirm_dir_fsync": 0, "withdraw": 0, "read_eio": 0, "open_read_eio": 0}
    real_read_at, real_confirm, real_unseal = consent._read_at, consent.confirm, consent.unseal
    real_fsync, real_seal = os.fsync, consent.seal
    armed = {"dir": False}

    def withdraw(*a, **kw):
        hits["withdraw"] += 1
        raise ConsentRefused("fixture: withdraw busy")

    def read_at(leaf):
        # EIO only for the reads `reading()` makes (a write's read-back works).
        if flag["eio"] and sys._getframe(1).f_code.co_name == "reading":
            hits["read_eio"] += 1
            caller = sys._getframe(1).f_back  # the read-back made directly by `_open_grant`
            if caller is not None and caller.f_code.co_name == "_open_grant":
                hits["open_read_eio"] += 1
            raise OSError(5, "fixture: EIO reading the record")
        return real_read_at(leaf)

    def fsync(fd):
        # The real `confirm` renames N+1 into place; its directory fsync then
        # fails with EIO without running.
        if armed["dir"] and stat.S_ISDIR(os.fstat(fd).st_mode):
            armed["dir"] = False
            flag["eio"] = True
            hits["confirm_dir_fsync"] += 1
            raise OSError(5, "fixture: directory fsync after rename")
        real_fsync(fd)

    def confirm(generation, **kw):
        armed["dir"] = mode == "confirm_fails"
        try:
            return real_confirm(generation, **kw)
        finally:
            armed["dir"] = False

    seals = {"n": 0}

    def seal(generation):
        seals["n"] += 1
        if mode == "unsettled" and seals["n"] > 1:
            raise OSError(5, "fixture: seal write")
        return real_seal(generation)

    def unseal():
        real_unseal()
        flag["eio"] = True

    os.fsync = fsync
    consent.withdraw, consent._read_at, consent.confirm = withdraw, read_at, confirm
    consent.seal = seal
    if mode == "unsettled":
        consent.unseal = unseal
    try:
        result = {"returned": set_one(list(PREREQUISITES)[-1])}
    except entry.RequestRefused as exc:
        result = {"refused": str(exc.args)}
    result["state"] = str(runtime_paths.mio_state_dir())
    result["hits"] = hits
    tmp = Path(ready + ".tmp")
    tmp.write_text(json.dumps(result))
    os.replace(tmp, ready)
    time.sleep(600)


def combo(root: str, fifo: str, mode: str, sock_fd: int = -1) -> None:
    """The completing `set` of entryd with the failure placed at the real
    `os.fsync` (the call is not run and raises EIO), per combination:

    e1: the directory fsync after `seal(N+1)`'s rename fails.
    e2: confirm's directory fsync fails after N+1 is published, and the
        withdrawal's writes fail too (the seal stays).
    e3: `unseal`'s directory fsync fails, the withdrawal's writes fail, the
        re-seal works.
    e4: from `unseal` on every fsync fails (withdraw and re-seal fail).
    e5: unseal and the read back succeed inside `_open_grant`; the process then
        writes `parked` to the FIFO and blocks inside the handler, before the
        reply frame is built (the parent SIGKILLs it and expects EOF on the
        socket it holds).

    For e1-e4 the reply (JSON) goes to the FIFO and the process parks.
    """
    from types import SimpleNamespace

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

    sets_done = [0]

    def set_one(prerequisite):
        # Each set names the generation the previous one made (#470).
        expected, sets_done[0] = sets_done[0], sets_done[0] + 1
        return service.handle(SimpleNamespace(
            verb=entry.OPT_IN_SET_VERB, principal=operator,
            arguments={"prerequisite": prerequisite.value,
                       "expected_generation": expected}))

    for prerequisite in list(PREREQUISITES)[:-1]:
        set_one(prerequisite)

    def post(payload: dict) -> None:
        fd = os.open(fifo, os.O_WRONLY)
        os.write(fd, json.dumps(payload).encode() + b"\n")
        os.close(fd)

    consent = service.consent
    real = {n: getattr(consent, n) for n in ("seal", "confirm", "unseal", "withdraw", "reading")}
    real_fsync = os.fsync
    fail = {"mode": None, "op": None}  # mode: None | "dir" | "all"
    seen = {"opens": None, "unsealed": False, "seals": 0}
    hits: list = []  # [operation, "dir"|"file"] of each injected fsync failure
    calls: list = []  # consent operations in call order

    def fsync(fd):
        is_dir = stat.S_ISDIR(os.fstat(fd).st_mode)
        if fail["mode"] == "all" or (fail["mode"] == "dir" and is_dir):
            hits.append([fail["op"], "dir" if is_dir else "file"])
            raise OSError(5, "fixture: fsync failed without running")
        real_fsync(fd)

    def during(mode_, op, call, *a, **kw):
        fail["mode"], fail["op"] = mode_, op
        try:
            return call(*a, **kw)
        finally:
            fail["mode"] = None

    def seal(generation):
        seen["seals"] += 1
        seen["opens"] = generation
        calls.append("seal")
        if mode == "e4" and seen["seals"] > 1:
            fail["op"] = "seal"
        if mode == "e1" and seen["seals"] == 1:
            return during("dir", "seal", real["seal"], generation)
        return real["seal"](generation)

    def confirm(generation, **kw):
        calls.append("confirm")
        if mode == "e2":
            return during("dir", "confirm", real["confirm"], generation, **kw)
        return real["confirm"](generation, **kw)

    def unseal():
        calls.append("unseal")
        if mode == "e3":
            try:
                return during("dir", "unseal", real["unseal"])
            finally:
                seen["unsealed"] = True
        if mode == "e4":
            fail["mode"], fail["op"] = "all", "unseal"  # stays: nothing is durable from here
            seen["unsealed"] = True
            return real["unseal"]()
        real["unseal"]()
        seen["unsealed"] = True

    def withdraw(*a, **kw):
        calls.append("withdraw")
        if mode == "e4":
            fail["op"] = "withdraw"
        if mode in ("e2", "e3"):
            return during("all", "withdraw", real["withdraw"], *a, **kw)
        return real["withdraw"](*a, **kw)

    def reading():
        value = real["reading"]()
        if (mode == "e5" and seen["unsealed"]
                and sys._getframe(1).f_code.co_name == "_open_grant"):
            post({"parked": True, "opens": seen["opens"],
                  "state": str(runtime_paths.mio_state_dir()),
                  "hits": hits, "calls": calls,
                  "read_back": {"generation": value.generation,
                                "status": value.status, "permits": value.permits}})
            time.sleep(600)
        return value

    os.fsync = fsync
    consent.seal, consent.confirm, consent.unseal = seal, confirm, unseal
    consent.withdraw, consent.reading = withdraw, reading
    if mode == "e5":
        # The last set goes through the real socket engine (as `serve_once`
        # does); the parent holds the other end and sees EOF when this process
        # is killed before a reply frame is written.
        import socket as _socket

        from azazel_nexus_runtime import transport
        from azazel_nexus_runtime.principal import PrincipalPolicy

        transport.peer_credentials = lambda c: (1, os.getuid(), os.getgid())
        transport.peer_supplementary_groups = lambda c: ()
        engine = transport.SocketServer(
            registry=entry.REGISTRY, policy=PrincipalPolicy(os.getgid(), frozenset()),
            audit=service.record_refusal)
        engine.serve_connection(_socket.socket(fileno=sock_fd), service.handle)
        raise SystemExit("e5: the handler returned before the park")
    try:
        result = {"returned": set_one(list(PREREQUISITES)[-1])}
    except entry.RequestRefused as exc:
        result = {"refused": str(exc.args)}
    fail["mode"] = None
    result.update(state=str(runtime_paths.mio_state_dir()), opens=seen["opens"],
                  hits=hits, calls=calls)
    post(result)
    time.sleep(600)


if __name__ == "__main__":
    if sys.argv[1] == "hold":
        hold(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
    elif sys.argv[1] == "combo":
        combo(sys.argv[2], sys.argv[3], sys.argv[4],
              int(sys.argv[5]) if len(sys.argv) > 5 else -1)
    else:
        faultset(sys.argv[2], sys.argv[3], sys.argv[4])
