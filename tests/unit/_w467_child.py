"""Child process for test_w467_audit_unavailable: one daemon's real `main()` with ledger faults.

Run as `python _w467_child.py <daemon>` with cwd = a run directory and
AZAZEL_ROOT=r (a relative root, so unix socket paths stay short and every file
stays under the run directory). The parent controls faults through
`ctl.json`; this process never reads anything else from the parent.

Fault injection replaces `os.open`, `os.fsync` and `pathlib.Path.open` for
files named `*.jsonl` under the daemon's ledger roots only. `fsync` is never
run when it is made to fail, so the line the append wrote stays in the file.
SO_PEERCRED does not exist on macOS, so the peer credentials are patched; the
transport, serve loop, registry and handler are the real ones.
"""

from __future__ import annotations

import errno
import json
import os
import pathlib
import sys
import time
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

ROOTS = {
    "auditd": ["r/var/lib/azazel/state/audit"],
    "mio-entryd": ["r/var/lib/azazel/state/mio"],
    "mio-locald": ["r/var/lib/azazel/mio"],
    "mio-referenced": ["r/var/lib/azazel/state/mio-reference"],
    "mio-contextobsd": ["r/var/lib/azazel/state/mio-contextobs"],
    "knowledge-contextd": ["r/var/lib/azazel/state/knowledge-context"],
}

STATE = {"seq": None, "mode": "off", "n": 0, "opens": 0, "fsyncs": 0, "fired": False}
_REAL: dict = {}


def _log(name: str, **fields) -> None:
    with _REAL["open"]("log/" + name, "a") as handle:
        handle.write(json.dumps({"t": round(time.monotonic(), 4), **fields}) + "\n")


def op(kind: str, **fields) -> None:
    """One operation (a peer call, a send) the daemon performed."""
    _log("ops.log", op=kind, **fields)


def _refresh() -> None:
    try:
        with _REAL["open"]("ctl.json") as handle:
            control = json.load(handle)
    except (OSError, ValueError):
        return
    if control.get("seq") != STATE["seq"]:
        STATE.update(seq=control.get("seq"), mode=control.get("mode", "off"),
                     n=int(control.get("n", 1)), opens=0, fsyncs=0, fired=False)


def _install_faults(daemon: str) -> None:
    roots = [os.path.abspath(path) for path in ROOTS[daemon]]
    real_os_open, real_fsync, real_path_open = os.open, os.fsync, pathlib.Path.open
    _REAL.update(open=open, os_open=real_os_open, fsync=real_fsync)

    def is_ledger(path) -> bool:
        try:
            text = os.path.abspath(os.fsdecode(path))
        except (TypeError, ValueError):
            return False
        return text.endswith(".jsonl") and any(text.startswith(root + os.sep) for root in roots)

    def ledger_inodes() -> dict:
        found = {}
        for root in roots:
            for current, _, names in os.walk(root):
                for name in names:
                    if name.endswith(".jsonl"):
                        try:
                            info = os.stat(os.path.join(current, name))
                        except OSError:
                            continue
                        found[(info.st_dev, info.st_ino)] = os.path.join(current, name)
        return found

    def last_event(path) -> str | None:
        """The event type of the line a failed sync was for (the file's last line)."""
        try:
            with _REAL["open"](path, "rb") as handle:
                lines = [line for line in handle.read().splitlines() if line.strip()]
            return json.loads(lines[-1])["event"].get("event_type")
        except (OSError, ValueError, KeyError, IndexError):
            return None

    def eio(where: str, path, **extra) -> OSError:
        _log("faults.log", fault=where, path=os.path.basename(os.fsdecode(path)) if path else None,
             mode=STATE["mode"], opens=STATE["opens"], fsyncs=STATE["fsyncs"], **extra)
        return OSError(errno.EIO, "injected EIO " + where)

    def check_open(path, write: bool) -> None:
        if not is_ledger(path):
            return
        _refresh()
        mode = STATE["mode"]
        if mode == "persist":
            raise eio("open" if write else "read-open", path)
        if write:
            STATE["opens"] += 1
            _log("faults.log", seen="write-open", n=STATE["opens"], mode=mode)
            if mode == "pre" and not STATE["fired"] and STATE["opens"] == STATE["n"]:
                STATE["fired"] = True
                raise eio("open", path)

    def hooked_os_open(path, flags, mode=0o777, *args, **kwargs):
        if isinstance(path, (str, bytes, os.PathLike)):
            check_open(path, bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT)))
        return real_os_open(path, flags, mode, *args, **kwargs)

    def hooked_path_open(self, mode="r", *args, **kwargs):
        check_open(self, any(flag in mode for flag in "aw+x"))
        return real_path_open(self, mode, *args, **kwargs)

    def hooked_fsync(fd):
        number = fd if isinstance(fd, int) else fd.fileno()
        located = None
        try:
            info = os.fstat(number)
            located = ledger_inodes().get((info.st_dev, info.st_ino))
        except OSError:
            pass
        ledger = located is not None
        if ledger:
            _refresh()
            STATE["fsyncs"] += 1
            _log("faults.log", seen="ledger-fsync", n=STATE["fsyncs"], mode=STATE["mode"])
            if STATE["mode"] == "persist" or (
                    STATE["mode"] == "fsync" and not STATE["fired"]
                    and STATE["fsyncs"] == STATE["n"]):
                STATE["fired"] = True
                raise eio("fsync", None, event=last_event(located))
        return real_fsync(fd)

    os.open, os.fsync, pathlib.Path.open = hooked_os_open, hooked_fsync, hooked_path_open


def _install_transport() -> None:
    import grp

    from azazel_nexus_runtime import principal, transport

    transport.peer_credentials = lambda connection: (os.getppid(), os.getuid(), os.getgid())
    transport.peer_supplementary_groups = lambda connection: ()
    grp.getgrnam = lambda name: SimpleNamespace(gr_gid=os.getgid(), gr_name=name)

    class Everyone(principal.PrincipalPolicy):
        def classify(self, uid, gid, pid, supplementary_groups=()):
            return principal.Principal(uid, gid, pid, frozenset({
                principal.PrincipalClass.OPERATOR, principal.PrincipalClass.SERVICE}))

    policy = Everyone(operator_gid=os.getgid(), service_uids=frozenset(), daemon_uids=frozenset())
    principal.PrincipalPolicy.resolve = classmethod(lambda cls, **kwargs: policy)


def _stop() -> bool:
    return os.path.exists("stop")


def _ready() -> None:
    with _REAL["open"]("ready", "w") as handle:
        handle.write(str(os.getpid()))


def _entryd() -> None:
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime.mio_socket_client import fast_assessment_degraded

    original = entry.MioEntryService.__init__

    def init(self, *args, **kwargs):
        original(self, *args, **kwargs)

        def assess(frame, *, deadline_s, **kw):
            op("peer-call:locald.assess")
            return fast_assessment_degraded("unavailable")

        def reference(frame, *, deadline_at):
            op("peer-call:referenced.reference")
            return None, "reference_service_unavailable"

        def observe(*, deadline_s=0.05):
            # A capability change on demand: the periodic tick records it.
            return "local_not_admitted" if os.path.exists("flip") else "local_unavailable"

        self.local.assess, self.reference.reference = assess, reference
        self.local.observe = observe

    entry.MioEntryService.__init__ = init
    raise SystemExit(entry.main([], stop=_stop, ready=_ready))


def _knowledge() -> None:
    from azazel_nexus_runtime import knowledge_context_config as cfg
    from azazel_nexus_runtime import knowledge_contextd as kc
    from stop_helpers import granted_marker
    from test_knowledge_context_observation_gate import write_rule
    from test_knowledge_contextd import _policy

    cfg._OWNER = os.getuid()
    write_rule(pathlib.Path("r"), 60)

    class Peer:
        def request_context(self, **kw):
            op("send:knowledge-peer.request_context")
            return {"authority": "advisory_only"}

    commissioning = SimpleNamespace(status="commissioned", reason_code=None,
                                    registry_version=None, client=Peer(),
                                    policy=_policy(), mission="lab", alias_key=b"x" * 32)
    kc.load_commissioning = lambda: commissioning
    base = kc.KnowledgeContextBroker

    class Broker(base):
        def __init__(self, **kwargs):
            super().__init__(grant_marker=granted_marker, **kwargs)

    kc.KnowledgeContextBroker = Broker
    raise SystemExit(kc.main([], stop=_stop, ready=_ready))


def _contextobsd() -> None:
    from _technique_fixture import make_response

    from azazel_nexus_runtime import mio_contextobsd as obs

    def request_context(query, *, deadline_s):
        op("send:broker.request_context")
        return make_response(["T1059", "T1059.001"])

    obs.request_context = request_context
    raise SystemExit(obs.main([], stop=_stop, ready=_ready))


def main(daemon: str) -> None:
    _install_faults(daemon)
    _install_transport()
    if daemon == "mio-entryd":
        _entryd()
    elif daemon == "knowledge-contextd":
        _knowledge()
    elif daemon == "mio-contextobsd":
        _contextobsd()
    else:
        module = {"auditd": "auditd", "mio-locald": "mio_locald",
                  "mio-referenced": "mio_referenced"}[daemon]
        import importlib

        runtime = importlib.import_module("azazel_nexus_runtime." + module)
        raise SystemExit(runtime.main([], stop=_stop, ready=_ready))


if __name__ == "__main__":
    main(sys.argv[1])
