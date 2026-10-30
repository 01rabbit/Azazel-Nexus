"""Run as azui (runuser -u azui): what this account can and cannot reach.

Reads every UI copy; is refused every operator leaf, every daemon socket
leaf (so no daemon verb is reachable), every private store, and every write
into the UI leaves. Prints JSON; exit 1 on any unexpected outcome.
"""
import errno, json, os, socket, sys
from pathlib import Path
RUN = Path("/var/lib/azazel/run")
result, bad = {}, []

def attempt(label, fn, expect):
    try:
        fn(); got = "ok"
    except OSError as e:
        got = errno.errorcode.get(e.errno, str(e.errno))
    result[label] = got
    if got != expect and not (isinstance(expect, tuple) and got in expect):
        bad.append((label, got, expect))

from azazel_nexus import runtime_paths as rp
for name in rp.UI_COPIES:
    attempt("read ui copy " + name, lambda n=name: rp.snapshot_path(n, reader="ui").read_bytes(), "ok")
    attempt("read operator leaf " + name, lambda n=name: rp.snapshot_path(n).read_bytes(), "EACCES")
    attempt("write into ui leaf " + name,
            lambda n=name: open(rp.snapshot_path(n, reader="ui").parent / ".probe", "wb"), "EACCES")
# Every daemon socket leaf the layout declares (the change verbs live behind
# these sockets). azui cannot list run/ (0711), so the declaration names them.
from azazel_nexus.layout import LAYOUT
for spec in LAYOUT:
    path = Path(spec.path)
    if spec.mode == 0o2710:
        def connect(p=path):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.connect(str(p / "service.sock"))
            finally:
                s.close()
        attempt("connect socket leaf " + path.name, connect, "EACCES")
for private in ("/var/lib/azazel/state/audit", "/var/lib/azazel/state/commission",
                "/var/lib/azazel/state/mio", "/var/lib/azazel/secrets", "/etc/azazel/activation",
                "/etc/azazel/commissioning", "/var/lib/azazel/models", "/var/lib/azazel/lite-trust",
                "/var/lib/azazel/knowledge", "/var/lib/azazel/edge-intake", "/var/lib/azazel/edge-incidents",
                "/var/lib/azazel/incident-explain", "/var/lib/azazel/run/edge-probe"):
    attempt("list private " + private, lambda p=private: os.listdir(p), "EACCES")
attempt("write ui-read parent", lambda: open(RUN / "ui-read" / ".probe", "wb"), "EACCES")
print(json.dumps({"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(),
                  "unexpected": bad, "result": result}, indent=1))
sys.exit(1 if bad else 0)
