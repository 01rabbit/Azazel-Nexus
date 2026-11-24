"""Child for `test_mio_remote_consent_w470.py` (not collected).

`stalled <root> <expected> <where> <reached-fifo> <release-fifo>` is the real
`MioEntryService` of one process handling the completing `mio.remote.opt_in.set`
that names generation `expected`. It signals `reached` and blocks until
`release` is written, at one of two places:

  pre_check  the first read of the store made by the set handler, which is
             what entryd's early comparison uses (before it)
  before_lock  `ConsentStore._change`, after the early comparison passed and
             before the write lock is taken (before the in-lock comparison)

It then goes on and prints one JSON line: the reply or the refusal detail, and
the events this process asked its ledger to record.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import sys
import time
from types import SimpleNamespace


def _pause(reached: str, release: str) -> None:
    deadline = time.monotonic() + 30
    while True:
        try:
            fd = os.open(reached, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError:  # ENXIO: the parent is not reading yet
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


def stalled(root: str, expected: int, where: str, reached: str, release: str) -> None:
    from azazel_nexus.mio_profile import PREREQUISITES
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import mio_socket_client as client
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus_runtime.principal import Principal, PrincipalClass

    os.environ["AZAZEL_ROOT"] = root
    runtime_paths.ROOT = Path(root)
    client.pwd.getpwnam = lambda _: SimpleNamespace(pw_uid=os.getuid())
    client.grp.getgrnam = lambda _: SimpleNamespace(gr_gid=os.getgid())
    service = entry.MioEntryService()
    operator = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))
    consent = service.consent
    events: list = []
    real_record = service.router._record
    paused = {"done": False}

    def record(event, **kw):
        events.append(event.get("event_type"))
        return real_record(event, **kw)

    service.router._record = record
    if where == "pre_check":
        real_reading = consent.reading

        def reading():
            if not paused["done"] and sys._getframe(1).f_code.co_name == "_opt_in":
                paused["done"] = True
                _pause(reached, release)
            return real_reading()

        consent.reading = reading
    else:
        real_change = consent._change

        def change(*a, **kw):
            _pause(reached, release)
            return real_change(*a, **kw)

        consent._change = change
    try:
        result = {"returned": service.handle(SimpleNamespace(
            verb=entry.OPT_IN_SET_VERB, principal=operator,
            arguments={"prerequisite": list(PREREQUISITES)[-1].value,
                       "expected_generation": expected}))}
    except entry.RequestRefused as exc:
        result = {"refused": {"code": exc.refusal.value, "detail": exc.detail}}
    result["events"] = events
    print(json.dumps(result))


if __name__ == "__main__":
    stalled(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6])
