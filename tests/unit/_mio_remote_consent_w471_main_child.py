"""Child for `test_mio_remote_consent_w471.py` (not collected): the real `main()` of entryd.

Same harness as `_w467_child.py` (relative root, `ready` and `stop` files,
transport credentials), plus a log of when `recover_withdrawal` is called and
a ledger fault the parent controls through the file `fault`:

  unavailable      every ledger append fails and writes nothing
  unknown_present  the next recovery row is written and reported unknown
  unknown_absent   the next recovery row is not written and reported unknown

The fault is installed when `main()` calls the recovery, so the start-up
records before it are written normally. Removing the file ends `unavailable`.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def log(**fields) -> None:
    with open("log/main.log", "a") as handle:
        handle.write(json.dumps(fields) + "\n")


def main() -> None:
    import _w467_child as base
    from azazel_nexus.audit import AuditEntry, AuditOutcomeUnknown, AuditUnavailable
    from azazel_nexus_runtime import mio_entryd as entry

    base._REAL["open"] = open
    base._install_transport()
    real_recover = entry.MioEntryService.recover_withdrawal

    def recover(self):
        log(event="recover_withdrawal", ready_file_exists=os.path.exists("ready"))
        ledger = self.router.ledger
        real_append = ledger._append_once
        fired = {"n": 0}

        def append(event, **kw):
            try:
                mode = Path("fault").read_text().strip()
            except OSError:
                return real_append(event, **kw)
            if mode == "unavailable":
                raise AuditUnavailable("injected")
            if mode in ("unknown_present", "unknown_absent") and \
                    event.get("event_type") == "audit.late_record":
                fired["n"] += 1
                if fired["n"] > 1:
                    return real_append(event, **kw)
                if mode == "unknown_present":
                    written = real_append(event, **kw)
                    raise AuditOutcomeUnknown(
                        "injected", entry=written, path=ledger._target(),
                        absent_head=(written.sequence - 1, written.previous_hash))
                head = ledger.head()
                draft = AuditEntry(head[0] + 1, head[1], "", event)
                written = AuditEntry(draft.sequence, draft.previous_hash,
                                     draft.recomputed(), event)
                raise AuditOutcomeUnknown("injected", entry=written, path=ledger._target(),
                                          absent_head=head)
            return real_append(event, **kw)

        ledger._append_once = append
        found = real_recover(self)
        log(event="recovered", result=found)
        return found

    entry.MioEntryService.recover_withdrawal = recover
    raise SystemExit(entry.main([], stop=base._stop, ready=base._ready))


if __name__ == "__main__":
    main()
