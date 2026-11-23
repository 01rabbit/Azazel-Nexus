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
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def hold(state_dir: str, generation: int, reached: str, release: str) -> None:
    import test_mio_remoted as helpers
    from azazel_nexus_runtime.mio_remote_consent import ConsentStore

    calls: list = []
    store = ConsentStore(Path(state_dir), owner=os.geteuid())

    def seam() -> None:
        fd = os.open(reached, os.O_WRONLY)  # blocks until the parent reads
        os.write(fd, b"1")
        os.close(fd)
        fd = os.open(release, os.O_RDONLY)  # blocks until the parent releases
        os.read(fd, 1)
        os.close(fd)

    store._after_send_read = seam
    service = helpers._service(transport=helpers._spy_transport(calls), consent=store)
    reply = service.handle(helpers.Request(
        frame=helpers.FRAME, envelope=helpers._seal(opt_in_generation=generation)))
    print(json.dumps({"calls": len(calls), "outcome": reply.get("outcome"),
                      "refusal": reply.get("refusal"),
                      "status": store.reading().status}))


if __name__ == "__main__":
    hold(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
