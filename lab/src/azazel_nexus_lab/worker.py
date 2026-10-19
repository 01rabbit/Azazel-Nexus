"""Fresh process: ROOT is fixed before importing any production runtime module."""
from __future__ import annotations

import grp
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


def main():
    operation, *args = sys.argv[1:]
    root = Path(os.environ["AZAZEL_ROOT"])
    if operation in {"status", "setup", "pack-inspect"}:
        from azazel_nexus.cli import main as cli

        if operation == "pack-inspect":
            return cli(["pack", "inspect", str(root / "media")])
        if operation == "status":
            return cli(["--knowledge-lite", str(root / "var/lib/azazel/knowledge"),
                        "--edge-root", str(root / "opt/azazel/edge-core"),
                        "--edge-probe", str(root / "var/lib/azazel/run/edge-probe/edge-probe.json"),
                        "status"])
        return cli(["setup"])
    if operation in {"ask", "ask-frame", "roundtrips"}:
        from azazel_nexus_runtime.mio_socket_client import _exchange

        from azazel_nexus.local_advisory import MAX_FRAME_BYTES, read_frame
        from azazel_nexus.model_paths import bounded_read

        # PrincipalPolicy explicitly classifies root with this primary GID as
        # OPERATOR. Supplementary membership alone never grants root that class.
        os.setegid(grp.getgrnam("azazel-operator").gr_gid)
        if operation == "ask-frame":
            raw = sys.stdin.read(MAX_FRAME_BYTES + 1)
            document = json.loads(raw)
        else:
            scenario = Path(args[0])
            if scenario.suffix != ".json":
                raise ValueError("scenario JSON file required")
            document = json.loads(bounded_read(scenario, MAX_FRAME_BYTES))
            if document.get("schema") == "azazel-nexus-lab/scenario/1":
                document = document["frame"]
        frame = read_frame(document)
        def exchange():
            return _exchange("mio-entry", "azmioentry", "mio.advise",
                             {"deadline_ms": 2000}, payload=frame, deadline_s=3)

        if operation in {"ask", "ask-frame"}:
            result = exchange()
        else:
            import time
            from concurrent.futures import ThreadPoolExecutor

            def timed(_):
                began = time.perf_counter()
                try:
                    reply = exchange()
                    status = {key: reply.get(key) for key in ("outcome", "reason", "reference_status")}
                except Exception as error:  # noqa: BLE001 - report bounded sample failure, never content
                    status = {"error_type": type(error).__name__}
                return {"ms": (time.perf_counter() - began) * 1000, "status": status}

            with ThreadPoolExecutor(max_workers=int(args[2])) as pool:
                result = list(pool.map(timed, range(int(args[1]))))
    elif operation == "knowledge-status":
        from azazel_nexus_runtime.mio_socket_client import _exchange

        os.setegid(grp.getgrnam("azazel-operator").gr_gid)
        result = _exchange("knowledge", "azknowledge", "knowledge.status", {}, deadline_s=3)
    elif operation == "knowledge":
        from dataclasses import asdict

        from azazel_nexus.lite_import import lookup_context_reading

        # Operator lookup is local read-only: the daemon lookup verb is service
        # only. ask exercises locald -> knowledge-read with real peer credentials.
        reading = lookup_context_reading(
            root=root / "var/lib/azazel/knowledge", trust_root=root / "var/lib/azazel/lite-trust",
            technique_ids=tuple(args), query_as_of=datetime.now(UTC).isoformat().replace("+00:00", "Z"))
        result = {"reason_code": reading.reason_code, "refs": [asdict(ref) for ref in reading.refs]}
    else:
        raise ValueError("unknown lab worker operation")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
