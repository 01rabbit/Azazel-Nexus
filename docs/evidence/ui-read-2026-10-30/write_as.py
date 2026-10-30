"""Write one snapshot and its UI copy as the writer account (rehearsal input).

Run with `runuser -u <writer> --`: the operator leaf and the UI leaf are
written with the product's `UiCopy` and the same temp-file-and-rename the
daemon uses, under the installer's owners and modes. The content is a fixture
built by the product's builders (gen_inputs.py), with its times moved to now
(or `--age` seconds ago). The daemons themselves stay masked.
"""
import argparse, json, os, sys, tempfile, time
from pathlib import Path
from azazel_nexus_runtime.runtime_paths import ui_copy_path
from azazel_nexus_runtime.status_snapshot import UiCopy, _replace
from azazel_nexus import runtime_paths as paths

TIME_KEYS = {"written_at", "last_accepted_at", "last_processed_at", "last_explained_at",
             "first_seen", "last_seen", "since", "reported_at"}

def shift(value, delta):
    if isinstance(value, dict):
        return {k: (v + delta if k in TIME_KEYS and isinstance(v, (int, float)) and not isinstance(v, bool)
                    else shift(v, delta)) for k, v in value.items()}
    if isinstance(value, list):
        return [shift(v, delta) for v in value]
    return value

p = argparse.ArgumentParser()
p.add_argument("name"); p.add_argument("--age", type=float, default=0.0)
p.add_argument("--ui-only", action="store_true")
a = p.parse_args()
inputs = Path("/share/inputs")
now0 = float((inputs / "NOW").read_text())
value = json.loads((inputs / f"{a.name}.json").read_text())
value = shift(value, time.time() - a.age - now0)
if a.name == "mio_status":
    value["written_at"] = time.time() - a.age
body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
if not a.ui_only:
    _replace(paths.snapshot_path(a.name), body, 0o640)
ok = UiCopy(ui_copy_path(a.name), name="rehearsal").write(body)
print(a.name, "ui_copy_written" if ok else "ui_copy_failed")
sys.exit(0 if ok else 1)
