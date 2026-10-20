#!/usr/bin/env python3
"""Write `packaging/systemd/*.service` from the hardening declaration.

Run after changing `azazel_nexus_runtime.hardening`. The committed files are
compared against what this produces, so forgetting to run it fails CI rather
than shipping a unit that disagrees with the table it came from.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from azazel_nexus_runtime.hardening import ALL_PROFILES, render_unit  # noqa: E402


def main() -> int:
    target = ROOT / "packaging" / "systemd"
    target.mkdir(parents=True, exist_ok=True)
    for profile in ALL_PROFILES:
        (target / profile.unit).write_text(render_unit(profile), encoding="utf-8")
        print(f"wrote {profile.unit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
