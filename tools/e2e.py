#!/usr/bin/env python3
"""Install to status, end to end, in finite time (Nexus#43).

## What this produces, and what it does not

**Produces:** evidence that the distribution does not contradict itself --
that `install.sh` creates what the layout declares, that the daemons start on
the sockets the units name, that a commissioning record leads to a generation
and an activation pass, and that an injected daemon failure is rolled back and
recorded.

**Does not produce:** evidence about real hardware, or about what systemd
enforces. This harness never says a stage passed that it did not run. A stage
it could not execute is reported `not_executed` with the reason, and
`summary()["passed"]` does not count it.

That accounting is the point. A harness whose skipped stages read as
successes is a harness that reports a green install on a host where nothing
was installed.

## Finite

Every stage carries a deadline. Daemons are started as subprocesses and
stopped by a condition the harness controls, never by waiting for a signal
that may not come. Nothing here sleeps in a loop without a bound.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from tools.e2e_harness import Harness  # noqa: E402

#: Per-stage ceiling. A stage that overruns is a failure, not a slow pass.
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="fail if any stage could not be executed (for a host with systemd)",
    )
    parser.add_argument("--report", type=Path, default=None)
    arguments = parser.parse_args(argv)

    from tools.e2e_stages import run_all  # noqa: PLC0415 - kept beside this file

    harness = Harness(arguments.root)
    run_all(harness)
    text = harness.report.render()
    print(text)
    if arguments.report:
        arguments.report.write_text(text + "\n", encoding="utf-8")
    return 0 if harness.report.ok(require_all=arguments.require_all) else 1


if __name__ == "__main__":
    raise SystemExit(main())
