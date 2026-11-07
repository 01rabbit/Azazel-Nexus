"""Exec the guarded repository process fixture; lab has no locald composition.

The test launcher retains the container/root/UID checks and production deadlines.
Exec preserves the controller-owned PID, stdout, stderr and signal lifecycle.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys


def main(argv=None):
    launcher = Path(__file__).resolve().parents[3] / 'tests/real_process/_weekend_locald_process.py'
    args = sys.argv[1:] if argv is None else argv
    os.execv(sys.executable, [sys.executable, '-B', str(launcher), *args])


if __name__ == '__main__':
    raise SystemExit(main())
