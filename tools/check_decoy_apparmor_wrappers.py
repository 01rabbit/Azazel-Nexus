#!/usr/bin/env python3
"""Refuse an install whose decoy wrappers would run outside their profiles (#196 G3).

The Deception Lite AppArmor profiles (`packaging/apparmor/`) let the Python
body execute only `decoy_apparmor.PROFILE_INTERPRETER` and read code only
under `decoy_apparmor.PROFILE_PYTHON_ROOTS`. The interpreter and import
paths are chosen at install (`tools/stage_runtime_entrypoints.py`), so this
reads the three staged wrappers (`az-decoy-nsd`, `az-decoy-netd`,
`az-decoyd`) with the canonical wrapper parser, resolves the interpreter and
every import path as the kernel would, and refuses (exit 1) when any falls
outside the profiles. Fixed wrapper names and targets (equal to
`runtime/pyproject.toml`'s, a test checks); nothing is executed, written or
loaded.

`--warn-only` reports the same finding and exits 0: for a `DESTDIR` staging
run, whose interpreter is not the node's. The installer uses it only
without the service manager.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from azazel_nexus_runtime.decoy_apparmor import wrapper_profile_refusal  # noqa: E402
from azazel_nexus_runtime.startup_wrapper import parse_wrapper  # noqa: E402

#: The wrappers the three exposure units execute, and the targets they must
#: call (`runtime/pyproject.toml`'s scripts; a test keeps them equal).
TARGETS = {
    "az-decoy-nsd": "azazel_nexus_runtime.decoy_nsd:main",
    "az-decoy-netd": "azazel_nexus_runtime.decoy_netd:main",
    "az-decoyd": "azazel_nexus_runtime.decoyd:main",
}
WRAPPERS = tuple(TARGETS)
_LIMIT = 65536


def _targets() -> dict[str, str]:
    return dict(TARGETS)


def findings(libexec: Path) -> list[str]:
    """One line per wrapper that is unreadable or outside the profiles."""

    found = []
    for name, target in _targets().items():
        try:
            fd = os.open(libexec / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                raw = os.read(fd, _LIMIT + 1)
            finally:
                os.close(fd)
            interpreter, paths = parse_wrapper(raw, target=target)
        except (OSError, ValueError):
            found.append(f"{name}: not a readable canonical wrapper")
            continue
        reason = wrapper_profile_refusal(
            os.path.realpath(interpreter),
            tuple(os.path.realpath(path) for path in paths))
        if reason is not None:
            found.append(f"{name}: {reason}")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("libexec", type=Path)
    parser.add_argument("--warn-only", action="store_true")
    args = parser.parse_args(argv)
    found = findings(args.libexec)
    for line in found:
        print(("WARNING: " if args.warn_only else "refusing to install: ") + line,
              file=sys.stderr)
    return 1 if found and not args.warn_only else 0


if __name__ == "__main__":
    raise SystemExit(main())
