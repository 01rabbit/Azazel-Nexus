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
import tempfile
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from tools.e2e_harness import Harness  # noqa: E402


def enclosing_git_working_tree(root: Path) -> Optional[Path]:
    """The Git working tree `root` lies in, or `None`.

    A working tree is a directory holding `.git` -- a directory in an ordinary
    checkout, a *file* in a linked worktree. Both are looked for, at `root`
    and at every ancestor, because a guard that knew only this checkout would
    move the accident to the next worktree rather than prevent it.

    `.git` is read as a name on disk and nothing is executed: a guard that
    shelled out to `git` would not run where `git` is absent, which is
    exactly where nobody is watching.
    """

    resolved = root.resolve()
    for candidate in (resolved, *resolved.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def refuse_root_in_a_git_working_tree(root: Path) -> Optional[str]:
    """Refuse a node root inside any Git working tree.

    The harness builds a synthetic node under the root, and among the files it
    writes is a Core reserve record whose provenance is `measured` -- a record
    that is **not** a measurement and is not admissible as one. Pointed at a
    checkout it writes that record into a working tree, and the next
    `git add -A` commits it. `test_no_measurement_is_committed_anywhere`
    catches that, but it catches it after the commit exists, and a commit that
    reached a remote is not taken back by rewriting a branch.

    So the harness writes only to a dedicated directory outside version
    control, and the refusal happens **before any stage runs**: a refusal
    after the first write is a refusal that leaves the files behind.
    """

    enclosing = enclosing_git_working_tree(root)
    if enclosing is None:
        return None
    return (
        f"refusing to write to {root.resolve()}: it is inside the Git "
        f"working tree at {enclosing}. The harness writes a synthetic node, "
        "including a Core reserve record that declares itself measured, and "
        "such a record must never enter version control -- it is not a "
        "measurement and is not admissible as one. Omit --root, or give a "
        "directory outside any working tree."
    )


def dedicated_root() -> Path:
    """A fresh directory for one run, outside version control.

    The default, so that the ordinary way to run the harness cannot put a
    synthetic node anywhere a commit could pick it up.
    """

    return Path(tempfile.mkdtemp(prefix="az-e2e-"))


#: Per-stage ceiling. A stage that overruns is a failure, not a slow pass.
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help=(
            "where to build the synthetic node. Omitted: a fresh "
            "directory outside version control. Given: it must be "
            "outside every Git working tree"
        ),
    )
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="fail if any stage could not be executed (for a host with systemd)",
    )
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument(
        "--edge-core", type=Path, default=None,
        help="built azazel-edge-core binary for the integrated loop (test tooling only)",
    )
    parser.add_argument(
        "--edge-redirect-policy", type=Path, default=None,
        help="redirect policy copied into the root for --edge-core (test tooling only)",
    )
    arguments = parser.parse_args(argv)

    # The default is a dedicated directory; an explicit one is checked the
    # same way, because a root somebody typed is the one most likely to be a
    # checkout they were standing in.
    root = arguments.root if arguments.root is not None else dedicated_root()
    refusal = refuse_root_in_a_git_working_tree(root)
    if refusal is not None:
        print(refusal, file=sys.stderr)
        return 2

    from tools.e2e_stages import run_all  # noqa: PLC0415 - kept beside this file

    harness = Harness(root, edge_core=arguments.edge_core,
                      edge_redirect_policy=arguments.edge_redirect_policy)
    run_all(harness)
    text = harness.report.render()
    print(text)
    if arguments.report:
        arguments.report.write_text(text + "\n", encoding="utf-8")
    return 0 if harness.report.ok(require_all=arguments.require_all) else 1


if __name__ == "__main__":
    raise SystemExit(main())
