#!/usr/bin/env python3
"""Run the shared vectors on aarch64 and amd64 and compare the digests.

ADR-0003 D6: shared vectors with injected clocks and identifiers are run on
both CPUs and compared byte for byte. This is the local runner for that. It
starts one container per CPU, each installing this checkout and running
`tests/vectors/cross_arch.py` as a non-root user (uid 1001, umask 022), and
then compares the two digest lists with each other and with the pins in
`tests/vectors/digests.json`.

    target    docker context    platform       how it executes
    aarch64   colima            linux/arm64    native on Apple Silicon (a VM, not hardware)
    amd64     colima-rosetta    linux/amd64    x86_64 translated by Rosetta 2

**Neither run is a hardware run.** The aarch64 container runs on the colima
VM; the amd64 one is x86_64 code translated by Rosetta, which ADR-0003 D6
says is recorded as emulated, not as an amd64 host. The report says so in
every run it records. A CPU whose run did not finish is reported with no
digest -- never filled in from the other CPU.

Usage:

    python3 tools/cross_arch_vectors.py [--python 3.12] [--out REPORT.json]
    python3 tools/cross_arch_vectors.py --compare AARCH64.json AMD64.json

The first form needs docker with both contexts and network access for
``pip install`` inside the containers (or ``--pip-cache DIR``). The test
dependencies are installed from ``uv.lock`` with ``--require-hashes``. The second
only compares two outputs of ``python tests/vectors/cross_arch.py`` that were
produced elsewhere. Exit status 0 only when both CPUs produced every digest,
the two agree, and both match the pins.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINS = ROOT / "tests" / "vectors" / "digests.json"

#: One native aarch64 and one Rosetta-translated amd64 container. The amd64
#: context needs an explicit platform: without it colima-rosetta pulls arm64.
TARGETS = {
    "aarch64": {
        "context": "colima",
        "platform": "linux/arm64",
        "machine": "aarch64",
        "execution": "container on the colima VM (aarch64, Apple Silicon); not hardware",
    },
    "amd64": {
        "context": "colima-rosetta",
        "platform": "linux/amd64",
        "machine": "x86_64",
        "execution": "container on colima with Rosetta 2 translating x86_64; "
                     "emulated, not an amd64 host",
    },
}

#: The uv that turns `uv.lock` into a hash-pinned requirements file inside
#: the container. Only `uv export` runs; it resolves nothing.
UV_VERSION = "0.9.5"

#: What runs inside each container. The checkout is mounted read-only and
#: copied, so nothing is written back into it. The library's dev closure is
#: installed from `uv.lock` with `--require-hashes` (the same pytest and PyNaCl
#: on both CPUs); the runtime's own dependencies are exact `==` pins in
#: `runtime/pyproject.toml`.
_INSIDE = (
    "set -e; cp -r /src /w; cd /w; "
    f"python -m pip install -q --root-user-action=ignore uv=={UV_VERSION} >/dev/null; "
    "uv export --frozen --extra dev --no-emit-project --format requirements-txt "
    "-o /w/.locked-dev.txt >/dev/null; "
    "python -m pip install -q --root-user-action=ignore --require-hashes --no-deps "
    "-r /w/.locked-dev.txt >/dev/null; "
    "python -m pip install -q --root-user-action=ignore --no-deps -e . >/dev/null; "
    "python -m pip install -q --root-user-action=ignore -e ./runtime >/dev/null; "
    "useradd -m -u 1001 ci; chown -R ci /w; "
    "su ci -c 'umask 022; cd /w && python tests/vectors/cross_arch.py'"
)


def pins() -> dict[str, str]:
    document = json.loads(PINS.read_text(encoding="utf-8"))
    return {name: entry["sha256"] for name, entry in document["vectors"].items()}


def bind(source: Path, target: str, *, readonly: bool = False) -> list[str]:
    """``--mount type=bind`` for a resolved host directory.

    `--mount` takes comma-separated fields and `-v` colon-separated ones, so
    a path holding either character could add a field nobody asked for. Such
    a path is refused rather than quoted.
    """

    resolved = Path(source).resolve()
    text = str(resolved)
    if ":" in text or "," in text:
        raise ValueError(f"refusing to mount a path containing ':' or ',': {text!r}")
    if not resolved.is_dir():
        raise ValueError(f"not a directory: {text!r}")
    spec = f"type=bind,source={text},target={target}"
    return ["--mount", spec + (",readonly" if readonly else "")]


def run_target(name: str, *, python: str, pip_cache: Path | None) -> dict:
    target = TARGETS[name]
    command = ["docker", "--context", target["context"], "run", "--rm",
               "--platform", target["platform"], "--dns", "1.1.1.1",
               *bind(ROOT, "/src", readonly=True)]
    if pip_cache is not None:
        command += [*bind(pip_cache, "/pipcache"), "-e", "PIP_CACHE_DIR=/pipcache"]
    command += [f"python:{python}", "bash", "-c", _INSIDE]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    base = {"target": name, **target, "image": f"python:{python}"}
    if completed.returncode != 0:
        return {**base, "error": f"exit {completed.returncode}",
                "stderr_tail": completed.stderr.splitlines()[-20:]}
    try:
        report = json.loads(completed.stdout)
    except ValueError:
        return {**base, "error": "output is not JSON",
                "stderr_tail": completed.stderr.splitlines()[-20:]}
    return {**base, **report}


def compare(reports: dict[str, dict], pinned: dict[str, str]) -> dict:
    """Per vector: each CPU's digest, whether they agree, and whether they match the pin.

    A CPU without a digest for a vector is `None`, and `None` never equals
    anything: a vector not run on a CPU is not counted as agreeing. A run that
    failed (its report carries ``error``) is listed in ``failed_runs``, and
    then neither ``all_equal`` nor ``all_match_pins`` is true.
    """

    usable: dict[str, dict] = {}
    failed = []
    for name in TARGETS:
        report = reports.get(name)
        if report is None or "error" in report or "digests" not in report:
            # A run that did not finish has no digests. Its vectors are None
            # below, and None never agrees with anything.
            failed.append(name)
            usable[name] = {}
            continue
        machine = report.get("host", {}).get("machine")
        if machine != TARGETS[name]["machine"]:
            raise ValueError(f"the {name} report was produced on {machine!r}")
        usable[name] = report["digests"]
    unknown = sorted(set(reports) - set(TARGETS))
    if unknown:
        raise ValueError(f"reports for unknown targets: {unknown}")
    names = sorted(set(pinned).union(*usable.values()))
    vectors = {}
    for vector in names:
        row = {cpu: usable[cpu].get(vector) for cpu in TARGETS}
        values = list(row.values())
        equal = None not in values and len(set(values)) == 1
        row.update(equal=equal, pinned=pinned.get(vector),
                   matches_pin=equal and values[0] == pinned.get(vector))
        vectors[vector] = row
    return {
        "vectors": vectors,
        "failed_runs": failed,
        "differing": [v for v, row in vectors.items() if not row["equal"]],
        "all_equal": not failed and all(row["equal"] for row in vectors.values()),
        "all_match_pins": not failed and all(row["matches_pin"] for row in vectors.values()),
    }


def _commit() -> str:
    try:
        head = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain"],
                               capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return head + ("+uncommitted" if dirty else "")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--python", default="3.12", help="python image tag (default 3.12)")
    parser.add_argument("--pip-cache", type=Path, help="host directory mounted as pip's cache")
    parser.add_argument("--out", type=Path, help="write the report here as well as stdout")
    parser.add_argument("--compare", nargs=2, metavar=("AARCH64", "AMD64"), type=Path,
                        help="compare two saved outputs instead of running containers")
    args = parser.parse_args(argv)

    if args.pip_cache is not None:
        bind(args.pip_cache, "/pipcache")  # refuse before any container starts
    if args.compare:
        runs = {cpu: {"target": cpu, **TARGETS[cpu], **json.loads(path.read_text())}
                for cpu, path in zip(TARGETS, args.compare)}
    else:
        runs = {cpu: run_target(cpu, python=args.python, pip_cache=args.pip_cache)
                for cpu in TARGETS}
    comparison = compare(runs, pins())
    report = {
        "schema": "azazel-nexus/cross-arch-vectors/v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": _commit(),
        "evidence_kind": "container software run; aarch64 on a VM, amd64 under Rosetta "
                         "emulation; not hardware evidence",
        "runs": runs,
        "comparison": comparison,
    }
    text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    sys.stdout.write(text)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    ok = comparison["all_equal"] and comparison["all_match_pins"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
