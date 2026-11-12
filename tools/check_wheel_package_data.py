#!/usr/bin/env python3
"""Compare a wheel's package data with an offline bundle's contents.

The wheel's RECORD is the independent oracle: it lists what a real build put in
the wheel. The bundle's non-`.py` source files (package data) must be exactly
those, so a package-data file the bundle drops (or a file it adds that no build
would ship) is found without trusting the bundler's own selection code.

    python3 tools/check_wheel_package_data.py --wheel azazel_nexus_runtime-*.whl \
        --bundle source.tar.gz [--package azazel_nexus_runtime] [--source runtime/src]

The bundle may be the source bundle (members `runtime/src/...`, `src/...`) or an
install bundle (the same tree under `source/`: `source/runtime/src/...`,
`source/src/...`). Without `--source` the prefix is detected: for
`azazel_nexus_runtime` one of `runtime/src` or `source/runtime/src`, for
`azazel_nexus` one of `src` or `source/src`, whichever holds the package (exactly
one may; both or neither is an error). Any other package needs `--source`.

Exit status 0 when equal, 1 on any difference (printed), 2 on a usage or read
error. Two empty sets are not a match by themselves: the package must exist on
BOTH sides (the wheel's RECORD lists `<package>/__init__.py`, the bundle holds
`<source>/<package>/__init__.py`), otherwise the exit is 2 with a message. A
package with no data files (`azazel_nexus`) therefore passes when it exists.

Compiled extensions (`.so`), bytecode and the `*.dist-info` directory are not
package data. The native extension's `.c` source is shipped in the wheel
(MANIFEST.in) and counts on both sides.

Trust: this reads a wheel and a bundle that the caller produced; it does not
defend against someone replacing them while it runs (no `O_NOFOLLOW` handling).
Run it on a clean, detached clone's own build output.
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

_NOT_DATA_SUFFIXES = {".py", ".so", ".pyc", ".pyd"}


def wheel_package_data(wheel: Path, package: str) -> set[str]:
    """RECORD entries below `package/` that are package data, relative to the package."""
    with zipfile.ZipFile(wheel) as archive:
        records = [name for name in archive.namelist() if name.endswith(".dist-info/RECORD")]
        if len(records) != 1:
            raise ValueError("the wheel has no single RECORD")
        listed = [row[0] for row in csv.reader(io.StringIO(archive.read(records[0]).decode("utf-8")))
                  if row]
    if f"{package}/__init__.py" not in listed:
        raise ValueError(f"the wheel's RECORD has no {package}/__init__.py: no such package")
    data = set()
    for name in listed:
        path = PurePosixPath(name)
        if path.parts[:1] != (package,) or path.suffix in _NOT_DATA_SUFFIXES:
            continue
        data.add(PurePosixPath(*path.parts[1:]).as_posix())
    return data


def bundle_package_data(bundle: Path, package: str, source: str) -> set[str]:
    """The bundle's non-code files below `source/package/`, relative to the package.

    Raises `ValueError` when the bundle holds no `source/package/__init__.py`.
    """
    prefix = PurePosixPath(source) / package
    data = set()
    found_package = False
    with tarfile.open(bundle, "r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = PurePosixPath(member.name)
            try:
                relative = path.relative_to(prefix)
            except ValueError:
                continue
            if relative.as_posix() == "__init__.py":
                found_package = True
            if relative.suffix in _NOT_DATA_SUFFIXES:
                continue
            data.add(relative.as_posix())
    if not found_package:
        raise ValueError(f"the bundle has no {prefix.as_posix()}/__init__.py")
    return data


_DEFAULT_SOURCES = {
    "azazel_nexus_runtime": ("runtime/src", "source/runtime/src"),
    "azazel_nexus": ("src", "source/src"),
}


def detect_source(bundle: Path, package: str, source: str | None) -> str:
    """The bundle's source prefix: given, or the one default that holds the package."""
    if source is not None:
        return source
    candidates = _DEFAULT_SOURCES.get(package)
    if candidates is None:
        raise ValueError(f"no default source prefix for {package}: pass --source")
    holding = []
    with tarfile.open(bundle, "r:*") as archive:
        names = {member.name for member in archive.getmembers() if member.isfile()}
    for candidate in candidates:
        if f"{candidate}/{package}/__init__.py" in names:
            holding.append(candidate)
    if len(holding) != 1:
        raise ValueError(
            f"the bundle holds {package} under {len(holding)} of {list(candidates)}; "
            "expected exactly one (pass --source)")
    return holding[0]


def compare(wheel: Path, bundle: Path, package: str, source: str | None
            ) -> tuple[set[str], set[str]]:
    """`(in the wheel only, in the bundle only)`; both sides must hold the package."""
    prefix = detect_source(bundle, package, source)
    in_wheel = wheel_package_data(wheel, package)
    in_bundle = bundle_package_data(bundle, package, prefix)
    return in_wheel - in_bundle, in_bundle - in_wheel


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--package", default="azazel_nexus_runtime")
    parser.add_argument("--source", default=None,
                        help="the bundle prefix holding the package (default: detected)")
    args = parser.parse_args(argv)
    try:
        wheel_only, bundle_only = compare(args.wheel, args.bundle, args.package, args.source)
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"check_wheel_package_data: {error}", file=sys.stderr)
        return 2
    for name in sorted(wheel_only):
        print(f"in the wheel, missing from the bundle: {name}")
    for name in sorted(bundle_only):
        print(f"in the bundle, not in the wheel: {name}")
    if wheel_only or bundle_only:
        return 1
    print(f"package data of {args.package} matches "
          f"({len(wheel_package_data(args.wheel, args.package))} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
