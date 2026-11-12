#!/usr/bin/env python3
"""Compare a wheel's package data with an offline source bundle's contents.

The wheel's RECORD is the independent oracle: it lists what a real build put in
the wheel. The bundle's non-`.py` source files (package data) must be exactly
those, so a package-data file the bundle drops (or a file it adds that no build
would ship) is found without trusting the bundler's own selection code.

    python3 tools/check_wheel_package_data.py --wheel azazel_nexus_runtime-*.whl \
        --bundle source.tar.gz [--package azazel_nexus_runtime --source runtime/src]

Exit status 0 when equal, 1 on any difference (printed), 2 on a usage or read error.
Both `--wheel` and `--bundle` may be given for the library too (`--package
azazel_nexus --source src`). Compiled extensions (`.so`), bytecode and the
`*.dist-info` directory are not package data. The native extension's `.c` source
is shipped in the wheel (MANIFEST.in) and counts on both sides.
"""

from __future__ import annotations

import argparse
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
        listed = [line.split(",")[0] for line in archive.read(records[0]).decode().splitlines()]
    data = set()
    for name in listed:
        path = PurePosixPath(name)
        if path.parts[:1] != (package,) or path.suffix in _NOT_DATA_SUFFIXES:
            continue
        data.add(PurePosixPath(*path.parts[1:]).as_posix())
    return data


def bundle_package_data(bundle: Path, package: str, source: str) -> set[str]:
    """The bundle's non-code files below `source/package/`, relative to the package."""
    prefix = PurePosixPath(source) / package
    data = set()
    with tarfile.open(bundle, "r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            path = PurePosixPath(member.name)
            try:
                relative = path.relative_to(prefix)
            except ValueError:
                continue
            if relative.suffix in _NOT_DATA_SUFFIXES:
                continue
            data.add(relative.as_posix())
    return data


def compare(wheel: Path, bundle: Path, package: str, source: str) -> tuple[set[str], set[str]]:
    """`(in the wheel only, in the bundle only)`."""
    in_wheel = wheel_package_data(wheel, package)
    in_bundle = bundle_package_data(bundle, package, source)
    return in_wheel - in_bundle, in_bundle - in_wheel


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--package", default="azazel_nexus_runtime")
    parser.add_argument("--source", default="runtime/src")
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
    print(f"package data of {args.package} matches ({len(wheel_package_data(args.wheel, args.package))} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
