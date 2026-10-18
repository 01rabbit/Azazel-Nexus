"""Offline prebuilt runtime validation/publication, called by install.sh only."""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from azazel_nexus.model_runtime import (
    LLAMA_RUNTIME_ID,
    RUNTIMES,
    RuntimeRefused,
    pinned_runtime_digest,
)


def verify_prebuilt(record, path):
    """Untrusted installation input: hash bytes; root ownership is set on staging."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RuntimeRefused("prebuilt input must be regular")
        if "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest() != record.digest:
            raise RuntimeRefused("prebuilt digest mismatch")


def install_runtime(source: Path, destination: Path, *, check_only: bool = False) -> None:
    if os.geteuid() != 0:
        raise RuntimeRefused("--llama-runtime requires root for root:root ownership")
    record = replace(RUNTIMES[LLAMA_RUNTIME_ID], digest=pinned_runtime_digest())
    verify_prebuilt(record, source)
    if check_only:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".llama-server-", dir=destination.parent)
    staged = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output, os.fdopen(
            os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb"
        ) as input_file:
            if not stat.S_ISREG(os.fstat(input_file.fileno()).st_mode):
                raise RuntimeRefused("prebuilt input is no longer a regular file")
            while chunk := input_file.read(1024 * 1024):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.chown(staged, 0, 0)
        staged.chmod(0o755)
        verify_prebuilt(record, staged)
        os.replace(staged, destination)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        staged.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    try:
        install_runtime(args.source, args.destination, check_only=args.check_only)
    except (RuntimeRefused, OSError) as error:
        parser.exit(1, f"refusing --llama-runtime: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
