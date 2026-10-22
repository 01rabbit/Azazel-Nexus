#!/usr/bin/env python3
"""Record the SHA-256 of each Deception Lite profile as compiled (#196 G6 prep K).

`docs/deception-exposure-wiring.md` §5.2: the installer, with the service
manager only and after placing the four profiles in `/etc/apparmor.d`,
compiles each with `apparmor_parser -Q -o <private temporary file>
/etc/apparmor.d/<name>` (no other flag, so `/etc/apparmor/parser.conf`
applies as it does to `apparmor.service`'s load) and writes the SHA-256 of
each output to `/etc/azazel/activation/apparmor-compiled.json`
(`azazel_nexus_runtime.apparmor_compiled`). On one VM (parser 4.1.0) that
value equalled the kernel's `raw_sha256` and the boot cache (grant §7).

Nothing is loaded, replaced or removed in the kernel: `-Q` skips the load,
and the profiles are loaded by `apparmor.service` at the next boot. The
record is written as a private temporary file in the same directory,
fsynced, given mode 0644, renamed into place and the directory fsynced; it
is checked with the library's strict decoder before the rename. Any failure
(a profile that does not compile, an empty output, a version line of
another form, the directory a link) refuses (exit 1) and leaves an earlier
record as it was.

Fixed profile names (`decoy_apparmor.REQUIRED_ENFORCED_PROFILES`); the two
paths default to the installed ones and are arguments only so a test can
point them elsewhere. Nothing reads the record in this build (G6).
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from azazel_nexus_runtime.apparmor_compiled import (  # noqa: E402
    APPARMOR_COMPILED_MODE,
    APPARMOR_COMPILED_PATH,
    ApparmorCompiledRefused,
    decode_apparmor_compiled,
    encode_apparmor_compiled,
)
from azazel_nexus_runtime.decoy_apparmor import REQUIRED_ENFORCED_PROFILES  # noqa: E402

APPARMOR_DIRECTORY = "/etc/apparmor.d"
PARSER = "apparmor_parser"
_OUTPUT_LIMIT = 64 << 20
_TIMEOUT = 300


class Refused(Exception):
    """One fixed line for the operator; nothing compiled appears in it."""


def _parser() -> str:
    found = shutil.which(PARSER)
    if found is None:
        raise Refused("apparmor_parser is not installed")
    return found


def parser_version(parser: str) -> str:
    try:
        run = subprocess.run([parser, "--version"], stdin=subprocess.DEVNULL,
                             capture_output=True, timeout=_TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        raise Refused("apparmor_parser --version could not be run") from None
    lines = run.stdout.decode("ascii", "replace").splitlines()
    if run.returncode != 0 or not lines:
        raise Refused("apparmor_parser --version gave no version line")
    return lines[0].strip()


def compiled_hashes(parser: str, apparmor_dir: Path) -> dict[str, str]:
    """Each profile's `apparmor_parser -Q -o` output, as SHA-256 hex."""

    hashes = {}
    with tempfile.TemporaryDirectory(prefix="az-apparmor-compiled.") as scratch:
        for name in sorted(REQUIRED_ENFORCED_PROFILES):
            out = Path(scratch) / name
            try:
                run = subprocess.run(
                    [parser, "-Q", "-o", str(out), str(apparmor_dir / name)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, timeout=_TIMEOUT, check=False)
            except (OSError, subprocess.SubprocessError):
                raise Refused(f"AppArmor profile {name} could not be compiled") from None
            if run.returncode != 0:
                raise Refused(f"AppArmor profile {name} does not compile")
            try:
                fd = os.open(out, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    chunks, size = [], 0
                    while size <= _OUTPUT_LIMIT:
                        chunk = os.read(fd, 1 << 20)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        size += len(chunk)
                    data = b"".join(chunks)
                finally:
                    os.close(fd)
            except OSError:
                raise Refused(f"AppArmor profile {name} gave no compiled output") from None
            if not data or len(data) > _OUTPUT_LIMIT:
                raise Refused(f"AppArmor profile {name} gave no usable compiled output")
            hashes[name] = sha256(data).hexdigest()
    return hashes


def write_record(path: Path, record: bytes) -> None:
    """Atomically: a private temporary file beside it, fsync, chmod, rename, fsync."""

    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused(f"{path.parent} is not a directory") from None
    temporary = None
    try:
        for attempt in range(16):
            candidate = f".{path.name}.{os.getpid()}.{attempt}.tmp"
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
            except FileExistsError:
                continue
            temporary = candidate
            break
        else:
            raise Refused(f"no temporary file could be created in {path.parent}")
        try:
            view = memoryview(record)
            while view:
                view = view[os.write(fd, view):]
            os.fchmod(fd, APPARMOR_COMPILED_MODE)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        os.fsync(directory)
    except OSError:
        raise Refused(f"{path} could not be written") from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory)
            except OSError:
                pass
        os.close(directory)


def record(apparmor_dir: Path, output: Path) -> dict[str, str]:
    parser = _parser()
    version = parser_version(parser)
    hashes = compiled_hashes(parser, apparmor_dir)
    try:
        raw = encode_apparmor_compiled(hashes, version)
        if decode_apparmor_compiled(raw).apparmor_policy_hashes != hashes:
            raise ApparmorCompiledRefused("round trip")
    except ApparmorCompiledRefused:
        raise Refused("the compiled-policy record is not in its closed form") from None
    write_record(output, raw)
    return hashes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apparmor-dir", type=Path, default=Path(APPARMOR_DIRECTORY))
    parser.add_argument("--output", type=Path, default=Path(APPARMOR_COMPILED_PATH))
    args = parser.parse_args(argv)
    try:
        record(args.apparmor_dir, args.output)
    except Refused as exc:
        print(f"refusing to install: {exc}.", file=sys.stderr)
        return 1
    print(f"AppArmor compiled-policy hashes recorded in {args.output} (nothing loaded).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
