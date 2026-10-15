"""Bounded, read-only observation of Debian's installed binary packages.

This is an observation adapter only. Its rows are not an allowlist, package
trust/authentication, a complete Python or runtime closure, or admission
evidence. The native architecture is reported from the architecture of the
installed, unqualified ``dpkg`` binary-package row; the adapter invokes only
the fixed ``dpkg-query -W`` query and does not infer architecture from uname.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import selectors
import subprocess
import time
from typing import Final

__all__ = [
    "PackageObservationRefused",
    "PackageRecord",
    "PackageSnapshot",
    "QUERY_ARGV",
    "SCHEMA",
    "observe_installed_packages",
    "parse_package_output",
    "validate_package_snapshot",
]

QUERY_ARGV: Final = (
    "/usr/bin/dpkg-query",
    "-W",
    "-f=${binary:Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n",
)
QUERY_TIMEOUT_SECONDS: Final = 10.0
MAX_OUTPUT_BYTES: Final = 4 * 1024 * 1024
SCHEMA: Final = "azazel-nexus.debian-installed-packages.v1"
_ENV: Final = {"LC_ALL": "C", "LANG": "C"}
_PACKAGE_NAME = re.compile(r"[a-z0-9][a-z0-9+.-]{0,254}\Z")
_ARCH = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_VERSION = re.compile(
    r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+~\-]*(?:-[A-Za-z0-9.+~]+)?\Z"
)
_STATUS = re.compile(r"[ uihpr][ nciUHFWt][ R ]\Z")


class PackageObservationRefused(Exception):
    """A redacted refusal to observe a bounded, canonical package snapshot."""


@dataclass(frozen=True, slots=True)
class PackageRecord:
    """One installed binary package row; architecture is never collapsed."""

    binary_package: str
    version: str
    architecture: str
    status: str


@dataclass(frozen=True, slots=True)
class PackageSnapshot:
    """Immutable installed-package observation with a canonical content hash."""

    schema: str
    native_architecture: str
    records: tuple[PackageRecord, ...]
    digest: str


def parse_package_output(raw: bytes) -> PackageSnapshot:
    """Parse fixed-format dpkg-query bytes and hash their canonical projection."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_OUTPUT_BYTES:
        raise PackageObservationRefused("package observation output size refused")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise PackageObservationRefused("package observation encoding refused") from None
    if "\r" in text or "\x00" in text or not text.endswith("\n"):
        raise PackageObservationRefused("package observation framing refused")

    rows = text[:-1].split("\n")
    if not rows or any(not row for row in rows):
        raise PackageObservationRefused("package observation row refused")
    parsed: list[PackageRecord] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        columns = row.split("\t")
        if len(columns) != 4:
            raise PackageObservationRefused("package observation row refused")
        package, version, architecture, status = columns
        package_parts = package.split(":")
        if (len(package_parts) > 2
                or not _PACKAGE_NAME.fullmatch(package_parts[0])
                or (len(package_parts) == 2 and not _ARCH.fullmatch(package_parts[1]))
                or (len(package_parts) == 2 and package_parts[1] != architecture)
                or not _VERSION.fullmatch(version)
                or not _ARCH.fullmatch(architecture)
                or not _STATUS.fullmatch(status)):
            raise PackageObservationRefused("package observation field refused")
        identity = (package_parts[0], architecture)
        if identity in seen:
            raise PackageObservationRefused("duplicate package observation refused")
        seen.add(identity)
        if status == "ii ":
            parsed.append(PackageRecord(package, version, architecture, status))

    native_rows = [record for record in parsed if record.binary_package == "dpkg"]
    if len(native_rows) != 1:
        raise PackageObservationRefused("native architecture observation unavailable")
    native_architecture = native_rows[0].architecture
    records = tuple(sorted(
        parsed,
        key=lambda item: (item.binary_package, item.architecture, item.version, item.status),
    ))
    canonical = {
        "schema": SCHEMA,
        "native_architecture": native_architecture,
        "records": [
            {
                "binary_package": item.binary_package,
                "version": item.version,
                "architecture": item.architecture,
                "status": item.status,
            }
            for item in records
        ],
    }
    payload = json.dumps(
        canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    return PackageSnapshot(SCHEMA, native_architecture, records, digest)


def validate_package_snapshot(snapshot: PackageSnapshot) -> None:
    """Revalidate a snapshot at a trust boundary; constructors are not evidence."""
    if (type(snapshot) is not PackageSnapshot or snapshot.schema != SCHEMA
            or type(snapshot.native_architecture) is not str
            or not _ARCH.fullmatch(snapshot.native_architecture)
            or type(snapshot.records) is not tuple
            or type(snapshot.digest) is not str
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", snapshot.digest)):
        raise PackageObservationRefused("package snapshot structure refused")
    records = snapshot.records
    if any(type(record) is not PackageRecord for record in records):
        raise PackageObservationRefused("package snapshot record refused")
    if records != tuple(sorted(
        records,
        key=lambda item: (item.binary_package, item.architecture, item.version, item.status),
    )):
        raise PackageObservationRefused("package snapshot ordering refused")
    identities = set()
    for record in records:
        columns = (record.binary_package, record.version, record.architecture, record.status)
        if any(type(value) is not str for value in columns):
            raise PackageObservationRefused("package snapshot field refused")
        parts = record.binary_package.split(":")
        if (len(parts) > 2 or not _PACKAGE_NAME.fullmatch(parts[0])
                or (len(parts) == 2 and parts[1] != record.architecture)
                or not _VERSION.fullmatch(record.version)
                or not _ARCH.fullmatch(record.architecture)
                or record.status != "ii "):
            raise PackageObservationRefused("package snapshot field refused")
        identity = (parts[0], record.architecture)
        if identity in identities:
            raise PackageObservationRefused("package snapshot duplicate refused")
        identities.add(identity)
    native_rows = [record for record in records if record.binary_package == "dpkg"]
    if len(native_rows) != 1 or native_rows[0].architecture != snapshot.native_architecture:
        raise PackageObservationRefused("package snapshot native architecture refused")
    if _snapshot_digest(snapshot.native_architecture, records) != snapshot.digest:
        raise PackageObservationRefused("package snapshot digest refused")


def _snapshot_digest(native_architecture: str, records: tuple[PackageRecord, ...]) -> str:
    canonical = {
        "schema": SCHEMA,
        "native_architecture": native_architecture,
        "records": [
            {
                "binary_package": item.binary_package,
                "version": item.version,
                "architecture": item.architecture,
                "status": item.status,
            }
            for item in records
        ],
    }
    payload = json.dumps(
        canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def observe_installed_packages() -> PackageSnapshot:
    """Run only the fixed absolute dpkg-query command and parse its bounded output."""
    try:
        output = _run_query()
        return parse_package_output(output)
    except PackageObservationRefused:
        raise
    except Exception:
        raise PackageObservationRefused("installed package observation refused") from None


def _run_query() -> bytes:
    """Stream stdout under a strict byte and wall-clock bound; never capture stderr."""
    process = None
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            QUERY_ARGV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(_ENV),
            close_fds=True,
        )
        if process.stdout is None:
            raise PackageObservationRefused("package observation output unavailable")
        selector.register(process.stdout, selectors.EVENT_READ)
        output = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise PackageObservationRefused("package observation timed out")
            chunk = os.read(process.stdout.fileno(), min(8192, MAX_OUTPUT_BYTES + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_OUTPUT_BYTES:
                raise PackageObservationRefused("package observation output exceeds bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PackageObservationRefused("package observation timed out")
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise PackageObservationRefused("package observation timed out") from None
        if return_code != 0:
            raise PackageObservationRefused("package query failed")
        return bytes(output)
    except PackageObservationRefused:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise
    except Exception:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise PackageObservationRefused("package query failed") from None
    finally:
        selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()
