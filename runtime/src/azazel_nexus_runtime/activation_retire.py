"""Retiring an approval after its operator is explicitly revoked (stop contract).

A grant records the approval it was made under in
``<state>/activation/accepted-grant.json`` (root ``0600``), written atomically
and synced before any marker or READY. When a later, freshly loaded operator
trust snapshot lists that approval's operator in ``revoked`` (an explicit
entry; a loader failure or a missing key proves nothing), the approval is
retired: the approval-sequence floor is raised to ``approval_seq + 1``, so the
same approval is refused from then on for every unit it names.

The sequence is crash-safe. ``retirement-pending.json`` is written first; the
floor is raised and read back; then the accepted record and the pending file
are removed. A recheck that finds a pending file resumes it, and the main pass
grants nothing while one exists.

Conditions that are not revocations (expiry, health, evidence) retire nothing:
once the condition is back, the same approval can grant again.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import re

from azazel_nexus import activation_approval_v2 as approval_v2

from . import activation_markers
from .activation_markers import GRANTABLE_UNITS

__all__ = [
    "RetireRefused",
    "read_accepted_grant",
    "resume_pending_retirement",
    "retirement_pending",
    "retire_if_revoked",
    "write_accepted_grant",
]

SCHEMA = "azazel-nexus/accepted-grant/v1"
ACCEPTED = "accepted-grant.json"
PENDING = "retirement-pending.json"
_STATE = ("var", "lib", "azazel", "state")
_LEAF = "activation"
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_LIMIT = 8192
_FIELDS = {"schema", "operator", "approval_seq", "approval_id", "payload_sha256", "units"}
#: The approval-ID grammar of the v2 approval schema (one source).
_APPROVAL_ID = approval_v2._APPROVAL_ID
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OPERATOR = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_MAX_SKEW = 86400


class RetireRefused(Exception):
    """The accepted-grant state is unreadable, inconsistent or cannot be advanced."""


def _owner() -> int:
    return activation_markers._OWNER


def _leaf(root: Path, *, create: bool) -> int | None:
    fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in _STATE:
            fd2 = os.open(component, _DIR, dir_fd=fd)
            os.close(fd)
            fd = fd2
        try:
            fd2 = os.open(_LEAF, _DIR, dir_fd=fd)
        except FileNotFoundError:
            if not create:
                return None
            os.mkdir(_LEAF, 0o700, dir_fd=fd)
            fd2 = os.open(_LEAF, _DIR, dir_fd=fd)
        os.close(fd)
        fd = fd2
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _owner()
                or info.st_mode & 0o077):
            raise RetireRefused("accepted-grant directory protection refused")
        result, fd = fd, None
        return result
    except FileNotFoundError:
        return None
    finally:
        if fd is not None:
            os.close(fd)


def _unique_object(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate key")
        document[key] = value
    return document


def _canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _read(leaf: int, name: str) -> dict | None:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=leaf)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != _owner()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= _LIMIT):
            raise RetireRefused("accepted-grant file protection refused")
        raw = os.read(fd, _LIMIT + 1)
    finally:
        os.close(fd)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        # Exactly the bytes the writer produces: no whitespace, no reordering,
        # no alternate number or string spelling, no trailing data.
        if raw != _canonical(document):
            raise ValueError
    except (ValueError, TypeError):
        raise RetireRefused("accepted-grant file malformed") from None
    return document


def _check(document, *, pending: bool) -> dict:
    """The record is exactly what `write_accepted_grant` writes, or it is refused.

    Canonical lowercase SHA-256, an operator label, a non-empty sorted unique
    subset of the grantable units, and a sequence that can still be advanced.
    """
    fields = _FIELDS | ({"target_seq", "skew_seconds"} if pending else set())
    if (type(document) is not dict or set(document) != fields
            or document["schema"] != SCHEMA
            or type(document["operator"]) is not str
            or _OPERATOR.fullmatch(document["operator"]) is None
            or type(document["approval_id"]) is not str
            or _APPROVAL_ID.fullmatch(document["approval_id"]) is None
            or type(document["payload_sha256"]) is not str
            or _SHA256.fullmatch(document["payload_sha256"]) is None
            or type(document["units"]) is not list
            or not document["units"]
            or any(type(u) is not str for u in document["units"])
            or document["units"] != sorted(set(document["units"]))
            or not set(document["units"]) <= GRANTABLE_UNITS
            or type(document["approval_seq"]) is not int
            or not 0 <= document["approval_seq"] < 2**63 - 1):
        raise RetireRefused("accepted-grant record inconsistent")
    if pending:
        skew = document["skew_seconds"]
        target = document["target_seq"]
        if (type(target) is not int or not 0 < target < 2**63
                or target != document["approval_seq"] + 1
                or type(skew) is not int or not 0 <= skew <= _MAX_SKEW):
            raise RetireRefused("retirement target inconsistent")
    return document


def _write(leaf: int, name: str, document: dict) -> None:
    raw = _canonical(document)
    partial = "." + name + ".partial"
    try:
        os.unlink(partial, dir_fd=leaf)
    except FileNotFoundError:
        pass
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=leaf)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write that makes no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(partial, name, src_dir_fd=leaf, dst_dir_fd=leaf)
    os.fsync(leaf)


def _remove(leaf: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=leaf)
    except FileNotFoundError:
        pass
    os.fsync(leaf)


def write_accepted_grant(root: Path, *, operator: str, approval_seq: int,
                         approval_id: str, payload_sha256: str, units) -> None:
    """Record the approval a grant is made under; raises `RetireRefused` on failure."""
    document = {"schema": SCHEMA, "operator": operator, "approval_seq": approval_seq,
                "approval_id": approval_id, "payload_sha256": payload_sha256,
                "units": sorted(units)}
    try:
        _check(document, pending=False)
        leaf = _leaf(root, create=True)
        try:
            _write(leaf, ACCEPTED, document)
        finally:
            os.close(leaf)
    except RetireRefused:
        raise
    except Exception:
        raise RetireRefused("accepted-grant record could not be written") from None


def read_accepted_grant(root: Path) -> dict | None:
    """The accepted-grant record, None when absent; malformed raises."""
    try:
        leaf = _leaf(root, create=False)
        if leaf is None:
            return None
        try:
            document = _read(leaf, ACCEPTED)
        finally:
            os.close(leaf)
    except RetireRefused:
        raise
    except Exception:
        raise RetireRefused("accepted-grant record unreadable") from None
    return None if document is None else _check(document, pending=False)


def retirement_pending(root: Path) -> bool:
    """Whether a retirement is unfinished. Unreadable counts as pending."""
    try:
        leaf = _leaf(root, create=False)
        if leaf is None:
            return False
        try:
            os.stat(PENDING, dir_fd=leaf, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        finally:
            os.close(leaf)
    except Exception:
        return True


def _advance(leaf: int, record: dict, *, read_floor, raise_floor, now: str) -> None:
    """Raise the floor to the record's target, confirm it, then clear both files."""
    current = read_floor()
    if current is None:
        raise RetireRefused("activation floor absent")
    target = max(current.approval_seq, record["target_seq"])
    if target >= 2**63:
        raise RetireRefused("approval sequence cannot be advanced")
    raise_floor(replace(current, approval_seq=target), now=now,
                skew_seconds=record["skew_seconds"])
    confirmed = read_floor()
    if confirmed is None or confirmed.approval_seq < record["target_seq"]:
        raise RetireRefused("raised floor not confirmed")
    _remove(leaf, ACCEPTED)
    _remove(leaf, PENDING)


def resume_pending_retirement(*, root: Path, read_floor, raise_floor, now: str) -> str:
    """Finish a retirement that was already classified; needs no trust and no policy.

    `"none"` when nothing is pending, `"resumed"` when it was completed. The
    clock skew the floor raise needs is in the pending record, so a trust or
    policy that cannot be loaded now does not stop the resume.
    """
    try:
        leaf = _leaf(root, create=False)
        if leaf is None:
            return "none"
        try:
            pending = _read(leaf, PENDING)
            if pending is None:
                return "none"
            _advance(leaf, _check(pending, pending=True), read_floor=read_floor,
                     raise_floor=raise_floor, now=now)
        finally:
            os.close(leaf)
    except RetireRefused:
        raise
    except Exception:
        raise RetireRefused("approval retirement failed") from None
    return "resumed"


def retire_if_revoked(*, root: Path, trust, read_floor, raise_floor, now: str,
                      skew_seconds: int) -> str:
    """Retire the accepted approval if its operator is explicitly revoked.

    Returns ``"none"``, ``"retired"`` or ``"resumed"``. `trust` is a freshly
    loaded `OperatorTrust`; `read_floor()` and `raise_floor(value, now=,
    skew_seconds=)` are the high-water readers. A pending retirement is
    resumed first, whatever `trust` says. Raises `RetireRefused` when the
    state cannot be advanced; nothing is granted by this function.
    """
    resumed = resume_pending_retirement(root=root, read_floor=read_floor,
                                        raise_floor=raise_floor, now=now)
    if resumed != "none":
        return resumed
    try:
        leaf = _leaf(root, create=False)
        if leaf is None:
            return "none"
        try:
            accepted = _read(leaf, ACCEPTED)
            if accepted is None:
                return "none"
            accepted = _check(accepted, pending=False)
            if accepted["operator"] not in trust.revoked:
                return "none"
            if type(skew_seconds) is not int or not 0 <= skew_seconds <= _MAX_SKEW:
                raise RetireRefused("clock skew bound refused")
            record = dict(accepted, target_seq=accepted["approval_seq"] + 1,
                          skew_seconds=skew_seconds)
            if record["target_seq"] >= 2**63:
                raise RetireRefused("approval sequence cannot be advanced")
            _write(leaf, PENDING, record)
            _advance(leaf, record, read_floor=read_floor, raise_floor=raise_floor,
                     now=now)
        finally:
            os.close(leaf)
    except RetireRefused:
        raise
    except Exception:
        raise RetireRefused("approval retirement failed") from None
    return "retired"
