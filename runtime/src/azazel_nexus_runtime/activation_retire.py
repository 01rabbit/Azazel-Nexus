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

from . import activation_markers

__all__ = [
    "RetireRefused",
    "read_accepted_grant",
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
        document = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise RetireRefused("accepted-grant file malformed") from None
    return document


def _check(document, *, pending: bool) -> dict:
    fields = _FIELDS | ({"target_seq"} if pending else set())
    if (type(document) is not dict or set(document) != fields
            or document["schema"] != SCHEMA
            or type(document["operator"]) is not str or not document["operator"]
            or type(document["approval_id"]) is not str
            or type(document["payload_sha256"]) is not str
            or type(document["units"]) is not list
            or any(type(u) is not str for u in document["units"])
            or type(document["approval_seq"]) is not int
            or not 0 <= document["approval_seq"] < 2**63 - 1):
        raise RetireRefused("accepted-grant record inconsistent")
    if pending and document["target_seq"] != document["approval_seq"] + 1:
        raise RetireRefused("retirement target inconsistent")
    return document


def _write(leaf: int, name: str, document: dict) -> None:
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    partial = "." + name + ".partial"
    try:
        os.unlink(partial, dir_fd=leaf)
    except FileNotFoundError:
        pass
    fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o600, dir_fd=leaf)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, raw)
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


def retire_if_revoked(*, root: Path, trust, read_floor, raise_floor, now: str,
                      skew_seconds: int) -> str:
    """Retire the accepted approval if its operator is explicitly revoked.

    Returns ``"none"``, ``"retired"`` or ``"resumed"``. `trust` is a freshly
    loaded `OperatorTrust`; `read_floor()` and `raise_floor(value, now=,
    skew_seconds=)` are the high-water readers. Raises `RetireRefused` when
    the state cannot be advanced; nothing is granted by this function.
    """
    try:
        leaf = _leaf(root, create=False)
        if leaf is None:
            return "none"
        try:
            pending = _read(leaf, PENDING)
            resumed = pending is not None
            if resumed:
                record = _check(pending, pending=True)
            else:
                accepted = _read(leaf, ACCEPTED)
                if accepted is None:
                    return "none"
                accepted = _check(accepted, pending=False)
                if accepted["operator"] not in trust.revoked:
                    return "none"
                record = dict(accepted, target_seq=accepted["approval_seq"] + 1)
                if record["target_seq"] >= 2**63:
                    raise RetireRefused("approval sequence cannot be advanced")
                _write(leaf, PENDING, record)
            current = read_floor()
            if current is None:
                raise RetireRefused("activation floor absent")
            target = max(current.approval_seq, record["target_seq"])
            if target >= 2**63:
                raise RetireRefused("approval sequence cannot be advanced")
            raise_floor(replace(current, approval_seq=target), now=now,
                        skew_seconds=skew_seconds)
            confirmed = read_floor()
            if confirmed is None or confirmed.approval_seq < record["target_seq"]:
                raise RetireRefused("raised floor not confirmed")
            _remove(leaf, ACCEPTED)
            _remove(leaf, PENDING)
        finally:
            os.close(leaf)
    except RetireRefused:
        raise
    except Exception:
        raise RetireRefused("approval retirement failed") from None
    return "resumed" if resumed else "retired"
