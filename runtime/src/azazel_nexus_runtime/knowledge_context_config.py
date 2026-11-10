"""Commissioning bundle loader for the Knowledge Context broker.

Fixed root-owned directory; no environment or command-line switch, no file
creation and no network I/O at load time. Every refusal is a fixed reason code:
parser text, paths, digests, mission strings and key material never leave this
module. Absence of the directory is the default and means "closed".
"""

from __future__ import annotations

import json
import os
import stat
import threading
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from azazel_nexus.knowledge_peer import KnowledgeRefused, load_registry
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy

from .knowledge_egress import KnowledgeClient
from . import runtime_paths
from .runtime_paths import (
    knowledge_context_commission_dir, knowledge_context_observation_rule_path,
)

__all__ = ["CommissioningResult", "load_commissioning", "MANIFEST_SCHEMA",
           "ObservationRule", "load_observation_rule", "OBSERVATION_RULE_SCHEMA"]

MANIFEST_SCHEMA = "azazel.knowledge-context.commissioning/1"
OBSERVATION_RULE_SCHEMA = "azazel.knowledge-context.observation-query/1"
_RULE_LIMIT = 4096
_RULE_KEYS = {"schema", "rule", "max_requests_per_minute"}
ObservationRule = namedtuple("ObservationRule", ("rule", "max_requests_per_minute"))
_OWNER = 0  # structural: tests may monkeypatch to the current uid
_FILES = {  # name -> (max bytes, secret)
    "manifest.json": (64 * 1024, False),
    "registry-keys.json": (16 * 1024, False),
    "registry.signed": (64 * 1024, False),
    "ca.pem": (64 * 1024, False),
    "client.pem": (64 * 1024, False),
    "client.key": (64 * 1024, True),
    "alias.key": (4096, True),
}
_MANIFEST_KEYS = {"schema", "enabled", "peer_id", "client_identity",
                  "commissioning_digest", "max_ttl_seconds", "mission",
                  "sanitizer_policy"}


class _Refused(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, repr=False)
class CommissioningResult:
    status: str  # "commissioned" | "absent" | "refused"
    reason_code: str | None = None
    client: Any = None
    policy: SanitizerPolicy | None = None
    mission: str | None = None
    alias_key: bytes | None = field(default=None)
    registry_version: int | None = None

    def __repr__(self) -> str:
        return f"CommissioningResult(status={self.status!r}, reason_code={self.reason_code!r})"


class _GuardedClient:
    """Latches closed for good once the manifest is removed or replaced."""

    def __init__(self, inner, manifest_path, identity):
        self._inner = inner
        self._path = manifest_path
        self._identity = identity
        self._latched = False
        self._lock = threading.Lock()

    # Only request_context is exposed (the broker calls nothing else,
    # knowledge_contextd.py:113); there is deliberately no attribute delegation.
    def request_context(self, **kwargs):
        with self._lock:
            if not self._latched:
                try:
                    info = os.lstat(self._path)
                    current = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns)
                except OSError:
                    current = None
                if current != self._identity:
                    self._latched = True
            if self._latched:
                raise KnowledgeRefused("commissioning bundle changed")
        return self._inner.request_context(**kwargs)


def _check(info, *, directory, secret=False, limit=0):
    ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not ok:
        raise _Refused("path_unsafe")
    if info.st_uid != _OWNER or info.st_mode & 0o022:
        raise _Refused("perm_unsafe")
    if not directory:
        if info.st_nlink != 1 or not 0 < info.st_size <= limit:
            raise _Refused("path_unsafe")
        if secret and info.st_mode & 0o007:
            raise _Refused("perm_unsafe")
        # Group read is allowed only for the daemon's own effective group (the
        # service group) or root's group (unreadable to a non-root daemon).
        if secret and info.st_mode & 0o040 and info.st_gid not in (os.getegid(), 0):
            raise _Refused("perm_unsafe")


def _open_dir(target=None) -> int | None:
    """Walk from the trust base; None means the bundle directory is absent."""
    if target is None:
        target = knowledge_context_commission_dir()
    base = runtime_paths.ROOT
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(base if str(base) else "/", flags)
    try:
        # The relocation root (AZAZEL_ROOT) is itself the trust base; "/" is
        # checked like any other directory.
        if str(base) == "/":
            _check(os.fstat(fd), directory=True)
        for part in target.relative_to(base).parts:
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                os.close(fd)
                return None
            except OSError:
                raise _Refused("path_unsafe") from None
            os.close(fd)
            fd = child
            _check(os.fstat(fd), directory=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read(dirfd, name):
    limit, secret = _FILES[name]
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=dirfd)
    except FileNotFoundError:
        raise _Refused("manifest_missing" if name == "manifest.json" else "file_missing") from None
    except OSError:
        raise _Refused("path_unsafe") from None
    try:
        before = os.fstat(fd)
        _check(before, directory=False, secret=secret, limit=limit)
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
            raise _Refused("path_unsafe")
        return bytes(data), before
    finally:
        os.close(fd)


def _json(raw, code):
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise _Refused(code) from None


def _load(now: str) -> CommissioningResult:
    dirfd = _open_dir()
    if dirfd is None:
        return CommissioningResult("absent")
    try:
        # Presence of the exact file set first (cheap, no content read).
        names = set(os.listdir(dirfd))
        if "manifest.json" not in names:
            raise _Refused("manifest_missing")
        if names != set(_FILES):
            raise _Refused("bundle_incomplete" if names < set(_FILES) else "bundle_unexpected")
        raw, manifest_stat = _read(dirfd, "manifest.json")
        manifest = _json(raw, "manifest_schema")
        if type(manifest) is not dict or set(manifest) != _MANIFEST_KEYS:
            raise _Refused("manifest_schema")
        if manifest["schema"] != MANIFEST_SCHEMA:
            raise _Refused("manifest_schema")
        if type(manifest["enabled"]) is not bool:
            raise _Refused("manifest_schema")
        if manifest["enabled"] is not True:
            raise _Refused("enabled_not_true")
        for key in ("peer_id", "client_identity", "commissioning_digest", "mission"):
            if type(manifest[key]) is not str or not manifest[key]:
                raise _Refused("manifest_schema")
        ttl = manifest["max_ttl_seconds"]
        if type(ttl) is not int or ttl < 1:
            raise _Refused("ttl_invalid")
        if type(manifest["sanitizer_policy"]) is not dict:
            raise _Refused("manifest_schema")

        keys_doc = _json(_read(dirfd, "registry-keys.json")[0], "registry_keys")
        try:
            if type(keys_doc) is not dict or not keys_doc:
                raise ValueError
            keys = {}
            for name, value in keys_doc.items():
                key = bytes.fromhex(value)
                if type(name) is not str or not name or len(key) != 32:
                    raise ValueError
                keys[name] = key
        except (ValueError, TypeError):
            raise _Refused("registry_keys") from None
        registry_raw = _read(dirfd, "registry.signed")[0]
        try:
            registry = load_registry(registry_raw, keys=keys,
                                     commissioning_digest=manifest["commissioning_digest"],
                                     now=now)
        except KnowledgeRefused:
            # Distinguish expiry from other registry defects without parsing text.
            raise _Refused(_registry_code(registry_raw, keys, manifest, now)) from None
        except Exception:
            raise _Refused("registry_invalid") from None
        try:
            peer = registry.resolve(manifest["peer_id"], now=now)
        except KnowledgeRefused:
            raise _Refused("peer_unknown") from None
        except Exception:
            raise _Refused("registry_invalid") from None
        if peer.endpoint.client_identity != manifest["client_identity"]:
            raise _Refused("identity_mismatch")
        if PrivacyClass.P0_PUBLIC not in peer.endpoint.allowed_privacy_classes:
            raise _Refused("privacy_class")
        try:
            policy = SanitizerPolicy.from_mapping(manifest["sanitizer_policy"])
        except Exception:
            raise _Refused("policy_invalid") from None
        for name in ("ca.pem", "client.pem", "client.key"):
            _read(dirfd, name)
        alias_key = _read(dirfd, "alias.key")[0]
        if len(alias_key) < 32:
            raise _Refused("alias_short")
        base = knowledge_context_commission_dir()
        try:
            client = KnowledgeClient(
                registry=registry, peer_id=manifest["peer_id"],
                ca_certificate=str(base / "ca.pem"),
                identities={manifest["client_identity"]:
                            (str(base / "client.pem"), str(base / "client.key"))},
                knowledge_context_enabled=True,
                knowledge_context_max_ttl_seconds=ttl,
            )
        except Exception:
            raise _Refused("identity_unusable") from None
        guarded = _GuardedClient(
            client, str(base / "manifest.json"),
            (manifest_stat.st_dev, manifest_stat.st_ino,
             manifest_stat.st_mtime_ns, manifest_stat.st_ctime_ns))
        return CommissioningResult(
            "commissioned", client=guarded, policy=policy,
            mission=manifest["mission"], alias_key=alias_key,
            registry_version=registry.version)
    finally:
        os.close(dirfd)


def _registry_code(raw, keys, manifest, now):
    from azazel_nexus.knowledge_peer import REGISTRY_DOMAIN, signed_document, fresh
    try:
        doc, _ = signed_document(raw, domain=REGISTRY_DOMAIN, keys=keys, limit=64 * 1024)
    except Exception:
        return "registry_signature"
    if doc.get("commissioning_digest") != manifest["commissioning_digest"]:
        return "registry_digest"
    try:
        fresh(doc, now)
    except Exception:
        return "registry_expired"
    return "registry_invalid"


def load_commissioning(*, now: str | None = None) -> CommissioningResult:
    """Read and verify the bundle once. Never raises, never communicates."""
    stamp = now if now is not None else datetime.now(UTC).isoformat()
    try:
        return _load(stamp)
    except _Refused as exc:
        return CommissioningResult("refused", exc.code)
    except Exception:
        return CommissioningResult("refused", "path_unsafe")


def _read_rule_file():
    path = knowledge_context_observation_rule_path()
    dirfd = _open_dir(path.parent)
    if dirfd is None:
        return None
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=dirfd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            _check(before, directory=False, limit=_RULE_LIMIT)
            data = os.read(fd, _RULE_LIMIT + 1)
            after = os.fstat(fd)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
                raise _Refused("path_unsafe")
            return data, before
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)


def load_observation_rule():
    """Read the observation-query rule once.

    Returns ``(ObservationRule, identity)`` with identity ``(dev, ino, mtime_ns,
    ctime_ns)``, or None for absence or any defect. Never raises and never says
    why: the caller may only learn "usable" or "not usable".
    """
    try:
        found = _read_rule_file()
        if found is None:
            return None
        data, info = found
        doc = json.loads(data.decode("utf-8"))
        if type(doc) is not dict or set(doc) != _RULE_KEYS:
            return None
        if doc["schema"] != OBSERVATION_RULE_SCHEMA or doc["rule"] != "technique-set/1":
            return None
        limit = doc["max_requests_per_minute"]
        if type(limit) is not int or not 1 <= limit <= 60:
            return None
        return (ObservationRule("technique-set/1", limit),
                (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns))
    except BaseException as exc:  # noqa: BLE001 - never raise, never explain
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        return None
