"""Nexus-local signed offline selection packs; not a Fabric wire contract.

Only references to already installed assets are admitted. No extraction,
installer, service activation, network acquisition or Edge authority exists
here. The caller supplies commissioned facts from outside removable media.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .audit import AuditLedger
from .compatibility import HostFacts, TestedTupleSet
from .core_reserve import load_reserve
from .generation import Generation, GenerationStore, _make_store_root
from .lite_import import LiteImport
from .model_import import ModelImport
from .resource_profile import ResourceReading
from .signature import SIGNATURE_BYTES, SignatureRefused, verify_detached

PACK_DOMAIN = b"azazel-nexus/mission-pack/v1\x00"
MANIFEST_SCHEMA = "azazel-nexus/mission-pack/1"
ADMISSION_SCHEMA = "azazel-nexus/mission-pack-admission/1"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_COMPONENTS = 128
MIN_FREE_BYTES = 2 * 1024**3
KINDS = frozenset({"model", "knowledge_lite", "adapter", "policy", "runbook",
                   "reasoning_playbook", "deception_asset"})
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class PackRefused(Exception):
    """No selection was changed; first-install failures leave CORE available."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise PackRefused(reason)


def _json(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate field")
        result[key] = value
    return result


def canonical(document: Mapping) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fields(value, fields) -> None:
    _require(type(value) is dict and set(value) == set(fields), "unknown or missing fields")


def _time(value: str) -> datetime:
    _require(type(value) is str and value.endswith("Z"), "UTC timestamp required")
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        raise PackRefused("invalid timestamp") from None


def _regular(path: Path, limit: int) -> bytes:
    # O_NOFOLLOW also closes the lstat/open symlink substitution window.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        status = os.fstat(stream.fileno())
        _require(stat.S_ISREG(status.st_mode) and status.st_size <= limit,
                 "not a bounded regular file")
        raw = stream.read(limit + 1)
    _require(len(raw) <= limit, "file too large")
    return raw


@dataclass(frozen=True)
class InstalledAsset:
    """Commissioned verified inventory entry, never accepted from a pack.

    Non-model/Lite assets are data or installed adapters. Digest and version
    pins must come from installation verification, not an operator pack.
    """
    path: Path
    digest: str
    size_bytes: int
    version: str
    memory_need_mib: int = 0


@dataclass(frozen=True)
class PackContext:
    root: Path
    trusted_keys: Mapping[str, bytes]
    signing_epoch: int
    revoked_keys: frozenset[str]
    revoked_packs: frozenset[str]
    host: HostFacts
    tuples: TestedTupleSet
    resources: ResourceReading
    reserve_path: Path
    host_digest: str
    commissioning_digest: str
    assets: Mapping[tuple[str, str, str], InstalledAsset]
    allowed_features: frozenset[str] = frozenset()
    models: ModelImport | None = None
    lite: LiteImport | None = None
    max_selected_bytes: int = 64 * 1024**3
    max_pack_bytes: int = MAX_MANIFEST_BYTES
    disk_headroom_bytes: int = MIN_FREE_BYTES


@dataclass(frozen=True)
class VerifiedPack:
    raw: bytes
    manifest: Mapping
    pack_digest: str

    def summary(self) -> dict:
        return {"schema": MANIFEST_SCHEMA, "pack_digest": self.pack_digest,
                "manifest": json.loads(canonical(self.manifest)),
                "authority": "selection only; no Edge authority"}


def inspect_media(media: Path) -> dict:
    """Bounded untrusted preview, explicitly not signature verification."""
    raw = _media(media)
    return {"verified": False, "pack_digest": digest(raw),
            "manifest": _manifest(raw), "authority": "untrusted preview"}


def _media(media: Path) -> bytes:
    _require(media.is_dir() and not media.is_symlink(), "removable-media directory required")
    with os.scandir(media) as entries:
        names = {entry.name for _, entry in zip(range(2), entries)}
    _require(names == {"mission-pack.signed"},
             "media must contain only mission-pack.signed; no payload or installers")
    return _regular(media / "mission-pack.signed", MAX_MANIFEST_BYTES + SIGNATURE_BYTES)


def _manifest(raw: bytes) -> dict:
    _require(SIGNATURE_BYTES < len(raw) <= MAX_MANIFEST_BYTES + SIGNATURE_BYTES,
             "manifest size refused")
    try:
        doc = json.loads(raw[SIGNATURE_BYTES:], object_pairs_hook=_json)
        _fields(doc, {"schema", "pack_version", "signer", "signing_epoch", "issued_at", "expires_at",
                      "rollback_predecessor", "features", "compatibility", "memory_need_mib",
                      "total_size_bytes", "components"})
        _require(doc["schema"] == MANIFEST_SCHEMA, "unknown local manifest schema")
        for name in ("signing_epoch", "memory_need_mib", "total_size_bytes"):
            _require(type(doc[name]) is int and doc[name] >= 0, f"invalid {name}")
        _require(type(doc["signer"]) is str and bool(NAME.fullmatch(doc["signer"])),
                 "invalid signer")
        _version(doc["pack_version"])
        predecessor = doc["rollback_predecessor"]
        _require(predecessor is None or (type(predecessor) is str and
                 bool(DIGEST.fullmatch(predecessor))), "invalid rollback predecessor")
        _require(type(doc["features"]) is list and all(type(f) is str and
                 NAME.fullmatch(f) for f in doc["features"]), "invalid features")
        _require(len(set(doc["features"])) == len(doc["features"]), "duplicate features")
        components = doc["components"]
        _require(type(components) is list and 0 < len(components) <= MAX_COMPONENTS,
                 "invalid component count")
        _require({"adapter", "policy", "runbook", "reasoning_playbook"} <=
                 {c.get("kind") for c in components if type(c) is dict},
                 "missing required selection kinds")
        identities = set()
        for component in components:
            _fields(component, {"kind", "id", "digest", "size_bytes", "version"})
            _require(type(component["kind"]) is str and component["kind"] in KINDS,
                     "component kind not allowlisted")
            _require(type(component["id"]) is str and bool(NAME.fullmatch(component["id"])),
                     "invalid component id")
            _require(type(component["digest"]) is str and
                     bool(DIGEST.fullmatch(component["digest"])), "invalid component digest")
            _require(type(component["size_bytes"]) is int and component["size_bytes"] > 0,
                     "invalid component size")
            _require(type(component["version"]) is str and
                     bool(NAME.fullmatch(component["version"])), "exact asset version required")
            identity = (component["kind"], component["id"])
            _require(identity not in identities, "duplicate component")
            identities.add(identity)
        _require(sum(c["size_bytes"] for c in components) == doc["total_size_bytes"],
                 "total size mismatch")
        return doc
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise PackRefused("malformed manifest") from None


class MissionPack:
    """Offline admission and atomic selection, serialized on trusted storage.

    Storage must be commissioned under the product encrypted-storage boundary.
    Activation publishes selection data only; ActivationController retains
    sole ownership of enabling operational units.
    """
    def __init__(self, context: PackContext, *, checkpoint: Callable[[str], None] | None = None):
        self.context = context
        self.store = GenerationStore(context.root / "generations")
        self.ledger = AuditLedger(context.root / "audit.jsonl")
        self.checkpoint = checkpoint or (lambda step: None)

    def current(self) -> Generation | None:
        path = self.context.root / "current"
        try:
            raw = _regular(path, 256)
        except FileNotFoundError:
            return None
        _require(re.fullmatch(rb"[1-9][0-9]*\n", raw) is not None, "invalid active pointer")
        return self.store.verify(int(raw))

    def status(self, *, now: str | None = None) -> dict:
        generation = self.current()
        reasons = []
        if generation:
            retained = self._retained(generation)
            if retained.pack_digest in self.context.revoked_packs:
                reasons.append("revoked pack")
            if retained.manifest["signer"] in self.context.revoked_keys:
                reasons.append("revoked signer")
            observed = _time(now) if now else datetime.now(UTC)
            if observed >= _time(retained.manifest["expires_at"]):
                reasons.append("expired pack")
        return {"state": "degraded" if reasons else ("active" if generation else "core"),
                "degradation_reasons": reasons,
                "generation": generation.number if generation else None,
                "pack_digest": self._record(generation)["pack_digest"] if generation else None,
                "fallback": "prior admitted selection" if generation else "CORE (no previous provider)",
                "authority": "selection only; ActivationController and Edge unchanged"}

    def verify(self, media: Path, *, now: str) -> VerifiedPack:
        return self._verify(_media(media), now=now, predecessor=True)

    def _verify(self, raw: bytes, *, now: str, predecessor: bool) -> VerifiedPack:
        doc = _manifest(raw)
        ctx = self.context
        pack_digest = digest(raw)
        _require(doc["signer"] not in ctx.revoked_keys and pack_digest not in ctx.revoked_packs,
                 "revoked pack or signer")
        key = ctx.trusted_keys.get(doc["signer"])
        _require(key is not None, "untrusted signer")
        try:
            signed = verify_detached(public_key=key, message=PACK_DOMAIN + raw[SIGNATURE_BYTES:],
                                     signature=raw[:SIGNATURE_BYTES])
        except SignatureRefused:
            signed = False
        _require(signed, "invalid domain-tagged signature")
        _require(doc["signing_epoch"] == ctx.signing_epoch, "signing epoch mismatch")
        _require(_time(doc["issued_at"]) <= _time(now) < _time(doc["expires_at"]),
                 "expired or not yet valid")
        _require(set(doc["features"]) <= ctx.allowed_features, "unsupported feature set")
        matching = [t for t in ctx.tuples.tuples if canonical(t.as_record()) == canonical(doc["compatibility"])]
        _require(bool(matching), "no exact commissioned tested tuple")
        tested = matching[0]
        _require(tested.refusal_for(ctx.host) is None, "incompatible host or security epoch")
        _require(any(c["kind"] == "adapter" and c["digest"] == tested.adapter_digest
                     for c in doc["components"]), "tested adapter must be selected")
        _require(any(c["digest"] == tested.component_digest for c in doc["components"]),
                 "tested component must be selected")
        if predecessor:
            current = self.current()
            previous = self._record(current)["pack_digest"] if current else None
            _require(doc["rollback_predecessor"] == previous, "rollback-unsafe predecessor")
            if current:
                retained = self._retained(current)
                _require(_version(retained.manifest["pack_version"]) >=
                         _version(tested.max_rollback_version),
                         "rollback-unsafe predecessor below tested version floor")
        _require(doc["total_size_bytes"] <= ctx.max_selected_bytes, "selected assets oversized")
        for component in doc["components"]:
            self._asset(component, now)
        floor = sum(ctx.assets[(c["kind"], c["id"], c["digest"])].memory_need_mib
                    for c in doc["components"])
        _require(doc["memory_need_mib"] >= floor, "declared RAM below installed asset requirements")
        _require(ctx.resources.profile is ctx.host.profile, "resource profile mismatch")
        reserve = load_reserve(ctx.reserve_path)
        _require(reserve is not None, "resource gate: HG-05 Core reserve unmeasured")
        _require(reserve.profile is ctx.host.profile and reserve.host_digest == ctx.host_digest,
                 "Core reserve host/profile mismatch")
        _require(reserve.fits(memory_need_mib=doc["memory_need_mib"],
                              envelope_mib=ctx.resources.usable_mib), "RAM/Core reserve envelope exceeded")
        _require(len(raw) <= ctx.max_pack_bytes, "pack exceeds disk budget")
        existing = ctx.root
        while not existing.exists():
            existing = existing.parent
        space = os.statvfs(existing)
        # One new tree, one pointer, audit and metadata; installed assets are
        # referenced, never copied. Keep conservative space for JSON framing.
        _require(space.f_bavail * space.f_frsize >= len(raw) * 4 + 65536 + ctx.disk_headroom_bytes,
                 "insufficient disk budget before staging")
        return VerifiedPack(raw, doc, pack_digest)

    def _asset(self, component: Mapping, now: str) -> None:
        ctx = self.context
        kind, identity = component["kind"], component["id"]
        if kind == "model":
            _require(ctx.models is not None, "model slice not commissioned")
            entry = ctx.models.commissioned.catalog().entry(identity)
            _require(entry is not None and entry.digest == component["digest"] and
                     entry.size_bytes == component["size_bytes"], "model catalog reference mismatch")
            _require(ctx.models.reading_for(identity).refused_by is None,
                     "installed model verification refused")
            _require(component["size_bytes"] <= ctx.max_selected_bytes and
                     ctx.assets.get((kind, identity, component["digest"])) is not None and
                     ctx.assets[(kind, identity, component["digest"])].memory_need_mib >= entry.declared_min_ram_mib,
                     "model memory floor missing from commissioned inventory")
            # Version pin comes from commissioned inventory as for other assets.
        if kind == "knowledge_lite":
            _require(ctx.lite is not None, "Knowledge Lite slice not commissioned")
            accepted = ctx.lite._admitted_bundle()
            _require(accepted is not None and accepted.bundle_digest == component["digest"] and
                     str(accepted.bundle_version) == component["version"],
                     "installed Knowledge Lite reference refused")
            # Reuses the slice's signature/revocation gate; serving remains in
            # LiteImport, including claim time bounds. Pack supplies no claims.
            ctx.lite.read(query_as_of=now)
        asset = ctx.assets.get((kind, identity, component["digest"]))
        _require(asset is not None, "asset not in commissioned verified inventory")
        _require((asset.digest, asset.size_bytes, asset.version) ==
                 (component["digest"], component["size_bytes"], component["version"]),
                 "installed asset pin mismatch")
        try:
            installed_digest = _file_digest(asset.path, asset.size_bytes)
        except FileNotFoundError:
            raise PackRefused("commissioned asset no longer installed") from None
        _require(installed_digest == asset.digest, "installed asset hash or size mismatch")

    def stage(self, media: Path, *, now: str, actor: str, dry_run: bool = False) -> dict:
        pack = self.verify(media, now=now)  # Before ANY local staging write.
        _require(type(actor) is str and 0 < len(actor.strip()) <= 128, "bounded actor required")
        if dry_run:
            return {**pack.summary(), "dry_run": True}
        with self._lock(now=now):
            pack = self._verify(pack.raw, now=now, predecessor=True)
            self.checkpoint("prechecked")
            current = self.current()
            record = {"schema": ADMISSION_SCHEMA, "pack_digest": pack.pack_digest,
                      "predecessor_generation": current.number if current else None,
                      "actor": actor, "admitted_at": now}
            self.checkpoint("before_generation")
            generation = self.store.create(
                {"mission-pack.signed": pack.raw, "admission.json": canonical(record)},
                created_at=now, commissioning_digest=self.context.commissioning_digest)
            self.checkpoint("generation_published")
            self._audit("staged", pack, current, generation, actor, "operator staged", now)
            self.checkpoint("stage_audited")
            return {**pack.summary(), "staged_generation": generation.number}

    def activate(self, number: int, *, now: str, actor: str, reason: str,
                 dry_run: bool = False) -> dict:
        return self._transition(number, now=now, actor=actor, reason=reason,
                                dry_run=dry_run, rollback=False)

    def rollback(self, *, now: str, actor: str, reason: str, dry_run: bool = False) -> dict:
        current = self.current()
        _require(current is not None, "no predecessor; CORE (no previous provider)")
        number = self._record(current)["predecessor_generation"]
        _require(type(number) is int, "no rollback predecessor")
        return self._transition(number, now=now, actor=actor, reason=reason,
                                dry_run=dry_run, rollback=True)

    def _transition(self, number, *, now, actor, reason, dry_run, rollback):
        _require(type(number) is int and number > 0, "invalid generation number")
        _require(type(actor) is str and 0 < len(actor.strip()) <= 128 and
                 type(reason) is str and 0 < len(reason.strip()) <= 2048,
                 "bounded actor and reason required")
        # Read-only preflight even for a dry run; trust/assets/resources rechecked.
        pack, target = self._candidate(number, now=now, rollback=rollback)
        if dry_run:
            return {**pack.summary(), "dry_run": True, "target_generation": number}
        with self._lock(now=now):
            pack, target = self._candidate(number, now=now, rollback=rollback)
            current = self.current()
            action = "rollback" if rollback else "activation"
            if rollback:
                # Native GenerationStore rollback makes history monotonic.
                record = dict(self._record(target))
                record.update(predecessor_generation=current.number, actor=actor, admitted_at=now)
                target = self.store.create(
                    {"mission-pack.signed": pack.raw, "admission.json": canonical(record)},
                    created_at=now, commissioning_digest=self.context.commissioning_digest,
                    rolled_back_from=current.number, rollback_reason=reason, actor=actor,
                    expected_latest_generation=self.store.current().number)
                self.checkpoint("rollback_generation_published")
            self.checkpoint("before_intent")
            self._audit(action + ".commit_intent", pack, current, target, actor, reason, now)
            self.checkpoint("intent_durable")
            _pointer(self.context.root / "current", target.number, self.checkpoint)
            self.checkpoint("pointer_durable")
            self._audit(action + ".completed", pack, current, target, actor, reason, now)
            self.checkpoint("completion_audited")
            return self.status(now=now)

    def _candidate(self, number, *, now, rollback):
        generation = self.store.verify(number)
        record = self._record(generation)
        self.ledger.verify()
        _require(any(e.event.get("event_type") in {"mission_pack.staged",
                     "mission_pack.rollback.commit_intent"} and
                     e.event.get("to_generation") == number and
                     e.event.get("to_digest") == generation.digest and
                     e.event.get("pack_digest") == record["pack_digest"]
                     for e in self.ledger), "generation lacks durable admission audit")
        raw = self.store.read_tree(number)["mission-pack.signed"]
        _require(record["pack_digest"] == digest(raw), "admission digest mismatch")
        pack = self._verify(raw, now=now, predecessor=not rollback)
        current = self.current()
        _require(current is None or current.number != number, "generation already active")
        if rollback:
            _require(current is not None, "no active rollback source")
            active_manifest = self._retained(current).manifest
            _require(_version(pack.manifest["pack_version"]) >=
                     _version(active_manifest["compatibility"]["max_rollback_version"]),
                     "rollback version below tested floor")
            _require(current is not None and self._record(current)["predecessor_generation"] == number,
                     "rollback target is not prior admitted generation")
        else:
            _require(record["predecessor_generation"] == (current.number if current else None),
                     "stale staged predecessor")
        return pack, generation

    def _retained(self, generation: Generation) -> VerifiedPack:
        # Storage integrity/ancestry only. Current trust and time gates belong
        # to candidates, including a retained pack selected as a rollback target.
        self.store.verify(generation.number)
        record = self._record(generation)
        raw = self.store.read_tree(generation.number)["mission-pack.signed"]
        _require(record["pack_digest"] == digest(raw), "admission digest mismatch")
        return VerifiedPack(raw, _manifest(raw), digest(raw))

    def recover(self, *, now: str) -> None:
        """Reconcile a published intent under the writer lock; never move current."""
        with self._lock(now=now):
            pass

    def _recover(self, *, now: str) -> None:
        self.ledger.verify()
        entries = list(self.ledger)
        intents = [e for e in entries if e.event.get("event_type") in {
            "mission_pack.activation.commit_intent", "mission_pack.rollback.commit_intent"}]
        if not intents:
            return
        intent = intents[-1]
        completed = intent.event["event_type"].replace(".commit_intent", ".completed")
        if any(e.sequence > intent.sequence and e.event.get("event_type") == completed
               and all(e.event.get(k) == intent.event[k] for k in (
                   "from_generation", "to_generation", "from_digest", "to_digest", "pack_digest"))
               for e in entries):
            return
        current = self.current()
        if current and (current.number, current.digest) == (
                intent.event["to_generation"], intent.event["to_digest"]):
            pack = self._retained(current)
            _require(pack.pack_digest == intent.event["pack_digest"], "recovery intent pack mismatch")
            # Persist the observed publication before attesting its completion.
            parent = os.open(self.context.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            self.ledger.append({**intent.event, "event_type": completed,
                                "recovered_at": now, "commit_intent_hash": intent.event_hash})

    def _record(self, generation: Generation) -> dict:
        _require(generation.commissioning_digest == self.context.commissioning_digest,
                 "generation commissioning mismatch")
        record = json.loads(self.store.read_tree(generation.number)["admission.json"],
                            object_pairs_hook=_json)
        _fields(record, {"schema", "pack_digest", "predecessor_generation", "actor", "admitted_at"})
        _require(record["schema"] == ADMISSION_SCHEMA, "unknown local admission schema")
        return record

    def _audit(self, action, pack, previous, target, actor, reason, now):
        self.ledger.verify()
        self.ledger.append({"event_type": "mission_pack." + action, "at": now,
                            "actor": actor, "reason": reason, "pack_digest": pack.pack_digest,
                            "from_generation": previous.number if previous else None,
                            "to_generation": target.number,
                            "from_digest": previous.digest if previous else None,
                            "to_digest": target.digest})
        # AuditLedger syncs its file; persist a newly created directory entry
        # before any active pointer can reference this admission/intent.
        parent = os.open(self.context.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)

    @contextmanager
    def _lock(self, *, now):
        # Trusted encrypted state, single writer. Removable media never names it.
        _make_store_root(self.context.root)
        fd = os.open(self.context.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PackRefused("Mission Pack writer already active") from None
            self._recover(now=now)
            yield
        finally:
            os.close(fd)


def _version(value) -> tuple[int, ...]:
    _require(type(value) is str and re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value)
             is not None, "local pack version must be major.minor.patch")
    return tuple(int(part) for part in value.split("."))


def _file_digest(path: Path, size: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_size == size, "installed asset size mismatch")
        value = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = stream.read(min(8 * 1024**2, remaining))
            _require(bool(chunk), "installed asset truncated")
            value.update(chunk)
            remaining -= len(chunk)
        _require(not stream.read(1), "installed asset grew")
    return "sha256:" + value.hexdigest()


def _pointer(path: Path, number: int, checkpoint) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".pack-pointer-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(f"{number}\n".encode())
            stream.flush()
            os.fsync(stream.fileno())
        checkpoint("pointer_prepared")
        os.replace(temporary, path)
        checkpoint("pointer_replaced")
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
