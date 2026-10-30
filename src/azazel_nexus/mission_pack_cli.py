"""Thin offline pack CLI; all commissioning input stays outside the media."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from . import platform_profile
from .compatibility import HostFacts, TestedTuple, TestedTupleSet
from .hil_preflight import luks_backed
from .lite_import import CommissionedLite, LiteImport
from .mission_pack import (
    InstalledAsset,
    MissionPack,
    PackContext,
    PackRefused,
    _json,
    _regular,
    inspect_media,
    refuse_lab_host,
)
from .model_import import CommissionedModels, ModelImport
from .model_paths import load_model_trust
from .resource_profile import ResourceProfile, take_reading
from .signature import parse_public_key

CONFIG = Path("/etc/azazel/mission-pack.json")
STATE = Path("/data/azazel/mission-packs")


def add_parser(sub):
    pack = sub.add_parser("pack", help="offline signed Mission Pack selection lifecycle")
    operations = pack.add_subparsers(dest="pack_operation", required=True)
    for name in ("inspect", "verify", "stage", "activate", "rollback"):
        operation = operations.add_parser(name)
        operation.add_argument("--dry-run", action="store_true", help="validate without writes")
        if name in {"inspect", "verify", "stage"}:
            operation.add_argument("media", type=Path, help="removable-media directory")
        if name == "activate":
            operation.add_argument("generation", type=int, help="reviewed staged generation")
        if name in {"stage", "activate", "rollback"}:
            operation.add_argument("--actor", required=True)
        if name in {"activate", "rollback"}:
            operation.add_argument("--reason", required=True)


def _observed_architecture(declared: object) -> str:
    """The kernel's CPU, never the configuration's (ADR-0003 R5).

    The commissioned config still declares ``host.architecture``; a value that
    differs from what this kernel reports is refused rather than overridden,
    and a CPU outside the reviewed table is refused by name. The result is the
    kernel spelling `HostFacts`/`TestedTuple` compare (``x86_64``), so an
    arm64 host never matches the x86_64 tested tuples.
    """

    machine = os.uname().machine
    try:
        architecture = platform_profile.from_boundary("kernel", machine)
    except platform_profile.PlatformRefused as refused:
        raise PackRefused(f"host architecture refused: {refused.reason}") from None
    if declared != machine:
        raise PackRefused(
            "commissioned host architecture differs from the observed "
            f"{platform_profile.fabric_name(architecture)} kernel")
    return machine


def _context() -> PackContext:
    # The CLI has no trust/root/egress overrides. Provisioning owns this file
    # and the encrypted /data volume. No test or guessed HG-05 values here.
    status = CONFIG.lstat()
    if not stat.S_ISREG(status.st_mode) or status.st_uid != 0 or status.st_mode & 0o022:
        raise PackRefused("commissioned config must be root-owned and private from writers")
    existing = STATE
    while not existing.exists():
        existing = existing.parent
    if not luks_backed(existing):
        raise PackRefused("Mission Pack state requires commissioned encrypted storage")
    doc = json.loads(_regular(CONFIG, 1024 * 1024), object_pairs_hook=_json)
    if doc["schema"] != "azazel-nexus/mission-pack-config/1":
        raise PackRefused("unknown commissioned config schema")
    facts = dict(doc["host"])
    facts["architecture"] = _observed_architecture(facts.get("architecture"))
    facts["profile"] = ResourceProfile(facts["profile"])
    for name in ("cpu_features", "fabric_features", "schema_features"):
        facts[name] = frozenset(facts[name])
    tuples = []
    for raw in doc["tested_tuples"]:
        raw = dict(raw)
        raw["profile"] = ResourceProfile(raw["profile"])
        for name in ("cpu_features", "fabric_features", "schema_features"):
            raw[name] = frozenset(raw[name])
        tuples.append(TestedTuple(**raw))
    assets = {}
    for raw in doc["assets"]:
        key = (raw["kind"], raw["id"], raw["digest"])
        if key in assets:
            raise PackRefused("duplicate commissioned asset")
        assets[key] = InstalledAsset(Path(raw["path"]), raw["digest"], raw["size_bytes"],
                                     raw["version"], raw["memory_need_mib"])
    models = None
    if doc.get("models_root"):
        root = Path(doc["models_root"])
        keys, commissioning, _ = load_model_trust(root / "trust/trust.json")
        if commissioning != doc["commissioning_digest"]:
            raise PackRefused("model commissioning mismatch")
        models = ModelImport(CommissionedModels(root, keys, commissioning))
    return PackContext(
        root=STATE,
        trusted_keys={k: parse_public_key(v) for k, v in doc["trusted_keys"].items()},
        signing_epoch=doc["signing_epoch"], revoked_keys=frozenset(doc["revoked_keys"]),
        revoked_packs=frozenset(doc["revoked_packs"]), host=HostFacts(**facts),
        tuples=TestedTupleSet.of(tuples), resources=take_reading(),
        reserve_path=Path(doc["reserve_path"]), host_digest=doc["host_digest"],
        commissioning_digest=doc["commissioning_digest"], assets=assets,
        allowed_features=frozenset(doc["allowed_features"]), models=models,
        lite=LiteImport(CommissionedLite(Path(doc["lite_root"]))) if doc.get("lite_root") else None,
        max_pack_bytes=doc["max_pack_bytes"], max_selected_bytes=doc["max_selected_bytes"],
        disk_headroom_bytes=doc["disk_headroom_bytes"],
    )


def run(args, *, now, out):
    service = None
    try:
        if args.pack_operation == "inspect":
            result = inspect_media(args.media)
        else:
            if (args.pack_operation in {"stage", "activate", "rollback"}
                    and not args.dry_run and os.geteuid() != 0):
                raise PackRefused("root required for local state writes")
            refuse_lab_host()  # Before the commissioned config or state is read.
            service = MissionPack(_context())
            if args.pack_operation == "verify":
                result = service.verify(args.media, now=now).summary()
            elif args.pack_operation == "stage":
                result = service.stage(args.media, now=now, actor=args.actor, dry_run=args.dry_run)
            elif args.pack_operation == "activate":
                result = service.activate(args.generation, now=now, actor=args.actor,
                                          reason=args.reason, dry_run=args.dry_run)
            else:
                result = service.rollback(now=now, actor=args.actor, reason=args.reason,
                                          dry_run=args.dry_run)
        print(json.dumps(result, sort_keys=True), file=out)
        return 0
    except Exception as refused:  # noqa: BLE001 - CLI boundary fails closed
        # Do not print configuration/key material.
        detail = str(refused) if isinstance(refused, PackRefused) else "local verification/state unavailable"
        try:
            state = service.status() if service else {"fallback": "CORE (no previous provider verified)"}
        except Exception:  # noqa: BLE001 - unreadable state cannot promise a provider
            state = {"fallback": "CORE (no previous provider verified); inspect local state"}
        print(json.dumps({"refused": detail, **state}, sort_keys=True), file=out)
        return 1
