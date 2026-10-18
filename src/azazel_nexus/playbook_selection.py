"""Read-only Mission Pack references; failures remove optional advisory data."""
from __future__ import annotations

import json
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .generation import GenerationRefused
from .mission_pack import (
    PACK_DOMAIN,
    InstalledAsset,
    MissionPack,
    PackContext,
    PackRefused,
    _json,
    _regular,
    _time,
)
from .reasoning_playbook import Library, PlaybookRefused, compose, load_library
from .signature import (
    SIGNATURE_BYTES,
    SignatureRefused,
    parse_public_key,
    verify_detached,
)


@dataclass(frozen=True)
class SelectionContext:
    """The commissioned subset needed for status and retained generation reads."""
    root: Path
    trusted_keys: Mapping[str, bytes]
    signing_epoch: int
    revoked_keys: frozenset[str]
    revoked_packs: frozenset[str]
    commissioning_digest: str
    assets: Mapping[tuple[str, str, str], InstalledAsset]


def selection_context(config: Path, root: Path) -> SelectionContext:
    """Read the existing CLI config without admission probes or any writes.

    Encrypted storage and read permissions are provisioning prerequisites.
    This consumer does not admit/activate packs or rerun hardware probes.
    """
    info = config.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PackRefused('unsafe commissioned config')
    doc = json.loads(_regular(config, 1024 * 1024), object_pairs_hook=_json)
    if doc['schema'] != 'azazel-nexus/mission-pack-config/1':
        raise PackRefused('unknown commissioned config schema')
    assets = {}
    for raw in doc['assets']:
        key = (raw['kind'], raw['id'], raw['digest'])
        if key in assets:
            raise PackRefused('duplicate commissioned asset')
        assets[key] = InstalledAsset(Path(raw['path']), raw['digest'], raw['size_bytes'],
                                     raw['version'], raw['memory_need_mib'])
    return SelectionContext(
        root, {k: parse_public_key(v) for k, v in doc['trusted_keys'].items()},
        doc['signing_epoch'], frozenset(doc['revoked_keys']), frozenset(doc['revoked_packs']),
        doc['commissioning_digest'], assets)


@dataclass(frozen=True)
class PlaybookSelection:
    library: Library | None
    reason: str
    ids: tuple[str, ...] = ()
    versions: tuple[str, ...] = ()
    digests: tuple[str, ...] = ()
    expires_at: str | None = None
    watch_paths: tuple[Path, ...] = ()

    def as_event(self) -> dict:
        return {'event_type': 'mio.local.playbook_selection', 'reason': self.reason,
                'ids': list(self.ids), 'versions': list(self.versions), 'digests': list(self.digests)}


def retained_paths(root: Path) -> tuple[Path, ...]:
    """Discover retained files without verifying or composing their contents."""
    try:
        raw = _regular(root / 'current', 256)
    except FileNotFoundError:
        return ()
    if not (raw.endswith(b'\n') and raw[:-1].isdigit()
            and raw == str(int(raw)).encode() + b'\n' and int(raw) > 0):
        raise PackRefused('invalid active pointer')
    tree = root / 'generations' / str(int(raw))
    return (tree, tree / 'tree', tree / 'generation.json',
            tree / 'tree' / 'mission-pack.signed', tree / 'tree' / 'admission.json')


def active_playbooks(context: PackContext | SelectionContext, *, now: str) -> PlaybookSelection:
    """Resolve only ACTIVE retained selections, with current trust and exact pins.

    MissionPack.status and _retained provide generation/admission integrity and
    degradation checks. Retained ancestry deliberately skips signature/epoch
    checks, so this consumer additionally checks them before using any prose.
    """
    try:
        # GenerationStore wraps metadata OSErrors as GenerationRefused. Read the
        # retained files first so permission failures keep their fixed reason.
        for path in retained_paths(context.root)[2:]:
            _regular(path, 16 * 1024 * 1024)
        service = MissionPack(context)
        status = service.status(now=now)
        if status['state'] == 'core':
            return PlaybookSelection(None, 'no_pack')
        if status['state'] != 'active':
            return PlaybookSelection(None, 'pack_degraded')
        generation = service.store.verify(status['generation'])
        pack = service._retained(generation)
        doc = pack.manifest
        key = context.trusted_keys.get(doc['signer'])
        if (key is None or doc['signing_epoch'] != context.signing_epoch
                or not _time(doc['issued_at']) <= _time(now) < _time(doc['expires_at'])
                or not verify_detached(public_key=key, message=PACK_DOMAIN + pack.raw[SIGNATURE_BYTES:],
                                       signature=pack.raw[:SIGNATURE_BYTES])):
            return PlaybookSelection(None, 'pack_degraded')
        layers = []
        paths = []
        for component in doc['components']:
            if component['kind'] != 'reasoning_playbook':
                continue
            asset = context.assets.get(('reasoning_playbook', component['id'], component['digest']))
            if asset is None:
                return PlaybookSelection(None, 'asset_missing')
            if (asset.digest, asset.version, asset.size_bytes) != (
                    component['digest'], component['version'], component['size_bytes']):
                return PlaybookSelection(None, 'digest_mismatch')
            try:
                info = asset.path.lstat()
            except FileNotFoundError:
                return PlaybookSelection(None, 'asset_missing')
            if info.st_size != component['size_bytes']:
                return PlaybookSelection(None, 'digest_mismatch')
            layers.append(load_library(asset.path, component['digest']))
            paths.append(asset.path)
            if layers[-1].version != component['version']:
                return PlaybookSelection(None, 'invalid_library')
        if not layers:
            return PlaybookSelection(None, 'none_selected')
        baselines = [layer for layer in layers if layer.layer == 'baseline']
        if len(baselines) > 1:
            return PlaybookSelection(None, 'multiple_baselines')
        if not baselines:
            return PlaybookSelection(None, 'invalid_library')
        library = compose(baselines[0], *(layer for layer in layers if layer.layer == 'site'))
        if service.current() != generation:
            return PlaybookSelection(None, 'pack_degraded')
        # Watch retained bytes too: a damaged active generation drops cached references.
        tree = service.store.root / str(generation.number)
        return PlaybookSelection(library, 'active',
                                 tuple(layer.library_id for layer in library.layers),
                                 tuple(layer.version for layer in library.layers),
                                 tuple(layer.digest for layer in library.layers), doc['expires_at'],
                                 (*paths, tree / 'generation.json', tree / 'tree' / 'mission-pack.signed',
                                  tree / 'tree' / 'admission.json'))
    except PermissionError:
        return PlaybookSelection(None, 'store_unreadable')
    except PlaybookRefused as error:
        reason = 'digest_mismatch' if str(error) == 'digest_mismatch' else 'invalid_library'
        return PlaybookSelection(None, reason)
    except (OSError, ValueError, TypeError, KeyError, GenerationRefused, PackRefused, SignatureRefused):
        return PlaybookSelection(None, 'pack_degraded')
