"""Test-signed active selections; no production trust or hardware evidence."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_mission_pack import NOW, stage_activate

from azazel_nexus import mission_pack as mp
from azazel_nexus.playbook_selection import active_playbooks, selection_context

pytest_plugins = ['test_mission_pack']

FIXTURE = Path(__file__).parents[1] / 'fixtures/reasoning-playbook.json'


@pytest.fixture
def selection_node(node):
    ctx, doc, media = node
    assets = dict(ctx.assets)
    doc = json.loads(mp.canonical(doc))
    doc['components'] = [c for c in doc['components'] if c['kind'] != 'reasoning_playbook']

    def add(document, identity):
        raw = mp.canonical(document)
        path = ctx.root.parent.parent / (identity + '.json')
        path.write_bytes(raw)
        pin = mp.digest(raw)
        assets[('reasoning_playbook', identity, pin)] = mp.InstalledAsset(
            path, pin, len(raw), document['version'])
        doc['components'].append({'kind': 'reasoning_playbook', 'id': identity, 'digest': pin,
                                  'size_bytes': len(raw), 'version': document['version']})
        doc['total_size_bytes'] = sum(c['size_bytes'] for c in doc['components'])
        return path

    baseline = json.loads(FIXTURE.read_bytes())
    add(baseline, 'baseline')
    ctx = replace(ctx, assets=assets)
    return ctx, doc, media, add, baseline


def activate(selection_node):
    ctx, doc, media, _, _ = selection_node
    service = mp.MissionPack(ctx)
    stage_activate(service, media(doc))
    return ctx


def test_no_pack_is_readonly(selection_node):
    ctx = selection_node[0]
    assert active_playbooks(ctx, now=NOW).reason == 'no_pack'
    assert not ctx.root.exists()


def test_baseline_site_override_manifest_site_order(selection_node):
    ctx, _, _, add, baseline = selection_node
    site = dict(baseline, library_id='site-one', layer='site')
    site['entries'][0]['status'] = 'reviewed'
    add(site, 'site-one')
    add(dict(site, library_id='site-two', entries=[], disable=[site['entries'][0]['id']]), 'site-two')
    # A site can precede the baseline in the signed component list.
    components = selection_node[1]['components']
    components.insert(0, components.pop(-2))
    activate(selection_node)
    result = active_playbooks(ctx, now=NOW)
    assert result.reason == 'active'
    assert result.ids == (baseline['library_id'], 'site-one', 'site-two')
    assert result.library.entries == ()
    assert result.digests == tuple(layer.digest for layer in result.library.layers)


@pytest.mark.parametrize('mode', ['expired', 'revoked_key', 'revoked_pack', 'epoch', 'untrusted'])
def test_degraded_active_never_supplies_library(selection_node, mode):
    ctx = activate(selection_node)
    if mode == 'revoked_key':
        ctx = replace(ctx, revoked_keys=frozenset({'fixture'}))
    elif mode == 'revoked_pack':
        ctx = replace(ctx, revoked_packs=frozenset({mp.MissionPack(ctx).status(now=NOW)['pack_digest']}))
    elif mode == 'epoch':
        ctx = replace(ctx, signing_epoch=4)
    elif mode == 'untrusted':
        ctx = replace(ctx, trusted_keys={})
    result = active_playbooks(ctx, now='2026-11-01T00:00:00Z' if mode == 'expired' else NOW)
    assert (result.library, result.reason) == (None, 'pack_degraded')


@pytest.mark.parametrize('mode,reason', [
    ('digest', 'digest_mismatch'), ('missing', 'asset_missing'),
    ('inventory', 'asset_missing'), ('two', 'multiple_baselines'),
    ('invalid', 'invalid_library'), ('site_only', 'invalid_library'),
])
def test_failure_drops_library(selection_node, mode, reason):
    ctx, _, _, add, baseline = selection_node
    if mode == 'two':
        add(dict(baseline, library_id='second-baseline'), 'second-baseline')
    elif mode == 'invalid':
        add(dict(baseline, library_id='invalid', unexpected=True), 'invalid')
    elif mode == 'site_only':
        key = next(k for k in ctx.assets if k[0] == 'reasoning_playbook' and k[1] == 'baseline')
        # Replace the selected baseline with a valid site layer before admission.
        selection_node[1]['components'] = [c for c in selection_node[1]['components']
                                             if c['kind'] != 'reasoning_playbook']
        del ctx.assets[key]
        add(dict(baseline, layer='site'), 'only-site')
    activate(selection_node)
    asset = next(v for k, v in ctx.assets.items() if k[:2] == ('reasoning_playbook', 'baseline')) if mode != 'site_only' else None
    if mode == 'digest':
        raw = asset.path.read_bytes()
        asset.path.write_bytes(raw.replace(b'template', b'reviewed'))
    elif mode == 'missing':
        asset.path.unlink()
    elif mode == 'inventory':
        ctx = replace(ctx, assets={})
    result = active_playbooks(ctx, now=NOW)
    assert (result.library, result.reason) == (None, reason)


@pytest.mark.parametrize("mode", [0o600, 0o640])
def test_config_reader_existing_schema_and_ownership(selection_node, tmp_path, monkeypatch, mode):
    ctx = selection_node[0]
    config = tmp_path / 'mission-pack.json'
    doc = {'schema': 'azazel-nexus/mission-pack-config/1', 'assets': [],
           'trusted_keys': {k: v.hex() for k, v in ctx.trusted_keys.items()},
           'signing_epoch': ctx.signing_epoch, 'revoked_keys': [], 'revoked_packs': [],
           'commissioning_digest': ctx.commissioning_digest}
    config.write_text(json.dumps(doc))
    config.chmod(mode)
    original = Path.lstat

    def root_owned(path):
        info = original(path)
        from types import SimpleNamespace
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0)

    monkeypatch.setattr(Path, 'lstat', root_owned)
    loaded = selection_context(config, ctx.root)
    assert loaded.trusted_keys == ctx.trusted_keys
    assert active_playbooks(loaded, now=NOW).reason == 'no_pack'
    for unsafe in (0o620, 0o602, 0o660, 0o666):
        config.chmod(unsafe)
        with pytest.raises(mp.PackRefused):
            selection_context(config, ctx.root)


def test_holder_generation_reload_cache_damage_and_expiry(selection_node, monkeypatch):
    from azazel_nexus_runtime import mio_playbooks

    ctx = activate(selection_node)
    _, doc, media, add, baseline = selection_node
    config = ctx.root.parent / 'config.json'
    config.write_text('{}')  # Reader is injected; real config ownership is tested above.
    reads = []
    monkeypatch.setattr(mio_playbooks, 'selection_context', lambda *args: reads.append(args) or ctx)
    clock = [NOW]
    holder = mio_playbooks.PlaybookSelectionHolder(config=config, root=ctx.root, clock=lambda: clock[0])
    events = []
    first = holder.refresh(audit=events.append)
    assert first is not None
    assert holder.refresh(audit=events.append) is first
    assert len(reads) == 1
    assert len(events) == 1
    assert set(events[0]) == {'event_type', 'reason', 'ids', 'versions', 'digests'}
    service = mp.MissionPack(ctx)
    doc.update(pack_version='2.0.0', rollback_predecessor=service.status(now=NOW)['pack_digest'])
    add(dict(baseline, layer='site', library_id='disable-all', entries=[],
             disable=[baseline['entries'][0]['id']]), 'disable-all')
    stage_activate(service, media(doc))
    second = holder.refresh(audit=events.append)
    assert second.entries == () and second != first
    assert events[-1]['ids'][-1] == 'disable-all'
    event_count = len(events)
    assert holder.refresh(audit=events.append) is second
    assert len(events) == event_count
    # A changed inventory/trust config rechecks current trust with no pointer change.
    monkeypatch.setattr(mio_playbooks, 'selection_context', lambda *args: replace(ctx, signing_epoch=99))
    config.write_text('{"changed":true}')
    assert holder.refresh(audit=events.append) is None
    assert events[-1]['reason'] == 'pack_degraded'
    monkeypatch.setattr(mio_playbooks, 'selection_context', lambda *args: ctx)
    config.write_text('{}')
    assert holder.refresh(audit=events.append) is not None
    asset = next(v for k, v in ctx.assets.items() if k[1] == 'disable-all')
    original = asset.path.read_bytes()
    asset.path.write_bytes(b'x' * len(original))
    assert holder.refresh(audit=events.append) is None
    assert events[-1]['reason'] == 'digest_mismatch'
    asset.path.write_bytes(original)
    assert holder.refresh(audit=events.append) is not None
    clock[0] = '2026-11-01T00:00:00Z'
    assert holder.refresh(audit=events.append) is None
    assert events[-1]['reason'] == 'pack_degraded'
    (ctx.root / 'current').unlink()
    assert holder.refresh(audit=events.append) is None
    assert events[-1]['reason'] == 'no_pack'


def test_tampered_retained_tree_is_degraded(selection_node):
    ctx = activate(selection_node)
    generation = mp.MissionPack(ctx).current()
    path = ctx.root / 'generations' / str(generation.number) / 'tree' / 'mission-pack.signed'
    path.write_bytes(path.read_bytes() + b' ')
    assert active_playbooks(ctx, now=NOW).reason == 'pack_degraded'


def test_retained_integrity_alone_does_not_replace_signature_check(selection_node):
    ctx = activate(selection_node)
    service = mp.MissionPack(ctx)
    current = service.current()
    tree = service.store.read_tree(current.number)
    raw = tree['mission-pack.signed']
    tree['mission-pack.signed'] = bytes([raw[0] ^ 1]) + raw[1:]
    record = json.loads(tree['admission.json'])
    record['pack_digest'] = mp.digest(tree['mission-pack.signed'])
    tree['admission.json'] = mp.canonical(record)
    generation = service.store.create(tree, created_at=NOW, commissioning_digest=ctx.commissioning_digest)
    (ctx.root / 'current').write_text(str(generation.number) + '\n')
    assert service.status(now=NOW)['state'] == 'active'
    before = {str(p): p.read_bytes() for p in ctx.root.rglob('*') if p.is_file()}
    assert active_playbooks(ctx, now=NOW).reason == 'pack_degraded'
    assert {str(p): p.read_bytes() for p in ctx.root.rglob('*') if p.is_file()} == before


@pytest.mark.parametrize('failure', ['missing', 'degraded', 'tree', 'no_pack', 'expired'])
def test_holder_caches_failures_and_recovers_on_metadata_change(selection_node, monkeypatch, failure):
    from azazel_nexus_runtime import mio_playbooks

    ctx = activate(selection_node)
    config = ctx.root.parent / 'config.json'
    config.write_text('{}')
    asset = next(v for k, v in ctx.assets.items() if k[:2] == ('reasoning_playbook', 'baseline'))
    target = asset.path
    if failure == 'tree':
        generation = mp.MissionPack(ctx).current()
        target = ctx.root / 'generations' / str(generation.number) / 'tree' / 'mission-pack.signed'
    elif failure == 'no_pack':
        target = ctx.root / 'current'
    original = target.read_bytes()
    if failure in ('missing', 'no_pack'):
        target.unlink()
    elif failure == 'tree':
        target.write_bytes(original + b' ')
    reads = []
    active_context = [replace(ctx, signing_epoch=99) if failure == 'degraded' else ctx]
    monkeypatch.setattr(mio_playbooks, 'selection_context',
                        lambda *args: reads.append(args) or active_context[0])
    clock = ['2026-11-01T00:00:00Z' if failure == 'expired' else NOW]
    holder = mio_playbooks.PlaybookSelectionHolder(config=config, root=ctx.root, clock=lambda: clock[0])
    events = []
    assert holder.refresh(audit=events.append) is None
    count = len(reads)
    for _ in range(3):
        assert holder.refresh(audit=events.append) is None
    assert len(reads) == count
    assert len(events) == 1
    if failure == 'degraded':
        active_context[0] = ctx
        config.write_text('{"restored":true}')
    else:
        target.write_bytes(original)
    clock[0] = NOW
    assert holder.refresh(audit=events.append) is not None
    assert len(events) == 2


@pytest.mark.parametrize('location', ['current', 'generation', 'pack', 'config'])
def test_permission_failures_are_store_unreadable(selection_node, monkeypatch, location):
    from azazel_nexus_runtime import mio_playbooks

    ctx = activate(selection_node)
    generation = mp.MissionPack(ctx).current()
    tree = ctx.root / 'generations' / str(generation.number)
    config = ctx.root.parent / 'config.json'
    config.write_text('{}')
    denied = {'current': ctx.root / 'current', 'generation': tree / 'generation.json',
              'pack': tree / 'tree' / 'mission-pack.signed', 'config': config}[location]
    from azazel_nexus import playbook_selection

    original = playbook_selection._regular

    def read(path, limit):
        if path == denied:
            raise PermissionError('test denial')
        return original(path, limit)

    monkeypatch.setattr(playbook_selection, '_regular', read)
    if location != 'config':
        assert active_playbooks(ctx, now=NOW).reason == 'store_unreadable'
    def context(*args):
        if location == 'config':
            raise PermissionError('test denial')
        return ctx

    monkeypatch.setattr(mio_playbooks, 'selection_context', context)
    holder = mio_playbooks.PlaybookSelectionHolder(config=config, root=ctx.root, clock=lambda: NOW)
    events = []
    assert holder.refresh(audit=events.append) is None
    assert events[-1]['reason'] == 'store_unreadable'
    assert holder.refresh(audit=events.append) is None
    assert len(events) == 1


def test_no_playbook_components_is_none_selected(selection_node, monkeypatch):
    ctx = activate(selection_node)
    original = mp.MissionPack._retained

    def retained(service, generation):
        pack = original(service, generation)
        manifest = dict(pack.manifest, components=[c for c in pack.manifest['components']
                                                  if c['kind'] != 'reasoning_playbook'])
        return replace(pack, manifest=manifest)

    monkeypatch.setattr(mp.MissionPack, '_retained', retained)
    result = active_playbooks(ctx, now=NOW)
    assert (result.library, result.reason) == (None, 'none_selected')


def test_generation_commissioning_digest_mismatch(selection_node):
    ctx = activate(selection_node)
    assert active_playbooks(replace(ctx, commissioning_digest='sha256:' + '0' * 64),
                            now=NOW).reason == 'pack_degraded'


def test_published_selection_remains_group_readable(selection_node):
    import stat
    ctx = activate(selection_node)
    service = mp.MissionPack(ctx)
    generation = service.current()
    directory = ctx.root / 'generations' / str(generation.number)
    for path in directory.rglob('*'):
        assert stat.S_IMODE(path.stat().st_mode) & 0o777 == (0o750 if path.is_dir() else 0o640)
    assert stat.S_IMODE((ctx.root / 'current').stat().st_mode) == 0o640
