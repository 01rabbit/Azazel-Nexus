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


def test_config_reader_existing_schema_and_ownership(selection_node, tmp_path, monkeypatch):
    ctx = selection_node[0]
    config = tmp_path / 'mission-pack.json'
    doc = {'schema': 'azazel-nexus/mission-pack-config/1', 'assets': [],
           'trusted_keys': {k: v.hex() for k, v in ctx.trusted_keys.items()},
           'signing_epoch': ctx.signing_epoch, 'revoked_keys': [], 'revoked_packs': [],
           'commissioning_digest': ctx.commissioning_digest}
    config.write_text(json.dumps(doc))
    config.chmod(0o600)
    original = Path.lstat

    def root_owned(path):
        info = original(path)
        from types import SimpleNamespace
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0)

    monkeypatch.setattr(Path, 'lstat', root_owned)
    loaded = selection_context(config, ctx.root)
    assert loaded.trusted_keys == ctx.trusted_keys
    assert active_playbooks(loaded, now=NOW).reason == 'no_pack'
    config.chmod(0o666)
    with pytest.raises(mp.PackRefused):
        selection_context(config, ctx.root)


def test_holder_generation_reload_cache_damage_and_expiry(selection_node, monkeypatch):
    from azazel_nexus_runtime import mio_locald

    ctx = activate(selection_node)
    _, doc, media, add, baseline = selection_node
    config = ctx.root.parent / 'config.json'
    config.write_text('{}')  # Reader is injected; real config ownership is tested above.
    reads = []
    monkeypatch.setattr(mio_locald, 'selection_context', lambda *args: reads.append(args) or ctx)
    clock = [NOW]
    holder = mio_locald.PlaybookSelectionHolder(config=config, root=ctx.root, clock=lambda: clock[0])
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
    # A changed inventory/trust config rechecks current trust with no pointer change.
    monkeypatch.setattr(mio_locald, 'selection_context', lambda *args: replace(ctx, signing_epoch=99))
    config.write_text('{"changed":true}')
    assert holder.refresh(audit=events.append) is None
    assert events[-1]['reason'] == 'pack_degraded'
    monkeypatch.setattr(mio_locald, 'selection_context', lambda *args: ctx)
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
