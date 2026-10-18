"""Installer permission migration and future selection publication."""
import json
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.provision_mission_read import provision


def test_staging_idempotent_config_assets_and_retained_selection(tmp_path):
    config = tmp_path / 'etc/azazel/mission-pack.json'
    config.parent.mkdir(parents=True)
    asset = tmp_path / 'opt/playbooks/baseline.json'
    asset.parent.mkdir(parents=True, mode=0o700)
    asset.write_text('{}')
    asset.chmod(0o600)
    config.write_text(json.dumps({'schema': 'azazel-nexus/mission-pack-config/1',
                                'assets': [{'kind': 'reasoning_playbook',
                                            'path': '/opt/playbooks/baseline.json'}]}))
    config.chmod(0o600)
    tree = tmp_path / 'data/azazel/mission-packs/generations/1/tree'
    tree.mkdir(parents=True)
    retained = tree / 'mission-pack.signed'
    retained.write_bytes(b'test fixture only')
    retained.chmod(0o600)
    store = tree.parents[2]
    (store / 'current').write_text('1\n')
    (store / 'audit.jsonl').write_text('private')
    (store / 'audit.jsonl').chmod(0o600)
    for _ in range(2):
        provision(tmp_path, accounts=False, staging=True)
    for path in (config, asset, retained, store / 'current'):
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert stat.S_IMODE((store / 'audit.jsonl').stat().st_mode) == 0o600
    for path in (store, store / 'generations', tree.parent, tree):
        # macOS can clear setgid for an unprivileged caller; read/write bits hold.
        assert stat.S_IMODE(path.stat().st_mode) & 0o777 == 0o750
    assert asset.parent.stat().st_mode & 0o010


@pytest.mark.parametrize('unsafe', ['writable', 'symlink', 'runtime'])
def test_unsafe_asset_provisioning_refuses(tmp_path, unsafe):
    config = tmp_path / 'etc/azazel/mission-pack.json'
    config.parent.mkdir(parents=True)
    asset = tmp_path / 'opt/playbook.json'
    asset.parent.mkdir()
    asset.write_text('{}')
    if unsafe == 'writable':
        asset.chmod(0o660)
    elif unsafe == 'symlink':
        asset.unlink()
        asset.symlink_to(config)
    path = '/var/lib/azazel/mio/playbook.json' if unsafe == 'runtime' else '/opt/playbook.json'
    config.write_text(json.dumps({'schema': 'azazel-nexus/mission-pack-config/1',
                                'assets': [{'kind': 'reasoning_playbook', 'path': path}]}))
    config.chmod(0o600)
    with pytest.raises(ValueError):
        provision(tmp_path, accounts=False, staging=True)


def test_unverified_storage_is_not_created_and_rerun_after_mount_succeeds(tmp_path, capsys):
    checked = []
    def encrypted(path):
        checked.append(path)
        return False
    provision(tmp_path, accounts=False, encrypted=encrypted)
    assert checked == [tmp_path]
    assert not (tmp_path / 'data').exists()
    assert 'MISSION PACK STORE NOT PROVISIONED' in capsys.readouterr().out
    provision(tmp_path, accounts=False, encrypted=lambda path: True)
    assert (tmp_path / 'data/azazel/mission-packs/generations').is_dir()


def test_live_projection_keeps_owner_and_assigns_dedicated_reader_gid(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace

    from tools import provision_mission_read as installer

    original = Path.lstat
    def root_owned(path):
        values = list(original(path))
        values[4] = 0
        return os.stat_result(values)
    monkeypatch.setattr(Path, 'lstat', root_owned)
    monkeypatch.setattr(installer.grp, 'getgrnam',
                        lambda name: SimpleNamespace(gr_gid=4321) if name == 'azmission-read' else None)
    changes = []
    monkeypatch.setattr(installer.os, 'chown',
                        lambda path, uid, gid, **kwargs: changes.append((path, uid, gid)))
    provision(tmp_path, encrypted=lambda path: True)
    store = tmp_path / 'data/azazel/mission-packs'
    assert changes == [(store, -1, 4321), (store / 'generations', -1, 4321)]
    assert stat.S_IMODE(store.stat().st_mode) & 0o777 == 0o750
