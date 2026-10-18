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
    asset = tmp_path / 'var/lib/azazel/playbooks/baseline.json'
    asset.parent.mkdir(parents=True, mode=0o700)
    asset.write_text('{}')
    asset.chmod(0o600)
    config.write_text(json.dumps({'schema': 'azazel-nexus/mission-pack-config/1',
                                'assets': [{'kind': 'reasoning_playbook',
                                            'path': '/var/lib/azazel/playbooks/baseline.json'}]}))
    config.chmod(0o600)
    tree = tmp_path / 'data/azazel/mission-packs/generations/1/tree'
    tree.mkdir(parents=True)
    retained = tree / 'mission-pack.signed'
    retained.write_bytes(b'test fixture only')
    retained.chmod(0o600)
    store = tree.parents[2]
    (store / 'current').write_text('1\n')
    from azazel_nexus.audit import AuditLedger
    AuditLedger(store / 'audit.jsonl').append({'fixture': 'legacy ledger'})
    (store / '.pack-pointer-interrupted').write_text('1\n')
    for _ in range(2):
        provision(tmp_path, accounts=False, staging=True)
    for path in (config, asset, retained, store / 'current'):
        assert stat.S_IMODE(path.stat().st_mode) == 0o640
    for name in ('audit.jsonl', '.pack-pointer-interrupted'):
        assert stat.S_IMODE((store / name).stat().st_mode) == 0o600
    for path in (store, store / 'generations', tree.parent, tree):
        # macOS can clear setgid for an unprivileged caller; read/write bits hold.
        assert stat.S_IMODE(path.stat().st_mode) & 0o777 == 0o750
    assert asset.parent.stat().st_mode & 0o010


@pytest.mark.parametrize('unsafe', ['writable', 'symlink', 'runtime'])
def test_unsafe_asset_provisioning_refuses(tmp_path, unsafe):
    config = tmp_path / 'etc/azazel/mission-pack.json'
    config.parent.mkdir(parents=True)
    asset = tmp_path / 'var/lib/azazel/playbooks/playbook.json'
    asset.parent.mkdir(parents=True)
    asset.write_text('{}')
    if unsafe == 'writable':
        asset.chmod(0o660)
    elif unsafe == 'symlink':
        asset.unlink()
        asset.symlink_to(config)
    path = '/var/lib/azazel/mio/playbook.json' if unsafe == 'runtime' else '/var/lib/azazel/playbooks/playbook.json'
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
        values[5] = 0
        return os.stat_result(values)
    monkeypatch.setattr(Path, 'lstat', root_owned)
    monkeypatch.setattr(installer.grp, 'getgrnam',
                        lambda name: SimpleNamespace(gr_gid=4321) if name == 'azmission-read' else None)
    changes = []
    monkeypatch.setattr(installer.os, 'chown',
                        lambda path, uid, gid, **kwargs: changes.append((path, uid, gid)))
    provision(tmp_path, encrypted=lambda path: True)
    store = tmp_path / 'data/azazel/mission-packs'
    assert (store, -1, 4321) in changes
    assert (store / "generations", -1, 4321) in changes
    assert (tmp_path / "var/lib/azazel/playbooks", -1, 4321) in changes
    assert stat.S_IMODE(store.stat().st_mode) & 0o777 == 0o750


@pytest.mark.parametrize('destination,staging', [('/', False), ('/./', False), ('/tmp/image', True)])
def test_destdir_root_does_not_bypass_encryption(destination, staging, monkeypatch):
    from tools import provision_mission_read as installer

    calls = []
    monkeypatch.setenv('DESTDIR', destination)
    monkeypatch.setattr(sys, 'argv', ['provision_mission_read.py', '--without-accounts'])
    monkeypatch.setattr(installer, 'provision', lambda root, **kw: calls.append((root, kw)))
    installer.main()
    assert calls == [(Path(destination).resolve(), {'accounts': False, 'staging': staging})]


def test_private_ancestor_group_is_preserved(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace

    from tools import provision_mission_read as installer

    private = tmp_path / 'var/lib/azazel'
    private.mkdir(parents=True)
    private.chmod(0o750)
    original = Path.lstat
    def root_owned(path):
        values = list(original(path))
        values[4] = 0
        values[5] = 9876 if path == private else 0
        return os.stat_result(values)
    monkeypatch.setattr(Path, 'lstat', root_owned)
    monkeypatch.setattr(installer.grp, 'getgrnam', lambda name: SimpleNamespace(gr_gid=4321))
    changed = []
    monkeypatch.setattr(installer.os, 'chown', lambda path, *a, **kw: changed.append(path))
    with pytest.raises(ValueError, match='refusing to replace private directory group'):
        provision(tmp_path, encrypted=lambda path: False)
    assert private not in changed


@pytest.mark.parametrize('path', ['/etc/azazel/commissioning/private.json',
                                  '/opt/playbooks/book.json', '/root/book.json',
                                  '/var/lib/azazel/playbooks/../secret.json'])
def test_only_dedicated_asset_root_is_admitted(tmp_path, path):
    config = tmp_path / 'etc/azazel/mission-pack.json'
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({'schema': 'azazel-nexus/mission-pack-config/1',
                                 'assets': [{'kind': 'reasoning_playbook', 'path': path}]}))
    with pytest.raises(ValueError, match='playbook must live under'):
        provision(tmp_path, accounts=False, staging=True)


def _trust_store(root, *, directory_mode=0o700, file_mode=0o600):
    import os
    trust = root / 'etc/azazel/operator-trust'
    trust.mkdir(parents=True)
    store = trust / 'operators.json'
    store.write_text('{"schema":"azazel-nexus/operator-trust/v1","keys":{},"revoked":[]}\n')
    os.chmod(store, file_mode)
    os.chmod(trust, directory_mode)
    return trust, store


def test_operator_trust_store_migrates_to_reader_group_idempotently(tmp_path):
    import os

    from tools.provision_mission_read import migrate_operator_trust
    trust, store = _trust_store(tmp_path)
    before = store.read_bytes()
    gid = os.getgid()  # stands in for azmission-read; owner seam stands in for root
    for _ in range(2):
        assert migrate_operator_trust(tmp_path, gid, owner=os.getuid()) is True
        assert stat.S_IMODE(trust.stat().st_mode) == 0o750 and trust.stat().st_gid == gid
        assert stat.S_IMODE(store.stat().st_mode) == 0o640 and store.stat().st_gid == gid
    assert store.read_bytes() == before
    from azazel_nexus.operator_store import _read_at
    fd = os.open(trust, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert _read_at(fd, owner=os.getuid()).public_keys == {}
    finally:
        os.close(fd)


def test_operator_trust_absent_is_not_created(tmp_path):
    import os

    from tools.provision_mission_read import migrate_operator_trust
    assert migrate_operator_trust(tmp_path, os.getgid(), owner=os.getuid()) is False
    provision(tmp_path, accounts=False, staging=True)
    assert not (tmp_path / 'etc/azazel/operator-trust').exists()


def test_operator_trust_directory_without_store_migrates_directory_only(tmp_path):
    import os

    from tools.provision_mission_read import migrate_operator_trust
    trust, store = _trust_store(tmp_path)
    store.unlink()
    assert migrate_operator_trust(tmp_path, os.getgid(), owner=os.getuid())
    assert stat.S_IMODE(trust.stat().st_mode) == 0o750
    assert not store.exists()


def test_staging_provision_migrates_operator_trust_without_accounts(tmp_path):
    trust, store = _trust_store(tmp_path)
    provision(tmp_path, accounts=False, staging=True)
    assert stat.S_IMODE(trust.stat().st_mode) == 0o750
    assert stat.S_IMODE(store.stat().st_mode) == 0o640


@pytest.mark.parametrize('unsafe', ['symlink-dir', 'symlink-file', 'hardlink', 'group-writable-file',
                                    'other-writable-dir', 'non-root-file', 'non-root-dir',
                                    'fifo', 'file-as-dir', 'foreign-group'])
def test_unsafe_operator_trust_refuses_and_changes_nothing(tmp_path, monkeypatch, unsafe):
    import os

    from tools import provision_mission_read as installer
    trust, store = _trust_store(tmp_path)
    if unsafe == 'symlink-dir':
        real = tmp_path / 'elsewhere'
        trust.rename(real)
        trust.symlink_to(real)
        trust, store = real, real / 'operators.json'
    elif unsafe == 'symlink-file':
        target = tmp_path / 'target.json'
        store.rename(target)
        store.symlink_to(target)
        store = target
    elif unsafe == 'hardlink':
        os.link(store, tmp_path / 'second-link.json')
    elif unsafe == 'group-writable-file':
        os.chmod(store, 0o620)
    elif unsafe == 'other-writable-dir':
        os.chmod(trust, 0o702)
    elif unsafe == 'fifo':
        store.unlink()
        os.mkfifo(store, 0o600)
    elif unsafe == 'file-as-dir':
        store.unlink()
        store.mkdir(mode=0o700)
    owner = os.getuid()
    if unsafe.startswith('non-root'):
        # Production requires uid 0; the test owner seam asks for another owner.
        real_fstat = os.fstat
        def foreign(fd):
            values = list(real_fstat(fd))
            is_dir = stat.S_ISDIR(values[0])
            if (unsafe == 'non-root-dir') == is_dir:
                values[4] = owner + 1
            return os.stat_result(values)
        monkeypatch.setattr(installer.os, 'fstat', foreign)
    gid = os.getgid()
    if unsafe == 'foreign-group':
        # An administrator-assigned non-root group is never silently replaced.
        os.chown(trust, -1, os.getgid())
        if os.getgid() == 0:
            pytest.skip('needs a non-root primary group')
        gid = os.getgid() + 4321
    snapshot = [(p, p.lstat().st_mode, p.lstat().st_gid) for p in (trust, store)]
    changes = []
    monkeypatch.setattr(installer.os, 'fchown', lambda *a: changes.append(a))
    monkeypatch.setattr(installer.os, 'fchmod', lambda *a: changes.append(a))
    with pytest.raises(ValueError, match='refusing'):
        installer.migrate_operator_trust(tmp_path, gid, owner=owner)
    monkeypatch.undo()
    assert changes == []
    assert [(p, p.lstat().st_mode, p.lstat().st_gid) for p in (trust, store)] == snapshot
