"""Exercise fixed-path traversal on a private ordinary-file tree only."""

import os

import pytest

from azazel_nexus_runtime import bootstrap_audit


def _tree(tmp_path, monkeypatch):
    root = tmp_path / "root"
    ledger = root / "var/lib/azazel/state/audit"
    ledger.mkdir(parents=True)
    for path in (root, root / "var", root / "var/lib", root / "var/lib/azazel",
                 ledger.parent, ledger):
        path.chmod(0o700)
    real_open = os.open
    real_protected = bootstrap_audit._protected
    opened, owners = [], []

    def open_local(path, flags, *args, **kwargs):
        opened.append(path)
        assert flags & os.O_NOFOLLOW
        assert not flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR)
        return real_open(root if path == "/" else path, flags, *args, **kwargs)

    def check_local(fd, *, owner, directory):
        owners.append(owner)
        return real_protected(fd, owner=os.getuid(), directory=directory)

    monkeypatch.setattr(bootstrap_audit.os, "open", open_local)
    monkeypatch.setattr(bootstrap_audit, "_protected", check_local)
    return ledger, opened, owners


def test_fixed_path_and_expected_root_to_service_ownership(tmp_path, monkeypatch, private_os):
    private_os(bootstrap_audit)
    ledger, opened, owners = _tree(tmp_path, monkeypatch)
    fd = bootstrap_audit._open_ledger(1234)
    try:
        assert os.fstat(fd).st_ino == ledger.stat().st_ino
    finally:
        os.close(fd)
    assert opened == ["/", "var", "lib", "azazel", "state", "audit"]
    assert owners == [0, 0, 0, 0, 0, 1234]


@pytest.mark.parametrize("relative", ["state", "state/audit"])
def test_symlink_in_service_owned_ancestry_refuses(tmp_path, monkeypatch, relative, private_os):
    private_os(bootstrap_audit)
    ledger, _opened, _owners = _tree(tmp_path, monkeypatch)
    base = ledger.parent.parent
    target = base / relative
    renamed = target.with_name(target.name + "-saved")
    target.rename(renamed)
    target.symlink_to(renamed, target_is_directory=True)
    with pytest.raises(OSError):
        bootstrap_audit._open_ledger(1234)


def test_missing_ledger_is_not_created(tmp_path, monkeypatch, private_os):
    private_os(bootstrap_audit)
    ledger, _opened, _owners = _tree(tmp_path, monkeypatch)
    ledger.rmdir()
    with pytest.raises(FileNotFoundError):
        bootstrap_audit._open_ledger(1234)
    assert not ledger.exists()
