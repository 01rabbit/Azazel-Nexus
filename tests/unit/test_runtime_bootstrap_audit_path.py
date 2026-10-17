"""Real ordinary directories/Unix sockets, synthetic Linux account metadata."""

from contextlib import contextmanager
from pathlib import Path
import os
import socket
import tempfile
from types import SimpleNamespace

import pytest

from azazel_nexus_runtime import bootstrap_audit_peer as peer
from azazel_nexus_runtime.units import UnitOperationFailed


@contextmanager
def _path_environment(monkeypatch):
    # Short path also fits macOS AF_UNIX limits. No real deployment path opened.
    with tempfile.TemporaryDirectory(prefix="az-peer-", dir="/tmp") as directory:
        root = Path(directory)
        leaf = root / "var/lib/azazel/run/audit"
        leaf.mkdir(parents=True)
        (root / "var").chmod(0o755)
        (root / "var/lib").chmod(0o755)
        (root / "var/lib/azazel").chmod(0o711)
        (root / "var/lib/azazel/run").chmod(0o711)
        leaf.chmod(0o2710)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        target = leaf / "audit.sock"
        listener.bind(str(target))
        target.chmod(0o660)
        descriptors = {}
        closed = []
        overrides = {}

        def path_for(name, parent=None):
            return root if name == "/" else descriptors[parent] / name

        def metadata(info, path):
            service_owned = path == leaf or path == target
            values = {key: getattr(info, key) for key in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_ctime_ns",
            )}
            if path == leaf:
                # macOS may clear the directory's SGID on socket creation.
                # Model the declared Linux bit, not successful Linux inheritance.
                values["st_mode"] |= 0o2000
            values.update(st_uid=1001 if service_owned else 0,
                          st_gid=1003 if service_owned else 0)
            values.update(overrides.get(path, {}))
            return SimpleNamespace(**values)

        def open_path(name, flags, *, dir_fd=None):
            path = path_for(name, dir_fd)
            fd = os.open(path, flags)
            descriptors[fd] = path
            return fd

        def close(fd):
            closed.append(fd)
            os.close(fd)

        shim = SimpleNamespace(
            open=open_path, close=close, geteuid=lambda: 0,
            fstat=lambda fd: metadata(os.fstat(fd), descriptors[fd]),
            stat=lambda name, *, dir_fd, follow_symlinks: metadata(
                os.stat(path_for(name, dir_fd), follow_symlinks=follow_symlinks),
                path_for(name, dir_fd),
            ),
        )
        try:
            with monkeypatch.context() as patch:
                patch.setattr(peer, "os", shim)
                patch.setattr(peer, "ROOT", Path("/"))
                yield root, leaf, target, overrides
            assert sorted(closed) == sorted(descriptors)
        finally:
            listener.close()


def test_fixed_descriptor_path_checks_names_and_closes_all_fds(monkeypatch):
    with _path_environment(monkeypatch):
        with peer._open_audit_path((1001, 1002, 1003)) as proof:
            proof.check()


@pytest.mark.parametrize("fault", ["socket-mode", "socket-uid", "socket-gid", "leaf-mode"])
def test_audit_path_rejects_declared_acl_mismatch(monkeypatch, fault):
    with _path_environment(monkeypatch) as (_root, leaf, target, overrides):
        if fault == "socket-mode":
            target.chmod(0o666)
        elif fault == "socket-uid":
            overrides[target] = {"st_uid": 1004}
        elif fault == "socket-gid":
            overrides[target] = {"st_gid": 1002}  # primary GID is not socket GID
        else:
            leaf.chmod(0o2770)
        with pytest.raises(UnitOperationFailed):
            with peer._open_audit_path((1001, 1002, 1003)):
                pytest.fail("bad ACL admitted")


def test_audit_path_refuses_symlink_parent(monkeypatch):
    with _path_environment(monkeypatch) as (root, _leaf, _target, _overrides):
        (root / "var/lib").rename(root / "var/old-lib")
        (root / "var/lib").symlink_to("old-lib", target_is_directory=True)
        with pytest.raises(OSError):
            with peer._open_audit_path((1001, 1002, 1003)):
                pytest.fail("symlink parent admitted")


def test_audit_path_detects_replacement_socket(monkeypatch):
    with _path_environment(monkeypatch) as (_root, _leaf, target, _overrides):
        with peer._open_audit_path((1001, 1002, 1003)) as proof:
            target.unlink()
            replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                replacement.bind(str(target))
                target.chmod(0o660)
                with pytest.raises(UnitOperationFailed, match="identity changed"):
                    proof.check()
            finally:
                replacement.close()


def test_audit_path_detects_replaced_parent_despite_retained_fd(monkeypatch):
    with _path_environment(monkeypatch) as (_root, leaf, _target, _overrides):
        with peer._open_audit_path((1001, 1002, 1003)) as proof:
            leaf.rename(leaf.with_name("old-audit"))
            leaf.mkdir(mode=0o2710)
            leaf.chmod(0o2710)
            with pytest.raises(UnitOperationFailed, match="directory binding changed"):
                proof.check()
