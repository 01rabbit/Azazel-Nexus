"""Root pre-start handoff uses ephemeral identity digests, never secret bytes."""
import os
import stat
import sys
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import model_identity as identity


@pytest.fixture
def handoff(tmp_path, monkeypatch):
    tmp_path.chmod(0o750)
    monkeypatch.setattr(identity, "DIRECTORY", str(tmp_path))
    monkeypatch.setattr(identity.os, "geteuid", lambda: 0)
    monkeypatch.setattr(identity.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=tmp_path.stat().st_gid))
    monkeypatch.setattr(identity.os, "fchown", lambda *args: None)
    real_fstat = os.fstat

    def root_metadata(fd):
        info = real_fstat(fd)
        return SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_gid=info.st_gid,
                               st_nlink=info.st_nlink, st_size=info.st_size)

    monkeypatch.setattr(identity.os, "fstat", root_metadata)
    monkeypatch.setattr(sys, "argv", ["az-mio-identity"])
    return tmp_path


def test_every_start_reobserves_and_only_writes_digest(handoff, monkeypatch):
    digest = ["hmac-sha256:" + "1" * 64]
    monkeypatch.setattr(identity, "run_identity", lambda: {"host_digest": digest[0], "secret": "never written"})
    monkeypatch.setenv("AZAZEL_ROOT", "/some/cloned/etc")
    assert identity.main() == 0
    path = handoff / identity.NAME
    assert path.read_bytes() == (digest[0] + "\n").encode()
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert identity.read_identity()["host_digest"] == digest[0]
    digest[0] = "hmac-sha256:" + "2" * 64
    identity.main()
    assert identity.read_identity()["host_digest"] == digest[0]
    assert list(handoff.iterdir()) == [path]


@pytest.mark.parametrize("mutation", ["mode", "symlink", "oversize", "hardlink", "owner", "group"])
def test_reader_refuses_unprotected_or_unbounded(handoff, monkeypatch, mutation):
    monkeypatch.setattr(identity, "run_identity", lambda: {"host_digest": "hmac-sha256:" + "1" * 64})
    identity.main()
    path = handoff / identity.NAME
    if mutation == "mode":
        path.chmod(0o660)
    elif mutation == "oversize":
        path.write_bytes(b"a" * 10000)
    elif mutation == "symlink":
        path.rename(handoff / "target")
        path.symlink_to(handoff / "target")
    elif mutation == "hardlink":
        os.link(path, handoff / "other")
    else:
        real = identity.os.fstat
        def metadata(fd):
            info = real(fd)
            setattr(info, "st_uid" if mutation == "owner" else "st_gid", 999999)
            return info
        monkeypatch.setattr(identity.os, "fstat", metadata)
    with pytest.raises((OSError, ValueError)):
        identity.read_identity()


def test_failed_observation_removes_previous_digest(handoff, monkeypatch):
    (handoff / identity.NAME).write_bytes(b"old digest")
    def fail():
        raise ValueError("identity unavailable")
    monkeypatch.setattr(identity, "run_identity", fail)
    assert identity.main() == 0
    assert not (handoff / identity.NAME).exists()


def test_arguments_are_refused_before_observation(handoff, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["az-mio-identity", "ignored"])
    monkeypatch.setattr(identity, "run_identity", lambda: pytest.fail("arguments observed"))
    with pytest.raises(SystemExit):
        identity.main()


@pytest.mark.parametrize("enabled", [False, True])
def test_unavailable_identity_exit_tracks_kill_switch(handoff, monkeypatch, enabled):
    monkeypatch.setattr(identity.admission, "LOCAL_MODEL_ADMISSION_ENABLED", enabled)
    (handoff / identity.NAME).write_bytes(b"stale")
    monkeypatch.setattr(identity, "run_identity", dict)
    # Missing fields are unavailable observations too.
    assert identity.main() == int(enabled)
    assert not (handoff / identity.NAME).exists()


@pytest.mark.parametrize("mutation", ["owner", "group", "mode", "symlink"])
def test_reader_refuses_unsafe_parent(handoff, monkeypatch, mutation):
    monkeypatch.setattr(identity, "run_identity", lambda: {"host_digest": "hmac-sha256:" + "1" * 64})
    identity.main()
    if mutation == "mode":
        handoff.chmod(0o770)
    elif mutation == "symlink":
        link = handoff.parent / "identity-link"
        link.symlink_to(handoff, target_is_directory=True)
        monkeypatch.setattr(identity, "DIRECTORY", str(link))
    else:
        real = identity.os.fstat
        def metadata(fd):
            info = real(fd)
            if stat.S_ISDIR(info.st_mode):
                setattr(info, "st_uid" if mutation == "owner" else "st_gid", 999999)
            return info
        monkeypatch.setattr(identity.os, "fstat", metadata)
    with pytest.raises((OSError, ValueError)):
        identity.read_identity()


def test_short_write_never_publishes(handoff, monkeypatch):
    monkeypatch.setattr(identity, "run_identity", lambda: {"host_digest": "hmac-sha256:" + "1" * 64})
    monkeypatch.setattr(identity.os, "write", lambda fd, raw: len(raw) - 1)
    with pytest.raises(OSError, match="short identity write"):
        identity.main()
    assert not (handoff / identity.NAME).exists()
