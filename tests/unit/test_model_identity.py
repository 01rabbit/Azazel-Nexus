"""Root pre-start handoff uses ephemeral identity digests, never secret bytes."""
import os
import stat
import sys
from types import SimpleNamespace

import pytest
from azazel_nexus_runtime import model_identity as identity


@pytest.fixture
def handoff(tmp_path, monkeypatch, private_os):
    private_os(identity)
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


def _inputs(failing):
    def ok():
        return "value"

    def refuse():
        raise FileNotFoundError(2, "No such file", "/secret/path/never/printed")

    return tuple((name, refuse if name == failing else ok)
                 for name in ("commissioning_key", "boot_id", "machine_id", "build_commit"))


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("failing", ["commissioning_key", "boot_id", "machine_id", "build_commit", None])
def test_unavailable_identity_names_a_fixed_input(handoff, monkeypatch, capsys, enabled, failing):
    monkeypatch.setattr(identity.admission, "LOCAL_MODEL_ADMISSION_ENABLED", enabled)
    monkeypatch.setattr(identity, "IDENTITY_INPUTS", _inputs(failing))

    def fail():
        raise ValueError("private identity details")

    # `None`: every input reads, but the observation still produced no digest.
    monkeypatch.setattr(identity, "run_identity", fail if failing else dict)
    assert identity.main() == int(enabled)
    err = capsys.readouterr().err
    expected = failing or "identity_digest"
    assert err == ("az-mio-identity: NODE_IDENTITY_UNAVAILABLE input=" + expected
                   + "; no node identity written; "
                   + ("start refused" if enabled else "admission disabled, start continues") + "\n")
    assert "private" not in err and "/secret" not in err


def test_identity_inputs_are_the_ones_run_identity_reads():
    from azazel_nexus_runtime import hil_readiness

    assert [name for name, _ in hil_readiness.IDENTITY_INPUTS] == [
        "commissioning_key", "boot_id", "machine_id", "build_commit"]
    assert hil_readiness.IDENTITY_INPUTS[0][1] is hil_readiness.protection_key


@pytest.mark.parametrize("commit,ok", [("a" * 40, True), ("b" * 64, True), ("a" * 39, False),
                                       ("A" * 40, False), ("", False)])
def test_build_commit_grammar_is_unchanged(tmp_path, monkeypatch, commit, ok):
    from azazel_nexus_runtime import hil_readiness

    path = tmp_path / "build-commit"
    path.write_text(commit + "\n")
    monkeypatch.setattr(hil_readiness, "BUILD_COMMIT", path)
    if ok:
        assert hil_readiness._build_commit() == commit
    else:
        with pytest.raises(ValueError):
            hil_readiness._build_commit()
