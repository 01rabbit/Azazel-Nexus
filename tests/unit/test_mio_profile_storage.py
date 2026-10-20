"""The unencrypted profile directory receives only the reviewed signature (#244)."""

import os
import stat

import pytest

from azazel_nexus import commissioning_draft as draft


@pytest.fixture
def profile(tmp_path, monkeypatch):
    directory = tmp_path / "mio-profile"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(draft, "MIO_PROFILE_DIR", directory)
    return directory


def test_only_the_private_signature_is_published(profile):
    values = (b"synthetic-proposal", b"synthetic-proposal", b"s" * 64)
    draft.publish_mio_profile_signature(*values)
    # Reviewing unchanged inputs again is safe and does not overwrite anything.
    draft.publish_mio_profile_signature(*values)
    assert [p.name for p in profile.iterdir()] == ["commissioning-proposal.sig"]
    path = profile / "commissioning-proposal.sig"
    assert path.read_bytes() == b"s" * 64
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.stat().st_uid == os.geteuid()
    assert path.stat().st_nlink == 1


@pytest.mark.parametrize("values", [
    (b"synthetic-proposal", b"synthetic-proposal"),
    (b"synthetic-proposal", b"synthetic-proposal", b"s" * 64),
    (),
])
def test_proposal_bytes_can_never_be_published(profile, values):
    with pytest.raises(draft.DraftRefused):
        draft._publish_mio_files(values)
    assert list(profile.iterdir()) == []


@pytest.mark.parametrize("values", [
    (b"synthetic-proposal", b"other-proposal", b"s" * 64),
    (b"synthetic-proposal", b"synthetic-proposal", b"s" * 63),
])
def test_inconsistent_review_inputs_publish_nothing(profile, values):
    with pytest.raises(draft.DraftRefused):
        draft.publish_mio_profile_signature(*values)
    assert list(profile.iterdir()) == []


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "different-bytes", "public-mode"])
def test_existing_untrusted_state_is_never_replaced(profile, tmp_path, kind):
    path = profile / "commissioning-proposal.sig"
    target = tmp_path / "retained"
    target.write_bytes(b"existing")
    target.chmod(0o600)
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "hardlink":
        path.hardlink_to(target)
    else:
        path.write_bytes(b"existing")
        path.chmod(0o644 if kind == "public-mode" else 0o600)
    with pytest.raises((draft.DraftRefused, OSError)):
        draft._publish_mio_files((b"n" * 64,))
    assert target.read_bytes() == b"existing"
    assert path.read_bytes() == b"existing"
    assert [p.name for p in profile.iterdir()] == ["commissioning-proposal.sig"]


@pytest.mark.parametrize("failure", ["write", "publish"])
def test_incomplete_file_is_never_visible_at_final_name(profile, monkeypatch, failure):
    if failure == "write":
        original = os.write
        def failed_write(fd, value):
            original(fd, value[:1])
            raise OSError("synthetic interrupted write")
        monkeypatch.setattr(os, "write", failed_write)
    else:
        def failed_link(*args, **kwargs):
            raise OSError("synthetic publication failure")
        monkeypatch.setattr(os, "link", failed_link)
    with pytest.raises(OSError):
        draft._publish_mio_files((b"s" * 64,))
    assert list(profile.iterdir()) == []


@pytest.mark.parametrize("kind", ["missing", "symlink", "permissions", "owner"])
def test_profile_directory_must_be_installed_and_private(profile, tmp_path, monkeypatch, kind):
    if kind == "missing":
        profile.rmdir()
    elif kind == "symlink":
        profile.rmdir()
        profile.symlink_to(tmp_path, target_is_directory=True)
    elif kind == "permissions":
        profile.chmod(0o750)
    else:
        monkeypatch.setattr(os, "geteuid", lambda: profile.stat().st_uid + 1)
    with pytest.raises((draft.DraftRefused, OSError)):
        draft._publish_mio_files((b"s" * 64,))


def test_publication_failure_remains_review_refusal(profile, monkeypatch, capsys):
    from types import SimpleNamespace
    from azazel_nexus_runtime import proposal_review
    monkeypatch.setattr("azazel_nexus.lab_host.is_lab_host", lambda: False)
    monkeypatch.setattr(proposal_review, "load_declared_node", lambda: SimpleNamespace(node_id="synthetic"))
    monkeypatch.setattr(proposal_review, "load_operator_trust", lambda: "synthetic-public-trust")
    monkeypatch.setattr(proposal_review, "read_proposal_review_inputs", lambda: (b"payload", b"payload", b"s" * 64))
    monkeypatch.setattr(proposal_review, "verify_retained_commissioning_proposal", lambda **kw: None)
    profile.rmdir()
    assert proposal_review.run("operator-a") == 1
    output = capsys.readouterr()
    assert "refused" in output.err
    assert "verified" not in output.out


# Migration of nodes where an earlier release copied the proposal here (#244).

from tools import purge_mio_profile_copies as purge_tool  # noqa: E402

LEGACY = ("commissioning-proposal.expected.json", "commissioning-proposal.json")
# Obviously synthetic identity, never a real board or interface.
FAKE_IDENTITY = b'{"board_serial":"SYNTHETIC-SERIAL-0000","permanent_mac":"02:00:00:00:00:0a"}'


def _legacy(profile):
    for name in LEGACY:
        (profile / name).write_bytes(FAKE_IDENTITY)
        (profile / name).chmod(0o600)
    (profile / "commissioning-proposal.sig").write_bytes(b"s" * 64)
    (profile / "commissioning-proposal.sig").chmod(0o600)


def test_purge_removes_only_the_two_legacy_copies(profile):
    _legacy(profile)
    assert purge_tool.purge(profile) == list(LEGACY)
    assert [p.name for p in profile.iterdir()] == ["commissioning-proposal.sig"]
    assert all(FAKE_IDENTITY not in p.read_bytes() for p in profile.iterdir())
    # Idempotent: a second run (every later install) finds nothing to do.
    assert purge_tool.purge(profile) == []


def test_purge_never_follows_a_symlink_at_a_fixed_name(profile, tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_bytes(FAKE_IDENTITY)
    (profile / LEGACY[0]).symlink_to(outside)
    (profile / LEGACY[1]).write_bytes(FAKE_IDENTITY)
    with pytest.raises(purge_tool.PurgeRefused):
        purge_tool.purge(profile)
    # Refused as a whole: nothing removed, the target untouched.
    assert outside.read_bytes() == FAKE_IDENTITY
    assert (profile / LEGACY[0]).is_symlink() and (profile / LEGACY[1]).exists()


def test_purge_refuses_a_symlinked_directory(profile, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for name in LEGACY:
        (elsewhere / name).write_bytes(FAKE_IDENTITY)
    profile.rmdir()
    profile.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(purge_tool.PurgeRefused):
        purge_tool.purge(profile)
    assert sorted(p.name for p in elsewhere.iterdir()) == sorted(LEGACY)


def test_purge_leaves_other_files_and_tolerates_a_missing_directory(profile, tmp_path):
    (profile / "unrelated").write_bytes(b"kept")
    (profile / LEGACY[1]).write_bytes(FAKE_IDENTITY)
    assert purge_tool.purge(profile) == [LEGACY[1]]
    assert (profile / "unrelated").read_bytes() == b"kept"
    assert purge_tool.purge(tmp_path / "never-installed") == []


def test_purge_command_accepts_only_the_fixed_directory(profile, capsys):
    _legacy(profile)
    # Any other directory, including this one under a different name, is refused.
    assert purge_tool.main([str(profile)]) == 2
    assert purge_tool.main([]) == 2
    assert len(list(profile.iterdir())) == 3
    installed = profile.parent / "root/etc/azazel/mio-profile"
    installed.mkdir(parents=True, mode=0o700)
    _legacy(installed)
    assert purge_tool.main([str(installed)]) == 0
    output = capsys.readouterr()
    assert "SYNTHETIC" not in output.out + output.err
    assert [p.name for p in installed.iterdir()] == ["commissioning-proposal.sig"]


def test_installer_runs_the_purge_on_the_installed_directory():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[2] / "packaging/install.sh").read_text()
    line = ('python_fixed -IS "$REPO_ROOT/tools/purge_mio_profile_copies.py" '
            '"${DESTDIR:-}/etc/azazel/mio-profile"')
    assert line in text
    assert text.index("make_dir 0700 root /etc/azazel/mio-profile") < text.index(line)
