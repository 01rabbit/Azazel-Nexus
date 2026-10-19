"""The minimal credential source contains only synthetic proposal bytes."""

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


def test_only_three_private_proposal_files_are_published(profile):
    values = (b"synthetic-proposal", b"synthetic-proposal", b"s" * 64)
    draft._publish_mio_files(values[:2])
    assert {p.name for p in profile.iterdir()} == set(draft._PROPOSAL_FILES[:2])
    draft.publish_mio_profile_signature(*values)
    # Reviewing unchanged inputs again is safe and does not overwrite anything.
    draft.publish_mio_profile_signature(*values)
    assert {p.name for p in profile.iterdir()} == set(draft._PROPOSAL_FILES)
    for name, value in zip(draft._PROPOSAL_FILES, values):
        path = profile / name
        assert path.read_bytes() == value
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_uid == os.geteuid()
        assert path.stat().st_nlink == 1


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "different-bytes", "public-mode"])
def test_existing_untrusted_state_is_never_replaced(profile, tmp_path, kind):
    path = profile / draft._PROPOSAL_FILES[0]
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
        draft._publish_mio_files((b"new", b"new"))
    assert target.read_bytes() == b"existing"
    assert path.read_bytes() == b"existing"
    assert not (profile / draft._PROPOSAL_FILES[1]).exists()


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
        draft._publish_mio_files((b"synthetic-proposal",))
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
        draft._publish_mio_files((b"synthetic-proposal",))


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
