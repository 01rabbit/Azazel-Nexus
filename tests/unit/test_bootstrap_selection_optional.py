"""Optional routing reader tests using only temporary protected-shaped trees."""

from contextlib import contextmanager
import os

import pytest

from azazel_nexus import bootstrap_selection_optional as optional
from azazel_nexus import bootstrap_selection_store
from azazel_nexus import bootstrap_store
from azazel_nexus.operator_trust import ApprovalRefused


@pytest.fixture
def paths(tmp_path, monkeypatch):
    root = tmp_path / "root"
    parent = root / "etc/azazel"
    parent.mkdir(parents=True)
    for directory in (root, root / "etc", root / "etc/azazel"):
        directory.chmod(0o755)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    owner = os.getuid()

    original_walk = bootstrap_store._optional_bootstrap_directory

    @contextmanager
    def walk():
        with original_walk(
            root_fd=root_fd, owner=owner
        ) as result:
            yield result

    monkeypatch.setattr(bootstrap_store, "_optional_bootstrap_directory", walk)
    yield root, parent, root_fd, owner, original_walk
    os.close(root_fd)


def present_directory(paths):
    _root, parent, _root_fd, _owner, _original_walk = paths
    directory = parent / "bootstrap"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


def test_genuine_final_directory_absence_returns_none_without_creating(paths):
    assert optional.load_optional_bootstrap_selection() is None
    assert not (paths[1] / "bootstrap").exists()


def test_existing_protected_directory_with_no_selection_records_returns_none(paths):
    present_directory(paths)
    assert optional.load_optional_bootstrap_selection() is None


def test_missing_protected_parent_is_not_misclassified_as_absence(paths):
    original = bootstrap_store._protected

    def fail_parent(*_args, **_kwargs):
        raise PermissionError("synthetic protected-parent refusal")

    bootstrap_store._protected = fail_parent
    try:
        with pytest.raises(ApprovalRefused):
            optional.load_optional_bootstrap_selection()
    finally:
        bootstrap_store._protected = original


def test_final_directory_symlink_is_not_misclassified_as_absence(paths):
    (paths[1] / "bootstrap").symlink_to(paths[1], target_is_directory=True)
    with pytest.raises(ApprovalRefused):
        optional.load_optional_bootstrap_selection()


def test_dangling_selection_symlink_is_not_misclassified_as_absence(paths):
    directory = present_directory(paths)
    (directory / "selection.json").symlink_to(directory / "missing")
    with pytest.raises(ApprovalRefused):
        optional.load_optional_bootstrap_selection()


@pytest.mark.parametrize("failure", ["owner", "size"])
def test_selection_owner_or_size_refusal_is_not_misclassified_as_absence(
    paths, monkeypatch, failure
):
    directory = present_directory(paths)
    selection = directory / "selection.json"
    selection.write_bytes(b"x" * (4097 if failure == "size" else 8))
    selection.chmod(0o644 if failure == "owner" else 0o600)
    if failure == "size":
        # Force the shared protected-file reader's size refusal after its
        # missing-pending check; no file-not-found fallback is permitted.
        monkeypatch.setattr(
            bootstrap_selection_store, "_read_file_at",
            lambda *_a, **_k: (_ for _ in ()).throw(ApprovalRefused("size refused")),
        )
    with pytest.raises(ApprovalRefused):
        optional.load_optional_bootstrap_selection()


def test_present_selection_delegates_strict_reader_and_returns_its_result(
    paths, monkeypatch
):
    directory = present_directory(paths)
    selected = object()
    calls = []
    monkeypatch.setattr(bootstrap_selection_store, "_read_at", lambda *_a, **_k: b"record")

    def strict_reader():
        calls.append(None)
        return selected

    monkeypatch.setattr(bootstrap_selection_store, "load_bootstrap_selection", strict_reader)
    assert optional.load_optional_bootstrap_selection() is selected
    assert calls == [None]
    assert directory.is_dir()


@pytest.mark.parametrize("failure", [
    "malformed", "pending", "stale", "mismatched", "unprotected",
])
def test_present_but_invalid_selection_is_never_fallback(paths, monkeypatch, failure):
    present_directory(paths)
    if failure == "pending":
        (paths[1] / "bootstrap/selection.pending").write_bytes(b"pending")
    else:
        monkeypatch.setattr(bootstrap_selection_store, "_read_at", lambda *_a, **_k: b"record")

    def refuse():
        raise ApprovalRefused(f"synthetic {failure} selection refusal")

    monkeypatch.setattr(bootstrap_selection_store, "load_bootstrap_selection", refuse)
    with pytest.raises(ApprovalRefused):
        optional.load_optional_bootstrap_selection()


def test_selection_appearing_during_absence_recheck_refuses(paths, monkeypatch):
    present_directory(paths)
    calls = []

    def changes_on_recheck(*_args, **_kwargs):
        calls.append(None)
        if len(calls) == 1:
            raise FileNotFoundError("synthetic absent selection")
        return b"selection appeared"

    monkeypatch.setattr(bootstrap_selection_store, "_read_at", changes_on_recheck)
    with pytest.raises(ApprovalRefused):
        optional.load_optional_bootstrap_selection()
    assert len(calls) == 2


def test_newly_created_directory_during_absence_recheck_refuses(paths, monkeypatch):
    original = paths[4]
    calls = []

    @contextmanager
    def changes_on_second_walk():
        calls.append(None)
        if len(calls) == 2:
            (paths[1] / "bootstrap").mkdir(mode=0o700)
            (paths[1] / "bootstrap").chmod(0o700)
        with original(root_fd=paths[2], owner=paths[3]) as result:
            yield result

    monkeypatch.setattr(
        bootstrap_store, "_optional_bootstrap_directory", changes_on_second_walk
    )
    with pytest.raises(ApprovalRefused):
        optional.load_optional_bootstrap_selection()
    assert len(calls) == 2


def test_replaced_present_directory_during_delegated_read_refuses(paths, monkeypatch):
    directory = present_directory(paths)
    selected = object()

    def replace_then_return():
        directory.rename(paths[1] / "old-bootstrap")
        replacement = paths[1] / "bootstrap"
        replacement.mkdir(mode=0o700)
        replacement.chmod(0o700)
        return selected

    monkeypatch.setattr(
        bootstrap_selection_store, "_read_at", lambda *_a, **_k: b"record"
    )
    monkeypatch.setattr(
        bootstrap_selection_store, "load_bootstrap_selection", replace_then_return
    )
    with pytest.raises(ApprovalRefused):
        optional.load_optional_bootstrap_selection()
