"""Protected reads for independently pinned bootstrap generations."""

from contextlib import contextmanager
import os
from pathlib import Path
import shutil

import pytest

from azazel_nexus.bootstrap_approval import BootstrapContext
from azazel_nexus.bootstrap_generation import VerifiedBootstrapGeneration
from azazel_nexus.bootstrap_generation_store import _load_at, load_bootstrap_generation
from azazel_nexus.generation import GenerationRefused, GenerationStore
from test_bootstrap_generation import _context, _write_bootstrap


def _chmod_tree(root: Path) -> None:
    root.chmod(0o700)
    generation = root / "7"
    generation.chmod(0o700)
    (generation / "tree").chmod(0o700)
    (generation / "generation.json").chmod(0o600)
    (generation / "tree" / "bootstrap.json").chmod(0o600)


def _store(tmp_path: Path, *, number: int = 7, package_digest=None):
    root = tmp_path / "generations"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    options = {} if package_digest is None else {"package_digest": package_digest}
    context, files = _write_bootstrap(GenerationStore(root), number=number, **options)
    _chmod_tree(root)
    return root, context, files


def _load(root: Path, expected: BootstrapContext):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return _load_at(fd, owner=os.getuid(), expected=expected)
    finally:
        os.close(fd)


def _public_reader(monkeypatch, root: Path):
    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr("azazel_nexus.bootstrap_generation_store._generation_directory", directory)
    original = _load_at

    def load_for_test(fd, *, owner, expected):
        return original(fd, owner=os.getuid(), expected=expected)

    monkeypatch.setattr("azazel_nexus.bootstrap_generation_store._load_at", load_for_test)


def test_descriptor_and_public_read_return_actual_verifier_result(tmp_path, monkeypatch):
    root, context, _ = _store(tmp_path)
    result = _load(root, context)
    assert result == VerifiedBootstrapGeneration(7, context.generation_digest, "2026-10-13T00:00:00Z")

    _public_reader(monkeypatch, root)
    assert load_bootstrap_generation(expected=context) == result


def test_normal_generation_reader_still_refuses_bootstrap(tmp_path):
    root, _, _ = _store(tmp_path)
    with pytest.raises(GenerationRefused):
        GenerationStore(root).read(7)


@pytest.mark.parametrize("case", ["missing", "number", "context"])
def test_refuses_missing_generation_number_or_context_mismatch(tmp_path, case):
    root, context, _ = _store(tmp_path)
    if case == "missing":
        (root / "7").rename(root / "old")
    elif case == "number":
        context = _context(generation=8)
    else:
        context = _context(policy_digest="sha256:" + "9" * 64)
    with pytest.raises(GenerationRefused):
        _load(root, context)


@pytest.mark.parametrize("location", ["generation", "tree"])
def test_refuses_extra_files_and_paths(tmp_path, location):
    root, context, _ = _store(tmp_path)
    target = root / "7" if location == "generation" else root / "7" / "tree"
    (target / "unexpected").mkdir()
    with pytest.raises(GenerationRefused):
        _load(root, context)


@pytest.mark.parametrize("mode", [0o750, 0o755])
def test_refuses_nonprivate_generation_directories(tmp_path, mode):
    root, context, _ = _store(tmp_path)
    (root / "7" / "tree").chmod(mode)
    with pytest.raises(GenerationRefused):
        _load(root, context)


@pytest.mark.parametrize("mode", [0o640, 0o644])
@pytest.mark.parametrize("filename", ["generation.json", "tree/bootstrap.json"])
def test_refuses_files_with_group_or_other_permissions(tmp_path, mode, filename):
    root, context, _ = _store(tmp_path)
    (root / "7" / filename).chmod(mode)
    with pytest.raises(GenerationRefused):
        _load(root, context)


@pytest.mark.parametrize("filename", ["generation.json", "tree/bootstrap.json"])
def test_refuses_symlink_files(tmp_path, filename):
    root, context, _ = _store(tmp_path)
    target = root / "7" / filename
    saved = target.read_bytes()
    target.unlink()
    replacement = tmp_path / "saved"
    replacement.write_bytes(saved)
    replacement.chmod(0o600)
    target.symlink_to(replacement)
    assert target.exists()  # Refuse a valid symlink, not merely a missing target.
    with pytest.raises(GenerationRefused):
        _load(root, context)


@pytest.mark.parametrize("filename", ["generation.json", "tree/bootstrap.json"])
def test_refuses_hardlinked_files(tmp_path, filename):
    root, context, _ = _store(tmp_path)
    target = root / "7" / filename
    os.link(target, tmp_path / "extra-link")
    with pytest.raises(GenerationRefused):
        _load(root, context)


@pytest.mark.parametrize("content", [b"", b"x" * 65537])
@pytest.mark.parametrize("filename", ["generation.json", "tree/bootstrap.json"])
def test_refuses_empty_or_oversized_files(tmp_path, content, filename):
    root, context, _ = _store(tmp_path)
    target = root / "7" / filename
    target.write_bytes(content)
    target.chmod(0o600)
    with pytest.raises(GenerationRefused):
        _load(root, context)


def test_refuses_generation_directory_replaced_during_verification(tmp_path, monkeypatch):
    root, context, _ = _store(tmp_path)
    import azazel_nexus.bootstrap_generation_store as reader

    verifier = reader.verify_bootstrap_generation

    def replace_then_verify(**kwargs):
        original = root / "7"
        moved = root / "old-generation"
        original.rename(moved)
        shutil.copytree(moved, original)
        for directory, _, files in os.walk(original):
            Path(directory).chmod(0o700)
            for filename in files:
                (Path(directory) / filename).chmod(0o600)
        return verifier(**kwargs)

    monkeypatch.setattr(reader, "verify_bootstrap_generation", replace_then_verify)
    with pytest.raises(GenerationRefused):
        _load(root, context)
