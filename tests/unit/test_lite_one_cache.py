"""One live cache, and one rule for serving it (#6, E1).

Two modules now know how to hold a Knowledge Lite artifact:
`lite_cache.StagedReader`, which faces Azazel-Knowledge's archives and its
negative fixtures, and `lite_service.KnowledgeLite`, which is the product
path. Two implementations of one concern agree only until one of them is
edited, so this file pins the two places they must not diverge.

The first test is a regression. Before it existed, a node whose staged reader
and generation store shared a root had one of them overwrite the other's
`live`, and the next promotion raised `NotADirectoryError` out of
`shutil.rmtree` -- an unhandled exception from a module whose own docstring
says it never raises for the node.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from pathlib import Path

import pytest

from azazel_nexus import lite_cache, lite_service
from azazel_nexus.content_store import ContentStore
from azazel_nexus.lite_cache import Admission, StagedReader, Verdict, split_by_freshness
from azazel_nexus.lite_generation import LiteGenerationStore

SIGNER = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def _generation_store(root: Path) -> LiteGenerationStore:
    return LiteGenerationStore(root=root, content=ContentStore(root=root))


def test_a_staged_reader_and_a_generation_store_share_a_root_without_colliding(
    tmp_path: Path,
) -> None:
    """The regression. Both mechanisms, one root, no exception.

    Asserted in both orders, because a collision that only happens when one
    goes first is still a collision.
    """

    for order, root in (("generation first", tmp_path / "a"), ("reader first", tmp_path / "b")):
        root.mkdir()
        generations = _generation_store(root)
        reader = StagedReader(root=root, verifier=lambda artifact: Verdict(True, "ok"))
        archive = tmp_path / f"incoming-{root.name}"
        archive.write_bytes(b"an archive")

        def promote() -> None:
            artifact = generations.content.put(b"artifact-" + root.name.encode())
            signature = generations.content.put(b"signature-" + root.name.encode())
            generations.promote(
                artifact_digest=artifact,
                signature_digest=signature,
                signer_key=SIGNER,
                admitted_at="2026-09-01T00:00:00Z",
            )

        def admit() -> None:
            decision = reader.admit(
                archive, extract=lambda src, dst: (dst / "claims").write_bytes(b"{}")
            )
            assert decision.admission is Admission.ADMITTED, order

        if order == "generation first":
            promote()
            admit()
        else:
            admit()
            promote()

        # Both mechanisms still answer, which is the whole point.
        assert generations.live() is not None, order
        assert reader.live.is_dir(), order


def test_the_generation_pointer_and_the_staged_cache_are_different_names() -> None:
    """Stated directly, so the collision cannot come back silently.

    One is a file holding a generation number; the other is a directory of
    unpacked content. They cannot share a name at one root.
    """

    root = Path("/nexus-lite")
    assert StagedReader(root=root).live != _generation_store(root).live_pointer


def test_a_second_promotion_after_a_generation_exists_does_not_raise(
    tmp_path: Path,
) -> None:
    """The exact call that raised: promote, admit, admit again.

    The second admission is the one that retires the first, and retiring is
    where the old code walked into the generation store's file.
    """

    root = tmp_path / "lite"
    root.mkdir()
    generations = _generation_store(root)
    generations.promote(
        artifact_digest=generations.content.put(b"artifact"),
        signature_digest=generations.content.put(b"signature"),
        signer_key=SIGNER,
        admitted_at="2026-09-01T00:00:00Z",
    )

    reader = StagedReader(root=root, verifier=lambda artifact: Verdict(True, "ok"))
    archive = tmp_path / "incoming"
    archive.write_bytes(b"an archive")
    for _ in range(2):
        decision = reader.admit(
            archive, extract=lambda src, dst: (dst / "claims").write_bytes(b"{}")
        )
        assert decision.admission is Admission.ADMITTED
    assert generations.live().number == 1


# -- one rule for serving --------------------------------------------------


def test_both_paths_use_the_same_serving_rule() -> None:
    """Not "they agree on this input" -- they are the same function.

    `serve` is parsed rather than grepped: its docstring names the shared
    function too, and a test that counted mentions would pass for a body that
    had gone back to deciding for itself.
    """

    assert lite_service.split_by_freshness is split_by_freshness
    assert "split_by_freshness" in lite_service.KnowledgeLite.read.__code__.co_names

    tree = ast.parse(textwrap.dedent(inspect.getsource(StagedReader.serve)))
    body = [
        node
        for node in tree.body[0].body
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))
    ]
    assert len(body) == 1, "serve delegates; it does not decide"
    statement = body[0]
    assert isinstance(statement, ast.Return)
    assert isinstance(statement.value, ast.Call)
    assert statement.value.func.id == "split_by_freshness"


def test_the_service_has_no_serving_rule_of_its_own() -> None:
    """A private copy would be the drift this file exists to prevent."""

    module_source = inspect.getsource(lite_service)
    assert "Freshness.CURRENT" not in module_source
    assert "classify_freshness(" not in module_source


@pytest.mark.parametrize(
    "claims, served_ids, withheld_ids",
    [
        ([{"id": "a", "expiry": "2030-01-01T00:00:00Z"}], ["a"], []),
        ([{"id": "b", "expiry": "2020-01-01T00:00:00Z"}], [], ["b"]),
        ([{"id": "c"}], ["c"], []),
        ([{"id": "d", "expiry": "not a date"}], [], ["d"]),
    ],
)
def test_the_shared_rule_withholds_rather_than_labels(
    claims: list[dict], served_ids: list[str], withheld_ids: list[str]
) -> None:
    served, withheld = split_by_freshness(claims, as_of="2026-09-20T00:00:00Z")
    assert [claim["id"] for claim in served] == served_ids
    assert [claim["id"] for claim in withheld] == withheld_ids
    for claim in served + withheld:
        assert "freshness" in claim, "the label survives on everything, served or not"


def test_the_staged_reader_and_the_service_split_one_input_identically() -> None:
    """The behavioural half of the claim, alongside the structural one above."""

    claims = [
        {"id": "current", "expiry": "2030-01-01T00:00:00Z"},
        {"id": "expired", "expiry": "2020-01-01T00:00:00Z"},
        {"id": "undated"},
    ]
    reader = StagedReader(root=Path("/nexus-lite"))
    assert reader.serve(claims, as_of="2026-09-20T00:00:00Z") == split_by_freshness(
        claims, as_of="2026-09-20T00:00:00Z"
    )


def test_the_two_vocabularies_describe_different_questions() -> None:
    """`Admission` and `LiteState` are not two names for one thing.

    `Admission` answers "how did this admission attempt end"; `LiteState`
    answers "what is the cache now". Keeping the value sets disjoint is what
    stops a later reader from assuming a mapping that does not exist.
    """

    admissions = {value.value for value in Admission}
    states = {value.value for value in lite_service.LiteState}
    assert admissions == {"admitted", "absent", "refused", "unverifiable"}
    assert states == {"available", "stale", "unavailable", "quarantined"}
    assert admissions & states == set()


def test_lite_cache_still_never_raises_for_the_node(tmp_path: Path) -> None:
    """The docstring's promise, exercised on the path that once broke it."""

    root = tmp_path / "lite"
    root.mkdir()
    (root / "live").write_text("1\n", encoding="utf-8")  # the generation pointer
    reader = StagedReader(root=root, verifier=lambda artifact: Verdict(True, "ok"))
    archive = tmp_path / "incoming"
    archive.write_bytes(b"an archive")

    decision = reader.admit(archive, extract=lambda src, dst: (dst / "c").write_bytes(b"{}"))
    assert decision.admission is Admission.ADMITTED
    assert decision.blocks_core() is False
    assert (root / "live").read_text(encoding="utf-8") == "1\n", "the pointer was not touched"


def test_staged_cache_directories_ignore_loose_umask(tmp_path):
    import os
    reader = StagedReader(root=tmp_path / "cache")
    previous = os.umask(0o002)
    try:
        reader._reset_staging()
        reader._promote()
    finally:
        os.umask(previous)
    for directory in (reader.root, reader.staging, reader.live):
        assert directory.stat().st_mode & 0o022 == 0


@pytest.mark.parametrize("operation", ["reset", "promote"])
def test_staged_cache_refuses_symlinked_directory(tmp_path, operation):
    target = tmp_path / "outside"
    target.mkdir()
    reader = StagedReader(root=tmp_path / "cache")
    if operation == "reset":
        reader.root.mkdir()
        reader.staging.symlink_to(target, target_is_directory=True)
    else:
        reader.root.symlink_to(target, target_is_directory=True)
        reader.staging.mkdir()
        (reader.staging / "claims").write_bytes(b"{}")
    before = sorted(path.relative_to(target) for path in target.rglob("*"))
    with pytest.raises(OSError):
        if operation == "reset":
            reader._reset_staging()
        else:
            reader._promote()
    assert sorted(path.relative_to(target) for path in target.rglob("*")) == before
