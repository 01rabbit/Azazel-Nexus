"""How a model artifact gets in, and what getting in does not buy it (#95).

The distinctions this file defends:

*not in the inbox* ≠ *not in the catalog* ≠ *does not fit* ≠ *does not verify*
≠ *installed*. And *installed* is not *admitted*, which is not *running*.

The signing oracle is a fixed, test-only key derived from a literal string.
It is shared with no production, commissioned or release key, exists only for
the run, and no key material reaches a file, a fixture, a log or an assertion.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import pathlib

import pytest

from azazel_nexus import model_import
from azazel_nexus.model_catalog import (
    CATALOG_DOMAIN,
    CATALOG_FILENAME,
    CatalogState,
    ModelEntry,
    Refusal,
    artifact_filename,
    catalog_payload,
)
from azazel_nexus.model_import import (
    MAX_ARTIFACT_BYTES,
    MAX_INBOX_ENTRIES,
    MAX_RETAINED_GENERATIONS,
    MIN_FREE_HEADROOM_BYTES,
    CommissionedModels,
    ImportRefusal,
    ImportRefused,
    ModelImport,
    Transition,
    entry_id_for,
)
from azazel_nexus.resource_profile import ResourceProfile

nacl_signing = pytest.importorskip("nacl.signing", reason="PyNaCl is a dev dependency")

COMMISSIONING = "sha256:" + "c" * 64
NOW = "2026-01-01T00:00:00Z"
ACTOR = "operator-under-test"

#: Fixed, test-only. Never leaves this process.
_SEED = hashlib.sha256(b"azazel-nexus/test-only/model-import/0").digest()

WEIGHTS = b"weights, not a program -- " + b"w" * 4096
OTHER_WEIGHTS = b"different weights entirely -- " + b"x" * 8192


def _key():
    return nacl_signing.SigningKey(_SEED)


def trusted():
    return {"catalog-key": bytes(_key().verify_key)}


def an_entry(body=WEIGHTS, **overrides) -> ModelEntry:
    fields = {
        "model_id": "small-advisor",
        "format": "gguf",
        "digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        "size_bytes": len(body),
        "provenance": "fixture",
        "license_acknowledgement_required": False,
        "runtime_abi": "llama.cpp/1",
        "purpose": "summarise a situation frame",
        "context_limit": 4096,
        "declared_min_ram_mib": 4096,
        "declared_min_disk_mib": 2048,
        "declared_profile": ResourceProfile.LITE,
        "rollback_lineage": (),
    }
    fields.update(overrides)
    return ModelEntry(**fields)


@pytest.fixture
def node(tmp_path):
    """A commissioned node with a signed catalog and an empty inbox."""

    root = tmp_path / "node"
    (root / "inbox").mkdir(parents=True)
    (root / "trust").mkdir(parents=True)
    commissioned = CommissionedModels(
        root=root, trusted_keys=trusted(), commissioning_digest=COMMISSIONING
    )
    _write_catalog(root, [an_entry()])
    return commissioned


def _write_catalog(root, entries):
    body = catalog_payload(
        version=1, commissioning_digest=COMMISSIONING, entries=list(entries)
    )
    signature = bytes(_key().sign(CATALOG_DOMAIN + body).signature)
    path = root / "trust" / CATALOG_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(signature + body)
    return path


def _second_entry() -> ModelEntry:
    return an_entry(
        model_id="second",
        digest="sha256:" + hashlib.sha256(OTHER_WEIGHTS).hexdigest(),
        size_bytes=len(OTHER_WEIGHTS),
    )


def place(node, name="model.bin", body=WEIGHTS) -> str:
    """Put an artifact in the inbox and return the id it answers to."""

    (node.inbox / name).write_bytes(body)
    return entry_id_for(display_name=name, size=len(body))


def recorded():
    """A recorder that keeps the transitions, so the audit can be read back."""

    log = []
    return log, lambda transition, event: log.append((transition, dict(event)))


def an_import(node, log=None):
    if log is None:
        return ModelImport(node)
    return ModelImport(node, recorder=lambda t, e: log.append((t, dict(e))))


# -- the inbox is enumerated, never passed through -------------------------


def test_the_inbox_is_enumerated_and_takes_no_path(node) -> None:
    entry_id = place(node)
    service = an_import(node)
    listing = service.list_inbox()
    assert [entry.display_name for entry in listing] == ["model.bin"]
    assert listing[0].entry_id == entry_id
    # And the signature of the import takes an id, not a path.
    parameters = model_import.ModelImport.import_entry.__code__.co_varnames[:4]
    assert "path" not in parameters and "root" not in parameters


def test_an_id_the_listing_does_not_produce_is_refused(node) -> None:
    place(node)
    outcome = an_import(node).import_entry(
        "f" * 64, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.refused_by is ImportRefusal.NOT_IN_INBOX
    assert outcome.transition is None


def test_a_file_swapped_after_the_listing_no_longer_answers_to_its_id(node) -> None:
    """The id covers the size, so a substitution is a different entry."""

    entry_id = place(node)
    (node.inbox / "model.bin").write_bytes(OTHER_WEIGHTS)
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.refused_by is ImportRefusal.NOT_IN_INBOX


def test_enumeration_reads_no_artifact(node, monkeypatch) -> None:
    """Listing must not cost what importing costs.

    Every way the module could open the file is watched, not just the one it
    happens to use: a test that pinned `Path.open` alone would go green the
    day somebody reached for `builtins.open` instead.
    """

    place(node, body=WEIGHTS)
    opened = []
    real_path_open, real_open, real_os_open = pathlib.Path.open, open, os.open

    def watched_path(self, *args, **kwargs):
        opened.append(str(self))
        return real_path_open(self, *args, **kwargs)

    def watched_builtin(file, *args, **kwargs):
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    def watched_os(path, *args, **kwargs):
        opened.append(str(path))
        return real_os_open(path, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", watched_path)
    monkeypatch.setattr("builtins.open", watched_builtin)
    monkeypatch.setattr(model_import.os, "open", watched_os)
    an_import(node).list_inbox()
    assert [name for name in opened if "inbox" in name] == []


def test_a_symlink_in_the_inbox_is_not_listed(node) -> None:
    """Following one would read outside the operator's media entirely."""

    outside = node.root / "elsewhere.bin"
    outside.write_bytes(OTHER_WEIGHTS)
    (node.inbox / "link.bin").symlink_to(outside)
    (node.inbox / "real.bin").write_bytes(WEIGHTS)
    assert [e.display_name for e in an_import(node).list_inbox()] == ["real.bin"]


def test_the_listing_is_bounded(node) -> None:
    for index in range(MAX_INBOX_ENTRIES + 8):
        (node.inbox / f"m{index:03d}.bin").write_bytes(b"x")
    assert len(an_import(node).list_inbox()) == MAX_INBOX_ENTRIES


def test_an_overfull_inbox_refuses_rather_than_importing_from_a_cut_listing(node) -> None:
    entry_id = place(node)
    for index in range(MAX_INBOX_ENTRIES):
        (node.inbox / f"z{index:03d}.bin").write_bytes(b"x")
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.refused_by is ImportRefusal.INBOX_OVERFULL


# -- the catalog decides what may be selected ------------------------------


def test_a_model_the_catalog_does_not_name_is_refused(node) -> None:
    entry_id = place(node)
    outcome = an_import(node).import_entry(
        entry_id, "never-declared", now=NOW, actor=ACTOR
    )
    assert outcome.refused_by is ImportRefusal.NOT_IN_CATALOG
    assert outcome.transition is None


def test_an_unreadable_catalog_refuses_the_import(node) -> None:
    entry_id = place(node)
    node.catalog_path.unlink()
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.refused_by is ImportRefusal.CATALOG_UNREADABLE


# -- capacity is checked before staging, not during ------------------------


def test_free_space_is_checked_before_a_byte_is_staged(node, monkeypatch) -> None:
    """A node must not discover the disk is full with half an artifact on it."""

    entry_id = place(node)
    staged = []
    monkeypatch.setattr(
        model_import.ModelImport,
        "_stage",
        lambda self, entry, declared: staged.append(entry) or pathlib.Path("."),
    )
    monkeypatch.setattr(
        model_import.ModelImport,
        "_room_for",
        lambda self, size: (False, f"no room for {size}"),
    )
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.refused_by is ImportRefusal.INSUFFICIENT_DISK
    assert staged == [], "staging began although the precheck had refused"


def test_the_precheck_reserves_headroom_for_the_node_itself(node, monkeypatch) -> None:
    """Importing a model and losing the ability to write the audit chain is
    not a gain."""

    class Statvfs:
        f_frsize = 1
        f_bavail = MIN_FREE_HEADROOM_BYTES + len(WEIGHTS) - 1

    monkeypatch.setattr(model_import.os, "statvfs", lambda path: Statvfs())
    service = an_import(node)
    service._prepare_directories()
    room, detail = service._room_for(len(WEIGHTS))
    assert room is False
    assert str(MIN_FREE_HEADROOM_BYTES) in detail
    Statvfs.f_bavail = MIN_FREE_HEADROOM_BYTES + len(WEIGHTS)
    assert service._room_for(len(WEIGHTS))[0] is True


def test_an_artifact_over_the_ceiling_is_refused(node) -> None:
    _write_catalog(node.root, [an_entry(size_bytes=MAX_ARTIFACT_BYTES + 1)])
    (node.inbox / "huge.bin").write_bytes(b"x")
    entry_id = entry_id_for(display_name="huge.bin", size=1)
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.refused_by is ImportRefusal.TOO_LARGE


def test_a_cross_device_promotion_is_refused_as_not_atomic(node, monkeypatch) -> None:
    """No amount of free space makes a copy-and-unlink atomic."""

    entry_id = place(node)
    service = an_import(node)
    service._prepare_directories()
    real_stat = pathlib.Path.stat

    def split(self, *args, **kwargs):
        result = real_stat(self, *args, **kwargs)
        if self == node.store:
            return os.stat_result(
                tuple(result)[:2] + (result.st_dev + 1,) + tuple(result)[3:]
            )
        return result

    monkeypatch.setattr(pathlib.Path, "stat", split)
    outcome = service.import_entry(entry_id, "small-advisor", now=NOW, actor=ACTOR)
    assert outcome.refused_by is ImportRefusal.PROMOTION_NOT_ATOMIC
    assert "atomic" in outcome.detail


# -- each verification condition refuses on its own ------------------------


def test_a_verified_artifact_is_promoted(node) -> None:
    entry_id = place(node)
    log, recorder = recorded()
    outcome = ModelImport(node, recorder=recorder).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.promoted
    assert outcome.reading.state is CatalogState.PRESENT
    assert outcome.generation.number == 1
    assert outcome.generation.installed == {"small-advisor": an_entry().digest}
    assert (node.store / artifact_filename(an_entry())).read_bytes() == WEIGHTS
    assert (node.store / artifact_filename(an_entry())).stat().st_mode & 0o777 == 0o640
    assert [transition for transition, _ in log] == [
        Transition.IMPORT_STARTED,
        Transition.PROMOTED,
    ]


@pytest.mark.parametrize(
    "magic",
    [
        pytest.param(b"\x7fELF", id="elf"),
        pytest.param(b"PK\x03\x04", id="zip"),
        pytest.param(b"#!/bin/sh\n", id="shebang"),
        pytest.param(b"\x1f\x8b", id="gzip"),
    ],
)
def test_a_program_or_an_archive_is_quarantined_not_stored(node, magic) -> None:
    """Each condition reaches its own refusal, and none reaches the store."""

    body = magic + WEIGHTS[len(magic):]
    expected = Refusal.NOT_WEIGHTS
    assert len(body) == len(WEIGHTS)
    entry_id = place(node, body=body)
    _write_catalog(node.root, [an_entry(digest="sha256:" + hashlib.sha256(body).hexdigest())])
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.transition is Transition.QUARANTINED
    assert outcome.reading.refused_by is expected
    assert list(node.store.iterdir()) == []
    assert len(list(node.quarantine.iterdir())) == 1


def test_a_digest_mismatch_is_quarantined(node) -> None:
    body = b"y" * len(WEIGHTS)
    entry_id = place(node, body=body)
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.reading.refused_by is Refusal.DIGEST_MISMATCH
    assert list(node.store.iterdir()) == []


def test_a_size_mismatch_is_refused_before_a_byte_is_copied(node, monkeypatch) -> None:
    entry_id = place(node, body=WEIGHTS + b"extra")
    copied = []
    monkeypatch.setattr(
        model_import.ModelImport,
        "_stage",
        lambda self, entry, declared: copied.append(1) or pathlib.Path("."),
    )
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.reading.refused_by is Refusal.SIZE_MISMATCH
    assert copied == []


def test_an_unacknowledged_licence_quarantines_rather_than_installing(node) -> None:
    """The operator's acknowledgement is the operator's; the default is
    withheld, and the import does not supply it on their behalf."""

    _write_catalog(node.root, [an_entry(license_acknowledgement_required=True)])
    entry_id = place(node)
    outcome = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    )
    assert outcome.reading.refused_by is Refusal.LICENSE_NOT_ACKNOWLEDGED
    assert list(node.store.iterdir()) == []
    granted = an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR, license_acknowledged=True
    )
    assert granted.promoted


def test_the_import_never_consumes_the_inbox(node) -> None:
    """An import that ate the only copy would be one nobody could retry."""

    entry_id = place(node)
    an_import(node).import_entry(entry_id, "small-advisor", now=NOW, actor=ACTOR)
    assert (node.inbox / "model.bin").read_bytes() == WEIGHTS
    bad = place(node, name="bad.bin", body=b"z" * len(WEIGHTS))
    an_import(node).import_entry(bad, "small-advisor", now=NOW, actor=ACTOR)
    assert (node.inbox / "bad.bin").exists()


# -- quarantine holds, and does nothing else -------------------------------


def test_quarantine_holds_and_the_module_has_no_verb_that_would_do_more() -> None:
    source = pathlib.Path(model_import.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node_ in ast.walk(tree):
        if isinstance(node_, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node_.names)
        elif isinstance(node_, ast.ImportFrom) and node_.module and node_.level == 0:
            imported.add(node_.module.split(".")[0])
    # `shutil` above all: importing it would put `unpack_archive` one
    # attribute access away from a module whose contract is that it unpacks
    # nothing.
    assert imported & {
        "subprocess", "shutil", "tarfile", "zipfile", "gzip", "lzma", "bz2",
        "socket", "ssl", "http", "urllib", "requests", "httpx", "ctypes",
    } == set()
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert not any(
        name.lstrip("_").startswith(
            ("run", "exec", "launch", "start", "download", "fetch", "unpack",
             "extract", "retry", "serve", "admit", "activate")
        )
        for name in names
    ), sorted(names)


def test_a_quarantined_artifact_is_not_retried_on_the_next_import(node) -> None:
    bad = place(node, name="bad.bin", body=b"z" * len(WEIGHTS))
    service = an_import(node)
    service.import_entry(bad, "small-advisor", now=NOW, actor=ACTOR)
    held = sorted(p.name for p in node.quarantine.iterdir())
    assert len(held) == 1
    # A second, unrelated import must not touch what is held.
    good = place(node)
    service.import_entry(good, "small-advisor", now=NOW, actor=ACTOR)
    assert sorted(p.name for p in node.quarantine.iterdir()) == held


# -- interruption leaves no half state -------------------------------------


def test_an_interrupt_during_staging_leaves_nothing_behind(node) -> None:
    """Killed mid-copy: no store entry, no generation, and staging swept."""

    entry_id = place(node)

    class Killed(BaseException):
        pass

    class Dying(ModelImport):
        def _stage(self, entry, declared):
            path = super()._stage(entry, declared)
            raise Killed(str(path))

    with pytest.raises(Killed):
        Dying(node).import_entry(entry_id, "small-advisor", now=NOW, actor=ACTOR)
    assert list(node.store.iterdir()) == []
    assert an_import(node).current_generation() is None
    # The debris is real and is named: without it, the sweep below would have
    # nothing to prove.
    debris = sorted(p.name for p in node.staging.iterdir())
    assert debris == [artifact_filename(an_entry())]
    # A *failing* import sweeps it, so the sweep is not the promotion tidying
    # up after itself. This one is refused for a reason of its own.
    an_import(node).import_entry("f" * 64, "small-advisor", now=NOW, actor=ACTOR)
    assert sorted(p.name for p in node.staging.iterdir()) == []
    # And the node still works afterwards.
    assert an_import(node).import_entry(
        entry_id, "small-advisor", now=NOW, actor=ACTOR
    ).promoted


def test_an_interrupt_between_the_generation_and_the_pointer_keeps_the_old_one(
    node, monkeypatch
) -> None:
    """A generation nothing points at is debris. A pointer to a generation
    that is not there would be a node that cannot start."""

    first = place(node)
    an_import(node).import_entry(first, "small-advisor", now=NOW, actor=ACTOR)
    before = an_import(node).current_generation()

    calls = []
    real = model_import._atomic_write

    def die_on_the_pointer(path, payload):
        calls.append(path)
        if path == node.current_path:
            raise KeyboardInterrupt("killed before the pointer moved")
        return real(path, payload)

    monkeypatch.setattr(model_import, "_atomic_write", die_on_the_pointer)
    second_body = OTHER_WEIGHTS
    second = place(node, name="second.bin", body=second_body)
    _write_catalog(
        node.root,
        [an_entry(), an_entry(model_id="second", body=second_body,
                              digest="sha256:" + hashlib.sha256(second_body).hexdigest(),
                              size_bytes=len(second_body))],
    )
    with pytest.raises(KeyboardInterrupt):
        an_import(node).import_entry(second, "second", now=NOW, actor=ACTOR)
    after = an_import(node).current_generation()
    assert after.generation_id == before.generation_id
    assert after.installed == before.installed


# -- rollback --------------------------------------------------------------


def test_rollback_restores_the_previous_generation_and_records_why(node) -> None:
    second_body = OTHER_WEIGHTS
    _write_catalog(
        node.root,
        [an_entry(), an_entry(model_id="second", body=second_body,
                              digest="sha256:" + hashlib.sha256(second_body).hexdigest(),
                              size_bytes=len(second_body))],
    )
    log, recorder = recorded()
    service = ModelImport(node, recorder=recorder)
    first = place(node)
    service.import_entry(first, "small-advisor", now=NOW, actor=ACTOR)
    generation_one = service.current_generation()
    second = place(node, name="second.bin", body=second_body)
    service.import_entry(second, "second", now=NOW, actor=ACTOR)
    assert set(service.current_generation().installed) == {"small-advisor", "second"}

    restored = service.rollback(reason="the second model answered badly", actor=ACTOR, now=NOW)
    assert restored.generation_id == generation_one.generation_id
    assert set(service.current_generation().installed) == {"small-advisor"}
    entry = [event for transition, event in log if transition is Transition.ROLLED_BACK]
    assert len(entry) == 1
    recorded_event = entry[0]
    assert recorded_event["reason"] == "the second model answered badly"
    assert recorded_event["actor"] == ACTOR
    assert recorded_event["from_generation"] == 2
    assert recorded_event["to_generation"] == 1
    assert recorded_event["to_generation_id"] == generation_one.generation_id
    assert recorded_event["digests"] == [an_entry().digest]


def test_a_rollback_with_no_predecessor_is_refused_not_invented(node) -> None:
    entry_id = place(node)
    service = an_import(node)
    service.import_entry(entry_id, "small-advisor", now=NOW, actor=ACTOR)
    with pytest.raises(ImportRefused) as caught:
        service.rollback(reason="nothing to go back to", actor=ACTOR, now=NOW)
    assert "no earlier generation" in str(caught.value)


def test_a_rollback_records_a_reason_or_does_not_happen(node) -> None:
    """With a predecessor in place, so that only the blank reason can refuse
    it. Without one, this passed on "there is nothing to go back to" -- a
    test green for a reason it was not testing."""

    second_body = OTHER_WEIGHTS
    _write_catalog(node.root, [an_entry(), _second_entry()])
    service = an_import(node)
    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    service.import_entry(
        place(node, name="second.bin", body=second_body), "second", now=NOW, actor=ACTOR
    )
    with pytest.raises(ImportRefused) as caught:
        service.rollback(reason="   ", actor=ACTOR, now=NOW)
    assert "records why" in str(caught.value)
    # And with a reason it lands, so the refusal above was the reason's.
    assert service.rollback(reason="a stated reason", actor=ACTOR, now=NOW).number == 1


def test_a_rollback_onto_a_missing_artifact_is_refused(node) -> None:
    """Restoring a generation the store can no longer satisfy would activate
    a generation that is not complete."""

    _write_catalog(node.root, [an_entry(), _second_entry()])
    service = an_import(node)
    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    service.import_entry(
        place(node, name="second.bin", body=OTHER_WEIGHTS), "second", now=NOW, actor=ACTOR
    )
    (node.store / artifact_filename(an_entry())).unlink()
    with pytest.raises(ImportRefused) as caught:
        service.rollback(reason="the store lost it", actor=ACTOR, now=NOW)
    assert "no longer holds" in str(caught.value)
    # And the current generation is untouched by the refusal.
    assert set(service.current_generation().installed) == {"small-advisor", "second"}


def test_the_staged_copy_stops_at_the_declared_size(node) -> None:
    """A file that grows while it is read is stopped, not copied to the end.

    The post-loop length check would also catch it -- after the disk had
    taken the whole thing. The bound is in the loop so that it does not.
    """

    service = an_import(node)
    service._prepare_directories()
    (node.inbox / "grown.bin").write_bytes(WEIGHTS + b"much more than declared")
    entry = model_import.InboxEntry(
        entry_id=entry_id_for(display_name="grown.bin", size=len(WEIGHTS)),
        size=len(WEIGHTS),
        display_name="grown.bin",
    )
    with pytest.raises(ImportRefused) as caught:
        service._stage(entry, an_entry())
    assert "yielded more than" in str(caught.value)
    assert list(node.staging.iterdir()) == []


def test_the_staged_copy_refuses_a_short_read(node) -> None:
    """Fewer bytes than declared is refused where it is observed, not left
    for the digest to notice later."""

    service = an_import(node)
    service._prepare_directories()
    (node.inbox / "short.bin").write_bytes(WEIGHTS[:-16])
    entry = model_import.InboxEntry(
        entry_id=entry_id_for(display_name="short.bin", size=len(WEIGHTS)),
        size=len(WEIGHTS),
        display_name="short.bin",
    )
    with pytest.raises(ImportRefused) as caught:
        service._stage(entry, an_entry())
    assert "bytes read against" in str(caught.value)
    assert list(node.staging.iterdir()) == []


def test_bytes_in_the_store_are_not_an_installed_model(node) -> None:
    """The store holding an artifact is not the node having installed it.

    Verification alone would call this `present`; only a generation naming it
    makes it so. Debris from an interrupted sweep must not read as installed.
    """

    service = an_import(node)
    service._prepare_directories()
    (node.store / artifact_filename(an_entry())).write_bytes(WEIGHTS)
    reading = service.reading_for("small-advisor")
    assert reading.state is CatalogState.DECLARED
    assert reading.refused_by is Refusal.ARTIFACT_ABSENT
    assert "no generation installs it" in reading.reason


def test_a_generation_id_covers_what_is_installed(node) -> None:
    """Two generations can share a number across nodes; they must not share
    an id while installing different things."""

    one = model_import._generation_id(2, {"a": "sha256:" + "1" * 64})
    other = model_import._generation_id(2, {"a": "sha256:" + "2" * 64})
    more = model_import._generation_id(2, {"a": "sha256:" + "1" * 64, "b": "sha256:" + "3" * 64})
    assert len({one, other, more}) == 3
    assert model_import._generation_id(3, {"a": "sha256:" + "1" * 64}) != one


def test_distinct_entries_get_distinct_ids() -> None:
    """The size trails as a fixed width, so the name is whatever precedes it."""

    pairs = [
        ("a", 1), ("a", 2), ("ab", 1), ("b", 1), ("a\x00b", 1), ("", 1),
        # The pair that collides the moment the size stops being fixed-width:
        # "a" + "11" and "a1" + "1" are the same bytes.
        ("a", 11), ("a1", 1),
    ]
    assert len({entry_id_for(display_name=n, size=s) for n, s in pairs}) == len(pairs)


def test_the_predecessors_artifact_is_retained_so_rollback_can_land(node) -> None:
    """Retention is what makes rollback possible, and what makes it cost disk."""

    second_body = OTHER_WEIGHTS
    second_entry = an_entry(
        model_id="second", digest="sha256:" + hashlib.sha256(second_body).hexdigest(),
        size_bytes=len(second_body),
    )
    _write_catalog(node.root, [an_entry(), second_entry])
    service = an_import(node)
    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    service.import_entry(
        place(node, name="second.bin", body=second_body), "second", now=NOW, actor=ACTOR
    )
    assert (node.store / artifact_filename(an_entry())).exists()
    assert (node.store / artifact_filename(second_entry)).exists()


def test_cleanup_removes_only_what_no_retained_generation_names(node) -> None:
    """An artifact nothing references is disk. One a live generation
    references and that is missing is a node that cannot start."""

    service = an_import(node)
    service._prepare_directories()
    orphan = node.store / ("0" * 64 + ".gguf")
    orphan.write_bytes(b"nobody references this")
    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    assert not orphan.exists()
    assert (node.store / artifact_filename(an_entry())).exists()


def test_generations_are_retained_only_to_the_window(node) -> None:
    service = an_import(node)
    for index in range(MAX_RETAINED_GENERATIONS + 3):
        body = b"g" + bytes([index]) + b"w" * 512
        entry = an_entry(
            model_id=f"m{index}", digest="sha256:" + hashlib.sha256(body).hexdigest(),
            size_bytes=len(body),
        )
        existing = [
            an_entry(model_id=f"m{i}",
                     digest="sha256:" + hashlib.sha256(b"g" + bytes([i]) + b"w" * 512).hexdigest(),
                     size_bytes=len(body))
            for i in range(index)
        ]
        _write_catalog(node.root, existing + [entry])
        service.import_entry(
            place(node, name=f"m{index}.bin", body=body), f"m{index}", now=NOW, actor=ACTOR
        )
    kept = sorted(int(p.stem) for p in node.generations.glob("*.json"))
    assert len(kept) == MAX_RETAINED_GENERATIONS
    assert kept[-1] == MAX_RETAINED_GENERATIONS + 3


def test_a_model_the_installed_generation_supersedes_is_refused(node) -> None:
    """Rolling forward is not rolling back. An entry the installed set
    declares superseded does not come back in by being offered again."""

    successor = an_entry(
        model_id="successor",
        digest="sha256:" + hashlib.sha256(OTHER_WEIGHTS).hexdigest(),
        size_bytes=len(OTHER_WEIGHTS),
        rollback_lineage=("small-advisor",),
    )
    _write_catalog(node.root, [an_entry(), successor])
    service = an_import(node)
    service.import_entry(
        place(node, name="successor.bin", body=OTHER_WEIGHTS),
        "successor", now=NOW, actor=ACTOR,
    )
    outcome = service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    assert outcome.reading.refused_by is Refusal.STALE_ROLLBACK_LINEAGE
    assert "small-advisor" not in service.current_generation().installed


def test_promotion_drops_what_the_new_entry_supersedes(node) -> None:
    successor = an_entry(
        model_id="successor",
        digest="sha256:" + hashlib.sha256(OTHER_WEIGHTS).hexdigest(),
        size_bytes=len(OTHER_WEIGHTS),
        rollback_lineage=("small-advisor",),
    )
    _write_catalog(node.root, [an_entry(), successor])
    service = an_import(node)
    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    assert set(service.current_generation().installed) == {"small-advisor"}
    service.import_entry(
        place(node, name="successor.bin", body=OTHER_WEIGHTS),
        "successor", now=NOW, actor=ACTOR,
    )
    assert set(service.current_generation().installed) == {"successor"}
    # And the superseded artifact survives, because the generation that named
    # it is still retained. A rollback with nothing to land on is not one.
    assert (node.store / artifact_filename(an_entry())).exists()
    restored = service.rollback(reason="the successor was worse", actor=ACTOR, now=NOW)
    assert set(restored.installed) == {"small-advisor"}


# -- installed is not admitted ---------------------------------------------


def test_an_installed_artifact_is_present_and_still_not_admitted(node) -> None:
    """Being in the store is not permission to be used."""

    service = an_import(node)
    outcome = service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    assert outcome.promoted
    reading = service.reading_for("small-advisor")
    assert reading.state is CatalogState.PRESENT
    assert reading.admitted is False
    assert "HG-05" in reading.reason
    assert outcome.reading.admitted is False


def test_the_outcome_has_no_word_that_would_read_as_usable(node) -> None:
    outcome = an_import(node).import_entry(
        place(node), "small-advisor", now=NOW, actor=ACTOR
    )
    event = outcome.as_event()
    assert "available" not in event and "ready" not in event
    assert event["admitted"] is False
    assert "AVAILABLE" not in {t.name for t in Transition}


def test_reading_for_distinguishes_absent_empty_declared_and_present(node, tmp_path) -> None:
    """Four answers, four states -- collapsing them is the failure this
    whole path exists to avoid."""

    bare = CommissionedModels(
        root=tmp_path / "bare", trusted_keys=trusted(), commissioning_digest=COMMISSIONING
    )
    assert ModelImport(bare).reading_for("small-advisor").state is CatalogState.ABSENT

    _write_catalog(node.root, [])
    assert an_import(node).reading_for("small-advisor").state is CatalogState.EMPTY

    _write_catalog(node.root, [an_entry()])
    service = an_import(node)
    declared = service.reading_for("small-advisor")
    assert declared.state is CatalogState.DECLARED
    assert declared.refused_by is Refusal.ARTIFACT_ABSENT

    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    assert service.reading_for("small-advisor").state is CatalogState.PRESENT


def test_a_status_read_writes_nothing(node) -> None:
    """A ledger that grew every time somebody looked at a screen would be a
    ledger nobody can read."""

    service = an_import(node)
    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    def snapshot():
        return {
            str(path.relative_to(node.root)): (
                path.stat().st_mtime_ns if path.is_file() else "dir"
            )
            for path in sorted(node.root.rglob("*"))
        }

    before = snapshot()
    log, recorder = recorded()
    watched = ModelImport(node, recorder=recorder)
    watched.reading_for("small-advisor")
    watched.current_generation()
    watched.list_inbox()
    assert snapshot() == before
    assert log == []


# -- the audit carries no content and no key material ----------------------


def test_the_audit_records_digests_and_reasons_never_content(node) -> None:
    log, recorder = recorded()
    service = ModelImport(node, recorder=recorder)
    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    service.import_entry(
        place(node, name="bad.bin", body=b"z" * len(WEIGHTS)),
        "small-advisor", now=NOW, actor=ACTOR,
    )
    flattened = json.dumps([(t.value, e) for t, e in log])
    assert WEIGHTS.decode("utf-8", "ignore")[:24] not in flattened
    assert "z" * 32 not in flattened
    for forbidden in ("prompt", "secret", "token", "private", "signing"):
        assert forbidden not in flattened.lower(), forbidden
    assert an_entry().digest in flattened


def test_no_artifact_or_manifest_is_committed_to_the_repository() -> None:
    repository = pathlib.Path(__file__).resolve().parents[2]
    found = [
        str(path.relative_to(repository))
        for name in ("current", "installed.json")
        for path in repository.rglob(name)
        if ".git" not in path.parts and ".venv" not in path.parts
    ]
    assert found == []


# -- no authority ----------------------------------------------------------


def test_no_import_moves_the_edge_answer(node) -> None:
    """Edge authority, the action lease, enforcement and activation are
    unmoved by every transition this module can make."""

    from azazel_nexus.edge_package import inspect as inspect_edge

    root = pathlib.Path("/nonexistent-edge-core-for-model-import")

    def edge_answer():
        answer = inspect_edge(root)
        return (answer.ready, answer.presence.value, answer.state().ready)

    baseline = edge_answer()
    assert baseline == (False, "absent", False)

    second_body = OTHER_WEIGHTS
    second_entry = an_entry(
        model_id="second", digest="sha256:" + hashlib.sha256(second_body).hexdigest(),
        size_bytes=len(second_body),
    )
    _write_catalog(node.root, [an_entry(), second_entry])
    service = an_import(node)
    service.import_entry(place(node), "small-advisor", now=NOW, actor=ACTOR)
    assert edge_answer() == baseline
    service.import_entry(
        place(node, name="second.bin", body=second_body), "second", now=NOW, actor=ACTOR
    )
    assert edge_answer() == baseline
    service.import_entry(
        place(node, name="bad.bin", body=b"z" * len(WEIGHTS)),
        "small-advisor", now=NOW, actor=ACTOR,
    )
    assert edge_answer() == baseline
    service.rollback(reason="checking the Edge answer does not move", actor=ACTOR, now=NOW)
    assert edge_answer() == baseline
    service.reading_for("small-advisor")
    assert edge_answer() == baseline
