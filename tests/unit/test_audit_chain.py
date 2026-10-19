"""A chain that refuses a gap, and a write that leaves nothing on failure (#27).

`IMPLEMENTATION_SPEC.md` §6.4 gives Nexus chain *enforcement* and leaves the
envelope to Fabric. What that means in practice is tested here: the chaining
works with nothing installed, and it refuses rather than repairs.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from azazel_nexus.audit import (
    GENESIS_HASH,
    AuditChainBroken,
    AuditLedger,
    AuditUnavailable,
    canonical_event_bytes,
)

MODULE = Path(__file__).resolve().parents[2] / "src" / "azazel_nexus" / "audit.py"


@pytest.fixture()
def ledger(tmp_path) -> AuditLedger:
    return AuditLedger(tmp_path / "audit" / "ledger.jsonl")


def test_an_empty_chain_starts_at_genesis(ledger):
    assert ledger.head() == (0, GENESIS_HASH)
    ledger.verify()


def test_entries_chain_onto_one_another(ledger):
    first = ledger.append({"event_type": "a"})
    second = ledger.append({"event_type": "b"})

    assert first.previous_hash == GENESIS_HASH
    assert second.previous_hash == first.event_hash
    assert (second.sequence, second.event_hash) == ledger.head()
    ledger.verify()


def test_an_edited_event_breaks_its_own_link(ledger):
    """The half a re-linking check would miss."""

    ledger.append({"event_type": "a", "detail": "as recorded"})
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    raw = json.loads(lines[0])
    raw["event"]["detail"] = "edited afterwards"
    ledger.path.write_text(json.dumps(raw) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainBroken, match="hashes to"):
        ledger.verify()


def test_a_spliced_entry_breaks_the_link_to_its_neighbour(ledger):
    """The other half. A correctly-hashed record in the wrong place.

    Checking only that each event hashes to its recorded hash would pass here:
    the entry is internally consistent. What is wrong is where it sits.
    """

    ledger.append({"event_type": "a"})
    ledger.append({"event_type": "b"})
    lines = ledger.path.read_text(encoding="utf-8").splitlines()

    foreign = AuditLedger(ledger.path.parent / "other.jsonl")
    foreign.append({"event_type": "elsewhere"})
    spliced = foreign.path.read_text(encoding="utf-8").splitlines()[0]
    raw = json.loads(spliced)
    raw["sequence"] = 2
    lines[1] = json.dumps(raw)
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainBroken, match="chains onto"):
        ledger.verify()


def test_a_missing_entry_breaks_the_sequence(ledger):
    ledger.append({"event_type": "a"})
    ledger.append({"event_type": "b"})
    ledger.append({"event_type": "c"})
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    ledger.path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    with pytest.raises(AuditChainBroken):
        ledger.verify()


def test_a_writer_that_expected_a_different_head_is_refused(ledger):
    """Concurrent append becomes a refusal rather than silent interleaving."""

    first = ledger.append({"event_type": "a"})
    ledger.append({"event_type": "b"})

    with pytest.raises(AuditChainBroken, match="moved under this writer"):
        ledger.append({"event_type": "c"}, expected_head=first.event_hash)


def test_a_refused_append_records_nothing(ledger):
    """The event was not recorded, so the file does not carry it."""

    first = ledger.append({"event_type": "a"})
    ledger.append({"event_type": "b"})
    before = ledger.path.read_text(encoding="utf-8")

    with pytest.raises(AuditChainBroken):
        ledger.append({"event_type": "never"}, expected_head=first.event_hash)

    assert ledger.path.read_text(encoding="utf-8") == before
    assert "never" not in before


def test_an_unreadable_ledger_raises_rather_than_reporting_an_empty_chain(tmp_path):
    """A chain that cannot be read is not a chain with nothing in it.

    Returning an empty head here would let the next append start a second
    chain from genesis beside the one already on disk, and both would verify.
    """

    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    ledger = AuditLedger(blocked / "ledger.jsonl")

    with pytest.raises(AuditUnavailable):
        ledger.append({"event_type": "a"})


def test_a_failed_write_raises_rather_than_reporting_success(tmp_path, monkeypatch):
    """Fail-closed on the **write** (§8), which is a different path.

    The test above looks like this one and is not: `append` reads the head
    before it writes, so an unreadable ledger never reaches the write handler
    at all. A mutation that swallowed the write failure and returned the entry
    passed the whole suite, because nothing exercised the branch it broke.

    The failure is injected at the write rather than arranged on the
    filesystem, because a permission trick does not stop a test running as
    root — and it would then pass for a third wrong reason.
    """

    ledger = AuditLedger(tmp_path / "audit" / "ledger.jsonl")
    ledger.append({"event_type": "recorded"})
    before = ledger.path.read_text(encoding="utf-8")

    real_open = Path.open

    def refuse(self, *args, **kwargs):
        if self == ledger.path and args and "a" in args[0]:
            raise OSError("device full")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse)
    with pytest.raises(AuditUnavailable, match="not recorded"):
        ledger.append({"event_type": "never"})

    monkeypatch.undo()
    assert ledger.path.read_text(encoding="utf-8") == before
    assert "never" not in before
    ledger.verify()


def test_canonical_bytes_do_not_depend_on_key_order():
    assert canonical_event_bytes({"b": 1, "a": 2}) == canonical_event_bytes(
        {"a": 2, "b": 1}
    )


def test_the_same_events_produce_the_same_chain(tmp_path):
    """Deterministic: no clock, no randomness, no path in the hash."""

    events = [{"event_type": "a", "n": 1}, {"event_type": "b", "n": 2}]
    heads = []
    for name in ("one", "two"):
        ledger = AuditLedger(tmp_path / name / "ledger.jsonl")
        for event in events:
            ledger.append(event)
        heads.append(ledger.head())
    assert heads[0] == heads[1]


def test_the_chain_needs_nothing_installed():
    """CORE runs with no optional extra (ADR-0001).

    A ledger that needed Fabric to write a link would stop existing exactly
    when a node is least able to explain itself. Fabric owns the envelope for
    export; `azazel_nexus.fabric_boundary` is where that happens.
    """

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "azazel_fabric" not in imported, (
        "the audit chain imports Fabric. §6.4 gives Nexus chain enforcement "
        "precisely because it is a product-local trust decision, and the CORE "
        "path must write a ledger with nothing installed"
    )


# -- the head is read from the end (#175) -------------------------------------


def test_the_head_reads_only_the_last_record(ledger):
    # Everything before the last record is unreadable, so a head that walked
    # the file would raise. One that reads from the end never reaches it, and
    # so costs the same however long the ledger grows.
    ledger.append({"event_type": "a"})
    last = ledger.path.read_text(encoding="utf-8")
    ledger.path.write_text("not a record\n" * 50_000 + last, encoding="utf-8")

    assert ledger.head() == (1, json.loads(last)["event_hash"])
    with pytest.raises(AuditChainBroken):
        ledger.verify()


def test_the_head_agrees_with_a_full_walk(ledger):
    for index in range(40):
        ledger.append({"event_type": "e", "n": index})
    *_, final = ledger

    assert ledger.head() == (final.sequence, final.event_hash) == (40, final.event_hash)


def test_a_last_record_longer_than_one_read_is_found_whole(ledger):
    ledger.append({"event_type": "a"})
    entry = ledger.append({"event_type": "b", "blob": "x" * 200_000})

    assert ledger.head() == (2, entry.event_hash)


def test_trailing_blank_lines_do_not_hide_the_head(ledger):
    entry = ledger.append({"event_type": "a"})
    with ledger.path.open("a", encoding="utf-8") as handle:
        handle.write("\n  \n\n")

    assert ledger.head() == (1, entry.event_hash)


def test_a_blank_file_is_an_empty_chain(ledger):
    ledger.path.parent.mkdir(parents=True)
    ledger.path.write_text("\n\n", encoding="utf-8")

    assert ledger.head() == (0, GENESIS_HASH)


def test_a_torn_last_record_breaks_the_head(ledger):
    ledger.append({"event_type": "a"})
    with ledger.path.open("a", encoding="utf-8") as handle:
        handle.write('{"sequence": 2, "previous')

    with pytest.raises(AuditChainBroken):
        ledger.head()
    with pytest.raises(AuditChainBroken):
        ledger.append({"event_type": "b"})


@pytest.mark.parametrize(
    "line",
    [
        '{"sequence": 1, "previous_hash": "0", "event": {}}',
        '["sequence", 1]',
        '"a string"',
        '{"sequence": "1", "previous_hash": "0", "event_hash": "0", "event": {}}',
        '{"sequence": 1, "previous_hash": "0", "event_hash": "0", "event": []}',
    ],
    ids=["missing-field", "array", "string", "string-sequence", "array-event"],
)
def test_a_malformed_record_is_a_broken_chain_not_a_crash(ledger, line):
    ledger.path.parent.mkdir(parents=True)
    ledger.path.write_text(line + "\n", encoding="utf-8")

    with pytest.raises(AuditChainBroken):
        ledger.head()
    with pytest.raises(AuditChainBroken):
        ledger.verify()


def test_a_ledger_that_is_not_utf8_is_a_broken_chain(ledger):
    ledger.path.parent.mkdir(parents=True)
    ledger.path.write_bytes(b"\xff\xfe\n")

    with pytest.raises(AuditChainBroken):
        ledger.head()
    with pytest.raises(AuditChainBroken):
        ledger.verify()


def test_a_line_separator_inside_an_event_is_not_a_record_boundary(ledger):
    # `ensure_ascii=False` writes U+2028 raw. Splitting on it would cut one
    # valid record in two and report the chain as broken.
    ledger.append({"event_type": "a", "note": "one two\x85three"})
    entry = ledger.append({"event_type": "b"})

    ledger.verify()
    assert [e.sequence for e in ledger] == [1, 2]
    assert ledger.head() == (2, entry.event_hash)
