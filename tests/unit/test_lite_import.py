"""Offline operator import, and the boundaries it must not be able to cross (#67).

Every case runs the producer's own pinned fixtures through the inbox, end to
end: enumerate, select by id, verify, admit or quarantine, then serve.

The boundaries are the point. An import service that could be handed a cache
root, a trust key, a policy, a generation number or a quarantine path would
not be a service -- it would be a general file-moving primitive with a
Knowledge-shaped name.
"""

from __future__ import annotations

import ast
import hashlib
import os
import shutil
from pathlib import Path

import pytest

from azazel_nexus.lite_bundle import StaticReference, TimeBound, read_anchors
from azazel_nexus.lite_import import (
    CommissionedLite,
    ImportRefused,
    InboxEntry,
    LiteImport,
    Transition,
)

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contract" / "azazel-knowledge-lite"
MODULE = ROOT / "src" / "azazel_nexus" / "lite_import.py"

FRESH = "2026-09-21T00:00:00Z"


@pytest.fixture
def node(tmp_path):
    """A commissioned node: an inbox, a trust root, and nothing admitted."""

    def build(*bundles: str):
        root = tmp_path / "knowledge-lite"
        (root / "inbox").mkdir(parents=True)
        (root / "trust").mkdir(parents=True)
        shutil.copy(CONTRACT / "anchors.toml", root / "trust" / "anchors.toml")
        for bundle in bundles:
            shutil.copy(CONTRACT / bundle, root / "inbox" / Path(bundle).name)
        log: list[tuple[str, dict]] = []
        service = LiteImport(
            CommissionedLite(root=root),
            recorder=lambda transition, event: log.append((transition.value, dict(event))),
        )
        return service, log, root

    return build


def _import_only_entry(service, now=FRESH):
    entries = service.list_inbox()
    assert len(entries) == 1, f"expected one inbox entry, found {len(entries)}"
    return service.import_entry(entries[0].entry_id, now=now)


# -- the six cases, through the inbox --------------------------------------


def test_a_valid_bundle_is_admitted_and_serves_real_claims(node) -> None:
    service, log, _ = node("lite.tar.gz")
    outcome = _import_only_entry(service)

    assert outcome.admitted is True
    assert outcome.reading.overall == "available"
    assert outcome.reading.time_bound is TimeBound.CURRENT
    assert outcome.reading.static_reference is StaticReference.AVAILABLE

    rows = list(service.serve(query_as_of=FRESH))
    assert rows, "admitted and served nothing"
    assert any("agg_next_expiry" in row for row in rows), "no time-bound claim served"
    assert any("technique_id" in row for row in rows), "no static reference served"
    assert [name for name, _ in log] == [
        Transition.IMPORT_STARTED.value,
        Transition.ADMITTED.value,
    ]


@pytest.mark.parametrize(
    "bundle",
    [
        "negative/corrupt-signature.tar.gz",
        "negative/corrupt-payload.tar.gz",
        "negative/corrupt-truncated.tar.gz",
    ],
)
def test_a_broken_bundle_is_quarantined_and_serves_nothing(node, bundle) -> None:
    service, log, root = node(bundle)
    outcome = _import_only_entry(service)

    assert outcome.admitted is False
    assert outcome.reading.overall == "quarantined"
    assert list(service.serve(query_as_of=FRESH)) == []
    assert [name for name, _ in log] == [
        Transition.IMPORT_STARTED.value,
        Transition.QUARANTINED.value,
    ]
    held = sorted(p.name for p in (root / "quarantine").iterdir())
    assert len(held) == 1, "the refused artifact was not held"
    assert not (root / "admitted").exists(), "a refused bundle reached the admitted area"


def test_the_expired_bundle_serves_reference_and_withholds_indicators(node) -> None:
    """The distinction the producer put reference material in that fixture for."""

    service, _, _ = node("negative/expired.tar.gz")
    outcome = _import_only_entry(service)

    assert outcome.admitted is True
    assert outcome.reading.overall == "available"
    assert outcome.reading.qualifier == "static reference"
    assert outcome.reading.time_bound is TimeBound.STALE
    assert outcome.reading.static_reference is StaticReference.AVAILABLE

    rows = list(service.serve(query_as_of=FRESH))
    assert rows, "the reference material was not served"
    assert all("agg_next_expiry" not in row for row in rows), (
        "an expired indicator was served"
    )
    assert any("technique_id" in row for row in rows)


def test_a_node_with_an_empty_inbox_is_unavailable_and_writes_no_audit(node) -> None:
    service, log, _ = node()
    assert service.list_inbox() == ()
    reading = service.read(query_as_of=FRESH)
    assert reading.overall == "unavailable"
    assert "not a fault" in reading.reason
    assert list(service.serve(query_as_of=FRESH)) == []
    assert log == [], "absence of knowledge wrote to the ledger"


# -- the caller chooses an entry, and chooses nothing else ------------------


def test_import_takes_an_entry_id_and_no_other_argument() -> None:
    """Not a cache root, a trust key, a policy, a generation, or a path."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    method = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "import_entry"
    )
    positional = [arg.arg for arg in method.args.args]
    keyword_only = [arg.arg for arg in method.args.kwonlyargs]
    assert positional == ["self", "entry_id"]
    assert keyword_only == ["now"]
    for forbidden in ("root", "path", "key", "policy", "generation", "quarantine"):
        assert forbidden not in positional + keyword_only


@pytest.mark.parametrize(
    "supplied",
    [
        "../../etc/passwd",
        "/etc/passwd",
        "lite.tar.gz",
        "",
        "0" * 63,
        "g" * 64,
        "A" * 64,
    ],
)
def test_anything_that_is_not_an_entry_id_is_refused(node, supplied) -> None:
    """A caller cannot spell a path with a content digest."""

    service, log, _ = node("lite.tar.gz")
    with pytest.raises(ImportRefused):
        service.import_entry(supplied, now=FRESH)
    assert log == [], "a refused call still wrote to the ledger"


def test_an_id_not_in_the_listing_is_refused_rather_than_looked_for(node) -> None:
    service, _, _ = node("lite.tar.gz")
    with pytest.raises(ImportRefused, match="not in the inbox"):
        service.import_entry("0" * 64, now=FRESH)


def test_the_entry_id_is_the_content_digest(node) -> None:
    """So the id names the bytes, not a location an operator chose."""

    service, _, root = node("lite.tar.gz")
    entry = service.list_inbox()[0]
    expected = hashlib.sha256((CONTRACT / "lite.tar.gz").read_bytes()).hexdigest()
    assert entry.entry_id == expected


def test_renaming_the_file_does_not_change_the_entry_id(node, tmp_path) -> None:
    service, _, root = node("lite.tar.gz")
    before = service.list_inbox()[0].entry_id
    (root / "inbox" / "lite.tar.gz").rename(root / "inbox" / "operator-named-it-this.bin")
    after = service.list_inbox()[0]
    assert after.entry_id == before
    assert after.display_name == "operator-named-it-this.bin"


def test_an_inbox_entry_id_that_is_not_a_digest_is_refused() -> None:
    with pytest.raises(ImportRefused, match="not an entry id"):
        InboxEntry(entry_id="../escape", size=1, display_name="x")


# -- a bundle's trust material is subject matter ---------------------------


def test_a_bundle_carrying_trust_material_is_refused(node, tmp_path) -> None:
    """A bundle does not get to ship this node's trust root."""

    from test_lite_bundle import KEY_ID, SEED, _manifest, _signed

    service, log, root = node()
    raw = _signed(_manifest(), {"anchors.toml": b"threshold = 1\n"})
    (root / "inbox" / "hostile.tar.gz").write_bytes(raw)
    # The commissioned anchor is the fixture's; this bundle is signed by the
    # test key, so it is refused at the signature gate first. Point the node
    # at the test key to reach the member check.
    (root / "trust" / "anchors.toml").write_text(
        "threshold = 1\n[keys]\n"
        f'"{KEY_ID}" = "{__import__("signing_oracle").public_key_for(SEED).hex()}"\n',
        encoding="utf-8",
    )
    outcome = _import_only_entry(service)
    assert outcome.admitted is False
    assert outcome.refusal.code == "BUNDLE_CARRIES_TRUST_MATERIAL"
    assert outcome.reading.overall == "quarantined"


def test_the_trust_root_is_read_from_the_commissioned_location_only() -> None:
    """Never from the artifact, and never from a caller."""

    source = MODULE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    reads = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "read_anchors"
    ]
    assert len(reads) == 1, "the anchor is read in more than one place"
    assert "self.anchors_path" in source or "anchors_path" in source


def test_commissioned_paths_are_all_derived_from_one_root(tmp_path) -> None:
    """A caller supplies a root once; it does not supply the rest, ever."""

    commissioned = CommissionedLite(root=tmp_path / "kl")
    for path in (
        commissioned.inbox,
        commissioned.anchors_path,
        commissioned.admitted,
        commissioned.quarantine,
        commissioned.state_path,
    ):
        assert commissioned.root in path.parents
    fields = set(CommissionedLite.__dataclass_fields__)
    assert fields == {"root"}, f"{fields - {'root'}} are configurable per import"


# -- quarantine holds, and does nothing else -------------------------------


def test_quarantine_never_extracts_runs_or_re_serves(node) -> None:
    service, _, root = node("negative/corrupt-payload.tar.gz")
    _import_only_entry(service)
    held = root / "quarantine"
    # Exactly one artifact, and nothing unpacked beside it.
    assert [p.name for p in sorted(held.iterdir())] == [
        f"{service.list_inbox()[0].entry_id}.tar.gz"
    ]
    assert all(p.is_file() for p in held.iterdir())
    assert list(service.serve(query_as_of=FRESH)) == []


def test_the_quarantine_audit_records_no_content_and_no_key_material(node) -> None:
    """Digest, instant, structured reason. Nothing from inside the artifact."""

    service, log, _ = node("negative/corrupt-payload.tar.gz")
    _import_only_entry(service)
    event = next(payload for name, payload in log if name == Transition.QUARANTINED.value)
    assert set(event) == {
        "entry_id",
        "at",
        "bundle_digest",
        "gate",
        "code",
        "deterministic_path_affected",
    }
    rendered = repr(event)
    # Nothing that appears inside the bundle appears in the record.
    for leaked in ("agg_raw_confidence", "technique_id", "az-", "manifest"):
        assert leaked not in rendered, f"{leaked} reached the audit payload"
    assert event["deterministic_path_affected"] is False


def test_the_admit_audit_records_counts_rather_than_claims(node) -> None:
    service, log, _ = node("lite.tar.gz")
    _import_only_entry(service)
    event = next(payload for name, payload in log if name == Transition.ADMITTED.value)
    assert isinstance(event["served"], int)
    rendered = repr(event)
    for leaked in ("agg_next_expiry", "technique_id", "Brute Force"):
        assert leaked not in rendered, f"{leaked} reached the audit payload"


# -- the audit records transitions, not reads ------------------------------


def test_reading_and_serving_write_nothing(node) -> None:
    """Looking is not a transition."""

    service, log, _ = node("lite.tar.gz")
    _import_only_entry(service)
    before = len(log)
    for _ in range(5):
        service.read(query_as_of=FRESH)
        list(service.serve(query_as_of=FRESH))
        service.list_inbox()
    assert len(log) == before, "a status read wrote to the ledger"


def test_the_transitions_are_a_closed_set() -> None:
    assert {transition.value for transition in Transition} == {
        "lite.import.started",
        "lite.import.state_untrusted",
        "lite.import.store_tightened",
        "lite.import.admitted",
        "lite.import.quarantined",
        "lite.import.rolled_back",
        "lite.serving.stopped_by_revocation",
    }


# -- atomicity and anti-rollback -------------------------------------------


def test_admission_is_atomic_and_leaves_no_debris(node) -> None:
    service, _, root = node("lite.tar.gz")
    _import_only_entry(service)
    assert sorted(p.name for p in (root / "admitted").iterdir()) == ["current.tar.gz"]
    assert sorted(p.name for p in (root / "state").iterdir()) == ["watermark"]


def test_a_second_import_of_the_same_bundle_is_refused_by_the_watermark(node) -> None:
    """A correctly signed older artifact is still an older artifact."""

    service, log, _ = node("lite.tar.gz")
    first = _import_only_entry(service)
    assert first.admitted is True
    second = _import_only_entry(service)
    assert second.admitted is False
    assert second.refusal.code == "BUNDLE_VERSION_REGRESSION"


def test_a_revoked_key_stops_serving_without_waiting_for_the_next_import(node) -> None:
    """Re-verified on every read, which is what makes revocation take effect."""

    service, _, root = node("lite.tar.gz")
    assert _import_only_entry(service).admitted is True
    assert list(service.serve(query_as_of=FRESH))

    # Written as a whole file, with `revoked` **before** the `[keys]` table.
    # Appending it to the end put it inside `[keys]` -- TOML scopes a bare key
    # to the table above it -- which made the anchor unreadable rather than
    # revoking anything. The test still passed, for entirely the wrong
    # reason, and a mutation that ignored revocation on read survived it.
    key = read_anchors(root / "trust" / "anchors.toml").keys["c561fa9f"].hex()
    (root / "trust" / "anchors.toml").write_text(
        "threshold = 1\n"
        'revoked = ["c561fa9f"]\n'
        "[keys]\n"
        f'"c561fa9f" = "{key}"\n',
        encoding="utf-8",
    )
    # The anchor is still valid -- it just revokes the signer.
    reloaded = read_anchors(root / "trust" / "anchors.toml")
    assert reloaded.keys and reloaded.revoked == frozenset({"c561fa9f"})

    assert service.read(query_as_of=FRESH).overall == "unavailable"
    assert list(service.serve(query_as_of=FRESH)) == []


# -- what the import service cannot reach ----------------------------------


def test_the_import_service_reaches_no_activation_unit_edge_or_network() -> None:
    """Statically. A supply path that could activate something is not a supply path."""

    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    imported = set()
    for node_ in ast.walk(tree):
        if isinstance(node_, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node_.names)
        elif isinstance(node_, ast.ImportFrom) and node_.module:
            imported.add(node_.module.split(".")[0])
    for forbidden in (
        "activation",
        "edge_package",
        "socket",
        "subprocess",
        "urllib",
        "http",
        "azazel_nexus_runtime",
    ):
        assert forbidden not in imported, f"the import service can reach {forbidden}"
    assert "lite_bundle" in imported, "a vacuous scan: the module imports nothing"


def test_the_import_service_fetches_nothing() -> None:
    """The only supply route is an operator putting a file in a directory."""

    source = MODULE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    # Unambiguous fetch verbs only. A first draft included `get`, which
    # matched `dict.get` -- the same over-broad match that once flagged
    # `SIGNATURE_BYTES` and `signature_of`. A guard that fires on ordinary
    # code is a guard somebody removes.
    verbs = {"urlopen", "urlretrieve", "download", "fetch", "connect", "Popen"}
    offenders = [
        f"{node_.func.attr}:{node_.lineno}"
        for node_ in ast.walk(tree)
        if isinstance(node_, ast.Call)
        and isinstance(node_.func, ast.Attribute)
        and node_.func.attr in verbs
    ]
    assert offenders == [], f"{offenders} look like a fetch"

    # Non-vacuity: the rule must still catch a real one.
    sample = ast.parse("urllib.request.urlopen(target)")
    caught = [
        node_.func.attr
        for node_ in ast.walk(sample)
        if isinstance(node_, ast.Call)
        and isinstance(node_.func, ast.Attribute)
        and node_.func.attr in verbs
    ]
    assert caught == ["urlopen"]


def test_importing_changes_no_edge_readiness_and_no_authority(node) -> None:
    """Integration, not a scan: the Edge answer is identical before and after."""

    from azazel_nexus.edge_package import inspect as inspect_edge

    service, _, root = node("lite.tar.gz")
    before = inspect_edge(root / "no-edge-here").as_event()
    assert _import_only_entry(service).admitted is True
    after = inspect_edge(root / "no-edge-here").as_event()
    assert before == after
    assert after["ready"] is False
    assert after["presence"] == "absent"


@pytest.mark.parametrize(
    "bundle",
    [
        "lite.tar.gz",
        "negative/corrupt-signature.tar.gz",
        "negative/expired.tar.gz",
        None,
    ],
)
def test_no_knowledge_state_blocks_the_deterministic_path(node, bundle) -> None:
    """In every state, not in the convenient one."""

    service, _, _ = node(*( [bundle] if bundle else [] ))
    if bundle:
        _import_only_entry(service)
    reading = service.read(query_as_of=FRESH)
    assert reading.overall in {"available", "stale", "unavailable", "quarantined"}
    # The deterministic path is Edge's, and nothing here is in its call path.
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    assert "activation" not in {
        node_.module.split(".")[0]
        for node_ in ast.walk(tree)
        if isinstance(node_, ast.ImportFrom) and node_.module
    }


def test_an_id_that_is_not_a_digest_is_refused_before_the_inbox_is_read(node) -> None:
    """Two refusals, distinguishable. Survived a mutation that merged them.

    Removing the format check left the behaviour the same -- an unparseable
    id is not in the listing either -- so nothing noticed. The messages are
    asserted separately because the two refusals happen at different points:
    one before the directory is touched at all.
    """

    service, _, _ = node("lite.tar.gz")
    with pytest.raises(ImportRefused, match="does not take a path"):
        service.import_entry("../../etc/passwd", now=FRESH)
    with pytest.raises(ImportRefused, match="not in the inbox"):
        service.import_entry("f" * 64, now=FRESH)


def _test_key_node(tmp_path, *payloads):
    """A node whose commissioned anchor is the test key, so it can import twice.

    The producer publishes one valid bundle, already at `bundle_version 1`,
    so a second real promotion cannot be driven with it -- the watermark
    refuses it, correctly. This node exists only to exercise the promotion
    path more than once.
    """

    from signing_oracle import public_key_for
    from test_lite_bundle import KEY_ID, SEED, _manifest, _signed

    root = tmp_path / "test-key-node"
    (root / "inbox").mkdir(parents=True)
    (root / "trust").mkdir(parents=True)
    (root / "trust" / "anchors.toml").write_text(
        "threshold = 1\n[keys]\n"
        f'"{KEY_ID}" = "{public_key_for(SEED).hex()}"\n',
        encoding="utf-8",
    )
    for index, version in enumerate(payloads):
        (root / "inbox" / f"{index}.tar.gz").write_bytes(
            _signed(
                _manifest(bundle_version=version),
                {"tables/a.jsonl": b'{"agg_next_expiry": "2027-01-01T00:00:00Z"}\n'},
            )
        )
    return LiteImport(CommissionedLite(root=root)), root


def test_a_failed_promotion_leaves_the_previous_artifact_serving(tmp_path, monkeypatch) -> None:
    """Atomic, made observable. Survived a mutation to a plain write.

    A direct write truncates the live artifact before the new bytes land, so
    a failure part-way leaves a reader holding neither. The temporary-then-
    move keeps the previous one intact.

    An earlier version of this test drove the second import with a bundle
    signed by the wrong key. It was refused at the signature gate, the
    promotion path was never reached, and the `OSError` the test waited for
    came from the *quarantine* writer instead -- so it passed while proving
    nothing. Both bundles are signed by the same key here.
    """

    import os as _os

    service, root = _test_key_node(tmp_path, 5, 6)
    entries = service.list_inbox()
    assert len(entries) == 2

    first = service.import_entry(entries[0].entry_id, now=FRESH)
    second_entry = entries[1]
    if not first.admitted:
        # Enumeration is by digest, so which of the two came first is not
        # ours to choose. Take the other one.
        first = service.import_entry(entries[1].entry_id, now=FRESH)
        second_entry = entries[0]
    assert first.admitted is True, "neither bundle was admitted"
    before = (root / "admitted" / "current.tar.gz").read_bytes()
    assert list(service.serve(query_as_of=FRESH))

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(_os, "replace", explode)
    with pytest.raises(OSError):
        service.import_entry(second_entry.entry_id, now=FRESH)
    monkeypatch.undo()

    assert (root / "admitted" / "current.tar.gz").read_bytes() == before, (
        "the live artifact was damaged by a promotion that did not complete"
    )
    assert list(service.serve(query_as_of=FRESH)), "the node stopped serving"
    assert [p for p in (root / "admitted").iterdir() if p.name.startswith(".")] == []


def test_a_node_holding_only_quarantined_artifacts_says_quarantined(node) -> None:
    """Found by a completion check, and it was a real defect.

    `read` looked only at the admitted area, so a node that had just
    quarantined an artifact reported `unavailable` -- "nothing happened" --
    which is exactly the confusion the four words exist to prevent. "We do
    not have it" and "we had it and it is not trustworthy" call for different
    actions.
    """

    service, _, root = node("negative/corrupt-signature.tar.gz")
    assert _import_only_entry(service).admitted is False

    reading = service.read(query_as_of=FRESH)
    assert reading.overall == "quarantined"
    assert "held in" in reading.reason
    assert "not executed" in reading.reason
    assert "deterministic path is untouched" in reading.reason
    assert list(service.serve(query_as_of=FRESH)) == []


def test_an_admitted_bundle_outranks_a_quarantined_one_in_the_reading(node) -> None:
    """Holding a refused artifact does not stop a good one being served."""

    service, _, root = node("lite.tar.gz")
    assert _import_only_entry(service).admitted is True
    # Put something in quarantine beside it.
    (root / "quarantine").mkdir(parents=True, exist_ok=True)
    (root / "quarantine" / "old.tar.gz").write_bytes(b"refused earlier")

    reading = service.read(query_as_of=FRESH)
    assert reading.overall == "available"
    assert list(service.serve(query_as_of=FRESH))


def test_counting_quarantined_artifacts_never_opens_one(node) -> None:
    """They are held, not read. Counting is all a reading needs."""

    service, _, root = node("negative/corrupt-payload.tar.gz")
    _import_only_entry(service)
    (root / "quarantine" / "not-even-an-archive.tar.gz").write_bytes(b"\x00\x01\x02")
    reading = service.read(query_as_of=FRESH)
    assert reading.overall == "quarantined"
    assert "2 artifact(s)" in reading.reason


# -- store directory modes do not depend on the importer's umask (#186) -----


def _write_bits(path: Path) -> int:
    return path.stat().st_mode & 0o022


@pytest.mark.parametrize("bundle,leaves", [
    ("lite.tar.gz", ("admitted", "state")),
    ("negative/corrupt-signature.tar.gz", ("quarantine",)),
])
def test_store_directories_are_not_group_writable_under_a_loose_umask(node, bundle, leaves) -> None:
    # Debian's default user umask; an operator-run import used to inherit it.
    service, _, root = node(bundle)
    previous = os.umask(0o002)
    try:
        _import_only_entry(service)
    finally:
        os.umask(previous)
    for leaf in leaves:
        assert (root / leaf).is_dir()
        assert _write_bits(root / leaf) == 0, f"{leaf} is group/other-writable"
    for written in root.rglob("*"):
        if written.is_file() and written.parent.name in leaves:
            assert written.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("bundle,leaf", [
    ("lite.tar.gz", "admitted"),
    ("lite.tar.gz", "state"),
    ("negative/corrupt-signature.tar.gz", "quarantine"),
])
def test_a_loosened_store_directory_is_tightened_and_keeps_setgid(node, bundle, leaf) -> None:
    # A store left behind by an import before the fix.
    service, _, root = node(bundle)
    (root / leaf).mkdir()
    (root / leaf).chmod(0o2775)
    if not (root / leaf).stat().st_mode & 0o2000:
        pytest.skip("filesystem does not retain setgid on chmod")
    _import_only_entry(service)
    mode = (root / leaf).stat().st_mode
    assert mode & 0o022 == 0
    assert mode & 0o2000, "setgid must be kept so the group can still read"


def test_a_symlinked_store_directory_is_refused_and_its_target_untouched(node, tmp_path) -> None:
    service, _, root = node("lite.tar.gz")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir(mode=0o777)
    elsewhere.chmod(0o777)
    (root / "admitted").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(ImportRefused):
        _import_only_entry(service)
    assert elsewhere.stat().st_mode & 0o777 == 0o777
    assert not any(elsewhere.iterdir())


@pytest.mark.parametrize("delta, served", [(1, False), (0, True), (-1, True)])
def test_serving_obeys_watermark(node, delta, served):
    service, _, root = node("lite.tar.gz")
    _import_only_entry(service)
    watermark = service.commissioned.watermark()
    (root / "state/watermark").write_text(str(watermark + delta))
    assert bool(list(service.serve(query_as_of=FRESH))) is served
    assert (service.read(query_as_of=FRESH).overall == "available") is served
    if not served:
        assert service.read(query_as_of=FRESH).overall == "quarantined"
        assert "watermark" in service.read(query_as_of=FRESH).reason


@pytest.mark.parametrize("damage, code", [
    ("missing", "WATERMARK_MISSING"), ("abc", "WATERMARK_MALFORMED"),
    ("-1", "WATERMARK_MALFORMED"), ("9" * 100, "WATERMARK_MALFORMED"),
    ("directory", "STORE_FILE_UNSAFE"), ("symlink", "STORE_FILE_UNSAFE"),
])
def test_untrusted_watermark_blocks_serving_and_import_without_quarantine(node, damage, code):
    service, log, root = node("lite.tar.gz")
    _import_only_entry(service)
    path = root / "state/watermark"
    path.unlink()
    if damage == "directory":
        path.mkdir()
    elif damage == "symlink":
        path.symlink_to(root / "inbox/lite.tar.gz")
    elif damage != "missing":
        path.write_text(damage)
    current = (root / "admitted/current.tar.gz").read_bytes()
    inbox = (root / "inbox/lite.tar.gz").read_bytes()
    assert list(service.serve(query_as_of=FRESH)) == []
    assert service.read(query_as_of=FRESH).overall == "quarantined"
    with pytest.raises(ImportRefused, match="operator must restore"):
        _import_only_entry(service)
    assert log[-1] == (Transition.STATE_UNTRUSTED.value, {
        "entry_id": service.list_inbox()[0].entry_id, "at": FRESH, "code": code})
    assert (root / "admitted/current.tar.gz").read_bytes() == current
    assert (root / "inbox/lite.tar.gz").read_bytes() == inbox
    assert not (root / "quarantine").exists()


@pytest.mark.parametrize("role", ["admitted/current.tar.gz", "state/watermark"])
@pytest.mark.parametrize("damage", ["hardlink", "writable", "symlink", "owner"])
def test_unsafe_store_files_block_import(node, monkeypatch, role, damage):
    service, log, root = node("lite.tar.gz")
    _import_only_entry(service)
    path = root / role
    if damage == "hardlink":
        os.link(path, root / "extra-link")
    elif damage == "writable":
        path.chmod(0o660)
    elif damage == "symlink":
        path.rename(root / "original")
        path.symlink_to(root / "original")
    else:
        monkeypatch.setattr(os, "geteuid", lambda: path.stat().st_uid + 1)
    with pytest.raises(ImportRefused):
        _import_only_entry(service)
    assert log[-1][0] == Transition.STATE_UNTRUSTED.value
    assert log[-1][1]["code"] == "STORE_FILE_UNSAFE"
    assert not (root / "quarantine").exists()


def test_import_audits_existing_directory_tightening(node):
    service, log, root = node("lite.tar.gz")
    (root / "admitted").mkdir(mode=0o750)
    (root / "admitted").chmod(0o2770)
    assert _import_only_entry(service).admitted
    assert log[1] == (Transition.STORE_TIGHTENED.value, {
        "entry_id": service.list_inbox()[0].entry_id, "at": FRESH,
        "directories": ["admitted"]})
    assert (root / "admitted").stat().st_mode & 0o022 == 0


def test_unreadable_watermark_is_not_zero(node, monkeypatch):
    service, log, root = node("lite.tar.gz")
    _import_only_entry(service)
    original = os.open
    def deny(path, *args, **kwargs):
        if Path(path) == root / "state/watermark":
            raise PermissionError("private detail")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(os, "open", deny)
    assert list(service.serve(query_as_of=FRESH)) == []
    with pytest.raises(ImportRefused):
        _import_only_entry(service)
    assert log[-1][1]["code"] == "WATERMARK_UNREADABLE"
    assert "private detail" not in str(log)


@pytest.mark.parametrize("payload", [b"", b"abc", b"-1", b"1" * 33, b" 1", b"1\n2"])
def test_malformed_watermark_alone_blocks_first_import(node, payload):
    service, log, root = node("lite.tar.gz")
    (root / "state").mkdir()
    (root / "state/watermark").write_bytes(payload)
    with pytest.raises(ImportRefused):
        _import_only_entry(service)
    assert log[-1][1]["code"] == "WATERMARK_MALFORMED"
    assert (root / "state/watermark").read_bytes() == payload
    assert not (root / "admitted").exists()
    assert not (root / "quarantine").exists()


def test_tightening_is_audited_even_when_a_later_directory_is_unsafe(node, tmp_path):
    service, log, root = node("lite.tar.gz")
    (root / "admitted").mkdir()
    (root / "admitted").chmod(0o770)
    target = tmp_path / "outside"
    target.mkdir()
    (root / "state").symlink_to(target, target_is_directory=True)
    with pytest.raises(ImportRefused):
        _import_only_entry(service)
    assert [name for name, _ in log] == [Transition.IMPORT_STARTED.value,
                                         Transition.STORE_TIGHTENED.value,
                                         Transition.STATE_UNTRUSTED.value]
    assert log[1][1]["directories"] == ["admitted"]
    assert list(target.iterdir()) == []
