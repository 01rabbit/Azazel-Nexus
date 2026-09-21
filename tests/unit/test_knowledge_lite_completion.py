"""The six things that had to be true before #67 could be closed.

Each is checked here rather than asserted in a report. They are the
conditions the owner set for calling Knowledge Lite `functional`, and a
condition nobody runs is a condition nobody meets.
"""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pytest

from azazel_nexus.cli import main
from azazel_nexus.functional_readiness import readiness_for
from azazel_nexus.lite_import import CommissionedLite, LiteImport, Transition

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contract" / "azazel-knowledge-lite"
AS_OF = "2026-09-21T00:00:00Z"


def _node(tmp_path, *bundles):
    root = tmp_path / "knowledge-lite"
    (root / "inbox").mkdir(parents=True)
    (root / "trust").mkdir(parents=True)
    shutil.copy(CONTRACT / "anchors.toml", root / "trust" / "anchors.toml")
    for bundle in bundles:
        shutil.copy(CONTRACT / bundle, root / "inbox" / Path(bundle).name)
    log: list[str] = []
    service = LiteImport(
        CommissionedLite(root=root), recorder=lambda t, e: log.append(t.value)
    )
    return service, log, root


def _status(tmp_path, knowledge_root):
    out = io.StringIO()
    main(
        [
            "--sysfs", str(tmp_path / "nosysfs"),
            "--edge-root", str(tmp_path / "noedge"),
            "--knowledge-lite", str(knowledge_root),
            "--as-of", AS_OF,
            "status",
        ],
        out=out,
    )
    return out.getvalue()


# 1 -----------------------------------------------------------------------


def test_reading_status_many_times_never_grows_the_audit_ledger(tmp_path) -> None:
    service, log, root = _node(tmp_path, "lite.tar.gz")
    service.import_entry(service.list_inbox()[0].entry_id, now=AS_OF)
    after_import = list(log)

    for _ in range(10):
        text = _status(tmp_path, root)
        assert "Knowledge Lite:" in text
    assert log == after_import, "reading a screen wrote to the ledger"


# 2 -----------------------------------------------------------------------


def test_only_the_five_transitions_leave_an_event() -> None:
    assert {t.value for t in Transition} == {
        "lite.import.started",
        "lite.import.admitted",
        "lite.import.quarantined",
        "lite.import.rolled_back",
        "lite.serving.stopped_by_revocation",
    }


@pytest.mark.parametrize(
    "bundle, expected",
    [
        ("lite.tar.gz", ["lite.import.started", "lite.import.admitted"]),
        (
            "negative/corrupt-payload.tar.gz",
            ["lite.import.started", "lite.import.quarantined"],
        ),
    ],
)
def test_an_import_writes_exactly_its_own_transitions(tmp_path, bundle, expected) -> None:
    service, log, _ = _node(tmp_path, bundle)
    service.import_entry(service.list_inbox()[0].entry_id, now=AS_OF)
    assert log == expected


# 3 -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "bundles",
    [
        (),
        ("lite.tar.gz",),
        ("negative/expired.tar.gz",),
        ("negative/corrupt-signature.tar.gz",),
    ],
)
def test_no_knowledge_state_moves_edge_readiness_authority_or_enforcement(
    tmp_path, bundles
) -> None:
    """Knowledge is advice. Every Knowledge state leaves authority where it was."""

    service, _, root = _node(tmp_path, *bundles)
    if bundles:
        service.import_entry(service.list_inbox()[0].entry_id, now=AS_OF)

    text = _status(tmp_path, root)
    assert "edge-baseline-ready: no" in text
    assert "enforcement ready: no" in text
    assert "edge core (local): absent" in text
    assert "enforcement capable: no" in text
    assert "baseline ready: no" in text
    # And no activation lease is implied by any of it.
    assert "lease" not in text.lower() or "no commissioning record" in text


def test_every_knowledge_state_is_reachable_and_none_of_them_changes_authority(
    tmp_path,
) -> None:
    """The four states, driven for real, with one authority answer throughout."""

    from azazel_nexus.edge_package import inspect as inspect_edge

    seen = set()
    baseline = None
    for index, (bundle, expected) in enumerate(
        [
            (None, "unavailable"),
            ("lite.tar.gz", "available"),
            ("negative/expired.tar.gz", "available"),
            ("negative/corrupt-signature.tar.gz", "quarantined"),
        ]
    ):
        service, _, root = _node(tmp_path / f"case{index}", *( [bundle] if bundle else [] ))
        if bundle:
            service.import_entry(service.list_inbox()[0].entry_id, now=AS_OF)
        reading = service.read(query_as_of=AS_OF)
        assert reading.overall == expected, bundle
        seen.add(reading.overall)

        # The decision-bearing fields only. `root` is the directory this
        # test happened to build, and comparing it would be comparing the
        # test's own bookkeeping rather than the node's answer.
        event = inspect_edge(root / "no-edge").as_event()
        answer = {
            "presence": event["presence"],
            "ready": event["ready"],
            "caveats": event["caveats"],
            # The verdicts, not their prose: a reason quotes the directory
            # this test built, so comparing reasons compares the test.
            "verdicts": [
                (f["check"], f["evidence"], f["security"]) for f in event["findings"]
            ],
        }
        baseline = baseline or answer
        assert answer == baseline, "a Knowledge state moved the Edge answer"
        assert answer["ready"] is False
    assert seen == {"unavailable", "available", "quarantined"}


# 4 -----------------------------------------------------------------------


def test_the_directories_the_screen_and_the_docs_name_are_the_ones_used(tmp_path) -> None:
    """Owner, mode and ceiling agree between the code, the screen and the docs."""

    from azazel_nexus.lite_import import MAX_INBOX_BYTES, MAX_INBOX_ENTRIES

    commissioned = CommissionedLite(root=Path("/data/azazel/knowledge-lite"))
    doc = (ROOT / "docs" / "knowledge-lite-consumer.md").read_text(encoding="utf-8")
    for path in (
        commissioned.inbox,
        commissioned.quarantine,
        commissioned.admitted,
        commissioned.anchors_path,
    ):
        assert str(path) in doc, f"{path} is not named in the consumer document"
    assert str(MAX_INBOX_ENTRIES) in doc
    assert "256 MiB" in doc or str(MAX_INBOX_BYTES) in doc


# 5 -----------------------------------------------------------------------


def test_the_interpreter_floor_fails_before_any_import_or_write() -> None:
    """A node that came up on 3.10 would discover it when asked to verify."""

    installer = (ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")
    check = installer.index("version_info >= (3, 11)")
    assert check < installer.index("install -d"), "the check runs after writing starts"
    assert check < installer.index("useradd"), "the check runs after accounts are made"
    assert "no fallback parser" in installer


# 6 -----------------------------------------------------------------------


def test_the_fixture_source_manifest_is_reachable_from_the_docs() -> None:
    """Source revision, digest and generator command, findable from a document."""

    descriptor = json.loads((CONTRACT / "FIXTURE.json").read_text(encoding="utf-8"))
    doc = (ROOT / "docs" / "knowledge-lite-consumer.md").read_text(encoding="utf-8")

    assert "contract/azazel-knowledge-lite" in doc
    assert descriptor["source_revision"][:12] in doc
    assert descriptor["fixture_generator_command"] in doc
    assert "FIXTURE.json" in doc
    for field in ("source_repository", "source_revision", "artifact_digest"):
        assert field in descriptor


# the word itself -----------------------------------------------------------


def test_the_screen_bounds_what_functional_means(tmp_path) -> None:
    service, _, root = _node(tmp_path)
    text = _status(tmp_path, root)
    assert "Knowledge Lite: functional" in text
    assert "cryptographic implementation: not supported (Nexus#70 review pending)" in text
    assert "functional means: a correct Knowledge Lite bundle can be imported offline" in text
    for limit in readiness_for("knowledge_lite").does_not_mean:
        assert limit in text, "a limit of the capability word did not reach the screen"


def test_the_four_axes_each_get_their_own_line(tmp_path) -> None:
    service, _, root = _node(tmp_path, "negative/expired.tar.gz")
    service.import_entry(service.list_inbox()[0].entry_id, now=AS_OF)
    text = _status(tmp_path, root)
    assert "bundle integrity: admitted" in text
    assert "time-bound intelligence: stale" in text
    assert "static reference: available" in text
    assert "Knowledge Lite: functional" in text
