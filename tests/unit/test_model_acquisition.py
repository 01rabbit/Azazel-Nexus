"""Whether a model may be fetched, and the path that does not exist (#96).

The distinctions defended here:

*no source declared* ≠ *unknown source* ≠ *not confirmed*, and none of the
three is *there is no fetcher*. A node that cannot download is a node that
installs from a USB stick, not a node that cannot install.
"""

from __future__ import annotations

import ast
import hashlib
import pathlib
import sys

import pytest

from azazel_nexus import model_acquisition
from azazel_nexus.model_acquisition import (
    KNOWN_SOURCES,
    MAX_ATTEMPTS,
    MIN_FREE_HEADROOM_BYTES,
    NO_CONSENT,
    RESUME_CHUNK_BYTES,
    TIMEOUT_SECONDS,
    AcquisitionPlan,
    AcquisitionRefused,
    Refusal,
    SourceConsent,
    plan_acquisition,
)
from azazel_nexus.model_catalog import CatalogRefused, ModelEntry
from azazel_nexus.resource_profile import ResourceProfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "runtime" / "src"))
from azazel_nexus_runtime import model_fetch  # noqa: E402
from azazel_nexus_runtime.model_fetch import (  # noqa: E402
    ENDPOINT_FOR,
    Endpoint,
    FetchOutcome,
    FetchRefused,
    drive_fetch,
    endpoint_for,
)

WEIGHTS = b"weights, not a program -- " + b"w" * 2048
PLENTY = MIN_FREE_HEADROOM_BYTES + 10 * 1024 * 1024
NOW = "2026-01-01T00:00:00Z"


def an_entry(**overrides) -> ModelEntry:
    fields = {
        "model_id": "small-advisor",
        "format": "gguf",
        "digest": "sha256:" + hashlib.sha256(WEIGHTS).hexdigest(),
        "size_bytes": len(WEIGHTS),
        "provenance": "fixture",
        "license_acknowledgement_required": False,
        "runtime_abi": "llama.cpp/1",
        "purpose": "summarise a situation frame",
        "context_limit": 4096,
        "declared_min_ram_mib": 4096,
        "declared_min_disk_mib": 2048,
        "declared_profile": ResourceProfile.LITE,
        "rollback_lineage": (),
        "source_id": "vendor-mirror",
    }
    fields.update(overrides)
    return ModelEntry(**fields)


def consent_for(*sources) -> SourceConsent:
    return SourceConsent(
        sources=frozenset(sources or ("vendor-mirror",)),
        operator="an-operator",
        at=NOW,
    )


def a_plan(**overrides) -> AcquisitionPlan:
    return plan_acquisition(
        an_entry(), consent=consent_for(), free_bytes=PLENTY, **overrides
    )


# -- the catalog names a symbol, never a location --------------------------


def test_a_symbol_outside_this_builds_table_is_refused() -> None:
    """A symbol resolves against a fixed table or it resolves to nothing."""

    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(
            an_entry(source_id="somebody-elses-mirror"),
            consent=consent_for(),
            free_bytes=PLENTY,
        )
    assert caught.value.cause is Refusal.UNKNOWN_SOURCE


def test_an_entry_declaring_no_source_permits_no_online_route() -> None:
    """`null` is the answer, not a gap the node goes looking to fill."""

    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(
            an_entry(source_id=None), consent=consent_for(), free_bytes=PLENTY
        )
    assert caught.value.cause is Refusal.SOURCE_UNAVAILABLE
    assert "no fallback source is consulted" in str(caught.value)
    assert "imported offline" in str(caught.value)


def test_a_null_source_never_falls_back_to_another_entrys_source() -> None:
    """The failure this would be: a `null` that quietly became "try the
    usual place" is a way to acquire from a source the catalog never named --
    the exact power the symbol design exists to withhold.

    Every source this build knows is confirmed, and another entry in the same
    catalog names one. The entry with `null` must still be refused.
    """

    consent = consent_for(*KNOWN_SOURCES)
    assert an_entry(source_id="vendor-mirror").source_id in KNOWN_SOURCES
    for known in KNOWN_SOURCES:
        # Each is genuinely usable, so nothing below fails for lack of a
        # confirmed, resolvable source.
        assert plan_acquisition(
            an_entry(source_id=known), consent=consent, free_bytes=PLENTY
        ).source_id == known
    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(
            an_entry(source_id=None), consent=consent, free_bytes=PLENTY
        )
    assert caught.value.cause is Refusal.SOURCE_UNAVAILABLE


def test_no_endpoint_can_be_supplied_to_fill_a_null_source() -> None:
    """There is no argument, keyword or default that takes one.

    A `null` source is refused before capacity, before attempts and before
    anything else that a caller could influence, and `plan_acquisition` has
    no parameter through which a location could arrive.
    """

    import inspect

    parameters = set(inspect.signature(plan_acquisition).parameters)
    assert parameters == {
        "entry", "consent", "free_bytes", "resume_from", "attempts_used", "installed",
    }
    for forbidden in ("source", "endpoint", "url", "host", "fallback", "default"):
        assert not any(forbidden in name for name in parameters), forbidden


def test_no_source_declared_and_unknown_source_are_different_refusals() -> None:
    """One says the catalog permitted nothing; the other says it named
    something this build cannot resolve. An operator acts on them
    differently."""

    causes = set()
    for source_id in (None, "somebody-elses-mirror"):  # noqa: E501
        with pytest.raises(AcquisitionRefused) as caught:
            plan_acquisition(
                an_entry(source_id=source_id), consent=consent_for(), free_bytes=PLENTY
            )
        causes.add(caught.value.cause)
    assert causes == {Refusal.SOURCE_UNAVAILABLE, Refusal.UNKNOWN_SOURCE}


@pytest.mark.parametrize(
    "spelled",
    ["https://a.invalid/x", "a.invalid", "mirror/eu", "mirror:443", "../up"],
)
def test_a_catalog_cannot_spell_a_location_at_all(spelled) -> None:
    """Refused at the catalog, before acquisition is even consulted.

    If a catalog could carry an endpoint, a catalog signature would become a
    way to point a node at any host on the internet.
    """

    with pytest.raises(CatalogRefused):
        an_entry(source_id=spelled)


# -- the operator confirms, separately -------------------------------------


def test_without_a_confirmation_there_is_no_plan() -> None:
    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(an_entry(), free_bytes=PLENTY)
    assert caught.value.cause is Refusal.NOT_CONFIRMED


def test_a_confirmation_for_one_source_does_not_cover_another() -> None:
    """Confirmed one at a time. Never "all"."""

    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(
            an_entry(source_id="vendor-primary"),
            consent=consent_for("vendor-mirror"),
            free_bytes=PLENTY,
        )
    assert caught.value.cause is Refusal.NOT_CONFIRMED


def test_this_confirmation_is_not_the_other_confirmations() -> None:
    """Profile, remote routing and licence are three other consents.

    Sending a sanitised question to a remote advisor and pulling gibibytes
    onto this disk are different acts with different consequences.
    """

    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(an_entry(), consent=NO_CONSENT, free_bytes=PLENTY)
    message = str(caught.value)
    assert "profile" in message and "remote-routing opt-in" in message
    assert "licence" in message and "none of them is this one" in message


def test_a_confirmation_records_who_and_when() -> None:
    for missing in ("operator", "at"):
        fields = {"sources": frozenset({"vendor-mirror"}), "operator": "o", "at": NOW}
        fields[missing] = "   "
        with pytest.raises(AcquisitionRefused):
            SourceConsent(**fields)


def test_a_confirmation_for_an_unresolvable_symbol_is_refused() -> None:
    """A confirmation an operator could not have understood."""

    with pytest.raises(AcquisitionRefused) as caught:
        SourceConsent(
            sources=frozenset({"nowhere"}), operator="an-operator", at=NOW
        )
    assert caught.value.cause is Refusal.UNKNOWN_SOURCE


# -- capacity, attempts, and not fetching what is already here -------------


def test_free_space_is_checked_before_a_byte_moves() -> None:
    entry = an_entry()
    needed = entry.size_bytes + MIN_FREE_HEADROOM_BYTES
    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(entry, consent=consent_for(), free_bytes=needed - 1)
    assert caught.value.cause is Refusal.INSUFFICIENT_DISK
    assert plan_acquisition(
        entry, consent=consent_for(), free_bytes=needed
    ).expected_size_bytes == entry.size_bytes


def test_a_resumed_fetch_only_needs_what_is_left() -> None:
    """Otherwise a fetch that got to 99% would be refused for want of room
    it had already spent."""

    entry = an_entry()
    plan = plan_acquisition(
        entry,
        consent=consent_for(),
        free_bytes=MIN_FREE_HEADROOM_BYTES + 16,
        resume_from=entry.size_bytes - 16,
    )
    assert plan.remaining_bytes == 16
    assert plan.resume_from == entry.size_bytes - 16


def test_the_attempt_budget_is_finite() -> None:
    """Resume makes a retry cheap. It does not make an unbounded number of
    them acceptable."""

    entry = an_entry()
    assert plan_acquisition(
        entry, consent=consent_for(), free_bytes=PLENTY, attempts_used=MAX_ATTEMPTS - 1
    ).attempts_remaining == 1
    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(
            entry, consent=consent_for(), free_bytes=PLENTY, attempts_used=MAX_ATTEMPTS
        )
    assert caught.value.cause is Refusal.ATTEMPTS_EXHAUSTED


def test_what_is_already_installed_is_not_fetched_again() -> None:
    entry = an_entry()
    with pytest.raises(AcquisitionRefused) as caught:
        plan_acquisition(
            entry,
            consent=consent_for(),
            free_bytes=PLENTY,
            installed={entry.model_id: entry.digest},
        )
    assert caught.value.cause is Refusal.ALREADY_INSTALLED
    # A different digest under the same id is a different artifact.
    assert plan_acquisition(
        entry,
        consent=consent_for(),
        free_bytes=PLENTY,
        installed={entry.model_id: "sha256:" + "0" * 64},
    )


def test_a_plan_built_directly_still_refuses_an_unknown_symbol() -> None:
    """`plan_acquisition` refuses one first, so this invariant is only ever
    exercised by a caller who bypassed it -- which is exactly the caller it
    exists for. An invariant nothing reaches on its own is one that quietly
    stops holding."""

    with pytest.raises(AcquisitionRefused) as caught:
        AcquisitionPlan(
            model_id="m",
            source_id="somebody-elses-mirror",
            expected_digest="sha256:" + "0" * 64,
            expected_size_bytes=10,
            resume_from=0,
        )
    assert caught.value.cause is Refusal.UNKNOWN_SOURCE


@pytest.mark.parametrize("offset", [-1, 11])
def test_a_plan_built_directly_still_refuses_an_offset_outside_the_artifact(offset) -> None:
    with pytest.raises(AcquisitionRefused):
        AcquisitionPlan(
            model_id="m",
            source_id="vendor-mirror",
            expected_digest="sha256:" + "0" * 64,
            expected_size_bytes=10,
            resume_from=offset,
        )
    # The ends are inside: resuming from 0 or from the last byte are both real.
    for inside in (0, 10):
        assert AcquisitionPlan(
            model_id="m",
            source_id="vendor-mirror",
            expected_digest="sha256:" + "0" * 64,
            expected_size_bytes=10,
            resume_from=inside,
        ).resume_from == inside


def test_a_plan_built_directly_still_refuses_an_exhausted_budget() -> None:
    with pytest.raises(AcquisitionRefused) as caught:
        AcquisitionPlan(
            model_id="m",
            source_id="vendor-mirror",
            expected_digest="sha256:" + "0" * 64,
            expected_size_bytes=10,
            resume_from=0,
            attempts_remaining=0,
        )
    assert caught.value.cause is Refusal.ATTEMPTS_EXHAUSTED


def test_a_plan_carries_a_deadline_and_a_bounded_chunk() -> None:
    plan = a_plan()
    assert plan.timeout_seconds == TIMEOUT_SECONDS > 0
    assert plan.chunk_bytes == RESUME_CHUNK_BYTES > 0


def test_a_plan_names_no_address() -> None:
    """Resolving is the runtime's job. A plan that carried an address would
    be an address this layer had handled."""

    event = a_plan().as_event()
    flattened = repr(event).lower()
    for forbidden in ("http", "://", "host", "port", "url", ".invalid", "/artifacts"):
        assert forbidden not in flattened, forbidden
    assert event["source_id"] in KNOWN_SOURCES


# -- there is no acquisition path in this distribution ---------------------


def test_the_library_cannot_speak_to_a_network() -> None:
    """Absent, not configured off. A setting is a thing that can be set."""

    tree = ast.parse(
        pathlib.Path(model_acquisition.__file__).read_text(encoding="utf-8")
    )
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {
        "socket", "ssl", "http", "urllib", "requests", "httpx", "ftplib",
        "subprocess", "asyncio", "selectors",
    } == set(), sorted(imported)


@pytest.mark.parametrize("module", ["route_selection", "remote_trust"])
def test_the_judgement_layers_still_hold_no_client(module) -> None:
    """#93's premise: they are pure judgement, and acquisition did not
    change that by arriving next door."""

    import importlib

    source = pathlib.Path(
        importlib.import_module(f"azazel_nexus.{module}").__file__
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"socket", "ssl", "http", "urllib", "model_acquisition"} == set()


def test_the_runtime_holds_no_fetcher_either() -> None:
    tree = ast.parse(pathlib.Path(model_fetch.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {
        "socket", "ssl", "http", "urllib", "requests", "httpx", "subprocess"
    } == set(), sorted(imported)


def test_a_drive_with_no_fetcher_does_nothing_and_says_so() -> None:
    """The ordinary result in this build, and the acceptance condition."""

    result = drive_fetch(a_plan())
    assert result.outcome is FetchOutcome.NO_FETCHER
    assert result.received == 0
    assert "absent rather than disabled" in result.reason


def test_every_endpoint_is_a_host_that_cannot_resolve() -> None:
    """The second lock. Filling in a real host is a deliberate change to
    this table, not a typo somebody makes."""

    for symbol, endpoint in ENDPOINT_FOR.items():
        assert endpoint.host.endswith(".invalid"), symbol
    with pytest.raises(ValueError):
        Endpoint(host="models.example.com", port=443, path_template="/a/{digest}")


def test_a_path_template_has_exactly_one_hole() -> None:
    """A template with another hole is a template something can steer."""

    for endpoint in ENDPOINT_FOR.values():
        assert endpoint.path_template.count("{") == 1
        assert "{digest}" in endpoint.path_template
    with pytest.raises(ValueError):
        Endpoint(host="a.invalid", port=443, path_template="/{name}/{digest}")


def test_the_symbol_table_and_the_endpoint_table_are_one_fact() -> None:
    """A mismatch stops the import, not the fetch somebody finally confirmed."""

    assert set(ENDPOINT_FOR) == set(KNOWN_SOURCES)


def test_a_symbol_the_endpoint_table_does_not_cover_stops_the_import() -> None:
    """The two tables are one fact recorded twice, and this is what keeps
    them one fact.

    Without exercising the disagreement the check never fires, and a check
    that never fires is indistinguishable from one that was deleted. So the
    module is reloaded against a symbol set it does not cover: the failure
    has to arrive at import, not at the moment an operator finally confirms
    a fetch.

    The module is executed into a throwaway namespace rather than reloaded:
    a reload rebinds the real module's classes, and every later assertion of
    the form `outcome is FetchOutcome.COMPLETE` would then compare a new
    class against the one this file imported. The check under test is at
    module level, so a fresh exec reaches it without disturbing anything.
    """

    import types

    source = pathlib.Path(model_fetch.__file__).read_text(encoding="utf-8")
    code = compile(source, model_fetch.__file__, "exec")

    def run_isolated(name):
        # A real module object registered under a throwaway name: `@dataclass`
        # resolves `sys.modules[cls.__module__]`, so a bare dict is not enough.
        module = types.ModuleType(name)
        sys.modules[name] = module
        try:
            exec(code, module.__dict__)
        finally:
            sys.modules.pop(name, None)

    original = model_acquisition.KNOWN_SOURCES
    try:
        model_acquisition.KNOWN_SOURCES = original + ("a-symbol-with-no-address",)
        with pytest.raises(ImportError) as caught:
            run_isolated("_isolated_model_fetch_mismatch")
        assert "a-symbol-with-no-address" in str(caught.value)
    finally:
        model_acquisition.KNOWN_SOURCES = original
    # And with the tables agreeing again, the same exec completes.
    run_isolated("_isolated_model_fetch_agreeing")
    assert set(model_fetch.ENDPOINT_FOR) == set(model_acquisition.KNOWN_SOURCES)


def test_an_unresolvable_symbol_refuses_rather_than_inventing_an_endpoint() -> None:
    plan = a_plan()
    object.__setattr__(plan, "source_id", "not-in-the-table")
    with pytest.raises(FetchRefused):
        endpoint_for(plan)


# -- the bounds a fetcher cannot widen -------------------------------------


def _driven(chunks, *, plan=None, clock=None):
    written = bytearray()
    result = drive_fetch(
        plan or a_plan(),
        fetcher=lambda **kwargs: iter(chunks),
        sink=written.extend,
        elapsed=clock,
    )
    return result, bytes(written)


def test_a_complete_transfer_is_complete_and_nothing_more() -> None:
    """`COMPLETE` is not `VERIFIED` and not `PROMOTED`."""

    result, written = _driven([WEIGHTS])
    assert result.outcome is FetchOutcome.COMPLETE
    assert written == WEIGHTS
    assert "nothing here has decided it" in result.reason
    assert "VERIFIED" not in {o.name for o in FetchOutcome}
    assert "PROMOTED" not in {o.name for o in FetchOutcome}


def test_a_fetcher_that_yields_more_than_declared_is_stopped() -> None:
    """A file that grew is not the file that was planned for."""

    result, written = _driven([WEIGHTS, b"and more"])
    assert result.outcome is FetchOutcome.OVERRAN
    assert written == WEIGHTS


def test_a_short_transfer_is_interrupted_and_resumable() -> None:
    result, written = _driven([WEIGHTS[:100]])
    assert result.outcome is FetchOutcome.INTERRUPTED
    assert result.received == 100
    assert "cannot skip verification" in result.reason
    resumed = plan_acquisition(
        an_entry(), consent=consent_for(), free_bytes=PLENTY, resume_from=100
    )
    assert resumed.remaining_bytes == len(WEIGHTS) - 100


def test_the_deadline_stops_a_transfer_that_does_not() -> None:
    """A fetch with no deadline is one nobody learns has stopped."""

    ticks = iter([0, TIMEOUT_SECONDS + 1, TIMEOUT_SECONDS + 2])
    result, written = _driven(
        [WEIGHTS[:10], WEIGHTS[10:20], WEIGHTS[20:30]], clock=lambda: next(ticks)
    )
    assert result.outcome is FetchOutcome.TIMED_OUT
    assert result.received == 10, "a chunk was taken after the deadline"


def test_a_drive_that_cannot_write_does_not_run() -> None:
    with pytest.raises(FetchRefused):
        drive_fetch(a_plan(), fetcher=lambda **kwargs: iter([b"x"]))


def test_the_fetcher_is_handed_the_resolved_address_and_never_chooses_one() -> None:
    seen = {}

    def fetcher(**kwargs):
        seen.update(kwargs)
        return iter([WEIGHTS])

    plan = a_plan()
    drive_fetch(plan, fetcher=fetcher, sink=lambda chunk: None)
    endpoint = ENDPOINT_FOR[plan.source_id]
    assert seen["host"] == endpoint.host
    assert seen["port"] == endpoint.port
    assert seen["path"] == endpoint.path_template.format(digest=plan.expected_digest)
    assert seen["offset"] == plan.resume_from
    assert seen["chunk_bytes"] == plan.chunk_bytes
    # The digest is in the path, so a fetcher cannot be pointed at a
    # different artifact while claiming to serve this plan.
    assert plan.expected_digest.split(":")[1] in seen["path"]


def test_a_fetch_result_carries_no_address() -> None:
    result, _ = _driven([WEIGHTS])
    flattened = repr(result.as_event()).lower()
    for forbidden in (".invalid", "http", "://", "/artifacts"):
        assert forbidden not in flattened, forbidden


# -- fetching is not admitting, and failing is not fatal -------------------


def test_the_offline_route_is_untouched_by_every_acquisition_refusal(tmp_path) -> None:
    """A node that cannot download is a node that installs from a USB stick,
    not a node that cannot install."""

    from azazel_nexus.model_catalog import (
        CATALOG_DOMAIN,
        CATALOG_FILENAME,
        catalog_payload,
    )
    from azazel_nexus.model_import import CommissionedModels, ModelImport, entry_id_for

    nacl_signing = pytest.importorskip("nacl.signing")
    seed = hashlib.sha256(b"azazel-nexus/test-only/model-acquisition/0").digest()
    key = nacl_signing.SigningKey(seed)
    commissioning = "sha256:" + "c" * 64

    root = tmp_path / "node"
    (root / "inbox").mkdir(parents=True)
    entry = an_entry(source_id=None)
    body = catalog_payload(
        version=1, commissioning_digest=commissioning, entries=[entry]
    )
    path = root / "trust" / CATALOG_FILENAME
    path.parent.mkdir(parents=True)
    path.write_bytes(bytes(key.sign(CATALOG_DOMAIN + body).signature) + body)

    # No source, so no online route exists at all.
    with pytest.raises(AcquisitionRefused):
        plan_acquisition(entry, consent=consent_for(), free_bytes=PLENTY)

    # And the offline route works, unchanged.
    commissioned = CommissionedModels(
        root=root,
        trusted_keys={"catalog-key": bytes(key.verify_key)},
        commissioning_digest=commissioning,
    )
    (root / "inbox" / "model.bin").write_bytes(WEIGHTS)
    outcome = ModelImport(commissioned).import_entry(
        entry_id_for(display_name="model.bin", size=len(WEIGHTS)),
        "small-advisor",
        now=NOW,
        actor="an-operator",
    )
    assert outcome.promoted
    assert outcome.reading.admitted is False


def test_a_fetched_artifact_is_verified_by_the_same_path_as_an_imported_one() -> None:
    """No second verifier and no shortcut for bytes that arrived over a
    socket. This module contains no verification of its own."""

    for module in (model_acquisition, model_fetch):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        names = {
            n.name for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert not any(
            name.lstrip("_").startswith(("verify", "admit", "activate", "promote"))
            for name in names
        ), sorted(names)
        # And neither can compute a digest, so neither could verify even if
        # somebody named a function for it. `hashlib` is the only way to one.
        imported = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                imported.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                imported.add(n.module.split(".")[0])
        assert "hashlib" not in imported, f"{module.__name__} can hash"


def test_nothing_here_admits_or_starts_anything() -> None:
    tree = ast.parse(
        pathlib.Path(model_acquisition.__file__).read_text(encoding="utf-8")
    )
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert not any(
        name.lstrip("_").startswith(
            ("admit", "activate", "run", "exec", "launch", "start", "fetch", "download")
        )
        for name in names
    ), sorted(names)


# -- no authority ----------------------------------------------------------


def test_no_acquisition_state_moves_the_edge_answer() -> None:
    from azazel_nexus.edge_package import inspect as inspect_edge

    root = pathlib.Path("/nonexistent-edge-core-for-model-acquisition")

    def edge_answer():
        answer = inspect_edge(root)
        return (answer.ready, answer.presence.value, answer.state().ready)

    baseline = edge_answer()
    assert baseline == (False, "absent", False)

    for source_id in (None, "vendor-mirror", "unknown-mirror"):
        for consent in (NO_CONSENT, consent_for(), consent_for(*KNOWN_SOURCES)):
            try:
                plan = plan_acquisition(
                    an_entry(source_id=source_id),
                    consent=consent,
                    free_bytes=PLENTY,
                )
            except AcquisitionRefused:
                assert edge_answer() == baseline
                continue
            drive_fetch(plan)
            _driven([WEIGHTS], plan=plan)
            assert edge_answer() == baseline
