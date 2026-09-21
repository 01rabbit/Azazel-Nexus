"""The one screen an operator sees, and what looking at it does not do (#99).

Three vocabularies that must not merge, five confirmations that must not
collapse, and a page that must not change anything by being read.

The signing oracle is a fixed, test-only key derived from a literal string.
It is shared with no production, commissioned or release key, exists only for
the run, and no key material reaches a file, a fixture, a log or an assertion.
"""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib

import pytest

from azazel_nexus import operator_view
from azazel_nexus.model_catalog import (
    CATALOG_DOMAIN,
    CATALOG_FILENAME,
    CatalogState,
    ModelEntry,
    ModelReading,
    Refusal,
    catalog_payload,
)
from azazel_nexus.mio_profile import (
    NO_OPT_IN,
    PREREQUISITES,
    MioProfile,
    RemoteOptIn,
)
from azazel_nexus.model_import import CommissionedModels, ModelImport
from azazel_nexus.operator_view import (
    NOMINAL_CLASS_GIB,
    STATUS_SENTENCE,
    Confirmation,
    NodeResources,
    Operation,
    OperatorView,
    ProviderState,
    ViewFacts,
    build_view,
    gather_facts,
    possibilities,
)
from azazel_nexus.resource_profile import ResourceProfile

nacl_signing = pytest.importorskip("nacl.signing", reason="PyNaCl is a dev dependency")

COMMISSIONING = "sha256:" + "c" * 64
NOW = "2026-01-01T00:00:00Z"
ACTOR = "operator-under-test"
WEIGHTS = b"weights, not a program -- " + b"w" * 2048

_SEED = hashlib.sha256(b"azazel-nexus/test-only/operator-view/0").digest()


def _key():
    return nacl_signing.SigningKey(_SEED)


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
    }
    fields.update(overrides)
    return ModelEntry(**fields)


@pytest.fixture
def node(tmp_path):
    root = tmp_path / "node"
    (root / "inbox").mkdir(parents=True)
    commissioned = CommissionedModels(
        root=root,
        trusted_keys={"catalog-key": bytes(_key().verify_key)},
        commissioning_digest=COMMISSIONING,
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


def some_resources(usable_mib=16384):
    return NodeResources(
        usable_mib=usable_mib, disk_total_mib=512_000, disk_free_mib=400_000
    )


def facts(**overrides) -> ViewFacts:
    base = {
        "profile": MioProfile.CORE,
        "opt_in": NO_OPT_IN,
        "reserve_measured": False,
        "resources": some_resources(),
        "catalog_state": CatalogState.ABSENT,
        "readings": (),
        "inbox": (),
        "quarantined": 0,
        "installed": {},
        "rollback_target": None,
    }
    base.update(overrides)
    return ViewFacts(**base)


def a_reading(state=CatalogState.DECLARED, refused_by=Refusal.ARTIFACT_ABSENT,
              model_id="small-advisor", reason="fixture reading") -> ModelReading:
    return ModelReading(
        model_id=model_id, state=state, refused_by=refused_by, reason=reason
    )


def full_opt_in() -> RemoteOptIn:
    return RemoteOptIn(
        granted=frozenset(PREREQUISITES), operator="an-operator", at=NOW
    )


# -- after installation ----------------------------------------------------


def test_a_node_straight_out_of_installation_shows_core(node) -> None:
    view = build_view(facts())
    row = [
        r for r in view.section("cognition").rows if r["axis"] == "mio_profile"
    ][0]
    assert row["value"] == MioProfile.CORE.value
    assert view.status_sentence == STATUS_SENTENCE


# -- resources are shown, not asked, and never an admission input ----------


def test_resources_are_displayed_read_only(node) -> None:
    view = build_view(facts(resources=some_resources(usable_mib=16384)))
    rows = {r["axis"]: r for r in view.section("resources").rows if "axis" in r}
    assert rows["usable_memory_mib"]["value"] == 16384
    assert rows["resource_profile"]["value"] == ResourceProfile.LITE.value
    assert rows["disk_total_mib"]["value"] == 512_000
    assert rows["disk_free_mib"]["value"] == 400_000
    assert "never evidence that a capability fits" in rows["resource_profile"]["reason"]


def test_the_classes_are_shown_as_possibilities_and_nothing_is_chosen(node) -> None:
    """8 / 16 / 32 appear as what a host of that class selects -- an offer of
    information, not an offer of a model."""

    view = build_view(facts(resources=some_resources(usable_mib=16384)))
    shown = [r for r in view.section("resources").rows if "nominal_gib" in r]
    assert [r["nominal_gib"] for r in shown] == list(NOMINAL_CLASS_GIB)
    assert [r["is_this_node"] for r in shown] == [False, True, False]
    for row in shown:
        assert "nothing is chosen, fetched or started" in row["note"]
    # And no possibility is an operation: nothing here offers to act.
    assert all("model" not in r for r in shown)


def test_the_possibilities_come_from_the_selector_not_a_second_copy() -> None:
    """A screen carrying its own floors is where the numbers first diverge."""

    from azazel_nexus.resource_profile import select_profile

    for possibility in possibilities(some_resources()):
        assert possibility.profile is select_profile(possibility.nominal_gib * 1024)


def test_a_node_whose_memory_could_not_be_read_shows_no_profile() -> None:
    """A default here would be a hardware class asserted on no measurement."""

    view = build_view(facts(resources=NodeResources(None, None, None)))
    rows = {r["axis"]: r for r in view.section("resources").rows if "axis" in r}
    assert rows["resource_profile"]["value"] is None
    assert all(r["is_this_node"] is False
               for r in view.section("resources").rows if "nominal_gib" in r)


# -- three vocabularies, kept apart ----------------------------------------


def test_catalog_states_and_provider_states_share_no_word() -> None:
    """The two answer different questions, and a `present` artifact is
    routinely `not admitted`. If one word appeared in both, a row from one
    could be read as an answer from the other."""

    assert {s.value for s in CatalogState} & {s.value for s in ProviderState} == set()


def test_the_catalog_section_carries_only_catalog_states(node) -> None:
    view = build_view(
        facts(
            catalog_state=CatalogState.PRESENT,
            readings=(a_reading(state=CatalogState.PRESENT, refused_by=None),),
        )
    )
    catalog_values = {s.value for s in CatalogState}
    provider_values = {s.value for s in ProviderState}
    for row in view.section("catalog").rows:
        assert row["value"] in catalog_values
        assert row["value"] not in provider_values


def test_a_present_artifact_is_still_reported_not_admitted(node) -> None:
    """The pair this screen exists to keep apart, in one assertion."""

    view = build_view(
        facts(
            catalog_state=CatalogState.PRESENT,
            readings=(a_reading(state=CatalogState.PRESENT, refused_by=None),),
            installed={"small-advisor": an_entry().digest},
        )
    )
    model_row = [r for r in view.section("catalog").rows if r["axis"] == "model"][0]
    assert model_row["value"] == CatalogState.PRESENT.value
    assert model_row["admitted"] is False
    provider_row = [
        r for r in view.section("cognition").rows if r["axis"] == "provider_state"
    ][0]
    assert provider_row["value"] == ProviderState.NOT_ADMITTED.value


@pytest.mark.parametrize("state", list(CatalogState))
def test_every_catalog_state_is_shown_with_a_reason_of_its_own(state) -> None:
    view = build_view(facts(catalog_state=state))
    row = [r for r in view.section("catalog").rows if r["axis"] == "catalog_state"][0]
    assert row["value"] == state.value
    assert row["reason"].strip()


def test_absent_and_empty_do_not_read_alike() -> None:
    """One node was told nothing; the other was told nothing is offered."""

    absent = build_view(facts(catalog_state=CatalogState.ABSENT))
    empty = build_view(facts(catalog_state=CatalogState.EMPTY))
    absent_row = [r for r in absent.section("catalog").rows
                  if r["axis"] == "catalog_state"][0]
    empty_row = [r for r in empty.section("catalog").rows
                 if r["axis"] == "catalog_state"][0]
    assert absent_row["value"] != empty_row["value"]
    assert absent_row["reason"] != empty_row["reason"]
    assert absent.operation(Confirmation.MODEL_IMPORT).reason != \
        empty.operation(Confirmation.MODEL_IMPORT).reason


# -- the import lifecycle, and the next safe operation ---------------------


def test_the_import_section_shows_every_stage(node) -> None:
    view = build_view(
        facts(
            catalog_state=CatalogState.PRESENT,
            inbox=("model.bin", "other.bin"),
            quarantined=3,
            installed={"small-advisor": an_entry().digest},
            rollback_target=2,
        )
    )
    rows = {r["axis"]: r for r in view.section("import").rows}
    assert set(rows) == {"inbox", "staging", "quarantine", "promoted", "rollback_target"}
    assert rows["inbox"]["value"] == 2
    assert rows["inbox"]["entries"] == ["model.bin", "other.bin"]
    assert rows["staging"]["value"] == 0
    assert rows["quarantine"]["value"] == 3
    assert "never executed, extracted, served or retried" in rows["quarantine"]["reason"]
    assert rows["promoted"]["entries"] == ["small-advisor"]
    assert "Installed is not admitted" in rows["promoted"]["reason"]
    assert rows["rollback_target"]["value"] == 2


def test_with_no_earlier_generation_the_rollback_row_says_so(node) -> None:
    view = build_view(facts(rollback_target=None))
    row = [r for r in view.section("import").rows if r["axis"] == "rollback_target"][0]
    assert row["value"] is None
    assert "nothing to restore" in row["reason"]


@pytest.mark.parametrize(
    "state, inbox, available",
    [
        (CatalogState.ABSENT, (), False),
        (CatalogState.EMPTY, (), False),
        (CatalogState.DECLARED, (), False),
        (CatalogState.DECLARED, ("model.bin",), True),
    ],
)
def test_the_next_safe_operation_names_what_is_missing(state, inbox, available) -> None:
    """An option that cannot be taken is shown with its reason, never removed."""

    view = build_view(facts(catalog_state=state, inbox=inbox))
    operation = view.operation(Confirmation.MODEL_IMPORT)
    assert operation.available is available
    assert operation.reason.strip()


def test_an_absent_catalog_refuses_an_import_however_full_the_inbox() -> None:
    """A stocked inbox is not permission to install something nobody named.

    With only the empty-inbox case covered, "no catalog" and "nothing placed"
    reach the same refusal and the distinction is never exercised.
    """

    view = build_view(
        facts(catalog_state=CatalogState.ABSENT, inbox=("a.bin", "b.bin"))
    )
    operation = view.operation(Confirmation.MODEL_IMPORT)
    assert operation.available is False
    assert "no catalog has been presented" in operation.reason
    # And the empty catalog says something else again.
    stocked_empty = build_view(
        facts(catalog_state=CatalogState.EMPTY, inbox=("a.bin",))
    )
    assert stocked_empty.operation(Confirmation.MODEL_IMPORT).available is False
    assert stocked_empty.operation(
        Confirmation.MODEL_IMPORT
    ).reason != operation.reason


def test_acquisition_is_offered_as_absent_rather_than_hidden(node) -> None:
    """A confirmation with no path behind it is still shown, so that nobody
    goes looking for the setting that would enable it."""

    view = build_view(facts())
    operation = view.operation(Confirmation.MODEL_ACQUISITION)
    assert operation.available is False
    assert "absent rather than switched off" in operation.reason
    assert "offline import route is unaffected" in operation.reason
    assert operation.transition == "mio.model.acquisition.planned"
    # And it is not the import confirmation wearing another name.
    assert operation.transition != view.operation(Confirmation.MODEL_IMPORT).transition


def test_an_unavailable_operation_is_present_rather_than_missing() -> None:
    """A screen where options vanish is a screen somebody searches for an hour."""

    view = build_view(facts())
    assert {o.confirmation for o in view.operations} == set(Confirmation)
    assert any(o.available is False for o in view.operations)


def test_an_operation_cannot_be_built_without_a_reason() -> None:
    with pytest.raises(ValueError):
        Operation(confirmation=Confirmation.PROFILE, available=False, reason="  ")


# -- five confirmations stay five ------------------------------------------


def test_every_confirmation_is_its_own_operation_and_its_own_transition() -> None:
    """Collapsed into one "yes", an operator consents to six things
    believing they consented to one.

    The count is pinned alongside the identity so that adding a consent by
    widening an existing member's wording -- rather than by adding a member --
    shows up here as a count that did not move.
    """

    expected = len(Confirmation)
    assert expected == 6
    view = build_view(facts())
    assert len(view.operations) == expected
    confirmations = [o.confirmation for o in view.operations]
    assert len(set(confirmations)) == expected
    transitions = [o.transition for o in view.operations]
    assert len(set(transitions)) == expected, "two confirmations write one event"


def test_each_confirmation_names_exactly_one_thing() -> None:
    """A sixth consent folded into a fifth is a sixth consent nobody sees.

    The values are pinned rather than counted: five members whose wording
    quietly grew to cover two things each would still be five members.
    """

    assert {c.value for c in Confirmation} == {
        "profile",
        "remote opt-in",
        "license acknowledgement",
        "model import",
        "model acquisition",
        "provider admission",
    }
    for confirmation in Confirmation:
        assert " and " not in confirmation.value, confirmation


def test_no_operation_reason_offers_to_do_another_ones_job() -> None:
    """Widening the profile is not consenting to remote; importing is not
    admitting."""

    view = build_view(facts(profile=MioProfile.CORE))
    remote = view.operation(Confirmation.REMOTE_OPT_IN)
    assert remote.available is False
    assert "a separate confirmation" in remote.reason


def test_a_licence_is_asked_for_only_when_one_is_waiting() -> None:
    waiting = build_view(
        facts(
            catalog_state=CatalogState.DECLARED,
            readings=(a_reading(refused_by=Refusal.LICENSE_NOT_ACKNOWLEDGED),),
        )
    )
    assert waiting.operation(Confirmation.LICENSE_ACKNOWLEDGEMENT).available is True
    assert "small-advisor" in waiting.operation(
        Confirmation.LICENSE_ACKNOWLEDGEMENT
    ).reason
    quiet = build_view(facts(readings=(a_reading(),)))
    assert quiet.operation(Confirmation.LICENSE_ACKNOWLEDGEMENT).available is False


# -- fastest-permitted does not admit anything -----------------------------


@pytest.mark.parametrize("profile", list(MioProfile))
def test_no_profile_admits_a_provider_while_the_reserve_is_unmeasured(profile) -> None:
    view = build_view(facts(profile=profile, opt_in=full_opt_in(), reserve_measured=False))
    admission = view.operation(Confirmation.PROVIDER_ADMISSION)
    assert admission.available is False
    assert "HG-05" in admission.reason
    assert "not functional" in admission.reason
    provider_row = [
        r for r in view.section("cognition").rows if r["axis"] == "provider_state"
    ][0]
    assert provider_row["value"] == ProviderState.NOT_ADMITTED.value


def test_fastest_permitted_with_every_prerequisite_still_admits_nothing() -> None:
    """The case an operator is most likely to read as "ready"."""

    view = build_view(
        facts(
            profile=MioProfile.FASTEST_PERMITTED,
            opt_in=full_opt_in(),
            reserve_measured=False,
            catalog_state=CatalogState.PRESENT,
            readings=(a_reading(state=CatalogState.PRESENT, refused_by=None),),
            installed={"small-advisor": an_entry().digest},
        )
    )
    assert view.operation(Confirmation.PROVIDER_ADMISSION).available is False
    assert view.status_sentence == STATUS_SENTENCE
    assert "functional" not in view.status_sentence


@pytest.mark.parametrize("measured", [False, True])
def test_the_sentence_does_not_move_on_any_path(measured) -> None:
    for profile in MioProfile:
        for state in CatalogState:
            view = build_view(
                facts(profile=profile, opt_in=full_opt_in(),
                      reserve_measured=measured, catalog_state=state)
            )
            assert view.status_sentence == STATUS_SENTENCE
            document = json.dumps(view.as_document())
            assert "provider execution unavailable" in document
            assert '"functional"' not in document


def test_even_a_measured_reserve_does_not_reach_a_running_provider() -> None:
    view = build_view(facts(reserve_measured=True))
    admission = view.operation(Confirmation.PROVIDER_ADMISSION)
    assert admission.available is False
    assert "no implementation" in admission.reason
    assert view.status_sentence == STATUS_SENTENCE


# -- reading the screen does nothing ---------------------------------------


def test_the_view_module_performs_no_io_at_all() -> None:
    """Not a guard that could be edited: the module cannot read or write.

    A screen that changes something when looked at is a screen an operator
    stops looking at, and this one is meant to be consulted before every
    irreversible step.
    """

    tree = ast.parse(pathlib.Path(operator_view.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node_ in ast.walk(tree):
        if isinstance(node_, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node_.names)
        elif isinstance(node_, ast.ImportFrom) and node_.module and node_.level == 0:
            imported.add(node_.module.split(".")[0])
    assert imported & {
        "os", "pathlib", "shutil", "subprocess", "socket", "ssl", "http",
        "urllib", "requests", "httpx", "hashlib", "tempfile", "sqlite3",
    } == set(), sorted(imported)
    called = {
        n.func.id for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "open" not in called and "exec" not in called and "eval" not in called


def test_gather_facts_may_only_call_read_verbs() -> None:
    """The one function that touches a service, held to an allow-list.

    Checked against the syntax tree rather than trusted because it is in a
    function called `gather_facts`: a name is not an enforcement.
    """

    tree = ast.parse(pathlib.Path(operator_view.__file__).read_text(encoding="utf-8"))
    gather = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "gather_facts"
    ][0]
    on_service = {
        n.func.attr
        for n in ast.walk(gather)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id == "service"
    }
    assert on_service, "a vacuous check: no call on the service was found"
    assert on_service <= set(operator_view.READ_ONLY_VERBS), sorted(on_service)


def test_building_the_screen_over_a_real_node_changes_nothing(node) -> None:
    """End to end: gather, build, render -- and the tree is byte-identical."""

    service = ModelImport(node)
    entry_bytes = WEIGHTS
    (node.inbox / "model.bin").write_bytes(entry_bytes)
    service.import_entry(
        operator_view_entry_id(node), "small-advisor", now=NOW, actor=ACTOR
    )

    def snapshot():
        return {
            str(p.relative_to(node.root)): (
                p.stat().st_mtime_ns if p.is_file() else "dir"
            )
            for p in sorted(node.root.rglob("*"))
        }

    before = snapshot()
    written = []
    watched = ModelImport(node, recorder=lambda t, e: written.append(t))
    for _ in range(3):
        gathered = gather_facts(
            watched,
            profile=MioProfile.FASTEST_PERMITTED,
            opt_in=full_opt_in(),
            reserve_measured=False,
            resources=some_resources(),
            model_ids=("small-advisor", "never-declared"),
        )
        view = build_view(gathered)
        json.dumps(view.as_document())
    assert snapshot() == before
    assert written == [], "reading the screen wrote an audit event"
    assert view.status_sentence == STATUS_SENTENCE
    assert view.operation(Confirmation.PROVIDER_ADMISSION).available is False


def operator_view_entry_id(node):
    from azazel_nexus.model_import import entry_id_for

    return entry_id_for(display_name="model.bin", size=len(WEIGHTS))


def test_a_first_generation_offers_no_rollback_target(node) -> None:
    """Retention is what makes a rollback possible. Generation 1 has none,
    and offering one would point at a generation that never existed."""

    service = ModelImport(node)
    (node.inbox / "model.bin").write_bytes(WEIGHTS)
    service.import_entry(
        operator_view_entry_id(node), "small-advisor", now=NOW, actor=ACTOR
    )
    gathered = gather_facts(
        service,
        profile=MioProfile.CORE,
        opt_in=NO_OPT_IN,
        reserve_measured=False,
        resources=some_resources(),
        model_ids=("small-advisor",),
    )
    assert service.current_generation().number == 1
    assert gathered.rollback_target is None
    row = [
        r for r in build_view(gathered).section("import").rows
        if r["axis"] == "rollback_target"
    ][0]
    assert row["value"] is None
    assert "nothing to restore" in row["reason"]


def test_gathering_reports_the_strongest_state_the_node_holds(node) -> None:
    """One unknown model must not make a stocked node look empty."""

    service = ModelImport(node)
    (node.inbox / "model.bin").write_bytes(WEIGHTS)
    service.import_entry(
        operator_view_entry_id(node), "small-advisor", now=NOW, actor=ACTOR
    )
    gathered = gather_facts(
        service,
        profile=MioProfile.CORE,
        opt_in=NO_OPT_IN,
        reserve_measured=False,
        resources=some_resources(),
        model_ids=("never-declared", "small-advisor"),
    )
    assert gathered.catalog_state is CatalogState.PRESENT


# -- no authority ----------------------------------------------------------


def test_no_state_of_this_screen_moves_the_edge_answer(node) -> None:
    """Edge authority, the action lease, enforcement and activation are
    unmoved by every M.I.O. and model-artifact state this screen can show."""

    from azazel_nexus.edge_package import inspect as inspect_edge

    root = pathlib.Path("/nonexistent-edge-core-for-operator-view")

    def edge_answer():
        answer = inspect_edge(root)
        return (answer.ready, answer.presence.value, answer.state().ready)

    baseline = edge_answer()
    assert baseline == (False, "absent", False)

    for profile in MioProfile:
        for catalog_state in CatalogState:
            for measured in (False, True):
                for opt_in in (NO_OPT_IN, full_opt_in()):
                    view = build_view(
                        facts(
                            profile=profile,
                            opt_in=opt_in,
                            reserve_measured=measured,
                            catalog_state=catalog_state,
                            readings=(a_reading(state=catalog_state, refused_by=None),),
                            installed={"small-advisor": an_entry().digest},
                            rollback_target=1,
                        )
                    )
                    json.dumps(view.as_document())
                    assert edge_answer() == baseline

    service = ModelImport(node)
    (node.inbox / "model.bin").write_bytes(WEIGHTS)
    service.import_entry(
        operator_view_entry_id(node), "small-advisor", now=NOW, actor=ACTOR
    )
    assert edge_answer() == baseline
    build_view(
        gather_facts(
            service,
            profile=MioProfile.FASTEST_PERMITTED,
            opt_in=full_opt_in(),
            reserve_measured=True,
            resources=some_resources(),
            model_ids=("small-advisor",),
        )
    )
    assert edge_answer() == baseline


def test_the_screen_offers_no_verb_that_acts() -> None:
    """It displays. Its public surface contains nothing that does anything.

    Deliberately not a ban on the words `import`, `promote` or `rollback`:
    this module has an `_import_section` because it *shows* the import
    lifecycle, and a check that forbade the word would forbid describing the
    thing. What it cannot do is perform any of them, and
    `test_the_view_module_performs_no_io_at_all` is what establishes that --
    a module that opens no file cannot import, promote or roll back anything.

    What is banned here is Edge's plane, where this module has no business
    even having a name: activation, the lease, enforcement.
    """

    source = pathlib.Path(operator_view.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert not any(
        name.lstrip("_").startswith(
            ("admit", "activate", "enforce", "lease", "launch", "spawn")
        )
        for name in names
    ), sorted(names)
    public = {
        n.name for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not n.name.startswith("_")
    }
    assert public == {"build_view", "gather_facts", "possibilities"}, sorted(public)
    assert public <= set(operator_view.__all__)
