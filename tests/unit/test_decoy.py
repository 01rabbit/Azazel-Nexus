"""The embedded Tactical Decoy Runtime, before it is allowed to exist (#54, E3).

The decoy is the only internal feature that can be reached from outside, so
the tests that matter are the ones about *not* being reachable: what has to be
true before anything listens, and what is refused whatever the configuration
says.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from azazel_nexus import decoy as decoy_module
from azazel_nexus.content_store import ContentRefused, digest_bytes
from azazel_nexus.decoy import (
    DECOY_BRIDGE,
    MAX_DECOYS,
    MIN_PORT,
    Commissioning,
    DecoyCatalogue,
    DecoyEntry,
    DecoyRefused,
    DecoyState,
    IsolationCheck,
    evaluate,
)

IMAGE = digest_bytes(b"an approved decoy image")
OTHER_IMAGE = digest_bytes(b"another approved decoy image")
RECORD = digest_bytes(b"a commissioning record")
GENERATION = digest_bytes(b"a verified generation")

PREFIX = "198.51.100.0/24"
ADDRESS = "198.51.100.10"
OTHER_ADDRESS = "198.51.100.11"


def an_entry(**overrides) -> DecoyEntry:
    fields = {"name": "decoy-a", "image_digest": IMAGE, "listen_address": ADDRESS, "port": 8080}
    fields.update(overrides)
    return DecoyEntry(**fields)


def a_commissioning(**overrides) -> Commissioning:
    fields = {
        "record_digest": RECORD,
        "generation_digest": GENERATION,
        "bridge_prefix": PREFIX,
        "actor": "operator@node",
    }
    fields.update(overrides)
    return Commissioning(**fields)


def a_passing_check(**overrides) -> IsolationCheck:
    fields = {
        "passed": True,
        "checked_at": "2026-09-21T00:00:00Z",
        "denied_paths": ("protected", "management", "control-plane", "internet"),
        "detail": "",
    }
    fields.update(overrides)
    return IsolationCheck(**fields)


def status(**overrides):
    call = {
        "name": "decoy-a",
        "catalogue": DecoyCatalogue.of([an_entry()]),
        "commissioning": a_commissioning(),
        "isolation": a_passing_check(),
        "operator_exposed": False,
        "quarantine_reason": None,
    }
    call.update(overrides)
    name = call.pop("name")
    return evaluate(name, **call)


# -- nothing listens until everything is true ------------------------------


def test_a_fresh_node_has_no_catalogue_and_nothing_is_approved() -> None:
    reading = status(catalogue=None)
    assert reading.state is DecoyState.DISABLED
    assert reading.exposed is False
    assert "nothing is approved" in reading.reason


def test_a_catalogued_decoy_without_commissioning_does_not_listen() -> None:
    """Being in a catalogue is not being approved to listen."""

    reading = status(commissioning=None)
    assert reading.state is DecoyState.DISABLED
    assert "not being approved to listen" in reading.reason


def test_a_commissioned_decoy_without_an_isolation_check_does_not_listen() -> None:
    reading = status(isolation=IsolationCheck(passed=None))
    assert reading.state is DecoyState.DISABLED
    assert "absence of a check is not a pass" in reading.reason


def test_a_failed_isolation_check_does_not_listen() -> None:
    reading = status(
        isolation=IsolationCheck(passed=False, detail="forwarding to management succeeded")
    )
    assert reading.state is DecoyState.DISABLED
    assert "forwarding to management succeeded" in reading.reason


def test_an_isolation_check_that_tested_nothing_did_not_pass() -> None:
    """A passing check over an empty path set is a check that did not run."""

    reading = status(isolation=a_passing_check(denied_paths=()))
    assert reading.state is DecoyState.DISABLED
    assert "tested no denied path" in reading.reason


def test_a_passing_check_without_a_timestamp_does_not_expose() -> None:
    reading = status(isolation=a_passing_check(checked_at=""))
    assert reading.state is DecoyState.DISABLED
    assert "records when it ran" in reading.reason


def test_everything_true_and_not_exposed_is_eligible_not_exposed() -> None:
    """Eligibility is not exposure, and the two are separate words."""

    reading = status()
    assert reading.state is DecoyState.ELIGIBLE
    assert reading.exposed is False
    assert "eligibility is not exposure" in reading.reason


def test_an_operator_exposing_an_eligible_decoy_exposes_it() -> None:
    """So the tests above are about the preconditions, not about never exposing."""

    reading = status(operator_exposed=True)
    assert reading.state is DecoyState.EXPOSED
    assert reading.exposed is True
    assert f"{ADDRESS}:8080" in reading.reason


@pytest.mark.parametrize(
    "missing",
    [
        {"catalogue": None},
        {"commissioning": None},
        {"isolation": IsolationCheck(passed=None)},
        {"isolation": IsolationCheck(passed=False, detail="x")},
    ],
)
def test_exposing_does_not_override_a_missing_precondition(missing: dict) -> None:
    """The operator's intent is one input, never the only one."""

    reading = status(operator_exposed=True, **missing)
    assert reading.state is DecoyState.DISABLED
    assert reading.exposed is False


# -- nothing arbitrary -----------------------------------------------------


def test_a_decoy_not_in_the_catalogue_is_refused() -> None:
    reading = status(name="decoy-unknown")
    assert reading.state is DecoyState.DISABLED
    assert "and nothing else" in reading.reason


@pytest.mark.parametrize("address", ["0.0.0.0", "::"])
def test_the_unspecified_address_is_refused_whatever_a_catalogue_says(address: str) -> None:
    """Binding it listens on every interface. That is not a decoy."""

    with pytest.raises(DecoyRefused) as caught:
        an_entry(listen_address=address)
    assert "general-network primitive" in str(caught.value)


@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
def test_loopback_is_refused(address: str) -> None:
    with pytest.raises(DecoyRefused) as caught:
        an_entry(listen_address=address)
    assert "loopback" in str(caught.value)


def test_an_address_outside_the_commissioned_prefix_does_not_listen() -> None:
    """The catalogue can name it; the commissioning decides where it may live."""

    outside = DecoyCatalogue.of([an_entry(listen_address="203.0.113.5")])
    reading = status(catalogue=outside, operator_exposed=True)
    assert reading.state is DecoyState.DISABLED
    assert DECOY_BRIDGE in reading.reason
    assert "outside the commissioned bridge prefix" in reading.reason


@pytest.mark.parametrize("port", [0, 1, 80, 443, MIN_PORT - 1, 65536, 70000, -1])
def test_a_port_outside_the_unprivileged_range_is_refused(port: int) -> None:
    with pytest.raises(DecoyRefused) as caught:
        an_entry(port=port)
    assert "65535" in str(caught.value)


@pytest.mark.parametrize("port", [MIN_PORT, 8080, 65535])
def test_an_unprivileged_port_is_accepted(port: int) -> None:
    """So the test above is about the range and not about refusing every port."""

    assert an_entry(port=port).port == port


@pytest.mark.parametrize("port", [True, "8080", 8080.0, None])
def test_a_port_that_is_not_a_whole_number_is_refused(port) -> None:
    with pytest.raises(DecoyRefused) as caught:
        an_entry(port=port)
    assert "whole number" in str(caught.value)


@pytest.mark.parametrize("image", ["latest", "decoy:1.0", "", "sha256:short"])
def test_an_image_named_by_anything_but_a_digest_is_refused(image: str) -> None:
    """A tag is a pointer somebody else can move."""

    with pytest.raises(ContentRefused):
        an_entry(image_digest=image)


@pytest.mark.parametrize("address", ["not-an-address", "198.51.100.300", ""])
def test_an_address_that_is_not_an_address_is_refused(address: str) -> None:
    with pytest.raises(DecoyRefused) as caught:
        an_entry(listen_address=address)
    assert "is not an address" in str(caught.value)


# -- one to three ----------------------------------------------------------


@pytest.mark.parametrize("count", [1, 2, 3])
def test_up_to_three_decoys_are_catalogued(count: int) -> None:
    entries = [
        an_entry(name=f"decoy-{index}", port=8080 + index) for index in range(count)
    ]
    assert len(DecoyCatalogue.of(entries).entries) == count


def test_a_fourth_decoy_is_refused_rather_than_truncated() -> None:
    entries = [an_entry(name=f"decoy-{index}", port=8080 + index) for index in range(4)]
    with pytest.raises(DecoyRefused) as caught:
        DecoyCatalogue.of(entries)
    assert "rather than truncated" in str(caught.value)
    assert str(MAX_DECOYS) in str(caught.value)


def test_an_empty_catalogue_is_refused() -> None:
    """A node with no decoys has no catalogue, not an empty one."""

    with pytest.raises(DecoyRefused) as caught:
        DecoyCatalogue.of([])
    assert "approves nothing" in str(caught.value)


def test_two_decoys_cannot_share_a_name() -> None:
    with pytest.raises(DecoyRefused) as caught:
        DecoyCatalogue.of([an_entry(), an_entry(port=8081)])
    assert "share a name" in str(caught.value)


def test_two_decoys_cannot_share_an_address_and_port() -> None:
    """One would silently fail to bind, and nobody would be told which."""

    with pytest.raises(DecoyRefused) as caught:
        DecoyCatalogue.of([an_entry(), an_entry(name="decoy-b")])
    assert "claim one address and port" in str(caught.value)


def test_two_decoys_may_share_a_port_on_different_addresses() -> None:
    catalogue = DecoyCatalogue.of(
        [an_entry(), an_entry(name="decoy-b", listen_address=OTHER_ADDRESS)]
    )
    assert len(catalogue.entries) == 2


# -- failure stops the decoy, not the node ---------------------------------


def test_a_quarantined_decoy_is_stopped_and_isolated() -> None:
    reading = status(quarantine_reason="the container exited with an unexpected status")
    assert reading.state is DecoyState.QUARANTINED
    assert reading.exposed is False
    assert "stopped and isolated" in reading.reason


def test_quarantine_preserves_telemetry() -> None:
    reading = status(quarantine_reason="isolation probe regressed")
    assert "Telemetry is kept" in reading.reason
    assert reading.generation_digest == GENERATION


def test_quarantine_wins_over_every_other_condition() -> None:
    """A decoy that is not trusted is not trusted, whatever else is true."""

    reading = status(operator_exposed=True, quarantine_reason="anything at all")
    assert reading.state is DecoyState.QUARANTINED


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"operator_exposed": True},
        {"catalogue": None},
        {"commissioning": None},
        {"quarantine_reason": "failed"},
        {"isolation": IsolationCheck(passed=False, detail="x")},
    ],
)
def test_no_decoy_state_blocks_the_deterministic_path(overrides: dict) -> None:
    assert status(**overrides).blocks_deterministic_path() is False


# -- redirect is never granted here ----------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"operator_exposed": True},
        {"catalogue": None},
        {"quarantine_reason": "failed"},
    ],
)
def test_redirect_is_never_eligible_in_any_state(overrides: dict) -> None:
    """Redirect is the arbiter's to issue. Nothing here grants it."""

    reading = status(**overrides)
    assert reading.redirect_eligible is False
    assert reading.as_event()["redirect_eligible"] is False


def test_redirect_eligibility_is_derived_and_not_a_field() -> None:
    """A future change has to be written, not configured."""

    tree = ast.parse(pathlib.Path(decoy_module.__file__).read_text(encoding="utf-8"))
    status_class = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "DecoyStatus"
    )
    fields = {
        node.target.id
        for node in status_class.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    assert "redirect_eligible" not in fields
    properties = {
        node.name
        for node in status_class.body
        if isinstance(node, ast.FunctionDef)
        and any(
            isinstance(d, ast.Name) and d.id == "property" for d in node.decorator_list
        )
    }
    assert "redirect_eligible" in properties


# -- nothing here acts -----------------------------------------------------


def test_the_module_cannot_start_bind_or_execute_anything() -> None:
    """§7: no shell, no arbitrary container start, no network primitive."""

    tree = ast.parse(pathlib.Path(decoy_module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    forbidden = imported & {
        "subprocess", "os", "socket", "ssl", "shutil", "signal", "pty", "ctypes",
        "multiprocessing", "http", "urllib", "asyncio",
    }
    assert forbidden == set(), f"the decoy runtime reached for {forbidden}"


#: Verbs that would mean this module does something outside its own process.
_ACTING_VERBS = frozenset(
    {"start", "run", "exec", "execute", "launch", "bind", "listen", "spawn", "redirect", "attach"}
)


def test_the_module_defines_no_verb_that_could_run_a_decoy() -> None:
    """Properties are excluded: an attribute read is not an operation.

    `redirect_eligible` is a predicate, not a verb -- it answers whether
    redirect is permitted, and the answer is always no. A scan that could not
    tell a property from a method would force that predicate to be renamed
    into something less clear, which is a worse outcome than the scan.
    """

    tree = ast.parse(pathlib.Path(decoy_module.__file__).read_text(encoding="utf-8"))
    methods = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not any(
            isinstance(d, ast.Name) and d.id == "property" for d in node.decorator_list
        )
    ]
    acting = {
        node.name
        for node in methods
        if node.name.lstrip("_").split("_")[0] in _ACTING_VERBS
    }
    assert acting == set(), f"the decoy runtime defines {acting}"

    # Not vacuous: there are methods to scan, and the verb list matches what
    # it is meant to match.
    assert len(methods) > 5
    assert "start" in _ACTING_VERBS and "bind" in _ACTING_VERBS


def test_the_module_holds_no_credential_shaped_field() -> None:
    """A decoy is reached by someone hostile. What they send is not ours to keep."""

    tree = ast.parse(pathlib.Path(decoy_module.__file__).read_text(encoding="utf-8"))
    fields = {
        node.target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }
    secrets = {
        name
        for name in fields
        if any(
            word in name
            for word in ("credential", "password", "secret", "token", "key_material", "payload")
        )
    }
    assert secrets == set(), f"the decoy runtime would hold {secrets}"


# -- the audit event -------------------------------------------------------


def test_the_event_field_avoids_the_retired_role_word() -> None:
    """`decoy_name`, not `decoy`.

    The bare word is a retired interface role here and
    `test_no_retired_role_word_survives_as_a_value` refuses it as a string
    value. This is the same exact-match rule that keeps `capture_spool` while
    refusing `capture`.
    """

    for event in (an_entry().as_event(), status().as_event()):
        assert "decoy" not in event
        assert event["decoy_name"] == "decoy-a"


def test_the_state_event_carries_provenance_and_no_content() -> None:
    reading = status(operator_exposed=True)
    event = reading.as_event()
    assert event["event_type"] == "deception.lite.state"
    assert event["state"] == "exposed"
    assert event["generation_digest"] == GENERATION
    assert event["redirect_eligible"] is False


def test_the_entry_event_names_the_binding_and_the_image_digest() -> None:
    event = an_entry().as_event()
    assert event == {
        "decoy_name": "decoy-a",
        "image_digest": IMAGE,
        "listen_address": ADDRESS,
        "port": 8080,
    }


def test_the_four_states_have_four_distinct_reasons() -> None:
    reasons = {
        DecoyState.DISABLED: status(catalogue=None).reason,
        DecoyState.ELIGIBLE: status().reason,
        DecoyState.EXPOSED: status(operator_exposed=True).reason,
        DecoyState.QUARANTINED: status(quarantine_reason="failed").reason,
    }
    assert len(set(reasons.values())) == 4, reasons
    assert len({state.value for state in DecoyState}) == 4


# -- the commissioning record ----------------------------------------------


@pytest.mark.parametrize("field", ["record_digest", "generation_digest"])
def test_a_commissioning_without_a_digest_is_refused(field: str) -> None:
    with pytest.raises(ContentRefused):
        a_commissioning(**{field: "not-a-digest"})


def test_a_commissioning_without_an_actor_is_refused() -> None:
    with pytest.raises(DecoyRefused) as caught:
        a_commissioning(actor="   ")
    assert "who performed it" in str(caught.value)


@pytest.mark.parametrize("prefix", ["not-a-prefix", "198.51.100.10/24", ""])
def test_a_commissioning_without_a_real_prefix_is_refused(prefix: str) -> None:
    """`198.51.100.10/24` has host bits set: it names an address, not a network."""

    with pytest.raises(DecoyRefused) as caught:
        a_commissioning(bridge_prefix=prefix)
    assert "network prefix" in str(caught.value)


def test_the_status_is_serialisable_without_leaking_anything() -> None:
    event = status(operator_exposed=True).as_event()
    text = json.dumps(event)
    assert "operator@node" not in text
    assert IMAGE not in text
