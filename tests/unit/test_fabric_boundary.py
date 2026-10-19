"""The Fabric boundary, and the three things it must not be able to do.

Adopting an exact Fabric pin is the last open row of Phase 0. What makes the
adoption worth anything is not that a projection can be built -- it is that the
projection is structurally incapable of raising a capability, issuing an
enforcement intent, or publishing a capability state as an operating mode.

Those are stated in the module's own docstring and in
`docs/contract-ownership.md` §1. A property that lives only in prose is one
review away from being gone.
"""

from __future__ import annotations

import builtins
import re
from pathlib import Path

import pytest

from azazel_nexus.capability import (
    CORE_CAPABILITIES,
    CapabilityState,
    OptionalComponent,
    degrade,
    state_for,
)
from azazel_nexus.fabric_boundary import (
    FABRIC_PIN,
    PLANNED_FABRIC_MODULES,
    REQUIRED_FABRIC_MODULES,
    Projection,
    project_capability,
)

ROOT = Path(__file__).resolve().parents[2]

fabric = pytest.importorskip(
    "azazel_fabric",
    reason="the Fabric extra is optional; CORE must work without it",
)


# --------------------------------------------------------------------------
# The pin
# --------------------------------------------------------------------------


def test_the_module_pin_and_the_manifest_pin_are_the_same_tag():
    """Two statements of one value drift; this is what stops them.

    The module names the tag it is written against and `pyproject.toml` names
    the tag pip installs. A reader trusts the former and a machine obeys the
    latter, so they disagreeing is worse than either being wrong alone.
    """

    declared = re.findall(
        r'"azazel-fabric\s*@\s*git\+[^"@]+@(?P<tag>[^"]+)"',
        (ROOT / "pyproject.toml").read_text("utf-8"),
    )
    assert declared == [FABRIC_PIN], (
        f"pyproject.toml pins {declared} and fabric_boundary.py names "
        f"{FABRIC_PIN!r}"
    )


def test_the_pin_is_an_exact_tag_not_a_branch_or_a_commit():
    """A branch is not a release and cannot be depended on."""

    assert re.fullmatch(r"v\d+\.\d+\.\d+(?:rc\d+|a\d+|b\d+)?", FABRIC_PIN), FABRIC_PIN


def test_the_installed_fabric_is_the_pinned_one():
    """A local install that has drifted off the pin proves nothing about it."""

    assert fabric.__version__ == FABRIC_PIN.lstrip("v"), (
        f"installed azazel_fabric is {fabric.__version__}, the pin is {FABRIC_PIN}"
    )


# --------------------------------------------------------------------------
# Fabric's absence is a bounded condition, not a crash
# --------------------------------------------------------------------------


def test_a_missing_fabric_yields_an_unavailable_projection_and_no_exception(
    monkeypatch,
):
    real_import = builtins.__import__

    def refuse_fabric(name, *args, **kwargs):
        if name == "azazel_fabric" or name.startswith("azazel_fabric."):
            raise ImportError("simulated: azazel_fabric is not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse_fabric)

    projection = project_capability(CapabilityState.CORE, CORE_CAPABILITIES)

    assert isinstance(projection, Projection)
    assert projection.available is False
    assert "not installed" in projection.reason
    assert projection.view is None


def test_an_unavailable_projection_always_says_why():
    """An unavailable projection with no reason is indistinguishable from a bug."""

    projection = project_capability(CapabilityState.CORE, CORE_CAPABILITIES)
    assert projection.available is (projection.reason == "")


# --------------------------------------------------------------------------
# The three things it must not be able to do
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", list(CapabilityState))
def test_the_projection_reports_the_capability_it_was_given_and_no_other(state):
    """A projection renders; it does not promote.

    Degradation is driven by the loss of an optional component. If a
    projection could return a state other than the one it was handed, the
    presentation layer would have become a second source of capability.
    """

    projection = project_capability(state, CORE_CAPABILITIES)

    assert projection.available is True
    assert projection.view.product_view["capability_state"] == state.value
    assert projection.view.product_view["capabilities"] == sorted(CORE_CAPABILITIES)


def test_a_degraded_node_does_not_come_back_richer_through_the_projection():
    """End to end, through the rule that produces the degraded set."""

    available = degrade(
        frozenset(CORE_CAPABILITIES) | {"knowledge_lite", "local_model"},
        OptionalComponent.KNOWLEDGE_LITE,
    )
    state = state_for(available)

    projection = project_capability(state, available)

    assert set(projection.view.product_view["capabilities"]) == set(available)
    assert "knowledge_lite" not in projection.view.product_view["capabilities"]


def test_the_projection_issues_no_enforcement_intent():
    """`StatusView.current_action` carries an arbiter's enforcement intent.

    Nexus integrates released components without creating another decision
    authority, so this field stays empty in every capability state. It is the
    one field on this view that could make a Nexus record read as a decision.
    """

    for state in CapabilityState:
        projection = project_capability(state, CORE_CAPABILITIES)
        assert projection.view.current_action is None
        assert projection.view.next_actions == []


@pytest.mark.parametrize("state", list(CapabilityState))
def test_a_capability_state_is_never_published_as_an_operating_mode(state):
    """The collapse Nexus#OF-04 already had to correct once.

    `ModeState.name` is the series' operating-mode vocabulary and those modes
    are Azazel-Edge's. `CORE` / `LITE` / `FULL` answer a different question
    with a different owner. A value from one appearing in the other's field is
    how two namespaces merge.
    """

    projection = project_capability(state, CORE_CAPABILITIES)
    mode_json = projection.view.mode.model_dump_json()

    assert state.value not in mode_json, (
        f"the capability state {state.value!r} reached the operating-mode "
        f"record: {mode_json}"
    )


def test_the_projection_states_that_nexus_holds_no_authority():
    """Said out loud in the record, not left to be inferred from an empty list."""

    product_view = project_capability(
        CapabilityState.FULL, CORE_CAPABILITIES
    ).view.product_view

    assert product_view["authority"] == []
    assert "no decision or enforcement authority" in product_view["authority_note"]


# --------------------------------------------------------------------------
# Determinism and the presence probe
# --------------------------------------------------------------------------


def test_the_projection_reads_no_clock():
    """Two runs must be byte-identical, or nothing can be compared across them."""

    first = project_capability(CapabilityState.CORE, CORE_CAPABILITIES)
    second = project_capability(CapabilityState.CORE, CORE_CAPABILITIES)

    assert first.view.model_dump_json() == second.view.model_dump_json()
    assert "1970-01-01T00:00:00Z" in first.view.model_dump_json()


def test_every_required_module_is_present_at_the_pin():
    import importlib.util

    missing = [
        name for name in REQUIRED_FABRIC_MODULES if importlib.util.find_spec(name) is None
    ]
    assert missing == [], f"the pin does not provide {missing}"


def test_the_presence_probe_reports_rather_than_assumes():
    """A probe is not adoption, and its result is a report either way.

    The remaining planned families exist at this pin. Presence alone does
    not attest a mapping; provisioning already has commissioning consumers.
    """

    projection = project_capability(CapabilityState.CORE, CORE_CAPABILITIES)

    assert projection.available is True
    assert projection.missing_planned == (), (
        f"mapped families absent at {FABRIC_PIN}: {projection.missing_planned}"
    )
    assert "azazel_fabric.mio_contracts" in PLANNED_FABRIC_MODULES
    assert "azazel_fabric.provisioning_contracts" not in PLANNED_FABRIC_MODULES
