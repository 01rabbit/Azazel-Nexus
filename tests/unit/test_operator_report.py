"""The four things an operator display may never say (#29).

Each of the prohibitions in issue #29 is tested here as an *unrepresentable
state* rather than as a string that must not appear. A display test that
searches rendered text for a forbidden word passes the moment the word is
spelled differently; a constructor that refuses to hold the claim does not.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from azazel_nexus.capability import CORE_CAPABILITIES
from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole
from azazel_nexus.inventory import read_interfaces
from azazel_nexus.operator import (
    CapabilityReport,
    HealthReport,
    InterfacePresentation,
    ModuleReport,
    ModuleState,
    NextAction,
    OperatorReport,
    ProfileReport,
    ReportRefused,
    build_report,
)
from azazel_nexus.resource_profile import ResourceProfile, ResourceReading
from azazel_nexus.status import (
    EvidenceKind,
    StatusClaim,
    SubjectScope,
    VerificationState,
)

NOW = "2026-09-20T00:00:00Z"
KERNEL_NAME = "enp4s0"
MAC = "aa:bb:cc:dd:ee:ff"


def _tree(tmp_path: Path, name: str = KERNEL_NAME) -> Path:
    root = tmp_path / "sys"
    bus = root / "devices" / "pci0000:00" / "0000:04:00.0"
    bus.mkdir(parents=True)
    (bus / "vendor").write_text("0x8086\n")
    (bus / "device").write_text("0x15b7\n")
    (bus / "label").write_text("LAN1\n")
    net = root / "class" / "net"
    interface = net / name
    interface.mkdir(parents=True)
    (interface / "device").symlink_to("../../../devices/pci0000:00/0000:04:00.0")
    return net


def _readouts(tmp_path: Path, name: str = KERNEL_NAME):
    return read_interfaces(_tree(tmp_path, name), permanent_mac_reader=lambda n: MAC)


def _core_capabilities() -> CapabilityReport:
    return CapabilityReport(available=frozenset(CORE_CAPABILITIES))


def _profile() -> ProfileReport:
    return ProfileReport(
        reading=ResourceReading(usable_mib=16095, profile=ResourceProfile.LITE)
    )


def _record(*, roles=(), profiles=("hardware", "resource", "topology")):
    return CommissioningRecord(
        roles=tuple(roles), profiles_present=tuple(profiles), created_at=NOW
    )


def _role_for(readout, role="observation"):
    return ConfirmedRole(
        composite=tuple(sorted(readout.fields.items())),
        role=role,
        confirmed_by="operator@console",
        confirmed_at=NOW,
    )


def _report(tmp_path, **kwargs):
    # `kwargs.pop(key, default)` evaluates the default eagerly, so building
    # the sysfs tree there would build it even when the caller supplied its
    # own readouts -- and the second build raises FileExistsError.
    if "readouts" not in kwargs:
        kwargs["readouts"] = _readouts(tmp_path)
    kwargs.setdefault("profile", _profile())
    kwargs.setdefault("capabilities", _core_capabilities())
    return build_report(**kwargs)


# -- enforcement-ready is not a field -----------------------------------


def test_enforcement_ready_is_not_a_field_anything_can_set():
    """There is nothing to set, so there is nothing to set wrongly.

    A boolean carried on the report would be correct at the moment it was
    computed and a claim about the past at the moment it was read.
    """

    names = {f.name for f in dataclasses.fields(OperatorReport)}
    assert "enforcement_ready" not in names


def test_a_node_with_every_profile_and_no_role_is_not_enforcement_ready(tmp_path):
    report = _report(tmp_path, record=_record())
    assert report.enforcement_ready is False


def test_a_node_with_a_role_and_a_missing_profile_is_not_enforcement_ready(tmp_path):
    readouts = _readouts(tmp_path)
    report = _report(
        tmp_path,
        readouts=readouts,
        record=_record(
            roles=(_role_for(readouts[0]),), profiles=("hardware", "resource")
        ),
    )
    assert report.enforcement_ready is False
    assert any("topology" in a.summary for a in report.next_actions)


def test_a_node_with_no_record_at_all_is_not_enforcement_ready(tmp_path):
    report = _report(tmp_path, record=None)
    assert report.enforcement_ready is False
    assert any("No operator has confirmed" in a.summary for a in report.next_actions)


def test_both_halves_make_it_enforcement_ready(tmp_path):
    readouts = _readouts(tmp_path)
    report = _report(
        tmp_path, readouts=readouts, record=_record(roles=(_role_for(readouts[0]),))
    )
    assert report.enforcement_ready is True


# -- a module that was not reached --------------------------------------


def test_a_module_state_is_an_enum_rather_than_a_sentence():
    """There is no free text in which unreachable could be phrased as fine."""

    with pytest.raises(ReportRefused):
        ModuleReport(name="AZ-04", state=ModuleState.ABSENT)
    with pytest.raises(ReportRefused):
        ModuleReport(name="AZ-04", state=ModuleState.UNREACHABLE, reason="  ")


def test_absent_and_unreachable_are_not_the_same_answer():
    """They call for different operator actions.

    "Not configured" and "configured and not reached" collapse into one word
    only if nobody has to act on the difference.
    """

    assert ModuleState.ABSENT is not ModuleState.UNREACHABLE
    for state in (ModuleState.ABSENT, ModuleState.UNREACHABLE, ModuleState.UNVERIFIED):
        assert not ModuleReport("AZ-04", state, reason="because").working


def test_attestation_needs_evidence_behind_it():
    with pytest.raises(ReportRefused):
        ModuleReport(name="AZ-04", state=ModuleState.ATTESTED)


def test_a_module_in_another_product_is_never_verified_from_here():
    """Nexus#23's discipline, applied to the display.

    An observation is not re-derivable here, however carefully it was made.
    """

    verified = StatusClaim(
        subject="azazel-nexus",
        subject_scope=SubjectScope.THIS_REPOSITORY,
        statement="this package is installed",
        verification_state=VerificationState.VERIFIED,
        evidence_kind=EvidenceKind.LOCAL_MANIFEST,
        source_ref="pyproject.toml",
    )
    with pytest.raises(ReportRefused):
        ModuleReport(name="AZ-04", state=ModuleState.ATTESTED, claim=verified)


# -- an uncommissioned interface ----------------------------------------


def test_an_interface_with_no_confirmed_role_is_not_configured(tmp_path):
    report = _report(tmp_path, record=_record())
    assert report.unconfigured == report.interfaces
    assert all(not i.configured for i in report.interfaces)


def test_a_confirmed_role_is_matched_by_composite_identity(tmp_path):
    """Matched the way `confirm_roles` stores it, unfiltered.

    A presentation that dropped the empty identity fields would compute a
    composite no record contains, and every commissioned interface would
    render as unconfigured -- a display that under-claims, but still a
    display that is wrong about what the operator did.
    """

    readouts = _readouts(tmp_path)
    report = _report(
        tmp_path, readouts=readouts, record=_record(roles=(_role_for(readouts[0]),))
    )
    assert report.interfaces[0].configured
    assert report.interfaces[0].role == "observation"
    assert report.unconfigured == ()


def test_an_interface_that_cannot_be_commissioned_must_say_what_is_missing():
    with pytest.raises(ReportRefused):
        InterfacePresentation(
            handle="if-1",
            description={"physical_label": "LAN1"},
            commissionable=False,
        )


def test_a_row_with_nothing_checkable_is_refused():
    """A row an operator cannot identify invites a meaningless confirmation."""

    with pytest.raises(ReportRefused):
        InterfacePresentation(handle="if-1", description={}, commissionable=True)


def test_the_kernel_name_never_reaches_the_operator(tmp_path):
    report = _report(tmp_path)
    for interface in report.interfaces:
        shown = [interface.handle, *interface.description.values()]
        assert KERNEL_NAME not in shown


def test_a_kernel_name_that_slipped_into_a_shown_field_is_refused(tmp_path):
    """The check is against what would be displayed, not against the filter.

    `describe_for_operator` excludes the kernel name today. This is what
    notices if a field is ever added that carries it along.
    """

    from azazel_nexus.operator import _refuse_kernel_name

    presentation = InterfacePresentation(
        handle="if-1", description={"physical_label": KERNEL_NAME}, commissionable=True
    )
    with pytest.raises(ReportRefused):
        _refuse_kernel_name(presentation, KERNEL_NAME)


# -- degradation --------------------------------------------------------


def test_a_report_can_never_list_losses_with_nothing_continuing():
    """Issue #29: show what continues, not only what was lost.

    The guarantee is structural and it comes from the core-capability refusal,
    not from a check of its own. `retained` is empty only when `available` is,
    and an available set missing the core capabilities is refused as a broken
    node rather than a degraded one.

    This test asserts the *reason*, because a version of it that only asserted
    `ReportRefused` passed against a redundant branch that never executed --
    and would have gone on passing with that branch deleted.
    """

    with pytest.raises(ReportRefused) as refusal:
        CapabilityReport(available=frozenset(), lost=("remote_cognition",))
    assert "core capabilities are absent" in str(refusal.value)

    degraded = CapabilityReport(
        available=frozenset(CORE_CAPABILITIES), lost=("remote_cognition",)
    )
    assert degraded.retained, (
        "every constructible report has something continuing to show"
    )


def test_a_missing_core_capability_is_not_degradation_to_display():
    """It is a broken node, and the report refuses to dress it as narrowing."""

    with pytest.raises(ReportRefused):
        CapabilityReport(available=frozenset(CORE_CAPABILITIES) - {"audit"})


def test_a_core_node_with_every_optional_component_lost_still_reports_what_it_has():
    report = CapabilityReport(
        available=frozenset(CORE_CAPABILITIES),
        lost=("remote_cognition", "knowledge_lite"),
    )
    assert set(report.retained) == CORE_CAPABILITIES
    assert report.state.value == "CORE"


# -- everything else a report owes --------------------------------------


def test_a_profile_that_was_not_measured_must_say_why():
    with pytest.raises(ReportRefused):
        ProfileReport()
    assert ProfileReport(reason="/proc/meminfo was unreadable").profile is None


def test_a_health_check_cannot_be_a_bare_green():
    with pytest.raises(ReportRefused):
        HealthReport(subject="audit chain", healthy=True, detail="  ")


def test_an_unestablished_health_check_is_unknown_not_healthy():
    check = HealthReport("systemd units", None, "no service manager was consulted")
    assert check.unknown
    assert check.healthy is not False and check.healthy is not True


def test_a_failed_health_check_becomes_a_next_action(tmp_path):
    readouts = _readouts(tmp_path)
    report = _report(
        tmp_path,
        readouts=readouts,
        record=_record(roles=(_role_for(readouts[0]),)),
        health=(HealthReport("audit chain", False, "link 3 does not hold"),),
    )
    assert any("link 3 does not hold" in a.summary for a in report.next_actions)


def test_a_next_action_must_say_what_to_do():
    with pytest.raises(ReportRefused):
        NextAction("   ")


def test_a_host_with_no_interfaces_reports_no_interfaces(tmp_path):
    report = _report(tmp_path, readouts=())
    assert report.interfaces == ()
