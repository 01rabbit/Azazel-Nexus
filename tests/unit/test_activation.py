"""The activation controller, checked as a privilege boundary (#28).

Two halves, and they are not the same claim.

The *design* boundary is provable here: no component other than the controller
can reach the widening verb, because the token is unmintable outside this
module and nothing else in the package references either. That is what these
tests establish.

The *enforcement* boundary -- that a daemon running under `azobs` on a real
host cannot `systemctl unmask` -- is the operating system's, and no test in
this repository executes it. It is `HG-02` in `docs/hardware-gates.md`.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from azazel_nexus.activation import (
    ACTIVATION_CONTROLLER_UNIT,
    ActivationLease,
    EdgeBaselineState,
    CORE_UNITS,
    ActivationAuthorization,
    ActivationController,
    ActivationRefused,
    RecordingUnitController,
    SystemdUnitController,
    UnitController,
    UnitDefinition,
    UnitState,
    UnitTier,
    Watchdog,
)
from azazel_nexus.audit import AuditLedger, AuditUnavailable
from azazel_nexus.commissioning import CommissioningRecord, ConfirmedRole
from azazel_nexus.generation import GenerationStore

PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / "azazel_nexus"

NOW = "2026-09-20T00:00:00Z"
ACTOR = "operator@console"


def _lease(digest: str = "sha256:" + "0" * 64) -> ActivationLease:
    """A lease covering `NOW`. Every activation needs one (#39)."""

    return ActivationLease(
        granted_by=ACTOR,
        granted_at="2026-09-19T00:00:00Z",
        expires_at="2026-09-21T00:00:00Z",
        generation_digest=digest,
    )

ENFORCING = UnitDefinition(
    "azazel-enforced.service",
    UnitTier.ENFORCEMENT,
    "azenforce",
    "applies one approved intent and emits a receipt",
)


def _record(*, roles=(), profiles=("hardware", "resource", "topology")):
    return CommissioningRecord(
        roles=tuple(roles), profiles_present=tuple(profiles), created_at=NOW
    )


def _confirmed_role():
    return ConfirmedRole(
        composite=(("mac", "00:11:22:33:44:55"), ("path", "pci-0000:01:00.0")),
        role="observation",
        confirmed_by=ACTOR,
        confirmed_at=NOW,
    )


def _store_with_generation(tmp_path: Path, contents=b"role: observation\n"):
    store = GenerationStore(tmp_path / "generations")
    store.create(
        {"suricata.yaml": contents},
        created_at=NOW,
        commissioning_digest="sha256:" + "0" * 64,
    )
    return store


def _controller(tmp_path: Path, definitions=CORE_UNITS, **kwargs):
    units = RecordingUnitController(d.name for d in definitions)
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    store = kwargs.pop("generations", None) or _store_with_generation(tmp_path)
    controller = ActivationController(
        units=units, generations=store, ledger=ledger, definitions=definitions
    )
    return controller, units, ledger, store


def _event_types(ledger: AuditLedger):
    return [entry.event["event_type"] for entry in ledger]


# -- the token ----------------------------------------------------------


def test_a_unit_is_not_unmasked_without_an_authorization():
    units = RecordingUnitController(["azazel-auditd.service"])
    with pytest.raises(ActivationRefused):
        units.unmask_and_enable("azazel-auditd.service", authorization=None)
    assert units.calls == []
    assert units.state("azazel-auditd.service") is UnitState.MASKED


def test_an_authorization_cannot_be_minted_outside_the_controller():
    """The refusal is at construction, not at use.

    A token that exists until something validates it is a token that gets
    passed around, logged and stored in between.
    """

    with pytest.raises(ActivationRefused):
        ActivationAuthorization(
            unit="azazel-auditd.service", generation=1, digest="sha256:" + "0" * 64
        )
    with pytest.raises(ActivationRefused):
        ActivationAuthorization(
            unit="azazel-auditd.service",
            generation=1,
            digest="sha256:" + "0" * 64,
            mint=object(),
        )


def test_an_authorization_is_not_transferable_between_units(tmp_path):
    """One grant, one unit. A real token, replayed elsewhere, is refused.

    Without this, the ledger entry for a granted unit would describe a
    widening that happened to a different unit.
    """

    captured: list[ActivationAuthorization] = []

    class Capturing(RecordingUnitController):
        def unmask_and_enable(self, unit, *, authorization):
            captured.append(authorization)
            return super().unmask_and_enable(unit, authorization=authorization)

    units = Capturing(d.name for d in CORE_UNITS)
    controller = ActivationController(
        units=units,
        generations=_store_with_generation(tmp_path),
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
    )
    controller.activate(now=NOW, actor=ACTOR, lease=_lease())
    assert captured, "nothing was granted, so nothing was captured to replay"

    token = captured[0]
    other = next(d.name for d in CORE_UNITS if d.name != token.unit)
    plain = RecordingUnitController([other])
    with pytest.raises(ActivationRefused):
        plain.unmask_and_enable(other, authorization=token)
    assert plain.calls == []


def test_no_unit_controller_subclass_overrides_the_guarded_entry_point():
    """The guard lives on the base class and stays there.

    A subclass that replaced `unmask_and_enable` would be granting itself the
    privilege the base class exists to withhold, and every other test here
    would still pass.
    """

    offenders = []
    pending = list(UnitController.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if cls.__module__ != "azazel_nexus.activation":
            continue
        if "unmask_and_enable" in cls.__dict__:
            offenders.append(cls.__name__)
    assert offenders == [], (
        f"{offenders} override the guarded entry point; the check that a token "
        "was minted by the activation controller is not a subclass's to relax"
    )


def test_no_other_module_in_the_package_reaches_the_widening_verb():
    """`activation.py` is the only file that may name the mint or the verb.

    This is the mechanical form of IMPLEMENTATION_SPEC 4: the operator UI, the
    commissioning daemon, the module manager and M.I.O. have no path to
    unmasking. A rule kept only in review is one review away from being gone.
    """

    forbidden = ("ActivationAuthorization", "unmask_and_enable", "_MINT")
    offenders = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if path.name == "activation.py":
            continue
        text = path.read_text(encoding="utf-8")
        hits = [name for name in forbidden if name in text]
        if hits:
            offenders[path.name] = hits
    assert offenders == {}, (
        f"{offenders} reach the widening path; only activation.py may, so that "
        "a component cannot grant itself privilege by importing a name"
    )


def test_within_activation_only_the_controller_mints():
    """Even inside the module, the mint is not scattered.

    The watchdog shares this file with the controller. If it could mint, the
    package-wide scan above would still be green and the boundary would be
    gone.
    """

    tree = ast.parse((PACKAGE_ROOT / "activation.py").read_text(encoding="utf-8"))
    minting_classes = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Name) and inner.id == "_MINT":
                minting_classes.add(node.name)
    assert minting_classes == {"ActivationAuthorization", "ActivationController"}, (
        f"{sorted(minting_classes)} reference the mint. Only the token (to "
        "refuse a forged one) and the controller (to issue a real one) may"
    )


# -- what activation requires -------------------------------------------


def test_the_controller_does_not_govern_itself():
    with pytest.raises(ActivationRefused):
        ActivationController(
            units=RecordingUnitController(),
            generations=GenerationStore(Path("/nonexistent")),
            ledger=AuditLedger(Path("/nonexistent/ledger")),
            definitions=CORE_UNITS
            + (
                UnitDefinition(
                    ACTIVATION_CONTROLLER_UNIT, UnitTier.SUPPORTING, "root", "itself"
                ),
            ),
        )


def test_a_repeated_unit_in_the_governed_set_is_refused():
    with pytest.raises(ActivationRefused):
        ActivationController(
            units=RecordingUnitController(),
            generations=GenerationStore(Path("/nonexistent")),
            ledger=AuditLedger(Path("/nonexistent/ledger")),
            definitions=CORE_UNITS + (CORE_UNITS[0],),
        )


def test_with_no_generation_nothing_is_unmasked(tmp_path):
    units = RecordingUnitController(d.name for d in CORE_UNITS)
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    controller = ActivationController(
        units=units,
        generations=GenerationStore(tmp_path / "generations"),
        ledger=ledger,
    )
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    assert outcome.granted == ()
    assert set(outcome.withheld) == {d.name for d in CORE_UNITS}
    assert all(call[0] == "mask" for call in units.calls)
    assert _event_types(ledger) == ["activation.refused"]


def test_a_generation_whose_tree_moved_does_not_pass_activation(tmp_path):
    controller, units, ledger, store = _controller(tmp_path)
    (store.root / "1" / "tree" / "suricata.yaml").write_bytes(b"role: enforcement\n")

    outcome = controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    assert outcome.granted == ()
    assert all(call[0] == "mask" for call in units.calls)
    reason = outcome.verdicts[0].reason
    assert reason.startswith("generation_unverified")


def test_the_digest_is_re_derived_on_every_activation(tmp_path):
    """Not cached from the boot that first verified it.

    A generation verified once and not since describes whatever its tree has
    become -- which is exactly the window an attacker with write access to the
    staging tree would use.
    """

    controller, units, _, store = _controller(tmp_path)
    first = controller.activate(now=NOW, actor=ACTOR, lease=_lease())
    assert set(first.granted) == {d.name for d in CORE_UNITS}

    (store.root / "1" / "tree" / "suricata.yaml").write_bytes(b"tampered\n")
    second = controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    assert second.granted == ()
    assert all(
        units.state(d.name) is UnitState.MASKED for d in CORE_UNITS
    ), "a re-derived digest that no longer matches must leave the node masked"


def test_an_operational_unit_is_withheld_with_no_commissioning_record(tmp_path):
    controller, units, _, _ = _controller(tmp_path, CORE_UNITS + (ENFORCING,))
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    assert ENFORCING.name in outcome.withheld
    assert set(outcome.granted) == {d.name for d in CORE_UNITS}
    verdict = next(v for v in outcome.verdicts if v.unit == ENFORCING.name)
    assert verdict.reason.startswith("commissioning_absent")


def test_an_operational_unit_is_withheld_while_a_profile_is_missing(tmp_path):
    controller, _, _, _ = _controller(tmp_path, CORE_UNITS + (ENFORCING,))
    outcome = controller.activate(
        now=NOW,
        actor=ACTOR,
        lease=_lease(),
        record=_record(roles=(_confirmed_role(),), profiles=("hardware", "resource")),
    )

    verdict = next(v for v in outcome.verdicts if v.unit == ENFORCING.name)
    assert not verdict.granted
    assert "topology" in verdict.reason, (
        "the reason must name which profile is missing; 'one is missing' "
        "leaves the operator to find out which"
    )


def test_an_operational_unit_is_withheld_while_the_node_is_observe_only(tmp_path):
    """A record with every profile and no confirmed role is not enforcement-ready.

    It is also not the same as having no record: somebody looked, and
    confirmed nothing. The reason distinguishes the two.
    """

    controller, _, _, _ = _controller(tmp_path, CORE_UNITS + (ENFORCING,))
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=_lease(), record=_record())

    verdict = next(v for v in outcome.verdicts if v.unit == ENFORCING.name)
    assert not verdict.granted
    assert verdict.reason.startswith("commissioning_observe_only")


def test_an_operational_unit_is_granted_once_commissioning_is_complete(tmp_path):
    controller, units, _, _ = _controller(tmp_path, CORE_UNITS + (ENFORCING,))
    outcome = controller.activate(
        now=NOW, actor=ACTOR, lease=_lease(), record=_record(roles=(_confirmed_role(),))
    )

    assert ENFORCING.name in outcome.granted
    assert units.state(ENFORCING.name) is UnitState.ENABLED


def test_a_bootstrap_unit_runs_before_anyone_has_commissioned_anything(tmp_path):
    """Otherwise there is no path from an installed node to a commissioned one.

    Requiring a commissioning record before the commissioning daemon may run
    would be a precondition that can only be satisfied by the thing it gates.
    """

    controller, _, _, _ = _controller(tmp_path)
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=_lease(), record=None)

    assert "azazel-commissiond.service" in outcome.granted


# -- what the ledger must contain ---------------------------------------


def test_a_grant_is_recorded_before_the_unit_is_widened(tmp_path):
    """The ordering is the fail-closed choice, and it is testable.

    Reversed, a crash between the two leaves a running service with no record
    that it was granted -- and nothing afterwards can discover it. This way a
    crash leaves a record of a grant that did not take effect, which the next
    boot's revalidation corrects.
    """

    order: list[str] = []
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = AuditLedger(ledger_path)
    real_append = ledger.append

    def logging_append(event, **kwargs):
        order.append("audit:" + event["event_type"])
        return real_append(event, **kwargs)

    ledger.append = logging_append  # type: ignore[assignment]

    class Logging(RecordingUnitController):
        def _unmask_and_enable(self, unit):
            order.append("unmask:" + unit)
            super()._unmask_and_enable(unit)

    units = Logging(d.name for d in CORE_UNITS)
    controller = ActivationController(
        units=units, generations=_store_with_generation(tmp_path), ledger=ledger
    )
    controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    expected = []
    for definition in CORE_UNITS:
        expected.append("audit:activation.unit_granted")
        expected.append("unmask:" + definition.name)
    assert order == expected, (
        "each unit's ledger entry must precede its own widening, not merely "
        "precede the last of them"
    )


def test_an_activation_that_cannot_be_recorded_does_not_happen(tmp_path):
    """Fail-closed: an unrecordable widening is not performed.

    The alternative is a node that is running services the ledger cannot
    account for, which is the state the ledger exists to make impossible.
    """

    units = RecordingUnitController(d.name for d in CORE_UNITS)
    ledger = AuditLedger(tmp_path / "ledger.jsonl")

    def refuse(event, **kwargs):
        raise AuditUnavailable("the ledger volume is read-only")

    ledger.append = refuse  # type: ignore[assignment]
    controller = ActivationController(
        units=units, generations=_store_with_generation(tmp_path), ledger=ledger
    )

    with pytest.raises(AuditUnavailable):
        controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    assert [c[0] for c in units.calls] == ["mask"] * len(CORE_UNITS)
    assert all(units.state(d.name) is UnitState.MASKED for d in CORE_UNITS)


def test_a_unit_that_fails_to_widen_is_masked_again_and_recorded(tmp_path):
    """The failure is modelled as a *partial* one, and that is the whole point.

    `systemctl unmask` succeeding and `systemctl enable` failing leaves the
    unit unmasked. A test whose failure raised before anything changed would
    find the unit masked because it was never unmasked -- and would pass with
    the re-mask deleted. So the double here unmasks first, then fails.
    """

    FAILING = "azazel-watchdog.service"

    class Failing(RecordingUnitController):
        def _unmask_and_enable(self, unit):
            if unit == FAILING:
                # The half that succeeded, before the half that did not.
                self._states[unit] = UnitState.ENABLED
                self.calls.append(("unmask_and_enable", unit))
                raise OSError("systemctl enable exited 1")
            super()._unmask_and_enable(unit)

    units = Failing(d.name for d in CORE_UNITS)
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    controller = ActivationController(
        units=units, generations=_store_with_generation(tmp_path), ledger=ledger
    )
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    assert FAILING in outcome.withheld
    assert units.state(FAILING) is UnitState.MASKED, (
        "a unit left half-widened by a failed activation must be narrowed "
        "again, not left in whatever state the failure stopped at"
    )
    # The last thing done *to this unit*, not the last thing done at all:
    # the pass continues with the units after it, and a later unit's call
    # being last says nothing about this one. Narrowing it to the unit keeps
    # what the assertion was for -- that the mask follows the failed attempt
    # rather than preceding it.
    for_unit = [call for call in units.calls if call[1] == FAILING]
    assert for_unit[-1] == ("mask", FAILING), (
        "the re-mask must be the last thing done to the unit; a mask recorded "
        "before the failed attempt would be the installer's, not this one's"
    )
    assert ("unmask_and_enable", FAILING) in for_unit, (
        "a vacuous check: the unit was never attempted, so the mask below is "
        "not a re-mask"
    )
    assert "activation.unit_failed" in _event_types(ledger)


def test_the_activation_events_extend_one_unbroken_chain(tmp_path):
    controller, _, ledger, _ = _controller(tmp_path)
    controller.activate(now=NOW, actor=ACTOR, lease=_lease())
    controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    ledger.verify()
    assert len(list(ledger)) == 2 * len(CORE_UNITS)


def test_a_refusal_names_the_generation_it_refused(tmp_path):
    controller, _, ledger, store = _controller(tmp_path)
    (store.root / "1" / "tree" / "suricata.yaml").write_bytes(b"tampered\n")
    controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    refusal = next(e for e in ledger if e.event["event_type"] == "activation.refused")
    assert refusal.event["generation"] == 1
    assert "generation_unverified" in refusal.event["reason"]


# -- the watchdog -------------------------------------------------------


def test_the_watchdog_will_not_restart_a_unit_activation_withheld(tmp_path):
    """"Recovering" a unit that was never granted is a widening.

    This is IMPLEMENTATION_SPEC 4's "never restarts into a broader authority
    state", stated as a refusal the watchdog cannot talk its way past.
    """

    units = RecordingUnitController(d.name for d in CORE_UNITS)
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    watchdog = Watchdog(
        units=units, ledger=ledger, granted=["azazel-auditd.service"]
    )

    with pytest.raises(ActivationRefused):
        watchdog.restart(
            "azazel-enforced.service",
            reason="health check failed",
            now=NOW,
            perform=lambda: None,
        )
    assert list(ledger) == []


def test_the_watchdog_does_not_return_a_unit_it_fenced(tmp_path):
    units = RecordingUnitController(["azazel-auditd.service"])
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    watchdog = Watchdog(units=units, ledger=ledger, granted=["azazel-auditd.service"])

    watchdog.fence("azazel-auditd.service", reason="ledger volume lost", now=NOW)
    with pytest.raises(ActivationRefused):
        watchdog.restart(
            "azazel-auditd.service", reason="retry", now=NOW, perform=lambda: None
        )
    assert _event_types(ledger) == ["watchdog.fenced"]


def test_a_fence_is_recorded_and_masks(tmp_path):
    units = RecordingUnitController(["azazel-auditd.service"])
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    watchdog = Watchdog(units=units, ledger=ledger, granted=["azazel-auditd.service"])

    watchdog.fence("azazel-auditd.service", reason="ledger volume lost", now=NOW)

    assert units.state("azazel-auditd.service") is UnitState.MASKED
    assert _event_types(ledger) == ["watchdog.fenced"]


def test_an_interrupted_restart_is_fenced_and_recorded(tmp_path):
    """A restart that did not complete leaves a record and a narrower node.

    The failure mode this refuses is a unit left half-restarted with the
    watchdog's opinion that it is fine.
    """

    units = RecordingUnitController(["azazel-auditd.service"])
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    watchdog = Watchdog(units=units, ledger=ledger, granted=["azazel-auditd.service"])

    def interrupted():
        raise KeyboardInterrupt("the host was rebooted mid-restart")

    with pytest.raises(KeyboardInterrupt):
        watchdog.restart(
            "azazel-auditd.service", reason="health check failed", now=NOW,
            perform=interrupted,
        )

    assert units.state("azazel-auditd.service") is UnitState.MASKED
    assert _event_types(ledger) == ["watchdog.restart_interrupted"]
    assert "azazel-auditd.service" in watchdog.fenced


def test_a_completed_restart_is_recorded(tmp_path):
    units = RecordingUnitController(["azazel-auditd.service"])
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    watchdog = Watchdog(units=units, ledger=ledger, granted=["azazel-auditd.service"])

    watchdog.restart(
        "azazel-auditd.service", reason="health check failed", now=NOW,
        perform=lambda: None,
    )

    assert _event_types(ledger) == ["watchdog.restarted"]


def test_masking_records_why(tmp_path):
    units = RecordingUnitController(["azazel-auditd.service"])
    with pytest.raises(ActivationRefused):
        units.mask("azazel-auditd.service", reason="   ")


# -- the systemd port ---------------------------------------------------


def test_the_systemd_controller_has_no_runner_of_its_own():
    """No default runner, so the package still spawns no process.

    A `subprocess` default would be the first operational surface in a package
    that has commissioned no interface, and it would arrive as a convenience.
    `test_boundary_static.py` refuses the import; this refuses the shape that
    would have wanted it.
    """

    with pytest.raises(TypeError):
        SystemdUnitController()  # type: ignore[call-arg]
    with pytest.raises(ActivationRefused):
        SystemdUnitController(run=None)  # type: ignore[arg-type]


def test_the_systemd_controller_runs_nothing_for_an_unauthorized_unmask():
    """The refusal precedes the subprocess, not the other way round."""

    calls = []
    controller = SystemdUnitController(run=lambda argv: calls.append(argv))
    with pytest.raises(ActivationRefused):
        controller.unmask_and_enable("azazel-auditd.service", authorization=None)
    assert calls == []


def test_the_systemd_controller_masks_with_now(tmp_path):
    """`mask` without `--now` leaves a running service running.

    A node that masked a unit and left it serving has narrowed its next boot
    and nothing else.
    """

    calls = []
    controller = SystemdUnitController(run=lambda argv: calls.append(argv))
    controller.mask("azazel-auditd.service", reason="digest mismatch")
    assert calls == [["systemctl", "mask", "--now", "azazel-auditd.service"]]


# -- narrowing must not raise out of a pass ------------------------------


def test_a_unit_that_will_not_mask_does_not_end_the_pass(tmp_path):
    """Found by a runtime test, and the failure was in this layer.

    A `mask` that raised propagated out of `activate` entirely: no outcome was
    returned, the remaining units were never decided, and **the units this
    pass had already widened stayed widened** with nothing left running to
    take them back. An exception on the narrowing path was behaving as a
    widening.
    """

    class WontMask(RecordingUnitController):
        def _mask(self, unit):
            raise OSError(f"{unit} will not mask")

    units = WontMask(d.name for d in CORE_UNITS)
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    controller = ActivationController(
        units=units,
        generations=GenerationStore(tmp_path / "empty"),
        ledger=ledger,
    )
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=_lease())

    assert outcome.granted == (), "nothing may be granted when nothing can be masked"
    assert controller.unmaskable == {d.name for d in CORE_UNITS}
    assert "activation.unit_would_not_mask" in _event_types(ledger)


def test_every_unit_is_still_decided_when_one_will_not_mask(tmp_path):
    """The pass continues withholding rather than stopping at the first refusal."""

    class WontMaskOne(RecordingUnitController):
        def _mask(self, unit):
            if unit == "azazel-commissiond.service":
                raise OSError("stuck")
            super()._mask(unit)

    units = WontMaskOne(d.name for d in CORE_UNITS)
    controller = ActivationController(
        units=units,
        generations=GenerationStore(tmp_path / "empty"),
        ledger=AuditLedger(tmp_path / "ledger.jsonl"),
    )
    outcome = controller.activate(now=NOW, actor=ACTOR, lease=_lease())
    assert len(outcome.verdicts) == len(CORE_UNITS)
    assert controller.unmaskable == {"azazel-commissiond.service"}
