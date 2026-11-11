"""A1 (#395 preparation): `azazel-knowledge-contextd.service` is grantable.

It is granted, withheld and contained by the same pass as every other
SUPPORTING unit. The pass has no StopUnit authority
(`activated._mask_and_confirm_inactive`), so a revocation, lease loss or
failed health/evidence closes the next start (marker removed, unit masked) and
a still-running broker is reported as a containment failure; the operator's
`systemctl stop` or a reboot then lets the next pass confirm it inactive.
"""

from __future__ import annotations

import pytest

from azazel_nexus.activation import (
    CORE_UNITS,
    KNOWLEDGE_CONTEXT_TRANSPORT,
    ActivationController,
    ActivationLease,
    UnitState,
)
from azazel_nexus.activation_policy import (
    ACTIVATION_UNIT_ALLOWLIST,
    ApprovalRefused,
)
from azazel_nexus_runtime import activated, activation_markers
from azazel_nexus_runtime.units import RecordingUnitManager

from test_runtime_activation_pass import (  # noqa: F401 - fixtures
    NOW,
    SCOPE,
    World,
    make_policy,
    world,
)

CTX = "azazel-knowledge-contextd.service"
CTX_SCOPE = tuple(sorted(SCOPE + (CTX,)))


class _RunningContext(RecordingUnitManager):
    """contextd keeps running after it is masked (nothing here can stop it)."""

    running = True

    def is_inactive(self, unit):
        if unit == CTX and self.running:
            return False
        return super().is_inactive(unit)


@pytest.fixture
def ctx_world(tmp_path, monkeypatch):
    from test_runtime_activation_pass import _owned_by_the_test
    monkeypatch.setattr(activation_markers, "_OWNER", __import__("os").getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    _owned_by_the_test(monkeypatch)
    return World(tmp_path, units=CTX_SCOPE)


def _make_running(w):
    m = _RunningContext(d.name for d in CORE_UNITS)
    for d in CORE_UNITS:
        m.unmask_and_enable(d.name)
    m.calls.clear()
    w.manager = m
    return m


def _closed(w):
    assert w.markers() is None or CTX not in w.markers()
    assert w.manager.state(CTX) is UnitState.MASKED


def test_a_policy_naming_contextd_is_accepted_and_others_stay_refused():
    assert CTX in ACTIVATION_UNIT_ALLOWLIST
    assert CTX in make_policy(units=CTX_SCOPE).units
    for unit in ("azazel-mio-locald.service", "azazel-mio-remoted.service",
                 "azazel-model-fetchd.service"):
        with pytest.raises(ApprovalRefused):
            make_policy(units=CTX_SCOPE + (unit,))


def test_contextd_is_granted_and_marked_with_the_rest_of_the_policy(ctx_world):
    outcome = ctx_world.run()
    assert sorted(outcome.granted) == list(CTX_SCOPE)
    assert ctx_world.manager.state(CTX) is UnitState.ENABLED
    assert CTX in ctx_world.markers()


def test_a_generation_with_contextd_measures_its_unit_file(ctx_world):
    # The generation was built from the policy units (World), and the pass
    # measured the contextd unit file against it without refusing.
    assert CTX in ctx_world.policy.units
    outcome = ctx_world.run()
    assert CTX in outcome.granted
    import json
    tree = ctx_world.store.read_tree(ctx_world.generation.number)
    assert CTX in json.loads(tree["baseline.json"])["unit_files"]


def test_contextd_is_not_granted_for_a_changed_unit_file(ctx_world):
    ctx_world.unit_files[CTX] = b"[Unit]\nDescription=tampered\n"
    outcome = ctx_world.run()
    assert outcome.granted == ()
    _closed(ctx_world)


def test_contextd_lease_scope_follows_the_signed_units(ctx_world):
    # Approval (lease) without contextd although the policy allows it.
    ctx_world.sign(units=SCOPE)
    outcome = ctx_world.run()
    assert CTX not in outcome.granted
    _closed(ctx_world)


def test_bundle_state_is_not_a_grant_input(ctx_world, tmp_path):
    # No Knowledge Context bundle exists anywhere in this root, and the unit
    # is granted anyway; adding an unreadable one changes nothing either.
    first = ctx_world.run()
    assert CTX in first.granted
    bundle = ctx_world.root / "etc/azazel/knowledge-context"
    bundle.mkdir(parents=True)
    (bundle / "bundle.json").write_bytes(b"\xff not a bundle")
    second = ctx_world.run()
    assert sorted(second.granted) == sorted(first.granted)


def test_core_definition_has_no_wiring_and_wired_set_is_unchanged():
    definition = next(d for d in CORE_UNITS if d.name == CTX)
    assert definition.wiring is None
    assert KNOWLEDGE_CONTEXT_TRANSPORT not in activated.wired_capabilities()


def test_library_grants_contextd_inside_the_lease_and_not_outside(tmp_path):
    from test_activation import ACTOR, _controller, _lease
    controller, units, _, store = _controller(tmp_path)
    digest = store.current().digest
    lease = ActivationLease(
        granted_by=ACTOR, granted_at="2026-09-19T00:00:00Z",
        expires_at="2026-09-21T00:00:00Z", generation_digest=digest,
        units=frozenset({CTX}))
    from test_activation import NOW as LNOW
    inside = controller.activate(now=LNOW, actor=ACTOR, lease=lease, wired=[])
    assert CTX in inside.granted
    other = ActivationLease(
        granted_by=ACTOR, granted_at="2026-09-19T00:00:00Z",
        expires_at="2026-09-21T00:00:00Z", generation_digest=digest,
        units=frozenset({"azazel-mio-entryd.service"}))
    outside = controller.activate(now=LNOW, actor=ACTOR, lease=other, wired=[])
    verdict = next(v for v in outside.verdicts if v.unit == CTX)
    assert CTX not in outside.granted
    assert verdict.reason.startswith("outside_lease_scope")


# -- the four closing transitions: marker, mask, and the stop that is not made --

def _closing_cases():
    def revoked(w):  # policy re-signed without contextd
        w.policy = make_policy(units=SCOPE)
        w.units = SCOPE
        w.sign(units=SCOPE)

    def lease_gone(w):
        w.sign(units=SCOPE)

    def unhealthy(w):
        w.healthy = False

    def no_evidence(w):
        w.evidence = None

    return {"revoked": revoked, "lease-outside": lease_gone,
            "health-failed": unhealthy, "evidence-missing": no_evidence}


@pytest.mark.parametrize("case", ["revoked", "lease-outside", "health-failed", "evidence-missing"])
def test_closing_transitions_remove_marker_and_mask_when_contextd_is_inactive(ctx_world, case):
    first = ctx_world.run()
    assert CTX in first.granted and CTX in ctx_world.markers()
    # contextd was never running (next boot, or the operator stopped it).
    _closing_cases()[case](ctx_world)
    outcome = ctx_world.run(**({"commissioning_evidence": lambda: None}
                               if case == "evidence-missing" else {}))
    assert CTX not in outcome.granted
    assert ctx_world.markers() is None or CTX not in ctx_world.markers()
    assert ctx_world.manager.state(CTX) is UnitState.MASKED


@pytest.mark.parametrize("case", ["revoked", "lease-outside", "health-failed", "evidence-missing"])
def test_closing_transitions_fail_loudly_while_contextd_still_runs(ctx_world, case):
    running = _make_running(ctx_world)
    _closing_cases()[case](ctx_world)
    extra = {"commissioning_evidence": lambda: None} if case == "evidence-missing" else {}
    with pytest.raises(activated.RollbackFailed) as raised:
        ctx_world.run(**extra)
    assert CTX in str(raised.value)
    # Next starts are closed even though the process cannot be stopped here.
    assert ctx_world.manager.state(CTX) is UnitState.MASKED
    assert ctx_world.markers() is None or CTX not in ctx_world.markers()
    # The pass has no stop authority: it only ever masked.
    assert {c[0] for c in running.calls} == {"mask"}
    # The operator stops it (systemctl stop or reboot); the next pass is clean.
    running.running = False
    again = ctx_world.run(**extra)
    assert CTX not in again.granted
