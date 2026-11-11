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


@pytest.mark.parametrize("bundle", ["absent", "defective", "present-empty"])
def test_bundle_state_is_not_a_grant_input(ctx_world, monkeypatch, bundle):
    # The broker reads runtime_paths.knowledge_context_commission_dir()
    # (/etc/azazel/knowledge-context/commissioning/manifest.json); put the
    # bundle there, under the world's root.
    from azazel_nexus_runtime import runtime_paths
    monkeypatch.setattr(runtime_paths, "ROOT", ctx_world.root)
    directory = runtime_paths.knowledge_context_commission_dir()
    if bundle != "absent":
        directory.mkdir(parents=True)
        (directory / "manifest.json").write_bytes(
            b"\xff not a manifest" if bundle == "defective" else b"{}")
        assert (ctx_world.root / "etc/azazel/knowledge-context/commissioning"
                / "manifest.json").exists()
    outcome = ctx_world.run()
    assert sorted(outcome.granted) == list(CTX_SCOPE)
    assert CTX in ctx_world.markers()


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
        pass  # the producer is replaced in run(), see `extra`

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
def test_revoking_a_granted_running_contextd_clears_its_marker_and_fails_loudly(ctx_world, case):
    first = ctx_world.run()
    assert CTX in first.granted and CTX in ctx_world.markers()
    # contextd is now running under that grant, then the grant is revoked.
    running = _make_running(ctx_world)
    _closing_cases()[case](ctx_world)
    extra = {"commissioning_evidence": lambda: None} if case == "evidence-missing" else {}
    with pytest.raises(activated.RollbackFailed) as raised:
        ctx_world.run(**extra)
    assert CTX in str(raised.value)
    # The existing marker is gone first and the next start is closed, though
    # the process itself cannot be stopped by the pass.
    assert ctx_world.markers() is None or CTX not in ctx_world.markers()
    assert ctx_world.manager.state(CTX) is UnitState.MASKED
    assert {c[0] for c in running.calls} == {"mask"}
    # The operator stops it (systemctl stop or reboot); the next pass is clean.
    running.running = False
    again = ctx_world.run(**extra)
    assert CTX not in again.granted


def test_a_running_contextd_that_was_never_granted_fails_the_preflight(ctx_world):
    """No marker existed: the pass-start containment check alone refuses."""
    running = _make_running(ctx_world)
    assert ctx_world.markers() is None
    with pytest.raises(activated.RollbackFailed, match="knowledge-contextd"):
        ctx_world.run()
    assert ctx_world.manager.state(CTX) is UnitState.MASKED
    running.running = False


def test_withdrawing_only_contextd_keeps_the_others_with_a_republished_generation(ctx_world):
    """Changing the policy alone breaks the generation match and every grant;
    keeping the other SUPPORTING units needs a matching generation and approval."""
    from azazel_nexus.observe_baseline import (
        build_observe_baseline,
        evidence_commissioning_digest,
    )
    first = ctx_world.run()
    assert CTX in first.granted
    ctx_world.policy = make_policy(units=SCOPE)
    ctx_world.units = SCOPE
    ctx_world.generation = ctx_world.store.create(
        build_observe_baseline(
            units=list(SCOPE),
            unit_files={u: ctx_world.unit_files[u] for u in SCOPE}),
        created_at="2026-10-20T00:00:00Z",
        commissioning_digest=evidence_commissioning_digest(ctx_world.evidence),
        commissioning_evidence_binding=ctx_world.evidence.binding)
    ctx_world.sign(units=SCOPE, approval_seq=6)
    outcome = ctx_world.run()
    assert CTX not in outcome.granted
    assert sorted(outcome.granted) == list(SCOPE)
    assert CTX not in ctx_world.markers()
    assert ctx_world.manager.state(CTX) is UnitState.MASKED


def test_dropping_contextd_from_the_allowlist_refuses_the_whole_policy(monkeypatch):
    """The negative of the allowlist change: without it, a policy naming
    contextd is refused as a whole (what an older release does)."""
    from azazel_nexus import activation_policy
    monkeypatch.setattr(
        activation_policy, "ACTIVATION_UNIT_ALLOWLIST",
        tuple(u for u in activation_policy.ACTIVATION_UNIT_ALLOWLIST if u != CTX))
    with pytest.raises(ApprovalRefused):
        make_policy(units=CTX_SCOPE)
