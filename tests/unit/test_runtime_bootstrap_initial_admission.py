"""First admission ordering: verify, prestart, create-only retain, guard, grant."""

from dataclasses import replace
from pathlib import Path

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs
from azazel_nexus_runtime.bootstrap_audit import AuditObservation
from test_runtime_bootstrap import NS, Harness, evidence as _harness_evidence

@pytest.fixture
def evidence(request):
    return _harness_evidence.__wrapped__(request)


HEAD = AuditObservation(1, "a" * 64, 1, 100)


class FakeAdmission:
    def __init__(self, h, *, verify_error=None, retain_error=None,
                 verify_value="approval", retain_value="deadline"):
        self.h = h
        self.verify_error = verify_error
        self.retain_error = retain_error
        self.verify_value = h.deadline.approval if verify_value == "approval" else verify_value
        self.retain_value = h.deadline if retain_value == "deadline" else retain_value
        self.retained_with = []

    def verify(self):
        self.h.timeline.append(("verify", None))
        if self.verify_error:
            raise self.verify_error
        return self.verify_value

    def retain(self, approval):
        self.h.timeline.append(("retain", None))
        self.retained_with.append(approval)
        if self.retain_error:
            raise self.retain_error
        return self.retain_value


def _harness(evidence, *, admission_kwargs=None, prestart=None, **options):
    holder = {}

    def default_prestart(_context):
        holder["h"].timeline.append(("prestart", None))
        if prestart is not None:
            return prestart(_context)
        return HEAD

    class Lazy:
        def verify(inner):
            return holder["admission"].verify()

        def retain(inner, approval):
            return holder["admission"].retain(approval)

    h = Harness(evidence, prestart=default_prestart, initial_admission=Lazy(), **options)
    holder["h"] = h
    holder["admission"] = FakeAdmission(h, **(admission_kwargs or {}))
    h.admission = holder["admission"]
    original_open_pair = h.manager.open_pair
    original_ready = h.manager.confirm_controller_ready
    original_start = h.manager.start_and_wait

    def open_pair(*a, **k):
        h.timeline.append(("open_pair", None))
        return original_open_pair(*a, **k)

    def ready(*a, **k):
        h.timeline.append(("ready", None))
        return original_ready(*a, **k)

    def start(*a, **k):
        h.timeline.append(("start", None))
        return original_start(*a, **k)

    h.manager.open_pair = open_pair
    h.manager.confirm_controller_ready = ready
    h.manager.start_and_wait = start
    return h


def _shifted(base):
    return replace(
        base,
        admitted_boottime_ns=101 * NS,
        deadline_boottime_ns=401 * NS,
        last_boottime_ns=101 * NS,
    )


def _names(h):
    return [event[0] for event in h.timeline]


def _first(h, name):
    return _names(h).index(name)


def test_happy_path_ordering_and_guard_bound_to_retained_deadline(evidence):
    h = _harness(evidence)
    h.supervisor.run()
    names = _names(h)
    assert names[:3] == ["store.load_optional", "verify", "admit_generation"]
    assert names.index("prestart") < names.index("retain") < names.index("deadline_guard")
    assert (names.index("verify") < names.index("admit_generation")
            < names.index("prestart"))
    assert (names.index("deadline_guard") < names.index("store.create")
            < names.index("open_pair") < names.index("ready") < names.index("start"))
    assert names.count("retain") == 1 and names.count("verify") == 1
    assert names.count("prestart") == 1
    assert h.admission.retained_with == [h.deadline.approval]
    assert h.deadline_guard.deadlines and all(
        d == h.deadline for d in h.deadline_guard.deadlines)
    assert [d for d in h.deadline_guard.deadlines].count(h.deadline) >= 1
    assert [c for c in h.manager.calls if c[0] == "start_and_wait"]


def test_guard_armed_after_retain_and_before_any_publication(evidence):
    h = _harness(evidence)
    h.supervisor.run()
    ix = {n: _first(h, n) for n in
          ("prestart", "retain", "deadline_guard", "store.create", "open_pair",
           "ready", "start")}
    assert (ix["prestart"] < ix["retain"] < ix["deadline_guard"]
            < ix["store.create"] < ix["open_pair"] < ix["ready"] < ix["start"])


def _assert_contained_and_unpublished(h):
    names = _names(h)
    assert "store.create" not in names
    assert "open_pair" not in names
    assert "start" not in names


@pytest.mark.parametrize("case", ["prestart_error", "prestart_type", "generation"])
def test_pre_retain_failures_never_retain_or_arm_guard(evidence, case):
    if case == "prestart_error":
        def bad(_context):
            raise ApprovalRefused("prestart")
        h = _harness(evidence, prestart=bad)
    elif case == "prestart_type":
        h = _harness(evidence, prestart=lambda _context: object())
    else:
        h = _harness(evidence)
        h.admit_error = ApprovalRefused("generation")
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    names = _names(h)
    assert "retain" not in names
    assert "deadline_guard" not in names
    _assert_contained_and_unpublished(h)
    if case == "generation":
        assert "prestart" not in names


def test_cancellation_before_retain_never_retains(evidence):
    h = _harness(evidence)
    original = h.admit

    def admit(context):
        result = original(context)
        h.stop = True
        return result

    h.supervisor.admit_generation = admit
    h.supervisor.run()
    names = _names(h)
    assert "retain" not in names and "prestart" not in names
    assert "deadline_guard" not in names
    _assert_contained_and_unpublished(h)


def test_cancellation_after_prestart_never_retains(evidence):
    def prestart(_context):
        h.stop = True
        return HEAD

    h = _harness(evidence, prestart=prestart)
    h.supervisor.run()
    names = _names(h)
    assert "prestart" in names and "retain" not in names
    assert "deadline_guard" not in names
    _assert_contained_and_unpublished(h)


def test_verify_refusal_stops_before_prestart_and_retain(evidence):
    h = _harness(evidence, admission_kwargs={"verify_error": ApprovalRefused("expired")})
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    names = _names(h)
    assert "prestart" not in names and "retain" not in names
    assert "admit_generation" not in names and "deadline_guard" not in names
    _assert_contained_and_unpublished(h)


def test_verify_wrong_type_refuses(evidence):
    h = _harness(evidence, admission_kwargs={"verify_value": object()})
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    assert "retain" not in _names(h) and "prestart" not in _names(h)


def test_retain_refusal_does_not_fall_back_to_refresh_or_arm_guard(evidence):
    h = _harness(evidence, admission_kwargs={"retain_error": ApprovalRefused("exists")})
    refreshes = []
    h.supervisor.refresh = lambda: refreshes.append(True) or h.deadline
    with pytest.raises(ApprovalRefused, match="exists"):
        h.supervisor.run()
    assert refreshes == []
    names = _names(h)
    assert "deadline_guard" not in names
    assert h.deadline_guard.releases == 1  # release is a no-op when never armed
    _assert_contained_and_unpublished(h)


@pytest.mark.parametrize("which", ["approval", "deadline_fields", "type"])
def test_retain_result_must_match_verified_approval(evidence, which):
    base = evidence[0]
    if which == "approval":
        other = replace(base.approval, operator="operator-b")
        value = replace(base, approval=other)
    elif which == "deadline_fields":
        value = _shifted(base)
    else:
        value = object()
    h = _harness(evidence, admission_kwargs={"retain_value": value})
    message = ("bootstrap admission cannot be renewed" if which == "deadline_fields"
               else "retained bootstrap deadline differs from verified approval")
    with pytest.raises(ApprovalRefused, match=message):
        h.supervisor.run()
    _assert_contained_and_unpublished(h)
    if which != "deadline_fields":
        assert "deadline_guard" not in _names(h)


def test_post_retain_check_failure_does_not_arm_guard_and_does_not_publish(evidence):
    h = _harness(evidence)
    h.refresh_error = ApprovalRefused("expired or revoked")
    with pytest.raises(ApprovalRefused):
        h.supervisor.run()
    names = _names(h)
    assert "retain" in names and "deadline_guard" not in names
    _assert_contained_and_unpublished(h)


def test_refresh_returning_different_deadline_is_not_renewable(evidence):
    h = _harness(evidence)
    h.refresh_value = _shifted(h.deadline)
    h.supervisor.boottime_ns = lambda: 101 * NS
    with pytest.raises(ApprovalRefused, match="cannot be renewed"):
        h.supervisor.run()
    _assert_contained_and_unpublished(h)


def test_existing_grant_record_refuses_before_first_admission(evidence):
    h = _harness(evidence)
    from test_runtime_bootstrap import _owned_grant_transaction
    h.grant_store.journal = _owned_grant_transaction()
    with pytest.raises(ApprovalRefused, match="manual review"):
        h.supervisor.run()
    names = _names(h)
    assert "verify" not in names and "retain" not in names
    assert "prestart" not in names


@pytest.mark.parametrize("point", ["guard", "grant_create"])
def test_crash_after_retain_never_publishes_and_release_is_safe(evidence, point):
    h = _harness(evidence)
    if point == "guard":
        class Boom(type(h.deadline_guard)):
            def __call__(self, deadline):
                super().__call__(deadline)
                raise RuntimeError("crash at guard")
        guard = Boom(h.timeline)
        h.supervisor.deadline_guard = guard
    else:
        def create(journal):
            raise RuntimeError("crash at create")
        h.grant_store.create = create
    with pytest.raises(RuntimeError):
        h.supervisor.run()
    names = _names(h)
    assert names.count("retain") == 1
    assert "open_pair" not in names and "start" not in names
    assert len(h.supervisor.deadline_guard.deadlines) <= 1
    assert h.supervisor.deadline_guard.releases == 1


def test_legacy_none_keeps_exact_order_and_never_calls_initializer(evidence):
    h = Harness(evidence, prestart=lambda _c: HEAD)
    assert h.supervisor.initial_admission is None
    h.supervisor.run()
    names = _names(h)
    assert names.index("deadline_guard") < names.index("admit_generation")
    assert "retain" not in names and "verify" not in names


@pytest.mark.parametrize("bad", [object(), type("V", (), {"verify": lambda s: 1})()])
def test_invalid_initial_admission_object_is_rejected(evidence, bad):
    with pytest.raises(ValueError):
        Harness(evidence, initial_admission=bad)


def test_supervisor_refresh_adapter_has_no_initializer():
    adapter = bootstrap_inputs.ProtectedBootstrapInputs
    assert not hasattr(adapter, "retain") and not hasattr(adapter, "verify")
    assert hasattr(bootstrap_inputs.ProtectedBootstrapInitialAdmission, "retain")


def test_initializers_are_referenced_in_runtime_only_by_bootstrap_inputs():
    import azazel_nexus_runtime
    root = Path(azazel_nexus_runtime.__file__).parent
    referencing = {
        path.name for path in root.rglob("*.py")
        if "begin_deadline" in path.read_text() or "retain_initial_deadline" in path.read_text()
    }
    assert referencing == {"bootstrap_inputs.py"}


def test_initial_admission_factory_takes_no_input_and_no_env_or_cli():
    import inspect
    assert not inspect.signature(
        bootstrap_inputs.protected_bootstrap_initial_admission).parameters
    root = Path(bootstrap_inputs.__file__).parent
    for name in ("bootstrap_entrypoint.py", "bootstrap_inputs.py"):
        text = (root / name).read_text()
        assert "os.environ" not in text and "argv" not in text


def test_real_factory_composition_is_exact_and_accepted_by_real_supervisor(evidence):
    """Construction reads no host state; only observation calls would."""
    admission = bootstrap_inputs.protected_bootstrap_initial_admission()
    assert type(admission) is bootstrap_inputs.ProtectedBootstrapInitialAdmission
    observation = admission.observe
    assert type(observation) is bootstrap_inputs.ProtectedAdministratorClockObservation
    assert (type(observation.observe_context)
            is bootstrap_inputs._BracketedBootstrapContextObservation)
    assert (admission.observe_installed_files
            is bootstrap_inputs.observe_bootstrap_installed_files_once)
    # Real supervisor construction with the real (unmocked) composition.
    h = Harness(evidence, initial_admission=admission)
    assert h.supervisor.initial_admission is admission
    # The real instance is also a distinct object from the refresh adapter.
    assert not isinstance(admission, bootstrap_inputs.ProtectedBootstrapInputs)
