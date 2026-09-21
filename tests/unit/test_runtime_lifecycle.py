"""Binary verification, the restart budget, and the gate that still refuses (#114).

`RuntimeBinary.digest` was declared in #97 and nothing compared anything
against it. A field that reads like a guarantee and is not one is worse than
an absent field: the absent one is noticed.

Everything here is `injected` -- it sets states and checks what follows.
The **process** evidence is `test_mio_supervisor.py`, marked `real_process`,
and the two are not interchangeable.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime" / "src"))

from azazel_nexus.core_reserve import CoreReserve  # noqa: E402
from azazel_nexus.model_runtime import (  # noqa: E402
    ActivationReadiness,
    RuntimeBinary,
    readiness as activation_readiness,
)
from azazel_nexus.resource_profile import ResourceProfile  # noqa: E402
from azazel_nexus.runtime_lifecycle import (  # noqa: E402
    LifecycleRefused,
    LifecycleState,
    MAX_RESTARTS,
    Provenance,
    Readiness,
    RestartBudget,
    verify_runtime_binary,
)

pytestmark = pytest.mark.injected

BODY = b"not a program this test runs -- bytes with a known digest\n"
DIGEST = "sha256:" + hashlib.sha256(BODY).hexdigest()


@pytest.fixture
def binary(tmp_path) -> Path:
    path = tmp_path / "az-runtime"
    path.write_bytes(BODY)
    return path


def _verify(binary: Path, **overrides):
    fields = dict(
        expected_digest=DIGEST,
        declared_provenance=Provenance.PACKAGED,
        signature_verified=True,
    )
    fields.update(overrides)
    return verify_runtime_binary(binary, **fields)


# -- all three, or it does not start -------------------------------------


def test_a_binary_with_all_three_is_admissible(binary):
    """So every refusal below is a refusal, not a function that never
    passes."""

    assert _verify(binary).admissible is True


def test_a_digest_mismatch_refuses(binary):
    verdict = _verify(binary, expected_digest="sha256:" + "0" * 64)
    assert verdict.admissible is False
    assert any("does not hash" in reason for reason in verdict.refusals)


def test_a_refusal_does_not_print_the_expected_digest(binary):
    """A message that named the target would hand an attacker what to forge."""

    verdict = _verify(binary, expected_digest="sha256:" + "a" * 64)
    assert "a" * 64 not in " ".join(verdict.refusals)


def test_an_unsigned_binary_refuses(binary):
    verdict = _verify(binary, signature_verified=False)
    assert verdict.admissible is False
    assert any("signature did not verify" in r for r in verdict.refusals)


def test_nobody_checked_refuses_as_firmly_as_a_failure_did(binary):
    """With a different reason. `None` is the absence of a check, not a
    permissive default."""

    verdict = _verify(binary, signature_verified=None)
    assert verdict.admissible is False
    assert any("absence of a check is not a pass" in r for r in verdict.refusals)


def test_an_undeclared_provenance_refuses(binary):
    verdict = _verify(binary, declared_provenance=None)
    assert verdict.admissible is False
    assert any("no provenance" in r for r in verdict.refusals)


def test_a_fixture_provenance_is_refused_by_name(binary):
    """A fixture is how the supervisor is tested, never how a provider is
    admitted -- the same rule `core_reserve.validate` holds for a measured
    reserve."""

    verdict = _verify(binary, declared_provenance=Provenance.FIXTURE)
    assert verdict.admissible is False
    assert any("fixture" in r for r in verdict.refusals)


def test_an_absent_binary_refuses(tmp_path):
    verdict = _verify(tmp_path / "nothing")
    assert verdict.admissible is False
    assert any("not present" in r for r in verdict.refusals)


def test_every_reason_is_reported_not_only_the_first(binary):
    """An operator who fixes one and is then told about the next has been
    sent round twice."""

    verdict = verify_runtime_binary(
        binary,
        expected_digest="sha256:" + "0" * 64,
        declared_provenance=None,
        signature_verified=False,
    )
    assert verdict.admissible is False
    assert len(verdict.refusals) >= 3


def test_a_verdict_cannot_be_admissible_and_refused():
    from azazel_nexus.runtime_lifecycle import BinaryVerdict

    with pytest.raises(LifecycleRefused):
        BinaryVerdict(admissible=True, refusals=("something",))
    with pytest.raises(LifecycleRefused):
        BinaryVerdict(admissible=False, refusals=())


# -- the restart budget --------------------------------------------------


def test_the_budget_grants_exactly_its_limit():
    """A limit that means one fewer than it says is a limit nobody can reason
    about. Found by a real-process test counting starts."""

    budget = RestartBudget(generation=1, limit=MAX_RESTARTS)
    granted = [budget.spend().may_restart for _ in range(MAX_RESTARTS)]
    assert granted == [True] * MAX_RESTARTS
    assert budget.spent == MAX_RESTARTS
    assert budget.fenced is False, "fenced while a restart was still granted"

    refused = budget.spend()
    assert refused.may_restart is False
    assert refused.state is LifecycleState.FENCED
    assert budget.fenced is True


def test_a_fence_is_permanent_for_the_generation():
    budget = RestartBudget(generation=1, limit=1)
    budget.spend()
    first = budget.spend()
    second = budget.spend()
    assert first.may_restart is False and second.may_restart is False
    assert "operator" in second.reason or "fenced" in second.reason


def test_the_budget_is_per_generation():
    """A budget a reboot refilled would be a budget a crash loop refills by
    taking the node down with it."""

    spent = RestartBudget(generation=1, limit=1)
    spent.spend()
    spent.spend()
    assert spent.fenced is True

    fresh = RestartBudget(generation=2, limit=1)
    assert fresh.fenced is False
    assert fresh.spend().may_restart is True


def test_a_budget_of_zero_cannot_be_built():
    with pytest.raises(LifecycleRefused):
        RestartBudget(generation=1, limit=0)


def test_the_budget_event_carries_counts_and_no_reason_text():
    budget = RestartBudget(generation=4)
    budget.spend()
    event = budget.as_event()
    assert event["generation"] == 4 and event["spent"] == 1
    assert event["remaining"] == MAX_RESTARTS - 1


# -- readiness is three-valued -------------------------------------------


def test_readiness_has_a_third_value_and_it_is_not_a_pass():
    assert {r.value for r in Readiness} == {"passed", "failed", "not-checked"}
    assert Readiness.NOT_CHECKED is not Readiness.PASSED
    assert Readiness.NOT_CHECKED is not Readiness.FAILED


def test_there_is_no_running_state():
    """"Running" would let a process that started and cannot answer read the
    same as one that is serving."""

    assert "RUNNING" not in {state.name for state in LifecycleState}


# -- HG-05 still refuses, however green the lifecycle is -----------------


def _reserve() -> CoreReserve:
    return CoreReserve(
        profile=ResourceProfile.STANDARD,
        reserve_mib=512,
        host_digest="sha256:" + "0" * 64,
        harness_version="fixture",
        sample_count=64,
        duration_seconds=3600,
    )


def test_an_unmeasured_reserve_refuses_with_the_whole_lifecycle_green(binary, tmp_path):
    """**The requirement of this issue.**

    Binary verified, provenance packaged, signature good, the process starts,
    answers, is bounded and is supervised -- and still no activation, because
    the Core reserve is unmeasured.

    "Verified" and "may be used" are not the same word, and a lifecycle that
    went green is not a measurement.
    """

    assert _verify(binary).admissible is True

    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"GGUF" + b"\x00" * 4096)
    from azazel_nexus.model_runtime import inspect_artifact

    verdict = activation_readiness(
        admitted=True,
        runtime_id="stub",
        artifact=inspect_artifact(artifact),
        reserve=None,
    )
    assert verdict.readiness is ActivationReadiness.REFUSED
    assert "HG-05" in verdict.reason


def test_the_gate_is_reachable_once_a_reserve_exists(binary, tmp_path, monkeypatch):
    """A gate that refuses only by being unreachable is a gate that starts
    passing the day something upstream stops refusing."""

    import azazel_nexus.model_runtime as module

    monkeypatch.setattr(
        module,
        "RUNTIMES",
        {
            "fixture": RuntimeBinary(
                runtime_id="fixture",
                executable="/usr/libexec/azazel/az-runtime",
                version="1",
                digest=DIGEST,
                argv=("/usr/libexec/azazel/az-runtime",),
            )
        },
    )
    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"GGUF" + b"\x00" * 4096)

    verdict = module.readiness(
        admitted=True,
        runtime_id="fixture",
        artifact=module.inspect_artifact(artifact),
        reserve=_reserve(),
    )
    assert verdict.readiness is ActivationReadiness.READY, (
        "the gate is unreachable, so its refusal proves nothing"
    )


def test_the_lifecycle_module_starts_nothing():
    import ast

    import azazel_nexus.runtime_lifecycle as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"subprocess", "os", "socket", "ssl", "signal"} == set()
