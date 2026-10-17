"""Pure guidance cannot turn complete preparation into authority."""

import ast
from pathlib import Path

import pytest

from azazel_nexus.operator_flow import ORDER, Observation, State, evaluate, next_step


def populated():
    return {name: Observation(State.COMPLETE, "scoped read succeeded", "azazel-nexus status")
            for name in ORDER}


def test_fresh_node_starts_with_install():
    steps = evaluate({})
    assert tuple(step.name for step in steps) == ORDER
    assert next_step(steps).name == "installed-files"
    assert all(step.reason and step.next_command for step in steps)


@pytest.mark.parametrize("count", range(11))
def test_progressive_observations_advance_next_step(count):
    facts = populated()
    for name in ORDER[count:]:
        facts[name] = Observation(State.MISSING, "not prepared", "azazel-nexus status")
    assert next_step(evaluate(facts)).name == ORDER[count]


def test_hg05_is_unmeasured_even_if_caller_marks_everything_complete():
    steps = evaluate(populated())
    gate = next_step(steps)
    assert gate.name == "provider-admission"
    assert gate.status == "blocked"
    assert gate.reason == "HG-05: unmeasured; provider admission blocked"


def test_optional_steps_are_skipped_and_refusal_is_retained():
    facts = populated()
    facts["knowledge-store"] = Observation(State.OPTIONAL, "not selected", "azazel-nexus status")
    facts["mission-pack"] = Observation(State.REFUSED, "revoked", "azazel-nexus pack --help")
    assert evaluate(facts)[6].status == "not-applicable"
    assert next_step(evaluate(facts)).name == "mission-pack"


def test_flow_has_no_io_or_runtime_imports():
    source = Path(__file__).resolve().parents[2] / "src/azazel_nexus/operator_flow.py"
    tree = ast.parse(source.read_text())
    modules = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
    modules += [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert not any(name.split(".")[0] in {"socket", "subprocess", "os", "pathlib", "azazel_nexus_runtime"}
                   for name in modules)
