"""Every v2 entry of the Fabric boundary needs the exact lab candidate (ADR-0011).

A Fabric of another version that happens to carry the clocklab module is
refused; nothing falls back to v1. Stub modules make this independent of which
Fabric the test environment installed.
"""
import sys
from types import ModuleType, SimpleNamespace

import pytest

from azazel_nexus import fabric_boundary as boundary
from azazel_nexus.fabric_boundary import (
    CLOCKLAB_CANDIDATE_FABRIC_VERSION, KnowledgeContextUnavailable)

CONTRACT = SimpleNamespace(contract_id="sha256:" + "0" * 64)

ENTRIES = {
    "validate_clocklab_request": lambda: boundary.validate_clocklab_request({}, contract=CONTRACT),
    "canonical_clocklab_request": lambda: boundary.canonical_clocklab_request(object()),
    "validate_clocklab_response": lambda: boundary.validate_clocklab_response(object(), {}, contract=CONTRACT),
    "clock_contract": lambda: boundary.clock_contract(skew_budget_us=5000),
    "clock_contract_from_dict": lambda: boundary.clock_contract_from_dict({}, consumer_revision=2),
    "clocklab_response_model": lambda: boundary.clocklab_response_model({}),
    "clocklab_response_v1_projection": lambda: boundary.clocklab_response_v1_projection(object()),
    "clocklab_response_v1": lambda: boundary.clocklab_response_v1({}),
}


def _install(monkeypatch, version):
    parent = ModuleType("azazel_fabric")
    parent.__version__ = version
    child = ModuleType("azazel_fabric.knowledge_context_clocklab")
    parent.knowledge_context_clocklab = child
    monkeypatch.setitem(sys.modules, "azazel_fabric", parent)
    monkeypatch.setitem(sys.modules, "azazel_fabric.knowledge_context_clocklab", child)
    return child


@pytest.mark.parametrize("version", ["0.10.0", "0.10.1", "0.10.1.dev1", "0.10.0.dev0", None])
@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_a_fabric_of_another_version_is_refused_even_with_the_module(monkeypatch, entry, version):
    _install(monkeypatch, version)
    with pytest.raises(KnowledgeContextUnavailable):
        ENTRIES[entry]()


@pytest.mark.parametrize("entry", sorted(ENTRIES))
def test_a_missing_module_is_refused_the_same_way(monkeypatch, entry):
    parent = ModuleType("azazel_fabric")
    parent.__version__ = CLOCKLAB_CANDIDATE_FABRIC_VERSION
    monkeypatch.setitem(sys.modules, "azazel_fabric", parent)
    monkeypatch.setitem(sys.modules, "azazel_fabric.knowledge_context_clocklab", None)
    with pytest.raises(KnowledgeContextUnavailable):
        ENTRIES[entry]()


def test_the_candidate_version_reaches_the_module(monkeypatch):
    module = _install(monkeypatch, CLOCKLAB_CANDIDATE_FABRIC_VERSION)
    seen = []
    module.ClockContract = lambda *, skew_budget_us: seen.append(skew_budget_us) or "contract"
    assert boundary.clock_contract(skew_budget_us=5000) == "contract" and seen == [5000]


def test_the_refusal_is_also_an_import_error_for_existing_callers():
    assert issubclass(boundary.ClocklabUnavailable, (KnowledgeContextUnavailable, ImportError))
