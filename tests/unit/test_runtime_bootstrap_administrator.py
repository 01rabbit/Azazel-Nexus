from dataclasses import replace

import pytest

from azazel_nexus.bootstrap_deployment import declared_node_digest
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs as inputs
from azazel_nexus_runtime.node_config import DeclaredNode
from test_bootstrap_deployment_store import declaration
from test_bootstrap_generation import _context


@pytest.fixture
def observed(monkeypatch):
    deployment = declaration()
    context = _context(node_digest=deployment.node_digest,
                       security_epoch=deployment.security_epoch,
                       revocation_digest=deployment.revocation_digest,
                       policy_digest=deployment.policy_digest,
                       approval_policy_digest=deployment.approval_policy_digest)
    observation = inputs.BootstrapObservation(context, deployment.operator,
                                               "2026-10-14T00:00:00Z", True)
    monkeypatch.setattr(inputs, "load_bootstrap_deployment", lambda: deployment)
    monkeypatch.setattr(inputs, "load_declared_node", lambda: DeclaredNode("node-a"))
    return deployment, observation


def test_administrator_producer_binds_then_returns_fresh_observation(observed):
    _, observation = observed
    assert inputs.AdministratorBootstrapObservation(lambda: observation)() is observation


@pytest.mark.parametrize("field", ["node_digest", "security_epoch", "revocation_digest",
                                   "policy_digest", "approval_policy_digest"])
def test_mismatched_observation_refuses(observed, field):
    _, observation = observed
    value = 4 if field == "security_epoch" else "sha256:" + "9" * 64
    changed = replace(observation, context=replace(observation.context, **{field: value}))
    with pytest.raises(ApprovalRefused):
        inputs.AdministratorBootstrapObservation(lambda: changed)()


@pytest.mark.parametrize("change", ["deployment", "node"])
def test_changed_protected_state_refuses(observed, monkeypatch, change):
    deployment, observation = observed
    if change == "deployment":
        values = iter([deployment, replace(deployment, security_epoch=4)])
        monkeypatch.setattr(inputs, "load_bootstrap_deployment", lambda: next(values))
    else:
        values = iter([DeclaredNode("node-a"), DeclaredNode("node-b")])
        monkeypatch.setattr(inputs, "load_declared_node", lambda: next(values))
    with pytest.raises(ApprovalRefused):
        inputs.AdministratorBootstrapObservation(lambda: observation)()


def test_cloned_identity_is_not_accepted_as_target_identity(observed, monkeypatch):
    _, observation = observed
    assert declared_node_digest("node-b") != observation.context.node_digest
    monkeypatch.setattr(inputs, "load_declared_node", lambda: DeclaredNode("node-b"))
    with pytest.raises(ApprovalRefused):
        inputs.AdministratorBootstrapObservation(lambda: observation)()


def test_missing_observer_does_not_create_trust():
    with pytest.raises(ValueError):
        inputs.AdministratorBootstrapObservation(None)
