"""Fixture-only checks of the closed generation boundary; no provider runs."""
from dataclasses import replace

import pytest

from admission_helpers import END, inputs
from azazel_nexus import model_admission as admission
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.mio_supervisor import ServingProcess, SupervisorRefused


@pytest.mark.parametrize("roles", [("generation",), ("embedding", "generation")])
def test_generation_requires_a_new_explicit_policy_contract(roles):
    kwargs, _, _ = inputs()
    with pytest.raises(ApprovalRefused, match="POLICY_REFUSED"):
        replace(kwargs["policy"], roles=roles)


def test_embedding_context_cannot_be_relabelled_generation():
    kwargs, _, _ = inputs()
    context = kwargs["expected"].as_document()
    context["model"]["role"] = "generation"
    with pytest.raises(ApprovalRefused, match="ROLE_MISMATCH"):
        admission.AdmissionContext(context)


@pytest.mark.parametrize("now", ["2026-10-18T00:00:00Z", END])
def test_embedding_signature_never_authorizes_generation_even_before_expiry(now):
    kwargs, _, _ = inputs()
    kwargs.update(role="generation", now=now)
    with pytest.raises(ApprovalRefused, match="ROLE_MISMATCH"):
        admission.verify_local_model_admission(**kwargs)


def test_production_process_gate_refuses_before_descriptor_or_process_access():
    assert admission.LOCAL_MODEL_ADMISSION_ENABLED is False
    # Inert objects suffice because disabled admission must precede all access.
    process = ServingProcess(object(), root=object(), descriptors=object())
    with pytest.raises(SupervisorRefused, match="ADMISSION_DISABLED"):
        process.start()
    assert process.process is None
