"""The declarations, and the code that makes them true (#53).

A hand-maintained "not done yet" list goes stale the day somebody finishes the
work and forgets the list. Every test here pairs one declaration with the
**mechanical reason** it is currently true. When that reason stops holding,
its test fails, and whoever made it stop holding has to come and update the
declaration.

That is the whole point of this file: the list cannot quietly outlive the gap
it describes.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from azazel_nexus import decoy as decoy_module
from azazel_nexus.cognition import AdmissionGate, LocalModelProvider, admit_local_model
from azazel_nexus.compatibility import (
    ADMITTED_ARCHITECTURE,
    HostFacts,
    TestedTuple,
    TestedTupleSet,
)
from azazel_nexus.functional_readiness import (
    CONTROL_PLANE_ONLY,
    READINESS,
    Readiness,
    readiness_for,
)
from azazel_nexus.lite_service import KnowledgeLite, no_claim_reader
from azazel_nexus.resource_profile import ResourceProfile


def test_the_three_embedded_features_are_tracked() -> None:
    assert set(READINESS) == {"knowledge_lite", "mio", "deception_lite"}


@pytest.mark.parametrize("feature", sorted(READINESS))
def test_none_of_them_is_functional_yet(feature: str) -> None:
    assert READINESS[feature].functional is False


# -- each declaration, tied to the code that makes it true -----------------


def test_knowledge_lite_is_not_functional_because_nothing_can_read_a_bundle() -> None:
    """The default claim reader refuses, and there is no other.

    `KnowledgeLite` takes its reader by injection and defaults to one that
    reads nothing. Until a real bundle format is accepted by default, no node
    can turn an admitted artifact into a claim -- which is what
    `knowledge_lite` being non-functional means.
    """

    assert KnowledgeLite.__dataclass_fields__["claims_of"].default is no_claim_reader
    with pytest.raises(Exception) as refused:
        no_claim_reader(b"any bytes at all")
    assert "does not parse Knowledge's" in str(refused.value)

    assert readiness_for("knowledge_lite").functional is False, (
        "a default reader that refuses everything means no node can serve a "
        "claim; if that has changed, update the declaration"
    )


def test_mio_is_not_functional_because_the_resource_gate_always_refuses() -> None:
    """A fully evidenced provider, in the largest envelope, is still refused.

    `HG-05` is the reason and the gate names it. While that holds, no local
    model provider is ever admitted on any node.
    """

    digest = "sha256:" + "1" * 64
    host = HostFacts(
        os_abi="debian-13/linux-6.12",
        architecture=ADMITTED_ARCHITECTURE,
        cpu_features=frozenset(),
        fabric_version="v0.9.0rc2",
        fabric_features=frozenset(),
        schema_features=frozenset(),
        profile=ResourceProfile.STANDARD,
        overlay_schema="3",
        security_epoch=4,
    )
    tested = TestedTupleSet.of(
        [
            TestedTuple(
                component_digest=digest,
                adapter_digest=digest,
                renderer_digest=digest,
                toolchain_digest=digest,
                os_abi="debian-13/linux-6.12",
                architecture=ADMITTED_ARCHITECTURE,
                fabric_version="v0.9.0rc2",
                profile=ResourceProfile.STANDARD,
                overlay_schema="3",
                security_epoch=4,
                max_rollback_version="0.9.0",
            )
        ]
    )
    outcome = admit_local_model(
        LocalModelProvider(
            name="fully-evidenced",
            component_digest=digest,
            declared_format="gguf",
            tokenizer_format="sentencepiece",
            runtime_version="1.4.0",
            quantization="q4_k_m",
            context_size=4096,
            memory_need_mib=1,
            signature_verified=True,
            content_policy_passed=True,
        ),
        host=host,
        tested=tested,
    )
    assert outcome.admitted is False
    assert outcome.failed_gate is AdmissionGate.RESOURCE_TOPOLOGY
    assert "HG-05" in outcome.reason

    assert readiness_for("mio").functional is False, (
        "the resource gate still refuses every provider; if HG-05 has closed, "
        "update the declaration"
    )


def test_deception_lite_is_not_functional_because_nothing_starts_a_decoy() -> None:
    """`decoy.py` defines no verb that could start, bind or spawn.

    This is the same scan `test_decoy.py` runs. It is repeated here because
    here it carries a second meaning: as long as it passes, no decoy runs,
    and the declaration below is correct.
    """

    tree = ast.parse(pathlib.Path(decoy_module.__file__).read_text(encoding="utf-8"))
    verbs = {"start", "run", "exec", "execute", "launch", "bind", "listen", "spawn"}
    acting = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and not any(
            isinstance(d, ast.Name) and d.id == "property" for d in node.decorator_list
        )
        and node.name.lstrip("_").split("_")[0] in verbs
    }
    assert acting == set()

    assert readiness_for("deception_lite").functional is False, (
        "nothing in decoy.py can start a decoy; if a runtime has landed, "
        "update the declaration"
    )


# -- what a declaration must carry -----------------------------------------


@pytest.mark.parametrize("feature", sorted(READINESS))
def test_a_gap_names_what_is_missing_and_where_it_is_tracked(feature: str) -> None:
    readiness = READINESS[feature]
    assert readiness.missing.strip()
    assert readiness.issue.startswith("Nexus#")
    assert readiness.feature == feature


@pytest.mark.parametrize("feature", sorted(READINESS))
def test_the_reason_distinguishes_itself_from_an_absent_peer(feature: str) -> None:
    """The sentence this whole change exists to make sure gets said."""

    reason = READINESS[feature].reason()
    assert "not the same fact as an external peer being absent" in reason
    assert READINESS[feature].missing in reason


def test_a_functional_declaration_needs_no_reason() -> None:
    """So the refusals below are about incomplete gaps, not about all gaps."""

    assert Readiness(feature="x", functional=True, missing="", issue="").functional


@pytest.mark.parametrize(
    "missing, issue, expected",
    [("  ", "Nexus#1", "cannot act on that"), ("something", "  ", "nobody closes")],
)
def test_an_incomplete_gap_declaration_is_refused(missing, issue, expected) -> None:
    with pytest.raises(ValueError) as caught:
        Readiness(feature="x", functional=False, missing=missing, issue=issue)
    assert expected in str(caught.value)


def test_an_unknown_feature_is_refused_rather_than_assumed_functional() -> None:
    with pytest.raises(KeyError):
        readiness_for("not-a-feature")


def test_the_word_is_not_one_the_other_vocabularies_use() -> None:
    from azazel_nexus.cognition import RemoteState
    from azazel_nexus.decoy import DecoyState
    from azazel_nexus.integration import MISSING
    from azazel_nexus.lite_service import LiteState

    taken = (
        {state.value for state in LiteState}
        | {state.value for state in DecoyState}
        | {state.value for state in RemoteState}
        | {MISSING}
    )
    assert CONTROL_PLANE_ONLY not in taken
