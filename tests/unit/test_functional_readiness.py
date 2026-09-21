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


#: The features that can supply their capability, and the ones that cannot.
#: Listed rather than derived, so that a feature crossing the line has to be
#: moved here by somebody who then reads the rules below.
FUNCTIONAL = {"knowledge_lite"}


@pytest.mark.parametrize("feature", sorted(READINESS))
def test_each_feature_is_on_the_side_this_file_says_it_is(feature: str) -> None:
    assert READINESS[feature].functional is (feature in FUNCTIONAL)


@pytest.mark.parametrize("feature", sorted(FUNCTIONAL))
def test_a_functional_feature_says_what_it_means_and_what_it_does_not(
    feature: str,
) -> None:
    """A bare capability word is one an operator fills in from hope."""

    readiness = READINESS[feature]
    assert readiness.means.strip()
    assert readiness.does_not_mean
    reason = readiness.reason()
    assert readiness.means in reason
    for limit in readiness.does_not_mean:
        assert limit in reason


def test_knowledge_lite_functional_claims_nothing_about_crypto_peers_or_authority() -> None:
    """The three claims the word would otherwise grow on its own."""

    limits = " ".join(READINESS["knowledge_lite"].does_not_mean).lower()
    assert "cryptographic implementation is supported" in limits
    assert "nexus#70" in limits
    assert "az-04" in limits
    assert "edge authority" in limits


def test_exactly_one_of_them_has_a_functional_layer_that_reaches_only_this_host() -> None:
    """Deception Lite, and only it. The two states must not blur together."""

    loopback = {f for f, r in READINESS.items() if r.loopback_only}
    assert loopback == {"deception_lite"}
    for feature in READINESS:
        readiness = READINESS[feature]
        assert readiness.value == (
            "loopback-only" if readiness.loopback_only else CONTROL_PLANE_ONLY
        )


def test_a_feature_cannot_be_both_functional_and_loopback_only() -> None:
    """A capability nothing outside can be affected by is not being supplied."""

    with pytest.raises(ValueError, match="not supplying its capability"):
        Readiness(
            feature="x",
            functional=True,
            missing="",
            issue="",
            loopback_only=True,
            means="a fixture",
            does_not_mean=("anything",),
        )


# -- each declaration, tied to the code that makes it true -----------------


def test_knowledge_lite_is_functional_because_a_real_bundle_is_admitted_and_served() -> None:
    """The mechanical tie for the one feature that crossed the line.

    Not a declaration checked against itself: the producer's own pinned
    fixture is imported through the inbox and its claims are served. If that
    stops working, this fails, and whoever made it stop has to come to
    `functional_readiness.py` and say what the feature now provides.
    """

    import shutil
    import tempfile

    from azazel_nexus.lite_import import CommissionedLite, LiteImport

    contract = (
        pathlib.Path(__file__).resolve().parents[2] / "contract" / "azazel-knowledge-lite"
    )
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "knowledge-lite"
        (root / "inbox").mkdir(parents=True)
        (root / "trust").mkdir(parents=True)
        shutil.copy(contract / "anchors.toml", root / "trust" / "anchors.toml")
        shutil.copy(contract / "lite.tar.gz", root / "inbox" / "lite.tar.gz")

        service = LiteImport(CommissionedLite(root=root))
        entries = service.list_inbox()
        assert len(entries) == 1
        outcome = service.import_entry(entries[0].entry_id, now="2026-09-21T00:00:00Z")
        assert outcome.admitted is True
        rows = list(service.serve(query_as_of="2026-09-21T00:00:00Z"))
        assert rows, "admitted and served nothing"

    assert readiness_for("knowledge_lite").functional is True, (
        "a real bundle was imported and served; if the declaration says "
        "otherwise, one of the two is wrong"
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


def test_the_library_half_of_deception_lite_still_starts_nothing() -> None:
    """`decoy.py` defines no verb that could start, bind or spawn.

    This is the same scan `test_decoy.py` runs. It is repeated here because
    here it carries a second meaning: the control plane stays a control plane.
    A decoy runtime that had grown into the library would be a runtime inside
    the half that `test_boundary_static.py` guarantees cannot act.

    It no longer establishes that *nothing* starts a decoy -- Nexus#69 landed
    the runtime half, in the runtime distribution. The tie for that half is
    the test below.
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


def test_deception_lite_is_loopback_only_because_nothing_can_bind_an_address() -> None:
    """The mechanical reason the declaration says `loopback-only` (Nexus#69).

    Decoys start and listen now, so `control-plane-only` would be false. What
    keeps them from supplying the capability is that **no module in the
    runtime distribution names an internet address family**: there is no path
    by which one could bind an address or a port, so nothing outside this host
    can reach a decoy.

    If that stops being true, this fails, and whoever made it stop has to come
    to `functional_readiness.py` and say what the feature now supplies.
    """

    runtime_root = (
        pathlib.Path(__file__).resolve().parents[2]
        / "runtime"
        / "src"
        / "azazel_nexus_runtime"
    )
    reaching = {}
    scanned = 0
    for path in sorted(runtime_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        scanned += 1
        found = sorted(
            {
                node.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and node.attr in {"AF_INET", "AF_INET6", "AF_PACKET", "create_connection"}
            }
        )
        if found:
            reaching[path.name] = found
    assert scanned > 1, "a vacuous scan: the runtime distribution was not found"
    assert reaching == {}, f"{reaching} can reach past this host"

    readiness = readiness_for("deception_lite")
    assert readiness.loopback_only is True
    assert readiness.functional is False, (
        "nothing in the runtime distribution can bind an address, so no "
        "hostile party can reach a decoy; if external exposure has landed, "
        "update the declaration"
    )


def test_the_loopback_runtime_really_binds_so_the_word_is_not_control_plane_only() -> None:
    """The other half of the tie: something must actually run.

    `loopback-only` claims a functional layer exists. A declaration that said
    so while the runtime bound nothing would be the overstatement this module
    was written to prevent, in the opposite direction.
    """

    from azazel_nexus_runtime.decoy_loopback import (
        LoopbackCatalogue,
        LoopbackDecoy,
        LoopbackRuntime,
        ResponderState,
    )

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        runtime = LoopbackRuntime(
            pathlib.Path(tmp) / "decoys",
            catalogue=LoopbackCatalogue.of(
                [LoopbackDecoy(name="alpha", responder="ssh-banner")]
            ),
            generation_digest="sha256:" + "ef" * 32,
            clock=lambda: "2026-09-21T00:00:00Z",
        )
        try:
            assert runtime.start() == ("alpha",)
            assert runtime.state("alpha") is ResponderState.LISTENING
            assert runtime.path_for("alpha").is_socket()
        finally:
            runtime.stop()

    assert readiness_for("deception_lite").value == "loopback-only"


# -- what a declaration must carry -----------------------------------------


@pytest.mark.parametrize(
    "feature", sorted(f for f in READINESS if f not in FUNCTIONAL)
)
def test_a_gap_names_what_is_missing_and_where_it_is_tracked(feature: str) -> None:
    readiness = READINESS[feature]
    assert readiness.missing.strip()
    assert readiness.issue.startswith("Nexus#")
    assert readiness.feature == feature


@pytest.mark.parametrize(
    "feature", sorted(f for f in READINESS if f not in FUNCTIONAL)
)
def test_an_unsupplied_feature_distinguishes_itself_from_an_absent_peer(
    feature: str,
) -> None:
    """The sentence this whole change exists to make sure gets said.

    Only for the features that cannot supply. A functional feature's reason
    says what it means and what it does not, which is a different sentence
    for a different fact.
    """

    reason = READINESS[feature].reason()
    assert "not the same fact as an external peer being absent" in reason
    assert READINESS[feature].missing in reason


def test_a_functional_declaration_needs_no_reason() -> None:
    """So the refusals below are about incomplete gaps, not about all gaps."""

    assert Readiness(
        feature="x",
        functional=True,
        missing="",
        issue="",
        means="a fixture",
        does_not_mean=("anything",),
    ).functional


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
