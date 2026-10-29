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
import re

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

# One source of truth for which module may reach the network. Imported
# rather than restated: two copies of an exemption list is one copy that
# stops matching, and the one that stops matching is the one nobody reads.
from tests.unit.test_runtime_boundary import EGRESS_EXEMPT, LISTENER_EXEMPT, _exempt


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


def test_knowledge_lite_is_functional_because_a_real_bundle_is_admitted_and_served(lab_host) -> None:
    # The producer's published fixture key is an anchor only on a marked lab host.
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

def test_mio_is_not_functional_without_minted_admission_evidence() -> None:
    """A fully evidenced provider, in the largest envelope, is still refused.

    `HG-05` is the reason and the gate names it. While that holds, no local
    model provider is ever admitted on any node.
    """

    digest = "sha256:" + "1" * 64
    host = HostFacts(
        os_abi="debian-13/linux-6.12",
        architecture=ADMITTED_ARCHITECTURE,
        cpu_features=frozenset(),
        fabric_version="v0.9.0rc5",
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
                model_role="embedding",
                adapter_digest=digest,
                renderer_digest=digest,
                toolchain_digest=digest,
                os_abi="debian-13/linux-6.12",
                architecture=ADMITTED_ARCHITECTURE,
                fabric_version="v0.9.0rc5",
                profile=ResourceProfile.STANDARD,
                overlay_schema="3",
                security_epoch=4,
                max_rollback_version="0.9.0",
            )
        ]
    )
    from admission_helpers import evidence

    from azazel_nexus.cognition import ResourceEvidence
    from azazel_nexus.core_reserve import CoreReserve
    from azazel_nexus.model_admission import canonical
    from azazel_nexus.model_admission import digest as hash_bytes

    matched, _ = tested.admits(digest, host, model_role="embedding")
    proof = evidence(component=digest, model_id="fully-evidenced", need=1,
                     tuple_digest=hash_bytes(canonical(matched.as_record())))
    provider = LocalModelProvider(
        "fully-evidenced", digest, "gguf", "sentencepiece", "1.4.0", "q4_k_m",
        2048, 1, evidence=proof, role="embedding")
    outcome = admit_local_model(provider, host=host, tested=tested)
    assert outcome.failed_gate is AdmissionGate.RESOURCE_TOPOLOGY
    assert "unmeasured" in outcome.reason
    reserve = CoreReserve(host.profile, 2000, "test-host", "test-only", 60, 600)
    outcome = admit_local_model(provider, host=host, tested=tested,
                               resources=ResourceEvidence(reserve, 64000))
    assert outcome.failed_gate is AdmissionGate.APPROVAL
    outcome = admit_local_model(provider, host=host, tested=tested,
                               resources=ResourceEvidence(reserve, 2000))
    assert outcome.failed_gate is AdmissionGate.RESOURCE_TOPOLOGY

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
        if (_exempt(path, EGRESS_EXEMPT, runtime_root)
                or _exempt(path, LISTENER_EXEMPT, runtime_root)):
            continue
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


def test_the_decoy_listener_is_called_only_by_the_ungranted_decoy_so_the_row_stays_loopback_only() -> None:
    """#196 P1 adds one module that can bind an address: `decoy_listener.py`.

    The row may stay `loopback-only` only while nothing that runs on a node
    runs it. Since the decoy body (§12) its one caller is `az-decoyd`, whose
    unit the activation pass never grants in this build (the
    `DECEPTION_EXPOSURE` tier is withheld as `isolation_evidence_absent`). Any
    other importer fails this, and whoever made it fail has to come to
    `functional_readiness.py` -- which, per
    `docs/deception-redirect-prerequisites.md` §5, moves to a new word only
    after `HG-06` passes on hardware.
    """

    runtime_root = (
        pathlib.Path(__file__).resolve().parents[2]
        / "runtime" / "src" / "azazel_nexus_runtime"
    )
    assert LISTENER_EXEMPT == {"decoy_listener.py"}
    importers = []
    for path in sorted(runtime_root.rglob("*.py")):
        if _exempt(path, LISTENER_EXEMPT, runtime_root):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] + [alias.name for alias in node.names]
            if any("decoy_listener" in name for name in names):
                importers.append(path.relative_to(runtime_root).as_posix())
    assert importers == ["decoyd.py"]
    assert READINESS["deception_lite"].loopback_only is True
    from azazel_nexus.activation import DECEPTION_EXPOSURE_UNITS

    assert "azazel-decoyd.service" in DECEPTION_EXPOSURE_UNITS


def test_the_one_module_that_reaches_the_network_cannot_be_reached_through() -> None:
    """The scan above grew an exemption (Nexus#105), so the claim needs the
    narrower reason the declaration always gave.

    `functional_readiness.py` says the reason is "the absence of any internet
    address family in the distribution **that binds**". The scan was broader
    than that -- it refused any mention at all -- and the artifact fetch
    service needs outbound TCP. Outbound TCP does not make a decoy reachable:
    reaching one from outside needs a `bind` to a non-loopback address and a
    `listen`, and the exempt module does neither.

    So the exemption is allowed to connect, and this is what keeps it from
    doing anything else. Had the declaration claimed the broader reason, the
    honest move would have been to change the declaration instead.
    """

    runtime_root = (
        pathlib.Path(__file__).resolve().parents[2]
        / "runtime"
        / "src"
        / "azazel_nexus_runtime"
    )
    for name in sorted(EGRESS_EXEMPT):
        path = runtime_root / name
        assert path.exists(), f"{name} is exempt and does not exist"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        serving = sorted(
            {
                node.func.attr
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"bind", "listen", "accept", "wrap_socket"}
                # `wrap_socket` is here for its server side; a client one is
                # the ordinary way to speak TLS and is not a listener.
                and not _is_client_wrap(node)
            }
        )
        assert serving == [], (
            f"{name} may connect outward. It may not {serving}: a module that "
            "bound or listened would be a path by which something outside "
            "this host could arrive, which is exactly what `loopback-only` "
            "says cannot happen"
        )


def _is_client_wrap(node) -> bool:
    """`wrap_socket(..., server_side=True)` is a listener's; a client's is not."""

    if node.func.attr != "wrap_socket":
        return False
    for keyword in node.keywords:
        if keyword.arg == "server_side":
            return False
    return True

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

    import tempfile

    from azazel_nexus_runtime.decoy_loopback import (
        LoopbackCatalogue,
        LoopbackDecoy,
        LoopbackRuntime,
        ResponderState,
    )

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


def _core_job_gate() -> str:
    """The body of the CI step that guards this module's declarations."""

    workflow = pathlib.Path(".github/workflows/ci.yml").read_text()
    start = workflow.index("PYTHONPATH=src python - <<'PY'")
    return workflow[start : workflow.index("\n          PY\n", start)]


def test_the_ci_gate_names_exactly_the_features_reviewed_as_functional() -> None:
    """The tripwire is a hand-written set in YAML, so tie it to the declarations.

    `CORE imports with nothing installed` fails when a feature is declared
    functional and is not in its `reviewed` set -- which is how Knowledge Lite
    becoming functional (#67) forced the status rows and
    `docs/integration-display.md` to be updated with it. The set is a literal
    in the workflow, and a literal drifts. The job checks its own set against
    the declarations, so the drift cannot reach `main`; this test is only so
    that it is found before a push rather than after one.
    """

    match = re.search(r'^\s*reviewed = \{(.*?)\}\s*$', _core_job_gate(), re.MULTILINE)
    assert match, "the CORE job declares no reviewed-functional set"
    reviewed = set(ast.literal_eval("{" + match.group(1) + "}"))
    declared = {name for name, entry in READINESS.items() if entry.functional}
    assert reviewed == declared, (
        f"the CI gate reviewed {sorted(reviewed)} and the declarations say "
        f"{sorted(declared)}"
    )


def test_every_tracked_feature_has_a_row_in_the_ci_gate() -> None:
    """A feature the gate has no row for is a feature whose display it checks nothing of."""

    match = re.search(r"^\s*rows = \{\n(.*?)^\s*\}\s*$", _core_job_gate(), re.MULTILINE | re.DOTALL)
    assert match, "the CORE job declares no feature-to-row map"
    named = set(re.findall(r'"([a-z_]+)": \("', match.group(1)))
    assert named == set(READINESS), (
        f"the CI gate has rows for {sorted(named)} and this module tracks "
        f"{sorted(READINESS)}"
    )
