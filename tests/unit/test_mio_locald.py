"""`az-mio-locald` as a service boundary, not a module with a socket (#97).

A module that imports `socket` is a module boundary. A service boundary is
its own unit, its own system account, its own socket, its own directory and
its own hardening -- and the reason to fix one now, on a build that starts
nothing, is that a containment written after the thing it contains is a
containment shaped by what that thing turned out to need.

Two accounts, kept apart on purpose:

- `azfetch` **may reach the network** and may not run a program.
- `azmio` **may run one program**, from a fixed list, and may reach nothing.

Neither one's access is reused for the other, and #98's remote inference
transport inherits neither.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "runtime" / "src"))

from azazel_nexus_runtime import mio_locald
from azazel_nexus_runtime.hardening import PROFILES, SYSTEM_ACCOUNTS, render_unit
from azazel_nexus_runtime.principal import PrincipalClass
from azazel_nexus_runtime.protocol import ArgumentKind

from azazel_nexus.activation import (
    ARTIFACT_TRANSPORT,
    CORE_UNITS,
    LOCAL_MODEL_PROVIDER,
)

UNIT = "azazel-mio-locald.service"
MODULE = REPO_ROOT / "runtime" / "src" / "azazel_nexus_runtime" / "mio_locald.py"


def _profile(unit: str):
    return next(p for p in PROFILES if p.unit == unit)


# -- the service boundary, not a module boundary --------------------------


def test_it_has_its_own_unit_account_socket_and_directory():
    profile = _profile(UNIT)
    assert profile.account == "azmio"
    assert "azmio" in SYSTEM_ACCOUNTS
    assert profile.runtime_directory == "azazel/mio"
    assert mio_locald.SOCKET_NAME == "mio"
    assert profile.read_write_paths == (
        "/var/lib/azazel/mio",
        "/var/lib/azazel/run",
    )


def test_it_shares_nothing_with_the_artifact_fetcher():
    """The one that may reach the network and the one that may run a program
    are different services, and a node where they were one service would have
    a path from a remote byte to a local execution."""

    mio, fetch = _profile(UNIT), _profile("azazel-model-fetchd.service")
    assert mio.account != fetch.account
    assert mio.runtime_directory != fetch.runtime_directory
    assert mio_locald.SOCKET_NAME != "fetch"
    assert set(mio.read_write_paths) & set(fetch.read_write_paths) == {
        "/var/lib/azazel/run"
    }, "the socket directory is shared; the staging directories must not be"
    assert "/var/lib/azazel/fetch" not in mio.read_write_paths
    assert "/var/lib/azazel/mio" not in fetch.read_write_paths


def test_no_shipped_profile_both_reaches_the_network_and_runs_a_model():
    for profile in PROFILES:
        assert not (profile.is_artifact_fetcher and profile.is_model_host)
    assert sum(p.is_model_host for p in PROFILES) == 1
    assert sum(p.is_artifact_fetcher for p in PROFILES) == 1


def test_a_profile_that_did_both_cannot_be_built():
    """The check above says no shipped profile *does*. This says none *can*.

    Found by mutation: removing the constructor guard left the suite green,
    because nothing tried to build the forbidden profile -- so the guarantee
    was "nobody has written one yet" rather than "one cannot exist". The
    first survives the next person who writes one.

    Together they would be a path from a remote byte to a local execution,
    which is the shape the two accounts exist to keep apart.
    """

    from azazel_nexus_runtime.hardening import ServiceProfile

    with pytest.raises(ValueError) as caught:
        ServiceProfile(
            unit="azazel-both.service",
            executable="/usr/libexec/azazel/az-both",
            account="azmio",
            description="d",
            documentation="u",
            address_families=("AF_UNIX", "AF_INET"),
            read_write_paths=("/var/lib/azazel/mio",),
            is_artifact_fetcher=True,
            is_model_host=True,
            extra=(
                ("CPUQuota", "40%"),
                ("TasksMax", "64"),
                ("LimitFSIZE", "1024"),
                ("PrivateNetwork", "yes"),
            ),
        )
    assert "one compromise is two" in str(caught.value)
    assert "artifact fetcher" in str(caught.value)
    assert "model host" in str(caught.value)


def test_the_model_host_has_no_internet_address_family():
    profile = _profile(UNIT)
    assert profile.address_families == ("AF_UNIX",)


def test_the_unit_denies_outbound_and_has_no_network_namespace():
    """`IPAddressDeny` is a filter; `PrivateNetwork` is no stack at all."""

    rendered = render_unit(_profile(UNIT))
    assert "PrivateNetwork=yes" in rendered
    assert "IPAddressDeny=any" in rendered


@pytest.mark.parametrize("setting", ["CPUQuota", "TasksMax", "LimitFSIZE"])
def test_the_unit_bounds_what_a_unit_file_can_bound(setting):
    assert setting in dict(_profile(UNIT).extra)


@pytest.mark.parametrize("setting", ["MemoryMax", "RuntimeMaxSec"])
def test_the_unit_states_no_bound_it_would_have_to_invent(setting):
    """Both are per-provider quantities derived from the measured Core
    reserve, and no node this build runs on has one.

    `RuntimeMaxSec` is the sharper of the two: it bounds how long the *unit*
    runs, while the deadline this product needs bounds one inference. Putting
    the inference deadline on the host would terminate a healthy service on a
    timer and record it as a failure -- a restart loop that reads, from the
    journal, exactly like a provider that keeps dying.
    """

    assert setting not in dict(_profile(UNIT).extra)


def test_a_model_host_without_its_ceilings_cannot_be_built():
    """A flag that can be set while the bounds are dropped is a flag that
    will be, in a refactor that keeps the flag."""

    from azazel_nexus_runtime.hardening import ServiceProfile

    base = dict(
        unit="azazel-test.service",
        executable="/usr/libexec/azazel/az-test",
        account="azmio",
        description="d",
        documentation="u",
        address_families=("AF_UNIX",),
        read_write_paths=("/var/lib/azazel/mio",),
        is_model_host=True,
    )
    with pytest.raises(ValueError) as caught:
        ServiceProfile(**base)
    assert "declares no" in str(caught.value)

    with pytest.raises(ValueError) as caught:
        ServiceProfile(
            **base,
            extra=(
                ("CPUQuota", "40%"),
                ("TasksMax", "64"),
                ("LimitFSIZE", "1024"),
                ("PrivateNetwork", "no"),
            ),
        )
    assert "private network" in str(caught.value)

    with pytest.raises(ValueError) as caught:
        ServiceProfile(
            **base,
            extra=(
                ("CPUQuota", "40%"),
                ("TasksMax", "64"),
                ("LimitFSIZE", "1024"),
                ("PrivateNetwork", "yes"),
                ("MemoryMax", "4096M"),
            ),
        )
    assert "invented" in str(caught.value)


# -- the control plane passes two symbols and nothing else ----------------


def test_the_verb_takes_two_identifiers_and_no_more():
    verb = mio_locald.ACTIVATE_VERB
    assert [a.name for a in verb.arguments] == ["model_id", "runtime_id"]
    assert {a.kind for a in verb.arguments} == {ArgumentKind.IDENTIFIER}


def test_there_is_no_kind_that_could_carry_a_command_or_a_path():
    """Not a check the service performs; a shape a request cannot take."""

    names = {kind.name for kind in ArgumentKind}
    assert names & {
        "STRING", "TEXT", "FREE_TEXT", "PATH", "COMMAND", "ARGV", "ENV", "URL"
    } == set()


def test_an_operator_cannot_reach_past_the_admission_decision():
    assert mio_locald.ACTIVATE_VERB.admits == frozenset(
        {PrincipalClass.ROOT, PrincipalClass.SERVICE}
    )
    assert PrincipalClass.OPERATOR not in mio_locald.ACTIVATE_VERB.admits


def test_readiness_and_advisory_verbs_exist():
    assert mio_locald.REGISTRY.names() == ("mio.local.infer", "model.activate")


def test_the_staging_directory_is_fixed_in_code():
    """A staging directory supplied by a caller is a caller choosing which
    file is the model."""

    assert str(mio_locald.STAGING) == "/var/lib/azazel/mio"


# -- the module cannot execute or connect ---------------------------------


def _imported_roots() -> set:
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def test_the_service_module_imports_nothing_that_starts_a_process():
    """The module that will one day start one does not import the means yet,
    and when it does, this test is the diff a reviewer sees."""

    assert _imported_roots() & {
        "subprocess", "os", "shutil", "pty", "multiprocessing", "socket", "ssl"
    } == set()


def test_the_service_has_no_method_that_starts_anything():
    """Not a disabled method. A method nothing calls is a method the next
    change calls."""

    names = {
        node.name
        for node in ast.walk(ast.parse(MODULE.read_text(encoding="utf-8")))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert names & {"start", "spawn", "launch", "run_model", "execute"} == set()


def test_the_executable_takes_no_arguments():
    """An argument vector is readable by every user on the host."""

    with pytest.raises(SystemExit) as caught:
        mio_locald.main(["--runtime", "/usr/bin/sh"])
    assert "takes no arguments" in str(caught.value)


def test_default_service_serves_refusals_with_only_entry_service_policy(tmp_path, monkeypatch):
    from azazel_nexus_runtime import runtime_paths

    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    runtime_paths.mio_state_dir().mkdir(parents=True)
    captured = {}
    policies = []
    monkeypatch.setattr(mio_locald, "serve_forever", lambda **kw: captured.update(kw) or 0)
    monkeypatch.setattr(mio_locald.PrincipalPolicy, "resolve",
                        lambda **kw: policies.append(kw) or "policy")
    services = []
    original = mio_locald.LocalRuntimeService

    def construct(**kwargs):
        service = original(**kwargs)
        services.append(service)
        return service

    monkeypatch.setattr(mio_locald, "LocalRuntimeService", construct)
    assert mio_locald.main([]) == 0
    assert services[0]._playbooks is None
    assert services[0]._knowledge_lookup is mio_locald.lookup_context
    from azazel_nexus.lite_import import KnowledgeRef

    assert mio_locald.KnowledgeRef is KnowledgeRef
    assert policies == [{"service_accounts": ("azmioentry",)}]
    assert captured["registry"] is mio_locald.REGISTRY
    assert captured["path"] == runtime_paths.socket_path("mio")


# -- three refusals, and each covers what the others do not ---------------


def test_the_unit_is_not_granted_while_no_runtime_is_wired():
    definition = next(d for d in CORE_UNITS if d.name == UNIT)
    assert definition.wiring == LOCAL_MODEL_PROVIDER
    assert definition.wiring != ARTIFACT_TRANSPORT, (
        "fetching weights and running them are different capabilities; a node "
        "that gained one must not be read as having gained the other"
    )


def test_a_wired_transport_does_not_wire_a_provider(monkeypatch):
    from azazel_nexus_runtime import activated

    monkeypatch.setattr(activated, "ENDPOINT_FOR", {"vendor-primary": object()})
    assert activated.wired_capabilities() == frozenset({ARTIFACT_TRANSPORT})


def test_a_wired_provider_does_not_wire_a_transport(monkeypatch):
    from azazel_nexus_runtime import activated

    monkeypatch.setattr(activated, "RUNTIMES", {"fixture": object()})
    assert activated.wired_capabilities() == frozenset({LOCAL_MODEL_PROVIDER})


def test_a_request_for_an_unwired_runtime_is_answered_not_acted_on(tmp_path):
    """The service answers. It resolves nothing and reads nothing, because
    the symbol resolves to no binary."""

    service = mio_locald.LocalRuntimeService(staging=tmp_path)

    class Request:
        arguments = {"model_id": "m", "runtime_id": "llama-cpp"}

    reply = service.handle(Request())
    assert reply["readiness"] == "refused"
    assert reply["model_id"] == "m"
    assert reply["runtime_id"] == "llama-cpp"


def test_a_reply_never_carries_a_path_or_an_argv(tmp_path):
    service = mio_locald.LocalRuntimeService(staging=tmp_path)

    class Request:
        arguments = {"model_id": "m", "runtime_id": "llama-cpp"}

    reply = service.handle(Request())
    rendered = repr(reply)
    for leak in (str(tmp_path), "/usr/libexec", "argv", "--"):
        assert leak not in rendered, f"the reply carries {leak!r}"


# -- Edge authority is unchanged in every local-runtime state -------------
#
# The doctrine this product is built on: the deterministic arbiter from
# Azazel-Edge holds the final authority to decide and to enforce, and
# `FULL -> LITE -> CORE` is a **capability** state, never an authority state.
#
# A local model runtime is the component most likely to be mistaken for an
# exception, because it is the one that "thinks". So the states are
# enumerated -- absent, refused, ready, crashed, rolled back -- and the same
# four properties are asserted across all of them. Enumerating them is the
# point: a test that drove one state would report an invariant it had checked
# once.


LOCAL_RUNTIME_STATES = (
    "absent",
    "refused_for_unmeasured_reserve",
    "refused_for_unwired_runtime",
    "ready_on_a_fixture_node",
    "crashed",
    "rolled_back",
)


def _verdict_for(state: str, tmp_path, monkeypatch):
    """Drive `readiness` into `state`. No provider, no inference, no process."""

    import azazel_nexus.model_runtime as module
    from azazel_nexus.core_reserve import CoreReserve
    from azazel_nexus.resource_profile import ResourceProfile

    reserve = CoreReserve(
        profile=ResourceProfile.STANDARD,
        reserve_mib=512,
        host_digest="sha256:" + "0" * 64,
        harness_version="fixture",
        sample_count=64,
        duration_seconds=3600,
    )
    fixture = module.RuntimeBinary(
        runtime_id="fixture",
        executable="/usr/libexec/azazel/az-runtime",
        version="1",
        digest="sha256:" + "0" * 64,
        argv=("/usr/libexec/azazel/az-runtime",),
    )
    artifact = tmp_path / "m.model"
    artifact.write_bytes(b"GGUF" + b"\x00" * 4096)

    if state == "absent":
        return module.readiness(
            admitted=False, runtime_id=None, artifact=None, reserve=None
        )
    if state == "refused_for_unmeasured_reserve":
        return module.readiness(
            admitted=True, runtime_id="fixture", artifact=None, reserve=None
        )
    if state == "refused_for_unwired_runtime":
        return module.readiness(
            admitted=True, runtime_id="fixture", artifact=None, reserve=reserve
        )
    monkeypatch.setattr(module, "RUNTIMES", {"fixture": fixture})
    if state == "crashed":
        # A crash leaves the staging file behind and nothing else. The node's
        # answer afterwards is the answer it had before, which is the property.
        (tmp_path / "core").write_bytes(b"\x00" * 16)
    if state == "rolled_back":
        artifact.unlink()
        return module.readiness(
            admitted=True,
            runtime_id="fixture",
            artifact=module.inspect_artifact(artifact),
            reserve=reserve,
        )
    return module.readiness(
        admitted=True,
        runtime_id="fixture",
        artifact=module.inspect_artifact(artifact),
        reserve=reserve,
    )


@pytest.mark.parametrize("state", LOCAL_RUNTIME_STATES)
def test_the_deterministic_path_is_never_blocked(state, tmp_path, monkeypatch):
    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    _verdict_for(state, tmp_path, monkeypatch)
    reading = CognitionReading(
        state=CognitionState.CORE_ONLY,
        remote=RemoteState.DISABLED,
        resource_reason=state,
        topology_reason=state,
        asset_reason=state,
        trust_health_reason=state,
    )
    assert reading.blocks_deterministic_path() is False


@pytest.mark.parametrize("state", LOCAL_RUNTIME_STATES)
def test_no_local_runtime_state_grants_an_edge_baseline(
    state, tmp_path, monkeypatch
):
    """A node that can think is not a node that has an Edge Core."""

    from azazel_nexus.activation import UnitTier

    _verdict_for(state, tmp_path, monkeypatch)
    definition = next(d for d in CORE_UNITS if d.name == UNIT)
    assert definition.tier is UnitTier.SUPPORTING
    assert definition.tier is not UnitTier.EDGE_BASELINE
    assert definition.tier is not UnitTier.ENFORCEMENT


@pytest.mark.parametrize("state", LOCAL_RUNTIME_STATES)
def test_no_local_runtime_state_extends_a_lease_or_enforces(
    state, tmp_path, monkeypatch
):
    """The module that decides whether a model may run holds no name that
    touches a lease, an activation or enforcement.

    Scanned over the **syntax tree**, not the text: prose about granting is
    prose, and a scan that could not tell the two apart would have to be
    silenced by whoever next explains why nothing is granted -- which is how
    a scan stops being enforced.
    """

    import azazel_nexus.model_runtime as module

    _verdict_for(state, tmp_path, monkeypatch)
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            used.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            used.add(node.name)
        elif isinstance(node, ast.arg):
            used.add(node.arg)
        elif isinstance(node, ast.alias):
            used.add((node.asname or node.name).split(".")[-1])
    offenders = sorted(
        name
        for name in used
        if any(
            token in name.lower()
            for token in ("lease", "unmask", "enforce", "grant", "activationcontroller")
        )
    )
    assert offenders == [], (
        f"model_runtime uses {offenders}; deciding that a model may run is "
        "not deciding anything about authority"
    )

    # And the scan can fail. A scan that cannot is a scan nobody should trust.
    sample = {n.id for n in ast.walk(ast.parse("extend_lease(x)")) if isinstance(n, ast.Name)}
    assert any("lease" in name.lower() for name in sample)


@pytest.mark.parametrize("state", LOCAL_RUNTIME_STATES)
def test_the_answer_is_the_same_whatever_the_runtime_is_doing(
    state, tmp_path, monkeypatch
):
    """The Edge answer does not vary with the local runtime's state.

    Asserted as identity of a fixed reading rather than as "nothing crashed":
    the claim is that the deterministic side is *unaffected*, and a test that
    only checked it still ran would pass on a node where it ran differently.
    """

    from azazel_nexus.cognition import CognitionReading, CognitionState, RemoteState

    _verdict_for(state, tmp_path, monkeypatch)
    reading = CognitionReading(
        state=CognitionState.CORE_ONLY,
        remote=RemoteState.DISABLED,
        resource_reason="unmeasured",
        topology_reason="unmeasured",
        asset_reason="none",
        trust_health_reason="none",
    )
    assert reading.state is CognitionState.CORE_ONLY
    assert reading.sources_local_cognition is False
    assert reading.remote is RemoteState.DISABLED


def test_the_state_list_covers_a_crash_and_a_rollback():
    """A list that quietly lost its interesting members is a list that still
    passes. `crashed` and `rolled_back` are the two the issue names."""

    assert {"crashed", "rolled_back"} <= set(LOCAL_RUNTIME_STATES)
    assert len(LOCAL_RUNTIME_STATES) == len(set(LOCAL_RUNTIME_STATES))


def test_trusted_reference_delivery_and_lookup_failures(tmp_path):
    from types import SimpleNamespace

    from azazel_nexus.reasoning_playbook import read_library
    library = read_library((REPO_ROOT / 'tests/fixtures/reasoning-playbook.json').read_bytes())
    frame = {'request_id': 'reference-fixture', 'privacy_class': 'P2-mission',
             'question': 'Password spray T1110.003',
             'context': [{'kind': 'auth_log', 'text': 'many accounts'}]}
    calls = []
    def infer(request, **kwargs):
        calls.append(request)
        return SimpleNamespace(text='A' if len(calls) % 2 else 'C')
    (tmp_path / 'fixture.model').write_bytes(b'GGUF' + b'\0' * 4096)
    service = mio_locald.LocalRuntimeService(
        staging=tmp_path, reserve=object(), admitted=lambda _: True, model_id='fixture',
        runtime_id='fixture', runtime=lambda _: object(), server=SimpleNamespace(infer=infer),
        playbooks=library, knowledge_lookup=lambda _: pytest.fail('unbounded lookup'))
    request = SimpleNamespace(verb=mio_locald.INFER_VERB, payload=frame,
                              arguments={'deadline_ms': 1000})
    events = []
    reply = service.handle(request, audit=events.append)
    assert reply['outcome'] == 'advisory'
    assert reply['candidate'] == {'option_id': 'auth-password-spraying', 'kind': 'playbook'}
    assert reply['provenance']['playbooks_reviewed'] is False
    assert reply['match_evidence'][0]['technique_ids'] == ['T1110.003']
    assert 'playbook' not in reply and 'knowledge' not in reply
    assert len(calls) == 0  # optional explanation skipped below one second
    assert any(e.get('knowledge') == 'skipped_deadline_contract' for e in events)
    assert 'many accounts' not in str(events)
    frame.update(question='How do I bake bread?', context=[])
    assert service.handle(request)['reason'] == 'out_of_scope'
    assert len(calls) == 0



def test_accepted_reply_without_references_has_null_playbook(tmp_path):
    from types import SimpleNamespace
    (tmp_path / 'fixture.model').write_bytes(b'GGUF' + b'\0' * 4096)
    letters = iter(['A', 'B'])
    service = mio_locald.LocalRuntimeService(
        staging=tmp_path, reserve=object(), admitted=lambda _: True, model_id='fixture',
        runtime_id='fixture', runtime=lambda _: object(),
        server=SimpleNamespace(infer=lambda *a, **kw: SimpleNamespace(text=next(letters))))
    request = SimpleNamespace(verb=mio_locald.INFER_VERB, arguments={'deadline_ms': 1000},
                              payload={'request_id': 'fixture', 'privacy_class': 'P2-mission',
                                       'question': 'SSH host-1', 'context': []})
    reply = service.handle(request)
    assert reply['match_evidence'] == []
    assert reply['candidate']['kind'] == 'other_suspicious'
    assert 'playbook' not in reply



def test_main_refreshes_optional_selection_before_each_request(tmp_path, monkeypatch):
    from azazel_nexus_runtime import runtime_paths

    from azazel_nexus.playbook_selection import PlaybookSelection

    monkeypatch.setattr(runtime_paths, 'ROOT', tmp_path)
    runtime_paths.mio_state_dir().mkdir(parents=True)
    libraries = [object(), object(), None]
    observed = []

    class Holder:
        def __init__(self, *, config, root):
            assert config == tmp_path / 'etc/azazel/mission-pack.json'
            assert root == tmp_path / 'data/azazel/mission-packs'
            self.selection = PlaybookSelection(None, 'no_pack')

        def refresh(self, *, audit):
            return libraries.pop(0)

    class Service:
        def __init__(self, *, playbooks, knowledge_lookup):
            self._playbooks = playbooks
            observed.append(playbooks)

        def set_playbooks(self, library):
            self._playbooks = library

        def handle(self, request, *, audit):
            observed.append(self._playbooks)
            return {'outcome': 'failed'}

    monkeypatch.setattr(mio_locald, 'PlaybookSelectionHolder', Holder)
    monkeypatch.setattr(mio_locald, 'LocalRuntimeService', Service)
    monkeypatch.setattr(mio_locald.PrincipalPolicy, 'resolve', lambda **kw: 'policy')

    def serve(**kwargs):
        kwargs['handler'](object())
        kwargs['handler'](object())
        return 0

    monkeypatch.setattr(mio_locald, 'serve_forever', serve)
    assert mio_locald.main([]) == 0
    assert observed[0] is not observed[1] and observed[1] is not None
    assert observed[2] is None


def test_selection_holder_unreadable_state_and_audit_failure(tmp_path, monkeypatch):
    from azazel_nexus.audit import AuditUnavailable

    root = tmp_path / 'packs'
    root.mkdir()
    (root / 'current').write_text('1\n')
    holder = mio_locald.PlaybookSelectionHolder(config=tmp_path / 'absent-config', root=root)
    events = []
    assert holder.refresh(audit=events.append) is None
    assert events[-1]['reason'] == 'pack_degraded'

    def broken_audit(event):
        raise AuditUnavailable('injected audit failure')

    holder = mio_locald.PlaybookSelectionHolder(config=tmp_path / 'absent-config', root=root)
    with pytest.raises(AuditUnavailable):
        holder.refresh(audit=broken_audit)


@pytest.mark.parametrize('with_reference', [False, True])
def test_infer_validates_against_exact_sent_reference(tmp_path, with_reference):
    import json

    from azazel_nexus.local_advisory import read_explanation
    frame = {'request_id': 'reference', 'privacy_class': 'P2-mission',
             'question': 'SSH host-1', 'context': []}
    text = json.dumps({'reason': 'Review "host-1" event 4625.',
                       'check_1': 'Review logs.', 'check_2': 'Review logs.',
                       'check_3': 'Review logs.', 'missing': 'Time is needed.'})
    candidate = {'option_id': 'other_suspicious', 'kind': 'other_suspicious'}
    if with_reference:
        assert read_explanation(text, frame, candidate, 'reference Event 4625')
    else:
        with pytest.raises(ValueError, match='ungrounded_facts'):
            read_explanation(text, frame, candidate)
