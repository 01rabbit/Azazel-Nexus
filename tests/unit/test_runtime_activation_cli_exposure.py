"""`az-activation` with the Deception Lite exposure tier, end to end (#196 G6).

`docs/deception-exposure-wiring.md` §5.1, §5.2 and §7 items 6 and 12: on one
temporary root, `generation-publish` renders the scope file as the pass does,
measures the exposure unit, watch unit and profile files and copies the
installer's compiled-policy record into a v2 generation's exposure section;
`request` writes a v3 payload with the scope digest and counts;
`tools/operator_sign.py --purpose activation-exposure` signs it with a key
generated for the test; `install` verifies it by its schema; and one
controller pass, with the real unit-file, section and approval readers and
in-memory host readers for step 10, grants exactly the three plus the
requested units. A v3 commissioning proposal on the pinned Fabric's golden
inventory (`test_exposure_interfaces`). None of this is VM evidence (§8).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path

import pytest

from azazel_nexus.activation import CORE_UNITS, DECEPTION_EXPOSURE_UNITS, UnitState
from azazel_nexus.commissioning_evidence import CommissioningEvidence
from azazel_nexus.generation import tree_digest
from azazel_nexus.observe_baseline import (
    OBSERVE_BASELINE_FILE,
    build_observe_baseline,
    decode_observe_baseline,
)
from azazel_nexus_runtime import activation_cli as cli
from azazel_nexus_runtime import activation_unit_files as scoped_unit_files
from azazel_nexus_runtime import exposure_generation
from azazel_nexus_runtime.apparmor_compiled import encode_apparmor_compiled
from azazel_nexus_runtime.decoy_apparmor import REQUIRED_ENFORCED_PROFILES
from azazel_nexus_runtime.hardening import packaged_unit_files

import test_exposure_interfaces as roles
from test_runtime_activation_cli import BINDING, LOOP, NOW, _policy, node  # noqa: F401
from test_runtime_activation_cli import operator_sign

pytestmark = roles.needs_fabric

EXPOSURE = tuple(DECEPTION_EXPOSURE_UNITS)
REPO = Path(__file__).resolve().parents[2]
HASHES = {name: format(index, "x") * 64 for index, name in
          enumerate(sorted(REQUIRED_ENFORCED_PROFILES), start=10)}


def _canonical(inventory) -> bytes:
    return json.dumps(inventory.model_dump(mode="json"), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@pytest.fixture
def exposure_node(node, monkeypatch):  # noqa: F811 - the CLI test's fixture
    from azazel_nexus.commissioning_approval import commissioning_proposal_payload

    root = node.root
    rendered = dict(packaged_unit_files())
    for unit in (*EXPOSURE, *scoped_unit_files.WATCH_UNITS):
        path = node.units_dir / unit
        path.write_text(rendered[unit] if unit in scoped_unit_files.WATCH_UNITS
                        else scoped_unit_files.rendered_unit(unit))
        path.chmod(0o644)
    profiles = root / "etc/apparmor.d"
    profiles.mkdir(mode=0o755)
    profiles.chmod(0o755)
    (root / "etc").chmod(0o755)
    for name in REQUIRED_ENFORCED_PROFILES:
        path = profiles / name
        path.write_bytes((REPO / "packaging/apparmor" / name).read_bytes())
        path.chmod(0o644)
    record = node.approvals / "apparmor-compiled.json"
    record.write_bytes(encode_apparmor_compiled(HASHES, "AppArmor parser version 4.1.0"))
    record.chmod(0o644)
    context = roles._node()
    proposal = commissioning_proposal_payload(
        **context, mio_profile="FULL", deception_scope=json.loads(json.dumps(roles.SCOPE)))
    node.evidence = CommissioningEvidence(proposal, b"s" * 64, _canonical(roles._current()),
                                          BINDING)
    node.policy = _policy(units=LOOP + EXPOSURE)
    return node


def _expected_digest(node):
    exposure = cli._measure_exposure(node.evidence)
    observe = {u: (node.units_dir / u).read_bytes() for u in node.policy.observe_units}
    return tree_digest(build_observe_baseline(units=list(node.policy.units),
                                              unit_files=observe, exposure=exposure.section))


def test_publish_writes_a_v2_generation_with_the_section_and_prints_it(exposure_node):
    digest = _expected_digest(exposure_node)
    code, out = exposure_node.publish(digest, "PUBLISH")
    assert code == 0, out
    assert "observe-baseline-generation/v2" in out
    for name, value in HASHES.items():
        assert f"apparmor_policy_hash {name}: {value}" in out
    assert "exposure_prefix_count: 2" in out and "exposure_ingress_count: 1" in out
    store = exposure_node.store
    generation = store.current()
    document = decode_observe_baseline(store.read_tree(generation.number)[OBSERVE_BASELINE_FILE])
    assert document["units"] == list(exposure_node.policy.observe_units)
    assert not set(EXPOSURE) & set(document["unit_files"])
    assert document["exposure"]["apparmor_policy_hashes"] == HASHES
    # No name, prefix or address is printed.
    for leak in ("lan0", "mgmt0", "10.20.0.0", "192.168.10.0"):
        assert leak not in out


@pytest.mark.parametrize("damage", ["absent", "writable", "malformed"])
def test_a_compiled_record_absent_unprotected_or_malformed_refuses_publish(exposure_node,
                                                                            damage):
    record = exposure_node.approvals / "apparmor-compiled.json"
    if damage == "absent":
        record.unlink()
    elif damage == "writable":
        record.chmod(0o666)
    else:
        record.write_bytes(record.read_bytes().replace(b"4.1.0", b"4.1.0\x01"))
    code, out = exposure_node.publish("sha256:" + "0" * 64, "PUBLISH")
    assert code == 1 and "compiled-policy record" in out
    assert exposure_node.store.current() is None


def test_a_v2_proposal_refuses_publish_with_the_stage_code(exposure_node):
    from azazel_nexus.commissioning_approval import commissioning_proposal_payload

    proposal = commissioning_proposal_payload(**roles._node(), mio_profile="FULL")
    exposure_node.evidence = CommissioningEvidence(
        proposal, b"s" * 64, exposure_node.evidence.current_inventory, BINDING)
    code, out = exposure_node.publish("sha256:" + "0" * 64, "PUBLISH")
    assert code == 1 and "deception_scope_absent" in out


def test_request_refuses_part_of_the_tier_and_writes_v3_for_all_three(exposure_node):
    assert exposure_node.publish(_expected_digest(exposure_node), "PUBLISH")[0] == 0
    code, _, err = exposure_node.request(units=",".join(LOOP + EXPOSURE[:2]))
    assert code == 1 and "all three exposure units or none" in err
    code, payload, err = exposure_node.request()
    assert code == 0, err
    assert json.loads(payload)["schema"] == "azazel-nexus/activation-approval/v3"
    assert "--purpose activation-exposure" in err
    code, payload, err = exposure_node.request(units=",".join(LOOP))
    assert code == 0 and json.loads(payload)["schema"] == "azazel-nexus/activation-approval/v2"


def test_request_refuses_after_an_exposure_file_changes(exposure_node):
    assert exposure_node.publish(_expected_digest(exposure_node), "PUBLISH")[0] == 0
    path = exposure_node.units_dir / "azazel-decoy-verify.timer"
    path.chmod(0o644)
    path.write_bytes(path.read_bytes() + b"#\n")
    code, _, err = exposure_node.request()
    assert code == 1
    # The reader the pass's P9 uses refuses it as content, not as unreadable.
    with pytest.raises(scoped_unit_files.UnitContentRefused):
        exposure_generation.measure_exposure_section_inputs()


def test_publish_request_sign_install_then_one_pass_grants_the_tier(exposure_node,
                                                                    monkeypatch):
    from azazel_nexus.activation_store import _read_at, verify_activation_approval_v2_or_v3
    from azazel_nexus_runtime import activated, activation_markers
    from azazel_nexus_runtime import activation_high_water as hw
    from azazel_nexus_runtime.activation_pass import PassProducers
    from azazel_nexus_runtime.units import RecordingUnitManager
    from azazel_nexus.activation import EdgeBaselineState
    import test_runtime_exposure_pass as tex

    node = exposure_node
    assert node.publish(_expected_digest(node), "PUBLISH")[0] == 0
    code, payload, _ = node.request()
    assert code == 0
    signature, facts = operator_sign.sign(
        purpose="activation-exposure", payload=payload,
        expect_payload_sha256=hashlib.sha256(payload).hexdigest(),
        seed=bytes(node.key), expect_public=bytes(node.key.verify_key).hex())
    assert facts["exposure"] == operator_sign.EXPOSURE_NOTICE
    code, out = node.install(payload, signature)
    assert code == 0, out
    assert node.events()[-1]["schema"] == "azazel-nexus/activation-approval/v3"

    def approval(**kwargs):
        fd = os.open(node.approvals, os.O_RDONLY | os.O_DIRECTORY)
        try:
            stored, stored_signature = _read_at(fd, owner=os.getuid())
        finally:
            os.close(fd)
        return verify_activation_approval_v2_or_v3(
            trust=node.trust, payload=stored, signature=stored_signature, **kwargs)

    host = tex.ExposureWorld.clean_host(type("Files", (), dict(
        exposure_unit_files={}, watch_unit_files={}, profile_files={}))())
    host["policy_hashes"] = tuple((name.encode() + b"\n", value.encode() + b"\n")
                                  for name, value in HASHES.items())
    readers = {name: (lambda value=value: lambda *args: value)()
               for name, value in host.items()}
    readers["section_inputs"] = exposure_generation.measure_exposure_section_inputs
    producers = PassProducers(
        commissioning_evidence=lambda: node.evidence,
        declared_node=lambda: node.node,
        deployment=lambda: node.declaration,
        policy=lambda: node.policy,
        high_water=hw.require_high_water_for_pass,
        unit_files=scoped_unit_files.measure_scoped_unit_files,
        loaded_units=lambda units: None,
        approval=approval,
        health=lambda policy, ledger: (True, (("state_capacity", "ok"),)),
        raise_high_water=hw.raise_high_water,
        edge_package_digest=lambda: pytest.fail("edge-core is not in this scope"),
        edge_state=lambda *, now: EdgeBaselineState(False, False, False, False, False),
        edge_components=lambda: pytest.fail("edge-core is not in this scope"),
        exposure=tex.ExposureReaders(**readers),
    )
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    (node.root / "run/azazel-activation").mkdir(parents=True)
    (node.root / "run/azazel-activation").chmod(0o755)
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)

    outcome = activated._run_once(manager=manager, root=node.root, now=NOW,
                                  actor="azazel-activated", producers=producers)
    expected = sorted(LOOP + EXPOSURE)
    assert sorted(outcome.granted) == expected
    for unit in EXPOSURE:
        assert manager.state(unit) is UnitState.ENABLED
    run = node.root / "run/azazel-activation"
    assert sorted(p.name for p in (run / "granted").iterdir()) == expected
    scope_file = (run / "decoy-scope.json").read_bytes()
    digest = "sha256:" + hashlib.sha256(scope_file).hexdigest()
    assert json.loads(payload)["exposure_scope_digest"] == digest
    assert (run / "decoy-scope.digest").read_bytes() == (digest + "\n").encode()
    assert node.events()[-1]["observed_inputs"]["exposure_evidence"] == "established"
