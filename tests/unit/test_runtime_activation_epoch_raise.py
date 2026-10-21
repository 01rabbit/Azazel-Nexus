"""`az-activation epoch-request` / `epoch-raise` (#251, design §11).

Temporary roots and in-memory ephemeral keys only, on the same fixtures as
`test_runtime_activation_cli.py`. The declaration store is a seam here
(`_raise_declaration`); its own replacement is tested on ordinary files in
`test_bootstrap_deployment_epoch_raise.py`.
"""

import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from azazel_nexus.activation_approval_v2 import verify_observe_baseline_approval
from azazel_nexus.activation_epoch import (
    EpochRaise,
    decode_epoch_raise,
    encode_epoch_raise,
    epoch_raise_request,
    verify_epoch_raise,
)
from azazel_nexus.operator_trust import (
    ApprovalPurpose,
    ApprovalRefused,
    OperatorTrust,
    approval_message,
)
from azazel_nexus_runtime import activation_cli as cli
from azazel_nexus_runtime import activation_high_water as hw
from azazel_nexus_runtime import activation_unit_files as scoped_unit_files
from test_runtime_activation_cli import (  # noqa: F401 - fixtures
    LOOP, NOW, Tty, _declaration, _high_water, node, published,
)


def _epoch_sign(node, payload, *, key=None, purpose=ApprovalPurpose.ACTIVATION_EPOCH_RAISE):
    return (key or node.key).sign(approval_message(purpose, payload)).signature


def _request(node, to_epoch, *, operator="operator-a"):
    directory = node.root.parent / "epoch-requests"
    directory.mkdir(mode=0o755, exist_ok=True)
    node._epoch = getattr(node, "_epoch", 0) + 1
    target = directory / f"epoch-{node._epoch}.json"
    stderr = io.StringIO()
    code = cli.run_epoch_request(operator=operator, to_epoch=to_epoch,
                                 out_path=str(target), stderr=stderr)
    return code, (target.read_bytes() if target.exists() else b""), stderr.getvalue()


def _raise(node, payload, signature, *lines, tty=True):
    directory = node.root.parent / "epoch-incoming"
    directory.mkdir(exist_ok=True)
    (directory / "epoch.json").write_bytes(payload)
    (directory / "epoch.sig").write_bytes(signature)
    if not lines:
        lines = (hashlib.sha256(payload).hexdigest(), "RAISE")
    out = io.StringIO()
    code = cli.run_epoch_raise(payload_path=str(directory / "epoch.json"),
                               signature_path=str(directory / "epoch.sig"),
                               source=Tty(*lines, tty=tty), out=out)
    return code, out.getvalue()


@pytest.fixture
def installed(published, monkeypatch):
    """An installed approval at epoch 2, seq 5; the declaration store is a seam."""
    calls = []

    def replace_declaration(current, to_epoch):
        assert current == published.declaration
        calls.append(to_epoch)
        published.declaration = dataclasses.replace(current, security_epoch=to_epoch)

    monkeypatch.setattr(cli, "_raise_declaration", replace_declaration)
    published.declaration_raises = calls
    payload, signature = published.approved()
    code, out = published.install(payload, signature)
    assert code == 0, out
    published.old = (payload, signature)
    return published


def _snapshot(node):
    return (node.declaration, _high_water(node), len(node.events()),
            sorted(p.name for p in node.approvals.iterdir()))


# -- the payload and its signature ---------------------------------------------


def test_payload_binds_node_declaration_and_both_epochs():
    declaration = _declaration(epoch=2)
    value = epoch_raise_request(declaration, operator="operator-a", to_epoch=3)
    raw = encode_epoch_raise(value)
    document = json.loads(raw)
    assert document == {
        "schema": "azazel-nexus/activation-epoch-raise/v1", "operator": "operator-a",
        "node_digest": declaration.node_digest,
        "deployment_digest": value.deployment_digest, "from_epoch": 2, "to_epoch": 3}
    assert decode_epoch_raise(raw) == value
    for bad in (raw + b"\n", raw.replace(b'"to_epoch":3', b'"to_epoch":true'),
                raw.replace(b'"to_epoch":3', b'"to_epoch":3.0'),
                json.dumps(document, indent=1).encode()):
        with pytest.raises(ApprovalRefused):
            decode_epoch_raise(bad)


@pytest.mark.parametrize("to_epoch", [2, 1, 0, 2**63])
def test_only_a_raise_is_a_payload(to_epoch):
    with pytest.raises(ApprovalRefused):
        epoch_raise_request(_declaration(epoch=2), operator="operator-a", to_epoch=to_epoch)
    with pytest.raises(ApprovalRefused):
        EpochRaise("operator-a", "sha256:" + "a" * 64, "sha256:" + "b" * 64, 2, to_epoch)
    lowered = json.dumps({
        "schema": "azazel-nexus/activation-epoch-raise/v1", "operator": "operator-a",
        "node_digest": "sha256:" + "a" * 64, "deployment_digest": "sha256:" + "b" * 64,
        "from_epoch": 2, "to_epoch": to_epoch}, sort_keys=True, separators=(",", ":"))
    with pytest.raises(ApprovalRefused):
        decode_epoch_raise(lowered.encode())


def test_purposes_stay_separate_both_ways():
    key = SigningKey.generate()
    trust = OperatorTrust({"operator-a": bytes(key.verify_key)})
    declaration = _declaration(epoch=2)
    payload = encode_epoch_raise(epoch_raise_request(declaration, operator="operator-a",
                                                     to_epoch=3))
    arguments = dict(trust=trust, payload=payload, deployment=declaration,
                     authorized_operators=frozenset({"operator-a"}))
    good = key.sign(approval_message(ApprovalPurpose.ACTIVATION_EPOCH_RAISE, payload)).signature
    assert verify_epoch_raise(signature=good, **arguments).to_epoch == 3
    for purpose in ApprovalPurpose:
        if purpose is not ApprovalPurpose.ACTIVATION_EPOCH_RAISE:
            with pytest.raises(ApprovalRefused):
                verify_epoch_raise(signature=key.sign(approval_message(purpose, payload))
                                   .signature, **arguments)
    with pytest.raises(ApprovalRefused):  # another key
        verify_epoch_raise(signature=SigningKey.generate().sign(approval_message(
            ApprovalPurpose.ACTIVATION_EPOCH_RAISE, payload)).signature, **arguments)
    with pytest.raises(ApprovalRefused):  # enrolled, not authorized by the policy
        verify_epoch_raise(signature=good, **(arguments | {
            "authorized_operators": frozenset({"operator-b"})}))
    with pytest.raises(ApprovalRefused):  # revoked
        verify_epoch_raise(signature=good, **(arguments | {"trust": OperatorTrust(
            {"operator-a": bytes(key.verify_key)}, frozenset({"operator-a"}))}))
    for other in (dataclasses.replace(declaration, security_epoch=3),
                  dataclasses.replace(declaration, policy_digest="sha256:" + "e" * 64),
                  _declaration(epoch=2, node="node-b")):
        with pytest.raises(ApprovalRefused):
            verify_epoch_raise(signature=good, **(arguments | {"deployment": other}))


# -- epoch-request -------------------------------------------------------------


def test_request_writes_the_payload_only_and_refuses_no_raise(installed):
    before = _snapshot(installed)
    code, payload, err = _request(installed, 3)
    assert code == 0, err
    assert decode_epoch_raise(payload).from_epoch == 2
    assert f"payload_sha256: {hashlib.sha256(payload).hexdigest()}" in err
    for to_epoch in (2, 1):
        code, written, err = _request(installed, to_epoch)
        assert code == 1 and written == b"" and "above the declared epoch" in err
    code, _, err = _request(installed, 3, operator="operator-b")
    assert code == 1 and "not authorized" in err
    assert _snapshot(installed) == before


# -- epoch-raise ---------------------------------------------------------------


def test_raise_raises_floor_and_declaration_records_and_ends_old_approvals(installed):
    code, payload, _ = _request(installed, 3)
    assert code == 0
    code, out = _raise(installed, payload, _epoch_sign(installed, payload))
    assert code == 0, out
    assert "security_epoch: 2 -> 3" in out and "stops verifying" in out
    assert installed.declaration.security_epoch == 3
    assert installed.declaration_raises == [3]
    floor = _high_water(installed)
    assert (floor["security_epoch"], floor["approval_seq"], floor["generation"]) == (3, 5, 1)
    event = installed.events()[-1]
    assert event["event_type"] == "activation.epoch_raised"
    assert (event["from_epoch"], event["to_epoch"], event["operator"]) == (2, 3, "operator-a")
    assert event["payload_sha256"] == "sha256:" + hashlib.sha256(payload).hexdigest()
    assert event["high_water"]["security_epoch"] == 3
    assert "activation.epoch_raised" in cli.FLOOR_EVENTS
    assert cli._ledger_history() == (True, (3, 5, 1))

    # The installed approval (epoch 2) no longer verifies: not against the
    # raised declaration, and not against the old one under the raised floor.
    old_payload, old_signature = installed.old
    context = cli._collect_context()
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(
            trust=installed.trust, expected=context.context, policy=context.approval_policy,
            payload=old_payload, signature=old_signature, now=NOW,
            security_epoch_floor=3, approval_seq_floor=5)
    with pytest.raises(ApprovalRefused):
        verify_observe_baseline_approval(
            trust=installed.trust,
            expected=dataclasses.replace(context.context, security_epoch=2),
            policy=context.approval_policy, payload=old_payload, signature=old_signature,
            now=NOW, security_epoch_floor=3, approval_seq_floor=5)
    code, out = installed.install(old_payload, old_signature, "REPLACE", replace=True)
    assert code == 1
    # A new approval at the new epoch, above the sequence floor, installs.
    payload, signature = installed.approved(seq=6, approval_id="approval-6")
    assert json.loads(payload)["security_epoch"] == 3
    code, out = installed.install(payload, signature, "REPLACE", replace=True)
    assert code == 0, out


def test_raise_twice_with_the_same_payload_is_refused(installed):
    code, payload, _ = _request(installed, 3)
    signature = _epoch_sign(installed, payload)
    assert _raise(installed, payload, signature)[0] == 0
    before = _snapshot(installed)
    code, out = _raise(installed, payload, signature)
    assert code == 1 and "does not match the current declaration" in out
    code, _, err = _request(installed, 3)
    assert code == 1 and "above the declared epoch" in err
    assert _snapshot(installed) == before
    assert installed.declaration_raises == [3]


@pytest.mark.parametrize("case", ["missing", "empty", "short", "other_key",
                                  "activation_purpose", "other_payload"])
def test_missing_or_false_signature_changes_nothing(installed, case):
    code, payload, _ = _request(installed, 3)
    signature = {
        "empty": b"",
        "short": b"\0" * 63,
        "other_key": _epoch_sign(installed, payload, key=SigningKey.generate()),
        "activation_purpose": _epoch_sign(installed, payload,
                                          purpose=ApprovalPurpose.ACTIVATION),
        "other_payload": _epoch_sign(installed, payload.replace(b'"to_epoch":3',
                                                                b'"to_epoch":4')),
        "missing": b"x" * 64,
    }[case]
    before = _snapshot(installed)
    if case == "missing":
        directory = installed.root.parent / "epoch-missing"
        directory.mkdir()
        (directory / "epoch.json").write_bytes(payload)
        out = io.StringIO()
        code = cli.run_epoch_raise(payload_path=str(directory / "epoch.json"),
                                   signature_path=str(directory / "absent.sig"),
                                   source=Tty(hashlib.sha256(payload).hexdigest(), "RAISE"),
                                   out=out)
        out = out.getvalue()
    else:
        code, out = _raise(installed, payload, signature)
    assert code == 1 and "Nothing changed" in out, out
    assert _snapshot(installed) == before
    assert installed.declaration_raises == []


def test_a_payload_for_another_node_or_declaration_is_refused(installed):
    for declaration in (_declaration(epoch=2, node="node-b"),
                        dataclasses.replace(installed.declaration,
                                            revocation_digest="sha256:" + "f" * 64)):
        payload = encode_epoch_raise(epoch_raise_request(declaration, operator="operator-a",
                                                         to_epoch=3))
        code, out = _raise(installed, payload, _epoch_sign(installed, payload))
        assert code == 1 and "does not match the current declaration" in out
    assert installed.declaration_raises == []


def test_raise_below_the_high_water_epoch_is_refused(installed):
    floor = hw.read_high_water()
    hw.raise_high_water(dataclasses.replace(floor, security_epoch=5), now=NOW, skew_seconds=0)
    code, _, err = _request(installed, 4)
    assert code == 1 and "high-water epoch floor" in err
    payload = encode_epoch_raise(epoch_raise_request(installed.declaration,
                                                     operator="operator-a", to_epoch=4))
    code, out = _raise(installed, payload, _epoch_sign(installed, payload))
    assert code == 1 and "high-water epoch floor" in out
    assert installed.declaration_raises == []


@pytest.mark.parametrize("lines,tty,label", [
    (("0" * 64, "RAISE"), True, "confirmation differs"),
    (None, True, "not confirmed"),
    (None, False, "interactive terminal"),
])
def test_confirmation_is_required(installed, lines, tty, label):
    code, payload, _ = _request(installed, 3)
    if lines is None:
        lines = (hashlib.sha256(payload).hexdigest(), "raise")
    before = _snapshot(installed)
    code, out = _raise(installed, payload, _epoch_sign(installed, payload), *lines, tty=tty)
    assert code == 1 and label in out
    assert _snapshot(installed) == before


def test_root_and_a_floor_are_required(installed):
    code, payload, _ = _request(installed, 3)
    signature = _epoch_sign(installed, payload)
    installed.root_user = False
    code, out = _raise(installed, payload, signature)
    assert code == 1 and "requires root" in out
    installed.root_user = True
    (installed.state / "activation/high-water.json").unlink()
    code, out = _raise(installed, payload, signature)
    assert code == 1 and "no high-water floor" in out
    assert installed.declaration_raises == []


def test_a_failed_declaration_replacement_after_the_floor_exits_2_and_resumes(
        installed, monkeypatch):
    code, payload, _ = _request(installed, 3)
    signature = _epoch_sign(installed, payload)
    working = cli._raise_declaration

    def fail(current, to_epoch):
        raise ApprovalRefused("injected")

    monkeypatch.setattr(cli, "_raise_declaration", fail)
    code, out = _raise(installed, payload, signature)
    assert code == 2 and "declaration replacement unconfirmed" in out
    # Fail-closed meanwhile: the floor is raised, the declaration is not.
    assert _high_water(installed)["security_epoch"] == 3
    assert installed.declaration.security_epoch == 2
    monkeypatch.setattr(cli, "_raise_declaration", working)
    code, out = _raise(installed, payload, signature)
    assert code == 0, out
    assert installed.declaration.security_epoch == 3


def test_pass_after_raise_and_after_declaration_rollback_grants_nothing(installed, monkeypatch):
    """The pass itself: raised declaration refuses the old approval; a declaration
    put back to the old epoch is below the raised floor."""
    from azazel_nexus.activation import CORE_UNITS, EdgeBaselineState
    from azazel_nexus.activation_store import _read_at
    from azazel_nexus_runtime import activated, activation_markers
    from azazel_nexus_runtime.activation_pass import PassProducers
    from azazel_nexus_runtime.units import RecordingUnitManager

    code, payload, _ = _request(installed, 3)
    assert _raise(installed, payload, _epoch_sign(installed, payload))[0] == 0

    def approval(**kwargs):
        fd = os.open(installed.approvals, os.O_RDONLY | os.O_DIRECTORY)
        try:
            stored, stored_signature = _read_at(fd, owner=os.getuid())
        finally:
            os.close(fd)
        return verify_observe_baseline_approval(
            trust=installed.trust, payload=stored, signature=stored_signature, **kwargs)

    producers = PassProducers(
        commissioning_evidence=lambda: installed.evidence,
        declared_node=lambda: installed.node,
        deployment=lambda: installed.declaration,
        policy=lambda: installed.policy,
        high_water=hw.require_high_water_for_pass,
        unit_files=scoped_unit_files.measure_scoped_unit_files,
        loaded_units=lambda units: None,
        approval=approval,
        health=lambda policy, ledger: (True, (("state_capacity", "ok"),)),
        raise_high_water=hw.raise_high_water,
        edge_package_digest=lambda: pytest.fail("edge-core is not in this scope"),
        edge_state=lambda *, now: EdgeBaselineState(False, False, False, False, False),
        edge_components=lambda: pytest.fail("edge-core is not in this scope"),
    )
    monkeypatch.setattr(activation_markers, "_OWNER", os.getuid())
    monkeypatch.setattr(activated, "_collect_input_status", lambda _root: {})
    (installed.root / "run/azazel-activation").mkdir(parents=True)
    (installed.root / "run/azazel-activation").chmod(0o755)
    manager = RecordingUnitManager(d.name for d in CORE_UNITS)

    def run():
        outcome = activated._run_once(manager=manager, root=installed.root, now=NOW,
                                      actor="azazel-activated", producers=producers)
        return outcome, installed.events()[-1]["observed_inputs"]["producers"]

    outcome, status = run()
    assert not outcome.granted
    assert status["epoch_high_water"] == "verified"
    assert status["activation_approval_loader"] == "failed"

    installed.declaration = dataclasses.replace(installed.declaration, security_epoch=2)
    outcome, status = run()
    assert not outcome.granted
    assert status["epoch_high_water"] == "failed"
    assert _high_water(installed)["security_epoch"] == 3


def test_main_offers_both_commands(installed, monkeypatch, capsys):
    target = Path(installed.root.parent / "main-epoch.json")
    assert cli.main(["epoch-request", "--operator", "operator-a", "--to-epoch", "3",
                     "--out", str(target)]) == 0
    assert decode_epoch_raise(target.read_bytes()).to_epoch == 3
    with pytest.raises(SystemExit):
        cli.main(["epoch-raise", "--payload", str(target)])


# -- review follow-ups (PR #264) -----------------------------------------------


@pytest.mark.parametrize("to_epoch,warned", [(2 + cli.LARGE_EPOCH_STEP, False),
                                             (3 + cli.LARGE_EPOCH_STEP, True)])
def test_a_large_step_is_warned_not_refused(installed, to_epoch, warned):
    code, payload, err = _request(installed, to_epoch)
    assert code == 0
    assert ("WARNING: the epoch rises by" in err) is warned
    code, out = _raise(installed, payload, _epoch_sign(installed, payload))
    assert code == 0, out
    assert ("WARNING: the epoch rises by" in out) is warned
    assert installed.declaration.security_epoch == to_epoch


def test_the_floor_is_raised_before_the_declaration_and_the_record_last(
        installed, monkeypatch):
    order = []
    for name, label in (("raise_high_water", "floor"), ("_raise_declaration", "declaration"),
                        ("_append", "ledger")):
        original = getattr(cli, name)

        def recording(*args, _original=original, _label=label, **kwargs):
            order.append(_label)
            return _original(*args, **kwargs)

        monkeypatch.setattr(cli, name, recording)
    code, payload, _ = _request(installed, 3)
    code, out = _raise(installed, payload, _epoch_sign(installed, payload))
    assert code == 0, out
    assert order == ["floor", "declaration", "ledger"]


def test_declaration_durability_uncertain_exits_2(installed, monkeypatch):
    from azazel_nexus.bootstrap_deployment_store import DeploymentDurabilityUncertain

    def uncertain(current, to_epoch):
        raise DeploymentDurabilityUncertain("injected")

    monkeypatch.setattr(cli, "_raise_declaration", uncertain)
    code, payload, _ = _request(installed, 3)
    events = len(installed.events())
    code, out = _raise(installed, payload, _epoch_sign(installed, payload))
    assert code == 2 and "durability UNCONFIRMED" in out
    assert _high_water(installed)["security_epoch"] == 3
    assert len(installed.events()) == events  # no record: an audit gap (§11)


def test_a_missing_ledger_record_exits_2_after_both_writes(installed, monkeypatch):
    def refuse(event):
        raise OSError("injected ledger failure")

    code, payload, _ = _request(installed, 3)
    events = len(installed.events())
    monkeypatch.setattr(cli, "_append", refuse)
    code, out = _raise(installed, payload, _epoch_sign(installed, payload))
    assert code == 2 and "activation ledger record missing" in out
    assert installed.declaration.security_epoch == 3
    assert _high_water(installed)["security_epoch"] == 3
    assert len(installed.events()) == events


def test_cli_through_the_real_declaration_store(installed, tmp_path, monkeypatch):
    """No declaration seam: epoch-raise replaces a real (temporary) deployment.json."""
    from contextlib import contextmanager

    from azazel_nexus import bootstrap_deployment_store as store
    from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment

    bootstrap = tmp_path / "bootstrap"
    bootstrap.mkdir(mode=0o700)
    bootstrap.chmod(0o700)
    (bootstrap / "deployment.json").write_bytes(
        encode_bootstrap_deployment(installed.declaration))
    (bootstrap / "deployment.json").chmod(0o600)

    @contextmanager
    def directory():
        fd = os.open(bootstrap, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(store, "_bootstrap_directory", directory)
    for name in ("_raise_epoch_at", "_read_at"):
        original = getattr(store, name)

        def local_owner(*args, _operation=original, **kwargs):
            return _operation(*args, **(kwargs | {"owner": os.getuid()}))

        monkeypatch.setattr(store, name, local_owner)
    monkeypatch.setattr(cli, "_load_declaration", store.load_bootstrap_deployment)
    monkeypatch.setattr(cli, "_raise_declaration", cli.raise_bootstrap_deployment_epoch)

    code, payload, err = _request(installed, 3)
    assert code == 0, err
    signature = _epoch_sign(installed, payload)
    code, out = _raise(installed, payload, signature)
    assert code == 0, out
    assert store.load_bootstrap_deployment().security_epoch == 3
    assert sorted(p.name for p in bootstrap.iterdir()) == ["deployment.json"]
    assert installed.events()[-1]["event_type"] == "activation.epoch_raised"
    code, out = _raise(installed, payload, signature)
    assert code == 1 and "does not match the current declaration" in out
