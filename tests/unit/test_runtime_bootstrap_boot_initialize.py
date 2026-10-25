"""approval-install and the one-session boot-initialize, on ordinary temp files.

approval-install verifies with the bootstrap admission's own verifier before
anything changes, moves only a prior boot's pair aside (recorded first) and
never replaces this boot's pair. boot-initialize keeps every confirmation, skips
steps already complete for this boot and reports where it stopped.
"""

import ast
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
from io import BytesIO, StringIO
import fcntl
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from azazel_nexus import activation_store
from azazel_nexus import bootstrap_approval_install as install
from azazel_nexus.bootstrap_approval import (
    BootstrapApprovalPolicy, BootstrapContext, bootstrap_payload,
)
from azazel_nexus.bootstrap_clock import AdministratorTimeAnchor, encode_administrator_anchor
from azazel_nexus.bootstrap_clock_store import TimeDurabilityUncertain
from azazel_nexus.bootstrap_prior_boot import EVENT_TYPE, retired_name
from azazel_nexus.bootstrap_selection import BootstrapSelection, encode_bootstrap_selection
from azazel_nexus.bootstrap_selection_store import SelectionReadRefused
from azazel_nexus.operator_trust import (
    ApprovalPurpose, ApprovalRefused, OperatorTrust, approval_message,
)
from azazel_nexus_runtime import bootstrap_cli as cli
from azazel_nexus_runtime.bootstrap_declared_context import DeclaredBootstrapContext

REPO = Path(__file__).resolve().parents[2]
DIGEST = "sha256:" + "a" * 64
OPERATOR = "operator-a"
POLICY = BootstrapApprovalPolicy(frozenset({OPERATOR}), 600)
BOOT = "11111111-1111-4111-8111-111111111111"
PRIOR = "33333333-3333-4333-8333-333333333333"
CONTEXT = BootstrapContext(
    approval_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", node_digest=DIGEST, boot_id=BOOT,
    generation=1, generation_digest=DIGEST, package_digest=DIGEST, unit_closure_digest=DIGEST,
    policy_digest=DIGEST, approval_policy_digest=POLICY.digest(), security_epoch=7,
    revocation_digest=DIGEST,
)
SELECTED = DeclaredBootstrapContext(CONTEXT, OPERATOR, DIGEST)
GRANTED, EXPIRES = "2026-10-26T00:00:00Z", "2026-10-26T00:05:00Z"
WINDOW = SimpleNamespace(earliest_utc="2026-10-26T00:01:00Z", latest_utc="2026-10-26T00:01:10Z")
KEY = SigningKey(b"\x07" * 32)
TRUST = OperatorTrust({OPERATOR: bytes(KEY.verify_key)})


def _pair(context=CONTEXT, *, granted=GRANTED, expires=EXPIRES, key=KEY):
    payload = bootstrap_payload(context=context, operator=OPERATOR, granted_at=granted,
                                expires_at=expires)
    message = approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    return payload, key.sign(message).signature


def _snapshot(root):
    return {entry.name: entry.read_bytes() for entry in sorted(root.iterdir())}


def _write(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


@pytest.fixture
def node(tmp_path, monkeypatch):
    root = tmp_path / "bootstrap"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    supplied = tmp_path / "supplied"
    supplied.mkdir()
    uid = os.getuid()

    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(install, "_bootstrap_directory", directory)
    monkeypatch.setattr(install, "_read_file_at", lambda fd, name, *, owner, limit:
                        activation_store._read_file_at(fd, name, owner=uid, limit=limit))
    monkeypatch.setattr(install, "_private_directory", lambda fd, *, owner:
                        activation_store._private_directory(fd, owner=uid))
    state = SimpleNamespace(root=root, supplied=supplied, events=[], record=True,
                            verifications=0, fail_verification_at=None)

    def record(event):
        state.events.append(event)
        if state.record is not True:
            raise OSError("ledger unavailable")
        return True

    def window(*, expected):
        # Read once per verification: the CLI's, then each recheck's.
        assert expected == CONTEXT
        state.verifications += 1
        if state.verifications == state.fail_verification_at:
            raise ApprovalRefused("protected administrator time refused")
        return WINDOW

    monkeypatch.setattr(cli, "_is_root", lambda: True)
    monkeypatch.setattr(cli, "_record_activation_event", record)
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: SELECTED)
    monkeypatch.setattr(cli, "_load_approval_policy", lambda: POLICY)
    monkeypatch.setattr(cli, "load_operator_trust", lambda: TRUST)
    monkeypatch.setattr(cli, "load_administrator_time_window", window)
    return state


def _run_install(state, payload, signature, monkeypatch, *, confirm=None):
    _write(state.supplied / "approval.json", payload)
    _write(state.supplied / "approval.sig", signature)
    out = StringIO()
    monkeypatch.setattr(cli.sys, "stdout", out)
    code = cli.main(["approval-install", "--payload", str(state.supplied / "approval.json"),
                     "--signature", str(state.supplied / "approval.sig"),
                     "--confirm-sha256", confirm or sha256(payload).hexdigest()])
    return code, out.getvalue()


def test_install_verifies_then_places_private_pair_and_records(node, monkeypatch):
    payload, signature = _pair()

    code, output = _run_install(node, payload, signature, monkeypatch)

    assert code == 0, output
    assert _snapshot(node.root) == {"approval.json": payload, "approval.sig": signature}
    for name in ("approval.json", "approval.sig"):
        info = (node.root / name).stat()
        assert info.st_mode & 0o777 == 0o600 and info.st_nlink == 1
    [event] = node.events
    assert event == {"event_type": "activation.bootstrap_approval_installed", "operator": OPERATOR,
                     "granted_at": GRANTED, "expires_at": EXPIRES,
                     "payload_sha256": "sha256:" + sha256(payload).hexdigest()}
    assert "NOT admission" in output


def _other_key():
    return SigningKey(b"\x09" * 32)


@pytest.mark.parametrize("case", [
    "wrong-signer", "other-boot-context", "window-before-grant", "window-after-expiry",
    "unauthorized-operator", "confirm-differs", "short-signature", "not-root",
    "noncanonical-payload",
])
def test_verifier_or_input_refusal_changes_nothing(node, monkeypatch, case):
    prior_payload, prior_signature = _pair(replace(CONTEXT, boot_id=PRIOR))
    _write(node.root / "approval.json", prior_payload)
    _write(node.root / "approval.sig", prior_signature)
    before = _snapshot(node.root)
    payload, signature = _pair()
    confirm = None
    if case == "wrong-signer":
        payload, signature = _pair(key=_other_key())
    elif case == "other-boot-context":
        payload, signature = prior_payload, prior_signature
    elif case == "window-before-grant":
        payload, signature = _pair(granted="2026-10-26T00:01:05Z")
    elif case == "window-after-expiry":
        payload, signature = _pair(expires="2026-10-26T00:01:05Z")
    elif case == "unauthorized-operator":
        monkeypatch.setattr(cli, "_load_approval_policy",
                            lambda: BootstrapApprovalPolicy(frozenset({"operator-b"}), 600))
    elif case == "confirm-differs":
        confirm = "0" * 64
    elif case == "short-signature":
        signature = signature[:63]
    elif case == "not-root":
        monkeypatch.setattr(cli, "_is_root", lambda: False)
    elif case == "noncanonical-payload":
        payload = payload + b" "

    code, output = _run_install(node, payload, signature, monkeypatch, confirm=confirm)

    assert code == 1, output
    assert "Nothing admitted" in output
    assert _snapshot(node.root) == before
    assert node.events == []


def test_prior_boot_pair_is_recorded_then_moved_aside(node, monkeypatch):
    prior_payload, prior_signature = _pair(replace(CONTEXT, boot_id=PRIOR))
    _write(node.root / "approval.json", prior_payload)
    _write(node.root / "approval.sig", prior_signature)
    payload, signature = _pair()

    code, output = _run_install(node, payload, signature, monkeypatch)

    assert code == 0, output
    assert _snapshot(node.root) == {
        "approval.json": payload, "approval.sig": signature,
        retired_name(PRIOR, "approval.json"): prior_payload,
        retired_name(PRIOR, "approval.sig"): prior_signature,
    }
    retire, installed = node.events
    assert (retire["event_type"], retire["record"], retire["boot_id"], retire["current_boot_id"]) == (
        EVENT_TYPE, "approval", PRIOR, BOOT)
    assert sorted(retire["files"]) == ["approval.json", "approval.sig"]
    assert installed["event_type"] == "activation.bootstrap_approval_installed"


@pytest.mark.parametrize("case", [
    "same-boot-pair", "payload-only", "signature-only", "partial-present",
    "prior-noncanonical", "prior-signature-size", "record-fails", "archive-present",
])
def test_existing_state_refusal_changes_nothing(node, monkeypatch, case):
    prior_payload, prior_signature = _pair(replace(CONTEXT, boot_id=PRIOR))
    payload, signature = _pair()
    if case == "same-boot-pair":
        same_payload, same_signature = _pair(expires="2026-10-26T00:04:00Z")
        _write(node.root / "approval.json", same_payload)
        _write(node.root / "approval.sig", same_signature)
    elif case == "payload-only":
        _write(node.root / "approval.json", prior_payload)
    elif case == "signature-only":
        _write(node.root / "approval.sig", prior_signature)
    elif case == "partial-present":
        _write(node.root / ".approval.json.partial", b"x")
    elif case == "prior-noncanonical":
        _write(node.root / "approval.json", prior_payload + b"\n")
        _write(node.root / "approval.sig", prior_signature)
    elif case == "prior-signature-size":
        _write(node.root / "approval.json", prior_payload)
        _write(node.root / "approval.sig", prior_signature[:32])
    elif case == "record-fails":
        _write(node.root / "approval.json", prior_payload)
        _write(node.root / "approval.sig", prior_signature)
        node.record = False
    elif case == "archive-present":
        _write(node.root / "approval.json", prior_payload)
        _write(node.root / "approval.sig", prior_signature)
        _write(node.root / retired_name(PRIOR, "approval.sig"), b"older")
    before = _snapshot(node.root)

    code, output = _run_install(node, payload, signature, monkeypatch)

    assert code == 1, output
    assert _snapshot(node.root) == before
    assert [e for e in node.events if e["event_type"] == "activation.bootstrap_approval_installed"] == []
    if case != "record-fails":
        assert node.events == []


def test_verification_lost_before_rename_removes_partials(node, monkeypatch):
    payload, signature = _pair()
    # 1: CLI verification, 2: recheck before any change, 3: recheck before rename.
    node.fail_verification_at = 3

    code, output = _run_install(node, payload, signature, monkeypatch)

    assert code == 1, output
    assert _snapshot(node.root) == {}
    assert node.events == []


def test_refusal_after_prior_pair_moved_aside_says_so_and_exits_two(node, monkeypatch):
    prior_payload, prior_signature = _pair(replace(CONTEXT, boot_id=PRIOR))
    _write(node.root / "approval.json", prior_payload)
    _write(node.root / "approval.sig", prior_signature)
    node.fail_verification_at = 3  # the verification before the rename

    code, output = _run_install(node, *_pair(), monkeypatch)

    assert code == 2, output
    assert "AFTER the prior boot's approval pair was recorded as retiring" in output
    assert _snapshot(node.root) == {
        retired_name(PRIOR, "approval.json"): prior_payload,
        retired_name(PRIOR, "approval.sig"): prior_signature,
    }
    assert [e["event_type"] for e in node.events] == [EVENT_TYPE]


def test_verification_failure_before_change_leaves_prior_pair(node, monkeypatch):
    prior_payload, prior_signature = _pair(replace(CONTEXT, boot_id=PRIOR))
    _write(node.root / "approval.json", prior_payload)
    _write(node.root / "approval.sig", prior_signature)
    before = _snapshot(node.root)
    node.fail_verification_at = 2

    code, output = _run_install(node, _pair()[0], _pair()[1], monkeypatch)

    assert code == 1, output
    assert _snapshot(node.root) == before and node.events == []


def test_install_options_are_exclusive_to_approval_install():
    with pytest.raises(SystemExit) as missing:
        cli.main(["approval-install", "--payload", "x"])
    assert missing.value.code == 2
    with pytest.raises(SystemExit) as stray:
        cli.main(["boot-initialize", "--payload", "x"])
    assert stray.value.code == 2


# -- boot-initialize ----------------------------------------------------------


class Terminal:
    def __init__(self, data: bytes, tty=True):
        self.buffer = BytesIO(data)
        self._tty = tty

    def isatty(self):
        return self._tty


SELECTION = encode_bootstrap_selection(BootstrapSelection(
    DIGEST, BOOT, CONTEXT.approval_id, CONTEXT.generation, CONTEXT.generation_digest))
ANCHOR = encode_administrator_anchor(AdministratorTimeAnchor(
    DIGEST, DIGEST, BOOT, "2026-10-26T00:01:00Z", "2026-10-26T00:01:10Z", 1, 10**12))
VALIDITY = json.dumps({"expires_at": EXPIRES, "granted_at": GRANTED},
                      sort_keys=True, separators=(",", ":")).encode()


def _selection_lines(digest=None, word=b"INITIALIZE"):
    digest = sha256(SELECTION).hexdigest().encode() if digest is None else digest
    return SELECTION + b"\n" + digest + b"\n" + word + b"\n"


def _time_lines(digest=None, word=b"INITIALIZE"):
    if digest is None:
        digest = cli.selected_time_digest(raw=ANCHOR, selected=SELECTED, recovery=False).encode()
    return ANCHOR + b"\n" + digest + b"\n" + word + b"\n"


@pytest.fixture
def session(monkeypatch):
    state = SimpleNamespace(selection=None, time=None, approval=False, calls=[],
                            time_failure=None)

    def load_selection():
        if state.selection is None:
            raise SelectionReadRefused("boot binding differs from the current boot")
        return state.selection

    def initialize_selection(raw, **kwargs):
        state.calls.append(("selection", kwargs))
        state.selection = raw

    def window(*, expected):
        assert expected == CONTEXT
        if state.time is None:
            raise ApprovalRefused("protected administrator time refused")
        return WINDOW

    def publish_time(**kwargs):
        state.calls.append(("time", kwargs))
        if state.time_failure is not None:
            raise state.time_failure
        state.time = kwargs["raw"]

    def approval(**kwargs):
        if not state.approval:
            raise ApprovalRefused("protected bootstrap approval refused")

    monkeypatch.setattr(cli, "load_bootstrap_selection", load_selection)
    monkeypatch.setattr(cli, "initialize_bootstrap_selection", initialize_selection)
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: SELECTED)
    monkeypatch.setattr(cli, "load_administrator_time_window", window)
    monkeypatch.setattr(cli, "publish_selected_administrator_time", publish_time)
    monkeypatch.setattr(cli, "load_bootstrap_approval", approval)
    monkeypatch.setattr(cli, "_load_approval_policy", lambda: POLICY)
    return state


def _boot_initialize(data, tty=True):
    out = StringIO()
    code = cli.run_boot_initialize(source=Terminal(data, tty), out=out)
    return code, out.getvalue()


def test_one_session_runs_each_step_with_its_own_confirmations(session):
    code, output = _boot_initialize(_selection_lines() + _time_lines() + VALIDITY + b"\n")

    assert code == 0, output
    (first, selection_kwargs), (second, time_kwargs) = session.calls
    assert (first, second) == ("selection", "time")
    assert selection_kwargs == {"confirmed_sha256": sha256(SELECTION).hexdigest(),
                                "confirmed_initialize": True,
                                "record_prior_boot": cli._record_prior_boot}
    assert time_kwargs["confirmed_operation"] is True and time_kwargs["recovery"] is False
    assert time_kwargs["record_prior_boot"] is cli._record_prior_boot
    payload = bootstrap_payload(context=CONTEXT, operator=OPERATOR, granted_at=GRANTED,
                                expires_at=EXPIRES)
    assert payload.decode() in output
    assert "approval-install --payload approval.json --signature approval.sig " \
           "--confirm-sha256 " + sha256(payload).hexdigest() in output
    assert output.index("Step 1/3") < output.index("Step 2/3") < output.index("Step 3/3")
    assert "No approval was signed or placed" in output


@pytest.mark.parametrize("case", ["selection-digest", "selection-word", "time-digest",
                                  "time-word", "not-tty", "validity"])
def test_every_confirmation_is_still_required(session, case):
    data = {
        "selection-digest": _selection_lines(digest=b"0" * 64),
        "selection-word": _selection_lines(word=b"YES"),
        "time-digest": _selection_lines() + _time_lines(digest=b"sha256:" + b"0" * 64),
        "time-word": _selection_lines() + _time_lines(word=b"YES"),
        "not-tty": _selection_lines() + _time_lines() + VALIDITY + b"\n",
        "validity": _selection_lines() + _time_lines() + b'{"granted_at":"x"}\n',
    }[case]

    code, output = _boot_initialize(data, tty=case != "not-tty")

    assert code == 1, output
    published = [name for name, _ in session.calls]
    expected = {"selection-digest": [], "selection-word": [], "time-digest": ["selection"],
                "time-word": ["selection"], "not-tty": [],
                "validity": ["selection", "time"]}[case]
    assert published == expected
    assert "Re-run az-nexus-bootstrap boot-initialize" in output


def test_rerun_continues_from_the_step_that_stopped(session):
    session.time_failure = ApprovalRefused("existing time state requires administrator review")
    code, output = _boot_initialize(_selection_lines() + _time_lines())

    assert code == 1
    assert ("Stopped at step 'time' (refused; inspect retained state). Completed for this "
            "boot: selection.") in output

    session.time_failure = None
    session.calls.clear()
    # The selection step reads the published selection and asks nothing.
    code, output = _boot_initialize(_time_lines() + VALIDITY + b"\n")

    assert code == 0, output
    assert [name for name, _ in session.calls] == ["time"]
    assert "Selection for this boot already published; skipped." in output

    session.calls.clear()
    session.approval = True
    code, output = _boot_initialize(b"")
    assert code == 0, output
    assert session.calls == []
    assert "already valid; skipped" in output and "already installed; skipped" in output


def test_selection_refusal_other_than_absent_or_prior_boot_stops_without_prompting(
        session, monkeypatch):
    def pending():
        raise SelectionReadRefused("selection unreadable or protection refused")

    monkeypatch.setattr(cli, "load_bootstrap_selection", pending)
    code, output = _boot_initialize(_selection_lines())

    assert code == 1 and session.calls == []
    assert "Enter canonical per-boot selection" not in output
    assert "Stopped at step 'selection'" in output and "Completed for this boot: none" in output


def test_durability_uncertainty_exits_two_and_says_do_not_retry(session):
    session.time_failure = TimeDurabilityUncertain("uncertain")
    code, output = _boot_initialize(_selection_lines() + _time_lines())

    assert code == 2
    assert "do not retry automatically" in output


def test_standalone_time_initialize_also_retires_and_recover_does_not(session, monkeypatch):
    session.selection = SELECTION
    out = StringIO()
    assert cli.run_time(source=Terminal(_time_lines()), out=out, recovery=False) == 0
    recover = cli.selected_time_digest(raw=ANCHOR, selected=SELECTED, recovery=True).encode()
    assert cli.run_time(source=Terminal(ANCHOR + b"\n" + recover + b"\nRECOVER\n"), out=out,
                        recovery=True) == 0
    (_, initialize), (_, recovery) = session.calls
    assert initialize["record_prior_boot"] is cli._record_prior_boot
    assert "record_prior_boot" not in recovery


# -- operator documentation ---------------------------------------------------


def _operations():
    tree = ast.parse((REPO / "runtime" / "src" / "azazel_nexus_runtime"
                      / "bootstrap_cli.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "add_argument"
                and node.args and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "operation"):
            [choices] = [k.value for k in node.keywords if k.arg == "choices"]
            return {element.value for element in choices.elts}
    raise AssertionError("operation choices not found")


def test_install_procedure_names_only_existing_operations_and_the_new_flow():
    text = (REPO / "docs" / "debian-live-install.md").read_text(encoding="utf-8")
    named = set(re.findall(r"az-nexus-bootstrap ([a-z][a-z-]+)", text))
    assert {"boot-initialize", "approval-install"} <= named
    assert named <= _operations()
    for flag in re.findall(r"approval-install((?: --[a-z0-9-]+ [A-Za-z0-9_.]+)+)", text):
        assert set(re.findall(r"--([a-z0-9-]+)", flag)) == {"payload", "signature",
                                                            "confirm-sha256"}
