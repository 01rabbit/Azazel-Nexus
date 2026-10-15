"""Read-only approval-request operation: prints bytes to sign off-host, signs nothing."""

from hashlib import sha256
from io import BytesIO, StringIO
import json
import sys

import pytest
from nacl.signing import SigningKey

from azazel_nexus.bootstrap_approval import (
    BootstrapApprovalPolicy, BootstrapContext, bootstrap_payload, verify_bootstrap_approval,
)
from azazel_nexus.operator_trust import (
    ApprovalPurpose, ApprovalRefused, OperatorTrust, approval_message,
)
from azazel_nexus_runtime import bootstrap_cli as cli
from azazel_nexus_runtime.bootstrap_declared_context import DeclaredBootstrapContext

REFUSED = "Approval request refused; no changes made.\n"
DIGEST = "sha256:" + "a" * 64
OPERATOR = "operator-a"
GRANTED, EXPIRES = "2026-10-15T00:00:00Z", "2026-10-15T00:04:00Z"
SECRET = "SECRET-MARKER-9f3"
POLICY = BootstrapApprovalPolicy(frozenset({OPERATOR}), 300)
CONTEXT = BootstrapContext(
    approval_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", node_digest=DIGEST,
    boot_id="11111111-1111-1111-1111-111111111111", generation=1, generation_digest=DIGEST,
    package_digest=DIGEST, unit_closure_digest=DIGEST, policy_digest=DIGEST,
    approval_policy_digest=POLICY.digest(), security_epoch=7, revocation_digest=DIGEST,
)


class FakeInput:
    def __init__(self, data: bytes, *, tty: bool = False):
        self.buffer = BytesIO(data)
        self._tty = tty

    def isatty(self):
        return self._tty


def _line(granted=GRANTED, expires=EXPIRES):
    return json.dumps({"expires_at": expires, "granted_at": granted},
                      sort_keys=True, separators=(",", ":")).encode() + b"\n"


@pytest.fixture
def protected(monkeypatch):
    state = {"operator": OPERATOR, "policy": POLICY, "context": CONTEXT}

    def context():
        if state["context"] is None:
            raise ApprovalRefused(SECRET)
        return DeclaredBootstrapContext(state["context"], state["operator"], DIGEST)

    monkeypatch.setattr(cli, "load_declared_bootstrap_context", context)
    monkeypatch.setattr(cli, "_load_approval_policy", lambda: state["policy"])
    return state


def _run(data, *, tty=False):
    out = StringIO()
    return cli.run_approval_request(source=FakeInput(data, tty=tty), out=out), out.getvalue()


def test_prints_exact_verifier_payload_and_signature_verifies(protected):
    code, text = _run(_line())
    assert code == 0
    lines = text.splitlines()
    payload = bootstrap_payload(context=CONTEXT, operator=OPERATOR,
                                granted_at=GRANTED, expires_at=EXPIRES)
    assert lines[0].encode() == payload
    message = approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    assert message == (b"azazel-nexus/operator-approval/v1\x00supporting-bootstrap\x00" + payload)
    assert lines[1] == "Payload SHA-256: sha256:" + sha256(payload).hexdigest()
    assert lines[2] == ("Signed message = b'azazel-nexus/operator-approval/v1\\x00supporting-bootstrap\\x00' "
                        "+ payload; SHA-256: sha256:" + sha256(message).hexdigest())
    assert "signs nothing and authorizes nothing" in lines[3]
    assert lines[4].startswith("Built from the declared context only:")
    assert "can still make admission refuse" in lines[4]
    assert len(lines) == 5
    # Off-host signing is simulated with an ephemeral key that exists only here.
    key = SigningKey.generate()
    signature = key.sign(message).signature
    verified = verify_bootstrap_approval(
        trust=OperatorTrust({OPERATOR: bytes(key.verify_key)}), expected=CONTEXT, policy=POLICY,
        operator=OPERATOR, payload=lines[0].encode(), signature=signature, now=GRANTED,
    )
    assert verified.operator == OPERATOR


@pytest.mark.parametrize("data", [
    b"", _line()[:-1], _line() + b"x", _line() + b"\n",
    b'{"granted_at":"2026-10-15T00:00:00Z","expires_at":"2026-10-15T00:04:00Z"}\n',
    b'{"expires_at":"2026-10-15T00:04:00Z","granted_at":"2026-10-15T00:00:00Z","x":"1"}\n',
    b'{"expires_at":"2026-10-15T00:04:00Z"}\n',
    b'{"expires_at": "2026-10-15T00:04:00Z", "granted_at": "2026-10-15T00:00:00Z"}\n',
    b'{"expires_at":5,"granted_at":"2026-10-15T00:00:00Z"}\n',
    b'{"expires_at":"2026-10-15T00:04:00+00:00","granted_at":"2026-10-15T00:00:00Z"}\n',
    b"[" * 100000 + b"\n", b"\xff\xfe\n", b"x" * 5000 + b"\n",
])
def test_malformed_input_refused(protected, data):
    assert _run(data) == (1, REFUSED)


def test_tty_refused(protected):
    assert _run(_line(), tty=True) == (1, REFUSED)


def test_expiry_not_after_grant_refused(protected):
    assert _run(_line(expires=GRANTED)) == (1, REFUSED)
    assert _run(_line(expires="2026-10-14T23:59:59Z")) == (1, REFUSED)


def test_over_policy_duration_refused_and_boundary_allowed(protected):
    assert _run(_line(expires="2026-10-15T00:05:01Z")) == (1, REFUSED)
    assert _run(_line(expires="2026-10-15T00:05:00Z"))[0] == 0


def test_operator_not_in_policy_refused(protected):
    protected["operator"] = "operator-b"
    assert _run(_line()) == (1, REFUSED)


def test_policy_digest_mismatch_refused(protected):
    protected["policy"] = BootstrapApprovalPolicy(frozenset({OPERATOR}), 301)
    assert _run(_line()) == (1, REFUSED)


def test_policy_reader_failure_refused(protected, monkeypatch):
    def boom():
        raise OSError(SECRET)
    monkeypatch.setattr(cli, "_load_approval_policy", boom)
    assert _run(_line()) == (1, REFUSED)


def test_context_reader_failure_refused_without_echo(protected):
    protected["context"] = None
    code, text = _run(_line())
    assert (code, text) == (1, REFUSED)
    assert SECRET not in text


def test_selection_change_refused(protected, monkeypatch):
    calls = []

    def context():
        calls.append(1)
        ctx = CONTEXT if len(calls) == 1 else BootstrapContext(
            **{**CONTEXT.__dict__, "generation": 2})
        return DeclaredBootstrapContext(ctx, OPERATOR, DIGEST)

    monkeypatch.setattr(cli, "load_declared_bootstrap_context", context)
    assert _run(_line()) == (1, REFUSED)


def test_input_never_echoed(protected):
    data = b'{"expires_at":"' + SECRET.encode() + b'","granted_at":"x"}\n'
    code, text = _run(data)
    assert (code, text) == (1, REFUSED)


def test_main_dispatch(protected, monkeypatch, capsys):
    class Stdin(FakeInput):
        pass

    monkeypatch.setattr(sys, "stdin", Stdin(_line()))
    assert cli.main(["approval-request"]) == 0
    assert capsys.readouterr().out.splitlines()[0].startswith('{"context":')
    monkeypatch.setattr(sys, "stdin", Stdin(b"junk\n"))
    assert cli.main(["approval-request"]) == 1
    assert capsys.readouterr().out == REFUSED
