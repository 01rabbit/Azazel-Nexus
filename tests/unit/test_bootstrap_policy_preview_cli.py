"""Unprivileged policy previews never consult host state or install anything."""

import hashlib
import io
import json
import sys

import pytest

from azazel_nexus import cli
from azazel_nexus.bootstrap_approval import BOOTSTRAP_UNITS, BootstrapApprovalPolicy
from azazel_nexus.bootstrap_prestart_policy import (
    BootstrapPrestartPolicy,
    encode_prestart_policy,
)

ADMISSION = "bootstrap-admission-preview"
APPROVAL = "bootstrap-approval-policy-preview"
ADMISSION_REFUSAL = "Admission preview refused; no changes made.\n"
APPROVAL_REFUSAL = "Approval policy preview refused; no changes made.\n"
LOADED = "sha256:" + "d" * 64


def prestart(loaded=None):
    # Synthetic fixture values only.
    return BootstrapPrestartPolicy(
        package_digest="sha256:" + "a" * 64,
        unit_closure_digest="sha256:" + "b" * 64,
        systemd_profile_digest="sha256:" + "c" * 64,
        min_usable_memory_mib=512, min_online_logical_cpus=2,
        min_mission_available_mib=256, bootstrap_bytes=4096, bootstrap_inodes=64,
        audit_bytes=4096, audit_inodes=64, audit_sequence=1, audit_head="e" * 64,
        max_audit_bytes=1048576, max_audit_segments=4,
        max_anchor_lifetime_ns=10**9, max_uncertainty_ns=10**6, drift_ppb=100,
        loaded_policy_digest=loaded,
    )


def approval_bytes(operators=("alice", "bob"), max_seconds=300):
    return json.dumps({
        "schema": "azazel-nexus/bootstrap-approval-policy/v1",
        "operators": list(operators), "max_seconds": max_seconds,
        "units": BOOTSTRAP_UNITS,
    }, sort_keys=True, separators=(",", ":")).encode()


def admission_doc(loaded=None):
    return json.loads(encode_prestart_policy(prestart(loaded)))


def dump(doc, **kwargs):
    return json.dumps(doc, **kwargs).encode()


def canonical(doc):
    return dump(doc, sort_keys=True, separators=(",", ":"))


@pytest.fixture
def run(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("preview must not inspect the host")

    monkeypatch.setattr(cli, "_report", forbidden)

    def invoke(command, raw):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
        output = io.StringIO()
        result = cli.main([command], out=output)
        return result, output.getvalue()

    return invoke


def test_admission_v3_reports_digest_and_non_authorization(run):
    raw = encode_prestart_policy(prestart())
    result, output = run(ADMISSION, raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    assert result == 0
    assert "Admission policy SHA-256 (deployment policy_digest): " + digest + "\n" in output
    assert "NOT installed, NOT admitted, NOT authorized" in output
    assert "Schema: v3" in output
    assert "Loaded-units" not in output
    assert "Independent package, closure, profile and fresh runtime checks remain required." in output


def test_admission_v4_reports_loaded_pin(run):
    raw = encode_prestart_policy(prestart(LOADED))
    result, output = run(ADMISSION, raw)
    assert result == 0
    assert "sha256:" + hashlib.sha256(raw).hexdigest() in output
    assert "NOT installed, NOT admitted, NOT authorized" in output
    assert "Schema: v4" in output
    assert "Loaded-units policy pin: " + LOADED + "\n" in output


def test_approval_policy_reports_digest_without_labels(run):
    raw = approval_bytes()
    result, output = run(APPROVAL, raw)
    expected = BootstrapApprovalPolicy(frozenset({"alice", "bob"}), 300).digest()
    assert result == 0
    assert "Approval policy digest (deployment approval_policy_digest): " + expected + "\n" in output
    assert "NOT installed, NOT enrolled, NOT authorized" in output
    assert "Operator enrollment and signatures remain separate." in output
    assert "alice" not in output and "bob" not in output
    assert "300" not in output


def _admission_cases():
    v3 = admission_doc()
    v4 = admission_doc(LOADED)
    good = canonical(v3)
    reordered = dict(reversed(list(v3.items())))
    duplicate = good[:-1] + b',"audit_mode":"existing-history"}'
    unknown_schema = dict(v3, schema="azazel-nexus/bootstrap-prestart-policy/v9")
    return {
        "empty": b"",
        "empty-object": b"{}",
        "secret-invalid-json": b"secret-invalid-json",
        "oversize": b" " * 8193,
        "valid-plus-excess": good + b" " * 8193,
        "whitespace": dump(v3, sort_keys=True),
        "reordered": dump(reordered, separators=(",", ":")),
        "duplicate-key": duplicate,
        "unknown-schema": canonical(unknown_schema),
        "extra-key": canonical(dict(v3, secret_extra=1)),
        "v3-with-loaded": canonical(dict(v3, loaded_policy_digest=LOADED)),
        "v4-null-loaded": canonical(dict(v4, loaded_policy_digest=None)),
    }


ADMISSION_CASES = _admission_cases()


@pytest.mark.parametrize("raw", ADMISSION_CASES.values(), ids=ADMISSION_CASES.keys())
def test_admission_refuses_invalid_input_without_echo(run, raw):
    result, output = run(ADMISSION, raw)
    assert result == 1
    assert output == ADMISSION_REFUSAL
    assert "secret" not in output


def _approval_cases():
    good = approval_bytes()
    return {
        "empty": b"",
        "empty-object": b"{}",
        "secret-invalid-json": b"secret-invalid-json",
        "oversize": b" " * 65537,
        "valid-plus-excess": good + b" " * 65537,
        "whitespace": good.replace(b",", b", ", 1),
        "unsorted-operators": approval_bytes(("bob", "alice")),
        "empty-operators": approval_bytes(()),
        "bool-max-seconds": approval_bytes(max_seconds=True),
        "zero-max-seconds": approval_bytes(max_seconds=0),
        "duplicate-key": good[:-1] + b',"max_seconds":300}',
        "extra-key": good[:-1] + b',"secret_extra":1}',
    }


APPROVAL_CASES = _approval_cases()


@pytest.mark.parametrize("raw", APPROVAL_CASES.values(), ids=APPROVAL_CASES.keys())
def test_approval_policy_refuses_invalid_input_without_echo(run, raw):
    result, output = run(APPROVAL, raw)
    assert result == 1
    assert output == APPROVAL_REFUSAL
    assert "secret" not in output


@pytest.mark.parametrize(
    ("command", "refusal"),
    [(ADMISSION, ADMISSION_REFUSAL), (APPROVAL, APPROVAL_REFUSAL)],
)
@pytest.mark.parametrize("raw", [b"[" * 65536, b'{"a":' * 13107], ids=["array", "object"])
def test_preview_refuses_deeply_nested_json_with_the_fixed_line(run, command, refusal, raw):
    # Deep nesting must fail closed with the fixed line, never a traceback.
    result, output = run(command, raw)
    assert result == 1
    assert output == refusal


@pytest.mark.parametrize(
    ("command", "refusal"),
    [(ADMISSION, ADMISSION_REFUSAL), (APPROVAL, APPROVAL_REFUSAL)],
)
def test_preview_refuses_interactive_stdin(monkeypatch, command, refusal):
    class Terminal:
        def isatty(self):
            return True

        @property
        def buffer(self):
            pytest.fail("must not block reading interactive input")

    monkeypatch.setattr(cli, "_report", lambda *args, **kwargs: pytest.fail("host inspected"))
    monkeypatch.setattr(sys, "stdin", Terminal())
    output = io.StringIO()
    assert cli.main([command], out=output) == 1
    assert output.getvalue() == refusal
