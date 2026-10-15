"""CLI framing and confirmation only; publication backend is recorded, not live."""

from hashlib import sha256
import io
import sys

import pytest

from azazel_nexus import bootstrap_selection_cli as command, cli
from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from azazel_nexus.bootstrap_selection import BootstrapSelection, encode_bootstrap_selection
from test_bootstrap_deployment_store import declaration
from test_bootstrap_generation import _context


class Terminal:
    def __init__(self, raw, interactive=True):
        self.buffer = io.BytesIO(raw)
        self.interactive = interactive

    def isatty(self):
        return self.interactive


@pytest.fixture
def selected():
    context = _context()
    return encode_bootstrap_selection(BootstrapSelection(
        "sha256:" + sha256(encode_bootstrap_deployment(declaration())).hexdigest(),
        context.boot_id, context.approval_id, context.generation, context.generation_digest,
    ))


@pytest.mark.parametrize("recovery", [False, True])
def test_cli_routes_separate_confirmations_without_echoing_identity(selected, monkeypatch, recovery):
    calls = []
    key = "confirmed_recovery" if recovery else "confirmed_initialize"
    backend = "recover_bootstrap_selection" if recovery else "initialize_bootstrap_selection"
    monkeypatch.setattr(command, backend, lambda raw, **kwargs: calls.append((raw, kwargs)))
    word = b"RECOVER" if recovery else b"INITIALIZE"
    digest = sha256(selected).hexdigest()
    monkeypatch.setattr(sys, "stdin", Terminal(selected + b"\n" + digest.encode() + b"\n" + word + b"\n"))
    out = io.StringIO()
    name = "bootstrap-selection-recover" if recovery else "bootstrap-selection-initialize"
    assert cli.main([name], out=out) == 0
    assert calls == [(selected, {"confirmed_sha256": digest, key: True})]
    assert "NOT approval, admission or activation" in out.getvalue()
    assert "11111111-1111-4111-8111-111111111111" not in out.getvalue()


@pytest.mark.parametrize("failure", ["noninteractive", "digest", "operation", "malformed", "oversize", "truncated"])
def test_refusals_never_call_backend_or_echo_input(selected, monkeypatch, failure):
    def forbidden(*args, **kwargs):
        pytest.fail("refused input reached publication")

    monkeypatch.setattr(command, "initialize_bootstrap_selection", forbidden)
    digest = sha256(selected).hexdigest().encode()
    raw = selected + b"\n" + digest + b"\nINITIALIZE\n"
    if failure == "digest":
        raw = selected + b"\n" + b"0" * 64 + b"\nINITIALIZE\n"
    elif failure == "operation":
        raw = selected + b"\n" + digest + b"\nRECOVER\n"
    elif failure == "malformed":
        raw = b"private-invalid-input\n"
    elif failure == "oversize":
        raw = b"X" * 4097 + b"\n"
    elif failure == "truncated":
        raw = selected
    out = io.StringIO()
    assert command.run_publication(source=Terminal(raw, failure != "noninteractive"), out=out) == 1
    assert "private-invalid-input" not in out.getvalue()
    assert "Selection published;" not in out.getvalue()


def test_uncertain_durability_has_distinct_exit_and_no_success(selected, monkeypatch):
    def uncertain(*args, **kwargs):
        raise command.SelectionDurabilityUncertain("private exception")

    monkeypatch.setattr(command, "initialize_bootstrap_selection", uncertain)
    source = Terminal(selected + b"\n" + sha256(selected).hexdigest().encode() + b"\nINITIALIZE\n")
    out = io.StringIO()
    assert command.run_publication(source=source, out=out) == 2
    assert "durability UNCONFIRMED" in out.getvalue()
    assert "private exception" not in out.getvalue()
    assert "Selection published;" not in out.getvalue()
