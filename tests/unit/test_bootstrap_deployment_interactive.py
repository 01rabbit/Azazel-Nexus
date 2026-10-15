"""Interactive declaration publication uses explicit terminal confirmations."""

import hashlib
import io
import sys

import pytest

from azazel_nexus import bootstrap_deployment_cli as interactive
from azazel_nexus import cli
from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from test_bootstrap_deployment_store import declaration


class FakeTerminal:
    def __init__(self, data, *, is_tty=True):
        self.buffer = io.BytesIO(data)
        self._is_tty = is_tty

    def isatty(self):
        return self._is_tty


@pytest.fixture
def raw():
    return encode_bootstrap_deployment(declaration())


@pytest.fixture
def operations(monkeypatch):
    calls = []

    def initialize(value, **kwargs):
        calls.append(("initialize", value, kwargs))

    def recover(value, **kwargs):
        calls.append(("recover", value, kwargs))

    monkeypatch.setattr(interactive, "initialize_bootstrap_deployment", initialize)
    monkeypatch.setattr(interactive, "recover_bootstrap_deployment", recover)
    return calls


def interaction(raw, word):
    digest = hashlib.sha256(raw).hexdigest().encode("ascii")
    return raw + b"\n" + digest + b"\n" + word + b"\n"


@pytest.mark.parametrize(
    ("recovery", "word", "expected"),
    [
        (False, b"INITIALIZE", ("initialize", "confirmed_initialize")),
        (True, b"RECOVER", ("recover", "confirmed_recovery")),
    ],
)
def test_run_publication_requires_declaration_digest_and_operation_word(
    raw, operations, recovery, word, expected,
):
    output = io.StringIO()

    result = interactive.run_publication(
        source=FakeTerminal(interaction(raw, word)), out=output, recovery=recovery,
    )

    assert result == 0
    assert operations == [(expected[0], raw, {
        "confirmed_sha256": hashlib.sha256(raw).hexdigest(), expected[1]: True,
    })]
    assert hashlib.sha256(raw).hexdigest() in output.getvalue()
    assert "NOT a start grant" in output.getvalue()
    assert "NOT admitted or authorized" in output.getvalue()


@pytest.mark.parametrize(
    ("recovery", "word", "expected"),
    [
        (False, b"INITIALIZE", "initialize"),
        (True, b"RECOVER", "recover"),
    ],
)
def test_cli_main_dispatches_to_the_matching_publication_operation(
    monkeypatch, raw, operations, recovery, word, expected,
):
    monkeypatch.setattr(sys, "stdin", FakeTerminal(interaction(raw, word)))
    monkeypatch.setattr(cli, "_report", lambda *args, **kwargs: pytest.fail("host report invoked"))
    command = "bootstrap-deployment-recover" if recovery else "bootstrap-deployment-initialize"

    result = cli.main([command], out=io.StringIO())

    assert result == 0
    assert len(operations) == 1
    assert operations[0][0] == expected
    assert operations[0][1] == raw


@pytest.mark.parametrize("case", [
    "wrong-digest", "declined", "piped", "eof", "oversized-declaration", "oversized-digest",
])
def test_refusals_never_call_publication_operations(monkeypatch, raw, operations, case):
    digest = hashlib.sha256(raw).hexdigest().encode("ascii")
    valid_word = b"INITIALIZE\n"
    tty = True
    if case == "wrong-digest":
        data = raw + b"\n" + b"0" * 64 + b"\n" + valid_word
    elif case == "declined":
        data = raw + b"\n" + digest + b"\n" + b"NO\n"
    elif case == "piped":
        data = interaction(raw, b"INITIALIZE")
        tty = False
    elif case == "eof":
        data = b""
    elif case == "oversized-declaration":
        data = b" " * 4097 + b"\n" + digest + b"\n" + valid_word
    else:
        data = raw + b"\n" + b"0" * 65 + b"\n" + valid_word
    monkeypatch.setattr(sys, "stdin", FakeTerminal(data, is_tty=tty))
    monkeypatch.setattr(cli, "_report", lambda *args, **kwargs: pytest.fail("host report invoked"))

    result = cli.main(["bootstrap-deployment-initialize"], out=io.StringIO())

    assert result == 1
    assert operations == []


def test_uncertain_durability_is_not_reported_as_clean_refusal(monkeypatch, raw):
    def uncertain(*args, **kwargs):
        raise interactive.DeploymentDurabilityUncertain("hidden details")

    monkeypatch.setattr(interactive, "initialize_bootstrap_deployment", uncertain)
    output = io.StringIO()
    result = interactive.run_publication(source=FakeTerminal(interaction(raw, b"INITIALIZE")),
                                         out=output)
    assert result == 2
    assert "durability UNCONFIRMED" in output.getvalue()
    assert "hidden details" not in output.getvalue()
