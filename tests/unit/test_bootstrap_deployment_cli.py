"""Unprivileged preview never consults host state or installs a declaration."""

import hashlib
import io
import sys

import pytest

from azazel_nexus import cli
from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from test_bootstrap_deployment_store import declaration


@pytest.fixture
def run(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("preview must not inspect the host")

    monkeypatch.setattr(cli, "_report", forbidden)

    def invoke(raw):
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw)))
        output = io.StringIO()
        result = cli.main(["bootstrap-deployment-preview"], out=output)
        return result, output.getvalue()

    return invoke


def test_preview_reports_only_digest_and_non_authorization(run):
    raw = encode_bootstrap_deployment(declaration())
    result, output = run(raw)
    assert result == 0
    assert hashlib.sha256(raw).hexdigest() in output
    assert "NOT installed, NOT admitted, NOT authorized" in output
    assert "operator-a" not in output
    assert declaration().node_digest not in output


@pytest.mark.parametrize("raw", [b"", b"{}", b"secret-invalid-json", b" " * 4097])
def test_preview_refuses_invalid_input_without_echo(run, raw):
    result, output = run(raw)
    assert result == 1
    assert output == "Deployment preview refused; no changes made.\n"


def test_preview_refuses_valid_document_with_excess_bytes(run):
    raw = encode_bootstrap_deployment(declaration()) + b" " * 4097
    result, output = run(raw)
    assert result == 1
    assert "SHA-256" not in output


def test_preview_refuses_interactive_stdin(monkeypatch):
    class Terminal:
        def isatty(self):
            return True

        @property
        def buffer(self):
            pytest.fail("must not block reading interactive input")

    monkeypatch.setattr(sys, "stdin", Terminal())
    assert cli.main(["bootstrap-deployment-preview"], out=io.StringIO()) == 1
