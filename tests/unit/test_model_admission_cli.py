"""Read-only bilingual request summaries and refusal parity."""
import io

import pytest
from admission_helpers import END, NOW, inputs
from azazel_nexus_runtime import model_admission_cli as cli

from azazel_nexus import model_admission as admission


def test_verify_reports_disabled_without_io(monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    assert cli.main(["verify", "--role", "embedding"]) == 0
    assert "embedding -> refused:ADMISSION_DISABLED" in capsys.readouterr().out


@pytest.mark.parametrize("option", ["--root", "--key", "--seed", "--output", "--approved"])
def test_cli_rejects_overrides_before_reading(option, monkeypatch):
    monkeypatch.setattr(cli, "request_context", lambda **kw: pytest.fail("override reached collector"))
    with pytest.raises(SystemExit):
        cli.main(["request", "--role", "embedding", option, "value"])


def test_request_prints_bilingual_summary_hashes_and_closes_descriptors(monkeypatch):
    from test_model_admission_evidence import admitted_candidate

    kwargs, _, _ = inputs(need=1000, version="b11716")
    candidate = admitted_candidate()
    closed = []
    held = type("Held", (), {"close": lambda self: closed.append(True)})()
    monkeypatch.setattr(cli, "request_context", lambda **kw: (kwargs["policy"], (
        kwargs["expected"], held, candidate.entry, candidate.provider, candidate.host,
        candidate.tested, candidate.resources, candidate.record)))
    doc = {"operator": "approver", "issued_at": NOW, "expires_at": END,
           "memory_need_mib": 1000, "envelope_floor_mib": 1}
    stdout = io.StringIO()
    assert cli.run_request(stdin=io.StringIO(admission.canonical(doc).decode() + "\n"), stdout=stdout) == 0
    text = stdout.getvalue()
    payload = text.splitlines()[0].encode()
    assert admission.digest(payload) in text
    for marker in ("モデル", "Runtime:", "argv:", "Core reserve", "Peak RSS", "Validity:", "Node:",
                   "virtualization_not_observed", "signs nothing, authorizes nothing", "feature disabled"):
        assert marker in text
    assert closed == [True]
