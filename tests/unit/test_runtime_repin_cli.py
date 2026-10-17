"""Interactive client never takes a key/path argument or reads an anchor."""

import pytest
from azazel_nexus_runtime import commission_cli
from azazel_nexus_runtime import repin_confirmation as repin


@pytest.fixture
def terminal(monkeypatch, capsys):
    monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(type(commission_cli.sys.stdout), "isatty", lambda self: True)
    calls = []
    words = "REPIN-TRUST-0123456789abcdef"

    def exchange(verb, arguments):
        calls.append((verb, arguments))
        if verb == "trust.repin.challenge":
            return {"reason": "rotation", "nonce": "sha256:" + "1" * 64,
                    "new_fingerprint": "sha256:" + "2" * 64, "confirmation_words": words}
        return {"promoted": True, "generation": 7}

    monkeypatch.setattr(repin, "_exchange", exchange)
    monkeypatch.setattr("builtins.input", lambda prompt: words)
    return calls


def test_human_sees_reason_and_fingerprint_then_confirms(terminal, capsys):
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 0
    assert terminal == [
        ("trust.repin.challenge", {"reason": "rotation", "new_anchor_file": repin.ANCHOR_FILENAME}),
        ("trust.repin.confirm", {"nonce": "sha256:" + "1" * 64,
                                 "echo": "REPIN-TRUST-0123456789abcdef"}),
    ]
    output = capsys.readouterr()
    assert "Reason: rotation" in output.out
    assert "sha256:" + "2" * 64 in output.out
    assert "generation 7" in output.out


@pytest.mark.parametrize("stream", ["stdin", "stdout"])
def test_redirected_terminal_never_requests_challenge(terminal, monkeypatch, stream):
    monkeypatch.setattr(getattr(commission_cli.sys, stream), "isatty", lambda: False)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    assert terminal == []


@pytest.mark.parametrize("answer", ["", "CONFIRM", "REPIN-TRUST-0123456789abcdef\n", "wrong"])
def test_wrong_or_automatic_generic_answer_never_confirms(terminal, monkeypatch, answer):
    monkeypatch.setattr("builtins.input", lambda prompt: answer)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    assert len(terminal) == 1


@pytest.mark.parametrize("error", [EOFError(), KeyboardInterrupt()])
def test_interrupted_confirmation_never_confirms(terminal, monkeypatch, error):
    def interrupted(prompt):
        raise error
    monkeypatch.setattr("builtins.input", interrupted)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    assert len(terminal) == 1


@pytest.mark.parametrize("args", [[], ["--reason", "free-form"], ["--reason", "rotation", "--yes"],
                                   ["--reason", "rotation", "--key", "SECRET"],
                                   ["--reason", "rotation", "--new-anchor-file", "/tmp/key"]])
def test_no_path_key_or_noninteractive_override(terminal, args):
    assert commission_cli.main(["trust-repin", *args]) == 2
    assert not terminal


def test_client_rechecks_terminal_before_sending_confirmation(terminal, monkeypatch):
    def answer(prompt):
        monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: False)
        return "REPIN-TRUST-0123456789abcdef"
    monkeypatch.setattr("builtins.input", answer)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    assert len(terminal) == 1


def test_server_exception_text_is_never_printed(terminal, monkeypatch, capsys):
    def exchange(verb, arguments):
        raise ValueError("SENTINEL-KEY-MATERIAL")
    monkeypatch.setattr(repin, "_exchange", exchange)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    output = capsys.readouterr()
    assert "SENTINEL" not in output.out + output.err
