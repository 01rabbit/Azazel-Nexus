"""The repin CLI never takes a key or path argument and confirms on a terminal.

Since ADR 0008 `az-nexus-commission trust-repin` runs the repin itself, in a
child that becomes the commissioning account (`lite_trust_ops`), instead of
asking `az-commissiond` over its socket. Here the child is replaced by an
in-process call (the narrowing is the root e2e stage's), and the root check
is answered yes; everything else -- the challenge, the words, the audit order, the
library repin -- is the production code on a relocated root.
"""

import json

import pytest
from azazel_nexus_runtime import commission_cli, lite_trust_ops, runtime_paths
from azazel_nexus_runtime import repin_confirmation as repin
from nacl.signing import SigningKey

from azazel_nexus.layout import create_layout
from azazel_nexus.lite_trust import TrustStore

NOW = "2026-10-30T00:00:00Z"
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def terminal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    create_layout(tmp_path)
    store = TrustStore(runtime_paths.lite_trust_root())
    store.pin([bytes(SigningKey.generate().verify_key).hex()], commissioning_digest=DIGEST,
              pinned_at=NOW, actor="root")
    store.path.chmod(0o640)
    (tmp_path / "etc/azazel/commissioning" / repin.ANCHOR_FILENAME).write_text(
        json.dumps({"keys": [bytes(SigningKey.generate().verify_key).hex()]}))
    monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(type(commission_cli.sys.stdout), "isatty", lambda self: True)
    monkeypatch.setattr(lite_trust_ops, "_is_root", lambda: True)
    monkeypatch.setattr(lite_trust_ops, "run_as_commissioner", lambda work: dict(work()))
    events = []
    monkeypatch.setattr(lite_trust_ops, "_default_append", events.append)
    shown = {}
    real_print = print

    def capture(*args, **kwargs):
        text = " ".join(map(str, args))
        if text.startswith("Type REPIN-TRUST-"):
            shown["words"] = text.split()[1]
        real_print(*args, **kwargs)

    monkeypatch.setattr("builtins.print", capture)
    monkeypatch.setattr("builtins.input", lambda prompt: shown["words"])
    return store, events, shown


def test_human_sees_reason_and_fingerprint_then_confirms(terminal, capsys):
    store, events, shown = terminal
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 0
    output = capsys.readouterr()
    assert "Reason: rotation" in output.out
    assert "New anchor file fingerprint: sha256:" in output.out
    assert "Trust anchors replaced; generation 1." in output.out
    assert store.current_generation() == 1
    # The request is recorded before the promotion, the promotion after.
    assert [event["event_type"] for event in events] == [
        "knowledge.lite.trust_repin_requested", "knowledge.lite.trust_repin_promoted"]
    assert events[0]["reason"] == "rotation" and events[1]["generation"] == 1
    assert events[0]["anchor_digest"] == events[1]["anchor_digest"]


@pytest.mark.parametrize("stream", ["stdin", "stdout"])
def test_redirected_terminal_never_requests_challenge(terminal, monkeypatch, stream):
    store, events, _ = terminal
    monkeypatch.setattr(getattr(commission_cli.sys, stream), "isatty", lambda: False)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    assert events == [] and store.current_generation() == 0


@pytest.mark.parametrize("answer", ["", "CONFIRM", "REPIN-TRUST-0123456789abcdef\n", "wrong"])
def test_wrong_or_automatic_generic_answer_never_confirms(terminal, monkeypatch, answer):
    store, events, _ = terminal
    monkeypatch.setattr("builtins.input", lambda prompt: answer)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    # Nothing is recorded for a request the human never confirmed.
    assert events == [] and store.current_generation() == 0


@pytest.mark.parametrize("error", [EOFError(), KeyboardInterrupt()])
def test_interrupted_confirmation_never_confirms(terminal, monkeypatch, error):
    store, events, _ = terminal

    def interrupted(prompt):
        raise error
    monkeypatch.setattr("builtins.input", interrupted)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    assert events == [] and store.current_generation() == 0


@pytest.mark.parametrize("args", [[], ["--reason", "free-form"], ["--reason", "rotation", "--yes"],
                                   ["--reason", "rotation", "--key", "SECRET"],
                                   ["--reason", "rotation", "--new-anchor-file", "/tmp/key"]])
def test_no_path_key_or_noninteractive_override(terminal, args):
    store, events, _ = terminal
    assert commission_cli.main(["trust-repin", *args]) == 2
    assert events == [] and store.current_generation() == 0


def test_terminal_is_rechecked_after_the_words_are_typed(terminal, monkeypatch):
    store, events, shown = terminal

    def answer(prompt):
        monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: False)
        return shown["words"]
    monkeypatch.setattr("builtins.input", answer)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    assert events == [] and store.current_generation() == 0


def test_no_promotion_without_the_request_record(terminal, monkeypatch):
    store, events, _ = terminal

    def unavailable(event):
        raise ConnectionRefusedError("auditd is not running")
    monkeypatch.setattr(lite_trust_ops, "_default_append", unavailable)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    assert store.current_generation() == 0
    assert not (store.root / "trust-reserved").exists()


def test_library_exception_text_is_never_printed(terminal, monkeypatch, capsys):
    store, events, _ = terminal
    original = repin.RepinConfirmation.__init__

    def fail(request, confirmation):
        raise ValueError("SENTINEL-KEY-MATERIAL")

    def init(self, **kwargs):
        original(self, **{**kwargs, "repin": fail})
    monkeypatch.setattr(repin.RepinConfirmation, "__init__", init)
    assert commission_cli.main(["trust-repin", "--reason", "rotation"]) == 1
    output = capsys.readouterr()
    assert "SENTINEL" not in output.out + output.err
    assert [event["event_type"] for event in events] == [
        "knowledge.lite.trust_repin_requested", "knowledge.lite.trust_repin_refused"]
    assert store.current_generation() == 0
