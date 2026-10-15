"""Read-only loaded-units preview CLI operation."""

from dataclasses import replace
from hashlib import sha256
from io import BytesIO, StringIO
import sys

import pytest

from azazel_nexus.bootstrap_prestart_policy import encode_prestart_policy
from azazel_nexus_runtime import bootstrap_cli as cli
from test_runtime_bootstrap_loaded_policy import _document, _pinned, _raw

REFUSED = "Loaded-units preview refused; no changes made.\n"


class FakeInput:
    def __init__(self, data: bytes, *, tty: bool = False):
        self.buffer = BytesIO(data)
        self._tty = tty

    def isatty(self):
        return self._tty


def _pair(loaded=None):
    loaded = _raw() if loaded is None else loaded
    return encode_prestart_policy(_pinned(loaded)), loaded


def _run(data, *, tty=False):
    out = StringIO()
    return cli.run_loaded_units_preview(source=FakeInput(data, tty=tty), out=out), out.getvalue()


def test_success_prints_exact_digests_and_disclaimers():
    admission, loaded = _pair()
    code, text = _run(admission + b"\n" + loaded + b"\n")
    assert code == 0
    lines = text.splitlines()
    assert lines == [
        "Loaded-units policy valid against the supplied v4 admission policy; "
        "NOT installed, NOT admitted, NOT authorized.",
        "Admission policy SHA-256 (deployment policy_digest): sha256:" + sha256(admission).hexdigest(),
        "Loaded-units policy SHA-256 (admission loaded_policy_digest): sha256:" + sha256(loaded).hexdigest(),
        "Digests are of the supplied bytes only, not verified pins; package, closure, "
        "live loaded units and systemd profile are checked only at admission.",
    ]


def test_main_dispatches_operation(monkeypatch):
    admission, loaded = _pair()
    monkeypatch.setattr(sys, "stdin", FakeInput(admission + b"\n" + loaded + b"\n"))
    out = StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert cli.main(["loaded-units-preview"]) == 0
    assert "NOT authorized" in out.getvalue()


def test_tty_refused_without_reading():
    admission, loaded = _pair()
    source = FakeInput(admission + b"\n" + loaded + b"\n", tty=True)
    out = StringIO()
    assert cli.run_loaded_units_preview(source=source, out=out) == 1
    assert out.getvalue() == REFUSED
    assert source.buffer.tell() == 0


def test_v3_admission_refused():
    loaded = _raw()
    v3 = encode_prestart_policy(replace(_pinned(loaded), loaded_policy_digest=None))
    assert _run(v3 + b"\n" + loaded + b"\n") == (1, REFUSED)


def test_mismatched_loaded_digest_refused():
    admission, loaded = _pair()
    other = _raw({**_document(), "systemd_profile_digest": "sha256:" + "9" * 64})
    assert _run(admission + b"\n" + other + b"\n") == (1, REFUSED)


def test_noncanonical_loaded_units_refused():
    loaded = _raw()
    spaced = loaded.replace(b",", b", ", 1)
    admission = encode_prestart_policy(_pinned(spaced))
    assert _run(admission + b"\n" + spaced + b"\n") == (1, REFUSED)


@pytest.mark.parametrize("tail", ["missing-second", "missing-newline", "trailing"])
def test_line_structure_refused(tail):
    admission, loaded = _pair()
    data = {
        "missing-second": admission + b"\n",
        "missing-newline": admission + b"\n" + loaded,
        "trailing": admission + b"\n" + loaded + b"\nextra\n",
    }[tail]
    assert _run(data) == (1, REFUSED)


def test_oversized_admission_line_refused():
    _admission, loaded = _pair()
    assert _run(b"x" * 8193 + b"\n" + loaded + b"\n") == (1, REFUSED)


def test_oversized_loaded_line_refused():
    admission, _loaded = _pair()
    assert _run(admission + b"\n" + b"x" * 65537 + b"\n") == (1, REFUSED)


def test_deeply_nested_json_refused_with_fixed_line_and_no_echo():
    admission, loaded = _pair()
    # Each nesting stays within its line limit, so the decoder (not the size
    # check) is what refuses it.
    deep_admission = b'{"secret":' + b"[" * 4000 + b"]" * 4000 + b"}"
    deep_loaded = b'{"secret":' + b"[" * 20000 + b"]" * 20000 + b"}"
    assert len(deep_admission) <= 8192 and len(deep_loaded) <= 65536
    for data in (deep_admission + b"\n" + loaded + b"\n",
                 admission + b"\n" + deep_loaded + b"\n"):
        assert _run(data) == (1, REFUSED)


def test_secret_marker_never_echoed():
    admission, loaded = _pair()
    secret = b'{"secret":"SECRET-MARKER"}'
    for data in (secret + b"\n" + loaded + b"\n", admission + b"\n" + secret + b"\n"):
        code, text = _run(data)
        assert code == 1 and "SECRET-MARKER" not in text and text == REFUSED
