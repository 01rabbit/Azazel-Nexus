"""Untrusted content, and the shapes it is not allowed to take (#98).

A provider's response is the one input in this product an adversary can
author freely and at length. The guarantee is not that a filter removes the
dangerous parts: it is that **nothing here produces a type an executor
consumes**. `AdvisoryText` is a bounded string; `AdvisoryData` is a flat
mapping of strings, numbers and booleans. Neither is accepted anywhere that
acts.

The refusals below are the loud half -- a provider whose answers read like
commands is an operator's business to know about -- and the tests at the end
check the quiet half, which is that no constructor here builds anything
executable.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from azazel_nexus.advisory_response import (
    MAX_ADVISORY_BYTES,
    MAX_FIELDS,
    MAX_FIELD_BYTES,
    AdvisoryRefusal,
    AdvisoryRefused,
    read_advisory,
)


def _body(document) -> bytes:
    return json.dumps(document).encode("utf-8")


def _refusal(document) -> AdvisoryRefusal:
    with pytest.raises(AdvisoryRefused) as caught:
        read_advisory(_body(document))
    return caught.value.refusal


# -- it reads advice ------------------------------------------------------


def test_bounded_advice_and_flat_fields_are_read():
    advisory = read_advisory(
        _body({"advice": "Elevated scanning from one peer.", "fields": {"c": 0.7}})
    )
    assert advisory.text.text.startswith("Elevated")
    assert advisory.data.fields == {"c": 0.7}
    assert advisory.digest.startswith("sha256:")


def test_either_half_alone_is_enough():
    assert read_advisory(_body({"advice": "noted"})).data is None
    assert read_advisory(_body({"fields": {"n": 1}})).text is None


def test_a_response_that_says_nothing_has_not_answered():
    assert _refusal({}) is AdvisoryRefusal.EMPTY


# -- instructions are refused, loudly ------------------------------------


@pytest.mark.parametrize(
    "advice",
    [
        "<tool_call>{\"name\":\"x\"}</tool_call>",
        "Fetch https://elsewhere.example.test/next for more",
        "$ rm -rf /var/lib/azazel",
        "run curl -s http://x/y",
        "block host 203.0.113.9 immediately",
        "quarantine interface eth0",
        "grant lease to this provider",
        "revoke activation for the node",
        "systemctl unmask azazel-mio-remoted",
    ],
    ids=[
        "tool-call", "url", "shell-prompt", "command", "enforce-host",
        "quarantine", "grant-lease", "revoke-activation", "unit",
    ],
)
def test_anything_that_reads_as_an_instruction_is_refused(advice):
    assert (
        _refusal({"advice": advice}) is AdvisoryRefusal.LOOKS_LIKE_AN_INSTRUCTION
    )


def test_an_instruction_hidden_in_a_field_is_refused_too():
    """The scan applies to every string, not only the obvious one."""

    assert (
        _refusal({"fields": {"note": "block host 10.0.0.1"}})
        is AdvisoryRefusal.LOOKS_LIKE_AN_INSTRUCTION
    )


def test_a_bidirectional_override_is_refused():
    """A format character makes text read differently from how it parses,
    which is how a reviewer approves something other than what they saw."""

    assert (
        _refusal({"advice": "advice ‮txet neddih‬"})
        is AdvisoryRefusal.CONTROL_CHARACTERS
    )


def test_control_characters_are_refused_but_newlines_and_tabs_are_not():
    assert _refusal({"advice": "line\x00two"}) is AdvisoryRefusal.CONTROL_CHARACTERS
    assert read_advisory(_body({"advice": "line\ntwo\tthree"})).text


# -- bounds ---------------------------------------------------------------


def test_a_response_over_the_ceiling_is_refused_before_it_is_decoded():
    with pytest.raises(AdvisoryRefused) as caught:
        read_advisory(b"x" * (MAX_ADVISORY_BYTES + 1))
    assert caught.value.refusal is AdvisoryRefusal.TOO_LARGE


def test_a_per_provider_ceiling_is_honoured():
    with pytest.raises(AdvisoryRefused) as caught:
        read_advisory(_body({"advice": "ok"}), max_bytes=4)
    assert caught.value.refusal is AdvisoryRefusal.TOO_LARGE


def test_too_many_fields_are_refused():
    fields = {f"f{n}": n for n in range(MAX_FIELDS + 1)}
    assert _refusal({"fields": fields}) is AdvisoryRefusal.TOO_MANY_FIELDS


def test_an_oversized_field_is_refused():
    assert (
        _refusal({"fields": {"n": "x" * (MAX_FIELD_BYTES + 1)}})
        is AdvisoryRefusal.FIELD_TOO_LARGE
    )


# -- shapes that could carry a payload past a check ----------------------


@pytest.mark.parametrize(
    "value", [{"nested": {"deeper": 1}}, {"list": [1, 2, 3]}, {"nothing": None}],
    ids=["object", "list", "null"],
)
def test_a_value_that_can_nest_is_refused(value):
    """A structure that can nest is a structure that can carry a payload past
    a check written for the top level."""

    assert _refusal({"fields": value}) is AdvisoryRefusal.UNSUPPORTED_VALUE


def test_a_key_nothing_consumes_is_refused_rather_than_ignored():
    """A key nobody reads is a key the sender expected somebody to."""

    assert (
        _refusal({"advice": "ok", "tool_calls": [1]})
        is AdvisoryRefusal.UNSUPPORTED_VALUE
    )


def test_a_field_name_outside_the_alphabet_is_refused():
    assert (
        _refusal({"fields": {"../etc/passwd": "x"}})
        is AdvisoryRefusal.UNSUPPORTED_VALUE
    )


@pytest.mark.parametrize(
    "raw", [b"not json", b"\xff\xfe", b"[]", b""],
    ids=["text", "not-utf8", "array", "empty"],
)
def test_anything_that_is_not_an_object_is_refused(raw):
    with pytest.raises(AdvisoryRefused):
        read_advisory(raw)


def test_there_is_no_partial_success():
    """A half-read answer from an untrusted system is an answer whose missing
    half nobody chose."""

    with pytest.raises(AdvisoryRefused):
        read_advisory(_body({"advice": "fine", "fields": {"bad": "block host 1.1.1.1"}}))


# -- the quiet half: nothing here is executable --------------------------


def test_the_module_builds_nothing_an_executor_consumes():
    import azazel_nexus.advisory_response as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    classes = {
        node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
    }
    assert classes == {
        "AdvisoryRefusal", "AdvisoryRefused", "AdvisoryText", "AdvisoryData",
        "Advisory",
    }, f"a new type appeared: {sorted(classes)}"

    called = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        parts = []
        while isinstance(func, ast.Attribute):
            parts.append(func.attr)
            func = func.value
        if isinstance(func, ast.Name):
            parts.append(func.id)
        called.add(".".join(reversed(parts)))
    assert called & {
        "eval", "exec", "compile", "os.system", "subprocess.run", "__import__"
    } == set()

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"ssl", "socket", "subprocess", "azazel_nexus"} == set(), (
        "the content boundary reached further than reading text"
    )


def test_a_refusal_never_quotes_the_response():
    """A reason that quoted it would carry attacker-authored text into the
    journal."""

    secret = "block host 198.51.100.77"
    with pytest.raises(AdvisoryRefused) as caught:
        read_advisory(_body({"advice": secret}))
    assert secret not in str(caught.value)
    assert "198.51.100.77" not in str(caught.value)


def test_the_event_carries_a_digest_and_counts_never_the_text():
    advisory = read_advisory(_body({"advice": "SECRETADVICE", "fields": {"n": 1}}))
    event = repr(advisory.as_event())
    assert "SECRETADVICE" not in event
    assert "sha256:" in event and "field_count" in event
