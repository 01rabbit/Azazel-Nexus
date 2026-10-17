"""Selected administrator-time CLI/publication integration on temp storage."""

from dataclasses import replace
from hashlib import sha256
from io import BytesIO, StringIO
import sys

import pytest

from azazel_nexus import bootstrap_clock_store as clock_store
from azazel_nexus.bootstrap_clock_store import TimeDurabilityUncertain
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_cli as cli
from azazel_nexus_runtime import bootstrap_provisioning as provisioning
from azazel_nexus_runtime.bootstrap_declared_context import DeclaredBootstrapContext

pytest_plugins = ("test_bootstrap_clock_publication",)


class FakeInput:
    def __init__(self, data: bytes, *, tty=True):
        self.buffer = BytesIO(data)
        self._tty = tty

    def isatty(self):
        return self._tty


def _selected(context):
    return DeclaredBootstrapContext(context, "operator-a", "sha256:" + "a" * 64)


def _digest(raw, selected, recovery=False):
    return provisioning.selected_time_digest(
        raw=raw, selected=selected, recovery=recovery,
    )


def _input(raw, selected, *, recovery=False, digest=None, word=None):
    digest = _digest(raw, selected, recovery) if digest is None else digest
    word = (b"RECOVER" if recovery else b"INITIALIZE") if word is None else word
    return raw + b"\n" + digest.encode() + b"\n" + word + b"\n"


def _wire_selection(monkeypatch, selected, *, cli_values=None, provisioning_values=None):
    if cli_values is None:
        monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    else:
        values = iter(cli_values)
        monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda values=values: next(values))
    if provisioning_values is None:
        monkeypatch.setattr(provisioning, "load_declared_bootstrap_context", lambda: selected)
    else:
        values = iter(provisioning_values)
        monkeypatch.setattr(provisioning, "load_declared_bootstrap_context", lambda values=values: next(values))


def test_selected_time_digest_binds_operation_operator_and_approval(public_environment):
    context, _anchor, raw, _policy, _root = public_environment
    selected = _selected(context)
    initialize = _digest(raw, selected)

    assert initialize != _digest(raw, selected, recovery=True)
    assert initialize != _digest(raw, replace(selected, operator="operator-b"))
    assert initialize != _digest(
        raw,
        replace(selected, context=replace(context, approval_id="44444444-4444-4444-8444-444444444444")),
    )


def test_actual_main_initializes_selected_anchor_then_protected_reader_loads_it(
    public_environment, monkeypatch,
):
    context, anchor, raw, _policy, root = public_environment
    selected = _selected(context)
    _wire_selection(monkeypatch, selected)
    monkeypatch.setattr(sys, "stdin", FakeInput(_input(raw, selected)))
    output = StringIO()
    monkeypatch.setattr(sys, "stdout", output)

    assert cli.main(["time-initialize"]) == 0
    assert clock_store.decode_administrator_anchor((root / "time.json").read_bytes()) == anchor
    assert not (root / "time.pending").exists()
    window = clock_store.load_administrator_time_window(expected=context)
    assert window.boot_id == context.boot_id
    assert "no OS clock change" in output.getvalue()


def test_actual_main_recovers_exact_pending_anchor_and_reader_accepts(
    public_environment, monkeypatch,
):
    context, anchor, raw, _policy, root = public_environment
    selected = _selected(context)
    (root / "time.pending").write_bytes(b"administrator time publication pending\n")
    (root / "time.pending").chmod(0o600)
    (root / "time.json").write_bytes(raw)
    (root / "time.json").chmod(0o600)
    _wire_selection(monkeypatch, selected)
    monkeypatch.setattr(sys, "stdin", FakeInput(_input(raw, selected, recovery=True)))
    output = StringIO()
    monkeypatch.setattr(sys, "stdout", output)

    assert cli.main(["time-recover"]) == 0
    assert not (root / "time.pending").exists()
    assert clock_store.decode_administrator_anchor((root / "time.json").read_bytes()) == anchor
    assert clock_store.load_administrator_time_window(expected=context).boot_id == context.boot_id


@pytest.mark.parametrize("case", ["not-tty", "wrong-digest", "wrong-word", "malformed", "oversize", "truncated"])
def test_cli_rejects_interaction_and_anchor_errors_before_publication(
    public_environment, monkeypatch, case,
):
    context, _anchor, raw, _policy, root = public_environment
    selected = _selected(context)
    _wire_selection(monkeypatch, selected)
    monkeypatch.setattr(
        cli, "publish_selected_administrator_time",
        lambda **_kwargs: pytest.fail("invalid CLI input reached publisher"),
    )
    if case == "not-tty":
        payload, tty = _input(raw, selected), False
    elif case == "wrong-digest":
        payload, tty = _input(raw, selected, digest="sha256:" + "0" * 64), True
    elif case == "wrong-word":
        payload, tty = _input(raw, selected, word=b"YES"), True
    elif case == "oversize":
        payload, tty = b"X" * 4097 + b"\n", True
    elif case == "truncated":
        payload, tty = raw, True
    else:
        payload, tty = b"{}\n", True
    monkeypatch.setattr(sys, "stdin", FakeInput(payload, tty=tty))
    monkeypatch.setattr(sys, "stdout", StringIO())

    assert cli.main(["time-initialize"]) == 1
    assert list(root.iterdir()) == []


def test_initialize_confirmation_cannot_be_reused_for_recovery(public_environment, monkeypatch):
    context, _anchor, raw, _policy, root = public_environment
    selected = _selected(context)
    _wire_selection(monkeypatch, selected)
    with pytest.raises(ApprovalRefused):
        provisioning.publish_selected_administrator_time(
            raw=raw, confirmed_digest=_digest(raw, selected, recovery=False),
            confirmed_operation=True, recovery=True,
        )
    assert list(root.iterdir()) == []


def test_selection_change_during_clock_publication_keeps_pending_and_reader_refuses(
    public_environment, monkeypatch,
):
    context, _anchor, raw, _policy, root = public_environment
    selected = _selected(context)
    changed = replace(
        selected,
        context=replace(context, approval_id="44444444-4444-4444-8444-444444444444"),
    )
    _wire_selection(monkeypatch, selected, provisioning_values=(selected, selected, changed))
    monkeypatch.setattr(sys, "stdin", FakeInput(_input(raw, selected)))
    monkeypatch.setattr(sys, "stdout", StringIO())

    assert cli.main(["time-initialize"]) == 1
    assert (root / "time.pending").read_bytes() == b"administrator time publication pending\n"
    assert (root / "time.json").read_bytes() == raw
    with pytest.raises(ApprovalRefused):
        clock_store.load_administrator_time_window(expected=context)


def test_stale_selected_confirmation_refuses_before_clock_store_write(
    public_environment, monkeypatch,
):
    context, _anchor, raw, _policy, root = public_environment
    selected = _selected(context)
    changed = replace(selected, operator="operator-b")
    _wire_selection(monkeypatch, changed)

    with pytest.raises(ApprovalRefused):
        provisioning.publish_selected_administrator_time(
            raw=raw, confirmed_digest=_digest(raw, selected),
            confirmed_operation=True, recovery=False,
        )
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("bad_callback", [1, lambda: False])
def test_clock_store_revalidation_requires_callable_returning_exact_none(
    public_environment, bad_callback,
):
    context, _anchor, raw, _policy, root = public_environment

    with pytest.raises(ApprovalRefused):
        clock_store.initialize_administrator_time(
            raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
            confirmed_initialize=True, revalidate_selection=bad_callback,
        )
    assert list(root.iterdir()) == []


def test_time_durability_uncertainty_maps_to_cli_exit_two(public_environment, monkeypatch):
    context, _anchor, raw, _policy, _root = public_environment
    selected = _selected(context)
    _wire_selection(monkeypatch, selected)
    monkeypatch.setattr(
        cli, "publish_selected_administrator_time",
        lambda **_kwargs: (_ for _ in ()).throw(TimeDurabilityUncertain("synthetic uncertainty")),
    )
    monkeypatch.setattr(sys, "stdin", FakeInput(_input(raw, selected)))
    output = StringIO()
    monkeypatch.setattr(sys, "stdout", output)

    assert cli.main(["time-initialize"]) == 2
    assert "durability UNCONFIRMED" in output.getvalue()
