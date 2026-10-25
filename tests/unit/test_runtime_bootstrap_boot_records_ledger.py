"""End to end through the real activation-ledger record and the real readers.

Only the fixed host paths are redirected to temporary ones: the activation
ledger file, and the protected bootstrap directories of the selection and clock
stores (their existing test fixtures). ``_record_activation_event`` and
``_record_prior_boot`` run unpatched and the ledger is read back.
"""

from dataclasses import replace
from hashlib import sha256
from io import BytesIO, StringIO
import json
from pathlib import Path

import pytest

from azazel_nexus import bootstrap_selection_store as selection_store
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_clock import encode_administrator_anchor
from azazel_nexus.bootstrap_prior_boot import EVENT_TYPE, retired_name
from azazel_nexus.bootstrap_selection import encode_bootstrap_selection
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import activated
from azazel_nexus_runtime import bootstrap_cli as cli
from azazel_nexus_runtime import bootstrap_provisioning as provisioning
from azazel_nexus_runtime.bootstrap_declared_context import DeclaredBootstrapContext
from test_bootstrap_selection_publication import protected  # noqa: F401 - fixture
import test_runtime_bootstrap_boot_initialize as approval_tests
from test_runtime_bootstrap_boot_initialize import node  # noqa: F401 - fixture

pytest_plugins = ("test_bootstrap_clock_publication",)

PRIOR = "33333333-3333-4333-8333-333333333333"
REAL_RECORD = cli._record_activation_event


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    path = tmp_path / "state" / "activation.jsonl"
    path.parent.mkdir()
    roots = []

    def activation_ledger(root):
        roots.append(root)
        return AuditLedger(path)

    monkeypatch.setattr(activated, "_activation_ledger", activation_ledger)
    monkeypatch.setattr(cli, "_record_activation_event", REAL_RECORD)

    def entries():
        if not path.exists():
            return []
        AuditLedger(path).verify()
        assert set(roots) == {Path("/")}
        return [dict(entry.event) for entry in AuditLedger(path)]

    return entries


def _write(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def _snapshot(root):
    return {entry.name: entry.read_bytes() for entry in sorted(root.iterdir())}


def test_selection_retirement_through_the_real_ledger_record(protected, ledger):  # noqa: F811
    root, _deployment, selection, raw, _context, _uid = protected
    prior = encode_bootstrap_selection(replace(selection, boot_id=PRIOR))
    _write(root / "selection.json", prior)

    selection_store.initialize_bootstrap_selection(
        raw, confirmed_sha256=sha256(raw).hexdigest(), confirmed_initialize=True,
        record_prior_boot=cli._record_prior_boot)

    [event] = ledger()
    assert event["event_type"] == EVENT_TYPE == "activation.bootstrap_prior_boot_record_retiring"
    assert (event["record"], event["boot_id"], event["current_boot_id"], event["actor"]) == (
        "selection", PRIOR, selection.boot_id, "az-nexus-bootstrap")
    assert event["files"] == {"selection.json": {
        "sha256": "sha256:" + sha256(prior).hexdigest(),
        "retired_as": retired_name(PRIOR, "selection.json")}}
    assert type(event["occurred_at"]) is str and event["occurred_at"].endswith("Z")
    assert (root / retired_name(PRIOR, "selection.json")).read_bytes() == prior


def test_unwritable_ledger_moves_nothing(protected, ledger, tmp_path, monkeypatch):  # noqa: F811
    root, _deployment, selection, raw, _context, _uid = protected
    _write(root / "selection.json", encode_bootstrap_selection(replace(selection, boot_id=PRIOR)))
    before = _snapshot(root)
    blocked = tmp_path / "blocked.jsonl"
    blocked.mkdir()  # a directory where the ledger file should be: append fails
    monkeypatch.setattr(activated, "_activation_ledger", lambda root: AuditLedger(blocked))

    with pytest.raises(ApprovalRefused):
        selection_store.initialize_bootstrap_selection(
            raw, confirmed_sha256=sha256(raw).hexdigest(), confirmed_initialize=True,
            record_prior_boot=cli._record_prior_boot)
    assert _snapshot(root) == before


def test_approval_install_through_the_real_ledger_record(node, ledger, monkeypatch):  # noqa: F811
    prior_payload, prior_signature = approval_tests._pair(
        replace(approval_tests.CONTEXT, boot_id=PRIOR))
    _write(node.root / "approval.json", prior_payload)
    _write(node.root / "approval.sig", prior_signature)
    payload, signature = approval_tests._pair()

    code, output = approval_tests._run_install(node, payload, signature, monkeypatch)

    assert code == 0, output
    retiring, installed = ledger()
    assert (retiring["event_type"], retiring["record"], retiring["boot_id"]) == (
        "activation.bootstrap_prior_boot_record_retiring", "approval", PRIOR)
    assert sorted(retiring["files"]) == ["approval.json", "approval.sig"]
    assert installed["event_type"] == "activation.bootstrap_approval_installed"
    assert installed["payload_sha256"] == "sha256:" + sha256(payload).hexdigest()
    assert installed["actor"] == "az-nexus-bootstrap"
    assert node.events == []  # the patched recorder was not used
    assert (node.root / "approval.json").read_bytes() == payload


# -- boot-initialize with the real selection and clock readers ----------------


class Terminal:
    def __init__(self, data):
        self.buffer = BytesIO(data)

    def isatty(self):
        return True


@pytest.fixture
def stores(protected, public_environment, ledger, monkeypatch):  # noqa: F811
    selection_root, _deployment, selection, selection_raw, context, _uid = protected
    clock_context, anchor, time_raw, _policy, time_root = public_environment
    assert clock_context == context
    selected = DeclaredBootstrapContext(context, "operator-a", "sha256:" + "a" * 64)
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    monkeypatch.setattr(provisioning, "load_declared_bootstrap_context", lambda: selected)

    def no_approval(**_kwargs):
        raise ApprovalRefused("protected bootstrap approval refused")

    monkeypatch.setattr(cli, "load_bootstrap_approval", no_approval)
    # The request bytes are not the subject here (covered by approval-request tests).
    monkeypatch.setattr(cli, "_approval_request", lambda raw: (b"REQUEST-PAYLOAD", b"m"))
    time_lines = (time_raw + b"\n"
                  + provisioning.selected_time_digest(raw=time_raw, selected=selected,
                                                      recovery=False).encode()
                  + b"\nINITIALIZE\n")
    selection_lines = (selection_raw + b"\n" + sha256(selection_raw).hexdigest().encode()
                       + b"\nINITIALIZE\n")
    validity = json.dumps({"expires_at": "2026-10-13T12:05:00Z",
                           "granted_at": "2026-10-13T12:00:00Z"},
                          sort_keys=True, separators=(",", ":")).encode() + b"\n"
    return dict(selection_root=selection_root, time_root=time_root, selection=selection,
                selection_raw=selection_raw, anchor=anchor, time_raw=time_raw,
                selection_lines=selection_lines, time_lines=time_lines, validity=validity,
                ledger=ledger)


def _run(data):
    out = StringIO()
    code = cli.run_boot_initialize(source=Terminal(data), out=out)
    return code, out.getvalue()


def test_prior_boot_records_are_retired_then_rerun_skips_with_real_readers(stores):
    s = stores
    prior_selection = encode_bootstrap_selection(replace(s["selection"], boot_id=PRIOR))
    prior_time = encode_administrator_anchor(replace(s["anchor"], boot_id=PRIOR))
    _write(s["selection_root"] / "selection.json", prior_selection)
    _write(s["time_root"] / "time.json", prior_time)

    code, output = _run(s["selection_lines"] + s["time_lines"] + s["validity"])

    assert code == 0, output
    assert (s["selection_root"] / "selection.json").read_bytes() == s["selection_raw"]
    assert (s["time_root"] / "time.json").read_bytes() == s["time_raw"]
    assert (s["selection_root"] / retired_name(PRIOR, "selection.json")).read_bytes() == prior_selection
    assert (s["time_root"] / retired_name(PRIOR, "time.json")).read_bytes() == prior_time
    assert [(e["event_type"], e["record"]) for e in s["ledger"]()] == [
        (EVENT_TYPE, "selection"), (EVENT_TYPE, "time")]
    assert "REQUEST-PAYLOAD" in output

    # Re-run: the real readers find both records valid for this boot.
    code, output = _run(s["validity"])

    assert code == 0, output
    assert "Selection for this boot already published; skipped." in output
    assert "Time record for this boot already valid; skipped." in output
    assert "Enter canonical" not in output
    assert len(s["ledger"]()) == 2


def test_broken_selection_stops_without_prompting_or_changing_anything(stores):
    s = stores
    _write(s["selection_root"] / "selection.json", b'{"schema":"broken"}')
    before = _snapshot(s["selection_root"])

    code, output = _run(s["selection_lines"] + s["time_lines"] + s["validity"])

    assert code == 1, output
    assert "Enter canonical per-boot selection" not in output
    assert "Stopped at step 'selection'" in output and "Completed for this boot: none" in output
    assert _snapshot(s["selection_root"]) == before
    assert s["ledger"]() == []


def test_broken_time_record_refuses_at_time_and_changes_nothing(stores):
    s = stores
    _write(s["selection_root"] / "selection.json", s["selection_raw"])
    broken = encode_administrator_anchor(replace(s["anchor"], boot_id=PRIOR)) + b" "
    _write(s["time_root"] / "time.json", broken)
    before = (_snapshot(s["selection_root"]), _snapshot(s["time_root"]))

    code, output = _run(s["time_lines"] + s["validity"])

    assert code == 1, output
    assert "Selection for this boot already published; skipped." in output
    assert ("Stopped at step 'time' (refused; inspect retained state). Completed for this "
            "boot: selection.") in output
    assert (_snapshot(s["selection_root"]), _snapshot(s["time_root"])) == before
    assert s["ledger"]() == []
