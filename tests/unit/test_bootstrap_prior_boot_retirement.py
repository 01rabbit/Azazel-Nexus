"""Prior-boot selection/time records are moved aside only inside the owner's
confirmed initialize, only with a durable record first, and never at startup."""

from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from azazel_nexus import bootstrap_clock_store as clock_store
from azazel_nexus import bootstrap_selection_store as store
from azazel_nexus.bootstrap_clock import encode_administrator_anchor
from azazel_nexus.bootstrap_prior_boot import EVENT_TYPE, retired_name
from azazel_nexus.bootstrap_selection import encode_bootstrap_selection
from azazel_nexus.operator_trust import ApprovalRefused
from test_bootstrap_selection_publication import protected  # noqa: F401 - fixture

pytest_plugins = ("test_bootstrap_clock_publication",)

PRIOR = "33333333-3333-4333-8333-333333333333"
REPO = Path(__file__).resolve().parents[2]


def _write(path, raw, mode=0o600):
    path.write_bytes(raw)
    path.chmod(mode)


def _snapshot(root):
    return {entry.name: entry.read_bytes() for entry in sorted(root.iterdir())}


class Recorder:
    def __init__(self, root, name, result=True):
        self.root, self.name, self.result, self.events = root, name, result, []

    def __call__(self, event):
        # Recorded before anything moves: the original is still in place.
        assert (self.root / self.name).exists()
        self.events.append(event)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _initialize_selection(raw, record):
    store.initialize_bootstrap_selection(raw, confirmed_sha256=sha256(raw).hexdigest(),
                                         confirmed_initialize=True, record_prior_boot=record)


# -- selection ---------------------------------------------------------------


def test_prior_boot_selection_is_recorded_then_moved_aside_then_created(protected):  # noqa: F811
    root, _deployment, selection, raw, _context, _uid = protected
    prior = encode_bootstrap_selection(replace(selection, boot_id=PRIOR))
    _write(root / "selection.json", prior)
    record = Recorder(root, "selection.json")

    _initialize_selection(raw, record)

    assert (root / "selection.json").read_bytes() == raw
    archived = root / retired_name(PRIOR, "selection.json")
    assert archived.read_bytes() == prior
    assert archived.stat().st_mode & 0o777 == 0o600 and archived.stat().st_nlink == 1
    assert not (root / "selection.pending").exists()
    assert store.load_bootstrap_selection() == selection
    [event] = record.events
    assert event == {
        "event_type": EVENT_TYPE, "record": "selection", "boot_id": PRIOR,
        "current_boot_id": selection.boot_id,
        "files": {"selection.json": {"sha256": "sha256:" + sha256(prior).hexdigest(),
                                     "retired_as": archived.name}},
    }


def _noncanonical(selection):
    return encode_bootstrap_selection(replace(selection, boot_id=PRIOR)) + b" "


@pytest.mark.parametrize("case", [
    "no-record-callback", "same-boot", "pending", "noncanonical", "record-false",
    "record-raises", "archive-present", "not-private",
])
def test_selection_missing_condition_refuses_and_changes_nothing(protected, case):  # noqa: F811
    root, _deployment, selection, raw, _context, _uid = protected
    existing = encode_bootstrap_selection(replace(selection, boot_id=PRIOR))
    record = Recorder(root, "selection.json")
    if case == "no-record-callback":
        record = None
    elif case == "same-boot":
        existing = encode_bootstrap_selection(replace(selection, generation=selection.generation + 1))
    elif case == "pending":
        _write(root / "selection.pending", b"administrator bootstrap selection publication pending\n")
    elif case == "noncanonical":
        existing = _noncanonical(selection)
    elif case == "record-false":
        record = Recorder(root, "selection.json", result=False)
    elif case == "record-raises":
        record = Recorder(root, "selection.json", result=OSError("ledger"))
    elif case == "archive-present":
        _write(root / retired_name(PRIOR, "selection.json"), b"older")
    _write(root / "selection.json", existing, 0o644 if case == "not-private" else 0o600)
    before = _snapshot(root)

    with pytest.raises(ApprovalRefused):
        _initialize_selection(raw, record)

    assert _snapshot(root) == before
    if case in {"same-boot", "pending", "noncanonical", "archive-present", "not-private"}:
        assert record.events == []


def test_selection_recovery_never_retires(protected):  # noqa: F811
    root, _deployment, selection, raw, _context, _uid = protected
    _write(root / "selection.json", encode_bootstrap_selection(replace(selection, boot_id=PRIOR)))
    before = _snapshot(root)

    with pytest.raises(ApprovalRefused):
        store.recover_bootstrap_selection(raw, confirmed_sha256=sha256(raw).hexdigest(),
                                          confirmed_recovery=True)
    assert _snapshot(root) == before


def test_startup_reader_refuses_prior_boot_selection_without_moving_it(protected):  # noqa: F811
    root, _deployment, selection, _raw, _context, _uid = protected
    _write(root / "selection.json", encode_bootstrap_selection(replace(selection, boot_id=PRIOR)))
    before = _snapshot(root)

    with pytest.raises(store.SelectionReadRefused) as refused:
        store.load_bootstrap_selection()
    assert refused.value.reason == "boot binding differs from the current boot"
    assert _snapshot(root) == before


def test_startup_modules_cannot_reach_retirement():
    """Boot-time execution only reads; retirement is wired only by the owner CLI."""
    runtime = REPO / "runtime" / "src" / "azazel_nexus_runtime"
    library = REPO / "src" / "azazel_nexus"
    for path in (runtime / "activated.py", runtime / "bootstrap_entrypoint.py",
                 runtime / "bootstrap.py", runtime / "bootstrap_inputs.py",
                 library / "bootstrap_selection_optional.py"):
        text = path.read_text(encoding="utf-8")
        for symbol in ("record_prior_boot", "retire_prior_boot_records", "bootstrap_prior_boot",
                       "install_bootstrap_approval", "initialize_bootstrap_selection",
                       "initialize_administrator_time"):
            assert symbol not in text, (path.name, symbol)
    users = sorted(path.name for path in (*runtime.glob("*.py"), *library.glob("*.py"))
                   if "record_prior_boot=_record_prior_boot" in path.read_text(encoding="utf-8"))
    assert users == ["bootstrap_cli.py"]


# -- time --------------------------------------------------------------------


def _prior_anchor(anchor):
    return encode_administrator_anchor(replace(anchor, boot_id=PRIOR))


def _initialize_time(context, raw, record):
    clock_store.initialize_administrator_time(
        raw, expected=context, confirmed_sha256=sha256(raw).hexdigest(),
        confirmed_initialize=True, record_prior_boot=record)


def test_prior_boot_time_is_recorded_then_moved_aside_then_created(public_environment):
    context, anchor, raw, _policy, root = public_environment
    prior = _prior_anchor(anchor)
    _write(root / "time.json", prior)
    record = Recorder(root, "time.json")

    _initialize_time(context, raw, record)

    assert (root / "time.json").read_bytes() == raw
    assert (root / retired_name(PRIOR, "time.json")).read_bytes() == prior
    assert not (root / "time.pending").exists()
    [event] = record.events
    assert (event["record"], event["boot_id"], event["current_boot_id"]) == (
        "time", PRIOR, context.boot_id)
    assert clock_store.load_administrator_time_window(expected=context).boot_id == context.boot_id


@pytest.mark.parametrize("case", [
    "no-record-callback", "same-boot-expired", "pending", "noncanonical", "record-false",
    "archive-present",
])
def test_time_missing_condition_refuses_and_changes_nothing(public_environment, case):
    context, anchor, raw, _policy, root = public_environment
    existing = _prior_anchor(anchor)
    record = Recorder(root, "time.json")
    if case == "no-record-callback":
        record = None
    elif case == "same-boot-expired":
        existing = encode_administrator_anchor(replace(anchor, expires_boottime_ns=anchor.boottime_ns + 1))
    elif case == "pending":
        _write(root / "time.pending", b"administrator time publication pending\n")
    elif case == "noncanonical":
        existing = existing + b"\n"
    elif case == "record-false":
        record = Recorder(root, "time.json", result=False)
    elif case == "archive-present":
        _write(root / retired_name(PRIOR, "time.json"), b"older")
    _write(root / "time.json", existing)
    before = _snapshot(root)

    with pytest.raises(ApprovalRefused):
        _initialize_time(context, raw, record)

    assert _snapshot(root) == before
    if case not in {"no-record-callback", "record-false"}:
        assert record.events == []


def test_time_new_anchor_of_another_boot_refuses_before_any_retirement(public_environment):
    context, anchor, _raw, _policy, root = public_environment
    _write(root / "time.json", _prior_anchor(anchor))
    record = Recorder(root, "time.json")
    before = _snapshot(root)
    other = encode_administrator_anchor(replace(anchor, boot_id=PRIOR))

    with pytest.raises(ApprovalRefused):
        _initialize_time(context, other, record)
    assert _snapshot(root) == before and record.events == []
