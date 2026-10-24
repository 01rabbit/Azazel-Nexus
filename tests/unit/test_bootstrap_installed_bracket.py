"""Nexus#324: one closure walk per bracket end, with the before/after kept.

The refresh, the initial admission and the generation admission each observe
the installed closure once before and once after the section they protect,
with a single walk each, and refuse unless the two observations are equal.
These tests pin the counts and show that a replacement between the two
observations (including an identical-byte replacement) is refused.
"""

from hashlib import sha256
import json
import os
from types import SimpleNamespace

import pytest

from azazel_nexus import installed_files as measured
from azazel_nexus.bootstrap_approval import BootstrapContext
from azazel_nexus.installed_files import InstalledFilesObservation, SelectedInstalledFiles
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs as bi


Z = "sha256:" + "0" * 64


def _context(closure=Z):
    return BootstrapContext(
        approval_id="00000000-0000-4000-8000-000000000001", node_digest=Z,
        boot_id="00000000-0000-4000-8000-000000000002", generation=1,
        generation_digest=Z, package_digest=Z, unit_closure_digest=closure,
        policy_digest=Z, approval_policy_digest=Z, security_epoch=0,
        revocation_digest=Z,
    )


# --- installed_files: one walk vs two walks, and the bracket comparison -----

@pytest.fixture
def selection(tmp_path):
    root = tmp_path / "root"
    leaf = root / "usr/libexec/azazel/helper"
    leaf.parent.mkdir(parents=True, mode=0o755)
    for directory in (root, root / "usr", root / "usr/libexec", leaf.parent):
        directory.chmod(0o755)
    payload = b"synthetic, never executed\n"
    leaf.write_bytes(payload)
    leaf.chmod(0o755)
    raw = json.dumps({"schema": "azazel-nexus/selected-installed-files/v1", "files": [
        {"path": "usr/libexec/azazel/helper", "mode": 0o755, "size": len(payload),
         "sha256": sha256(payload).hexdigest()},
    ]}, sort_keys=True, separators=(",", ":")).encode()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield leaf, raw, "sha256:" + sha256(raw).hexdigest(), fd
    finally:
        os.close(fd)


def _once(selection):
    _leaf, raw, pin, fd = selection
    return measured._observe_once_at(fd, raw, expected_digest=pin, owner=os.getuid())


def _replace_with_identical_bytes(leaf):
    replacement = leaf.parent / "replacement"
    replacement.write_bytes(leaf.read_bytes())
    replacement.chmod(0o755)
    replacement.replace(leaf)


def _count_walks(monkeypatch):
    walks = []
    original = measured._snapshot_at

    def snapshot(*args, **kwargs):
        walks.append(None)
        return original(*args, **kwargs)

    monkeypatch.setattr(measured, "_snapshot_at", snapshot)
    return walks


def test_single_walk_observation_walks_once_and_default_measurement_twice(
    selection, monkeypatch
):
    _leaf, raw, pin, fd = selection
    walks = _count_walks(monkeypatch)

    observation = _once(selection)
    assert len(walks) == 1
    assert type(observation) is InstalledFilesObservation
    assert observation.selected.manifest_digest == pin

    walks.clear()
    full = measured._measure_at(fd, raw, expected_digest=pin, owner=os.getuid())
    assert len(walks) == 2
    assert type(full) is SelectedInstalledFiles


def test_single_walk_observation_is_never_a_full_measurement():
    assert not issubclass(InstalledFilesObservation, SelectedInstalledFiles)
    assert not issubclass(SelectedInstalledFiles, InstalledFilesObservation)


def test_unchanged_closure_between_bracketing_observations_is_accepted(selection):
    _leaf, _raw, pin, _fd = selection
    before = _once(selection)
    after = _once(selection)
    bi._require_installed_files_unchanged(before, after, _context(pin))


def test_identical_byte_replacement_between_bracketing_observations_refuses(selection):
    leaf, _raw, pin, _fd = selection
    before = _once(selection)
    _replace_with_identical_bytes(leaf)
    after = _once(selection)  # still matches the pin on its own
    assert after.selected == before.selected
    with pytest.raises(ApprovalRefused):
        bi._require_installed_files_unchanged(before, after, _context(pin))


def test_content_replacement_between_bracketing_observations_refuses(selection):
    leaf, _raw, _pin, _fd = selection
    _once(selection)
    leaf.write_bytes(b"X" * leaf.stat().st_size)
    with pytest.raises(ApprovalRefused):
        _once(selection)


@pytest.mark.parametrize("bad", ["none", "selected", "digest"])
def test_bracket_comparison_requires_two_typed_observations_for_this_context(selection, bad):
    _leaf, _raw, pin, _fd = selection
    before = _once(selection)
    if bad == "none":
        args = (None, None, _context(pin))
    elif bad == "selected":
        args = (before.selected, before.selected, _context(pin))
    else:
        args = (before, before, _context(Z))
    with pytest.raises(ApprovalRefused):
        bi._require_installed_files_unchanged(*args)


# --- production composition: counts and refusal on change -------------------

class _Declared(SimpleNamespace):
    pass


class _Profile(SimpleNamespace):
    pass


class _Window(SimpleNamespace):
    pass


class _Node(SimpleNamespace):
    pass


class _Policy(SimpleNamespace):
    pass


class _Generation(SimpleNamespace):
    pass


class _Approval:
    pass


@pytest.fixture
def composed(monkeypatch):
    """Patch only the leaves; the production factories compose the rest."""
    ctx = _context()
    events = []
    observations = []
    approval = _Approval()

    def leaf(name, value):
        def read(*_args, **_kwargs):
            events.append(name)
            return value
        return read

    def observe_once(context):
        assert context == ctx
        events.append("files")
        observations.append(context)
        return state.next_files(len(observations))

    state = SimpleNamespace(next_files=lambda n: InstalledFilesObservation(
        SelectedInstalledFiles(Z, 1, 1), (("usr/x", n if state.change_at == n else 0),)),
        change_at=None)

    window = _Window(node_digest=Z, policy_digest=Z, boot_id=ctx.boot_id,
                     earliest_utc="2026-10-24T00:00:00Z", latest_utc="2026-10-24T00:00:01Z",
                     observed_boottime_ns=0, valid_until_boottime_ns=10**18)
    profile = _Profile(version=257, unit_path=("/x",))
    for name, value in {
        "DeclaredBootstrapContext": _Declared,
        "SystemdBootstrapProfile": _Profile,
        "AdministratorTimeWindow": _Window,
        "DeclaredNode": _Node,
        "BootstrapPrestartPolicy": _Policy,
        "VerifiedBootstrapGeneration": _Generation,
        "VerifiedBootstrapApproval": _Approval,
        "bootstrap_systemd_profile_digest": lambda _p: Z,
        "validate_package_snapshot": lambda _s: None,
        "observe_bootstrap_systemd_profile": leaf("profile-check", profile),
        "load_declared_bootstrap_context": leaf("declared", _Declared(
            context=ctx, operator="op", systemd_profile_digest=Z)),
        "observe_installed_packages": leaf("packages", SimpleNamespace(digest=Z)),
        "_observe_systemd_profile": leaf("profile", profile),
        "load_bootstrap_deployment": leaf("deployment", SimpleNamespace(operator="op")),
        "load_declared_node": leaf("node", _Node(node_id="n")),
        "bind_bootstrap_deployment": leaf("bind", None),
        "load_administrator_time_window": leaf("window", window),
        "load_bootstrap_approval": leaf("approval", approval),
        "read_boot_id": leaf("boot-id", ctx.boot_id),
        "read_boottime_ns": leaf("boottime", 1),
        "advance_deadline": leaf("advance_deadline", "deadline"),
        "begin_deadline": leaf("begin_deadline", "state"),
        "retain_initial_deadline": leaf("retain_initial_deadline", "retained"),
        "load_bootstrap_prestart_policy": leaf("policy", _Policy(systemd_profile_digest=Z)),
        "load_bootstrap_generation": leaf("generation", _Generation(number=1, digest=Z)),
        "check_bootstrap_capacity": leaf("capacity", None),
        "measure_bootstrap_installed_files": lambda _c: pytest.fail(
            "a bracketed caller must not take a two-walk measurement"),
        "observe_bootstrap_installed_files_once": observe_once,
    }.items():
        monkeypatch.setattr(bi, name, value)
    return SimpleNamespace(ctx=ctx, events=events, approval=approval, state=state)


def test_refresh_observes_closure_twice_around_the_whole_verification(composed):
    refresh = bi.protected_bootstrap_inputs()

    assert refresh() == "deadline"
    events = composed.events
    assert events.count("files") == 2
    files = [i for i, e in enumerate(events) if e == "files"]
    approvals = [i for i, e in enumerate(events) if e == "approval"]
    assert files[0] < approvals[0] and approvals[-1] < files[1]
    assert files[1] < events.index("advance_deadline")
    # The four context observations still re-read packages/profile/declaration.
    assert events.count("declared") == 8 and events.count("packages") == 8


def test_each_refresh_observes_fresh_and_carries_nothing_over(composed):
    refresh = bi.protected_bootstrap_inputs()
    refresh()
    refresh()
    assert composed.events.count("files") == 4


def test_generation_admission_observes_closure_twice(composed):
    admission = bi.protected_bootstrap_generation_admission()

    admission(composed.ctx)
    assert composed.events.count("files") == 2


def test_initial_admission_verify_and_retain_each_observe_twice(composed):
    admission = bi.protected_bootstrap_initial_admission()

    approval = admission.verify()
    assert composed.events.count("files") == 2
    assert admission.retain(approval) == "retained"
    assert composed.events.count("files") == 4


def test_check_cost_counts_four_single_walk_observations(composed):
    """One `_check` = refresh + generation admission: 4 observations, 0 measures."""
    bi.protected_bootstrap_inputs()()
    bi.protected_bootstrap_generation_admission()(composed.ctx)
    assert composed.events.count("files") == 4


def test_refresh_refuses_when_closure_changes_between_before_and_after(composed):
    composed.state.change_at = 2

    with pytest.raises(ApprovalRefused):
        bi.protected_bootstrap_inputs()()
    assert "advance_deadline" not in composed.events


def test_initial_retain_refuses_when_closure_changes_between_before_and_after(composed):
    admission = bi.protected_bootstrap_initial_admission()
    approval = admission.verify()
    composed.state.change_at = 4  # the retain's "after" observation

    with pytest.raises(ApprovalRefused):
        admission.retain(approval)
    assert "begin_deadline" not in composed.events
    assert "retain_initial_deadline" not in composed.events


def test_generation_admission_refuses_when_closure_changes_during_admission(composed):
    composed.state.change_at = 2

    with pytest.raises(ApprovalRefused):
        bi.protected_bootstrap_generation_admission()(composed.ctx)
    assert composed.events.count("files") == 2
