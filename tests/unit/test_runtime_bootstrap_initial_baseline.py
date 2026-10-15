"""Initial mask baseline without journal creation or inferred file ownership."""

import asyncio
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_overlay_journal import new_overlay_journal
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitKey
from test_runtime_bootstrap_close_files import _files
from test_runtime_bootstrap_close_sequence import FakeBus, Message
from test_runtime_bootstrap_overlay_files import PAIR, _environment, _intent, _publish
from test_runtime_bootstrap_overlay_withdraw import _withdraw_environment
from test_runtime_bootstrap_withdrawal_binding import _withdrawal


def test_initial_close_only_observes_persistent_masks_without_creating_journal(tmp_path):
    with _environment(tmp_path) as env:
        files = _files(env)
        assert files.close() is None
        assert files.check() == tuple(
            (key, str(env["masks_path"] / name))
            for key, name in zip((UnitKey.AUDITD, UnitKey.COMMISSIOND), PAIR, strict=True)
        )
        assert env["store"].load_optional() is None
        assert list(env["journal_path"].iterdir()) == []
        assert list(env["overlay_path"].iterdir()) == []


@pytest.mark.parametrize("kind", ["file", "empty-mask", "symlink", "directory"])
def test_missing_journal_never_adopts_existing_overlay(tmp_path, kind):
    with _environment(tmp_path) as env:
        candidate = env["overlay_path"] / PAIR[0]
        if kind == "file":
            candidate.write_bytes(b"unowned")
        elif kind == "empty-mask":
            candidate.touch()
        elif kind == "symlink":
            candidate.symlink_to("/dev/null")
        else:
            candidate.mkdir()
        with pytest.raises(ApprovalRefused, match="unjournaled"):
            _files(env).close()
        assert candidate.exists()
        assert env["store"].load_optional() is None
        if kind == "file":
            assert candidate.read_bytes() == b"unowned"


@pytest.mark.parametrize("change", ["journal", "overlay", "mask"])
def test_initial_baseline_is_rechecked_not_a_cached_permission(tmp_path, change):
    with _environment(tmp_path) as env:
        files = _files(env)
        files.close()
        if change == "journal":
            env["store"].create(new_overlay_journal(_intent()))
        elif change == "overlay":
            (env["overlay_path"] / PAIR[1]).write_text("unexpected")
        else:
            (env["masks_path"] / PAIR[1]).unlink()
        with pytest.raises(ApprovalRefused):
            files.check()


def test_missing_journal_does_not_resume_or_authorize_withdrawal(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        files = _withdrawal(env)
        assert files.resume_closure() is False
        with pytest.raises(ApprovalRefused):
            files.withdraw(lambda: None)
        assert env["store"].load_optional() is None


def test_prior_owned_closure_cannot_fall_back_to_absent_journal(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        files = _files(env)
        files.close()
        env["store"].remove(env["store"].load())
        with pytest.raises(ApprovalRefused, match="disappeared"):
            files.close()


def test_real_initial_files_feed_manager_reload_and_drain_without_fabricated_grant(tmp_path):
    with _withdraw_environment(tmp_path) as env:
        def persistent_fragments(_number, name, properties):
            properties["FragmentPath"] = SimpleNamespace(
                signature="s", value=str(env["masks_path"] / name),
            )
            return properties

        bus = FakeBus(snapshots=[[], []], mutate=persistent_fragments)
        bus.disconnect = lambda: None

        class Session:
            def __init__(self):
                self._bus = bus
                self._loop = asyncio.new_event_loop()
                self._message_factory = Message
                self._message_type = SimpleNamespace(ERROR=3, METHOD_RETURN=1)

            def close(self):
                self._loop.close()

        manager = BootstrapNarrowingManager(
            job_timeout_seconds=0.2, session_factory=Session,
            closed_overlay_files=_files(env), withdrawal_files=_withdrawal(env),
        )
        manager.close_starts()
        members = [call.member for call in bus.calls]
        assert "Reload" in members and "ListJobs" in members
        assert not {"StartUnit", "UnmaskUnitFiles", "EnableUnitFiles"} & set(members)
        assert env["store"].load_optional() is None
        assert list(env["overlay_path"].iterdir()) == []
