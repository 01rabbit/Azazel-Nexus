"""Owned overlay close adapter tests using ordinary temporary directories."""

import asyncio
import os
from dataclasses import replace
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_overlay_journal import OverlayJournal, new_overlay_journal
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_close_files import BootstrapClosedOverlayFiles
from azazel_nexus_runtime.bootstrap_manager import BootstrapNarrowingManager
from azazel_nexus_runtime.units import UnitKey
from test_runtime_bootstrap_overlay_files import (
    PAIR,
    _environment,
    _intent,
    _publish,
)
from test_runtime_bootstrap_close_sequence import FakeBus, Message


def _files(env):
    return BootstrapClosedOverlayFiles(
        overlay_fd=env["overlay_fd"],
        masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"],
        overlay_path=env["overlay_path"],
        masks_path=env["masks_path"],
        higher_priority_path=env["higher_path"],
        journal_store=env["store"],
        guard=env["guard"],
        owner_uid=os.getuid(),
    )


def _expected_fragments(overlay_path, masks_path):
    return (
        (UnitKey.AUDITD, str(overlay_path / PAIR[0])),
        (UnitKey.COMMISSIOND, str(overlay_path / PAIR[1])),
    )


def test_close_published_candidates_returns_none_and_check_returns_exact_fragments(
    tmp_path,
):
    with _environment(tmp_path) as env:
        _publish(env)
        files = _files(env)

        assert files.close() is None
        assert files.check() == _expected_fragments(
            env["overlay_path"], env["masks_path"]
        )
        assert all((env["overlay_path"] / unit).read_bytes() == b"" for unit in PAIR)


def test_partial_publication_closes_only_recorded_candidate(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        real_open = os.open

        def fail_second_create(name, flags, mode=0o777, *, dir_fd=None):
            if name == PAIR[1] and dir_fd == env["overlay_fd"] and flags & os.O_CREAT:
                raise OSError("injected second candidate create failure")
            if dir_fd is None:
                return real_open(name, flags, mode)
            return real_open(name, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr("azazel_nexus_runtime.bootstrap_overlay_files.os.open", fail_second_create)
        with pytest.raises(ApprovalRefused):
            _publish(env)
        monkeypatch.setattr("azazel_nexus_runtime.bootstrap_overlay_files.os.open", real_open)

        files = _files(env)
        assert files.close() is None
        assert files.check() == (
            (UnitKey.AUDITD, str(env["overlay_path"] / PAIR[0])),
            (UnitKey.COMMISSIOND, str(env["masks_path"] / PAIR[1])),
        )
        assert (env["overlay_path"] / PAIR[0]).read_bytes() == b""
        assert not (env["overlay_path"] / PAIR[1]).exists()


def test_empty_intent_closes_without_adopting_or_creating_candidates(tmp_path):
    with _environment(tmp_path) as env:
        env["store"].create(new_overlay_journal(_intent()))
        files = _files(env)

        assert files.close() is None
        assert files.check() == (
            (UnitKey.AUDITD, str(env["masks_path"] / PAIR[0])),
            (UnitKey.COMMISSIOND, str(env["masks_path"] / PAIR[1])),
        )
        assert list(env["overlay_path"].iterdir()) == []


def test_check_before_close_refuses(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        with pytest.raises(ApprovalRefused):
            _files(env).check()


def test_check_refuses_replaced_overlay_directory(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        files = _files(env)
        files.close()
        moved = env["overlay_path"].with_name("system.control.old")
        env["overlay_path"].rename(moved)
        env["overlay_path"].mkdir(mode=0o700)

        with pytest.raises(ApprovalRefused):
            files.check()


def test_check_refuses_replaced_owned_file_even_with_same_contents(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        files = _files(env)
        files.close()
        target = env["overlay_path"] / PAIR[0]
        target.unlink()
        target.write_bytes(b"")
        target.chmod(0o600)

        with pytest.raises(ApprovalRefused):
            files.check()


def test_check_refuses_changed_journal(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        files = _files(env)
        files.close()
        current = env["store"].load()
        changed = OverlayJournal(
            replace(current.intent, grant_id="1" * 32),
            current.phase,
            current.owned_files,
        )
        env["store"].replace(current, changed)

        with pytest.raises(ApprovalRefused):
            files.check()


def test_check_refuses_nonempty_owned_file(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        files = _files(env)
        files.close()
        target = env["overlay_path"] / PAIR[0]
        target.write_bytes(b"unexpected")

        with pytest.raises(ApprovalRefused):
            files.check()


def test_close_refuses_unowned_path_and_preserves_it(tmp_path):
    with _environment(tmp_path) as env:
        env["store"].create(new_overlay_journal(_intent()))
        foreign = env["overlay_path"] / PAIR[0]
        foreign.write_bytes(b"foreign")

        with pytest.raises(ApprovalRefused):
            _files(env).close()
        assert foreign.read_bytes() == b"foreign"


def test_close_refuses_persistent_mask_conflict(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        mask = env["masks_path"] / PAIR[0]
        mask.unlink()
        mask.symlink_to("/tmp/not-the-mask")

        with pytest.raises(ApprovalRefused):
            _files(env).close()
        assert (env["overlay_path"] / PAIR[0]).read_bytes()
        assert os.readlink(mask) == "/tmp/not-the-mask"


def test_manager_close_starts_closes_real_files_and_reloads_fake_systemd(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)

        def report_overlay_fragments(_call_number, name, properties):
            properties["FragmentPath"] = SimpleNamespace(
                signature="s", value=str(env["overlay_path"] / name),
            )
            return properties

        bus = FakeBus(snapshots=[[], []], mutate=report_overlay_fragments)
        bus.disconnect = lambda: None

        class Session:
            def __init__(self):
                self._bus = bus
                self._loop = asyncio.new_event_loop()
                self._message_factory = Message
                self._message_type = SimpleNamespace(ERROR=3, METHOD_RETURN=1)

            def close(self):
                if not self._loop.is_closed():
                    self._loop.close()

        manager = BootstrapNarrowingManager(
            job_timeout_seconds=0.2,
            session_factory=Session,
            closed_overlay_files=_files(env),
        )

        manager.close_starts()

        assert bus.reloaded
        assert env["store"].load().phase == "closing"
        assert all((env["overlay_path"] / unit).read_bytes() == b"" for unit in PAIR)
        members = [call.member for call in bus.calls]
        assert members.count("Reload") == 1
        assert "ListJobs" in members
        assert all(
            (call.member != "Reload" or call.body == [])
            for call in bus.calls
        )
        assert all(
            call.member not in {"StartUnit", "UnmaskUnitFiles", "EnableUnitFiles"}
            for call in bus.calls
        )
