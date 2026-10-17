from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "inspect_bootstrap_mask_overlay.py"
SPEC = importlib.util.spec_from_file_location("inspect_bootstrap_mask_overlay", TOOL)
assert SPEC is not None and SPEC.loader is not None
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)


PAIR = ("azazel-auditd.service", "azazel-commissiond.service")
OVERLAY = Path("run/systemd/system.control")
MASKS = Path("etc/systemd/system")


def _candidate(fixture: overlay.MaskOverlayFixture, name: str) -> Path:
    return fixture.root / OVERLAY / name


def _assert_masks_preserved(fixture: overlay.MaskOverlayFixture) -> None:
    assert {name: (fixture.root / MASKS / name).readlink() for name in PAIR} == {
        name: Path("/dev/null") for name in PAIR
    }


def test_recover_removes_partial_grant_after_second_create_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        real_open = overlay.os.open

        def fail_second_create(name, flags, mode=0o777, *, dir_fd=None):
            if name == PAIR[1] and dir_fd is not None and flags & os.O_CREAT:
                raise OSError("injected second create failure")
            if dir_fd is None:
                return real_open(name, flags, mode)
            return real_open(name, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(overlay.os, "open", fail_second_create)
        with pytest.raises(overlay.FixtureRefused, match="publication incomplete"):
            fixture.grant()
        monkeypatch.setattr(overlay.os, "open", real_open)

        recovered = fixture.recover()
        assert recovered["phase"] == "masked"
        assert recovered["candidate_sha256"] == {}
        assert all(not _candidate(fixture, name).exists() for name in PAIR)
        _assert_masks_preserved(fixture)


def test_recover_tracks_only_bytes_successfully_written_before_write_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        real_write = overlay.os.write
        calls = 0

        def short_then_fail(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, data[:7])
            raise OSError("injected write failure")

        monkeypatch.setattr(overlay.os, "write", short_then_fail)
        with pytest.raises(overlay.FixtureRefused, match="publication incomplete"):
            fixture.grant()
        assert calls == 2
        assert _candidate(fixture, PAIR[0]).read_bytes() == fixture._written[PAIR[0]]

        monkeypatch.setattr(overlay.os, "write", real_write)
        recovered = fixture.recover()
        assert recovered["phase"] == "masked"
        assert all(not _candidate(fixture, name).exists() for name in PAIR)
        _assert_masks_preserved(fixture)


def test_recover_after_partial_withdrawal_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        real_unlink = overlay.os.unlink

        def fail_second(name, *, dir_fd=None):
            if name == PAIR[1] and dir_fd is not None:
                raise OSError("injected second unlink failure")
            if dir_fd is None:
                return real_unlink(name)
            return real_unlink(name, dir_fd=dir_fd)

        monkeypatch.setattr(overlay.os, "unlink", fail_second)
        with pytest.raises(overlay.FixtureRefused, match="withdrawal incomplete"):
            fixture.withdraw()
        monkeypatch.setattr(overlay.os, "unlink", real_unlink)

        recovered = fixture.recover()
        assert recovered["phase"] == "masked"
        assert all(not _candidate(fixture, name).exists() for name in PAIR)
        _assert_masks_preserved(fixture)


def test_recover_can_retry_after_directory_fsync_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        real_fsync = overlay.os.fsync
        failed = False

        def fail_once(fd):
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("injected recovery fsync failure")
            return real_fsync(fd)

        monkeypatch.setattr(overlay.os, "fsync", fail_once)
        with pytest.raises(overlay.FixtureRefused, match="recovery incomplete"):
            fixture.recover()
        assert all(not _candidate(fixture, name).exists() for name in PAIR)

        recovered = fixture.recover()
        assert recovered["phase"] == "masked"
        assert recovered["candidate_sha256"] == {}
        _assert_masks_preserved(fixture)


def test_keyboard_interrupt_leaves_incomplete_phase_and_is_recoverable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        real_fsync = overlay.os.fsync
        calls = 0

        def interrupt_after_first_candidate(fd):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_fsync(fd)
            raise KeyboardInterrupt

        monkeypatch.setattr(overlay.os, "fsync", interrupt_after_first_candidate)
        with pytest.raises(KeyboardInterrupt):
            fixture.grant()
        assert fixture._phase == "incomplete"
        monkeypatch.setattr(overlay.os, "fsync", real_fsync)

        assert fixture.recover()["phase"] == "masked"
        _assert_masks_preserved(fixture)


def test_recovery_keyboard_interrupt_marks_incomplete_and_can_be_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        real_unlink = overlay.os.unlink

        def interrupt_unlink(name, *, dir_fd=None):
            if dir_fd is not None:
                raise KeyboardInterrupt
            return real_unlink(name)

        monkeypatch.setattr(overlay.os, "unlink", interrupt_unlink)
        with pytest.raises(KeyboardInterrupt):
            fixture.recover()
        assert fixture._phase == "incomplete"
        assert all(_candidate(fixture, name).is_file() for name in PAIR)

        monkeypatch.setattr(overlay.os, "unlink", real_unlink)
        assert fixture.recover()["phase"] == "masked"
        _assert_masks_preserved(fixture)


def test_recover_accepts_already_absent_owned_candidate_and_is_idempotent() -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        _candidate(fixture, PAIR[0]).unlink()

        assert fixture.recover()["phase"] == "masked"
        assert fixture.recover()["phase"] == "masked"
        _assert_masks_preserved(fixture)


def test_recover_refuses_replaced_inode_even_when_bytes_match() -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        path = _candidate(fixture, PAIR[0])
        payload = path.read_bytes()
        replacement = path.with_name("replacement.tmp")
        replacement.write_bytes(payload)
        replacement.chmod(0o600)
        assert replacement.stat().st_ino != path.stat().st_ino
        replacement.replace(path)

        with pytest.raises(overlay.FixtureRefused):
            fixture.recover()

        assert path.read_bytes() == payload
        assert _candidate(fixture, PAIR[1]).is_file()
        _assert_masks_preserved(fixture)


def test_recover_refuses_mutated_partial_bytes_before_removing_any_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        real_unlink = overlay.os.unlink

        def fail_first_unlink(name, *, dir_fd=None):
            if name == PAIR[0] and dir_fd is not None:
                raise OSError("injected first unlink failure")
            if dir_fd is None:
                return real_unlink(name)
            return real_unlink(name, dir_fd=dir_fd)

        monkeypatch.setattr(overlay.os, "unlink", fail_first_unlink)
        with pytest.raises(overlay.FixtureRefused, match="withdrawal incomplete"):
            fixture.withdraw()
        monkeypatch.setattr(overlay.os, "unlink", real_unlink)

        path = _candidate(fixture, PAIR[1])
        path.write_bytes(path.read_bytes() + b"foreign mutation")
        mutated = path.read_bytes()

        with pytest.raises(overlay.FixtureRefused):
            fixture.recover()

        assert path.read_bytes() == mutated
        assert _candidate(fixture, PAIR[0]).is_file()
        _assert_masks_preserved(fixture)


def test_recover_refuses_unknown_entry_before_removing_owned_candidates() -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        foreign = fixture.root / OVERLAY / "foreign.conf"
        foreign.write_bytes(b"unknown entry\n")

        with pytest.raises(overlay.FixtureRefused):
            fixture.recover()

        assert foreign.read_bytes() == b"unknown entry\n"
        assert all(_candidate(fixture, name).is_file() for name in PAIR)
        _assert_masks_preserved(fixture)
