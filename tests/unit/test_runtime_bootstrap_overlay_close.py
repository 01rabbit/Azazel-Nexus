import os
import stat
import subprocess
import sys

import pytest
from azazel_nexus_runtime import bootstrap_overlay_files as writer

from azazel_nexus.bootstrap_overlay_journal import OverlayJournalDurabilityUncertain
from azazel_nexus.operator_trust import ApprovalRefused
from test_runtime_bootstrap_overlay_files import PAIR, _environment, _intent, _publish


def _close(env):
    return writer._close_candidates_at(
        overlay_fd=env["overlay_fd"],
        masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"],
        journal_store=env["store"],
        guard=env["guard"],
        owner_uid=os.getuid(),
    )


def _identity(path):
    info = path.stat(follow_symlinks=False)
    return info.st_dev, info.st_ino


def test_close_preserves_owned_inodes_and_persistent_masks(tmp_path):
    with _environment(tmp_path) as env:
        published = _publish(env)
        identities = {unit: _identity(env["overlay_path"] / unit) for unit in PAIR}
        masks = {unit: os.readlink(env["masks_path"] / unit) for unit in PAIR}

        result = _close(env)

        assert result.phase == "closing"
        assert result.owned_files == published.owned_files
        assert env["store"].load() == result
        for unit in PAIR:
            path = env["overlay_path"] / unit
            assert path.read_bytes() == b""
            assert _identity(path) == identities[unit]
            info = path.stat(follow_symlinks=False)
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            mask = env["masks_path"] / unit
            assert mask.is_symlink() and os.readlink(mask) == masks[unit] == "/dev/null"


def test_closing_journal_is_durable_before_first_truncate(tmp_path, monkeypatch, private_os):
    private_os(writer)
    with _environment(tmp_path) as env:
        published = _publish(env)
        real_ftruncate = os.ftruncate
        observed = []

        def inspect_before_truncate(fd, length):
            assert env["store"].load().phase == "closing"
            observed.append((fd, length))
            return real_ftruncate(fd, length)

        monkeypatch.setattr(writer.os, "ftruncate", inspect_before_truncate)
        result = _close(env)

        assert result.phase == "closing"
        assert result.owned_files == published.owned_files
        assert len(observed) == len(PAIR)
        assert all(length == 0 for _fd, length in observed)


def test_second_truncate_failure_recovers_from_mixed_owned_files(tmp_path, monkeypatch, private_os):
    private_os(writer)
    with _environment(tmp_path) as env:
        _publish(env)
        real_ftruncate = os.ftruncate
        calls = 0

        def fail_second(fd, length):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected second truncate failure")
            return real_ftruncate(fd, length)

        monkeypatch.setattr(writer.os, "ftruncate", fail_second)
        with pytest.raises(ApprovalRefused):
            _close(env)
        monkeypatch.setattr(writer.os, "ftruncate", real_ftruncate)
        assert env["store"].load().phase == "closing"
        # Closing proceeds in reverse dependency order: commissiond closes first.
        assert (env["overlay_path"] / PAIR[0]).read_bytes() == writer._fixed_payloads()[PAIR[0]]
        assert (env["overlay_path"] / PAIR[1]).read_bytes() == b""

        recovered = _close(env)
        assert recovered.phase == "closing"
        assert all((env["overlay_path"] / unit).read_bytes() == b"" for unit in PAIR)


def test_file_fsync_failure_is_recoverable_while_closing(tmp_path, monkeypatch, private_os):
    private_os(writer)
    with _environment(tmp_path) as env:
        _publish(env)
        real_fsync = os.fsync
        injected = False

        def fail_overlay_fsync(fd):
            nonlocal injected
            info = os.fstat(fd)
            if not injected and stat.S_ISREG(info.st_mode) and info.st_size == 0:
                injected = True
                raise OSError("injected empty overlay fsync failure")
            return real_fsync(fd)

        monkeypatch.setattr(writer.os, "fsync", fail_overlay_fsync)
        with pytest.raises(ApprovalRefused):
            _close(env)
        monkeypatch.setattr(writer.os, "fsync", real_fsync)
        assert injected
        assert env["store"].load().phase == "closing"

        result = _close(env)
        assert result.phase == "closing"
        assert all((env["overlay_path"] / unit).read_bytes() == b"" for unit in PAIR)


def test_repeat_close_is_idempotent(tmp_path, monkeypatch, private_os):
    private_os(writer)
    with _environment(tmp_path) as env:
        _publish(env)
        first = _close(env)
        identities = {unit: _identity(env["overlay_path"] / unit) for unit in PAIR}
        stamps = {
            unit: (
                (env["overlay_path"] / unit).stat(follow_symlinks=False).st_mtime_ns,
                (env["overlay_path"] / unit).stat(follow_symlinks=False).st_ctime_ns,
            )
            for unit in PAIR
        }

        def unexpected_truncate(_fd, _length):
            pytest.fail("repeated close must not truncate an already-empty file")

        monkeypatch.setattr(writer.os, "ftruncate", unexpected_truncate)
        second = _close(env)

        assert second == first
        assert env["store"].load() == first
        assert {unit: _identity(env["overlay_path"] / unit) for unit in PAIR} == identities
        assert {
            unit: (
                (env["overlay_path"] / unit).stat(follow_symlinks=False).st_mtime_ns,
                (env["overlay_path"] / unit).stat(follow_symlinks=False).st_ctime_ns,
            )
            for unit in PAIR
        } == stamps


def test_missing_owned_path_refuses_without_losing_closing_journal(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        (env["overlay_path"] / PAIR[0]).unlink()
        with pytest.raises(ApprovalRefused):
            _close(env)
        assert env["store"].load().phase == "published"


def test_unowned_same_bytes_are_never_adopted_during_intent_recovery(tmp_path):
    with _environment(tmp_path) as env:
        intent = writer.new_overlay_journal(_intent())
        env["store"].create(intent)
        foreign = env["overlay_path"] / PAIR[0]
        foreign.write_bytes(writer._fixed_payloads()[PAIR[0]])
        with pytest.raises(ApprovalRefused):
            _close(env)
        assert foreign.read_bytes() == writer._fixed_payloads()[PAIR[0]]


def _retain_partial_publication(env, monkeypatch):
    real_open = os.open

    def fail_second_create(name, flags, mode=0o777, *, dir_fd=None):
        if name == PAIR[1] and dir_fd == env["overlay_fd"] and flags & os.O_CREAT:
            raise OSError("injected second candidate open failure")
        if dir_fd is None:
            return real_open(name, flags, mode)
        return real_open(name, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(writer.os, "open", fail_second_create)
    with pytest.raises(ApprovalRefused):
        _publish(env)
    monkeypatch.setattr(writer.os, "open", real_open)
    assert env["store"].load().phase == "partial"


def test_partial_publication_closes_owned_file_when_unowned_path_is_absent(
    tmp_path, monkeypatch, private_os
):
    private_os(writer)
    with _environment(tmp_path) as env:
        _retain_partial_publication(env, monkeypatch)

        result = _close(env)

        assert result.phase == "closing"
        assert tuple(row[0] for row in result.owned_files) == (PAIR[0],)
        assert (env["overlay_path"] / PAIR[0]).read_bytes() == b""
        assert not (env["overlay_path"] / PAIR[1]).exists()


def test_partial_publication_refuses_unowned_same_byte_file(tmp_path, monkeypatch, private_os):
    private_os(writer)
    with _environment(tmp_path) as env:
        _retain_partial_publication(env, monkeypatch)
        foreign = env["overlay_path"] / PAIR[1]
        foreign.write_bytes(writer._fixed_payloads()[PAIR[1]])

        with pytest.raises(ApprovalRefused):
            _close(env)

        assert env["store"].load().phase == "partial"
        assert foreign.read_bytes() == writer._fixed_payloads()[PAIR[1]]


def test_empty_owned_file_before_closing_intent_is_refused(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        path = env["overlay_path"] / PAIR[0]
        with path.open("wb"):
            pass

        with pytest.raises(ApprovalRefused):
            _close(env)

        assert env["store"].load().phase == "published"
        assert path.read_bytes() == b""


def test_changed_owned_bytes_during_closing_recovery_are_refused(tmp_path):
    with _environment(tmp_path) as env:
        _publish(env)
        published = env["store"].load()
        closing = type(published)(published.intent, "closing", published.owned_files)
        env["store"].replace(published, closing)
        path = env["overlay_path"] / PAIR[0]
        path.write_bytes(b"different bytes during recovery")

        with pytest.raises(ApprovalRefused):
            _close(env)

        assert env["store"].load() == closing
        assert path.read_bytes() == b"different bytes during recovery"


def test_journal_write_failure_prevents_truncation(tmp_path, monkeypatch):
    with _environment(tmp_path) as env:
        _publish(env)
        before = {unit: (env["overlay_path"] / unit).read_bytes() for unit in PAIR}

        def fail_replace(_expected, _updated):
            raise ApprovalRefused("injected close journal write failure")

        monkeypatch.setattr(env["store"], "replace", fail_replace)
        with pytest.raises(ApprovalRefused):
            _close(env)

        assert env["store"].load().phase == "published"
        assert {unit: (env["overlay_path"] / unit).read_bytes() for unit in PAIR} == before


def test_uncertain_closing_persistence_must_be_reaffirmed_before_recovery(
    tmp_path, monkeypatch, private_os
):
    private_os(writer)
    with _environment(tmp_path) as env:
        _publish(env)
        before = {
            unit: (env["overlay_path"] / unit).read_bytes()
            for unit in PAIR
        }
        real_replace = env["store"].replace
        real_ftruncate = os.ftruncate

        def replace_then_report_uncertain(expected, updated):
            real_replace(expected, updated)
            assert updated.phase == "closing"
            raise OverlayJournalDurabilityUncertain("injected directory fsync uncertainty")

        monkeypatch.setattr(env["store"], "replace", replace_then_report_uncertain)
        with pytest.raises(ApprovalRefused):
            _close(env)
        assert env["store"].load().phase == "closing"
        assert {
            unit: (env["overlay_path"] / unit).read_bytes()
            for unit in PAIR
        } == before

        def fail_reaffirmation(_expected, _updated):
            raise OverlayJournalDurabilityUncertain("injected reaffirmation failure")

        def unexpected_truncate(_fd, _length):
            pytest.fail("recovery must durably reaffirm closing before truncation")

        monkeypatch.setattr(env["store"], "replace", fail_reaffirmation)
        monkeypatch.setattr(writer.os, "ftruncate", unexpected_truncate)
        with pytest.raises(ApprovalRefused):
            _close(env)
        assert {
            unit: (env["overlay_path"] / unit).read_bytes()
            for unit in PAIR
        } == before

        monkeypatch.setattr(env["store"], "replace", real_replace)
        monkeypatch.setattr(writer.os, "ftruncate", real_ftruncate)
        result = _close(env)
        assert result.phase == "closing"
        assert all((env["overlay_path"] / unit).read_bytes() == b"" for unit in PAIR)


@pytest.mark.parametrize("conflict", ["higher", "dropin"])
def test_conflict_appearing_after_closing_intent_prevents_truncation(
    tmp_path, monkeypatch, conflict, private_os
):
    private_os(writer)
    with _environment(tmp_path) as env:
        _publish(env)
        before = {
            unit: (env["overlay_path"] / unit).read_bytes()
            for unit in PAIR
        }
        real_replace = env["store"].replace

        def replace_then_create_conflict(expected, updated):
            result = real_replace(expected, updated)
            assert updated.phase == "closing"
            if conflict == "higher":
                (env["higher_path"] / PAIR[0]).write_bytes(b"override")
            else:
                (env["overlay_path"] / f"{PAIR[0]}.d").mkdir(mode=0o700)
            return result

        def unexpected_truncate(_fd, _length):
            pytest.fail("new path conflict must be checked before truncation")

        monkeypatch.setattr(env["store"], "replace", replace_then_create_conflict)
        monkeypatch.setattr(writer.os, "ftruncate", unexpected_truncate)
        with pytest.raises(ApprovalRefused):
            _close(env)

        assert env["store"].load().phase == "closing"
        assert {
            unit: (env["overlay_path"] / unit).read_bytes()
            for unit in PAIR
        } == before


@pytest.mark.parametrize("conflict", ["replaced", "different-hash", "hardlink", "symlink", "mask", "higher"])
def test_close_refuses_untrusted_overlay_or_environment(tmp_path, conflict):
    with _environment(tmp_path) as env:
        _publish(env)
        target = env["overlay_path"] / PAIR[0]
        if conflict == "replaced":
            replacement = env["overlay_path"] / "replacement"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o644)
            replacement.replace(target)
        elif conflict == "different-hash":
            target.write_bytes(b"changed payload")
        elif conflict == "hardlink":
            os.link(target, env["overlay_path"] / "extra-link")
        elif conflict == "symlink":
            target.unlink()
            target.symlink_to("/dev/null")
        elif conflict == "mask":
            mask = env["masks_path"] / PAIR[0]
            mask.unlink()
            mask.symlink_to("/tmp/not-the-mask")
        elif conflict == "higher":
            (env["higher_path"] / PAIR[0]).write_bytes(b"override")

        with pytest.raises(ApprovalRefused):
            _close(env)
        assert env["store"].load().phase == "published"


def test_systemd_analyze_recognizes_closed_files_as_masks(tmp_path):
    analyzer = "/usr/bin/systemd-analyze"
    if sys.platform != "linux" or not os.path.isfile(analyzer):
        pytest.skip("requires Linux /usr/bin/systemd-analyze")

    with _environment(tmp_path) as env:
        _publish(env)
        _close(env)

        child_env = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            # Exclude persistent masks: each diagnostic must derive from the
            # actual empty candidate produced by the close transaction.
            "SYSTEMD_UNIT_PATH": "/system.control",
        }
        result = subprocess.run(
            [
                analyzer,
                f"--root={tmp_path}",
                "--generators=no",
                "--man=no",
                "verify",
                *PAIR,
            ],
            env=child_env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        output = result.stdout + result.stderr
        assert result.returncode != 0, output
        for unit in PAIR:
            assert any(unit in line and "masked" in line.lower()
                       for line in output.splitlines()), output
