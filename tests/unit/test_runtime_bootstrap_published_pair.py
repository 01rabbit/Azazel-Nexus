"""Exact post-publication file and mask checks using ordinary directories."""

import os

import pytest

from azazel_nexus.bootstrap_overlay_journal import advance_overlay
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_overlay_files as writer
from test_runtime_bootstrap_overlay_files import PAIR, _environment, _publish


def _check(env, expected, retained_mask_stamps):
    return writer._check_published_pair_at(
        overlay_fd=env["overlay_fd"],
        masks_fd=env["masks_fd"],
        higher_priority_fd=env["higher_fd"],
        journal_store=env["store"],
        guard=env["guard"],
        expected=expected,
        retained_mask_stamps=retained_mask_stamps,
        owner_uid=os.getuid(),
    )


def test_published_pair_matches_captured_journal_files_and_mask_baseline(tmp_path):
    with _environment(tmp_path) as env:
        retained_masks = writer._mask_paths(
            overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
            higher_priority_fd=env["higher_fd"], owner_uid=os.getuid(),
        )
        expected = _publish(env)

        assert expected.phase == "published"
        assert _check(env, expected, retained_masks) is None


@pytest.mark.parametrize(
    "mutation",
    [
        "same-bytes-new-inode",
        "same-inode-mutated-bytes",
        "missing-second-file",
        "journal-closing",
        "replaced-mask-symlink",
        "overlay-dropin",
        "higher-priority-candidate",
    ],
)
def test_published_pair_refuses_changed_files_journal_or_masks(tmp_path, mutation):
    with _environment(tmp_path) as env:
        retained_masks = writer._mask_paths(
            overlay_fd=env["overlay_fd"], masks_fd=env["masks_fd"],
            higher_priority_fd=env["higher_fd"], owner_uid=os.getuid(),
        )
        expected = _publish(env)
        unit = PAIR[0]
        path = env["overlay_path"] / unit

        if mutation == "same-bytes-new-inode":
            saved = env["overlay_path"] / f"{unit}.saved"
            path.rename(saved)  # Keep the recorded inode alive during the check.
            path.write_bytes(writer._fixed_payloads()[unit])
            path.chmod(0o644)
            assert path.read_bytes() == saved.read_bytes()
            assert path.stat().st_ino != saved.stat().st_ino
        elif mutation == "same-inode-mutated-bytes":
            identity = path.stat().st_ino
            with path.open("r+b") as candidate:
                original = candidate.read()
                candidate.seek(0)
                candidate.write(bytes([original[0] ^ 1]) + original[1:])
                candidate.flush()
            assert path.stat().st_ino == identity
        elif mutation == "missing-second-file":
            (env["overlay_path"] / PAIR[1]).unlink()
        elif mutation == "journal-closing":
            closing = advance_overlay(expected, "close-starts")
            env["store"].replace(expected, closing)
        elif mutation == "replaced-mask-symlink":
            mask = env["masks_path"] / unit
            saved = env["masks_path"] / f"{unit}.saved"
            mask.rename(saved)  # Preserve old inode so replacement is certain.
            mask.symlink_to("/dev/null")
            assert mask.is_symlink() and saved.is_symlink()
            assert mask.lstat().st_ino != saved.lstat().st_ino
        elif mutation == "overlay-dropin":
            (env["overlay_path"] / f"{unit}.d").mkdir(mode=0o700)
        else:
            (env["higher_path"] / unit).write_bytes(b"higher-priority candidate")
            (env["higher_path"] / unit).chmod(0o644)

        with pytest.raises(ApprovalRefused):
            _check(env, expected, retained_masks)
