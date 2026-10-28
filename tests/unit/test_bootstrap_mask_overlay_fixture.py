from __future__ import annotations

import hashlib
import importlib.util
import inspect
import os
from pathlib import Path
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "inspect_bootstrap_mask_overlay.py"
SPEC = importlib.util.spec_from_file_location("inspect_bootstrap_mask_overlay", TOOL)
assert SPEC is not None and SPEC.loader is not None
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)


PAIR = ("azazel-auditd.service", "azazel-commissiond.service")
VENDOR = Path("usr/lib/systemd/system")
MASKS = Path("etc/systemd/system")
OVERLAY = Path("run/systemd/system.control")
HIGHER = Path("etc/systemd/system.control")


def test_fixture_roundtrip_preserves_base_and_models_rendered_units() -> None:
    with overlay.MaskOverlayFixture() as fixture:
        initial = fixture.snapshot()
        vendor_bytes = {
            name: (fixture.root / VENDOR / name).read_bytes()
            for name in (*PAIR, "azazel-activated.service")
        }
        masks = {
            name: (fixture.root / MASKS / name).readlink()
            for name in PAIR
        }

        assert initial["phase"] == "masked"
        assert initial["persistent_mask_targets"] == {
            name: "/dev/null" for name in PAIR
        }
        assert initial["candidate_sha256"] == {}

        candidate = fixture.grant()
        assert candidate["phase"] == "candidate"
        assert candidate["persistent_mask_targets"] == initial["persistent_mask_targets"]
        for name in PAIR:
            raw = (fixture.root / OVERLAY / name).read_bytes()
            profile = next(profile for profile in overlay.PROFILES if profile.unit == name)
            rendered = overlay.render_unit(profile).encode()
            assert raw == rendered
            assert candidate["candidate_sha256"][name] == hashlib.sha256(rendered).hexdigest()
            assert (fixture.root / MASKS / name).readlink() == Path("/dev/null")

        withdrawn = fixture.withdraw()
        assert withdrawn["phase"] == "masked"
        assert withdrawn["candidate_sha256"] == {}
        assert not any((fixture.root / OVERLAY / name).exists() for name in PAIR)
        assert {name: (fixture.root / VENDOR / name).read_bytes() for name in vendor_bytes} == vendor_bytes
        assert {name: (fixture.root / MASKS / name).readlink() for name in PAIR} == masks


def test_fixture_has_no_destination_argument() -> None:
    assert list(inspect.signature(overlay.MaskOverlayFixture).parameters) == []
    with overlay.MaskOverlayFixture() as fixture:
        assert fixture.root.is_dir()


def test_foreign_file_refuses_grant_without_changing_it() -> None:
    with overlay.MaskOverlayFixture() as fixture:
        foreign = fixture.root / OVERLAY / "foreign.conf"
        payload = b"keep this foreign entry untouched\n"
        foreign.write_bytes(payload)

        with pytest.raises(overlay.FixtureRefused):
            fixture.grant()

        assert foreign.read_bytes() == payload
        assert not any((fixture.root / OVERLAY / name).exists() for name in PAIR)


def test_duplicate_grant_and_withdraw_without_grant_are_refused() -> None:
    with overlay.MaskOverlayFixture() as fixture:
        with pytest.raises(overlay.FixtureRefused):
            fixture.withdraw()

        fixture.grant()
        with pytest.raises(overlay.FixtureRefused):
            fixture.grant()


@pytest.mark.parametrize(
    "relative",
    (
        OVERLAY / f"{PAIR[0]}.d" / "override.conf",
        HIGHER / PAIR[0],
    ),
    ids=("dropin", "higher-priority-unit"),
)
def test_unexpected_dropin_or_higher_priority_unit_refuses_snapshot(
    relative: Path,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        foreign = fixture.root / relative
        foreign.parent.mkdir(parents=True, exist_ok=True)
        payload = b"foreign systemd input\n"
        foreign.write_bytes(payload)

        with pytest.raises(overlay.FixtureRefused):
            fixture.snapshot()

        assert foreign.read_bytes() == payload


def test_symlink_ancestor_refuses_without_writing_to_external_directory(
    tmp_path: Path,
) -> None:
    with overlay.MaskOverlayFixture() as fixture:
        external = tmp_path / "external-system.control"
        external.mkdir()
        system = fixture.root / "run/systemd"
        (system / "system.control").rmdir()
        system.rmdir()
        system.symlink_to(external, target_is_directory=True)

        with pytest.raises(overlay.FixtureRefused):
            fixture.grant()

        assert list(external.iterdir()) == []
        assert all((fixture.root / MASKS / name).readlink() == Path("/dev/null") for name in PAIR)


def test_hardlinked_vendor_file_is_refused() -> None:
    with (overlay.MaskOverlayFixture() as fixture,
          tempfile.TemporaryDirectory(dir=fixture.root.parent) as external_dir):
        vendor = fixture.root / VENDOR / PAIR[0]
        # Hardlinks require the same filesystem; VM /tmp and pytest's home
        # scratch directory are deliberately on different mounts.
        external = Path(external_dir) / PAIR[0]
        external.write_bytes(vendor.read_bytes())
        vendor.unlink()
        os.link(external, vendor)

        with pytest.raises(overlay.FixtureRefused):
            fixture.snapshot()

        assert vendor.read_bytes() == external.read_bytes()
        assert external.stat().st_nlink == 2


def test_mutated_candidate_refuses_withdrawal_without_changing_candidate() -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        candidate = fixture.root / OVERLAY / PAIR[0]
        mutated = b"mutated candidate bytes\n"
        candidate.write_bytes(mutated)

        with pytest.raises(overlay.FixtureRefused):
            fixture.withdraw()

        assert candidate.read_bytes() == mutated
        assert (fixture.root / OVERLAY / PAIR[1]).is_file()
        assert all((fixture.root / MASKS / name).readlink() == Path("/dev/null") for name in PAIR)


def test_second_candidate_open_failure_exposes_incomplete_partial_and_keeps_masks(
    monkeypatch: pytest.MonkeyPatch, private_os,
) -> None:
    private_os(overlay)
    with overlay.MaskOverlayFixture() as fixture:
        real_open = overlay.os.open

        def fail_second_candidate(name, flags, mode=0o777, *, dir_fd=None):
            if name == PAIR[1] and dir_fd is not None and flags & os.O_CREAT:
                raise OSError("injected second candidate open failure")
            if dir_fd is None:
                return real_open(name, flags, mode)
            return real_open(name, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(overlay.os, "open", fail_second_candidate)
        with pytest.raises(overlay.FixtureRefused, match="publication incomplete"):
            fixture.grant()

        partial = fixture.snapshot()
        assert partial["phase"] == "incomplete"
        assert set(partial["candidate_sha256"]) == {PAIR[0]}
        profile = next(profile for profile in overlay.PROFILES if profile.unit == PAIR[0])
        assert (fixture.root / OVERLAY / PAIR[0]).read_bytes() == overlay.render_unit(profile).encode()
        assert not (fixture.root / OVERLAY / PAIR[1]).exists()
        assert partial["persistent_mask_targets"] == {name: "/dev/null" for name in PAIR}
        assert all((fixture.root / MASKS / name).readlink() == Path("/dev/null") for name in PAIR)


def test_second_unlink_failure_exposes_incomplete_state_and_keeps_masks(
    monkeypatch: pytest.MonkeyPatch, private_os,
) -> None:
    private_os(overlay)
    with overlay.MaskOverlayFixture() as fixture:
        fixture.grant()
        original_second = (fixture.root / OVERLAY / PAIR[1]).read_bytes()
        real_unlink = overlay.os.unlink

        def fail_second_unlink(name, *, dir_fd=None):
            if name == PAIR[1] and dir_fd is not None:
                raise OSError("injected second candidate unlink failure")
            if dir_fd is None:
                return real_unlink(name)
            return real_unlink(name, dir_fd=dir_fd)

        with monkeypatch.context() as patcher:
            patcher.setattr(overlay.os, "unlink", fail_second_unlink)
            with pytest.raises(overlay.FixtureRefused, match="withdrawal incomplete"):
                fixture.withdraw()

            partial = fixture.snapshot()
            assert partial["phase"] == "incomplete"
            assert partial["candidate_sha256"] == {
                PAIR[1]: hashlib.sha256(original_second).hexdigest()
            }
            assert not (fixture.root / OVERLAY / PAIR[0]).exists()
            assert (fixture.root / OVERLAY / PAIR[1]).read_bytes() == original_second
            assert all((fixture.root / MASKS / name).readlink() == Path("/dev/null") for name in PAIR)


def test_constructor_vendor_files_are_private_even_under_group_writable_umask() -> None:
    previous = os.umask(0o002)
    try:
        with overlay.MaskOverlayFixture() as fixture:
            for name in (*PAIR, "azazel-activated.service"):
                assert (fixture.root / VENDOR / name).stat().st_mode & 0o777 == 0o600
    finally:
        os.umask(previous)


def test_group_or_world_accessible_fixture_root_is_refused() -> None:
    with overlay.MaskOverlayFixture() as fixture:
        fixture.root.chmod(0o750)
        with pytest.raises(overlay.FixtureRefused, match="not private"):
            fixture.snapshot()


def test_root_open_failure_removes_only_the_new_empty_scratch(monkeypatch, private_os):
    private_os(overlay)
    created = []
    original_mkdtemp = overlay.tempfile.mkdtemp
    original_open = overlay.os.open

    def make(**kwargs):
        path = original_mkdtemp(**kwargs)
        created.append(Path(path))
        return path

    def fail_root(path, *args, **kwargs):
        if created and Path(path) == created[-1]:
            raise OSError("injected root open failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(overlay.tempfile, "mkdtemp", make)
    monkeypatch.setattr(overlay.os, "open", fail_root)
    with pytest.raises(OSError, match="injected root"):
        overlay.MaskOverlayFixture()
    assert len(created) == 1 and not created[0].exists()
