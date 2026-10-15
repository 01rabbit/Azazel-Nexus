"""Fixed layout composition with real ordinary files, no systemd or devices."""

from itertools import product
from contextlib import contextmanager
import os
from types import SimpleNamespace

import pytest

from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.bootstrap_directory_paths import _overlay_directories_under
from azazel_nexus_runtime.bootstrap_overlay_files import _publish_candidates_at
from azazel_nexus_runtime.bootstrap_withdraw_files import _withdraw_candidates_at
from azazel_nexus_runtime.bootstrap_restore_files import BootstrapRestoredOverlayFiles
from test_runtime_bootstrap_overlay_files import PAIR, _environment, _intent

OPTIONAL = ("etc/systemd/system.control", "run/systemd/transient", "run/systemd/generator.early")


def layout(root, present):
    root.mkdir(mode=0o700)
    for name in ("etc", "etc/systemd", "etc/systemd/system", "run", "run/systemd", "run/systemd/system.control"):
        (root / name).mkdir(mode=0o700)
    for name, exists in zip(OPTIONAL, present, strict=True):
        if exists:
            (root / name).mkdir(mode=0o700)
    for unit in PAIR:
        (root / "etc/systemd/system" / unit).symlink_to("/dev/null")


@pytest.mark.parametrize("present", list(product((False, True), repeat=3)))
def test_all_optional_layouts_publish_close_withdraw_without_creating_missing_dirs(tmp_path, present):
    root = tmp_path.resolve() / "root"
    layout(root, present)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    with _environment(state) as env, _overlay_directories_under(root, owner_uid=os.getuid()) as dirs:
        args = dirs.arguments
        _publish_candidates_at(
            **{key: args[key] for key in ("overlay_fd", "masks_fd", "higher_priority_fd")},
            journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(), intent=_intent(),
        )
        closed = dirs.closed_files(journal_store=env["store"], guard=env["guard"])
        closed.close()
        assert len(closed.check()) == 2
        result = _withdraw_candidates_at(
            **{key: value for key, value in args.items() if key.endswith("_fd")},
            journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(),
            check_contained=lambda: None,
        )
        assert result.phase == "withdrawing"
        restored = BootstrapRestoredOverlayFiles(
            **args, journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(),
        )
        assert all(fragment.startswith(str(root / "etc/systemd/system") + "/")
                   for _unit, fragment in restored.check())
        assert all(not (root / "run/systemd/system.control" / unit).exists() for unit in PAIR)
        for name, exists in zip(OPTIONAL, present, strict=True):
            assert (root / name).exists() == exists


@pytest.mark.parametrize("phase", ["publication", "closing", "withdrawal"])
def test_optional_appearance_after_intent_refuses_before_next_file_mutation(tmp_path, phase):
    root = tmp_path.resolve() / "root"
    layout(root, (False, False, False))
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    with _environment(state) as env, _overlay_directories_under(root, owner_uid=os.getuid()) as dirs:
        args = dirs.arguments
        original_create, original_replace = env["store"].create, env["store"].replace

        def create(journal):
            result = original_create(journal)
            if phase == "publication":
                (root / OPTIONAL[0]).mkdir()
            return result

        def replace(expected, updated):
            result = original_replace(expected, updated)
            if ((phase == "closing" and updated.phase == "closing")
                    or (phase == "withdrawal" and updated.phase == "withdrawing")):
                (root / OPTIONAL[1]).mkdir()
            return result

        env["store"].create, env["store"].replace = create, replace

        def run():
            _publish_candidates_at(
                **{key: args[key] for key in ("overlay_fd", "masks_fd", "higher_priority_fd")},
                journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(), intent=_intent(),
            )
            dirs.closed_files(journal_store=env["store"], guard=env["guard"]).close()
            _withdraw_candidates_at(
                **{key: value for key, value in args.items() if key.endswith("_fd")},
                journal_store=env["store"], guard=env["guard"], owner_uid=os.getuid(),
                check_contained=lambda: None,
            )

        with pytest.raises(ApprovalRefused):
            run()
        files = [root / "run/systemd/system.control" / unit for unit in PAIR]
        if phase == "publication":
            assert all(not file.exists() for file in files)
        elif phase == "closing":
            assert all(file.stat().st_size > 0 for file in files)
        else:
            assert all(file.exists() and file.stat().st_size == 0 for file in files)


@pytest.mark.parametrize("name", OPTIONAL)
def test_appearing_optional_path_refuses_even_mandatory_fd_use(tmp_path, name):
    root = tmp_path.resolve() / "root"
    layout(root, (False, False, False))
    with _overlay_directories_under(root, owner_uid=os.getuid()) as dirs:
        (root / name).mkdir()
        with pytest.raises(ApprovalRefused):
            os.fstat(dirs.arguments["overlay_fd"])


@pytest.mark.parametrize("name", OPTIONAL)
def test_present_competitor_refuses_before_partial_close(tmp_path, name):
    root = tmp_path.resolve() / "root"
    layout(root, (True, True, True))
    with _overlay_directories_under(root, owner_uid=os.getuid()) as dirs:
        (root / name / PAIR[1]).write_text("unowned competitor")
        with pytest.raises(ApprovalRefused):
            os.fstat(dirs.arguments["masks_fd"])


def test_present_directory_replaced_refuses_inside_fd_consuming_operation(tmp_path):
    root = tmp_path.resolve() / "root"
    layout(root, (True, True, True))
    with _overlay_directories_under(root, owner_uid=os.getuid()) as dirs:
        source = root / "run/systemd/system.control"
        source.rename(source.with_name("retained-but-detached"))
        source.mkdir()
        with pytest.raises(ApprovalRefused):
            os.fsync(dirs.arguments["overlay_fd"])


@pytest.mark.parametrize("failure", [None, "store", "mount", "manager", "body"])
def test_fixed_manager_composition_owns_lifetimes_without_service_calls(tmp_path, monkeypatch, failure):
    from azazel_nexus_runtime import bootstrap_manager as module

    events = []
    closed, withdrawal, mount, store = object(), object(), object(), object()
    constructed_manager = SimpleNamespace()
    dirs = SimpleNamespace(
        check=lambda: events.append("check"),
        closed_files=lambda **kwargs: closed,
        withdrawal_files=lambda **kwargs: withdrawal,
    )

    @contextmanager
    def resource(name, value):
        events.append("enter-" + name)
        if failure == name:
            raise RuntimeError("synthetic failure")
        try:
            yield value
        finally:
            events.append("exit-" + name)

    monkeypatch.setattr(module, "open_bootstrap_overlay_directories", lambda: resource("dirs", dirs))
    monkeypatch.setattr(module, "open_bootstrap_cgroup_mount", lambda: resource("mount", mount))

    def construct(**kwargs):
        assert kwargs == dict(job_timeout_seconds=2, closed_overlay_files=closed,
                              withdrawal_files=withdrawal, cgroup_mount=mount)
        if failure == "manager":
            raise RuntimeError("synthetic failure")
        return constructed_manager

    monkeypatch.setattr(module, "BootstrapNarrowingManager", construct)
    with _environment(tmp_path) as env:
        def journal(guard):
            assert guard is env["guard"]
            guard()
            return resource("store", store)
        monkeypatch.setattr(module, "overlay_journal_store_in_transaction", journal)

        def run():
            with module.bootstrap_narrowing_manager_in_transaction(env["guard"], job_timeout_seconds=2) as manager:
                assert manager is constructed_manager
                assert manager._publication_inputs == (dirs, store, env["guard"])
                assert not any(event.startswith("exit-") for event in events)
                if failure == "body":
                    raise RuntimeError("synthetic failure")

        if failure:
            with pytest.raises(RuntimeError, match="synthetic failure"):
                run()
        else:
            run()
    entered = [event[6:] for event in events if event.startswith("enter-") and event != "enter-" + str(failure)]
    assert [event[5:] for event in events if event.startswith("exit-")] == entered[::-1]
