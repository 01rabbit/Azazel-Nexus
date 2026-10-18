"""Pinned leaf links on ordinary synthetic trees; never execute a target."""

from dataclasses import replace
from hashlib import sha256
import os

import pytest

from azazel_nexus import installed_files as measured
from azazel_nexus.bootstrap_grant_transaction import advance_transaction
from azazel_nexus.installed_manifest import (
    InstalledDirectory, InstalledFile, InstalledLink, InstalledManifest,
    encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs
from azazel_nexus_runtime import python_startup
from azazel_nexus_runtime.startup_wrapper import render_wrapper
from test_bootstrap_generation import _context
import test_runtime_running_python as running_python
import test_runtime_import_routing as import_routing
import test_runtime_loaded_modules as loaded_modules

PYVENV_CFG_PATH = "opt/env/pyvenv.cfg"
PYVENV_CFG = (
    b"home=/usr/bin\n"
    b"include-system-site-packages=false\n"
    b"version=3.13.5\n"
    b"executable=/usr/bin/python3.13\n"
)
BASE_INTERPRETER = b"synthetic interpreter; never executed\n"


@pytest.fixture
def linked_tree(tmp_path):
    root = tmp_path / "root"
    values = {
        "usr/bin/python3.13": (0o755, BASE_INTERPRETER),
        PYVENV_CFG_PATH: (0o644, PYVENV_CFG),
    }
    for name in ("activated", "auditd", "commissiond"):
        values[f"usr/libexec/azazel/az-{name}"] = (0o755, render_wrapper(
            "/opt/env/bin/python", f"azazel_nexus_runtime.{name}:main",
            import_paths=("/opt/env/site",),
        ))
    entries = []
    for path, (mode, content) in sorted(values.items()):
        leaf = root / path
        leaf.parent.mkdir(parents=True, exist_ok=True)
        leaf.write_bytes(content)
        leaf.chmod(mode)
        entries.append(InstalledFile(path, mode, len(content), sha256(content).hexdigest()))
    (root / "opt/env/bin").mkdir(parents=True)
    (root / "opt/env/site").mkdir()
    links = (
        InstalledLink("opt/env/bin/python", "python3"),
        InstalledLink("opt/env/bin/python3", "/usr/bin/python3"),
        InstalledLink("usr/bin/python3", "python3.13"),
    )
    for current, _dirs, _files in os.walk(root, followlinks=False):
        os.chmod(current, 0o755)
    for link in links:
        (root / link.path).symlink_to(link.target)
    manifest = InstalledManifest(tuple(entries), (
        InstalledDirectory("opt/env"),
        InstalledDirectory("opt/env/bin"),
        InstalledDirectory("opt/env/site"),
        InstalledDirectory("usr/bin"),
        InstalledDirectory("usr/libexec"),
        InstalledDirectory("usr/libexec/azazel"),
    ), version=3, links=links)
    raw = encode_installed_manifest(manifest)
    pin = "sha256:" + sha256(raw).hexdigest()
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield root, fd, manifest, raw, pin
    finally:
        os.close(fd)


def inspect(tree):
    return measured._measure_at(tree[1], tree[3], expected_digest=tree[4], owner=os.getuid())


def test_exact_pinned_chain_and_directory_membership_match_without_following(linked_tree, monkeypatch):
    real_open = measured.os.open
    opened = []

    def no_link_open(path, flags, *args, **kwargs):
        opened.append(path)
        if path in {"python", "python3"}:
            pytest.fail("link was opened")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(measured.os, "open", no_link_open)
    observed = inspect(linked_tree)
    assert observed.link_count == 3
    assert observed.directory_count == 6
    assert observed.file_count == 5
    assert "python3.13" in opened


@pytest.mark.parametrize("kind", ["text", "regular", "missing", "hardlink"])
def test_changed_or_unsafe_link_refuses(linked_tree, kind):
    root = linked_tree[0]
    leaf = root / "opt/env/bin/python"
    if kind == "hardlink":
        os.link(leaf, root / "second-link", follow_symlinks=False)
    else:
        leaf.unlink()
        if kind == "text":
            leaf.symlink_to("/usr/bin/python3.13")
        elif kind == "regular":
            leaf.write_bytes(b"not a link")
            leaf.chmod(0o755)
    with pytest.raises((ApprovalRefused, OSError)):
        inspect(linked_tree)


def test_link_replacement_with_same_text_between_snapshots_refuses(linked_tree, monkeypatch):
    original = measured._snapshot_at
    calls = []
    leaf = linked_tree[0] / "opt/env/bin/python"

    def snapshot(*args, **kwargs):
        result = original(*args, **kwargs)
        calls.append(True)
        if len(calls) == 1:
            replacement = leaf.parent / "replacement"
            replacement.symlink_to("python3")
            replacement.replace(leaf)
        return result

    monkeypatch.setattr(measured, "_snapshot_at", snapshot)
    with pytest.raises(ApprovalRefused):
        inspect(linked_tree)
    assert len(calls) == 2


def test_link_text_changed_during_regular_file_hashing_refuses(linked_tree, monkeypatch):
    original = measured.os.read
    calls = []
    leaf = linked_tree[0] / "opt/env/bin/python"

    def read(fd, size):
        if not calls:
            calls.append(True)
            leaf.unlink()
            leaf.symlink_to("/usr/bin/python3.13")
        return original(fd, size)

    monkeypatch.setattr(measured.os, "read", read)
    with pytest.raises(ApprovalRefused):
        inspect(linked_tree)
    assert calls


def test_bootstrap_uses_declared_chain_then_measures_links_and_terminal_bytes(linked_tree, monkeypatch):
    _root, fd, _manifest, raw, pin = linked_tree
    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw)
    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        lambda raw, *, expected_digest, paths: measured._read_pinned_at(
            fd, raw, expected_digest=expected_digest, paths=paths, owner=os.getuid(),
        ),
    )
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda raw, *, expected_digest: measured._measure_at(
            fd, raw, expected_digest=expected_digest, owner=os.getuid(),
        ),
    )
    context = replace(_context(), unit_closure_digest=pin)
    monkeypatch.setattr(bootstrap_inputs, "observe_running_python", lambda: running_python._observation(
        content=BASE_INTERPRETER, interpreter="/opt/env/bin/python",
        import_paths=("/opt/env/site",), version=(3, 13, 5),
    ))
    monkeypatch.setattr(bootstrap_inputs, "observe_python_startup_absence", lambda interpreter:
        python_startup._observe_at(fd, interpreter, owner=os.getuid()))
    monkeypatch.setattr(bootstrap_inputs, "observe_import_routing", lambda paths, _manifest, **_k:
        import_routing._routing(import_paths=paths))
    monkeypatch.setattr(bootstrap_inputs, "observe_loaded_modules", lambda _manifest, paths, _main:
        loaded_modules._loaded(import_paths=paths))
    assert bootstrap_inputs.measure_bootstrap_installed_files(context).link_count == 3
    leaf = linked_tree[0] / "opt/env/bin/python"
    leaf.unlink()
    leaf.symlink_to("/usr/bin/python3.13")
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(context)


def test_bootstrap_refuses_nonexecutable_terminal_file_even_when_pinned(linked_tree, monkeypatch):
    _root, _fd, manifest, _raw, _pin = linked_tree
    altered = replace(manifest, files=tuple(
        replace(entry, mode=0o644) if entry.path == "usr/bin/python3.13" else entry
        for entry in manifest.files
    ))
    raw = encode_installed_manifest(altered)
    context = replace(_context(), unit_closure_digest="sha256:" + sha256(raw).hexdigest())
    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw)
    wrappers = {entry.path: (linked_tree[0] / entry.path).read_bytes()
                for entry in manifest.files if entry.path.startswith("usr/libexec/")}

    def read_wrappers(raw, *, expected_digest, paths):
        if paths != tuple(sorted(wrappers)):
            pytest.fail("nonexecutable base reached venv metadata read")
        return tuple(wrappers[path] for path in paths)

    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        read_wrappers,
    )
    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files",
                        lambda *_a, **_kw: pytest.fail("nonexecutable target reached measurement"))
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(context)


@pytest.mark.parametrize("drift", [
    "link-text", "terminal-bytes", "startup-override", "import-routing", "loaded-modules",
])
def test_bound_audit_start_refuses_pinned_interpreter_chain_drift(
    linked_tree, tmp_path, monkeypatch, drift,
):
    import test_runtime_bootstrap_manager_publication as publication

    root, fd, _manifest, raw, pin = linked_tree
    approved = publication._approval()
    approved = replace(approved, context=replace(approved.context, unit_closure_digest=pin))
    monkeypatch.setattr(publication, "_approval", lambda: approved)
    monkeypatch.setattr(bootstrap_inputs, "observe_running_python", lambda: running_python._observation(
        content=BASE_INTERPRETER, interpreter="/opt/env/bin/python",
        import_paths=("/opt/env/site",), version=(3, 13, 5),
    ))
    monkeypatch.setattr(bootstrap_inputs, "observe_python_startup_absence", lambda interpreter:
        python_startup._observe_at(fd, interpreter, owner=os.getuid()))
    healthy_routing = import_routing._routing(import_paths=("/opt/env/site",))
    routing_state = {"drift": False, "calls": 0}

    def observe_routing(paths, manifest, **_k):
        del manifest
        if not routing_state["drift"]:
            return import_routing._routing(import_paths=paths)
        routing_state["calls"] += 1
        if routing_state["calls"] == 1:
            return healthy_routing
        return replace(healthy_routing, cache=healthy_routing.cache + (("synthetic-cache-drift",),))

    monkeypatch.setattr(bootstrap_inputs, "observe_import_routing", observe_routing)
    healthy_modules = loaded_modules._loaded(import_paths=("/opt/env/site",))
    modules_state = {"drift": False, "calls": 0}

    def observe_modules(_manifest, paths, _main):
        if not modules_state["drift"]:
            return loaded_modules._loaded(import_paths=paths)
        modules_state["calls"] += 1
        if modules_state["calls"] == 1:
            return healthy_modules
        return replace(
            healthy_modules,
            modules=healthy_modules.modules + (("synthetic-loaded-module-drift",),),
        )

    monkeypatch.setattr(bootstrap_inputs, "observe_loaded_modules", observe_modules)
    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw)
    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        lambda raw, *, expected_digest, paths: measured._read_pinned_at(
            fd, raw, expected_digest=expected_digest, paths=paths, owner=os.getuid(),
        ),
    )
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda raw, *, expected_digest: measured._measure_at(
            fd, raw, expected_digest=expected_digest, owner=os.getuid(),
        ),
    )
    calls = []

    def fresh_admission():
        calls.append(True)
        bootstrap_inputs.measure_bootstrap_installed_files(approved.context)

    fresh_admission()
    with publication._environment(tmp_path) as env:
        # Refusal of interpreter-chain drift, not deadlines: the shared 0.05 s job
        # bound timed out on a slow CI runner (same remedy as the ordering test).
        manager, sessions, bus, selected, *_ = publication._manager_fixture(
            env, monkeypatch, job_timeout_seconds=5.0)
        assert selected.context == approved.context
        grant = publication._transaction(approved)
        published, _ = manager._publish_and_inspect_pair(
            grant, approval=approved, check_publish=fresh_admission,
        )
        manager._controller_ready_confirmed = True
        bus.controller.phase = "ready"
        transaction = advance_transaction(
            advance_transaction(grant, "pair_grant_opened"), "auditd_start_intent",
        )
        if drift == "link-text":
            leaf = root / "opt/env/bin/python"
            leaf.unlink()
            leaf.symlink_to("/usr/bin/python3.13")
        elif drift == "terminal-bytes":
            terminal = root / "usr/bin/python3.13"
            terminal.write_bytes(terminal.read_bytes().replace(b"synthetic", b"modified!"))
        elif drift == "startup-override":
            override = root / "opt/env/bin/python._pth"
            override.write_bytes(b"isolated\n")
            monkeypatch.setattr(
                bootstrap_inputs, "measure_installed_files",
                lambda *_args, **_kwargs: pytest.fail(
                    "startup override reached full installed-file measurement"
                ),
            )
        elif drift == "import-routing":
            routing_state["drift"] = True
        elif drift == "loaded-modules":
            modules_state["drift"] = True
        before = len(calls)
        with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
            manager._start_bound_audit(transaction, check_start=fresh_admission)
        assert len(calls) == before + 1
        if drift == "import-routing":
            assert routing_state["calls"] == 2
        elif drift == "loaded-modules":
            assert modules_state["calls"] == 2
        assert not any(call.member == "StartUnit" for call in bus.calls)
        assert bus.reload_count == 1
        assert env["store"].load() == published
        assert bus.disconnected and all(session.closed for session in sessions)
