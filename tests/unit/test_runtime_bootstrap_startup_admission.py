"""Bound audit starts consume fresh pinned startup measurements, synthetic only."""

from dataclasses import replace
from hashlib import sha256
import os

import pytest

from azazel_nexus.bootstrap_grant_transaction import advance_transaction
from azazel_nexus.installed_files import _measure_at, _read_pinned_at
from azazel_nexus.installed_manifest import (
    InstalledDirectory, InstalledFile, InstalledManifest, encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs
from azazel_nexus_runtime import python_startup
from azazel_nexus_runtime.startup_wrapper import render_wrapper
import test_runtime_bootstrap_manager_publication as publication
import test_runtime_running_python as running_python
import test_runtime_import_routing as import_routing
import test_runtime_loaded_modules as loaded_modules

PYVENV_CFG = (
    b"home=/usr/bin\n"
    b"include-system-site-packages=false\n"
    b"version=3.13.5\n"
    b"executable=/usr/bin/python3.13\n"
)
INTERPRETER_BYTES = b"synthetic interpreter; never executed\n"


def _installed_tree(root):
    values = {
        "opt/env/bin/python": (0o755, INTERPRETER_BYTES),
        "usr/bin/python3.13": (0o755, INTERPRETER_BYTES),
        "opt/env/pyvenv.cfg": (0o644, PYVENV_CFG),
    }
    site = root / "opt/env/site"
    site.mkdir(parents=True)
    for name in ("activated", "auditd", "commissiond"):
        path = f"usr/libexec/azazel/az-{name}"
        values[path] = (0o755, render_wrapper(
            "/opt/env/bin/python", f"azazel_nexus_runtime.{name}:main",
            import_paths=("/opt/env/site",),
        ))
    entries = []
    for path, (mode, content) in sorted(values.items()):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(mode)
        entries.append(InstalledFile(path, mode, len(content), sha256(content).hexdigest()))
    for current, _directories, _files in os.walk(root):
        os.chmod(current, 0o755)
    directories = tuple(InstalledDirectory(path) for path in (
        "opt/env", "opt/env/bin", "opt/env/site",
        "usr/bin", "usr/libexec", "usr/libexec/azazel",
    ))
    raw = encode_installed_manifest(InstalledManifest(
        tuple(entries), directories, version=2,
    ))
    return raw, "sha256:" + sha256(raw).hexdigest()


@pytest.mark.parametrize("drift", ["wrapper", "directory", "pyvenv-config", "running-python"])
def test_retained_bound_audit_refuses_startup_drift_before_submission(
    tmp_path, monkeypatch, drift,
):
    root = tmp_path / "synthetic-installed-root"
    raw, pin = _installed_tree(root)
    approval = publication._approval()
    approval = replace(approval, context=replace(approval.context, unit_closure_digest=pin))
    monkeypatch.setattr(publication, "_approval", lambda: approval)
    healthy_observation = running_python._observation(
        content=INTERPRETER_BYTES, interpreter="/opt/env/bin/python",
        import_paths=("/opt/env/site",), version=(3, 13, 5),
    )
    monkeypatch.setattr(bootstrap_inputs, "observe_running_python", lambda: healthy_observation)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    calls = []
    try:
        monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw)
        monkeypatch.setattr(
            bootstrap_inputs, "read_pinned_installed_files",
            lambda raw, *, expected_digest, paths: _read_pinned_at(
                fd, raw, expected_digest=expected_digest, paths=paths, owner=os.getuid(),
            ),
        )
        monkeypatch.setattr(
            bootstrap_inputs, "measure_installed_files",
            lambda raw, *, expected_digest: _measure_at(
                fd, raw, expected_digest=expected_digest, owner=os.getuid(),
            ),
        )
        monkeypatch.setattr(bootstrap_inputs, "observe_python_startup_absence", lambda interpreter:
            python_startup._observe_at(fd, interpreter, owner=os.getuid()))
        monkeypatch.setattr(bootstrap_inputs, "observe_import_routing", lambda paths, _manifest:
            import_routing._routing(import_paths=paths))
        monkeypatch.setattr(bootstrap_inputs, "observe_loaded_modules", lambda _manifest, paths, _main:
            loaded_modules._loaded(import_paths=paths))

        def fresh_admission():
            calls.append(True)
            bootstrap_inputs.measure_bootstrap_installed_files(approval.context)

        # Prove this exact fixture passes real pinned startup and file checks.
        fresh_admission()
        with publication._environment(tmp_path) as env:
            manager, sessions, bus, selected, *_ = publication._manager_fixture(env, monkeypatch)
            assert selected.context == approval.context
            grant = publication._transaction(approval)
            published, _ = manager._publish_and_inspect_pair(
                grant, approval=approval, check_publish=fresh_admission,
            )
            manager._controller_ready_confirmed = True
            bus.controller.phase = "ready"
            transaction = advance_transaction(
                advance_transaction(grant, "pair_grant_opened"), "auditd_start_intent",
            )
            if drift == "wrapper":
                wrapper = root / "usr/libexec/azazel/az-auditd"
                wrapper.write_bytes(wrapper.read_bytes().replace(b"import sys", b"import os "))
            elif drift == "directory":
                (root / "opt/env/site/injected.py").write_bytes(b"unlisted")
            elif drift == "pyvenv-config":
                config = root / "opt/env/pyvenv.cfg"
                config.write_bytes(config.read_bytes().replace(b"false", b"true "))
            else:
                changed = replace(
                    healthy_observation,
                    executable=replace(healthy_observation.executable, sha256="0" * 64),
                )
                monkeypatch.setattr(bootstrap_inputs, "observe_running_python", lambda: changed)
            before = len(calls)
            with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
                manager._start_bound_audit(transaction, check_start=fresh_admission)
            assert len(calls) == before + 1
            assert not any(call.member == "StartUnit" for call in bus.calls)
            assert bus.reload_count == 1
            assert env["store"].load() == published
            assert bus.disconnected and all(session.closed for session in sessions)
    finally:
        os.close(fd)
