"""Fixed bootstrap semantic admission wiring with synthetic protected readers."""

from dataclasses import replace
from contextlib import contextmanager
from hashlib import sha256
import os
from types import SimpleNamespace

import pytest

from azazel_nexus.bootstrap_generation import VerifiedBootstrapGeneration
from azazel_nexus.bootstrap_prestart_policy import encode_prestart_policy
from azazel_nexus.installed_files import SelectedInstalledFiles, _measure_at
from azazel_nexus.installed_manifest import (
    InstalledDirectory, InstalledFile, InstalledManifest, encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime.debian_packages import parse_package_output
from azazel_nexus_runtime import bootstrap_inputs as inputs
from azazel_nexus_runtime import python_startup
from azazel_nexus_runtime.startup_wrapper import render_wrapper
from azazel_nexus_runtime.bootstrap_systemd_profile import (
    _DEBIAN13_V257_UNIT_PATH,
    SystemdBootstrapProfile,
    bootstrap_systemd_profile_digest,
)
from test_bootstrap_generation import _context
from test_bootstrap_prestart_policy import policy as _policy
from test_bootstrap_generation import _bootstrap_metadata, _config
import test_runtime_running_python as running_python
import test_runtime_import_routing as import_routing
import test_runtime_loaded_modules as loaded_modules


DIGEST = "sha256:" + "a" * 64
PYVENV_CFG = (
    b"home=/usr/bin\n"
    b"include-system-site-packages=false\n"
    b"version=3.13.5\n"
    b"executable=/usr/bin/python3.13\n"
)
INTERPRETER_BYTES = b"synthetic interpreter bytes\n"


@pytest.fixture
def umask_0002():
    previous = os.umask(0o002)
    try:
        yield
    finally:
        os.umask(previous)


def _profile(version="257.13-1~deb13u1"):
    return SystemdBootstrapProfile(
        "systemd-257.13-deb13-path-v1", version, _DEBIAN13_V257_UNIT_PATH
    )


def _wire(monkeypatch, *, profile=None, profiles=None, generations=None, policies=None):
    context = _context()
    generation = VerifiedBootstrapGeneration(
        context.generation, context.generation_digest, "2026-10-14T00:00:00Z"
    )
    current_profile = _profile() if profile is None else profile
    selected_policy = replace(
        _policy(),
        package_digest=context.package_digest,
        unit_closure_digest=context.unit_closure_digest,
        systemd_profile_digest=bootstrap_systemd_profile_digest(_profile()),
    )
    package = SimpleNamespace(digest=context.package_digest)
    files = SelectedInstalledFiles(context.unit_closure_digest, 2, 128)
    generation_values = iter([generation] * 8 if generations is None else generations)
    policy_values = iter([selected_policy] * 16 if policies is None else policies)
    monkeypatch.setattr(
        inputs,
        "load_bootstrap_prestart_policy",
        lambda *, expected: next(policy_values),
    )
    profile_values = iter([current_profile] * 8 if profiles is None else profiles)
    monkeypatch.setattr(
        inputs, "_observe_systemd_profile", lambda: next(profile_values)
    )
    monkeypatch.setattr(
        inputs, "load_bootstrap_generation", lambda *, expected: next(generation_values)
    )
    monkeypatch.setattr(inputs, "observe_installed_packages", lambda: package)
    monkeypatch.setattr(inputs, "validate_package_snapshot", lambda value: None)
    monkeypatch.setattr(inputs, "measure_bootstrap_installed_files", lambda context: files)
    capacity_calls = []
    monkeypatch.setattr(
        inputs, "check_bootstrap_capacity",
        lambda *, expected: capacity_calls.append(expected),
    )
    return context, generation, capacity_calls


def test_production_factory_rechecks_policy_profile_generation_and_measured_inputs(
    monkeypatch,
):
    context, generation, capacity_calls = _wire(monkeypatch)

    admitted = inputs.protected_bootstrap_generation_admission()(context)

    assert admitted == generation
    assert capacity_calls == [context]


def test_repeated_admission_rechecks_capacity_without_replaying_stopped_writer_audit(
    monkeypatch,
):
    context, generation, capacity_calls = _wire(monkeypatch)
    from azazel_nexus_runtime import bootstrap_prestart

    audit_calls = []
    monkeypatch.setattr(
        bootstrap_prestart, "check_bootstrap_existing_audit",
        lambda **kwargs: audit_calls.append(kwargs),
    )
    admission = inputs.protected_bootstrap_generation_admission()

    assert admission(context) == generation
    assert admission(context) == generation
    assert capacity_calls == [context, context]
    assert audit_calls == []


def test_live_profile_outside_approved_policy_refuses_without_fallback(monkeypatch):
    context, _generation, _capacity_calls = _wire(monkeypatch, profile=_profile("257.13-1~deb13u2"))

    with pytest.raises(
        ApprovalRefused, match="protected bootstrap generation admission refused"
    ):
        inputs.protected_bootstrap_generation_admission()(context)


def test_profile_change_during_admission_is_rechecked_and_refused(monkeypatch):
    context, _generation, _capacity_calls = _wire(
        monkeypatch,
        profiles=[_profile(), _profile("257.13-1~deb13u2")],
    )

    with pytest.raises(
        ApprovalRefused, match="protected bootstrap generation admission refused"
    ):
        inputs.protected_bootstrap_generation_admission()(context)


def test_policy_replacement_during_admission_is_rechecked_and_refused(monkeypatch):
    context = _context()
    selected_policy = replace(
        _policy(),
        package_digest=context.package_digest,
        unit_closure_digest=context.unit_closure_digest,
        systemd_profile_digest=bootstrap_systemd_profile_digest(_profile()),
    )
    changed_policy = replace(
        selected_policy, systemd_profile_digest="sha256:" + "b" * 64
    )
    context, _generation, _capacity_calls = _wire(
        monkeypatch,
        policies=[selected_policy] * 4 + [changed_policy],
    )

    with pytest.raises(
        ApprovalRefused, match="protected bootstrap generation admission refused"
    ):
        inputs.protected_bootstrap_generation_admission()(context)


def test_changed_generation_during_semantic_admission_refuses(monkeypatch):
    context, generation, _capacity_calls = _wire(
        monkeypatch,
        generations=[
            VerifiedBootstrapGeneration(
                _context().generation,
                _context().generation_digest,
                "2026-10-14T00:00:00Z",
            ),
            VerifiedBootstrapGeneration(
                _context().generation,
                "sha256:" + "b" * 64,
                "2026-10-14T00:00:00Z",
            ),
        ],
    )

    with pytest.raises(
        ApprovalRefused, match="protected bootstrap generation admission refused"
    ):
        inputs.protected_bootstrap_generation_admission()(context)


def test_capacity_failure_is_causal_and_does_not_enter_generation_or_audit_preflight(
    monkeypatch,
):
    context, generation, _capacity_calls = _wire(monkeypatch)
    calls = []

    def refuse_capacity(*, expected):
        calls.append(("capacity", expected))
        raise ApprovalRefused("synthetic capacity refusal")

    monkeypatch.setattr(inputs, "check_bootstrap_capacity", refuse_capacity)
    monkeypatch.setattr(
        inputs, "load_bootstrap_generation",
        lambda **kwargs: calls.append(("generation", kwargs)),
    )
    from azazel_nexus_runtime import bootstrap_prestart

    monkeypatch.setattr(
        bootstrap_prestart, "inspect_bootstrap_prestart",
        lambda **kwargs: calls.append(("audit-prestart", kwargs)),
    )

    with pytest.raises(
        ApprovalRefused, match="protected bootstrap semantic admission refused"
    ):
        inputs._admit_protected_bootstrap_generation(context, generation)

    assert calls == [("capacity", context)]


def test_policy_change_during_capacity_refuses_before_generation_read(monkeypatch):
    context, generation, _capacity_calls = _wire(monkeypatch)
    selected_policy = replace(
        _policy(),
        package_digest=context.package_digest,
        unit_closure_digest=context.unit_closure_digest,
        systemd_profile_digest=bootstrap_systemd_profile_digest(_profile()),
    )
    changed_policy = replace(
        selected_policy, loaded_policy_digest="sha256:" + "b" * 64,
    )
    policies = iter([selected_policy, changed_policy])
    monkeypatch.setattr(
        inputs, "load_bootstrap_prestart_policy",
        lambda *, expected: next(policies),
    )
    calls = []
    monkeypatch.setattr(
        inputs, "check_bootstrap_capacity",
        lambda *, expected: calls.append(("capacity", expected)),
    )
    monkeypatch.setattr(
        inputs, "load_bootstrap_generation",
        lambda **kwargs: calls.append(("generation", kwargs)),
    )

    with pytest.raises(
        ApprovalRefused, match="protected bootstrap semantic admission refused"
    ):
        inputs._admit_protected_bootstrap_generation(context, generation)

    assert calls == [("capacity", context)]


def test_fixed_factory_uses_real_policy_codec_manifest_and_generation_reader(
    tmp_path, monkeypatch, umask_0002,
):
    from azazel_nexus import (
        bootstrap_generation_store,
        bootstrap_prestart_store,
        bootstrap_store,
    )
    from azazel_nexus.activation_store import _read_file_at
    from azazel_nexus.bootstrap_generation_store import _load_at

    profile = _profile()
    package = parse_package_output(b"dpkg\t1.22.22\tarm64\tii \n")

    installed_root = tmp_path / "installed-root"
    share = installed_root / "usr" / "share" / "azazel"
    share.mkdir(parents=True, mode=0o755)
    for ancestor in (
        installed_root,
        installed_root / "usr",
        installed_root / "usr" / "share",
        share,
    ):
        ancestor.chmod(0o755)
    selected = share / "bootstrap-runtime.txt"
    selected.write_bytes(b"synthetic runtime file\n")
    selected.chmod(0o644)
    executable_paths = (
        "usr/libexec/azazel/az-activated",
        "usr/libexec/azazel/az-auditd",
        "usr/libexec/azazel/az-commissiond",
    )
    installed_modes = {selected: 0o644}
    interpreter_relative = "opt/env/bin/python"
    interpreter = installed_root / interpreter_relative
    interpreter.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    (installed_root / "opt").chmod(0o755)
    interpreter.write_bytes(INTERPRETER_BYTES)
    interpreter.chmod(0o755)
    installed_modes[interpreter] = 0o755
    base_interpreter = installed_root / "usr/bin/python3.13"
    base_interpreter.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    base_interpreter.write_bytes(INTERPRETER_BYTES)
    base_interpreter.chmod(0o755)
    installed_modes[base_interpreter] = 0o755
    pyvenv_config = installed_root / "opt/env/pyvenv.cfg"
    pyvenv_config.write_bytes(PYVENV_CFG)
    pyvenv_config.chmod(0o644)
    installed_modes[pyvenv_config] = 0o644
    import_paths = ("/opt/env/site",)
    targets = {
        "usr/libexec/azazel/az-activated": "azazel_nexus_runtime.activated:main",
        "usr/libexec/azazel/az-auditd": "azazel_nexus_runtime.auditd:main",
        "usr/libexec/azazel/az-commissiond": "azazel_nexus_runtime.commissiond:main",
    }
    for relative in executable_paths:
        executable = installed_root / relative
        executable.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        executable.write_bytes(render_wrapper(
            "/" + interpreter_relative, targets[relative], import_paths=import_paths,
        ))
        executable.chmod(0o755)
        installed_modes[executable] = 0o755
    entries = tuple(sorted((InstalledFile(
        path.relative_to(installed_root).as_posix(),
        mode,
        path.stat().st_size,
        sha256(path.read_bytes()).hexdigest(),
    ) for path, mode in installed_modes.items()), key=lambda entry: entry.path))
    directory_paths = (
        "opt/env", "opt/env/bin", "opt/env/site",
        "usr/bin",
        "usr/libexec", "usr/libexec/azazel",
        "usr/share", "usr/share/azazel",
    )
    for relative in directory_paths:
        directory = installed_root / relative
        directory.mkdir(parents=True, exist_ok=True, mode=0o755)
        directory.chmod(0o755)
    directories = tuple(InstalledDirectory(path) for path in directory_paths)
    manifest_raw = encode_installed_manifest(InstalledManifest(
        entries, directories, version=2,
    ))
    manifest_digest = "sha256:" + sha256(manifest_raw).hexdigest()

    protected_root = tmp_path / "protected-bootstrap"
    protected_root.mkdir(mode=0o700)
    (protected_root / "admission.json").write_bytes(b"")
    (protected_root / "installed-files.json").write_bytes(manifest_raw)
    (protected_root / "installed-files.json").chmod(0o600)

    selected_policy = replace(
        _policy(),
        package_digest=package.digest,
        unit_closure_digest=manifest_digest,
        systemd_profile_digest=bootstrap_systemd_profile_digest(profile),
    )
    policy_raw = encode_prestart_policy(selected_policy)
    policy_digest = "sha256:" + sha256(policy_raw).hexdigest()
    admission = protected_root / "admission.json"
    admission.write_bytes(policy_raw)
    admission.chmod(0o600)
    config = _config(
        policy=policy_digest,
        package=package.digest,
        closure=manifest_digest,
    )
    context = _context(
        {"bootstrap.json": config},
        package_digest=package.digest,
        unit_closure_digest=manifest_digest,
        policy_digest=policy_digest,
    )

    generation_root = tmp_path / "bootstrap-generations"
    generation_root.mkdir(mode=0o700)
    generation = generation_root / str(context.generation)
    tree = generation / "tree"
    tree.mkdir(parents=True, mode=0o700)
    generation_root.chmod(0o700)
    generation.chmod(0o700)
    tree.chmod(0o700)
    (tree / "bootstrap.json").write_bytes(config)
    (tree / "bootstrap.json").chmod(0o600)
    (generation / "generation.json").write_bytes(_bootstrap_metadata(context))
    (generation / "generation.json").chmod(0o600)

    @contextmanager
    def directory(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(
        bootstrap_store, "_bootstrap_directory", lambda: directory(protected_root)
    )
    monkeypatch.setattr(
        bootstrap_prestart_store, "_bootstrap_directory",
        lambda: directory(protected_root),
    )
    monkeypatch.setattr(
        bootstrap_prestart_store,
        "_read_at",
        lambda fd, *, owner: _read_file_at(
            fd, "admission.json", owner=os.getuid(), limit=8192
        ),
    )
    monkeypatch.setattr(
        bootstrap_store,
        "_read_file_at",
        lambda fd, name, *, owner, limit: _read_file_at(
            fd, name, owner=os.getuid(), limit=limit
        ),
    )
    monkeypatch.setattr(
        inputs,
        "measure_installed_files",
        lambda raw, *, expected_digest: _measure_selected(raw, expected_digest,
                                                          installed_root),
    )

    def read_pinned(raw, *, expected_digest, paths):
        fd = os.open(installed_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            from azazel_nexus.installed_files import _read_pinned_at

            return _read_pinned_at(
                fd, raw, expected_digest=expected_digest, paths=paths,
                owner=os.getuid(),
            )
        finally:
            os.close(fd)

    monkeypatch.setattr(inputs, "read_pinned_installed_files", read_pinned)
    def observe_startup_absence(interpreter):
        startup_fd = os.open(installed_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            return python_startup._observe_at(startup_fd, interpreter, owner=os.getuid())
        finally:
            os.close(startup_fd)

    monkeypatch.setattr(inputs, "observe_python_startup_absence", observe_startup_absence)
    monkeypatch.setattr(inputs, "observe_import_routing", lambda paths, _manifest, **_k:
        import_routing._routing(import_paths=paths))
    monkeypatch.setattr(inputs, "observe_loaded_modules", lambda _manifest, paths, _main:
        loaded_modules._loaded(import_paths=paths))
    monkeypatch.setattr(inputs, "observe_running_python", lambda: running_python._observation(
        content=INTERPRETER_BYTES, interpreter="/opt/env/bin/python",
        import_paths=("/opt/env/site",), version=(3, 13, 5),
    ))
    monkeypatch.setattr(inputs, "observe_installed_packages", lambda: package)
    monkeypatch.setattr(
        inputs, "_observe_systemd_profile", lambda: profile
    )
    capacity_calls = []
    monkeypatch.setattr(
        inputs, "check_bootstrap_capacity",
        lambda *, expected: capacity_calls.append(expected),
    )

    def load_at_current_user(fd, *, owner, expected):
        return _load_at(fd, owner=os.getuid(), expected=expected)

    monkeypatch.setattr(
        bootstrap_generation_store,
        "_generation_directory",
        lambda: directory(generation_root),
    )
    monkeypatch.setattr(
        bootstrap_generation_store, "_load_at", load_at_current_user
    )
    generation_fd = os.open(generation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        snapshot = bootstrap_generation_store._snapshot(
            generation_fd, owner=os.getuid()
        )
        assert snapshot[:2] == (_bootstrap_metadata(context), config)
    finally:
        os.close(generation_fd)

    # Verify each protected adapter first, so failures in the composition are
    # attributable rather than hidden behind the factory's redacted refusal.
    assert inputs.load_bootstrap_prestart_policy(expected=context) == selected_policy
    assert inputs.observe_installed_packages() == package
    assert _measure_selected(manifest_raw, manifest_digest, installed_root).manifest_digest == manifest_digest
    assert inputs.measure_bootstrap_installed_files(context).manifest_digest == manifest_digest
    assert inputs.load_bootstrap_generation(expected=context) == VerifiedBootstrapGeneration(
        context.generation, context.generation_digest, "2026-10-13T00:00:00Z"
    )

    result = inputs.protected_bootstrap_generation_admission()(context)

    assert result == VerifiedBootstrapGeneration(
        context.generation, context.generation_digest, "2026-10-13T00:00:00Z"
    )
    assert capacity_calls == [context]


def _measure_selected(raw, expected_digest, root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return _measure_at(fd, raw, expected_digest=expected_digest, owner=os.getuid())
    finally:
        os.close(fd)
