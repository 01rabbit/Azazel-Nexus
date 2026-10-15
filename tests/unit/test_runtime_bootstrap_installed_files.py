"""Protected selected-file manifest wiring for bootstrap admission."""

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import os

import pytest

from azazel_nexus import bootstrap_store
from azazel_nexus.installed_files import SelectedInstalledFiles, _measure_at
from azazel_nexus.installed_manifest import (
    InstalledDirectory, InstalledFile, InstalledManifest,
    encode_installed_manifest,
)
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_inputs
from azazel_nexus_runtime.startup_wrapper import parse_wrapper, render_wrapper
from test_bootstrap_generation import _context
from test_runtime_running_python import _observation
from test_runtime_python_startup import _absence
from test_runtime_import_routing import _routing
from test_runtime_loaded_modules import _loaded


ENTRYPOINTS = (
    "usr/libexec/azazel/az-activated",
    "usr/libexec/azazel/az-auditd",
    "usr/libexec/azazel/az-commissiond",
)
TARGETS = {
    ENTRYPOINTS[0]: "azazel_nexus_runtime.activated:main",
    ENTRYPOINTS[1]: "azazel_nexus_runtime.auditd:main",
    ENTRYPOINTS[2]: "azazel_nexus_runtime.commissiond:main",
}
INTERPRETER_PATH = "opt/env/bin/python"
INTERPRETER = "/" + INTERPRETER_PATH
IMPORT_PATHS = ("/opt/env/site",)
CONFIG_PATH = "opt/env/pyvenv.cfg"
BASE_PATH = "usr/bin/python3.13"
CONFIG = (b"home = /usr/bin\ninclude-system-site-packages = false\n"
          b"version = 3.13.5\nexecutable = /usr/bin/python3.13\n")


@pytest.fixture
def umask_0002():
    previous = os.umask(0o002)
    try:
        yield
    finally:
        os.umask(previous)


def _manifest_raw(
    *, modes=None, paths=ENTRYPOINTS, version=2, directory_paths=None,
    include_interpreter=True, wrappers=None, import_paths=IMPORT_PATHS,
    include_config=True, config=CONFIG, include_base=True,
    base_bytes=b"synthetic interpreter bytes\n",
):
    modes = {} if modes is None else modes
    wrappers = {} if wrappers is None else wrappers
    file_bytes = {}
    for path in paths:
        if path in TARGETS:
            file_bytes[path] = wrappers.get(
                path, render_wrapper(INTERPRETER, TARGETS[path], import_paths=import_paths),
            )
        else:
            file_bytes[path] = b"synthetic selected file: " + path.encode()
    if include_interpreter and any(path in TARGETS for path in paths):
        file_bytes[INTERPRETER_PATH] = b"synthetic interpreter bytes\n"
        if include_base:
            file_bytes[BASE_PATH] = base_bytes
        if include_config:
            file_bytes[CONFIG_PATH] = config
    entries = tuple(sorted((
        InstalledFile(
            path,
            modes.get(path, 0o755 if path in TARGETS or path in {
                INTERPRETER_PATH, BASE_PATH,
            } else 0o644),
            len(content), sha256(content).hexdigest(),
        )
        for path, content in file_bytes.items()
    ), key=lambda entry: entry.path))
    if directory_paths is None:
        declared = set()
        directory_inputs = list(file_bytes)
        if version == 2 and include_interpreter and any(
            path in TARGETS for path in paths
        ):
            directory_inputs.extend(path.removeprefix("/") for path in import_paths)
            declared.update(
                path.removeprefix("/") for path in import_paths
                if not path.endswith(".zip")
            )
        for path in directory_inputs:
            parts = path.split("/")
            declared.update(
                "/".join(parts[:index]) for index in range(2, len(parts))
            )
        directory_paths = tuple(sorted(declared))
    directories = (tuple(InstalledDirectory(path) for path in directory_paths)
                   if version == 2 else ())
    return encode_installed_manifest(InstalledManifest(
        entries, directories, version=version,
    ))


def _wrapper_contents(paths=ENTRYPOINTS, overrides=None, *, import_paths=IMPORT_PATHS):
    overrides = {} if overrides is None else overrides
    return tuple(overrides.get(
        path, render_wrapper(INTERPRETER, TARGETS[path], import_paths=import_paths),
    ) for path in sorted(path for path in paths if path in TARGETS))


def _wire_raw_and_content_reader(monkeypatch, raw, *, contents=None, config=CONFIG):
    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw)
    return _wire_content_reader(monkeypatch, raw, contents=contents, config=config)


def _wire_content_reader(monkeypatch, raw, *, contents=None, config=CONFIG):
    expected = _wrapper_contents() if contents is None else contents
    calls = []

    def read_pinned(actual, *, expected_digest, paths):
        calls.append((actual, expected_digest, paths))
        if paths == (CONFIG_PATH,):
            return (config,)
        return expected

    monkeypatch.setattr(bootstrap_inputs, "read_pinned_installed_files", read_pinned)

    def observe_running():
        interpreter, import_paths = parse_wrapper(expected[0], target=TARGETS[ENTRYPOINTS[0]])
        return _observation(interpreter=interpreter, import_paths=import_paths)

    monkeypatch.setattr(bootstrap_inputs, "observe_running_python", observe_running)
    monkeypatch.setattr(bootstrap_inputs, "observe_python_startup_absence", _absence)
    monkeypatch.setattr(bootstrap_inputs, "observe_import_routing",
                        lambda paths, _manifest, **_k: _routing(import_paths=paths))
    monkeypatch.setattr(bootstrap_inputs, "observe_loaded_modules",
                        lambda _manifest, paths, _main: _loaded(import_paths=paths))
    return calls


def _pinned_context(raw):
    return replace(
        _context(), unit_closure_digest="sha256:" + sha256(raw).hexdigest(),
    )


def _protected_directory(path):
    @contextmanager
    def open_directory():
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    return open_directory


def _read_current_user(fd, name, *, owner, limit):
    del owner
    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        if os.fstat(file_fd).st_uid != os.getuid():
            raise ApprovalRefused("test manifest owner mismatch")
        return os.read(file_fd, limit + 1)
    finally:
        os.close(file_fd)


def _wire_manifest(path, monkeypatch):
    monkeypatch.setattr(
        bootstrap_store, "_bootstrap_directory", _protected_directory(path)
    )
    monkeypatch.setattr(bootstrap_store, "_read_file_at", _read_current_user)


def test_measures_pinned_fixed_entrypoints_and_rechecks_exact_raw_bytes(
    tmp_path, monkeypatch,
):
    path = tmp_path / "bootstrap"
    path.mkdir(mode=0o700)
    raw = _manifest_raw()
    manifest_file = path / "installed-files.json"
    manifest_file.write_bytes(raw)
    os.chmod(manifest_file, 0o600)
    _wire_manifest(path, monkeypatch)
    context = _pinned_context(raw)
    observed = []
    content_reads = _wire_content_reader(monkeypatch, raw)

    def measure(actual, *, expected_digest):
        observed.append((actual, expected_digest))
        return SelectedInstalledFiles(expected_digest, 3, 4096)

    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)
    result = bootstrap_inputs.measure_bootstrap_installed_files(context)
    assert result == SelectedInstalledFiles(context.unit_closure_digest, 3, 4096)
    assert observed == [(raw, context.unit_closure_digest)]
    assert len(content_reads) == 2
    assert content_reads[0][2] == ENTRYPOINTS
    assert content_reads[1][2] == (CONFIG_PATH,)


@pytest.mark.parametrize("case", [
    "unlisted-interpreter",
    "nonexecutable-interpreter",
    "missing-import-directory",
    "altered-wrapper-bytes",
    "wrong-wrapper-target",
    "mismatched-import-paths",
    "ancestor-only-import-directory",
    "v1-uncovered-startup-paths",
])
def test_startup_content_and_path_coverage_fail_closed(monkeypatch, case):
    wrappers = {}
    modes = {}
    include_interpreter = True
    version = 2
    directories = None
    wrapper_import_paths = IMPORT_PATHS
    contents = list(_wrapper_contents())

    if case == "unlisted-interpreter":
        include_interpreter = False
    elif case == "nonexecutable-interpreter":
        modes[INTERPRETER_PATH] = 0o644
    elif case == "missing-import-directory":
        directories = (
            "opt/env", "opt/env/bin", "usr/libexec", "usr/libexec/azazel",
        )
    elif case == "altered-wrapper-bytes":
        wrappers[ENTRYPOINTS[0]] = b"#!/opt/env/bin/python -IS\n# altered\n"
        contents[0] = wrappers[ENTRYPOINTS[0]]
    elif case == "wrong-wrapper-target":
        wrappers[ENTRYPOINTS[0]] = render_wrapper(
            INTERPRETER, "azazel_nexus_runtime.auditd:not_main",
            import_paths=IMPORT_PATHS,
        )
        contents[0] = wrappers[ENTRYPOINTS[0]]
    elif case == "mismatched-import-paths":
        alternate = ("/opt/env/alternate",)
        wrappers[ENTRYPOINTS[0]] = render_wrapper(
            INTERPRETER, TARGETS[ENTRYPOINTS[0]], import_paths=alternate,
        )
        contents[0] = wrappers[ENTRYPOINTS[0]]
        directories = (
            "opt/env", "opt/env/alternate", "opt/env/bin", "opt/env/site",
            "usr/libexec", "usr/libexec/azazel",
        )
    elif case == "ancestor-only-import-directory":
        wrapper_import_paths = ("/opt/env/site/pkg",)
        wrappers = {
            path: render_wrapper(INTERPRETER, TARGETS[path],
                                import_paths=wrapper_import_paths)
            for path in ENTRYPOINTS
        }
        contents = list(_wrapper_contents(overrides=wrappers))
        directories = (
            "opt/env", "opt/env/bin", "opt/env/site",
            "usr/libexec", "usr/libexec/azazel",
        )
    elif case == "v1-uncovered-startup-paths":
        version = 1

    raw = _manifest_raw(
        modes=modes, version=version, directory_paths=directories,
        include_interpreter=include_interpreter, wrappers=wrappers,
        import_paths=wrapper_import_paths,
    )
    content_reads = _wire_raw_and_content_reader(
        monkeypatch, raw, contents=tuple(contents),
    )
    measured = []
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda *args, **kwargs: measured.append((args, kwargs)),
    )

    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))

    assert len(content_reads) == 1
    assert measured == []


def test_v1_zip_candidate_is_not_an_admitted_unpacked_runtime(monkeypatch):
    zip_path = "opt/env/site.zip"
    zip_import = ("/" + zip_path,)
    paths = (*ENTRYPOINTS, zip_path)
    raw = _manifest_raw(paths=paths, version=1, import_paths=zip_import)
    content_reads = _wire_raw_and_content_reader(
        monkeypatch, raw, contents=_wrapper_contents(import_paths=zip_import),
    )
    measured = []

    def measure(actual, *, expected_digest):
        pytest.fail("unsupported ZIP execution reached full measurement")

    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)
    context = _pinned_context(raw)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(context)
    assert len(content_reads) == 1
    assert measured == []


def test_generic_v1_selected_file_measurement_remains_supported(tmp_path, umask_0002):
    path = "usr/share/azazel/diagnostic.txt"
    content = b"ordinary v1 selected-file diagnostic\n"
    raw = encode_installed_manifest(InstalledManifest((InstalledFile(
        path, 0o644, len(content), sha256(content).hexdigest(),
    ),)))
    root = tmp_path / "installed"
    leaf = root / path
    leaf.parent.mkdir(parents=True)
    leaf.write_bytes(content)
    leaf.chmod(0o644)
    for directory in (root, root / "usr", root / "usr/share",
                      root / "usr/share/azazel"):
        directory.chmod(0o755)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        result = _measure_at(
            descriptor, raw,
            expected_digest="sha256:" + sha256(raw).hexdigest(),
            owner=os.getuid(),
        )
    finally:
        os.close(descriptor)
    assert result.file_count == 1
    assert result.total_bytes == len(content)


@pytest.mark.parametrize("case", [
    "missing-config", "config-mode", "empty-config", "oversized-config",
    "missing-base", "base-mode", "copy-mismatch", "home-redirect",
    "duplicate-home", "system-site", "wrong-version", "wrong-executable",
])
def test_pinned_venv_profile_refuses_before_full_measurement(monkeypatch, case):
    options = {}
    config = CONFIG
    if case == "missing-config":
        options["include_config"] = False
    elif case == "config-mode":
        options["modes"] = {CONFIG_PATH: 0o755}
    elif case == "empty-config":
        config = b""
    elif case == "oversized-config":
        config += b"prompt = " + b"x" * 4096 + b"\n"
    elif case == "missing-base":
        options["include_base"] = False
    elif case == "base-mode":
        options["modes"] = {BASE_PATH: 0o644}
    elif case == "copy-mismatch":
        options["base_bytes"] = b"different base interpreter\n"
    elif case == "home-redirect":
        config = config.replace(b"home = /usr/bin", b"home = /opt/other")
    elif case == "duplicate-home":
        config += b"home = /usr/bin\n"
    elif case == "system-site":
        config = config.replace(b"false", b"true")
    elif case == "wrong-version":
        config = config.replace(b"3.13.5", b"3.12.5")
    else:
        config = config.replace(b"executable = /usr/bin/python3.13",
                                b"executable = /opt/other/python3.13")
    raw = _manifest_raw(config=config, **options)
    reads = _wire_raw_and_content_reader(monkeypatch, raw, config=config)
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda *_a, **_kw: pytest.fail("invalid venv reached full measurement"),
    )
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))
    pre_read = {"missing-config", "config-mode", "empty-config", "oversized-config",
                "missing-base", "base-mode", "copy-mismatch"}
    assert len(reads) == (1 if case in pre_read else 2)


def test_venv_metadata_uses_independently_pinned_reader_before_full_measurement(monkeypatch):
    raw = _manifest_raw()
    _wire_raw_and_content_reader(monkeypatch, raw)
    original = bootstrap_inputs.read_pinned_installed_files
    calls = []

    def refused_read(actual, *, expected_digest, paths):
        calls.append(paths)
        if paths == (CONFIG_PATH,):
            assert actual == raw
            assert expected_digest == _pinned_context(raw).unit_closure_digest
            raise ApprovalRefused("synthetic metadata identity/hash drift")
        return original(actual, expected_digest=expected_digest, paths=paths)

    monkeypatch.setattr(bootstrap_inputs, "read_pinned_installed_files", refused_read)
    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files",
                        lambda *_a, **_kw: pytest.fail("unpinned config reached measurement"))
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))
    assert calls == [ENTRYPOINTS, (CONFIG_PATH,)]


@pytest.mark.parametrize("case", ["missing", "hash", "flags", "version"])
def test_current_interpreter_must_match_before_full_measurement(monkeypatch, case):
    raw = _manifest_raw()
    _wire_raw_and_content_reader(monkeypatch, raw)
    observed = _observation()
    if case == "missing":
        observed = None
    elif case == "hash":
        observed = replace(observed, executable=replace(observed.executable, sha256="0" * 64))
    elif case == "flags":
        observed = replace(observed, state=replace(observed.state, flags=(0, 1, 1, True, 1)))
    else:
        observed = replace(observed, state=replace(observed.state, version=(3, 13, 0, "final", 0)))
    monkeypatch.setattr(bootstrap_inputs, "observe_running_python", lambda: observed)
    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files",
                        lambda *_a, **_kw: pytest.fail("invalid current Python reached measure"))
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))


def test_current_interpreter_identity_change_across_full_measurement_refuses(monkeypatch):
    raw = _manifest_raw()
    _wire_raw_and_content_reader(monkeypatch, raw)
    observed = _observation()
    calls = []

    def running():
        calls.append(True)
        if len(calls) == 1:
            return observed
        identity = list(observed.executable.identity)
        identity[1] += 1
        return replace(observed, executable=replace(observed.executable, identity=tuple(identity)))

    monkeypatch.setattr(bootstrap_inputs, "observe_running_python", running)
    measured = []

    def measure(_raw, *, expected_digest):
        measured.append(True)
        return SelectedInstalledFiles(expected_digest, 6, 4096)

    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))
    assert measured == [True]
    assert calls == [True, True]


def test_startup_override_refuses_before_full_measurement(monkeypatch):
    raw = _manifest_raw()
    _wire_raw_and_content_reader(monkeypatch, raw)
    calls = []

    def refuse(interpreter):
        calls.append(interpreter)
        raise ApprovalRefused("synthetic existing startup override")

    monkeypatch.setattr(bootstrap_inputs, "observe_python_startup_absence", refuse)
    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files",
                        lambda *_a, **_kw: pytest.fail("startup override reached measure"))
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))
    assert calls == [INTERPRETER]


@pytest.mark.parametrize("case", ["type", "path", "changed"])
def test_startup_absence_type_path_and_continuity_required(monkeypatch, case):
    raw = _manifest_raw()
    _wire_raw_and_content_reader(monkeypatch, raw)
    good = _absence()
    calls = []

    def observe(_interpreter):
        calls.append(True)
        if case == "type":
            return None
        if case == "path":
            return replace(good, paths=())
        return good if len(calls) == 1 else replace(good, observations=())

    monkeypatch.setattr(bootstrap_inputs, "observe_python_startup_absence", observe)
    measured = []

    def measure(_raw, *, expected_digest):
        measured.append(True)
        return SelectedInstalledFiles(expected_digest, 6, 4096)

    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))
    assert len(calls) == (2 if case == "changed" else 1)
    assert measured == ([True] if case == "changed" else [])


@pytest.mark.parametrize("case", ["refuse", "type", "paths", "changed"])
def test_import_routing_required_before_and_after_full_measurement(monkeypatch, case):
    raw = _manifest_raw()
    _wire_raw_and_content_reader(monkeypatch, raw)
    good = _routing()
    calls = []

    def observe(paths, manifest, **_k):
        assert paths == IMPORT_PATHS
        assert manifest.files
        calls.append(True)
        if case == "refuse":
            raise ApprovalRefused("synthetic nonstandard routing")
        if case == "type":
            return None
        if case == "paths":
            return replace(good, import_paths=())
        return good if len(calls) == 1 else replace(good, cache=(("changed", "none"),))

    monkeypatch.setattr(bootstrap_inputs, "observe_import_routing", observe)
    measured = []

    def measure(_raw, *, expected_digest):
        measured.append(True)
        return SelectedInstalledFiles(expected_digest, 6, 4096)

    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))
    assert len(calls) == (2 if case == "changed" else 1)
    assert measured == ([True] if case == "changed" else [])


@pytest.mark.parametrize("case", ["refuse", "type", "paths", "changed"])
def test_loaded_modules_required_before_and_after_full_measurement(monkeypatch, case):
    raw = _manifest_raw()
    _wire_raw_and_content_reader(monkeypatch, raw)
    good = _loaded()
    calls = []

    def observe(manifest, paths, main_path):
        assert manifest.files and paths == IMPORT_PATHS
        assert main_path == "/" + ENTRYPOINTS[0]
        calls.append(True)
        if case == "refuse":
            raise ApprovalRefused("synthetic unpinned module")
        if case == "type":
            return None
        if case == "paths":
            return replace(good, import_paths=())
        return good if len(calls) == 1 else replace(good, files=("changed",))

    monkeypatch.setattr(bootstrap_inputs, "observe_loaded_modules", observe)
    measured = []

    def measure(_raw, *, expected_digest):
        measured.append(True)
        return SelectedInstalledFiles(expected_digest, 6, 4096)

    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))
    assert len(calls) == (2 if case == "changed" else 1)
    assert measured == ([True] if case == "changed" else [])


@pytest.mark.parametrize("missing", ENTRYPOINTS)
def test_each_missing_required_entrypoint_refuses_before_measure(
    monkeypatch, missing,
):
    raw = _manifest_raw(paths=tuple(path for path in ENTRYPOINTS if path != missing))
    context = _pinned_context(raw)
    measured = []
    monkeypatch.setattr(
        bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw,
    )
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda *args, **kwargs: measured.append((args, kwargs)),
    )
    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        lambda *args, **kwargs: pytest.fail("missing entrypoint reached content read"),
    )

    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(context)
    assert measured == []


@pytest.mark.parametrize("wrong_mode", ENTRYPOINTS)
def test_required_entrypoint_with_nonexecutable_mode_refuses_before_measure(
    monkeypatch, wrong_mode,
):
    raw = _manifest_raw(modes={wrong_mode: 0o644})
    context = _pinned_context(raw)
    measured = []
    monkeypatch.setattr(
        bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw,
    )
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda *args, **kwargs: measured.append((args, kwargs)),
    )
    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        lambda *args, **kwargs: pytest.fail("wrong entrypoint mode reached content read"),
    )

    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(context)
    assert measured == []


def test_unrelated_manifest_does_not_reach_file_measurement(monkeypatch):
    raw = _manifest_raw(paths=("usr/share/azazel/unrelated.txt",))
    context = _pinned_context(raw)
    measured = []
    monkeypatch.setattr(
        bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw,
    )
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda *args, **kwargs: measured.append((args, kwargs)),
    )
    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        lambda *args, **kwargs: pytest.fail("unrelated manifest reached content read"),
    )

    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(context)
    assert measured == []


def test_valid_manifest_with_extra_selected_file_is_accepted(monkeypatch):
    raw = _manifest_raw(paths=(*ENTRYPOINTS, "usr/share/azazel/extra.txt"))
    context = _pinned_context(raw)
    measured = []
    _wire_raw_and_content_reader(monkeypatch, raw)

    def measure(actual, *, expected_digest):
        measured.append((actual, expected_digest))
        return SelectedInstalledFiles(expected_digest, 4, 4096)

    monkeypatch.setattr(
        bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw,
    )
    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)
    assert bootstrap_inputs.measure_bootstrap_installed_files(context) == (
        SelectedInstalledFiles(context.unit_closure_digest, 4, 4096)
    )
    assert measured == [(raw, context.unit_closure_digest)]


def test_changed_manifest_during_measurement_refuses_after_same_raw_was_measured(
    tmp_path, monkeypatch,
):
    path = tmp_path / "bootstrap"
    path.mkdir(mode=0o700)
    raw = _manifest_raw()
    manifest_file = path / "installed-files.json"
    manifest_file.write_bytes(raw)
    os.chmod(manifest_file, 0o600)
    _wire_manifest(path, monkeypatch)
    context = _pinned_context(raw)
    measured = []
    _wire_content_reader(monkeypatch, raw)

    def measure(actual, *, expected_digest):
        measured.append((actual, expected_digest))
        changed = _manifest_raw(paths=(*ENTRYPOINTS, "usr/share/azazel/changed.txt"))
        manifest_file.write_bytes(changed)
        os.chmod(manifest_file, 0o600)
        return SelectedInstalledFiles(expected_digest, 3, 4096)

    monkeypatch.setattr(bootstrap_inputs, "measure_installed_files", measure)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(context)
    assert measured == [(raw, context.unit_closure_digest)]


def test_missing_manifest_refuses_without_fallback(tmp_path, monkeypatch):
    path = tmp_path / "bootstrap"
    path.mkdir(mode=0o700)
    _wire_manifest(path, monkeypatch)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_context())


def test_manifest_replaced_during_protected_read_refuses_before_content_measurement(
    tmp_path, monkeypatch,
):
    path = tmp_path / "bootstrap"
    path.mkdir(mode=0o700)
    raw = _manifest_raw()
    manifest_file = path / "installed-files.json"
    manifest_file.write_bytes(raw)
    manifest_file.chmod(0o600)
    _wire_manifest(path, monkeypatch)
    reads = []
    measured = []

    def read_then_replace(fd, name, *, owner, limit):
        value = _read_current_user(fd, name, owner=owner, limit=limit)
        reads.append(value)
        if len(reads) == 1:
            manifest_file.write_bytes(_manifest_raw(
                paths=(*ENTRYPOINTS, "usr/share/azazel/replacement.txt"),
            ))
        return value

    monkeypatch.setattr(bootstrap_store, "_read_file_at", read_then_replace)
    content_reads = []
    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        lambda *args, **kwargs: content_reads.append((args, kwargs)),
    )
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda *a, **kw: measured.append((a, kw)),
    )
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(_pinned_context(raw))
    assert len(reads) == 2
    assert measured == []
    assert content_reads == []


def test_entrypoint_presence_does_not_substitute_for_independent_manifest_pin(monkeypatch):
    raw = _manifest_raw()
    measured = []
    monkeypatch.setattr(bootstrap_inputs, "read_bootstrap_installed_manifest", lambda: raw)
    monkeypatch.setattr(
        bootstrap_inputs, "read_pinned_installed_files",
        lambda *args, **kwargs: pytest.fail("wrong digest reached content read"),
    )
    monkeypatch.setattr(
        bootstrap_inputs, "measure_installed_files",
        lambda *a, **kw: measured.append((a, kw)),
    )
    context = replace(_pinned_context(raw), unit_closure_digest="sha256:" + "0" * 64)
    with pytest.raises(ApprovalRefused, match="protected bootstrap installed files refused"):
        bootstrap_inputs.measure_bootstrap_installed_files(context)
    assert measured == []
