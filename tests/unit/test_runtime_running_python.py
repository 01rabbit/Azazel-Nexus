"""Synthetic tests for the fixed current-Python observer and its pins."""

from dataclasses import replace
from hashlib import sha256
import inspect
import os
import stat
from types import SimpleNamespace

import pytest

from azazel_nexus.installed_manifest import InstalledFile
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import running_python
from azazel_nexus_runtime.running_python import (
    PythonState,
    RunningExecutable,
    RunningPython,
    _fingerprint_fd,
    observe_running_python,
    validate_running_python,
)


_CONTENT = b"synthetic interpreter bytes\n"
_INTERPRETER = "/opt/env/bin/python"
_IMPORT_PATHS = ("/opt/env/site",)
_VERSION = (3, 13, 5)
_DEFAULT_OBSERVATION = object()


def _file(content=_CONTENT):
    return InstalledFile(
        "opt/env/bin/python", 0o755, len(content), sha256(content).hexdigest()
    )


def _observation(
    content=b"synthetic interpreter bytes\n",
    *,
    interpreter="/opt/env/bin/python",
    import_paths=("/opt/env/site",),
    version=(3, 13, 5),
):
    state = PythonState(
        "linux", "cpython", "cpython-313", (*version, "final", 0), "",
        interpreter, "/usr/bin/python3.13", ("/usr",) * 4,
        (1, 1, 1, True, 1), tuple(import_paths), True, "little", (1 << 63) - 1,
    )
    identity = (
        1, 9, stat.S_IFREG | 0o755, 0, 0, 1, len(content), 1, 1,
    )
    executable = RunningExecutable(identity, sha256(content).hexdigest())
    return RunningPython(state, executable, 123)


def _validate(observation=_DEFAULT_OBSERVATION, **overrides):
    arguments = {
        "interpreter": _INTERPRETER,
        "import_paths": _IMPORT_PATHS,
        "version": _VERSION,
        "expected_file": _file(),
    }
    arguments.update(overrides)
    if observation is _DEFAULT_OBSERVATION:
        observation = _observation()
    return validate_running_python(observation, **arguments)


def test_healthy_fixed_python_observation_is_accepted():
    assert _validate() is None


def test_none_is_not_replaced_by_the_default_observation():
    with pytest.raises(ApprovalRefused):
        _validate(None)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("platform", "darwin"),
        ("implementation", "pypy"),
        ("cache_tag", "cpython-312"),
        ("abiflags", "d"),
        ("executable", "/opt/other/bin/python"),
        ("base_executable", "/opt/env/bin/python"),
        ("prefixes", ("/opt/env",) * 4),
        ("import_paths", ("/opt/env/other",)),
        ("dont_write_bytecode", False),
        ("byteorder", "big"),
        ("maxsize", 1 << 31),
    ],
)
def test_state_field_mutations_are_refused(field, value):
    observation = _observation()
    mutated = replace(observation, state=replace(observation.state, **{field: value}))
    with pytest.raises(ApprovalRefused):
        _validate(mutated)


@pytest.mark.parametrize(
    "version",
    [
        (3, 12, 5),
        (3, 13, -1),
        (3, 13, 10000),
        (True, 13, 5),
        [3, 13, 5],
    ],
)
def test_state_version_mutations_are_refused(version):
    observation = _observation()
    state_version = (
        [*version, "final", 0]
        if type(version) is list
        else (*version, "final", 0)
    )
    mutated = replace(
        observation,
        state=replace(observation.state, version=state_version),
    )
    with pytest.raises(ApprovalRefused):
        _validate(mutated)


@pytest.mark.parametrize(
    "flags",
    [
        (0, 1, 1, True, 1),
        (True, 1, 1, True, 1),
        (1, 1, 1, 1, 1),
        (1, 1, 1, True, False),
        (1, 1, 1, True),
    ],
)
def test_flags_values_and_exact_types_are_enforced(flags):
    observation = _observation()
    mutated = replace(observation, state=replace(observation.state, flags=flags))
    with pytest.raises(ApprovalRefused):
        _validate(mutated)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pid", 0),
        ("pid", True),
    ],
)
def test_pid_must_be_a_positive_exact_integer(field, value):
    with pytest.raises(ApprovalRefused):
        _validate(replace(_observation(), **{field: value}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"interpreter": "/opt/env/../other/bin/python"},
        {"interpreter": "/usr/bin/python3.13"},
        {"import_paths": ["/opt/env/site"]},
        {"import_paths": ("/opt/env/site", "/opt/env/extra")},
        {"version": (3, 12, 5)},
        {"version": (3, 13, True)},
    ],
)
def test_independent_interpreter_import_and_version_pins_are_enforced(overrides):
    with pytest.raises(ApprovalRefused):
        _validate(**overrides)


@pytest.mark.parametrize(
    "expected_file",
    [
        InstalledFile("opt/env/bin/python", 0o644, len(_CONTENT), sha256(_CONTENT).hexdigest()),
        InstalledFile("opt/env/bin/python", 0o755, len(_CONTENT) + 1, sha256(_CONTENT).hexdigest()),
        InstalledFile("opt/env/bin/python", 0o755, len(_CONTENT), "0" * 64),
        object(),
    ],
)
def test_installed_file_pin_metadata_and_hash_are_enforced(expected_file):
    with pytest.raises(ApprovalRefused):
        _validate(expected_file=expected_file)


@pytest.mark.parametrize(
    "identity_change",
    [
        {0: -1},
        {1: 0},
        {2: stat.S_IFLNK | 0o755},
        {2: stat.S_IFREG | 0o744},
        {3: 1},
        {5: 2},
        {6: 0},
        {6: len(_CONTENT) + 1},
    ],
)
def test_executable_identity_metadata_is_enforced(identity_change):
    observation = _observation()
    identity = list(observation.executable.identity)
    for index, value in identity_change.items():
        identity[index] = value
    mutated = replace(
        observation,
        executable=replace(observation.executable, identity=tuple(identity)),
    )
    with pytest.raises(ApprovalRefused):
        _validate(mutated)


def test_executable_hash_must_be_exact_and_match_the_file_pin():
    observation = _observation()
    for value in ("0" * 64, b"0" * 64, None):
        mutated = replace(
            observation,
            executable=replace(observation.executable, sha256=value),
        )
        with pytest.raises(ApprovalRefused):
            _validate(mutated)


def _open_fd(path):
    return os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))


def test_fingerprint_regular_executable_file_uses_current_owner_and_sha(tmp_path):
    content = b"temporary synthetic executable\n"
    path = tmp_path / "python"
    path.write_bytes(content)
    path.chmod(0o755)
    fd = _open_fd(path)
    try:
        fingerprint = _fingerprint_fd(fd, owner=os.getuid())
    finally:
        os.close(fd)
    assert fingerprint.identity[3] == os.getuid()
    assert fingerprint.identity[2] == stat.S_IFREG | 0o755
    assert fingerprint.identity[5] == 1
    assert fingerprint.sha256 == sha256(content).hexdigest()


def test_fingerprint_refuses_changed_mode_and_multiple_links(tmp_path):
    path = tmp_path / "python"
    path.write_bytes(b"executable bytes")
    path.chmod(0o744)
    fd = _open_fd(path)
    try:
        with pytest.raises(ApprovalRefused):
            _fingerprint_fd(fd, owner=os.getuid())
    finally:
        os.close(fd)

    path.chmod(0o755)
    os.link(path, tmp_path / "python-alias")
    fd = _open_fd(path)
    try:
        with pytest.raises(ApprovalRefused):
            _fingerprint_fd(fd, owner=os.getuid())
    finally:
        os.close(fd)


@pytest.mark.parametrize("content", [b"", b"oversized"])
def test_fingerprint_refuses_empty_and_oversized_files(tmp_path, monkeypatch, content):
    path = tmp_path / "python"
    path.write_bytes(content)
    path.chmod(0o755)
    if content:
        monkeypatch.setattr(running_python, "_MAX_EXECUTABLE_BYTES", len(content) - 1)
    fd = _open_fd(path)
    try:
        with pytest.raises(ApprovalRefused):
            _fingerprint_fd(fd, owner=os.getuid())
    finally:
        os.close(fd)


def test_fingerprint_refuses_truncated_read(tmp_path, monkeypatch, private_os):
    private_os(running_python)
    path = tmp_path / "python"
    path.write_bytes(b"complete")
    path.chmod(0o755)
    fd = _open_fd(path)
    actual_fstat = os.fstat
    calls = 0

    def larger_first_size(descriptor):
        nonlocal calls
        info = actual_fstat(descriptor)
        calls += 1
        if descriptor == fd and calls == 1:
            values = {
                name: getattr(info, name)
                for name in (
                    "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                    "st_size", "st_mtime_ns", "st_ctime_ns",
                )
            }
            values["st_size"] = info.st_size + 1
            return SimpleNamespace(**values)
        return info

    monkeypatch.setattr(running_python.os, "fstat", larger_first_size)
    try:
        with pytest.raises(ApprovalRefused):
            _fingerprint_fd(fd, owner=os.getuid())
    finally:
        os.close(fd)


@pytest.mark.parametrize("same_stamp", [False, True])
def test_fingerprint_refuses_bytes_changed_during_read(tmp_path, monkeypatch, same_stamp, private_os):
    private_os(running_python)
    path = tmp_path / "python"
    path.write_bytes(b"stable-size-content")
    path.chmod(0o755)
    fd = _open_fd(path)
    writer = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0))
    actual_read = os.read
    actual_fstat = os.fstat
    stamp = actual_fstat(fd)
    if same_stamp:
        # Linux can coalesce metadata timestamps for writes within one clock
        # quantum. Force that condition: refusal must come from the second
        # content observation, not a conveniently advanced timestamp.
        monkeypatch.setattr(running_python.os, "fstat", lambda descriptor: (
            stamp if descriptor == fd else actual_fstat(descriptor)
        ))
    changed = False

    def mutate_after_read(descriptor, size):
        nonlocal changed
        result = actual_read(descriptor, size)
        if descriptor == fd and not changed:
            changed = True
            os.pwrite(writer, b"X", 0)
        return result

    monkeypatch.setattr(running_python.os, "read", mutate_after_read)
    try:
        message = "content observations differ" if same_stamp else "changed|content"
        with pytest.raises(ApprovalRefused, match=message):
            _fingerprint_fd(fd, owner=os.getuid())
    finally:
        os.close(fd)
        os.close(writer)


def test_observer_has_no_caller_selected_process_or_path_and_uses_procfs(monkeypatch, private_os):
    private_os(running_python)
    assert tuple(inspect.signature(observe_running_python).parameters) == ()
    state = _observation().state
    executable = _observation().executable
    opened = []
    closed = []
    stat_calls = []
    real_open, real_close, real_stat = os.open, os.close, os.stat

    def fake_open(path, flags, *, dir_fd=None):
        opened.append((path, dir_fd))
        return {"/proc": 41, "123": 42, "exe": 43}[path]

    def fake_stat(path, *, dir_fd=None, **kwargs):
        stat_calls.append((path, dir_fd))
        if path == "exe":
            return SimpleNamespace(
                st_dev=executable.identity[0], st_ino=executable.identity[1],
                st_mode=executable.identity[2], st_uid=executable.identity[3],
                st_gid=executable.identity[4], st_nlink=executable.identity[5],
                st_size=executable.identity[6], st_mtime_ns=executable.identity[7],
                st_ctime_ns=executable.identity[8],
            )
        return real_stat(path, dir_fd=dir_fd, **kwargs)

    def fake_close(fd):
        closed.append(fd)

    monkeypatch.setattr(running_python.sys, "platform", "linux")
    monkeypatch.setattr(running_python.os, "getpid", lambda: 123)
    monkeypatch.setattr(running_python, "_python_state", lambda: state)
    monkeypatch.setattr(running_python, "_filesystem_type", lambda fd: running_python._PROC_MAGIC)
    monkeypatch.setattr(running_python, "_fingerprint_fd", lambda fd: executable)
    monkeypatch.setattr(running_python.os, "open", fake_open)
    monkeypatch.setattr(running_python.os, "stat", fake_stat)
    monkeypatch.setattr(running_python.os, "close", fake_close)

    result = observe_running_python()

    assert result == RunningPython(state, executable, 123)
    assert opened == [("/proc", None), ("123", 41), ("exe", 42)]
    assert stat_calls == [("exe", 42), ("exe", 42)]
    assert closed == [43, 42, 41]
    # Keep references alive to make it explicit that only the call's seams were patched.
    assert real_open and real_close


@pytest.mark.parametrize("change", ["mode", "timestamp"])
def test_fingerprint_refuses_metadata_changed_during_read(tmp_path, monkeypatch, change, private_os):
    # The bytes stay the same, so both content observations agree; only the
    # file's identity says it was touched mid-measurement. That alone refuses.
    private_os(running_python)
    path = tmp_path / "python"
    path.write_bytes(b"stable executable bytes")
    path.chmod(0o755)
    fd = _open_fd(path)
    actual_read = os.read
    changed = False

    def touch_after_first_read(descriptor, size):
        nonlocal changed
        result = actual_read(descriptor, size)
        if descriptor == fd and not changed:
            changed = True
            if change == "mode":
                path.chmod(0o775)
            else:
                info = os.stat(path)
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 10**9))
        return result

    monkeypatch.setattr(running_python.os, "read", touch_after_first_read)
    try:
        with pytest.raises(ApprovalRefused, match="changed during measurement"):
            _fingerprint_fd(fd, owner=os.getuid())
    finally:
        os.close(fd)


def _stat_result(identity):
    return SimpleNamespace(
        st_dev=identity[0], st_ino=identity[1], st_mode=identity[2],
        st_uid=identity[3], st_gid=identity[4], st_nlink=identity[5],
        st_size=identity[6], st_mtime_ns=identity[7], st_ctime_ns=identity[8],
    )


@pytest.mark.parametrize("change", ["measured-differs", "exe-rebound-after"])
def test_observer_refuses_executable_identity_that_does_not_stay_bound(
    monkeypatch, change, private_os,
):
    # Same seams as the healthy observer test above; only one identity moves.
    private_os(running_python)
    state = _observation().state
    executable = _observation().executable
    other = list(executable.identity)
    other[1] += 1  # another inode: a different file behind the same name
    other = tuple(other)
    if change == "measured-differs":
        measured, named = replace(executable, identity=other), [executable.identity] * 2
    else:
        measured, named = executable, [executable.identity, other]
    stats = iter(named)

    monkeypatch.setattr(running_python.sys, "platform", "linux")
    monkeypatch.setattr(running_python.os, "getpid", lambda: 123)
    monkeypatch.setattr(running_python, "_python_state", lambda: state)
    monkeypatch.setattr(running_python, "_filesystem_type", lambda fd: running_python._PROC_MAGIC)
    monkeypatch.setattr(running_python, "_fingerprint_fd", lambda fd: measured)
    monkeypatch.setattr(
        running_python.os, "open",
        lambda path, flags, *, dir_fd=None: {"/proc": 41, "123": 42, "exe": 43}[path],
    )
    monkeypatch.setattr(
        running_python.os, "stat",
        lambda path, *, dir_fd=None, **kwargs: _stat_result(next(stats)),
    )
    monkeypatch.setattr(running_python.os, "close", lambda fd: None)

    with pytest.raises(ApprovalRefused, match="^current Python observation refused$"):
        observe_running_python()
