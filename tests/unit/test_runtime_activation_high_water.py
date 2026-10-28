"""Activation high-water store (#206 P2): temporary regular files only."""

from contextlib import contextmanager
from dataclasses import replace
import fcntl
import json
import os
import stat

import pytest

from azazel_nexus_runtime import activation_high_water as hw
from azazel_nexus_runtime.activation_high_water import (
    HighWater,
    HighWaterCommitUncertain,
    HighWaterRefused,
    activation_ledger_present,
    decode_high_water,
    encode_high_water,
    initialize_high_water,
    raise_high_water,
    read_high_water,
    require_high_water_for_pass,
)

NOW = "2027-06-01T00:00:00Z"
SKEW = 120


def _init(value, now=NOW, skew=SKEW):
    return initialize_high_water(value, now=now, skew_seconds=skew)


def _raise(value, now=NOW, skew=SKEW):
    return raise_high_water(value, now=now, skew_seconds=skew)


FLOOR = HighWater(security_epoch=3, approval_seq=10, generation=2,
                  time_floor="2026-10-20T00:00:00Z")


@pytest.fixture
def state(tmp_path, monkeypatch):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o711)
    directory.chmod(0o711)

    @contextmanager
    def state_directory():
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(hw, "_state_directory", state_directory)
    monkeypatch.setattr(hw, "_OWNER", os.getuid())
    return directory


def _file(state):
    return state / "activation" / "high-water.json"


def test_absent_is_none_and_distinct_from_present(state):
    assert read_high_water() is None
    (state / "activation").mkdir(mode=0o700)
    assert read_high_water() is None
    _init(FLOOR)
    assert read_high_water() == FLOOR


def test_initialize_creates_private_canonical_file(state):
    assert _init(FLOOR) == FLOOR
    leaf = os.stat(state / "activation")
    assert stat.S_IMODE(leaf.st_mode) == 0o700
    info = os.stat(_file(state))
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
    assert _file(state).read_bytes() == encode_high_water(FLOOR)
    assert json.loads(_file(state).read_bytes())["schema"] == "azazel-nexus/activation-high-water/v1"
    assert not (state / "activation" / ".high-water.json.partial").exists()


def test_initialize_never_overwrites(state):
    _init(FLOOR)
    with pytest.raises(HighWaterRefused):
        _init(replace(FLOOR, security_epoch=0))
    assert read_high_water() == FLOOR


def test_raise_requires_an_existing_floor(state):
    with pytest.raises(HighWaterRefused):
        _raise(FLOOR)
    (state / "activation").mkdir(mode=0o700)
    with pytest.raises(HighWaterRefused):
        _raise(FLOOR)
    assert read_high_water() is None


def test_raise_moves_every_field_forward(state):
    _init(FLOOR)
    higher = HighWater(4, 11, 3, "2026-10-21T00:00:00Z")
    assert _raise(higher) == higher
    assert read_high_water() == higher
    assert _raise(higher) == higher  # equal is a no-op, not a refusal


@pytest.mark.parametrize("lower", [
    replace(FLOOR, security_epoch=2),
    replace(FLOOR, approval_seq=9),
    replace(FLOOR, generation=1),
    replace(FLOOR, time_floor="2026-10-19T23:59:59Z"),
    HighWater(99, 99, 1, "2027-01-01T00:00:00Z"),
])
def test_raise_refuses_any_lower_field_and_changes_nothing(state, lower):
    _init(FLOOR)
    before = _file(state).read_bytes()
    stamp = os.stat(_file(state)).st_ino
    with pytest.raises(HighWaterRefused):
        _raise(lower)
    assert _file(state).read_bytes() == before
    assert os.stat(_file(state)).st_ino == stamp


def test_ledger_presence_and_pass_requirement(state):
    assert activation_ledger_present() is False
    assert require_high_water_for_pass() is None
    (state / "activation.jsonl").write_text("")
    assert activation_ledger_present() is True
    with pytest.raises(HighWaterRefused) as error:
        require_high_water_for_pass()
    assert "activation ledger" in str(error.value)
    _init(FLOOR)
    assert require_high_water_for_pass() == FLOOR


def test_ledger_of_any_type_counts_as_history(state, tmp_path):
    (state / "activation.jsonl").symlink_to(tmp_path / "nowhere")
    assert activation_ledger_present() is True
    with pytest.raises(HighWaterRefused):
        require_high_water_for_pass()


@pytest.mark.parametrize("fields", [
    {"security_epoch": -1}, {"approval_seq": True}, {"generation": 1.0},
    {"security_epoch": 2**63}, {"time_floor": "2026-10-20T00:00:00+00:00"},
    {"time_floor": "2026-13-01T00:00:00Z"}, {"time_floor": 0},
])
def test_record_values_are_validated(fields):
    with pytest.raises(HighWaterRefused):
        replace(FLOOR, **fields)


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


GOOD = json.loads(encode_high_water(FLOOR))


@pytest.mark.parametrize("raw", [
    _canonical({**GOOD, "extra": 1}),
    _canonical({k: v for k, v in GOOD.items() if k != "generation"}),
    _canonical({**GOOD, "schema": "azazel-nexus/activation-high-water/v2"}),
    _canonical({**GOOD, "approval_seq": -5}),
    json.dumps(GOOD, sort_keys=True, indent=1).encode(),
    _canonical(GOOD) + b"\n",
    _canonical(GOOD).replace(b'"generation":2', b'"generation":2,"generation":9'),
    b"[]", b"", b"\xff", b"0" * 5000,
])
def test_closed_shape_refusals(raw):
    with pytest.raises(HighWaterRefused):
        decode_high_water(raw)


def test_malformed_stored_file_is_refused_not_absent(state):
    _init(FLOOR)
    _file(state).write_bytes(b'{"schema":"x"}')
    with pytest.raises(HighWaterRefused):
        read_high_water()
    with pytest.raises(HighWaterRefused):
        require_high_water_for_pass()
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, security_epoch=9))


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o604, 0o660])
def test_file_wider_than_owner_only_refused(state, mode):
    _init(FLOOR)
    _file(state).chmod(mode)
    with pytest.raises(HighWaterRefused):
        read_high_water()


@pytest.mark.parametrize("mode", [0o750, 0o755, 0o701])
def test_leaf_directory_wider_than_owner_only_refused(state, mode):
    _init(FLOOR)
    (state / "activation").chmod(mode)
    with pytest.raises(HighWaterRefused):
        read_high_water()
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, security_epoch=9))


def test_wrong_owner_refused(state, monkeypatch):
    _init(FLOOR)
    monkeypatch.setattr(hw, "_OWNER", os.getuid() + 1)
    with pytest.raises(HighWaterRefused):
        read_high_water()


def test_symlinked_file_refused(state, tmp_path):
    (state / "activation").mkdir(mode=0o700)
    target = tmp_path / "elsewhere.json"
    target.write_bytes(encode_high_water(FLOOR))
    target.chmod(0o600)
    _file(state).symlink_to(target)
    with pytest.raises(HighWaterRefused):
        read_high_water()
    with pytest.raises(HighWaterRefused):
        _init(FLOOR)


def test_symlinked_leaf_directory_refused(state, tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (state / "activation").symlink_to(real)
    with pytest.raises(HighWaterRefused):
        read_high_water()
    with pytest.raises(HighWaterRefused):
        _init(FLOOR)
    assert not (real / "high-water.json").exists()


def test_hard_linked_file_refused(state, tmp_path):
    _init(FLOOR)
    os.link(_file(state), tmp_path / "second-name")
    with pytest.raises(HighWaterRefused):
        read_high_water()


def test_directory_in_place_of_file_refused(state):
    (state / "activation").mkdir(mode=0o700)
    _file(state).mkdir(mode=0o700)
    with pytest.raises(HighWaterRefused):
        read_high_water()


def test_file_replaced_between_stat_and_read_refused(state, monkeypatch, private_os):
    private_os(hw)
    _init(FLOOR)
    replacement = state / "activation" / "replacement"
    original = os.read

    def replacing(fd, size):
        data = original(fd, size)
        if data and not replacement.exists():
            replacement.write_bytes(encode_high_water(replace(FLOOR, security_epoch=0)))
            replacement.chmod(0o600)
            os.replace(replacement, _file(state))
        return data

    monkeypatch.setattr(hw.os, "read", replacing)
    with pytest.raises(HighWaterRefused):
        read_high_water()


def test_file_rewritten_in_place_while_reading_refused(state, monkeypatch, private_os):
    private_os(hw)
    _init(FLOOR)
    original = os.read
    done = False

    def rewriting(fd, size):
        nonlocal done
        data = original(fd, size)
        if data and not done:
            done = True
            with open(_file(state), "ab") as stream:
                stream.write(b" ")
        return data

    monkeypatch.setattr(hw.os, "read", rewriting)
    with pytest.raises(HighWaterRefused):
        read_high_water()


def test_concurrent_writer_is_refused_as_busy(state):
    _init(FLOOR)
    fd = os.open(state / "activation", os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(HighWaterRefused):
            _raise(replace(FLOOR, security_epoch=4))
        with pytest.raises(HighWaterRefused):
            read_high_water()
    finally:
        os.close(fd)
    assert read_high_water() == FLOOR


# -- crash safety --------------------------------------------------------------


def test_crash_before_rename_keeps_the_old_floor(state, monkeypatch, private_os):
    private_os(hw)
    _init(FLOOR)
    original = os.replace

    def crash(*args, **kwargs):
        raise OSError("power lost")

    monkeypatch.setattr(hw.os, "replace", crash)
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, security_epoch=4))
    monkeypatch.setattr(hw.os, "replace", original)
    assert (state / "activation" / ".high-water.json.partial").exists()
    assert read_high_water() == FLOOR
    assert _raise(replace(FLOOR, security_epoch=4)).security_epoch == 4
    assert not (state / "activation" / ".high-water.json.partial").exists()


def test_crash_during_write_keeps_the_old_floor(state, monkeypatch, private_os):
    private_os(hw)
    _init(FLOOR)
    original = os.write

    def partial(fd, data):
        original(fd, bytes(data[:5]))
        raise OSError("disk full")

    monkeypatch.setattr(hw.os, "write", partial)
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, approval_seq=11))
    assert _file(state).read_bytes() == encode_high_water(FLOOR)
    monkeypatch.setattr(hw.os, "write", original)
    assert read_high_water() == FLOOR


def test_crash_before_file_fsync_keeps_the_old_floor(state, monkeypatch, private_os):
    private_os(hw)
    _init(FLOOR)
    original = os.fsync
    calls = []

    def failing(fd):
        calls.append(fd)
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("io error")
        return original(fd)

    monkeypatch.setattr(hw.os, "fsync", failing)
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, generation=3))
    monkeypatch.setattr(hw.os, "fsync", original)
    assert read_high_water() == FLOOR


def test_directory_fsync_failure_after_rename_is_uncertain_not_success(state, monkeypatch, private_os):
    private_os(hw)
    _init(FLOOR)
    original = os.fsync

    def failing(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("io error")
        return original(fd)

    monkeypatch.setattr(hw.os, "fsync", failing)
    with pytest.raises(HighWaterCommitUncertain):
        _raise(replace(FLOOR, generation=3))
    monkeypatch.setattr(hw.os, "fsync", original)
    assert read_high_water() == replace(FLOOR, generation=3)


def test_write_syncs_file_then_directory_in_order(state, monkeypatch, private_os):
    private_os(hw)
    _init(FLOOR)
    original = os.fsync
    kinds = []

    def recording(fd):
        kinds.append("dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        return original(fd)

    monkeypatch.setattr(hw.os, "fsync", recording)
    _raise(replace(FLOOR, generation=5))
    assert kinds == ["file", "dir"]


def test_partial_entry_of_wrong_type_refused(state):
    _init(FLOOR)
    (state / "activation" / ".high-water.json.partial").mkdir()
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, generation=5))
    assert read_high_water() == FLOOR


# -- fixed path traversal --------------------------------------------------------


@pytest.fixture
def rooted(tmp_path, monkeypatch, private_os):
    private_os(hw)
    root = tmp_path / "root"
    state = root / "var/lib/azazel/state"
    state.mkdir(parents=True)
    for directory in (root, root / "var", root / "var/lib", root / "var/lib/azazel", state):
        directory.chmod(0o711)
    original = os.open

    def map_root(path, flags, *args, **kwargs):
        if path == "/" and "dir_fd" not in kwargs:
            path = root
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(hw.os, "open", map_root)
    monkeypatch.setattr(hw, "_OWNER", os.getuid())
    return root


def test_fixed_traversal_reads_and_writes_under_var_lib_azazel_state(rooted):
    assert read_high_water() is None
    _init(FLOOR)
    assert (rooted / "var/lib/azazel/state/activation/high-water.json").is_file()
    assert read_high_water() == FLOOR


def test_symlinked_path_component_refused(rooted, tmp_path):
    real = tmp_path / "real-azazel"
    os.rename(rooted / "var/lib/azazel", real)
    (rooted / "var/lib/azazel").symlink_to(real)
    with pytest.raises(HighWaterRefused):
        read_high_water()
    with pytest.raises(HighWaterRefused):
        _init(FLOOR)


def test_group_writable_path_component_refused(rooted):
    (rooted / "var/lib").chmod(0o775)
    with pytest.raises(HighWaterRefused):
        read_high_water()


def test_public_api_has_no_path_or_owner_override():
    import inspect

    for function in (read_high_water, activation_ledger_present, require_high_water_for_pass):
        assert list(inspect.signature(function).parameters) == []
    for function in (initialize_high_water, raise_high_water):
        assert list(inspect.signature(function).parameters) == ["value", "now", "skew_seconds"]


# -- upper bound and equal-value / concurrent cases ------------------------------


def test_raise_refuses_a_time_floor_beyond_now_plus_skew(state):
    _init(FLOOR)
    now = "2026-10-21T00:00:00Z"
    assert _raise(replace(FLOOR, time_floor="2026-10-21T00:02:00Z"), now=now).time_floor \
        == "2026-10-21T00:02:00Z"
    before = _file(state).read_bytes()
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, time_floor="2026-10-21T00:02:01Z"), now=now)
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, time_floor="2036-01-01T00:00:00Z"), now=now)
    assert _file(state).read_bytes() == before


def test_initialize_refuses_a_time_floor_beyond_now_plus_skew(state):
    with pytest.raises(HighWaterRefused):
        _init(FLOOR, now="2026-10-19T23:57:59Z")
    assert read_high_water() is None
    assert not (state / "activation").exists()
    _init(FLOOR, now="2026-10-19T23:58:00Z")
    assert read_high_water() == FLOOR


@pytest.mark.parametrize("now, skew", [
    (None, SKEW), ("2027-06-01 00:00:00", SKEW), ("2027-06-01T00:00:00.1Z", SKEW),
    (NOW, -1), (NOW, 301), (NOW, True), (NOW, 1.0), (NOW, None),
])
def test_clock_inputs_are_validated_before_touching_the_store(state, now, skew):
    with pytest.raises(HighWaterRefused):
        _init(FLOOR, now=now, skew=skew)
    assert not (state / "activation").exists()
    _init(FLOOR)
    with pytest.raises(HighWaterRefused):
        _raise(replace(FLOOR, generation=9), now=now, skew=skew)
    assert read_high_water() == FLOOR


def test_clock_and_skew_are_required_keywords(state):
    with pytest.raises(TypeError):
        raise_high_water(FLOOR)
    with pytest.raises(TypeError):
        initialize_high_water(FLOOR, NOW, SKEW)


def test_equal_value_raise_does_not_write(state, monkeypatch):
    _init(FLOOR)
    before = os.stat(_file(state))

    def forbidden(*args, **kwargs):
        raise AssertionError("an equal raise must not write")

    monkeypatch.setattr(hw, "_write_at", forbidden)
    assert _raise(FLOOR) == FLOOR
    after = os.stat(_file(state))
    assert (before.st_ino, before.st_mtime_ns, before.st_size) == (
        after.st_ino, after.st_mtime_ns, after.st_size)
    assert not (state / "activation" / ".high-water.json.partial").exists()


def test_concurrent_initialization_is_refused_as_busy(state):
    (state / "activation").mkdir(mode=0o700)
    fd = os.open(state / "activation", os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        with pytest.raises(HighWaterRefused) as error:
            _init(FLOOR)
        assert "busy" in str(error.value)
        assert not _file(state).exists()
    finally:
        os.close(fd)
    _init(FLOOR)
    with pytest.raises(HighWaterRefused):
        _init(replace(FLOOR, generation=7))
    assert read_high_water() == FLOOR
