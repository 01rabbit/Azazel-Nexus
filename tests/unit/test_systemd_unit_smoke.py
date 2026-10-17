"""Pure tests and mocked manager lifecycle; never invoke a service manager."""

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools import systemd_unit_smoke as smoke

ROOT = Path(__file__).resolve().parents[2]
NAME = "azazel-mio-entryd"


def source(name=NAME):
    return (ROOT / "packaging/systemd" / (name + ".service")).read_text()


@pytest.mark.parametrize("name", smoke.UNITS)
def test_every_other_installed_directive_is_carried_verbatim(name):
    props = smoke.parse_service(source(name))
    relocated = smoke.relocate(props, Path("/run/azsm-test"), name)
    command = smoke.build_command(name, relocated)
    assert command[:4] == ["systemd-run", "--unit=azazel-smoke-" + name, "--no-block", "--collect"]
    for key, value in props:
        if key not in {"ExecStart", "RuntimeDirectory", "ReadWritePaths", "ReadOnlyPaths", "Type"}:
            assert f"--property={key}={value}" in command
    assert "--property=CapabilityBoundingSet=" in command
    assert "--property=RuntimeDirectory=azazel-smoke-" + name in command
    assert "--property=RuntimeDirectory=azazel" not in command
    assert "--property=Environment=AZAZEL_ROOT=/run/azsm-test" in command
    assert "--property=Type=exec" in command
    assert command[-2:] == ["--", dict(props)["ExecStart"]]
    assert all("Requires=" not in word for word in command)


def test_occurrences_continuations_empty_resets_and_inverse_lists():
    props = smoke.parse_service('''[Unit]
Requires=real.service
[Service]
User=test
ExecStart=/bin/true
RestrictAddressFamilies=~AF_INET AF_INET6
RestrictAddressFamilies=~AF_NETLINK
ReadWritePaths=/old
ReadWritePaths=
ReadWritePaths=/one \\
 /two
ReadWritePaths=/three
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
''')
    command = smoke.build_command(NAME, props)
    assert [arg for arg in command if arg.startswith("--property=ReadWritePaths=")] == [
        "--property=ReadWritePaths=/old", "--property=ReadWritePaths=",
        "--property=ReadWritePaths=/one  /two", "--property=ReadWritePaths=/three"]
    assert "--property=RestrictAddressFamilies=~AF_INET AF_INET6" in command
    assert "--property=RestrictAddressFamilies=~AF_NETLINK" in command
    expected = smoke.expected_properties(props)
    assert expected["ReadWritePaths"] == "/one  /two /three"
    assert expected["RestrictAddressFamilies"] == "~AF_INET AF_INET6 AF_NETLINK"
    assert "Requires" not in expected and "WantedBy" not in expected


@pytest.mark.parametrize("extra", ["ExecStartPre=/bin/true", "ExecStartPost=", "ExecStop=/bin/true",
                                    "User=%u", "ReadOnlyPaths=/var/%n", "Environment=X=%%"])
def test_exec_hooks_and_all_value_specifiers_refused(extra):
    with pytest.raises(ValueError):
        smoke.parse_service("[Service]\nUser=x\nExecStart=/a\n" + extra)


@pytest.mark.parametrize("text", ["[Service]\nUser=x", "[Service]\nUser=x\nExecStart=/a\nExecStart=/b",
                                  "[Service]\nUser=x\nExecStart=/a\nBroken",
                                  "[Unit]\nDescription=%n\n[Service]\nUser=x\nExecStart=/a"])
def test_ambiguous_service_refused(text):
    with pytest.raises(ValueError):
        smoke.parse_service(text)


def test_command_has_literal_arguments():
    command = smoke.build_command(NAME, [("ExecStart", '/bin/echo "$(id)"'), ("User", "x")])
    assert command[-1] == "$(id)"
    with pytest.raises(ValueError):
        smoke.build_command(NAME, [("ExecStart", "/bin/%n"), ("User", "x")])


def test_path_relocation_flags_and_resets():
    props = smoke.parse_service(source() + "\n[Service]\nReadWritePaths=\n"
                                "ReadWritePaths=-+/var/lib/azazel/state/mio\n")
    relocated = smoke.relocate(props, Path("/run/azsm-test"), NAME)
    assert relocated[-3:] == [("ReadWritePaths", ""),
                             ("ReadWritePaths", "-+/run/azsm-test/var/lib/azazel/state/mio"),
                             ("Environment", "AZAZEL_ROOT=/run/azsm-test")]


@pytest.mark.parametrize("key,value", [("ReadWritePaths", "/etc"),
                                       ("ReadOnlyPaths", "/var/lib/azazel/../real"),
                                       ("EnvironmentFile", "/etc/real"),
                                       ("BindPaths", "/real:/scratch")])
def test_unreviewed_paths_refused(key, value):
    with pytest.raises(ValueError):
        smoke.relocate(smoke.parse_service(source()) + [(key, value)], Path("/run/azsm-test"), NAME)


@pytest.mark.parametrize("key,declared,shown", [
    ("CapabilityBoundingSet", "", ""),
    ("CapabilityBoundingSet", "CAP_CHOWN CAP_KILL", "cap_kill cap_chown"),
    ("RestrictAddressFamilies", "~AF_INET AF_INET6", "~AF_INET6 AF_INET"),
    ("ReadWritePaths", "/one/ /two", "/two /one"),
    ("ReadOnlyPaths", "-+/one/", "+-/one"),
    ("UMask", "0027", "0027"), ("RuntimeDirectoryMode", "0750", "750"),
    ("NoNewPrivileges", "yes", "true"), ("ProtectHome", "yes", "true"),
    ("IPAddressDeny", "any", "::/0 0.0.0.0/0"),
])
def test_show_normalisation(key, declared, shown):
    assert smoke.compare_properties([(key, declared)], {key: shown}) == []


@pytest.mark.parametrize("observed", [{}, {"CapabilityBoundingSet": "cap_chown"}])
def test_empty_capability_must_really_be_empty(observed):
    assert smoke.compare_properties([("CapabilityBoundingSet", "")], observed) == ["CapabilityBoundingSet"]


def test_inverse_and_path_flags_not_lost():
    for key, declared, shown in [("RestrictAddressFamilies", "~AF_INET", "AF_INET"),
                                  ("ReadWritePaths", "-/one", "/one")]:
        assert smoke.compare_properties([(key, declared)], {key: shown}) == [key]


def test_empty_reset_comparison_and_mixed_inverse_refusal():
    props = [("ReadWritePaths", "/old"), ("ReadWritePaths", ""), ("ReadWritePaths", "/new")]
    assert smoke.compare_properties(props, {"ReadWritePaths": "/new"}) == []
    with pytest.raises(ValueError):
        smoke.expected_properties([("RestrictAddressFamilies", "AF_UNIX"),
                                   ("RestrictAddressFamilies", "~AF_INET")])


@pytest.mark.parametrize("name", smoke.UNITS)
def test_scratch_uses_installer_owners_modes_and_ancestors(tmp_path, monkeypatch, name):
    changes = []
    monkeypatch.setattr(smoke.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid={"root": 0, "azmioentry": 77, "azknowledge": 78, "azcommission": 79}[name]))
    monkeypatch.setattr(smoke.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid={"root": 0, "azazel-operator": 88, "azknowledge": 89}[name]))
    monkeypatch.setattr(smoke.os, "chown", lambda path, uid, gid: changes.append((path.relative_to(tmp_path), uid, gid)))
    modes = []
    original_chmod = Path.chmod

    def chmod(path, mode):
        modes.append((path.relative_to(tmp_path), mode))
        original_chmod(path, mode & 0o777)  # macOS may clear setgid for the mocked owner/group

    monkeypatch.setattr(Path, "chmod", chmod)
    smoke.create_scratch_tree(tmp_path, smoke.parse_service(source(name)))
    assert (Path("var/lib"), 0o755) in modes
    if name == NAME:
        assert (Path("var/lib/azazel/run/mio-entry"), 0o2710) in modes
        assert (tmp_path / "var/lib/azazel/state/mio").stat().st_mode & 0o7777 == 0o700
        assert (Path("var/lib/azazel/state/mio"), 77, 0) in changes
        assert (Path("var/lib/azazel/run/mio-entry"), 77, 88) in changes
        assert not (tmp_path / "var/lib/azazel/state/knowledge").exists()
    else:
        assert (Path("var/lib/azazel/run/knowledge"), 0o2710) in modes
        assert (Path("var/lib/azazel/knowledge"), 0o2750) in modes
        assert (Path("var/lib/azazel/lite-trust"), 0o2750) in modes
        assert (Path("var/lib/azazel/state/knowledge"), 78, 0) in changes
        assert (Path("var/lib/azazel/run/knowledge"), 78, 88) in changes
        assert (Path("var/lib/azazel/knowledge"), 78, 88) in changes
        assert (Path("var/lib/azazel/lite-trust"), 79, 89) in changes
        assert not (tmp_path / "var/lib/azazel/state/mio").exists()


def test_bounded_replies():
    smoke.validate_reply(NAME, {"route": "deterministic handoff", "outcome": "refused",
                               "reason": "no provider", "ledger_seq": 1})
    smoke.validate_reply("azazel-knowledge-lited", {"state": "unavailable", "reason_code": "no_bundle",
                                                 "generation": None, "freshness": "absent"})
    with pytest.raises(ValueError):
        smoke.validate_reply("azazel-knowledge-lited", {"state": "available", "reason_code": "x" * 65,
                                                     "generation": None, "freshness": "absent"})


@pytest.fixture
def short_scratch():
    # Keep mocked daemon paths below the Linux limit even with a long basetemp.
    with tempfile.TemporaryDirectory(prefix="azE-", dir="/tmp") as directory:
        yield Path(directory)


@pytest.mark.parametrize("real_changed", [False, True])
def test_cleanup_preserves_primary_failure_and_reports_leftovers(tmp_path, short_scratch, monkeypatch, real_changed):
    import platform

    from azazel_nexus_runtime import startup_wrapper

    unit = tmp_path / "unit"
    unit.write_text(source())
    wrapper = tmp_path / "wrapper"
    wrapper.write_text("unused")
    unit.write_text(source().replace("/usr/libexec/azazel/az-mio-entryd", str(wrapper)))
    monkeypatch.setattr(smoke.os, "geteuid", lambda: 0)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("AZAZEL_ROOT", raising=False)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "freedesktop_os_release", lambda: {"ID": "debian", "VERSION_ID": "13"})
    monkeypatch.setattr(smoke, "installed_unit", lambda name: unit)
    monkeypatch.setattr(startup_wrapper, "parse_wrapper", lambda *a, **kw: ("python", ()))
    snapshots = iter(({"/real": {"inode": 7}},
                      {"/real": {"inode": 8 if real_changed else 7}}))
    monkeypatch.setattr(smoke, "snapshot_directories", lambda: next(snapshots))
    monkeypatch.setattr(smoke, "create_scratch_tree", lambda *a: None)
    monkeypatch.setattr(smoke.tempfile, "mkdtemp", lambda **kw: str(short_scratch))
    monkeypatch.setattr(smoke, "show", lambda unit, fields: {"LoadState": "loaded", "ActiveState": "inactive"})
    calls = []

    def run(argv):
        calls.append(argv)
        if argv[0] == "systemd-run":
            raise RuntimeError("original")
        raise OSError("cleanup")

    monkeypatch.setattr(smoke, "run", run)
    with pytest.raises(smoke.SmokeFailure) as caught:
        smoke.smoke(NAME)
    evidence = caught.value.evidence
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert evidence["error_type"] == "RuntimeError"
    assert evidence["cleanup_errors"] == ["stop:OSError", "reset-failed:OSError"] + (
        ["verify:real_paths_changed"] if real_changed else [])
    assert evidence["leftover_unit"] is True
    assert evidence["scratch_leftover"] == str(short_scratch)
    assert [call[1] for call in calls[1:]] == ["stop", "reset-failed"]
    assert evidence["real_units_after"] == evidence["real_units_before"]
    assert evidence["real_path_differences"] == ({"/real": ["inode"]} if real_changed else {})
    assert json.loads(json.dumps(evidence))["error_type"] == "RuntimeError"


def test_systemd_syscall_group_expansion_and_set_order(monkeypatch):
    definitions = {"@system-service": "# description\n@default\nread\nwrite\n",
                   "@default": "@default\n# baseline\nexit\n"}
    monkeypatch.setattr(smoke, "run", lambda argv: definitions[argv[-1]])
    props = [("SystemCallFilter", "@system-service")]
    observed = {"SystemCallFilter": "write exit read"}
    groups = smoke.expand_syscall_groups(props, observed)
    assert smoke.compare_properties(props, observed, groups) == []
    assert smoke.compare_properties(props, {"SystemCallFilter": "read exit"}, groups) == ["SystemCallFilter"]
    assert smoke.compare_properties([( "SystemCallFilter", "~@system-service")], observed, groups) == ["SystemCallFilter"]


def test_native_architecture_normalisation(monkeypatch):
    monkeypatch.setattr(smoke.platform, "machine", lambda: "x86_64")
    assert smoke.compare_properties([("SystemCallArchitectures", "native")],
                                    {"SystemCallArchitectures": "x86-64"}) == []


@pytest.mark.parametrize("name", smoke.UNITS)
def test_units_require_strict_before_start(name):
    props = smoke.parse_service(source(name))
    smoke.require_strict(props)
    for value in ("full", "yes", "no", ""):
        with pytest.raises(ValueError, match="ProtectSystem=strict"):
            smoke.require_strict(props + [("ProtectSystem", value)])
    with pytest.raises(ValueError):
        smoke.require_strict([])


def isolated_show(scratch):
    return {"ProtectSystem": "strict", "RuntimeDirectory": "azazel-smoke-test",
            "ReadWritePaths": f"-{scratch}/state +{scratch}/sockets /run/azazel-smoke-test"}


def test_effective_write_paths_allow_only_scratch_and_private_runtime(tmp_path):
    smoke.assert_write_isolation(isolated_show(tmp_path), tmp_path, Path("/run/azazel-smoke-test"))


@pytest.mark.parametrize("key,value", [
    ("ProtectSystem", "full"), ("ProtectSystem", ""),
    ("ReadWritePaths", "/var/lib/azazel/state/mio"),
    ("ReadWritePaths", "-/run/azazel"), ("ReadWritePaths", "/run"),
    ("ReadWritePaths", "relative"), ("ReadWritePaths", "/scratch/../real"),
    ("RuntimeDirectory", "azazel"), ("RuntimeDirectory", "azazel-smoke-test azazel"),
])
def test_effective_write_isolation_refuses_host_paths_and_weakened_protection(tmp_path, key, value):
    observed = isolated_show(tmp_path)
    observed[key] = value
    with pytest.raises(ValueError):
        smoke.assert_write_isolation(observed, tmp_path, Path("/run/azazel-smoke-test"))


def test_effective_write_paths_missing_or_symlink_escape_refused(tmp_path):
    observed = isolated_show(tmp_path)
    del observed["ReadWritePaths"]
    with pytest.raises(ValueError):
        smoke.assert_write_isolation(observed, tmp_path, Path("/run/azazel-smoke-test"))
    (tmp_path / "escape").symlink_to("/var/lib/azazel")
    observed["ReadWritePaths"] = str(tmp_path / "escape/state")
    with pytest.raises(ValueError):
        smoke.assert_write_isolation(observed, tmp_path, Path("/run/azazel-smoke-test"))


def test_snapshot_metadata_hash_bound_missing_roots_and_no_symlink_follow(tmp_path, monkeypatch):
    import hashlib
    import os
    import stat

    monkeypatch.setattr(smoke, "HASH_LIMIT", 4)
    small = tmp_path / "small"
    small.write_bytes(b"data")
    (tmp_path / "large").write_bytes(b"12345")
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    os.mkfifo(tmp_path / "fifo")
    missing = tmp_path / "missing"
    before = smoke.snapshot_directories((tmp_path, missing))
    assert before[str(missing)] is None
    record = before[str(small)]
    assert set(record) == {"path", "inode", "mode", "uid", "gid", "size", "mtime_ns", "sha256"}
    assert stat.S_ISREG(record["mode"])
    assert record["sha256"] == hashlib.sha256(b"data").hexdigest()
    assert "sha256" not in before[str(tmp_path / "large")]
    assert before[str(tmp_path / "link")]["symlink_target"] == str(tmp_path)
    assert smoke.snapshot_diff(before, smoke.snapshot_directories((tmp_path, missing))) == {}
    # Same length and restored mtime: content hashing still detects the change.
    small.write_bytes(b"edit")
    os.utime(small, ns=(small.stat().st_atime_ns, record["mtime_ns"]))
    after = smoke.snapshot_directories((tmp_path, missing))
    assert smoke.snapshot_diff(before, after)[str(small)] == ["sha256"]


def test_snapshot_diff_reports_added_removed_created_and_metadata(tmp_path):
    root = tmp_path / "root"
    before = smoke.snapshot_directories((root,))
    root.mkdir()
    file = root / "file"
    file.write_text("one")
    created = smoke.snapshot_directories((root,))
    diff = smoke.snapshot_diff(before, created)
    assert diff[str(root)] == ["created"]
    assert diff[str(file)] == ["added"]
    file.chmod(0o600)
    changed = smoke.snapshot_directories((root,))
    assert smoke.snapshot_diff(created, changed)[str(file)] == ["mode"]
    file.unlink()
    assert smoke.snapshot_diff(changed, smoke.snapshot_directories((root,)))[str(file)] == ["removed"]
