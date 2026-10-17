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


@pytest.fixture
def syscall_host(monkeypatch):
    # Representative systemd-analyze output: headers, comments, nested groups,
    # and names from other ABIs (the real commands are never executed).
    definitions = {group: f"{group}\n# dangerous\n{group[1:].replace('-', '_')}_call\n"
                   for group in smoke.DANGEROUS_SYSCALL_GROUPS}
    definitions.update({
        "@system-service": "@system-service\n# service calls\n  @default\n  read\n  write\n  _llseek\n",
        "@default": "@default\n# baseline\n  exit\n",
        "@known": "@known\n@system-service\nextra\n" + "\n".join(smoke.DANGEROUS_SYSCALL_GROUPS),
    })
    calls = []

    def run(argv):
        assert argv[:3] == ["systemd-analyze", "syscall-filter", "--no-pager"]
        calls.append(argv[-1])
        return definitions[argv[-1]]

    monkeypatch.setattr(smoke, "run", run)
    monkeypatch.setattr(smoke, "native_unknown_syscalls", lambda names: names & {"_llseek"})
    return definitions, calls


def syscall_compare(values, shown):
    evidence = {}
    mismatches = smoke.compare_properties([("SystemCallFilter", value) for value in values],
                                         {"SystemCallFilter": shown}, evidence=evidence)
    return mismatches, evidence["system_call_filter"]


def test_systemd_syscall_group_expansion_and_set_order(syscall_host):
    mismatches, detail = syscall_compare(["@system-service"], "write exit read write")
    assert mismatches == []
    assert detail["expanded_count"] == 4 and detail["observed_count"] == 3
    assert detail["omitted_native_unknown"] == ["_llseek"]
    assert detail["missing_native"] == []
    assert set(smoke.DANGEROUS_SYSCALL_GROUPS) <= set(syscall_host[1])
    assert syscall_host[1].count("@default") == 1


@pytest.mark.parametrize("shown,label,names", [
    ("read exit", "missing_native", ["write"]),
    ("read write exit extra", "unexpected", ["extra"]),
    ("read write exit mount_call", "dangerous", ["mount_call"]),
    ("", "missing_native", ["exit", "read", "write"]),
])
def test_syscall_differences_fail_with_evidence(syscall_host, shown, label, names):
    mismatches, detail = syscall_compare(["@system-service"], shown)
    assert mismatches == ["SystemCallFilter"]
    assert detail[label] == names
    assert not detail["ok"]


@pytest.mark.parametrize("group", smoke.DANGEROUS_SYSCALL_GROUPS)
def test_dangerous_names_are_judged_against_the_declared_filter(syscall_host, group):
    """The smoke verifies enforcement of the declared filter, not its policy.

    A dangerous member the unit declares (explicitly, by group, or through a
    nested group such as @system-service's own @chown) is the unit's stated
    policy: it is reported as declared_dangerous and passes. One the unit did
    not declare is enforcement drift and fails.
    """
    name = group[1:].replace("-", "_") + "_call"
    shown = "read write exit " + name
    assert syscall_compare(["@system-service"], shown)[0] == ["SystemCallFilter"]
    assert syscall_compare(["@system-service " + name], shown)[0] == []
    assert syscall_compare(["@system-service " + group], shown)[0] == []
    syscall_host[0]["@system-service"] += group + "\n"
    assert syscall_compare(["@system-service"], shown)[0] == []


def test_syscall_group_permission_handles_overlaps(syscall_host):
    syscall_host[0]["@privileged"] += "@mount\n"
    assert syscall_compare(["@system-service @mount"], "read write exit mount_call")[0] == []


def test_syscall_ordered_denials_explicit_names_and_resets(syscall_host):
    assert syscall_compare(["@system-service", "~write"], "read exit")[0] == []
    assert syscall_compare(["@system-service", "~write", "write"], "read write exit")[0] == []
    assert syscall_compare(["@mount", "", "@system-service"], "read write exit")[0] == []
    # The reset drops @mount; mount_call is then declared explicitly, so allowed.
    assert syscall_compare(["@mount", "", "@system-service mount_call"],
                           "read write exit mount_call")[0] == []
    # Observed but no longer declared after the reset: drift.
    assert syscall_compare(["@mount", "", "@system-service"],
                           "read write exit mount_call")[0] == ["SystemCallFilter"]
    assert syscall_compare(["read write"], "read write exit")[0] == []  # implicit @default


def test_syscall_deny_lists_use_known_universe(syscall_host):
    denied = "~" + " ".join(smoke.DANGEROUS_SYSCALL_GROUPS)
    assert syscall_compare([denied], "read write exit extra")[0] == []
    assert syscall_compare([denied], denied)[0] == []
    assert syscall_compare([denied, "~extra"], "read write exit")[0] == []
    assert syscall_compare(["~@system-service"], "read write exit")[0] == ["SystemCallFilter"]
    assert syscall_compare([""], "")[0] == ["SystemCallFilter"]
    assert syscall_compare(["@system-service"], "~@mount")[0] == ["SystemCallFilter"]


@pytest.mark.parametrize("output", ["", "@system-service\n", "read write\n", "~read\n",
                                   "read:EPERM\n", "@system-service\n@loop\n"])
def test_bad_group_expansions_refused(syscall_host, output):
    syscall_host[0]["@system-service"] = output
    syscall_host[0]["@loop"] = "@loop\n@system-service\n"
    with pytest.raises(ValueError):
        syscall_compare(["@system-service"], "read")


@pytest.mark.parametrize("error", [FileNotFoundError, smoke.subprocess.CalledProcessError])
def test_syscall_expander_unavailable_refuses(monkeypatch, error):
    def fail(argv):
        if error is FileNotFoundError:
            raise error("unavailable")
        raise error(1, argv)

    monkeypatch.setattr(smoke, "run", fail)
    with pytest.raises(error):
        syscall_compare(["@system-service"], "read")


def test_native_resolver_uses_host_libseccomp_without_installing_filter(monkeypatch):
    calls = []

    def resolve(name):
        calls.append(name)
        return {b"read": 63, b"_llseek": -10009, b"unknown": -1}[name]

    def library(name):
        assert name == "libseccomp.so.2"
        return SimpleNamespace(seccomp_syscall_resolve_name=resolve)

    monkeypatch.setattr(smoke.ctypes, "CDLL", library)
    assert smoke.native_unknown_syscalls({"read", "_llseek", "unknown"}) == {"_llseek", "unknown"}
    assert set(calls) == {b"read", b"_llseek", b"unknown"}
    assert resolve.restype is smoke.ctypes.c_int


def test_native_resolver_unavailable_refuses(monkeypatch):
    def fail(name):
        raise OSError("unavailable")

    monkeypatch.setattr(smoke.ctypes, "CDLL", fail)
    with pytest.raises(OSError):
        smoke.native_unknown_syscalls({"read"})


def test_syscall_evidence_difference_names_are_bounded(syscall_host):
    names = {f"extra_{i}" for i in range(100)}
    _, detail = syscall_compare(["@system-service"], "read write exit " + " ".join(names))
    assert detail["unexpected_count"] == 100
    assert len(detail["unexpected"]) == smoke.SYSCALL_DIFFERENCE_LIMIT
    assert detail["unexpected"] == sorted(names)[:smoke.SYSCALL_DIFFERENCE_LIMIT]


def test_syscall_special_comparison_does_not_weaken_other_properties(syscall_host):
    props = [("SystemCallFilter", "@system-service"), ("ProtectSystem", "strict"),
             ("CapabilityBoundingSet", "")]
    assert smoke.compare_properties(props, {"SystemCallFilter": "read write exit",
                                           "ProtectSystem": "full", "CapabilityBoundingSet": "cap_chown"}) == [
        "ProtectSystem", "CapabilityBoundingSet"]


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
