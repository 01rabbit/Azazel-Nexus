from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from azazel_nexus_runtime.install_platform import CURRENT_INSTALL_PLATFORM_PROFILES

from tools.stage_runtime_entrypoints import declared_daemons, stage

ROOT = Path(__file__).resolve().parents[2]
LIBEXEC = Path(CURRENT_INSTALL_PLATFORM_PROFILES[0].libexec_directory.lstrip("/"))


def test_staged_set_is_derived_from_the_installed_units_and_runtime_scripts() -> None:
    daemons = declared_daemons()

    unit_names = set()
    for unit in (ROOT / "packaging" / "systemd").glob("*.service"):
        for line in unit.read_text(encoding="utf-8").splitlines():
            if line.startswith(("ExecStart=", "ExecStartPre=+")):
                # The verify unit (#196 G2) runs the helper's wrapper with
                # one fixed word: the wrapper is the helper's.
                value = line.split("=", 1)[1].removeprefix("+").split(" ")[0]
                unit_names.add(Path(value).name)

    # Edge Core's own binary, and the system's ip that the decoy namespace
    # unit runs from its unit file (#196 G4 follow-up): neither is staged.
    assert set(daemons) == unit_names - {"azazel-edge-core", "ip"}
    assert "azazel-edge-core" not in daemons and "ip" not in daemons
    assert "az-decoy-nsd" not in daemons
    assert "az-core-reserve-probe" not in daemons


_NSD_FIRST = "ExecStart=/usr/bin/ip netns add azazel-decoy\n"
_NSD_SECOND = ("ExecStart=/usr/bin/ip link add name az-decoy-host0 type veth peer name "
               "az-decoy-ns0 netns azazel-decoy\n")
_NSD_UNDO_1 = "ExecStopPost=-/usr/bin/ip link delete az-decoy-host0\n"
_NSD_UNDO_2 = "ExecStopPost=/usr/bin/ip netns delete azazel-decoy\n"


@pytest.mark.parametrize("change", [
    ("[Service]\n", "[Service]\nExecStart=/usr/bin/ip netns add other\n"),
    ("[Service]\n", "[Service]\nExecStart=/usr/libexec/azazel/az-decoy-nsd\n"),
    ("[Service]\n", "[Service]\nExecStart=/bin/sh -c true\n"),
    ("[Service]\n", "[Service]\nExecStartPre=/usr/bin/ip netns list\n"),
    ("[Service]\n", "[Service]\nExecStop=/usr/bin/ip netns delete azazel-decoy\n"),
    # Order, repetition and omission of the start lines.
    (_NSD_FIRST + _NSD_SECOND, _NSD_SECOND + _NSD_FIRST),
    (_NSD_FIRST, _NSD_FIRST + _NSD_FIRST),
    (_NSD_SECOND, ""),
    # The undo: dropped, reordered, its dash moved, or another added.
    (_NSD_UNDO_2, ""),
    (_NSD_UNDO_1 + _NSD_UNDO_2, _NSD_UNDO_2 + _NSD_UNDO_1),
    (_NSD_UNDO_2, "ExecStopPost=-/usr/bin/ip netns delete azazel-decoy\n"),
    (_NSD_UNDO_2, _NSD_UNDO_2 + "ExecStopPost=/usr/bin/ip link delete eth0\n"),
], ids=["other-ns", "wrapper", "shell", "start-pre", "exec-stop", "reordered",
        "repeated", "missing", "undo-missing", "undo-reordered", "undo-dash",
        "undo-extra"])
def test_the_namespace_units_lines_must_be_its_fixed_ip_commands(tmp_path, change):
    """#196 G4 follow-up: nothing is staged for it, and nothing else may run there."""

    root = tmp_path / "root"
    shutil.copytree(ROOT / "packaging" / "systemd", root / "packaging" / "systemd")
    (root / "runtime").mkdir()
    shutil.copy(ROOT / "runtime" / "pyproject.toml", root / "runtime" / "pyproject.toml")
    shutil.copytree(ROOT / "runtime" / "src", root / "runtime" / "src",
                    ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
    assert declared_daemons(root) == declared_daemons()
    unit = root / "packaging" / "systemd" / "azazel-decoy-nsd.service"
    text = unit.read_text(encoding="utf-8")
    old, new = change
    assert text.count(old) == 1
    unit.write_text(text.replace(old, new, 1), encoding="utf-8")
    with pytest.raises(ValueError, match="fixed ip commands"):
        declared_daemons(root)


def test_stager_refuses_an_unregistered_platform_profile_before_writing(tmp_path, monkeypatch):
    from tools import stage_runtime_entrypoints as staging

    monkeypatch.setattr(staging, "_check_runtime_imports", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(staging, "_discover_import_paths", lambda *_args: ())
    destination = tmp_path / "image-root"
    with pytest.raises(ValueError, match="unknown reviewed install platform"):
        stage(Path(sys.executable), destdir=destination, profile_id="unreviewed-v1")
    assert not destination.exists()


def test_stages_executable_wrappers_under_the_fixed_libexec_path(
    tmp_path: Path, monkeypatch,
) -> None:
    # Wrapper publication test only; installed-environment isolation has its own
    # subprocess tests and must not depend on this test runner's PYTHONPATH.
    from tools import stage_runtime_entrypoints as staging
    monkeypatch.setattr(staging, "_check_runtime_imports", lambda *_args, **_kwargs: None)
    import_dir = tmp_path / "runtime-site-packages"
    import_dir.mkdir()
    import_paths = (os.fspath(import_dir),)
    discoveries = []
    checks = []

    def discover(*_args):
        discoveries.append(True)
        return import_paths

    def check(*_args, **kwargs):
        checks.append(kwargs["import_paths"])

    monkeypatch.setattr(staging, "_discover_import_paths", discover)
    monkeypatch.setattr(staging, "_check_runtime_imports", check)
    destdir = tmp_path / "image-root"
    staged = stage(Path(sys.executable), destdir=destdir)
    directory = destdir / LIBEXEC

    assert {path.name for path in staged} == set(declared_daemons())
    assert {path.name for path in directory.iterdir()} == set(declared_daemons())
    assert discoveries == [True]
    assert checks == [import_paths]
    for path in staged:
        assert stat.S_IMODE(path.stat().st_mode) == 0o755
        assert not path.is_symlink()
        text = path.read_text(encoding="utf-8")
        assert text.startswith(f"#!{sys.executable} -IS\n")
        assert os.fspath(Path(sys.executable)) in text
        assert repr(list(import_paths)) in text
        assert "\nfrom azazel_nexus_runtime." in text
        assert "#!/bin/sh" not in text
        assert "raise SystemExit(" in text


@pytest.mark.parametrize("interpreter", [
    "python3", "/usr//bin/python3", "/usr/../bin/python3", "/usr/./bin/python3",
    "/opt/two words/python", "/opt/tab\tpython", "/opt/new\npython",
    "/opt/null\x00python", "/opt/非ascii/python", "/" + "p" * 128,
])
def test_direct_wrapper_refuses_ambiguous_interpreter(interpreter):
    from tools import stage_runtime_entrypoints as staging

    with pytest.raises(ValueError):
        staging._wrapper(interpreter, "azazel_nexus_runtime.auditd:main")


@pytest.mark.parametrize("target", [
    "bad;code:main", "valid.module:main()", "valid..module:main",
    "valid.module:main:other", "valid.module:",
    "valid.class:main", "valid.module:class",
])
def test_direct_wrapper_refuses_non_identifier_target(target):
    from tools import stage_runtime_entrypoints as staging

    with pytest.raises(ValueError):
        staging._wrapper("/usr/bin/python3", target)


def test_staging_rejects_unsafe_shebang_before_imports_or_writes(tmp_path, monkeypatch):
    from tools import stage_runtime_entrypoints as staging

    interpreter = tmp_path / "two words"
    interpreter.write_bytes(b"unused")
    interpreter.chmod(0o755)
    destination = tmp_path / "image-root"
    calls = []
    monkeypatch.setattr(staging, "_check_runtime_imports", lambda *a, **kw: calls.append(a))
    monkeypatch.setattr(staging, "_discover_import_paths", lambda *_args: ())
    with pytest.raises(ValueError):
        stage(interpreter, destdir=destination)
    assert not calls
    assert not destination.exists()


def test_non_absolute_or_missing_interpreter_fails_before_writing(
    tmp_path: Path, tmp_path_factory,
) -> None:
    destdir = tmp_path / "image-root"
    with pytest.raises(ValueError, match="absolute executable"):
        stage(Path("python3"), destdir=destdir)
    with pytest.raises(ValueError, match="absolute executable"):
        stage(tmp_path_factory.mktemp("p") / "missing", destdir=destdir)
    assert not destdir.exists()


def test_existing_symlink_entrypoint_is_refused_before_any_replacement(
    tmp_path: Path,
) -> None:
    destdir = tmp_path / "image-root"
    directory = destdir / LIBEXEC
    directory.mkdir(parents=True)
    link = directory / "az-activated"
    link.symlink_to(tmp_path / "outside")

    with pytest.raises(ValueError, match="symlink"):
        stage(Path(sys.executable), destdir=destdir)

    assert link.is_symlink()
    assert list(directory.iterdir()) == [link]


def test_malformed_runtime_module_path_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / "runtime").mkdir(parents=True)
    (root / "runtime" / "pyproject.toml").write_text(
        '[project.scripts]\n"az-testd" = "azazel_nexus_runtime..outside:main"\n',
        encoding="utf-8",
    )
    unit_dir = root / "packaging" / "systemd"
    unit_dir.mkdir(parents=True)
    (unit_dir / "az-testd.service").write_text(
        "[Service]\nExecStart=/usr/libexec/azazel/az-testd\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="invalid runtime entrypoint"):
        declared_daemons(root)


def test_staging_requires_yaml_dependency_before_writing(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from tools import stage_runtime_entrypoints as staging

    import_paths = staging._discover_import_paths(Path(sys.executable))

    def run(command, **kwargs):
        assert command[1:3] == ["-IS", "-c"]
        code = command[3]
        assert "'yaml'" in code
        assert "'dbus_next'" in code
        return SimpleNamespace(returncode=1, stderr="required runtime module yaml is missing", stdout="")
    monkeypatch.setattr(staging.subprocess, "run", run)
    monkeypatch.setattr(staging, "_discover_import_paths", lambda *_args: import_paths)
    destination = tmp_path / "image-root"
    with pytest.raises(ValueError):
        staging.stage(Path(sys.executable), destdir=destination)
    assert not destination.exists()


@pytest.mark.parametrize("problem", ["broken-import", "wrong-version"])
def test_staging_refuses_broken_or_wrong_yaml(tmp_path, monkeypatch, problem):
    import importlib
    import importlib.metadata
    from types import SimpleNamespace

    from tools import stage_runtime_entrypoints as staging

    original_import = importlib.import_module
    original_version = importlib.metadata.version
    import_paths = staging._discover_import_paths(Path(sys.executable))
    def importing(name):
        if name == "yaml" and problem == "broken-import":
            raise ImportError("broken YAML")
        return original_import(name)
    def version(name):
        return "0.0.0" if name == "PyYAML" and problem == "wrong-version" else original_version(name)
    monkeypatch.setattr(importlib, "import_module", importing)
    monkeypatch.setattr(importlib.metadata, "version", version)
    def run(command, **kwargs):
        original_sys_path = sys.path
        original_sys_path_contents = original_sys_path.copy()
        original_dont_write_bytecode = sys.dont_write_bytecode
        try:
            assert command[1:3] == ["-IS", "-c"]
            exec(command[3], {})
        except (ImportError, RuntimeError) as error:
            return SimpleNamespace(returncode=1, stderr=type(error).__name__, stdout="")
        finally:
            sys.path = original_sys_path
            sys.path[:] = original_sys_path_contents
            sys.dont_write_bytecode = original_dont_write_bytecode
        pytest.fail("invalid dependency accepted")
    monkeypatch.setattr(staging.subprocess, "run", run)
    monkeypatch.setattr(staging, "_discover_import_paths", lambda *_args: import_paths)
    destination = tmp_path / "image-root"
    with pytest.raises(ValueError):
        staging.stage(Path(sys.executable), destdir=destination)
    assert not destination.exists()


def test_discovery_probe_preserves_first_occurrence_and_deduplicates_paths(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from tools import stage_runtime_entrypoints as staging

    first = os.fspath(tmp_path.resolve())
    second_dir = tmp_path / "second"
    second_dir.mkdir()
    second = os.fspath(second_dir.resolve())
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        assert command[1:3] == ["-IS", "-c"]
        assert kwargs["env"] == {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        }
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"paths": [first, second, first]}),
            stderr="",
        )

    monkeypatch.setattr(staging.subprocess, "run", run)
    assert staging._discover_import_paths(Path(sys.executable)) == (first, second)
    assert len(calls) == 1
    assert calls[0][1]["cwd"] == "/"
    assert calls[0][1]["capture_output"] is True
    assert calls[0][1]["text"] is True


@pytest.mark.parametrize("stdout", [
    "not-json",
    json.dumps({"paths": [], "extra": 1}),
    json.dumps({"paths": "not-a-list"}),
    json.dumps({"paths": ["relative/path"]}),
    json.dumps({"paths": [42]}),
    json.dumps({"paths": ["/path/that/does/not/exist/azazel-test"]}),
    json.dumps({"paths": ["/" + "p" * 4096]}),
    json.dumps({"paths": ["/"] * 17}),
    " " * 65537,
])
def test_discovery_probe_rejects_malformed_or_overbound_output(monkeypatch, stdout):
    from types import SimpleNamespace

    from tools import stage_runtime_entrypoints as staging

    monkeypatch.setattr(
        staging.subprocess, "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=stdout, stderr=""),
    )
    with pytest.raises(ValueError):
        staging._discover_import_paths(Path(sys.executable))


def test_wrapper_renders_explicit_isolated_import_paths(tmp_path):
    from tools import stage_runtime_entrypoints as staging

    first = tmp_path / "site-packages"
    second = tmp_path / "vendor"
    first.mkdir()
    second.mkdir()
    rendered = staging._wrapper(
        "/usr/bin/python3", "azazel_nexus_runtime.auditd:main",
        import_paths=(os.fspath(first), os.fspath(second)),
    ).decode("utf-8")
    assert rendered.startswith("#!/usr/bin/python3 -IS\n")
    assert "sys.path" in rendered
    assert repr([os.fspath(first), os.fspath(second)]) in rendered


def test_import_check_uses_same_isolated_mode_and_explicit_paths(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from tools import stage_runtime_entrypoints as staging

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "pyproject.toml").write_text(
        '[project]\ndependencies = []\n', encoding="utf-8",
    )
    import_dir = tmp_path / "site-packages"
    import_dir.mkdir()
    paths = (os.fspath(import_dir),)
    observed = []

    def run(command, **kwargs):
        observed.append((command, kwargs))
        assert kwargs["env"] == {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        }
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(staging.subprocess, "run", run)
    staging._check_runtime_imports(
        Path(sys.executable), {"az-testd": "azazel_nexus_runtime.testd:main"},
        root=tmp_path, import_paths=paths,
    )
    assert observed[0][0][1:3] == ["-IS", "-c"]
    assert repr(list(paths)) in observed[0][0][3]


def test_installer_selected_python_preflight_profile_and_stager_are_isolated():
    installer = (ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")
    assert "python_fixed()" in installer
    assert "python_stager()" in installer
    assert '/usr/bin/env -i PATH="$STAGING_PATH" LANG=C.UTF-8 LC_ALL=C.UTF-8 "$PYTHON" "$@"' in installer
    assert 'DESTDIR="$DESTDIR" "$PYTHON" "$@"' in installer
    assert "if ! python_fixed -IS -c" in installer
    assert 'python_fixed --version' in installer
    assert 'python_fixed -IS "$PROFILE_FIELDS"' in installer
    assert 'python_stager -IS "$STAGER"' in installer


def test_copied_installer_clears_python_environment_and_retains_destdir_for_stager(
    tmp_path,
):
    root = tmp_path / "copied"
    shutil.copytree(ROOT / "packaging", root / "packaging")
    tools = root / "tools"
    tools.mkdir()
    profile_fields = tools / "install_profile_fields.py"
    profile_fields.write_text(
        "import sys\n"
        "field = sys.argv[sys.argv.index('--field') + 1]\n"
        "values = {\n"
        " 'profile_id': 'debian-13-systemd-installer-v1',\n"
        " 'unit_directory': '/usr/lib/systemd/system',\n"
        " 'preset_directory': '/usr/lib/systemd/system-preset',\n"
        " 'libexec_directory': '/usr/libexec/azazel',\n"
        " 'service_manager': 'systemd', 'required_tools': '',\n"
        " 'platform': 'amd64 deployment-baseline',\n"
        "}\nprint(values[field])\n",
        encoding="utf-8",
    )
    shutil.copy(ROOT / "tools/provision_mission_read.py", tools)
    shutil.copy(ROOT / "tools/purge_mio_profile_copies.py", tools)
    # #196 G3: the decoy wrapper check reads runtime/pyproject.toml and
    # imports the runtime; without the service manager it only warns.
    shutil.copy(ROOT / "tools/check_decoy_apparmor_wrappers.py", tools)
    shutil.copytree(ROOT / "runtime", root / "runtime",
                    ignore=shutil.ignore_patterns("__pycache__", "*.egg-info", "build"))
    shutil.copytree(ROOT / "src", root / "src")
    destdir = tmp_path / "image"
    env_report = destdir / "stager-environment.json"
    entrypoints = (
        "az-activated", "az-commissiond", "az-auditd", "az-auditd-loop", "az-watchdog",
        "az-edge-probed", "az-edge-intaked", "az-incident-explaind", "az-model-fetchd", "az-mio-locald", "az-mio-identity", "az-mio-remoted",
        "az-mio-entryd", "az-mio-referenced", "az-knowledge-lited", "az-decoy-netd", "az-decoyd",
        "az-units-observe", "az-noc-observe", "az-ui",
    )
    stager = tools / "stage_runtime_entrypoints.py"
    stager.write_text(
        "import json, os\nfrom pathlib import Path\n"
        f"Path({str(destdir)!r}).mkdir(parents=True, exist_ok=True)\n"
        f"Path({str(env_report)!r}).write_text(json.dumps(dict(os.environ)), encoding='utf-8')\n"
        "destination = Path(os.environ['DESTDIR']) / 'usr/libexec/azazel'\n"
        "destination.mkdir(parents=True, exist_ok=True)\n"
        f"for name in {entrypoints!r}:\n"
        " target = destination / name\n"
        " target.write_text('#!/bin/sh\\nexit 0\\n', encoding='ascii')\n"
        " target.chmod(0o755)\n",
        encoding="utf-8",
    )

    proxy = tmp_path / "selected-python"
    log = tmp_path / "python-child-env.log"
    proxy.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"with open({str(log)!r}, 'a', encoding='utf-8') as stream:\n"
        "    stream.write(json.dumps({'args': sys.argv[1:], 'env': dict(os.environ)}) + '\\n')\n"
        "os.execv(sys.executable, [sys.executable, *sys.argv[1:]])\n",
        encoding="utf-8",
    )
    proxy.chmod(0o755)
    poison = tmp_path / "poison"
    poison.mkdir()
    result = subprocess.run(
        ["sh", str(root / "packaging" / "install.sh"),
         "--without-accounts", "--without-service-manager"],
        env={
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHON": str(proxy),
            "DESTDIR": str(destdir),
            "PYTHONPATH": str(poison),
            "PYTHONHOME": str(poison),
            "PYTHONUSERBASE": str(poison),
            "__PYVENV_LAUNCHER__": str(poison),
            "GLIBC_TUNABLES": "glibc.malloc.check=3",
            "LD_LIBRARY_PATH": str(poison),
            "LANG": "en_US.UTF-8", "LC_ALL": "C",
        },
        capture_output=True, text=True, timeout=60,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "SERVICE-MANAGER STAGE NOT EXECUTED" in result.stdout
    stager_env = json.loads(env_report.read_text(encoding="utf-8"))
    system_extra = {"__CF_USER_TEXT_ENCODING"} if sys.platform == "darwin" else set()
    assert set(stager_env) <= {"PATH", "LANG", "LC_ALL", "DESTDIR", *system_extra}
    assert stager_env["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
    assert stager_env["LANG"] == stager_env["LC_ALL"] == "C.UTF-8"
    assert stager_env["DESTDIR"] == str(destdir)
    invocations = [
        json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()
    ]
    assert len(invocations) >= 8
    staged = False
    for invocation in invocations:
        child_env = invocation["env"]
        system_extra = {"__CF_USER_TEXT_ENCODING"} if sys.platform == "darwin" else set()
        assert set(child_env) <= {
            "PATH", "LANG", "LC_ALL", "DESTDIR", *system_extra,
        }
        assert child_env["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"
        assert child_env["LANG"] == child_env["LC_ALL"] == "C.UTF-8"
        if any(Path(argument).name == "stage_runtime_entrypoints.py"
               for argument in invocation["args"]):
            staged = True
            assert child_env.get("DESTDIR") == str(destdir)
        elif any(Path(argument).name == "provision_mission_read.py"
                 for argument in invocation["args"]):
            assert child_env.get("DESTDIR") == str(destdir)
        else:
            assert "DESTDIR" not in child_env
    assert staged
    assert all((destdir / "usr/libexec/azazel" / name).is_file() for name in entrypoints)


@pytest.mark.parametrize("name,accepted", [("vendor.zip", True), ("vendor.data", False)])
def test_stager_and_admission_agree_on_regular_file_import_path_shape(
    tmp_path, name, accepted,
):
    from tools import stage_runtime_entrypoints as staging

    selected = tmp_path / name
    selected.write_bytes(b"synthetic; imports are validated separately")
    if accepted:
        assert staging._validated_import_paths((str(selected),)) == (str(selected),)
    else:
        with pytest.raises(ValueError):
            staging._validated_import_paths((str(selected),))


def test_new_daemon_entrypoints_import_in_isolated_staging_check():
    from tools import stage_runtime_entrypoints as staging

    daemons = declared_daemons()
    targets = {
        "az-mio-entryd": "azazel_nexus_runtime.mio_entryd:main",
        "az-mio-referenced": "azazel_nexus_runtime.mio_referenced:main",
        "az-edge-intaked": "azazel_nexus_runtime.edge_intaked:main",
        "az-incident-explaind": "azazel_nexus_runtime.incident_explaind:main",
        "az-knowledge-lited": "azazel_nexus_runtime.knowledge_lited:main",
    }
    assert {name: daemons[name] for name in targets} == targets
    # Explicit candidate roots, as with an installed environment. The child
    # disables site startup and cannot inherit this runner's PYTHONPATH.
    paths = tuple(dict.fromkeys(
        str(Path(path).resolve()) for path in sys.path if path and Path(path).exists()
    ))
    staging._check_runtime_imports(Path(sys.executable), targets, import_paths=paths)


@pytest.mark.parametrize("directive", [
    "ExecStart=/tmp/azazel-edge-core",
    "ExecStart=/opt/azazel/edge-core/bin/azazel-edge-core --health",
    "ExecStartPre=+/opt/azazel/edge-core/bin/azazel-edge-core",
])
def test_edge_package_unit_cannot_supply_another_staging_command(tmp_path, directive):
    """The external package exception is one fixed unit and command pair."""
    (tmp_path / "runtime").mkdir()
    (tmp_path / "runtime/pyproject.toml").write_text("[project.scripts]\n")
    units = tmp_path / "packaging/systemd"
    units.mkdir(parents=True)
    (units / "azazel-edge-core.service").write_text("[Service]\n" + directive + "\n")
    with pytest.raises(ValueError):
        declared_daemons(tmp_path)
