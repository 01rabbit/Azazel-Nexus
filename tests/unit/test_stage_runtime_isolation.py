"""Stager import checks and wrappers run in an isolated Python environment."""

import os
import json
from pathlib import Path
import subprocess
import sys
import venv

import pytest

from tools import stage_runtime_entrypoints as staging


@pytest.fixture
def isolated_env(tmp_path, tmp_path_factory):
    # Keep the synthetic interpreter within the portable shebang limit even
    # when the host's temporary root is long (for example on macOS).
    environment = tmp_path_factory.mktemp("v")
    venv.EnvBuilder(with_pip=False).create(environment)
    interpreter = environment / "bin" / "python"
    result = subprocess.run(
        [str(interpreter), "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
        check=True, capture_output=True, text=True,
    )
    site_packages = Path(result.stdout.strip())
    site_packages.mkdir(parents=True, exist_ok=True)
    root = tmp_path / "synthetic-repository"
    runtime = root / "runtime"
    runtime.mkdir(parents=True)
    (runtime / "pyproject.toml").write_text(
        '[project]\nname = "synthetic-runtime"\nversion = "0.0.1"\ndependencies = []\n',
        encoding="utf-8",
    )
    return interpreter, site_packages, root


def _check(interpreter, root):
    staging._check_runtime_imports(
        interpreter, {"synthetic-daemon": "synthetic_runtime_probe:main"}, root=root,
    )


def test_activation_staging_requires_native_backend_before_entrypoint_import(isolated_env):
    interpreter, site_packages, root = isolated_env
    package = site_packages / "azazel_nexus_runtime"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "bootstrap_kernel_deadline.py").write_text(
        "def _load_backend():\n"
        "    raise ImportError('synthetic native backend unavailable')\n",
        encoding="utf-8",
    )
    (package / "activated.py").write_text(
        "raise AssertionError('entrypoint imported before native check')\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="synthetic native backend unavailable"):
        staging._check_runtime_imports(
            interpreter, {"az-activated": "azazel_nexus_runtime.activated:main"}, root=root,
        )


def _install_site_startup_hooks(site_packages, marker):
    (site_packages / "synthetic-startup.pth").write_text(
        "import pathlib; pathlib.Path(" + repr(os.fspath(marker))
        + ").write_text('pth', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (site_packages / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        f"Path({os.fspath(marker)!r}).with_suffix('.sitecustomize').write_text('ran')\n",
        encoding="utf-8",
    )


def _assert_no_site_startup(marker):
    assert not marker.exists()
    assert not marker.with_suffix(".sitecustomize").exists()


def test_pythonpath_only_module_is_rejected_in_isolated_import_check(
    isolated_env, tmp_path, monkeypatch,
):
    interpreter, _site_packages, root = isolated_env
    poisoned = tmp_path / "pythonpath-only"
    poisoned.mkdir()
    (poisoned / "synthetic_runtime_probe.py").write_text(
        "def main():\n    return 0\n", encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", os.fspath(poisoned))

    with pytest.raises(ValueError, match="import check failed"):
        _check(interpreter, root)


def test_installed_synthetic_module_wins_over_poisoned_pythonpath(
    isolated_env, tmp_path, monkeypatch,
):
    interpreter, site_packages, root = isolated_env
    (site_packages / "synthetic_runtime_probe.py").write_text(
        "def main():\n    return 0\n", encoding="utf-8",
    )
    poisoned = tmp_path / "poisoned-path"
    poisoned.mkdir()
    (poisoned / "synthetic_runtime_probe.py").write_text(
        "raise RuntimeError('PYTHONPATH module was imported')\n", encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", os.fspath(poisoned))

    _check(interpreter, root)


def test_path_discovery_and_import_check_skip_pth_and_sitecustomize(
    isolated_env, tmp_path,
):
    interpreter, site_packages, root = isolated_env
    (site_packages / "synthetic_runtime_probe.py").write_text(
        "def main():\n    return 0\n", encoding="utf-8",
    )
    marker = tmp_path / "site-startup-marker"
    _install_site_startup_hooks(site_packages, marker)

    import_paths = staging._discover_import_paths(interpreter)
    staging._check_runtime_imports(
        interpreter, {"synthetic-daemon": "synthetic_runtime_probe:main"},
        root=root, import_paths=import_paths,
    )

    _assert_no_site_startup(marker)


def test_generated_wrapper_skips_site_startup_and_preserves_arguments(
    isolated_env, tmp_path, monkeypatch,
):
    interpreter, site_packages, _root = isolated_env
    (site_packages / "synthetic_wrapper_probe.py").write_text(
        "import sys\n"
        "def main():\n"
        "    print('synthetic-wrapper-ok:' + '|'.join(sys.argv[1:]))\n"
        "    return 0\n",
        encoding="utf-8",
    )
    marker = tmp_path / "wrapper-site-startup-marker"
    _install_site_startup_hooks(site_packages, marker)
    (tmp_path / "synthetic_wrapper_probe.py").write_text(
        "raise RuntimeError('CWD module imported')\n", encoding="utf-8",
    )
    poisoned = tmp_path / "pythonpath-poison"
    poisoned.mkdir()
    (poisoned / "synthetic_wrapper_probe.py").write_text(
        "raise RuntimeError('PYTHONPATH module imported')\n", encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", os.fspath(poisoned))
    import_paths = staging._discover_import_paths(interpreter)
    wrapper = tmp_path / "synthetic-wrapper"
    wrapper.write_bytes(staging._wrapper(
        os.fspath(interpreter), "synthetic_wrapper_probe:main",
        import_paths=import_paths,
    ))
    wrapper.chmod(0o755)

    result = subprocess.run(
        [os.fspath(wrapper), "alpha", "two words"], cwd=tmp_path,
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "synthetic-wrapper-ok:alpha|two words\n"
    _assert_no_site_startup(marker)


def test_missing_module_does_not_fall_back_to_pth_or_pythonpath(
    isolated_env, tmp_path, monkeypatch,
):
    interpreter, site_packages, root = isolated_env
    fallback = tmp_path / "fallback"
    fallback.mkdir()
    (fallback / "synthetic_runtime_probe.py").write_text(
        "raise RuntimeError('fallback module imported')\n", encoding="utf-8",
    )
    marker = tmp_path / "missing-module-startup-marker"
    _install_site_startup_hooks(site_packages, marker)
    monkeypatch.setenv("PYTHONPATH", os.fspath(fallback))
    import_paths = staging._discover_import_paths(interpreter)

    with pytest.raises(ValueError, match="import check failed"):
        staging._check_runtime_imports(
            interpreter, {"synthetic-daemon": "synthetic_runtime_probe:main"},
            root=root, import_paths=import_paths,
        )

    _assert_no_site_startup(marker)


def test_probe_and_import_check_children_receive_fresh_fixed_environment(
    isolated_env, tmp_path, monkeypatch,
):
    interpreter, site_packages, root = isolated_env
    (site_packages / "synthetic_runtime_probe.py").write_text(
        "def main():\n    return 0\n", encoding="utf-8",
    )
    poison = tmp_path / "poison-environment"
    poison.mkdir()
    for name, value in {
        "PYTHONPATH": os.fspath(poison),
        "PYTHONHOME": os.fspath(poison),
        "PYTHONUSERBASE": os.fspath(poison),
        "__PYVENV_LAUNCHER__": os.fspath(poison),
        "GLIBC_TUNABLES": "glibc.malloc.check=3",
        "LD_LIBRARY_PATH": os.fspath(poison),
        "LANG": "en_US.UTF-8",
        "LC_ALL": "C",
    }.items():
        monkeypatch.setenv(name, value)

    expected = staging.staging_environment()
    real_run = subprocess.run
    observed = []

    def run_and_observe(command, **kwargs):
        assert kwargs["env"] == expected
        modified = list(command)
        modified[3] += (
            "\nimport json, os, sys; "
            "print('__STAGING_ENV__' + json.dumps(dict(os.environ), sort_keys=True), "
            "file=sys.stderr)\n"
        )
        result = real_run(modified, **kwargs)
        marker = next(
            line for line in result.stderr.splitlines()
            if line.startswith("__STAGING_ENV__")
        )
        observed.append(json.loads(marker.removeprefix("__STAGING_ENV__")))
        return result

    monkeypatch.setattr(staging.subprocess, "run", run_and_observe)
    paths = staging._discover_import_paths(interpreter)
    staging._check_runtime_imports(
        interpreter, {"synthetic-daemon": "synthetic_runtime_probe:main"},
        root=root, import_paths=paths,
    )

    assert len(observed) == 2
    # macOS may add this process-local encoding hint after exec. The env
    # argument above is still checked exactly before each subprocess launch.
    added_by_platform = {"__CF_USER_TEXT_ENCODING"} if sys.platform == "darwin" else set()
    for child_environment in observed:
        assert set(child_environment) <= set(expected) | added_by_platform
        assert {key: child_environment[key] for key in expected} == expected


def test_generated_wrapper_executes_installed_harmless_module_with_arguments(
    isolated_env, tmp_path, monkeypatch,
):
    interpreter, site_packages, _root = isolated_env
    (site_packages / "synthetic_wrapper_probe.py").write_text(
        "import sys\n"
        "def main():\n"
        "    print('synthetic-wrapper-ok:' + '|'.join(sys.argv[1:]))\n"
        "    return 0\n",
        encoding="utf-8",
    )
    poisoned = tmp_path / "wrapper-poison"
    poisoned.mkdir()
    (poisoned / "synthetic_wrapper_probe.py").write_text(
        "raise RuntimeError('poisoned PYTHONPATH module imported')\n", encoding="utf-8",
    )
    monkeypatch.setenv("PYTHONPATH", os.fspath(poisoned))
    wrapper = tmp_path / "synthetic-wrapper"
    wrapper.write_bytes(staging._wrapper(
        os.fspath(interpreter), "synthetic_wrapper_probe:main",
    ))
    wrapper.chmod(0o755)

    result = subprocess.run(
        [os.fspath(wrapper), "alpha", "two words"], cwd=poisoned,
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "synthetic-wrapper-ok:alpha|two words\n"
