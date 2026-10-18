"""Stage the fixed Nexus runtime commands at the paths its systemd units use.

The runtime distribution's normal console scripts live in a Python
environment's ``bin`` directory. Nexus units intentionally execute from
``/usr/libexec/azazel`` instead. This tool creates small, fixed wrappers that
invoke the declared runtime module through an explicitly selected interpreter.
It never accepts executable names or unit names from the caller.
Both validation and wrappers disable site startup and replace initial import
paths with the same explicit installation candidate. Inherited PYTHONPATH,
user-site, .pth and sitecustomize are not installation evidence.
Wrappers use a direct Python -IS shebang, not a shell trampoline. This does
not validate the interpreter/environment's file integrity, ownership, or import
closure; staging intentionally still accepts an executable venv symlink.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIBEXEC_RELATIVE = Path("usr/libexec/azazel")
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "runtime" / "src"))

from azazel_nexus_runtime import startup_wrapper  # noqa: E402
from azazel_nexus_runtime.install_platform import (  # noqa: E402
    CURRENT_INSTALL_PLATFORM_PROFILES,
    InstallPlatformProfile,
)
from azazel_nexus_runtime.launch_environment import staging_environment  # noqa: E402


def declared_daemons(root: Path = ROOT) -> dict[str, str]:
    """Map unit-backed executable names to their declared Python callables."""
    runtime_manifest = root / "runtime" / "pyproject.toml"
    with runtime_manifest.open("rb") as stream:
        scripts = tomllib.load(stream)["project"]["scripts"]
    runtime_root = root / "runtime" / "src"

    executable_paths: set[str] = set()
    for unit in sorted((root / "packaging" / "systemd").glob("*.service")):
        for line in unit.read_text(encoding="utf-8").splitlines():
            if line.startswith("ExecStartPre=+"):
                value = line.removeprefix("ExecStartPre=+")
            elif line.startswith("ExecStart="):
                value = line.removeprefix("ExecStart=")
            else:
                continue
            fields = shlex.split(value)
            if len(fields) != 1 or not fields[0].startswith("/"):
                raise ValueError(
                    f"unit must declare one fixed absolute executable: {unit.name}"
                )
            executable_paths.add(fields[0])
    if not executable_paths:
        raise ValueError("no packaged systemd runtime entrypoints were found")

    expected_prefix = "/usr/libexec/azazel/"
    names: set[str] = set()
    for executable in executable_paths:
        if not executable.startswith(expected_prefix):
            raise ValueError(
                f"unit executable is outside the fixed libexec path: {executable}"
            )
        name = executable.removeprefix(expected_prefix)
        if not name or "/" in name:
            raise ValueError(f"unit executable is not a basename: {executable}")
        names.add(name)

    missing = sorted(names - scripts.keys())
    if missing:
        raise ValueError(f"unit executables have no runtime entrypoint: {missing}")

    result: dict[str, str] = {}
    for name in sorted(names):
        target = scripts[name]
        if not isinstance(target, str):
            raise ValueError(f"runtime entrypoint declaration for {name} must be text")
        module, separator, function = target.partition(":")
        module_parts = module.split(".")
        if (
            not separator
            or not module.startswith("azazel_nexus_runtime.")
            or not all(part.isidentifier() for part in module_parts)
        ):
            raise ValueError(f"invalid runtime entrypoint declaration for {name}")
        module_path = runtime_root.joinpath(*module.split(".")).with_suffix(".py")
        try:
            module_path.resolve().relative_to(runtime_root.resolve())
        except ValueError as error:
            raise ValueError(
                f"runtime entrypoint escapes the runtime package: {name}"
            ) from error
        if not module_path.is_file():
            raise ValueError(f"runtime module for {name} is missing")
        if not function.isidentifier():
            raise ValueError(f"runtime callable for {name} is invalid")
        result[name] = target
    return result


def _validate_interpreter_path(interpreter: str) -> None:
    startup_wrapper.validate_interpreter_path(interpreter)


def _validated_import_paths(paths: object) -> tuple[str, ...]:
    normalized = startup_wrapper.validate_import_paths(paths)
    for path in normalized:
        if not (Path(path).is_dir() or (path.endswith(".zip") and Path(path).is_file())):
            raise ValueError("existing canonical Python directory or .zip import path required")
    return normalized


def _discover_import_paths(interpreter: Path) -> tuple[str, ...]:
    """Observe an installation candidate without executing site startup hooks.

    In Python 3.11-3.13, -S suppresses venv prefix adjustment. Derive a
    conventional venv from the selected executable's lexical path, not its
    symlink destination. Never inherit include-system-site-packages or .pth.
    This observation does not independently approve or hash these directories.
    """
    _validate_interpreter_path(str(interpreter))
    code = (
        "import sys, os, sysconfig, json\n"
        f"prefix = os.path.dirname(os.path.dirname({str(interpreter)!r}))\n"
        "if os.path.isfile(os.path.join(prefix, 'pyvenv.cfg')):\n"
        "    install = sysconfig.get_paths(scheme='venv', "
        "vars={'base': prefix, 'platbase': prefix})\n"
        "else:\n"
        "    install = sysconfig.get_paths()\n"
        "paths = [p for p in [*sys.path, install['purelib'], install['platlib']] "
        "if p and os.path.exists(p)]\n"
        "print(json.dumps({'paths': paths}))\n"
    )
    try:
        result = subprocess.run(
            [str(interpreter), "-IS", "-c", code], cwd="/",
            capture_output=True, text=True, timeout=30, check=False,
            env=staging_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Python import path probe could not complete") from error
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise ValueError("Python import path probe failed or exceeded its bound")

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate Python import path probe key")
            value[key] = item
        return value

    try:
        value = json.loads(result.stdout, object_pairs_hook=unique_object)
    except (ValueError, RecursionError) as error:
        raise ValueError("malformed Python import path probe output") from error
    if type(value) is not dict or set(value) != {"paths"}:
        raise ValueError("Python import path probe must contain exactly paths")
    return _validated_import_paths(value["paths"])


def _import_bootstrap(paths: tuple[str, ...]) -> str:
    return startup_wrapper.import_bootstrap(_validated_import_paths(paths))


def _wrapper(
    interpreter: str, target: str, *, import_paths: tuple[str, ...] | None = None,
) -> bytes:
    _validate_interpreter_path(interpreter)
    startup_wrapper.validate_target(target)
    if import_paths is None:
        import_paths = _discover_import_paths(Path(interpreter))
    return startup_wrapper.render_wrapper(
        interpreter, target, import_paths=_validated_import_paths(import_paths),
    )


def _check_runtime_imports(
    interpreter: Path, daemons: dict[str, str], *, root: Path = ROOT,
    import_paths: tuple[str, ...] | None = None,
) -> None:
    if import_paths is None:
        import_paths = _discover_import_paths(interpreter)
    with (root / "runtime" / "pyproject.toml").open("rb") as stream:
        dependencies = tomllib.load(stream)["project"].get("dependencies", [])
    module_names = {"dbus-next": "dbus_next", "pyyaml": "yaml"}
    required_modules = [
        (dependency.split("==", 1)[0], module_names[dependency.split("=", 1)[0].strip().lower()],
         dependency.split("==", 1)[1])
        for dependency in dependencies
        if dependency.split("=", 1)[0].strip().lower() in module_names
    ]
    targets = tuple(target.split(":", 1) for target in daemons.values())
    code = (
        _import_bootstrap(import_paths)
        + "import importlib\n"
        "import importlib.metadata\n"
        f"targets = {targets!r}\n"
        f"required_modules = {required_modules!r}\n"
        "for distribution, module, expected in required_modules:\n"
        "    importlib.import_module(module)\n"
        "    if importlib.metadata.version(distribution) != expected:\n"
        "        raise RuntimeError(f'required runtime dependency {distribution} has wrong version')\n"
        "if any(module == 'azazel_nexus_runtime.activated' for module, _ in targets):\n"
        "    from azazel_nexus_runtime.bootstrap_kernel_deadline import _load_backend\n"
        "    _load_backend()  # import only: never arm a timer while staging\n"
        "for module, name in targets:\n"
        "    entrypoint = getattr(importlib.import_module(module), name)\n"
        "    if not callable(entrypoint):\n"
        "        raise TypeError(f'{module}:{name} is not callable')\n"
    )
    try:
        result = subprocess.run(
            [str(interpreter), "-IS", "-c", code],
            cwd="/",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=staging_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError(
            "runtime entrypoint import check could not complete"
        ) from error
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        summary = detail[-1][:240] if detail else "import check failed"
        raise ValueError(f"runtime entrypoint import check failed: {summary}")


def stage(
    interpreter: Path | str,
    *,
    destdir: Path | None = None,
    root: Path = ROOT,
    profile_id: str = "debian-13-systemd-installer-v1",
) -> list[Path]:
    """Write wrappers to the selected profile's fixed libexec path."""
    if not isinstance(interpreter, Path) and type(interpreter) is not str:
        raise ValueError("selected Python interpreter path must be text")
    interpreter_text = str(interpreter)
    if not interpreter_text.startswith("/") or interpreter_text == "/":
        raise ValueError(
            "selected Python interpreter must be an absolute executable file"
        )
    _validate_interpreter_path(interpreter_text)
    interpreter_path = Path(interpreter_text)
    if (
        not interpreter_path.is_file()
        or not os.access(interpreter_path, os.X_OK)
    ):
        raise ValueError(
            "selected Python interpreter must be an absolute executable file"
        )

    daemons = declared_daemons(root)
    profiles = {
        profile.profile_id: profile
        for profile in CURRENT_INSTALL_PLATFORM_PROFILES
        if type(profile) is InstallPlatformProfile
    }
    if type(profile_id) is not str or profile_id not in profiles:
        raise ValueError("unknown reviewed install platform profile")
    libexec_directory = profiles[profile_id].libexec_directory
    relative_libexec = Path(libexec_directory.lstrip("/"))
    if (
        not libexec_directory.startswith("/")
        or ".." in relative_libexec.parts
        or relative_libexec.as_posix() != libexec_directory.lstrip("/")
    ):
        raise ValueError("install profile libexec path is not normalized")
    output_root = destdir if destdir is not None else Path("/")
    if not output_root.is_absolute():
        raise ValueError("DESTDIR must be absolute")
    destination = output_root / relative_libexec
    if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
        raise ValueError("runtime entrypoint destination must be a real directory")
    targets = [destination / name for name in daemons]
    if any(path.is_symlink() for path in targets):
        raise ValueError("refusing to replace a symlink runtime entrypoint")

    import_paths = _discover_import_paths(interpreter_path)
    wrappers = {
        name: _wrapper(interpreter_text, target, import_paths=import_paths)
        for name, target in daemons.items()
    }

    # Refuse an unsafe destination before executing the selected interpreter.
    # Import validation can fail for ordinary environment reasons; it must not
    # obscure a path that the installer would never be allowed to replace.
    _check_runtime_imports(interpreter_path, daemons, root=root, import_paths=import_paths)
    destination.mkdir(parents=True, exist_ok=True)

    staged: list[Path] = []
    for name, data in wrappers.items():
        file_descriptor, temporary = tempfile.mkstemp(
            prefix=f".{name}.", dir=destination
        )
        temporary_path = Path(temporary)
        try:
            with os.fdopen(file_descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            temporary_path.chmod(
                stat.S_IRUSR
                | stat.S_IWUSR
                | stat.S_IXUSR
                | stat.S_IRGRP
                | stat.S_IXGRP
                | stat.S_IROTH
                | stat.S_IXOTH
            )
            target_path = destination / name
            os.replace(temporary_path, target_path)
            staged.append(target_path)
        finally:
            temporary_path.unlink(missing_ok=True)
    return staged


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--python",
        required=True,
        type=str,
        help="absolute Python executable from the installed Nexus runtime environment",
    )
    parser.add_argument(
        "--platform-profile",
        default="debian-13-systemd-installer-v1",
        choices=tuple(
            profile.profile_id for profile in CURRENT_INSTALL_PLATFORM_PROFILES
        ),
        help="registered host install profile; unknown profiles are refused",
    )
    args = parser.parse_args(argv)
    destdir_text = os.environ.get("DESTDIR")
    destdir = Path(destdir_text) if destdir_text else None
    try:
        staged = stage(
            args.python, destdir=destdir, profile_id=args.platform_profile
        )
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
    print(
        f"staged {len(staged)} fixed Nexus runtime entrypoints under /usr/libexec/azazel"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
