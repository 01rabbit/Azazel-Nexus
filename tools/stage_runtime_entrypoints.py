"""Stage the fixed Nexus runtime commands at the paths its systemd units use.

The runtime distribution's normal console scripts live in a Python
environment's ``bin`` directory. Nexus units intentionally execute from
``/usr/libexec/azazel`` instead. This tool creates small, fixed wrappers that
invoke the declared runtime module through an explicitly selected interpreter.
It never accepts executable names or unit names from the caller.
"""

from __future__ import annotations

import argparse
import os
import shlex
import stat
import subprocess
import tempfile
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIBEXEC_RELATIVE = Path("usr/libexec/azazel")


def declared_daemons(root: Path = ROOT) -> dict[str, str]:
    """Map unit-backed executable names to their declared Python callables."""
    runtime_manifest = root / "runtime" / "pyproject.toml"
    with runtime_manifest.open("rb") as stream:
        scripts = tomllib.load(stream)["project"]["scripts"]
    runtime_root = root / "runtime" / "src"

    executable_paths: set[str] = set()
    for unit in sorted((root / "packaging" / "systemd").glob("*.service")):
        for line in unit.read_text(encoding="utf-8").splitlines():
            if not line.startswith("ExecStart="):
                continue
            fields = shlex.split(line.removeprefix("ExecStart="))
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


def _wrapper(interpreter: str, target: str) -> bytes:
    module, function = target.split(":", 1)
    invocation = f"from {module} import {function}; raise SystemExit({function}())"
    command = (
        "exec "
        + shlex.quote(interpreter)
        + " -c "
        + shlex.quote(invocation)
        + ' "$@"\n'
    )
    return ("#!/bin/sh\n" + command).encode("utf-8")


def _check_runtime_imports(
    interpreter: Path, daemons: dict[str, str], *, root: Path = ROOT
) -> None:
    with (root / "runtime" / "pyproject.toml").open("rb") as stream:
        dependencies = tomllib.load(stream)["project"].get("dependencies", [])
    required_modules = [
        "dbus_next"
        for dependency in dependencies
        if dependency.split("=", 1)[0].strip().lower() == "dbus-next"
    ]
    targets = tuple(target.split(":", 1) for target in daemons.values())
    code = (
        "import importlib\n"
        "import importlib.util\n"
        f"targets = {targets!r}\n"
        f"required_modules = {required_modules!r}\n"
        "for module in required_modules:\n"
        "    if importlib.util.find_spec(module) is None:\n"
        "        raise ModuleNotFoundError(f'required runtime module {module} is missing')\n"
        "for module, name in targets:\n"
        "    entrypoint = getattr(importlib.import_module(module), name)\n"
        "    if not callable(entrypoint):\n"
        "        raise TypeError(f'{module}:{name} is not callable')\n"
    )
    try:
        result = subprocess.run(
            [str(interpreter), "-c", code],
            cwd="/",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
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
    interpreter: Path, *, destdir: Path | None = None, root: Path = ROOT
) -> list[Path]:
    """Write wrappers to ``/usr/libexec/azazel`` (under DESTDIR in tests)."""
    if (
        not interpreter.is_absolute()
        or not interpreter.is_file()
        or not os.access(interpreter, os.X_OK)
    ):
        raise ValueError(
            "selected Python interpreter must be an absolute executable file"
        )

    daemons = declared_daemons(root)
    output_root = destdir if destdir is not None else Path("/")
    if not output_root.is_absolute():
        raise ValueError("DESTDIR must be absolute")
    destination = output_root / LIBEXEC_RELATIVE
    if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
        raise ValueError("runtime entrypoint destination must be a real directory")
    targets = [destination / name for name in daemons]
    if any(path.is_symlink() for path in targets):
        raise ValueError("refusing to replace a symlink runtime entrypoint")

    # Refuse an unsafe destination before executing the selected interpreter.
    # Import validation can fail for ordinary environment reasons; it must not
    # obscure a path that the installer would never be allowed to replace.
    _check_runtime_imports(interpreter, daemons, root=root)
    destination.mkdir(parents=True, exist_ok=True)

    staged: list[Path] = []
    for name, target in daemons.items():
        data = _wrapper(str(interpreter), target)
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
        type=Path,
        help="absolute Python executable from the installed Nexus runtime environment",
    )
    args = parser.parse_args(argv)
    destdir_text = os.environ.get("DESTDIR")
    destdir = Path(destdir_text) if destdir_text else None
    try:
        staged = stage(args.python, destdir=destdir)
    except (OSError, ValueError, KeyError) as error:
        parser.error(str(error))
    print(
        f"staged {len(staged)} fixed Nexus runtime entrypoints under /usr/libexec/azazel"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
