"""Exact bounded Python-profile parsing for the fixed bootstrap runtime."""

from pathlib import Path

import pytest

from azazel_nexus_runtime.python_profile import (
    pyvenv_config_path,
    validate_pyvenv_config,
)


def _config(*, spaces=False, extras=()):
    separator = " = " if spaces else "="
    lines = [
        "home" + separator + "/usr/bin",
        "include-system-site-packages" + separator + "false",
        "version" + separator + "3.13.0",
        "executable" + separator + "/usr/bin/python3.13",
        *extras,
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


@pytest.mark.parametrize("spaces", [False, True])
def test_accepts_fixed_venv_config_and_returns_version_tuple(spaces):
    assert validate_pyvenv_config(_config(spaces=spaces)) == (3, 13, 0)


def test_optional_command_and_prompt_are_inert_printable_values():
    raw = _config(extras=(
        "command = /usr/bin/python3.13 -m venv /opt/nexus/env",
        "prompt = nexus bootstrap",
    ))
    assert validate_pyvenv_config(raw) == (3, 13, 0)


def test_accepts_maximum_canonical_patch_version():
    raw = _config().replace(b"version=3.13.0", b"version=3.13.9999")
    assert validate_pyvenv_config(raw) == (3, 13, 9999)


@pytest.mark.parametrize("raw", [
    None,
    Path("/opt/nexus/env/bin/python3.13"),
    "home=/usr/bin\n",
    bytearray(b"home=/usr/bin\n"),
    _config() + b"x" * 4097,
    _config() + b"home=/usr/bin\n",
    _config().replace(b"home=/usr/bin\n", b"HOME=/usr/bin\n"),
    _config().replace(b"home=/usr/bin\n", b"home=/usr/local/bin\n"),
    _config().replace(b"include-system-site-packages=false", b"include-system-site-packages=true"),
    _config().replace(b"version=3.13.0", b"version=3.14.0"),
    _config().replace(b"executable=/usr/bin/python3.13", b"executable=/opt/evil/python3.13"),
    _config() + b"unknown=value\n",
    _config() + b"Command=harmless\n",
    _config(extras=("prompt = ",)),
    _config(extras=("command = /usr/bin/python3.13\t-m venv",)),
    _config().replace(b"version=3.13.0", b"version=3.13.01"),
    _config().replace(b"version=3.13.0", b"version=3.13.10000"),
    _config().replace(b"version=3.13.0", b"version=3.13.-1"),
    _config().replace(b"version=3.13.0\n", b"version=3.13.0\r\n"),
    _config().replace(b"version=3.13.0\n", b"version=3.13.0\x00\n"),
    _config().replace(b"version=3.13.0\n", b"version=3.13.0\x7f\n"),
    _config().rstrip(b"\n"),
    _config().replace(b"version=3.13.0\n", b"\nversion=3.13.0\n"),
    _config() + b"\n",
    b"\xff\n",
])
def test_refuses_malformed_or_unsafe_venv_config(raw):
    with pytest.raises(ValueError):
        validate_pyvenv_config(raw)


@pytest.mark.parametrize(("interpreter", "expected"), [
    ("/opt/nexus/env/bin/python", "opt/nexus/env/pyvenv.cfg"),
    ("/opt/nexus/env/bin/python3", "opt/nexus/env/pyvenv.cfg"),
    ("/opt/nexus/env/bin/python3.13", "opt/nexus/env/pyvenv.cfg"),
    ("/opt/a/b/c/bin/python3.13", "opt/a/b/c/pyvenv.cfg"),
])
def test_maps_only_supported_interpreter_paths_to_venv_config(interpreter, expected):
    assert pyvenv_config_path(interpreter) == expected


@pytest.mark.parametrize("interpreter", [
    None,
    b"/opt/nexus/env/bin/python3.13",
    "/usr/bin/python3.13",
    "/opt/nexus/python3.13",
    "/opt/nexus/env/bin/python3.12",
    "/opt/nexus/env/bin/python3.13.1",
    "/opt/nexus/env/bin/python2",
    "/opt//nexus/env/bin/python3.13",
    "/opt/nexus/../env/bin/python3.13",
    "/opt/nexus/./env/bin/python3.13",
    "/opt/nexus/env/bin/python3.13/",
    "opt/nexus/env/bin/python3.13",
    "/opt/nexus/env/bin/python3.13\n",
    "/opt/nexus env/bin/python3.13",
    "/opt/nexus/非ascii/bin/python3.13",
])
def test_refuses_noncanonical_or_unapproved_interpreter_layout(interpreter):
    with pytest.raises(ValueError):
        pyvenv_config_path(interpreter)
