"""Pure conventional Debian CPython venv metadata constraints.

These checks interpret independently pinned metadata, not interpreter execution,
package authenticity, native-loader closure or authority to start a service.
Architecture-specific ABI qualification is deliberately separate.
"""

import re

from .startup_wrapper import validate_interpreter_path


MAX_PYVENV_BYTES = 4096
BASE_INTERPRETER = "usr/bin/python3.13"
_REQUIRED = {
    "home": "/usr/bin",
    "include-system-site-packages": "false",
    "executable": "/" + BASE_INTERPRETER,
}
_KEYS = frozenset((*_REQUIRED, "version", "command", "prompt"))
_VERSION = re.compile(r"3\.13\.(0|[1-9][0-9]{0,3})\Z")


def pyvenv_config_path(interpreter: str) -> str:
    """Derive one fixed metadata path; never search or follow filesystem links."""
    validate_interpreter_path(interpreter)
    parts = interpreter[1:].split("/")
    if (len(parts) < 4 or parts[0] != "opt" or parts[-2] != "bin"
            or parts[-1] not in {"python", "python3", "python3.13"}):
        raise ValueError("conventional protected Python venv path required")
    return "/".join((*parts[:-2], "pyvenv.cfg"))


def validate_pyvenv_config(raw: bytes) -> tuple[int, int, int]:
    """Reject ambiguous/unsupported metadata without executing any content.

    ``version`` and ``executable`` are pinned creation metadata, not evidence
    that a running process has that version or executable identity. CPython's
    startup override and implicit-file checks remain separate obligations.
    """
    if (type(raw) is not bytes or not 0 < len(raw) <= MAX_PYVENV_BYTES
            or not raw.endswith(b"\n")
            or any(byte != 10 and not 32 <= byte <= 126 for byte in raw)):
        raise ValueError("bounded ASCII Python venv metadata required")
    values = {}
    for line in raw.decode("ascii").splitlines():
        key, separator, value = line.partition("=")
        key, value = key.strip(" "), value.strip(" ")
        if (not separator or key not in _KEYS or key in values or not value):
            raise ValueError("Python venv metadata fields refused")
        values[key] = value
    if (any(values.get(key) != value for key, value in _REQUIRED.items())
            or not _VERSION.fullmatch(values.get("version", ""))):
        raise ValueError("unsupported Python venv configuration")
    return (3, 13, int(values["version"].rsplit(".", 1)[1]))
