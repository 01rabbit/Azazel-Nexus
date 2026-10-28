"""The read-only UI's one-time login code, and `azazel-nexus ui-login` (U5).

The UI (`az-ui`, account `azui`) listens on loopback, which every account on
the host can reach, so even reading needs a login. The smallest login that
reuses an authorisation this node already has: the UI keeps a short-lived,
one-use code in a file only the `azazel-operator` group can read
(`/var/lib/azazel/run/ui-login`, `2750 azui:azazel-operator`), and an
operator reads it with `azazel-nexus ui-login` and types it into the page.

* **One use, `CODE_TTL_S` seconds.** The UI forgets a code when it is
  redeemed or expires, and publishes a fresh one.
* **Never in a URL.** The code is typed into a form and sent in a POST body;
  the session that follows is an `HttpOnly; SameSite=Strict` cookie.
* **Read-only here.** This module and the command only read the file; the
  UI is its only writer. Nothing here grants anything: a code is a login to
  a page that shows what `status --json` shows, and the page has no action.
"""

from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path
from typing import Optional, TextIO

__all__ = [
    "CODE_ALPHABET", "CODE_LENGTH", "CODE_TTL_S", "LOGIN_CODE_BYTES", "SCHEMA",
    "format_code", "login_code_path", "normalize_code", "read_login_code", "run",
]

SCHEMA = "azazel-nexus/ui-login/1"

#: How long one code may be redeemed, at most.
CODE_TTL_S = 60

#: Upper-case letters and digits with the easily confused ones (0/O, 1/I/L, U)
#: removed: 30 symbols, so ten of them are about 49 bits.
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
CODE_LENGTH = 10

#: The file is a few hundred bytes; anything larger is refused.
LOGIN_CODE_BYTES = 1024

_CODE = re.compile(f"[{CODE_ALPHABET}]{{{CODE_LENGTH}}}")
_URL = re.compile(r"http://127\.0\.0\.1:[0-9]{1,5}/")


def login_code_path(root=None) -> Path:
    base = Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else Path(root)
    return base / "var/lib/azazel/run/ui-login/login-code.json"


def normalize_code(text) -> Optional[str]:
    """The code an operator typed, without spaces or hyphens; `None` if not one."""

    if not isinstance(text, str) or len(text) > 64:
        return None
    compact = re.sub(r"[\s-]", "", text).upper()
    return compact if _CODE.fullmatch(compact) else None


def format_code(code: str) -> str:
    """`ABCDEFGHJK` -> `ABCDE-FGHJK`, for reading aloud and typing."""

    half = CODE_LENGTH // 2
    return f"{code[:half]}-{code[half:]}"


def _number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def read_login_code(raw: bytes) -> dict:
    """The strict reader of the UI's login code file. Raises `ValueError`."""

    if len(raw) > LOGIN_CODE_BYTES:
        raise ValueError("oversized")
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or set(value) != {"schema", "code", "issued_at",
                                                     "expires_at", "url"}:
        raise ValueError("shape")
    if value["schema"] != SCHEMA:
        raise ValueError("schema")
    if not (isinstance(value["code"], str) and _CODE.fullmatch(value["code"])):
        raise ValueError("code")
    if not (_number(value["issued_at"]) and _number(value["expires_at"])):
        raise ValueError("time")
    if not 0 < value["expires_at"] - value["issued_at"] <= CODE_TTL_S:
        raise ValueError("lifetime")
    if not (isinstance(value["url"], str) and _URL.fullmatch(value["url"])):
        raise ValueError("url")
    return value


def run(out: TextIO, *, now: float, path: Optional[Path] = None) -> int:
    """`azazel-nexus ui-login`: print the current code, or why there is none.

    Reads one file and prints; writes nothing, starts nothing, contacts
    nothing. A code it prints is one use and expires on its own.
    """

    from .edge_loop_status import read_snapshot

    value = read_snapshot(path or login_code_path(), read_login_code, LOGIN_CODE_BYTES)
    if value is None:
        print("ui-login: no login code is readable. Either the UI is not running "
              "(systemctl start azazel-ui.socket, then open the page once), or this "
              "account is not in the azazel-operator group.", file=out)
        return 1
    remaining = int(value["expires_at"] - now)
    if value["issued_at"] > now + 5:
        print("ui-login: the login code is dated in the future; the clock is not "
              "trusted. No code is shown.", file=out)
        return 1
    if remaining <= 0:
        print("ui-login: the current code has expired. The UI publishes a new one "
              "within 30 seconds; run this again.", file=out)
        return 1
    print(f"UI login code (one use, valid for {remaining} more seconds): "
          f"{format_code(value['code'])}", file=out)
    print(f"Open {value['url']} in a browser on this host and type the code there.",
          file=out)
    print("The code is never part of a URL. The UI is read-only: it shows what "
          "`azazel-nexus status --json` shows and performs no action.", file=out)
    return 0
