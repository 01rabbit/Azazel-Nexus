"""The installer's record of the compiled AppArmor policy hashes (#196 G6 prep K).

`docs/deception-exposure-wiring.md` §5.2 and `docs/deception-exposure-grant.md`
§7 "Left to G6": with the service manager, the installer compiles each of
the four Deception Lite profiles placed in `/etc/apparmor.d` with
`apparmor_parser -Q -o <file>` (no other flag) and records the SHA-256 of
each output, the value the kernel shows as the profile's `raw_sha256` once
`apparmor.service` loads it (checked on one VM, grant §7), in one record:

    /etc/azazel/activation/apparmor-compiled.json

canonical JSON (sorted keys, no spaces, ASCII, one trailing newline) with
exactly three keys:

* `contract`: `azazel-nexus/apparmor-compiled/v1`;
* `apparmor_policy_hashes`: exactly the four profile names
  (`APPARMOR_PROFILE_NAMES`, equal to
  `decoy_apparmor.REQUIRED_ENFORCED_PROFILES`), each to 64 lowercase hex
  digits with no prefix, the rule `exposure_generation` applies to the
  exposure section's field of the same name (a test keeps them in
  agreement), so G6's `generation-publish` copies it unchanged;
* `parser_version`: the parser's version line, for diagnosis only, never
  compared, and never a reason to refuse an install: the writer passes it
  through `normalize_parser_version` (each character outside printable
  ASCII becomes `?`, at most 255 characters, `unknown` when empty), and the
  decoder accepts exactly the values that normalization leaves unchanged.

* `encode_apparmor_compiled` is pure: the record's bytes, or refused.
* `decode_apparmor_compiled` is pure and strict: the bytes as read, to the
  hashes and the version line, or refused (`ApparmorCompiledRefused`, one
  fixed phrase, nothing read appears in it). Bytes that are not exactly
  the canonical encoding of an accepted record are refused, so whitespace,
  key order, duplicate keys and a missing or extra newline all are.

The record is mode 0644, root's, in the root 0700 directory: it holds
hashes of compiled public policy, no secret, and only root may replace it.

**Implemented, not wired.** The writer is the installer's tool
(`tools/record_apparmor_compiled.py`), which checks its own output with
`decode_apparmor_compiled`. Nothing else calls this module: neither
`generation-publish` nor the pass reads the record in this build (G6). The
record is an input of `generation-publish` only, never of the pass; the
pass trusts only the section inside the signed generation.
"""

from __future__ import annotations

import json
import re
from typing import NamedTuple

__all__ = [
    "APPARMOR_COMPILED_CONTRACT",
    "APPARMOR_COMPILED_KEYS",
    "APPARMOR_COMPILED_MODE",
    "APPARMOR_COMPILED_PATH",
    "APPARMOR_COMPILED_REFUSED",
    "APPARMOR_PROFILE_NAMES",
    "PARSER_VERSION_LIMIT",
    "PARSER_VERSION_UNKNOWN",
    "ApparmorCompiled",
    "ApparmorCompiledRefused",
    "decode_apparmor_compiled",
    "encode_apparmor_compiled",
    "normalize_parser_version",
]

APPARMOR_COMPILED_CONTRACT = "azazel-nexus/apparmor-compiled/v1"
APPARMOR_COMPILED_PATH = "/etc/azazel/activation/apparmor-compiled.json"
#: Not secret (hashes of compiled public policy); only root writes it.
APPARMOR_COMPILED_MODE = 0o644
#: All required, no other.
APPARMOR_COMPILED_KEYS = ("apparmor_policy_hashes", "contract", "parser_version")
#: The four Deception Lite profiles (`decoy_apparmor.REQUIRED_ENFORCED_PROFILES`;
#: a test keeps them equal; not imported, so the product's importers of
#: `decoy_apparmor` stay what its own tests pin).
APPARMOR_PROFILE_NAMES = ("azazel-decoy-netd", "azazel-decoy-nsd",
                          "azazel-decoy-verify", "azazel-decoyd")
#: The one phrase every refusal carries.
APPARMOR_COMPILED_REFUSED = ("the AppArmor compiled-policy record is not in its "
                             "closed form")

#: `raw_sha256` as the kernel shows it, without the newline
#: (`exposure_generation._POLICY_HASH`; a test keeps them in agreement).
_POLICY_HASH = re.compile(r"[0-9a-f]{64}\Z")
#: `normalize_parser_version`'s bound, and its value for an empty line.
PARSER_VERSION_LIMIT = 255
PARSER_VERSION_UNKNOWN = "unknown"
_RECORD_LIMIT = 4096


class ApparmorCompiledRefused(ValueError):
    """The record, or what would be recorded, is not in its closed form."""


class ApparmorCompiled(NamedTuple):
    #: Exactly the four profile names, sorted, to 64 lowercase hex digits.
    apparmor_policy_hashes: dict[str, str]
    #: Diagnosis only; never compared.
    parser_version: str


def _refuse() -> ApparmorCompiledRefused:
    return ApparmorCompiledRefused(APPARMOR_COMPILED_REFUSED)


def _policy_hashes(hashes) -> dict[str, str]:
    if (type(hashes) is not dict or set(hashes) != set(APPARMOR_PROFILE_NAMES)
            or any(type(value) is not str or not _POLICY_HASH.match(value)
                   for value in hashes.values())):
        raise _refuse()
    return {name: hashes[name] for name in APPARMOR_PROFILE_NAMES}


def normalize_parser_version(value: str) -> str:
    """The version line as recorded: printable ASCII only (others become `?`),
    at most 255 characters, `unknown` when empty. Diagnosis only."""

    text = "".join(c if " " <= c <= "~" else "?" for c in str(value))
    return text[:PARSER_VERSION_LIMIT] or PARSER_VERSION_UNKNOWN


def _parser_version(value) -> str:
    if type(value) is not str or normalize_parser_version(value) != value:
        raise _refuse()
    return value


def encode_apparmor_compiled(apparmor_policy_hashes: dict[str, str],
                             parser_version: str) -> bytes:
    """The record's canonical bytes; refuses a hash set or version of another form."""

    document = {
        "apparmor_policy_hashes": _policy_hashes(apparmor_policy_hashes),
        "contract": APPARMOR_COMPILED_CONTRACT,
        "parser_version": _parser_version(parser_version),
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _no_duplicates(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise _refuse()
    return dict(pairs)


def _no_constant(_name):
    raise _refuse()


def decode_apparmor_compiled(raw) -> ApparmorCompiled:
    """The record as read, strictly; refuses (`ApparmorCompiledRefused`) otherwise.

    `raw` is the file's bytes, at most 4 KiB. Accepted only when it is the
    canonical encoding (`encode_apparmor_compiled`) of exactly the three
    keys, the contract above, exactly the four profile names each to 64
    lowercase hex digits, and a version line `normalize_parser_version`
    leaves unchanged. Pure; nothing read
    appears in the refusal. **Called by nothing but the installer's tool in
    this build**; G6's `generation-publish` is to call it.
    """

    if type(raw) is not bytes or not 0 < len(raw) <= _RECORD_LIMIT:
        raise _refuse()
    try:
        document = json.loads(raw.decode("ascii"), object_pairs_hook=_no_duplicates,
                              parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _refuse() from None
    if (type(document) is not dict or set(document) != set(APPARMOR_COMPILED_KEYS)
            or document["contract"] != APPARMOR_COMPILED_CONTRACT
            or type(document["contract"]) is not str):
        raise _refuse()
    record = ApparmorCompiled(_policy_hashes(document["apparmor_policy_hashes"]),
                              _parser_version(document["parser_version"]))
    if encode_apparmor_compiled(*record) != raw:
        raise _refuse()
    return record
