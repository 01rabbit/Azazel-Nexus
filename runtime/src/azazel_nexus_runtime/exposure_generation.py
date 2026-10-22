"""The generation's exposure section: what it digests, and its comparison (#196 G6 prep).

`docs/deception-exposure-grant.md` §4.4 item 5 and §5 C1 condition 2: a
generation that may carry the exposure tier gains an **exposure section**,
the SHA-256 of

* the three exposure unit files (`activation_markers.EXPOSURE_UNITS`),
* the watch's three unit files (`activation_unit_files.WATCH_UNITS`: the
  verify service, its timer and the trip target, §6),
* the four AppArmor profile files placed in `/etc/apparmor.d`
  (`decoy_apparmor.REQUIRED_ENFORCED_PROFILES`, §7), and
* the rendered scope file (`scope_digest`, `decoy_scope.parse_scope_file`,
  §4.3),

each `sha256:<hex>`, measured the way the observe-baseline generation
measures its unit files (`observe_baseline`, `activation_unit_files`): bytes
read once, without following a link, from a root-owned file no one else may
write, with one link, stable while read. Beside the digests, the section
records `apparmor_policy_hashes`: for each of the four profiles, the 64
lowercase hex digits the kernel should show as its `raw_sha256` (§7 "Left
to G6"). That field is a record, not a measurement: G6's installer computes
it as the SHA-256 of its `apparmor_parser -Q -o` output; this build only
accepts it, checks its form and hands it to
`decoy_apparmor.policy_hash_refusal` (`expected_policy_hashes`).

* `build_exposure_section` is pure: from supplied bytes and the recorded
  policy hashes to the section.
* `verify_exposure_section` is pure: a recorded section against a fresh
  measurement; any difference refuses (`GenerationRefused`).
* `expected_policy_hashes` is pure: a recorded section's policy hashes, in
  the form `decoy_apparmor.exposure_lsm_withholding` takes as `expected`.
* `measure_exposure_section_inputs` is the reader: the exposure unit files
  through `activation_unit_files.measure_exposure_unit_files` (content and
  override checks included), the watch files through
  `activation_unit_files.require_watch_unit_files` (byte for byte against
  the rendering, no override, no mask; it returns what it read, so the
  digest is of exactly the accepted bytes), and the profile files. The scope
  file is not read here: the pass renders it in G6 and passes its bytes.

**What it says.** Each refusal is `"<code>: <phrase>"` with a code of
`EXPOSURE_SECTION_CODES` and its one fixed phrase
(`EXPOSURE_SECTION_PHRASES`): `exposure_section_unverifiable` when the
section, a supplied set, the scope or a file read is not in its closed
form; `exposure_section_differs` when a well-formed record does not describe
the bytes measured now. Nothing measured appears in it. The readers keep
their exception types (`UnitContentRefused`, `UnitOverrideRefused`,
`ExposureFilesRefused`, all `UnitFilesRefused`); their own labels stay on
the chained cause.

**What is not digested.** The profiles `include <tunables/global>` and
`<abstractions/base>`, Debian's files; an edit there changes the compiled
policy, not these digests. That is the kernel-hash comparison's to catch
(`decoy_apparmor.policy_hash_refusal`, *inferred*, G6).

**Implemented, not wired.** The current generation schema
(`observe_baseline.OBSERVE_BASELINE_SCHEMA`), `ACTIVATION_UNIT_ALLOWLIST`,
`GRANTABLE_UNITS` and the policy scope are unchanged; this section is not in
any generation this build writes or reads, and nothing calls this module
(`tests/unit/test_exposure_g6_parts.py`). **The generation schema version
that carries the section is introduced in G6**; its name is G6's choice.
"""

from __future__ import annotations

from hashlib import sha256
import os
import re
from typing import Mapping

from azazel_nexus.decoy_scope import DecoyScopeRefused, parse_scope_file
from azazel_nexus.generation import GenerationRefused

from . import activation_unit_files as _unit_files
from .activation_markers import EXPOSURE_UNITS
from .activation_unit_files import (
    WATCH_UNITS,
    UnitFilesRefused,
    measure_exposure_unit_files,
    require_watch_unit_files,
)
from .decoy_apparmor import REQUIRED_ENFORCED_PROFILES

__all__ = [
    "APPARMOR_DIRECTORY",
    "EXPOSURE_SECTION_CODES",
    "EXPOSURE_SECTION_DIFFERS",
    "EXPOSURE_SECTION_KEYS",
    "EXPOSURE_SECTION_PHRASES",
    "EXPOSURE_SECTION_UNVERIFIABLE",
    "ExposureFilesRefused",
    "build_exposure_section",
    "expected_policy_hashes",
    "measure_apparmor_profile_files",
    "measure_exposure_section_inputs",
    "verify_exposure_section",
]

#: Where the installer places the profiles (`install_platform.APPARMOR_DIRECTORY`;
#: a test keeps them equal).
APPARMOR_DIRECTORY = "/etc/apparmor.d"

#: The section's keys, all required, no other.
EXPOSURE_SECTION_KEYS = ("apparmor_policy_hashes", "apparmor_profiles", "scope_digest",
                         "unit_files", "watch_unit_files")

EXPOSURE_SECTION_UNVERIFIABLE = "exposure_section_unverifiable"
EXPOSURE_SECTION_DIFFERS = "exposure_section_differs"
#: In the order they are judged.
EXPOSURE_SECTION_CODES: tuple[str, ...] = (
    EXPOSURE_SECTION_UNVERIFIABLE, EXPOSURE_SECTION_DIFFERS)

#: Each code's fixed phrase: no unit, profile or file name, digest or hash.
EXPOSURE_SECTION_PHRASES: dict[str, str] = {
    EXPOSURE_SECTION_UNVERIFIABLE: ("the exposure section, or the unit files, "
                                    "profile files, scope or policy hashes it "
                                    "describes, could not be read in their "
                                    "closed form"),
    EXPOSURE_SECTION_DIFFERS: ("the recorded exposure section does not describe "
                               "the unit files, profile files and scope placed "
                               "now"),
}

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
#: `raw_sha256` as the kernel shows it, without the newline
#: (`decoy_apparmor._hex_digest`; a test keeps them in agreement).
_POLICY_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FILE_LIMIT = 1 << 20


def _phrase(code: str) -> str:
    return f"{code}: {EXPOSURE_SECTION_PHRASES[code]}"


class ExposureFilesRefused(UnitFilesRefused):
    """An AppArmor profile file is missing, unprotected, linked or changing."""


def _digest(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def _digests(files, names) -> dict[str, str]:
    snapshot = dict(files) if isinstance(files, Mapping) else None
    if (snapshot is None or set(snapshot) != set(names) or any(
            type(data) is not bytes or not 0 < len(data) <= _FILE_LIMIT
            for data in snapshot.values())):
        raise GenerationRefused(_phrase(EXPOSURE_SECTION_UNVERIFIABLE))
    return {name: _digest(snapshot[name]) for name in sorted(names)}


def _policy_hashes(hashes) -> dict[str, str]:
    """Exactly the four profiles, each 64 lowercase hex digits, or refused."""

    if (type(hashes) is not dict or set(hashes) != set(REQUIRED_ENFORCED_PROFILES)
            or any(type(value) is not str or not _POLICY_HASH.match(value)
                   for value in hashes.values())):
        raise GenerationRefused(_phrase(EXPOSURE_SECTION_UNVERIFIABLE))
    return {name: hashes[name] for name in sorted(REQUIRED_ENFORCED_PROFILES)}


def build_exposure_section(
    *, unit_files: Mapping[str, bytes], watch_unit_files: Mapping[str, bytes],
    apparmor_profiles: Mapping[str, bytes], apparmor_policy_hashes: dict[str, str],
    scope_file: bytes,
) -> dict:
    """The exposure section for these bytes and hashes; nothing is read or written.

    `unit_files` maps exactly the three exposure units, `watch_unit_files`
    exactly the three watch units, `apparmor_profiles` exactly the four
    profile names, each to the file's bytes; `apparmor_policy_hashes` maps
    exactly the four profile names to the 64 lowercase hex digits the kernel
    should show as `raw_sha256` (G6's installer records them; nothing here
    derives one); `scope_file` is the rendered scope file, accepted only as
    `decoy_scope.parse_scope_file` accepts it. Refuses
    (`GenerationRefused`, `exposure_section_unverifiable`) on any other set,
    an empty or oversized file, a hash of another form, or a refused scope.
    """

    try:
        scope_digest = parse_scope_file(scope_file).scope_digest
    except DecoyScopeRefused:
        raise GenerationRefused(_phrase(EXPOSURE_SECTION_UNVERIFIABLE)) from None
    return {
        "apparmor_policy_hashes": _policy_hashes(apparmor_policy_hashes),
        "apparmor_profiles": _digests(apparmor_profiles, REQUIRED_ENFORCED_PROFILES),
        "scope_digest": scope_digest,
        "unit_files": _digests(unit_files, EXPOSURE_UNITS),
        "watch_unit_files": _digests(watch_unit_files, WATCH_UNITS),
    }


def _decoded(section) -> dict:
    expected_sets = {
        "apparmor_profiles": set(REQUIRED_ENFORCED_PROFILES),
        "unit_files": set(EXPOSURE_UNITS),
        "watch_unit_files": set(WATCH_UNITS),
    }
    if type(section) is not dict or set(section) != set(EXPOSURE_SECTION_KEYS):
        raise GenerationRefused(_phrase(EXPOSURE_SECTION_UNVERIFIABLE))
    if type(section["scope_digest"]) is not str or not _DIGEST.match(section["scope_digest"]):
        raise GenerationRefused(_phrase(EXPOSURE_SECTION_UNVERIFIABLE))
    for key, names in expected_sets.items():
        value = section[key]
        if (type(value) is not dict or set(value) != names
                or any(type(digest) is not str or not _DIGEST.match(digest)
                       for digest in value.values())):
            raise GenerationRefused(_phrase(EXPOSURE_SECTION_UNVERIFIABLE))
    _policy_hashes(section["apparmor_policy_hashes"])
    return section


def verify_exposure_section(
    section, *, unit_files: Mapping[str, bytes], watch_unit_files: Mapping[str, bytes],
    apparmor_profiles: Mapping[str, bytes], scope_file: bytes,
) -> None:
    """Refuse unless the recorded `section` describes exactly these bytes.

    `section` is the decoded section as a generation would record it; the
    rest is a fresh measurement (`measure_exposure_section_inputs`) and the
    scope file the pass rendered. Pure. A section not in its closed form, or
    a measurement or scope that is not, is `exposure_section_unverifiable`;
    a unit file, watch unit file, profile file or scope digest that differs
    is `exposure_section_differs`; nothing measured appears in either. The
    recorded `apparmor_policy_hashes` are checked for form only: they are
    compared with the kernel by `decoy_apparmor.policy_hash_refusal`, not
    with the files. A match describes the bytes; it is not an approval and
    grants nothing.
    """

    recorded = _decoded(section)
    expected = build_exposure_section(
        unit_files=unit_files, watch_unit_files=watch_unit_files,
        apparmor_profiles=apparmor_profiles,
        apparmor_policy_hashes=recorded["apparmor_policy_hashes"], scope_file=scope_file)
    if any(recorded[key] != expected[key] for key in
           ("unit_files", "watch_unit_files", "apparmor_profiles", "scope_digest")):
        raise GenerationRefused(_phrase(EXPOSURE_SECTION_DIFFERS))


def expected_policy_hashes(section) -> dict[str, str]:
    """The recorded section's `apparmor_policy_hashes`, as `expected`.

    A new dict of exactly the four profile names to 64 lowercase hex digits,
    the form `decoy_apparmor.policy_hash_refusal` and
    `exposure_lsm_withholding` take as `expected`. Pure; refuses
    (`exposure_section_unverifiable`) a section not in its closed form.
    **Called by nothing in this build** (G6).
    """

    return dict(_decoded(section)["apparmor_policy_hashes"])


def measure_apparmor_profile_files() -> dict[str, bytes]:
    """The four profile files in `/etc/apparmor.d`, as placed.

    Each path component root's and not group or other writable, no link
    followed; each file a regular root-owned file with one link, not group or
    other writable, non-empty, at most 1 MiB, stable while read (the unit
    files' reader, `activation_unit_files`). Refuses
    (`ExposureFilesRefused`) as `exposure_section_unverifiable` only.
    """

    try:
        fd = _unit_files._open(APPARMOR_DIRECTORY, required=True)
        try:
            return {name: _unit_files._read(fd, name)
                    for name in REQUIRED_ENFORCED_PROFILES}
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001 - redacted: the code and its phrase only
        raise ExposureFilesRefused(_phrase(EXPOSURE_SECTION_UNVERIFIABLE)) from None


def measure_exposure_section_inputs() -> tuple[dict[str, bytes], dict[str, bytes],
                                               dict[str, bytes]]:
    """`(unit_files, watch_unit_files, apparmor_profiles)`, as installed now.

    Read-only; refuses as each reader does, keeping its exception type
    (`UnitFilesRefused` and its subclasses) with the message
    `exposure_section_unverifiable: <phrase>`; the reader's own fixed label
    stays on the chained cause. **Not called by the pass in this build** (G6).
    """

    try:
        unit_files = measure_exposure_unit_files()
        watch_unit_files = require_watch_unit_files()
    except UnitFilesRefused as exc:
        raise type(exc)(_phrase(EXPOSURE_SECTION_UNVERIFIABLE)) from exc
    return unit_files, watch_unit_files, measure_apparmor_profile_files()
