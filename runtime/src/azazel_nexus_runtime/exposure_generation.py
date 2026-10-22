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
write, with one link, stable while read.

* `build_exposure_section` is pure: from supplied bytes to the section.
* `verify_exposure_section` is pure: a recorded section against a fresh
  measurement; any difference refuses (`GenerationRefused`, fixed labels).
* `measure_exposure_section_inputs` is the reader: the exposure unit files
  through `activation_unit_files.measure_exposure_unit_files` (content and
  override checks included), the watch files through
  `activation_unit_files.require_watch_unit_files` (byte for byte against
  the rendering, no override, no mask; it returns what it read, so the
  digest is of exactly the accepted bytes), and the profile files. The scope
  file is not read here: the pass renders it in G6 and passes its bytes.

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
    "EXPOSURE_SECTION_KEYS",
    "ExposureFilesRefused",
    "build_exposure_section",
    "measure_apparmor_profile_files",
    "measure_exposure_section_inputs",
    "verify_exposure_section",
]

#: Where the installer places the profiles (`install_platform.APPARMOR_DIRECTORY`;
#: a test keeps them equal).
APPARMOR_DIRECTORY = "/etc/apparmor.d"

#: The section's keys, all required, no other.
EXPOSURE_SECTION_KEYS = ("apparmor_profiles", "scope_digest", "unit_files",
                         "watch_unit_files")

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_FILE_LIMIT = 1 << 20


class ExposureFilesRefused(UnitFilesRefused):
    """An AppArmor profile file is missing, unprotected, linked or changing."""


def _digest(data: bytes) -> str:
    return "sha256:" + sha256(data).hexdigest()


def _digests(files, names) -> dict[str, str]:
    snapshot = dict(files) if isinstance(files, Mapping) else None
    if (snapshot is None or set(snapshot) != set(names) or any(
            type(data) is not bytes or not 0 < len(data) <= _FILE_LIMIT
            for data in snapshot.values())):
        raise GenerationRefused("exposure section files must match their set exactly")
    return {name: _digest(snapshot[name]) for name in sorted(names)}


def build_exposure_section(
    *, unit_files: Mapping[str, bytes], watch_unit_files: Mapping[str, bytes],
    apparmor_profiles: Mapping[str, bytes], scope_file: bytes,
) -> dict:
    """The exposure section for these bytes; nothing is read or written.

    `unit_files` maps exactly the three exposure units, `watch_unit_files`
    exactly the three watch units, `apparmor_profiles` exactly the four
    profile names, each to the file's bytes; `scope_file` is the rendered
    scope file, accepted only as `decoy_scope.parse_scope_file` accepts it.
    Refuses (`GenerationRefused`) on any other set, an empty or oversized
    file, or a refused scope.
    """

    try:
        scope_digest = parse_scope_file(scope_file).scope_digest
    except DecoyScopeRefused:
        raise GenerationRefused("exposure section scope file refused") from None
    return {
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
        raise GenerationRefused("exposure section fields refused")
    if type(section["scope_digest"]) is not str or not _DIGEST.match(section["scope_digest"]):
        raise GenerationRefused("exposure section scope digest refused")
    for key, names in expected_sets.items():
        value = section[key]
        if (type(value) is not dict or set(value) != names
                or any(type(digest) is not str or not _DIGEST.match(digest)
                       for digest in value.values())):
            raise GenerationRefused("exposure section digests refused")
    return section


def verify_exposure_section(
    section, *, unit_files: Mapping[str, bytes], watch_unit_files: Mapping[str, bytes],
    apparmor_profiles: Mapping[str, bytes], scope_file: bytes,
) -> None:
    """Refuse unless the recorded `section` describes exactly these bytes.

    `section` is the decoded section as a generation would record it; the
    rest is a fresh measurement (`measure_exposure_section_inputs`) and the
    scope file the pass rendered. Pure. Each difference has its own fixed
    label; nothing measured appears in it. A match describes the bytes; it
    is not an approval and grants nothing.
    """

    recorded = _decoded(section)
    expected = build_exposure_section(
        unit_files=unit_files, watch_unit_files=watch_unit_files,
        apparmor_profiles=apparmor_profiles, scope_file=scope_file)
    if recorded["unit_files"] != expected["unit_files"]:
        raise GenerationRefused("exposure unit file digest differs")
    if recorded["watch_unit_files"] != expected["watch_unit_files"]:
        raise GenerationRefused("watch unit file digest differs")
    if recorded["apparmor_profiles"] != expected["apparmor_profiles"]:
        raise GenerationRefused("AppArmor profile file digest differs")
    if recorded["scope_digest"] != expected["scope_digest"]:
        raise GenerationRefused("exposure scope digest differs")


def measure_apparmor_profile_files() -> dict[str, bytes]:
    """The four profile files in `/etc/apparmor.d`, as placed.

    Each path component root's and not group or other writable, no link
    followed; each file a regular root-owned file with one link, not group or
    other writable, non-empty, at most 1 MiB, stable while read (the unit
    files' reader, `activation_unit_files`). Fixed labels only.
    """

    try:
        fd = _unit_files._open(APPARMOR_DIRECTORY, required=True)
        try:
            return {name: _unit_files._read(fd, name)
                    for name in REQUIRED_ENFORCED_PROFILES}
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001 - redacted: labels only
        raise ExposureFilesRefused("AppArmor profile files unavailable") from None


def measure_exposure_section_inputs() -> tuple[dict[str, bytes], dict[str, bytes],
                                               dict[str, bytes]]:
    """`(unit_files, watch_unit_files, apparmor_profiles)`, as installed now.

    Read-only; refuses (`UnitFilesRefused` and its subclasses) as each
    reader does. **Not called by the pass in this build** (G6).
    """

    unit_files = measure_exposure_unit_files()
    watch_unit_files = require_watch_unit_files()
    return unit_files, watch_unit_files, measure_apparmor_profile_files()
