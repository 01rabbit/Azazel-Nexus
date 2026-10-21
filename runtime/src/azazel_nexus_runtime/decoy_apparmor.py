"""The Deception Lite AppArmor profiles, and whether they are enforced (#196 G3).

`docs/deception-exposure-grant.md` §7 (L1, decided as §10 Q8): each of the
three exposure units names its own profile with `AppArmorProfile=` (no `-`,
so a start without the profile loaded fails), and the activation pass is to
withhold the tier unless AppArmor is enabled and every profile is loaded in
enforce mode (§5 item 4). This module holds the profile names, which the unit
renderer (`hardening.py`) and the packaged profiles (`packaging/apparmor/`)
must agree with, and the pure judgement of the kernel's listing.

**Not reached in this build.** `exposure_lsm_refusal` defines the reason
codes the pass will give, but nothing on the pass calls it:
`ActivationController._withholding_reason` still withholds the tier as
`isolation_evidence_absent` unconditionally, and wiring this in is part of
G6 (§9). `tests/unit/test_decoy_apparmor.py` fails the day the activation
pass, the controller or the library imports this module.

A leaf: it imports only `os`, so the unit renderer can take the names from
here without loading anything else. Nothing here is a parameter of the
product: the paths are constants (moved only by the tests, through the
private attributes below), there is no argument, environment variable or
flag that changes the judgement, and an unreadable listing withholds.
"""

from __future__ import annotations

import os

__all__ = [
    "DECOY_APPARMOR_PROFILES",
    "LSM_APPARMOR_DISABLED",
    "LSM_PROFILES_ABSENT",
    "LSM_PROFILES_NOT_ENFORCED",
    "LSM_PROFILES_UNREADABLE",
    "LSM_REASON_CODES",
    "REQUIRED_ENFORCED_PROFILES",
    "apparmor_profile_for",
    "exposure_lsm_refusal",
    "read_exposure_lsm",
]

#: Each exposure unit and the AppArmor profile it names, in the order the
#: units start. The profile file of the same name is in `packaging/apparmor/`
#: and is installed to `/etc/apparmor.d/`. The verify unit of §6 is G2's and
#: gets its own profile there.
DECOY_APPARMOR_PROFILES: tuple[tuple[str, str], ...] = (
    ("azazel-decoy-nsd.service", "azazel-decoy-nsd"),
    ("azazel-decoy-netd.service", "azazel-decoy-netd"),
    ("azazel-decoyd.service", "azazel-decoyd"),
)

#: The namespace unit's child profile, under which its `ip` commands run
#: (only `ip` may mount, the Python body may not).
NAMESPACE_IP_CHILD = "azazel-decoy-nsd//ip"

#: Every profile the kernel must list in enforce mode: the three, and the
#: namespace unit's child. A child is loaded with its parent, but it is
#: checked on its own: a listing that held the parent and not the child was
#: not made from the packaged file.
REQUIRED_ENFORCED_PROFILES: tuple[str, ...] = tuple(
    name for _, name in DECOY_APPARMOR_PROFILES) + (NAMESPACE_IP_CHILD,)

#: The withholding reasons, as `_withholding_reason` will give them (G6).
LSM_APPARMOR_DISABLED = "lsm_apparmor_disabled"
LSM_PROFILES_UNREADABLE = "lsm_profiles_unreadable"
LSM_PROFILES_ABSENT = "lsm_profiles_absent"
LSM_PROFILES_NOT_ENFORCED = "lsm_profiles_not_enforced"
LSM_REASON_CODES: tuple[str, ...] = (
    LSM_APPARMOR_DISABLED,
    LSM_PROFILES_UNREADABLE,
    LSM_PROFILES_ABSENT,
    LSM_PROFILES_NOT_ENFORCED,
)

#: The kernel's active LSMs, comma-separated (securityfs).
_LSM = "/sys/kernel/security/lsm"
#: AppArmor's listing of loaded profiles, one `name (mode)` per line. It
#: exists only while AppArmor is initialised; reading it needs root
#: (*inferred*: euid 0 in the initial user namespace, no capability).
_PROFILES = "/sys/kernel/security/apparmor/profiles"
#: More than this is not a listing this judgement reads.
_LSM_LIMIT = 4096
_PROFILES_LIMIT = 1024 * 1024

_ENFORCE = "enforce"


def apparmor_profile_for(unit: str) -> str:
    """The profile `unit` names in `AppArmorProfile=`, or "" for none."""

    return dict(DECOY_APPARMOR_PROFILES).get(unit, "")


def _listing(raw: bytes) -> dict[str, set[str]] | None:
    """`name -> {modes}`, or None when any line is not `name (mode)`."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    modes: dict[str, set[str]] = {}
    for line in text.split("\n"):
        if not line:
            continue
        name, separator, rest = line.rpartition(" (")
        if (not separator or not name or name != name.strip()
                or not rest.endswith(")")):
            return None
        mode = rest[:-1]
        if not mode or not mode.isascii() or not mode.replace("_", "").isalpha():
            return None
        modes.setdefault(name, set()).add(mode)
    return modes


def exposure_lsm_refusal(lsm: bytes | None, profiles: bytes | None) -> str | None:
    """Why the exposure tier would be withheld for the LSM, or None.

    `lsm` is the content of `/sys/kernel/security/lsm`, `profiles` that of
    `/sys/kernel/security/apparmor/profiles`; None for a file that is absent
    or could not be read. Pure: it reads nothing and judges only its two
    arguments. In order, the first that holds is the reason:

    * `lsm_apparmor_disabled`: AppArmor is not among the active LSMs, or its
      listing does not exist (booted with `apparmor=0`, an `lsm=` list
      without it, or no securityfs);
    * `lsm_profiles_unreadable`: a listing out of bounds or not in the
      kernel's `name (mode)` form;
    * `lsm_profiles_absent`: a required profile is not listed;
    * `lsm_profiles_not_enforced`: a required profile is listed in any mode
      other than `enforce` (complain, kill, unconfined, ...), on any line.
    """

    if lsm is None or profiles is None or len(lsm) > _LSM_LIMIT:
        return (f"{LSM_APPARMOR_DISABLED}: AppArmor is not enabled, so no "
                "Deception Lite profile confines the exposure units")
    try:
        active = lsm.decode("ascii", errors="strict").strip().split(",")
    except UnicodeDecodeError:
        active = []
    if "apparmor" not in active:
        return (f"{LSM_APPARMOR_DISABLED}: AppArmor is not among the active "
                "LSMs, so no Deception Lite profile confines the exposure units")
    if len(profiles) > _PROFILES_LIMIT:
        return (f"{LSM_PROFILES_UNREADABLE}: the AppArmor profile listing is "
                "larger than this check reads")
    listing = _listing(profiles)
    if listing is None:
        return (f"{LSM_PROFILES_UNREADABLE}: the AppArmor profile listing is "
                "not in the kernel's form")
    absent = [name for name in REQUIRED_ENFORCED_PROFILES if name not in listing]
    if absent:
        return (f"{LSM_PROFILES_ABSENT}: {len(absent)} of the "
                f"{len(REQUIRED_ENFORCED_PROFILES)} Deception Lite AppArmor "
                "profiles are not loaded")
    lax = [name for name in REQUIRED_ENFORCED_PROFILES
           if listing[name] != {_ENFORCE}]
    if lax:
        return (f"{LSM_PROFILES_NOT_ENFORCED}: {len(lax)} of the "
                f"{len(REQUIRED_ENFORCED_PROFILES)} Deception Lite AppArmor "
                "profiles are loaded in a mode other than enforce")
    return None


def _read(path: str, limit: int) -> bytes | None:
    """At most `limit + 1` bytes of a regular file, or None."""

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        chunks: list[bytes] = []
        size = 0
        while size <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def read_exposure_lsm() -> tuple[bytes | None, bytes | None]:
    """The two securityfs files `exposure_lsm_refusal` judges, as read now.

    Read-only, bounded (one byte past each limit, so an oversized file is
    judged oversized rather than cut to fit). A file that is absent or cannot
    be read is None, which withholds.
    """

    return _read(_LSM, _LSM_LIMIT), _read(_PROFILES, _PROFILES_LIMIT)
