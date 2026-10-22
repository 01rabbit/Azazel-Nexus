"""The Deception Lite AppArmor profiles, and whether they are enforced (#196 G3).

`docs/deception-exposure-grant.md` §7 (L1, decided as §10 Q8): each of the
three exposure units, and the verify unit of §6 (G2), names its own profile
with `AppArmorProfile=` (no `-`) and carries `AssertSecurity=apparmor`. With AppArmor enabled, a start without
the profile loaded fails; with AppArmor disabled systemd ignores
`AppArmorProfile=`, and the assertion fails the start instead, so the unit
never runs unconfined. The activation pass is to withhold the tier unless
AppArmor is enabled and every profile is loaded in enforce mode (§5 item 4).
This module holds the profile names, which the unit renderer
(`hardening.py`) and the packaged profiles (`packaging/apparmor/`) must agree
with, the paths the profiles let the Python body read (the installer checks
the staged wrappers against them), and the pure judgement of the kernel's
listing.

**Not reached in this build.** `exposure_lsm_refusal` defines the reason
codes the pass will give, but nothing on the pass calls it:
`ActivationController._withholding_reason` still withholds the tier as
`isolation_evidence_absent` unconditionally, and wiring this in is part of
G6 (§9). `tests/unit/test_decoy_apparmor.py` fails the day the activation
pass, the controller or the library imports this module.

A leaf: it imports only `os` and `errno`, so the unit renderer can take the
names from here without loading anything else. Nothing here is a parameter
of the product: the paths are constants (moved only by the tests, through
the private attributes below), there is no argument, environment variable or
flag that changes the judgement, and an unreadable listing withholds.
"""

from __future__ import annotations

import errno
import os

__all__ = [
    "DECOY_APPARMOR_PROFILES",
    "LSM_APPARMOR_DISABLED",
    "LSM_PROFILES_ABSENT",
    "LSM_PROFILES_NOT_ENFORCED",
    "LSM_PROFILES_UNREADABLE",
    "LSM_REASON_CODES",
    "PROFILE_INTERPRETER",
    "PROFILE_PYTHON_ROOTS",
    "REQUIRED_ENFORCED_PROFILES",
    "UNREADABLE",
    "apparmor_profile_for",
    "exposure_lsm_refusal",
    "read_exposure_lsm",
    "wrapper_profile_refusal",
]

#: Each exposure unit, and the verify unit of §6 (#196 G2), with the
#: AppArmor profile it names, in the order the units start. The profile file
#: of the same name is in `packaging/apparmor/` and is installed to
#: `/etc/apparmor.d/`. The verify unit runs the helper's executable but
#: writes nothing, so it has a profile of its own, the helper's without its
#: one writable place.
DECOY_APPARMOR_PROFILES: tuple[tuple[str, str], ...] = (
    ("azazel-decoy-nsd.service", "azazel-decoy-nsd"),
    ("azazel-decoy-netd.service", "azazel-decoy-netd"),
    ("azazel-decoy-verify.service", "azazel-decoy-verify"),
    ("azazel-decoyd.service", "azazel-decoyd"),
)

#: The namespace unit's child profile, under which its `ip` commands run
#: (only `ip` holds the capabilities and may mount; the Python body may not).
NAMESPACE_IP_CHILD = "azazel-decoy-nsd//ip"

#: Every profile the kernel must list in enforce mode: the four, and the
#: namespace unit's child. A child is loaded with its parent, but it is
#: checked on its own: a listing that held the parent and not the child was
#: not made from the packaged file.
REQUIRED_ENFORCED_PROFILES: tuple[str, ...] = tuple(
    name for _, name in DECOY_APPARMOR_PROFILES) + (NAMESPACE_IP_CHILD,)

#: The one interpreter the profiles let the Python body execute and map
#: (`python_profile.BASE_INTERPRETER`, a test keeps them equal): the staged
#: wrapper's interpreter must resolve to it.
PROFILE_INTERPRETER = "/usr/bin/python3.13"

#: The only places the profiles let the Python body read its code from:
#: Debian's standard library and the product's venv (operations.md). Every
#: import path of a staged decoy wrapper must resolve under one of them; the
#: installer refuses otherwise. `/usr/local/lib/python3*` and
#: `/usr/lib/python3/dist-packages` are deliberately absent: the wrappers
#: replace `sys.path` and never need them.
PROFILE_PYTHON_ROOTS: tuple[str, ...] = ("/usr/lib/python3.13", "/opt/azazel-nexus/venv")

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


class _Unreadable:
    """A file that exists but could not be read (EACCES, EIO, a link, ...)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNREADABLE"


#: What `read_exposure_lsm` gives for a file it could not read, as opposed to
#: None for one that does not exist.
UNREADABLE = _Unreadable()

#: The kernel's active LSMs, comma-separated (securityfs).
_LSM = "/sys/kernel/security/lsm"
#: AppArmor's listing of loaded profiles, one `name (mode)` per line. It
#: exists only while AppArmor is initialised; reading it needs root
#: (*inferred*: euid 0 in the initial user namespace, no capability).
_PROFILES = "/sys/kernel/security/apparmor/profiles"
#: More than this is not a listing this judgement reads.
_LSM_LIMIT = 4096
_PROFILES_LIMIT = 1024 * 1024

_ENFORCE = b"enforce"
#: Absent, as opposed to present and unreadable.
_ABSENT = frozenset({errno.ENOENT, errno.ENOTDIR})


def apparmor_profile_for(unit: str) -> str:
    """The profile `unit` names in `AppArmorProfile=`, or "" for none."""

    return dict(DECOY_APPARMOR_PROFILES).get(unit, "")


def _modes(raw: bytes) -> dict[bytes, set[bytes]] | None:
    """`required name -> {modes}`; None when a required name's line is malformed.

    Only the lines of the required profiles are read strictly: each must be
    exactly `name (mode)`, the mode lowercase ASCII letters and `_`. Every
    other line (another profile, another policy namespace, a format this
    check does not know) is skipped: it says nothing about these profiles.
    """

    required = {name.encode("ascii") for name in REQUIRED_ENFORCED_PROFILES}
    modes: dict[bytes, set[bytes]] = {}
    for line in raw.split(b"\n"):
        name, separator, rest = line.rpartition(b" (")
        if not separator:
            # `name mode` or no mode at all: refused if it names a required
            # profile, ignored otherwise.
            if line.split(b" ", 1)[0] in required or line in required:
                return None
            continue
        if name.strip() not in required:
            continue
        mode = rest[:-1]
        if (name not in required or not rest.endswith(b")") or not mode
                or any(not (97 <= byte <= 122 or byte == 95) for byte in mode)):
            return None
        modes.setdefault(name, set()).add(mode)
    return modes


def exposure_lsm_refusal(lsm, profiles) -> str | None:
    """Why the exposure tier would be withheld for the LSM, or None.

    `lsm` is the content of `/sys/kernel/security/lsm`, `profiles` that of
    `/sys/kernel/security/apparmor/profiles`: bytes, None for a file that
    does not exist, or `UNREADABLE` for one that exists and could not be
    read. Pure: it reads nothing and judges only its two arguments. In
    order, the first that holds is the reason:

    * `lsm_apparmor_disabled`: no LSM list, AppArmor not among the active
      LSMs, or no listing (booted with `apparmor=0`, an `lsm=` list without
      it, or no securityfs);
    * `lsm_profiles_unreadable`: a file present and not readable, a file out
      of bounds, or a required profile's line not in the kernel's
      `name (mode)` form;
    * `lsm_profiles_absent`: a required profile is not listed;
    * `lsm_profiles_not_enforced`: a required profile is listed in any mode
      other than `enforce` (complain, kill, unconfined, ...), on any line.
    """

    if lsm is UNREADABLE or (type(lsm) is bytes and len(lsm) > _LSM_LIMIT):
        return (f"{LSM_PROFILES_UNREADABLE}: the kernel's LSM list could not be "
                "read")
    if type(lsm) is not bytes:
        return (f"{LSM_APPARMOR_DISABLED}: the kernel lists no LSM, so no "
                "Deception Lite profile confines the exposure units")
    if b"apparmor" not in lsm.strip().split(b","):
        return (f"{LSM_APPARMOR_DISABLED}: AppArmor is not among the active "
                "LSMs, so no Deception Lite profile confines the exposure units")
    if profiles is UNREADABLE:
        return (f"{LSM_PROFILES_UNREADABLE}: the AppArmor profile listing could "
                "not be read")
    if type(profiles) is not bytes:
        return (f"{LSM_APPARMOR_DISABLED}: AppArmor has no profile listing, so "
                "no Deception Lite profile confines the exposure units")
    if len(profiles) > _PROFILES_LIMIT:
        return (f"{LSM_PROFILES_UNREADABLE}: the AppArmor profile listing is "
                "larger than this check reads")
    listing = _modes(profiles)
    if listing is None:
        return (f"{LSM_PROFILES_UNREADABLE}: a Deception Lite profile's line in "
                "the AppArmor listing is not in the kernel's form")
    names = [name.encode("ascii") for name in REQUIRED_ENFORCED_PROFILES]
    absent = [name for name in names if name not in listing]
    if absent:
        return (f"{LSM_PROFILES_ABSENT}: {len(absent)} of the {len(names)} "
                "Deception Lite AppArmor profiles are not loaded")
    lax = [name for name in names if listing[name] != {_ENFORCE}]
    if lax:
        return (f"{LSM_PROFILES_NOT_ENFORCED}: {len(lax)} of the {len(names)} "
                "Deception Lite AppArmor profiles are loaded in a mode other "
                "than enforce")
    return None


def _read(path: str, limit: int):
    """At most `limit + 1` bytes of the file; None if absent, else UNREADABLE."""

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError as error:
        return None if error.errno in _ABSENT else UNREADABLE
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
        return UNREADABLE
    finally:
        os.close(fd)


def read_exposure_lsm():
    """The two securityfs files `exposure_lsm_refusal` judges, as read now.

    Read-only, bounded (one byte past each limit, so an oversized file is
    judged oversized rather than cut to fit), no link followed. Each is
    bytes, None when the file does not exist, or `UNREADABLE` when it exists
    and could not be read (EACCES, EIO, a link); both withhold.
    """

    return _read(_LSM, _LSM_LIMIT), _read(_PROFILES, _PROFILES_LIMIT)


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def wrapper_profile_refusal(interpreter: str, import_paths) -> str | None:
    """Why a staged decoy wrapper would run outside its profile, or None.

    `interpreter` and `import_paths` are the wrapper's, **resolved** (the
    kernel and AppArmor see the resolved file). Pure. The interpreter must
    be exactly `PROFILE_INTERPRETER` and every import path under one of
    `PROFILE_PYTHON_ROOTS`; anything else would be refused by the profile at
    the first start, so the installer refuses it first.
    """

    if interpreter != PROFILE_INTERPRETER:
        return ("the wrapper's interpreter does not resolve to "
                f"{PROFILE_INTERPRETER}, the one the AppArmor profiles allow")
    outside = [path for path in import_paths
               if not any(_within(path, root) for root in PROFILE_PYTHON_ROOTS)]
    if not import_paths or outside:
        return (f"{len(outside)} of the wrapper's import paths resolve outside "
                f"{', '.join(PROFILE_PYTHON_ROOTS)}, the places the AppArmor "
                "profiles let it read")
    return None
