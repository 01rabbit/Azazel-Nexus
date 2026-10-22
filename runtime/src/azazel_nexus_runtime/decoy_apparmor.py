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

**G6 preparation (implemented, not wired).** The two items §7 leaves to G6
are here as pure judgements and a bounded reader, called by nothing:
`loaded_unit_profile_refusal` compares each unit's loaded `AppArmorProfile`
with its declared profile (the value the bus gives; this module reads no
bus), and `policy_hash_refusal` compares the kernel's per-profile policy
hash with an expected hash. The kernel's file is
`/sys/kernel/security/apparmor/policy/profiles/*/raw_sha256`, the SHA-256 of
the compiled policy the parser loaded; on the VM (Debian 13, kernel 6.12,
AppArmor 4.1; a mechanism check, not hardware evidence) it equalled the
SHA-256 of `apparmor_parser -Q -o` output for each decoy profile (§7). The
expected hashes take the form of the generation's exposure section field
`apparmor_policy_hashes` (`exposure_generation.expected_policy_hashes` gives
that field as `expected`). G6's installer records them; this build records
and derives none, so the comparison withholds as `lsm_policy_unverifiable`
(fail closed). `exposure_lsm_withholding` puts the three judgements in one
order and `read_exposure_lsm_policy` makes the three securityfs reads in one
call.

**What it says.** Reason codes only, each a fixed word with a fixed phrase
(`LSM_PHRASES`), as `"<code>: <phrase>"`; never a profile name, a unit name,
a count or a hash.

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
    "LSM_LOADED_REASON_CODES",
    "LSM_PHRASES",
    "LSM_POLICY_DIFFERS",
    "LSM_POLICY_UNVERIFIABLE",
    "LSM_PROFILE_CHILD_PRESENT",
    "LSM_PROFILES_ABSENT",
    "LSM_PROFILES_NOT_ENFORCED",
    "LSM_PROFILES_UNREADABLE",
    "LSM_REASON_CODES",
    "LSM_UNIT_PROFILE_DIFFERS",
    "PROFILE_INTERPRETER",
    "PROFILE_PYTHON_ROOTS",
    "REQUIRED_ENFORCED_PROFILES",
    "UNREADABLE",
    "apparmor_profile_for",
    "exposure_lsm_refusal",
    "exposure_lsm_withholding",
    "loaded_unit_profile_refusal",
    "policy_hash_refusal",
    "read_exposure_lsm",
    "read_exposure_lsm_policy",
    "read_policy_hashes",
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

#: Every profile the kernel must list in enforce mode: the four. None has a
#: child profile (G4 follow-up): the namespace unit runs `/usr/bin/ip`
#: directly under its one profile, because under `NoNewPrivileges=yes` the
#: kernel refused a transition from a Python body into a wider child
#: (`docs/deception-exposure-grant.md` §11).
REQUIRED_ENFORCED_PROFILES: tuple[str, ...] = tuple(
    name for _, name in DECOY_APPARMOR_PROFILES)

#: The one interpreter the profiles of the Python units (the helper, the
#: verify unit and the decoy; the namespace unit runs no Python) let the body
#: execute and map (`python_profile.BASE_INTERPRETER`, a test keeps them
#: equal): the staged wrapper's interpreter must resolve to it.
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

#: The reasons of the loaded-policy comparison (§7 "Left to G6"), given after
#: `LSM_REASON_CODES` by `exposure_lsm_withholding`. Not reached in this
#: build either. `lsm_profile_child_present` is judged over the G3 listing
#: (`exposure_lsm_refusal`, after its own codes): a child profile or hat of a
#: required profile is loaded (review of #196 G6 preparation, L5 and
#: finding 5 of the review of #303).
LSM_PROFILE_CHILD_PRESENT = "lsm_profile_child_present"
LSM_UNIT_PROFILE_DIFFERS = "lsm_unit_profile_differs"
LSM_POLICY_UNVERIFIABLE = "lsm_policy_unverifiable"
LSM_POLICY_DIFFERS = "lsm_policy_differs"
LSM_LOADED_REASON_CODES: tuple[str, ...] = (
    LSM_PROFILE_CHILD_PRESENT,
    LSM_UNIT_PROFILE_DIFFERS,
    LSM_POLICY_UNVERIFIABLE,
    LSM_POLICY_DIFFERS,
)

#: Each code's fixed phrase: no profile or unit name, count or hash.
LSM_PHRASES: dict[str, str] = {
    LSM_APPARMOR_DISABLED: ("AppArmor is not among the active LSMs or shows no "
                            "profile listing, so no Deception Lite profile "
                            "confines the exposure units"),
    LSM_PROFILES_UNREADABLE: ("the kernel's LSM list or AppArmor profile listing "
                              "could not be read whole, or lists a Deception Lite "
                              "profile in a form this check does not judge"),
    LSM_PROFILES_ABSENT: "a Deception Lite AppArmor profile is not loaded",
    LSM_PROFILES_NOT_ENFORCED: ("a Deception Lite AppArmor profile is loaded in a "
                                "mode other than enforce"),
    LSM_PROFILE_CHILD_PRESENT: ("a child profile or hat of a Deception Lite "
                                "AppArmor profile is loaded; none is expected, and "
                                "it stays until a reboot or until its parent is "
                                "removed from the kernel and loaded again"),
    LSM_UNIT_PROFILE_DIFFERS: ("the loaded definitions read are not exactly the "
                               "Deception Lite units, or one is loaded without "
                               "exactly its AppArmor profile"),
    LSM_POLICY_UNVERIFIABLE: ("no expected policy hash of the Deception Lite "
                              "profiles is recorded, or the kernel shows no "
                              "readable policy hash listed exactly once for one "
                              "of them"),
    LSM_POLICY_DIFFERS: ("a Deception Lite profile loaded in the kernel is not "
                         "the one whose policy hash was recorded"),
}


def _lsm(code: str) -> str:
    return f"{code}: {LSM_PHRASES[code]}"


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
#: The kernel's per-profile policy directory: one entry per loaded profile of
#: the root namespace, each holding `name` (the profile's name and a newline)
#: and `raw_sha256` (the hex SHA-256 of the compiled policy the parser loaded,
#: the entry's `raw_data`, and a newline). Read on the VM (Debian 13, kernel
#: 6.12, AppArmor 4.1; a mechanism check, not hardware evidence): the entry
#: holds `attach mode name raw_abi raw_data raw_sha256 sha256` and no `sha1`;
#: `raw_sha256` equalled the SHA-256 of `raw_data` and of
#: `apparmor_parser -Q -o` output for the placed file, while `sha256` is
#: another value, equal to neither nor to the SHA-256 of the file in
#: `/etc/apparmor.d`, so it is not read. An absent directory or file
#: withholds as `lsm_policy_unverifiable`. On that kernel `raw_sha256` is a
#: symbolic link, `raw_sha256 -> ../../raw_data/<n>/sha256` (as are `raw_abi`
#: and `raw_data`; `name` and `sha256` are regular files); see
#: `_read_raw_sha256` for how it is read without following it.
_POLICY_PROFILES = "/sys/kernel/security/apparmor/policy/profiles"
#: Where the kernel keeps each loaded policy's raw data, `<n>/sha256` among
#: it: the directory `raw_sha256`'s link names, relative to a profile's
#: entry (`../../raw_data`), resolved here as a fixed path rather than by
#: following the link.
_POLICY_RAW_DATA = "/sys/kernel/security/apparmor/policy/raw_data"
_RAW_SHA256_PREFIX = "../../raw_data/"
_RAW_SHA256_SUFFIX = "/sha256"
#: A decimal number of at most this many digits names a raw data directory.
_RAW_DATA_DIGITS = 20
_POLICY_ENTRY_LIMIT = 4096
_POLICY_NAME_LIMIT = 4096
_POLICY_HASH_LIMIT = 256
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
    other line (another profile, a child or hat, which `_children` judges,
    another policy namespace, a format this check does not know) is skipped
    here.
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


def _children(raw: bytes) -> bool:
    """Whether a line of a child profile or hat of a required profile is listed.

    `<name>//...` in any mode or form, leading blanks ignored, such as a
    stale `azazel-decoy-nsd//ip` from before the G4 follow-up: replacing the
    parent leaves it in the kernel (observed on the VM). Another policy
    namespace's line (`:ns:<name>//...`) and a look-alike's are not ours.
    """

    nested = tuple(name.encode("ascii") + b"//" for name in REQUIRED_ENFORCED_PROFILES)
    return any(line.lstrip().startswith(nested) for line in raw.split(b"\n"))


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
      other than `enforce` (complain, kill, unconfined, ...), on any line;
    * `lsm_profile_child_present`: a line of a child profile or hat of a
      required profile (`<name>//...`, any mode) is listed (`_children`).

    Each as `"<code>: <phrase>"` with the code's one phrase (`LSM_PHRASES`).
    """

    if lsm is UNREADABLE or (type(lsm) is bytes and len(lsm) > _LSM_LIMIT):
        return _lsm(LSM_PROFILES_UNREADABLE)
    if type(lsm) is not bytes or b"apparmor" not in lsm.strip().split(b","):
        return _lsm(LSM_APPARMOR_DISABLED)
    if profiles is UNREADABLE:
        return _lsm(LSM_PROFILES_UNREADABLE)
    if type(profiles) is not bytes:
        return _lsm(LSM_APPARMOR_DISABLED)
    if len(profiles) > _PROFILES_LIMIT:
        return _lsm(LSM_PROFILES_UNREADABLE)
    listing = _modes(profiles)
    if listing is None:
        return _lsm(LSM_PROFILES_UNREADABLE)
    names = [name.encode("ascii") for name in REQUIRED_ENFORCED_PROFILES]
    if any(name not in listing for name in names):
        return _lsm(LSM_PROFILES_ABSENT)
    if any(listing[name] != {_ENFORCE} for name in names):
        return _lsm(LSM_PROFILES_NOT_ENFORCED)
    if _children(profiles):
        return _lsm(LSM_PROFILE_CHILD_PRESENT)
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


#: The units whose manager state may be `masked`: the three exposure units,
#: masked until a pass grants them. The verify unit is never masked (a masked
#: watch unit is refused by `activation_unit_files.require_watch_unit_files`).
_MASKABLE_UNITS = frozenset(unit for unit, _ in DECOY_APPARMOR_PROFILES
                            if unit != "azazel-decoy-verify.service")


def loaded_unit_profile_refusal(loaded) -> str | None:
    """Why the manager's loaded units would withhold the tier, or None (§7 (a)).

    `loaded` maps each unit of `DECOY_APPARMOR_PROFILES`, exactly those four,
    to what the manager holds: None when it holds no unit object (a later
    load reads the files the pass checked), or `{"LoadState": str,
    "AppArmorProfile": (bool, str)}`, the Unit interface's `LoadState` and the
    Service interface's `AppArmorProfile` (D-Bus `(bs)`: the `-` prefix and
    the name, per org.freedesktop.systemd1(5); *inferred* until read on the
    VM). Pure: it reads nothing. A loaded unit must name exactly its profile
    without `-`; an exposure unit may be `masked` (it cannot start); every
    other state, shape or value is `lsm_unit_profile_differs`.

    **What it does not see (review of #294).** Passing `masked` does not
    look at `ActiveState`: a unit masked while it runs passes here. That
    state, §6.3 (a) "masked and still running", is judged by
    `decoy_residue` (a separate PR, #293), not by this function. None is
    passed only because the G6 reader maps to None the one specific error
    that means "no unit object" (`NoSuchUnit` from `GetUnit`) and refuses
    every other error; that reader and its tests are G6's.
    """

    expected = dict(DECOY_APPARMOR_PROFILES)
    if type(loaded) is not dict or set(loaded) != set(expected):
        return _lsm(LSM_UNIT_PROFILE_DIFFERS)
    for unit, profile in DECOY_APPARMOR_PROFILES:
        value = loaded[unit]
        if value is None:
            continue
        if type(value) is not dict or set(value) != {"LoadState", "AppArmorProfile"}:
            return _lsm(LSM_UNIT_PROFILE_DIFFERS)
        state, attached = value["LoadState"], value["AppArmorProfile"]
        if state == "masked" and unit in _MASKABLE_UNITS:
            continue
        if (state != "loaded" or type(attached) is not tuple or len(attached) != 2
                or attached[0] is not False or type(attached[1]) is not str
                or attached[1] != profile):
            return _lsm(LSM_UNIT_PROFILE_DIFFERS)
    return None


def _hex_digest(value) -> bool:
    return (type(value) is str and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def policy_hash_refusal(entries, expected) -> str | None:
    """Why the kernel's loaded policy would withhold the tier, or None (§7 (b)).

    `entries` is what `read_policy_hashes()` gives: None when the kernel's
    per-profile directory does not exist, `UNREADABLE`, or a tuple of
    `(name, raw_sha256)`, each bytes, None (absent) or `UNREADABLE`.
    `expected` maps each of `REQUIRED_ENFORCED_PROFILES` to the 64-hex
    SHA-256 the kernel should show, or is None: the generation's exposure
    section field `apparmor_policy_hashes`, as
    `exposure_generation.expected_policy_hashes` gives it (G6: the installer
    records there the SHA-256 of its `apparmor_parser -Q -o` output). Pure.
    In order:

    * `lsm_policy_unverifiable`: no expected hashes (**this build records
      none**; G6), no directory, an unreadable one, an entry whose name
      cannot be read, a required profile listed not exactly once, or its
      hash absent, empty, unreadable or not one lowercase hex digest and a
      newline;
    * `lsm_policy_differs`: a required profile's hash is not the expected one.

    Each as `"<code>: <phrase>"` with the code's one phrase (`LSM_PHRASES`).
    """

    names = REQUIRED_ENFORCED_PROFILES
    if (type(expected) is not dict or set(expected) != set(names)
            or not all(_hex_digest(expected[name]) for name in names)):
        return _lsm(LSM_POLICY_UNVERIFIABLE)
    if (entries is None or entries is UNREADABLE or type(entries) is not tuple
            or len(entries) > _POLICY_ENTRY_LIMIT):
        return _lsm(LSM_POLICY_UNVERIFIABLE)
    found: dict[bytes, list] = {}
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 2 or type(entry[0]) is not bytes:
            return _lsm(LSM_POLICY_UNVERIFIABLE)
        found.setdefault(entry[0], []).append(entry[1])
    differ = False
    for name in names:
        hashes = found.get(name.encode("ascii") + b"\n", [])
        if len(hashes) != 1:
            return _lsm(LSM_POLICY_UNVERIFIABLE)
        raw = hashes[0]
        if (type(raw) is not bytes or not raw.endswith(b"\n")
                or not _hex_digest(raw[:-1].decode("ascii", "replace"))):
            return _lsm(LSM_POLICY_UNVERIFIABLE)
        if raw[:-1].decode("ascii") != expected[name]:
            differ = True
    return _lsm(LSM_POLICY_DIFFERS) if differ else None


_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _read_at(directory_fd: int, name: str, limit: int):
    """One bounded read relative to an open directory; None if absent, else UNREADABLE."""

    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=directory_fd)
    except OSError as error:
        return None if error.errno in _ABSENT else UNREADABLE
    try:
        data = os.read(fd, limit + 1)
        return UNREADABLE if len(data) > limit else data
    except OSError:
        return UNREADABLE
    finally:
        os.close(fd)


def _raw_data_number(target) -> str | None:
    """The `<n>` of exactly `../../raw_data/<n>/sha256`, `<n>` decimal, else None."""

    if (type(target) is not str or not target.startswith(_RAW_SHA256_PREFIX)
            or not target.endswith(_RAW_SHA256_SUFFIX)):
        return None
    number = target[len(_RAW_SHA256_PREFIX):-len(_RAW_SHA256_SUFFIX)]
    if (not 0 < len(number) <= _RAW_DATA_DIGITS
            or not all(c in "0123456789" for c in number)
            or (len(number) > 1 and number[0] == "0")):
        return None
    return number


def _read_raw_sha256(entry_fd: int):
    """An entry's `raw_sha256`: None if absent, `UNREADABLE`, or its bytes.

    On the VM's kernel it is a link to `../../raw_data/<n>/sha256`. The link
    is read (`readlink`), not followed: a target of exactly that form, `<n>`
    decimal, is read as `_POLICY_RAW_DATA/<n>/sha256`, each step opened
    without following a link; any other target (`../../../etc/x`, an
    absolute path, a name that is not a number) is `UNREADABLE`. A target
    that does not exist is None, as an absent file. Only the observed form,
    a link, is accepted: a regular file (`readlink` fails with `EINVAL`) or
    any other error is `UNREADABLE`. Whether `<n>` matches the entry's own
    number is not checked: the link is the kernel's, and it is trusted.
    """

    try:
        target = os.readlink("raw_sha256", dir_fd=entry_fd)
    except OSError as error:
        # EINVAL: not a link. Only the kernel's observed form is accepted.
        return None if error.errno in _ABSENT else UNREADABLE
    number = _raw_data_number(target)
    if number is None:
        return UNREADABLE
    try:
        raw_data = os.open(_POLICY_RAW_DATA, _DIRECTORY)
    except OSError as error:
        # ENOTDIR or ELOOP: a link or a file in place of the directory.
        return None if error.errno == errno.ENOENT else UNREADABLE
    try:
        try:
            directory = os.open(number, _DIRECTORY, dir_fd=raw_data)
        except OSError as error:
            # ENOTDIR here is a link or a file in place of the directory
            # (O_NOFOLLOW with O_DIRECTORY), not an absent one.
            return None if error.errno == errno.ENOENT else UNREADABLE
        try:
            return _read_at(directory, "sha256", _POLICY_HASH_LIMIT)
        finally:
            os.close(directory)
    finally:
        os.close(raw_data)


def read_policy_hashes():
    """The kernel's `(name, raw_sha256)` per loaded profile, as read now.

    None when the directory does not exist, `UNREADABLE` when it exists and
    cannot be listed or holds more than `_POLICY_ENTRY_LIMIT` entries, else a
    tuple with one pair per entry, each file bytes, None or `UNREADABLE`.
    Read-only, bounded, no link followed (an entry that is a link is read as
    `UNREADABLE`; `raw_sha256` is read as `_read_raw_sha256` says). The
    files are `_POLICY_PROFILES`'s; the kernel's other file, `sha256`, is
    not read.
    """

    try:
        directory = os.open(_POLICY_PROFILES, _DIRECTORY)
    except OSError as error:
        return None if error.errno in _ABSENT else UNREADABLE
    try:
        names = os.listdir(directory)
        if len(names) > _POLICY_ENTRY_LIMIT:
            return UNREADABLE
        entries = []
        for entry in sorted(names):
            try:
                fd = os.open(entry, _DIRECTORY, dir_fd=directory)
            except OSError as error:
                if error.errno == errno.ENOENT:
                    continue  # removed since the listing (a profile replaced)
                entries.append((UNREADABLE, UNREADABLE))
                continue
            try:
                entries.append((_read_at(fd, "name", _POLICY_NAME_LIMIT),
                                _read_raw_sha256(fd)))
            finally:
                os.close(fd)
        return tuple(entries)
    except OSError:
        return UNREADABLE
    finally:
        os.close(directory)


def exposure_lsm_withholding(lsm, profiles, loaded, policy, expected) -> str | None:
    """The tier's LSM condition (§5 item 4, §7), the first reason that holds, or None.

    `exposure_lsm_refusal(lsm, profiles)`, then
    `loaded_unit_profile_refusal(loaded)`, then
    `policy_hash_refusal(policy, expected)`. Pure. `expected` is the
    exposure section's `apparmor_policy_hashes` as
    `exposure_generation.expected_policy_hashes` gives it, or None.
    **Called by nothing in this build**; with `expected` None, as this build
    has it (nothing records the field yet), it never returns None.
    """

    return (exposure_lsm_refusal(lsm, profiles)
            or loaded_unit_profile_refusal(loaded)
            or policy_hash_refusal(policy, expected))


def read_exposure_lsm_policy():
    """`(lsm, profiles, policy)`: `read_exposure_lsm()`, then `read_policy_hashes()`."""

    lsm, profiles = read_exposure_lsm()
    return lsm, profiles, read_policy_hashes()


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
