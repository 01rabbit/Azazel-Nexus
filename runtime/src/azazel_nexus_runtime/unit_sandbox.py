"""Verify effective systemd service properties using the host syscall tables."""
import ctypes
import platform
import shlex
import subprocess
from pathlib import Path

SHOW = (
    "ActiveState", "SubState", "MainPID", "User", "Group", "SupplementaryGroups",
    "RestrictAddressFamilies", "ReadWritePaths", "ReadOnlyPaths", "CapabilityBoundingSet",
    "AmbientCapabilities", "NoNewPrivileges", "ProtectSystem", "ProtectHome",
    "PrivateNetwork", "IPAddressDeny", "RuntimeDirectory", "RuntimeDirectoryMode",
    "RuntimeDirectoryPreserve", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectControlGroups", "RestrictNamespaces",
    "RestrictSUIDSGID", "LockPersonality", "MemoryDenyWriteExecute",
    "SystemCallArchitectures", "SystemCallFilter", "UMask",
)


# Occurrences stay ordered: systemd-run applies each assignment, including resets.
Properties = list[tuple[str, str]]
PATH_KEYS = {"ReadWritePaths", "ReadOnlyPaths"}
SET_KEYS = {"SupplementaryGroups", "RestrictAddressFamilies", "CapabilityBoundingSet",
            "AmbientCapabilities", "SystemCallArchitectures", "RuntimeDirectory"}
BOOL_KEYS = {key for key in SHOW if key.startswith(("Private", "Protect", "Restrict"))} | {
    "NoNewPrivileges", "LockPersonality", "MemoryDenyWriteExecute"}


def normalise(key: str, value: str):
    """Normalise show's encodings, without erasing list inversion or path flags."""
    if key == "UMask" or key.endswith("DirectoryMode"):
        return int(value, 8)
    if key in BOOL_KEYS and value in {"1", "true", "yes", "on", "0", "false", "no", "off"}:
        return value in {"1", "true", "yes", "on"}
    if key == "IPAddressDeny":
        return frozenset({"0.0.0.0/0", "::/0"} if value == "any" else value.split())
    if key in SET_KEYS or key in PATH_KEYS:
        inverted = value.startswith("~")
        words = shlex.split(value[1:] if inverted else value)
        if key == "SystemCallArchitectures":
            native = {"x86_64": "x86-64", "aarch64": "arm64", "arm64": "arm64"}.get(
                platform.machine(), platform.machine())
            words = [native if word == "native" else word for word in words]
        if key in PATH_KEYS:
            paths = []
            for word in words:
                path = word.lstrip("-+")
                flags = word[:len(word) - len(path)]
                paths.append("".join(sorted(set(flags))) + str(Path(path)))
            words = paths
        if key in {"CapabilityBoundingSet", "AmbientCapabilities"}:
            words = [word.lower() for word in words]
        return inverted, frozenset(words)
    return value


def expected_properties(properties: Properties) -> dict[str, str]:
    result = {}
    for key, value in properties:
        if key == "ExecStart":
            continue
        if key == "SystemCallFilter":
            # Compared separately using the original ordered assignments.
            result[key] = value
            continue
        if key in SET_KEYS | PATH_KEYS | {"IPAddressDeny", "Environment"}:
            if not value:
                result[key] = ""
            elif key in {"CapabilityBoundingSet", "RestrictAddressFamilies"}:
                # Mixed positive/inverse repetitions require systemd's algebra.
                # Refuse rather than guess the resulting sandbox.
                old = result.get(key, "")
                if old and old.startswith("~") != value.startswith("~"):
                    raise ValueError("mixed inverted assignments require review")
                result[key] = ("~" if value.startswith("~") else "") + " ".join(
                    part.lstrip("~") for part in (old, value) if part)
            else:
                result[key] = " ".join(part for part in (result.get(key, ""), value) if part)
        else:
            result[key] = value
    return result


DANGEROUS_SYSCALL_GROUPS = (
    "@mount", "@reboot", "@module", "@raw-io", "@privileged", "@debug", "@swap",
    "@cpu-emulation", "@obsolete", "@clock",
)
SYSCALL_DIFFERENCE_LIMIT = 64


def compare_properties(properties: Properties, observed: dict[str, str],
                       syscall_groups: dict | None = None, evidence: dict | None = None,
                       native_resolver=None) -> list[str]:
    mismatches = []
    for key, value in expected_properties(properties).items():
        if key == "SystemCallFilter":
            groups = (expand_syscall_groups(properties, observed)
                      if syscall_groups is None else syscall_groups)
            detail = compare_syscall_filter(properties, observed.get(key, ""), groups,
                                            native_resolver=native_resolver)
            if evidence is not None:
                evidence["system_call_filter"] = detail
            if key not in observed or not detail["ok"]:
                mismatches.append(key)
        elif key not in observed or normalise(key, value) != normalise(key, observed[key]):
            mismatches.append(key)
    return mismatches


def syscall_words(value: str) -> tuple[bool, list[str]]:
    inverted = value.startswith("~")
    words = shlex.split(value[1:] if inverted else value)
    # errno overrides and other unreviewed syntax must never become literal names.
    if any(not word.lstrip("@").replace("_", "").replace("-", "").isalnum()
           or "@" in word[1:] for word in words):
        raise ValueError("unsupported syscall filter syntax")
    return inverted, words


def expand_syscall_groups(properties: Properties, observed: dict[str, str], *, runner=None) -> dict:
    """Use this host's systemd definitions, including recursively nested groups.

    Missing systemd-analyze, failed commands and malformed output all refuse smoke.
    """
    groups = {}
    pending = set()

    def expand(group):
        if group in pending:
            raise ValueError("recursive syscall group")
        if group in groups:
            return groups[group]
        pending.add(group)
        lines = (runner or run)(["systemd-analyze", "syscall-filter", "--no-pager", group]).splitlines()
        names = set()
        for line in lines:
            word = line.strip()
            if not word or word.startswith("#") or word == group:
                continue
            inverted, words = syscall_words(word)
            if inverted or len(words) != 1:
                raise ValueError("unrecognised syscall-filter representation")
            names.update(expand(word) if word.startswith("@") else {word})
        if not names:
            raise ValueError("empty syscall group expansion")
        pending.remove(group)
        groups[group] = names
        return names

    for group in (*DANGEROUS_SYSCALL_GROUPS, "@default"):
        expand(group)
    values = [value for key, value in properties if key == "SystemCallFilter"]
    for value in [*values, observed.get("SystemCallFilter", "")]:
        inverted, words = syscall_words(value)
        if inverted or not value:
            expand("@known")
        for word in words:
            if word.startswith("@"):
                expand(word)
    return groups


def native_unknown_syscalls(names: set[str]) -> set[str]:
    """Resolve against the native ABI; never infer architecture gaps from show.

    libseccomp returns negative numbers for unknown or architecture-only pseudo
    syscalls. No filters are installed. Fail closed if the resolver is unavailable.
    """
    if not names:
        return set()
    library = ctypes.CDLL("libseccomp.so.2")
    resolve = library.seccomp_syscall_resolve_name
    resolve.argtypes = [ctypes.c_char_p]
    resolve.restype = ctypes.c_int
    return {name for name in names if resolve(name.encode("ascii")) < 0}


def compare_syscall_filter(properties: Properties, shown: str, groups: dict, *,
                           native_resolver=None) -> dict:
    def expand(words):
        return set().union(*(groups[word] if word.startswith("@") else {word}
                             for word in words))

    allowed = set()
    explicit_groups = set()
    initial = True
    for key, value in properties:
        if key != "SystemCallFilter":
            continue
        if not value:
            allowed = set(groups["@known"])
            explicit_groups.clear()
            initial = True
            continue
        inverted, words = syscall_words(value)
        if initial:
            allowed = set(groups["@known"] if inverted else groups["@default"])
            initial = False
        names = expand(words)
        if inverted:
            allowed.difference_update(names)
            explicit_groups.difference_update(words)
        else:
            allowed.update(names)
            explicit_groups.update(word for word in words if word in DANGEROUS_SYSCALL_GROUPS)

    inverted, words = syscall_words(shown)
    observed = expand(words)
    if inverted:
        observed = set(groups["@known"]) - observed
    # An empty show property means no filter; it must never certify hardening.
    if not words:
        observed = set()
    exempt = expand(explicit_groups)
    dangerous = expand(DANGEROUS_SYSCALL_GROUPS) - exempt
    unexpected = observed - allowed
    # A dangerous-group member the declared filter itself allows (for example
    # @system-service's own @chown/@setuid subgroups) is the unit's stated
    # policy, not drift: it is reported, and fails only if it was not declared.
    forbidden = (observed & dangerous) - allowed
    declared_dangerous = (observed & dangerous) & allowed
    missing = allowed - observed
    unknown = (native_resolver or native_unknown_syscalls)(missing)
    missing_native = missing - unknown
    detail = {"ok": bool(observed) and not (unexpected or forbidden or missing_native),
              "expanded_count": len(allowed), "observed_count": len(observed),
              "explicit_dangerous_groups": sorted(explicit_groups),
              "difference_limit": SYSCALL_DIFFERENCE_LIMIT}
    for label, names in (("unexpected", unexpected), ("dangerous", forbidden),
                         ("declared_dangerous", declared_dangerous),
                         ("missing_native", missing_native), ("omitted_native_unknown", unknown)):
        detail[label + "_count"] = len(names)
        detail[label] = sorted(names)[:SYSCALL_DIFFERENCE_LIMIT]
    return detail


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=20).stdout
