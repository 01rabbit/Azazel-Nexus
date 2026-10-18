"""Pure adapter unit rendering and credential-reference lifecycle (#16).

The caller supplies an *admitted* manifest and reviewed commissioning, never
connector/M.I.O./Knowledge/Deception payloads. The real admission type is shared with the verifier; a Python object alone
does not authenticate commissioning.
No files are read, units installed, secrets fetched, or processes started.

Network limits: IPAddressAllow is address-only; SocketBindDeny=any denies
explicit local IP bind, not connect's destination port (nor implicit ephemeral
binding). There is no destination-port allowlist directive in the systemd
resource-control interface. SocketBindAllow must NOT contain destination
ports: that would grant local listening ports. The admitted port set is
retained as review comments only. Enforcing it requires separately reviewed
nftables rules or cgroup BPF connect/sendmsg hooks (including UDP), outside
this renderer. BPFProgram=/IPEgressFilterPath= attachment is possible, but
requires a separately installed/verified policy, not an invented unit option.
See https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html
Actual Linux cgroup/BPF and seccomp enforcement remains a hardware gate;
rendering alone cannot satisfy endpoint/port confinement acceptance.

Credential directories must be administrator-owned, non-symlink scoped
directories whose final component is adapter_id; executable mappings must
come from verified installed artifacts. Those filesystem facts are runtime
commissioning preconditions, not facts this pure library can establish.
Expiry is checked against the supplied current time, with a 24-hour maximum
from commissioning review; later activation must recheck time/revocation. Rotation returns immutable replacement records;
the broker must persist both atomically and replace its old reference.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from types import MappingProxyType

from .manifest import AdapterManifest, ManifestRefused, validate_egress


class ConfinementRefused(ValueError):
    """Unsafe, unbound, or expired commissioning cannot render a unit."""


# Copy of runtime.hardening.SHARED_HARDENING, without a runtime dependency.
# The tests compare both the declaration and committed service files.
SHARED_HARDENING: tuple[tuple[str, str], ...] = (
    ("NoNewPrivileges", "yes"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "yes"),
    ("PrivateTmp", "yes"),
    ("PrivateDevices", "yes"),
    ("ProtectKernelTunables", "yes"),
    ("ProtectKernelModules", "yes"),
    ("ProtectControlGroups", "yes"),
    ("RestrictNamespaces", "yes"),
    ("RestrictSUIDSGID", "yes"),
    ("LockPersonality", "yes"),
    ("MemoryDenyWriteExecute", "yes"),
    ("SystemCallArchitectures", "native"),
    ("SystemCallFilter", "@system-service"),
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
    ("IPAddressDeny", "any"),
    ("UMask", "0027"),
)


def _symbol(value: str) -> str:
    if (not isinstance(value, str) or ".." in value
            or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", value)):
        raise ConfinementRefused("unsafe symbol")
    return value


def _path(value: str) -> str:
    if (not isinstance(value, str)
            or not re.fullmatch(r"/[a-zA-Z0-9_./-]+", value)
            or ".." in value or any(p in ("", ".") for p in value[1:].split("/"))):
        raise ConfinementRefused("unsafe absolute path")
    return value


def _time(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ConfinementRefused("timezone-aware time required")
    return value


@dataclass(frozen=True)
class CredentialRef:
    """Public metadata only; generation is part of the scoped source filename."""

    adapter_id: str
    symbol: str
    expires_at: datetime
    generation: int = 1
    revoked: bool = False

    def __post_init__(self) -> None:
        _symbol(self.adapter_id)
        _symbol(self.symbol)
        _time(self.expires_at)
        if type(self.generation) is not int or self.generation < 1:
            raise ConfinementRefused("positive credential generation required")
        if type(self.revoked) is not bool:
            raise ConfinementRefused("invalid revocation flag")


def rotate_credential(
    old: CredentialRef, *, symbol: str, expires_at: datetime, now: datetime,
) -> tuple[CredentialRef, CredentialRef]:
    """Return (revoked_old, new); expired references may be replaced once.

    A fresh symbol must also be commissioned in a newly admitted manifest.
    This function neither provisions secret bytes nor mutates retained copies.
    """
    _time(now)
    _time(expires_at)
    _symbol(symbol)
    if (old.revoked or symbol == old.symbol or expires_at <= now
            or expires_at > now + timedelta(hours=24)):
        raise ConfinementRefused("rotation needs an unrevoked old and fresh live reference")
    new = CredentialRef(old.adapter_id, symbol, expires_at, old.generation + 1)
    return replace(old, revoked=True), new


@dataclass(frozen=True)
class AdapterCommissioning:
    """One reviewed adapter scope; account=None selects DynamicUser.

    Dedicated accounts must be provisioned uniquely per adapter by the
    commissioner. DynamicUser uses a deterministic per-adapter user name.
    """

    adapter_id: str
    account: str | None
    credential_directory: str
    installed_artifacts: Mapping[str, str]
    credential: CredentialRef
    reviewed_at: datetime
    wider_egress_allowlist: tuple[tuple[str, int], ...] = ()
    management_prefixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _symbol(self.adapter_id)
        if self.account is not None:
            if (not isinstance(self.account, str)
                    or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", self.account)
                    or self.account in {"root", "nobody"}):
                raise ConfinementRefused("dedicated unprivileged account required")
        else:
            # systemd user names are limited to 31 characters on target hosts.
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,22}", self.adapter_id):
                raise ConfinementRefused("adapter id cannot form a DynamicUser name")
        directory = _path(self.credential_directory)
        if directory.rsplit("/", 1)[-1] != self.adapter_id:
            raise ConfinementRefused("credential directory is not adapter-scoped")
        if not isinstance(self.credential, CredentialRef):
            raise ConfinementRefused("credential metadata required")
        if self.credential.adapter_id != self.adapter_id:
            raise ConfinementRefused("credential belongs to another adapter")
        _time(self.reviewed_at)
        artifacts = dict(self.installed_artifacts)
        for digest, executable in artifacts.items():
            _digest(digest)
            _path(executable)
            if executable.rsplit("/", 1)[-1] in {
                "sh", "bash", "dash", "zsh", "ksh", "fish", "csh", "tcsh",
                "ash", "busybox", "env",
            }:
                raise ConfinementRefused("artifact executable must not be a shell or launcher")
        object.__setattr__(self, "installed_artifacts", MappingProxyType(artifacts))


def _digest(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ConfinementRefused("sha256 artifact digest required")
    return value


def render_adapter_unit(manifest: AdapterManifest, *, commissioning: AdapterCommissioning,
                        now: datetime) -> str:
    """Render a complete service unit from admitted/reviewed values only.

    Exposure adapters get no additional host capability. Approval and lease
    checks belong to routing, and cannot be bypassed by a more powerful unit.
    No [Install] section: admission/rendering does not enable an adapter.
    """
    if not isinstance(commissioning, AdapterCommissioning):
        raise ConfinementRefused("reviewed adapter commissioning required")
    _time(now)
    if not isinstance(manifest, AdapterManifest):
        raise ConfinementRefused("admitted AdapterManifest required")
    adapter = _symbol(manifest.adapter_id)
    digest = _digest(manifest.artifact_digest)
    symbol = _symbol(manifest.credential_ref)
    if adapter != commissioning.adapter_id:
        raise ConfinementRefused("commissioning belongs to another adapter")
    credential = commissioning.credential
    if (credential.symbol != symbol or credential.revoked
            or credential.expires_at <= now
            or commissioning.reviewed_at > now
            or credential.expires_at > commissioning.reviewed_at + timedelta(hours=24)):
        raise ConfinementRefused("credential is uncommissioned, revoked or expired")
    executable = commissioning.installed_artifacts.get(digest)
    if executable is None:
        raise ConfinementRefused("artifact is not installed under this digest")
    capabilities = frozenset(manifest.capability_set)
    if (not capabilities
            or not capabilities <= {"telemetry_read", "advisory_read", "exposure_change"}
            or ("exposure_change" in capabilities and len(capabilities) != 1)):
        raise ConfinementRefused("invalid or mixed adapter capabilities")
    endpoints = []
    families = {"AF_UNIX"}
    for entry in manifest.egress_allowlist:
        cidr = entry.address
        if (not isinstance(cidr, str) or ".." in cidr
                or not re.fullmatch(r"[0-9a-fA-F:./]+", cidr)):
            raise ConfinementRefused("numeric IP/CIDR required")
        try:
            network = validate_egress(cidr, entry.port,
                                      wider_allowlist=commissioning.wider_egress_allowlist,
                                      management_prefixes=commissioning.management_prefixes)
        except (ManifestRefused, ValueError) as exc:
            raise ConfinementRefused("egress policy refused") from exc
        families.add("AF_INET" if network.version == 4 else "AF_INET6")
        endpoints.append((cidr, entry.port))
    lines = [
        "# Generated from reviewed adapter commissioning. Do not edit by hand.",
        "# Destination ports below are declarations, NOT enforced by this unit.",
        "# Enforce destination ports with reviewed nftables/cgroup BPF policy.",
        "# Capabilities: " + " ".join(sorted(capabilities)),
    ]
    lines += [f"# Declared destination: {cidr} port {port}" for cidr, port in endpoints]
    lines += ["", "[Unit]", f"Description=Azazel-Nexus adapter {adapter}",
              "", "[Service]", "Type=exec"]
    if commissioning.account is None:
        lines += ["DynamicUser=yes", f"User=azadapt-{adapter}"]
    else:
        lines += ["DynamicUser=no", f"User={commissioning.account}"]
    lines += [f"ExecStart={executable}",
              (f"LoadCredential={symbol}:{commissioning.credential_directory}/"
               f"{symbol}.g{credential.generation}"),
              "RestrictAddressFamilies=" + " ".join(
                  family for family in ("AF_UNIX", "AF_INET", "AF_INET6") if family in families
              ), "SocketBindDeny=any", "InaccessiblePaths=-/run -/var/run -/var/lib/azazel/run"]
    lines += [f"{key}={value}" for key, value in SHARED_HARDENING]
    lines += [f"IPAddressAllow={cidr}" for cidr in dict.fromkeys(cidr for cidr, _ in endpoints)]
    return "\n".join(lines) + "\n"
