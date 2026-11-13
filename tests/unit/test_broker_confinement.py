"""Confinement rendering is pure policy, not evidence of OS enforcement."""

from __future__ import annotations

import ast
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path

import pytest

from azazel_nexus.integration_broker.confinement import (
    SHARED_HARDENING,
    AdapterCommissioning,
    ConfinementRefused,
    CredentialRef,
    rotate_credential,
)

NOW = datetime(2026, 10, 18, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64
ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Egress:
    address: str
    port: int


from azazel_nexus.integration_broker.manifest import AdapterManifest


@dataclass(frozen=True)
class Manifest(AdapterManifest):
    schema: str = "azazel-nexus/adapter-manifest/1"
    commissioning_digest: str = DIGEST
    adapter_id: str = "telemetry"
    kind: str = "ndr"
    version: str = "1.0.0"
    artifact_digest: str = DIGEST
    capability_set: frozenset = frozenset({"telemetry_read"})
    tenant: str = "test"
    privacy_class: str = "P1-sanitized"
    egress_allowlist: tuple = (Egress("192.0.2.0/24", 443), Egress("2001:db8::/64", 6514))
    mtls_identity: str = "test"
    credential_ref: str = "mtls-v1"
    compatibility: tuple = ("azazel-nexus/1",)
    signer: str = "test"
    manifest_digest: str = DIGEST

    def __post_init__(self):
        pass  # Deliberately malformed nominal inputs must be rechecked by rendering.


def render_adapter_unit(manifest, *, commissioning, now=NOW):
    from azazel_nexus.integration_broker.confinement import (
        render_adapter_unit as render,
    )
    return render(manifest, commissioning=commissioning, now=now)


def commissioned(**overrides):
    values = {
        "adapter_id": "telemetry", "account": "aztelemetry",
        "credential_directory": "/etc/azazel/credentials/telemetry",
        "installed_artifacts": {DIGEST: "/opt/azazel/adapters/telemetry"},
        "credential": CredentialRef("telemetry", "mtls-v1", NOW + timedelta(hours=1)),
        "reviewed_at": NOW,
    }
    values.update(overrides)
    return AdapterCommissioning(**values)


# Deliberately literal: this fixture must not reproduce the implementation's
# property-loop algorithm, or accidentally bless a changed security setting.
TELEMETRY_UNIT = """# Generated from reviewed adapter commissioning. Do not edit by hand.
# Destination ports below are declarations, NOT enforced by this unit.
# Enforce destination ports with reviewed nftables/cgroup BPF policy.
# Capabilities: telemetry_read
# Declared destination: 192.0.2.0/24 port 443
# Declared destination: 2001:db8::/64 port 6514

[Unit]
Description=Azazel-Nexus adapter telemetry

[Service]
Type=exec
DynamicUser=no
User=aztelemetry
ExecStart=/opt/azazel/adapters/telemetry
LoadCredential=mtls-v1:/etc/azazel/credentials/telemetry/mtls-v1.g1
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SocketBindDeny=any
InaccessiblePaths=-/run -/var/run -/var/lib/azazel/run
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
IPAddressDeny=any
UMask=0027
IPAddressAllow=192.0.2.0/24
IPAddressAllow=2001:db8::/64
"""

EXPOSURE_UNIT = """# Generated from reviewed adapter commissioning. Do not edit by hand.
# Destination ports below are declarations, NOT enforced by this unit.
# Enforce destination ports with reviewed nftables/cgroup BPF policy.
# Capabilities: exposure_change

[Unit]
Description=Azazel-Nexus adapter exposure

[Service]
Type=exec
DynamicUser=yes
User=azadapt-exposure
ExecStart=/opt/azazel/adapters/exposure
LoadCredential=exposure-mtls:/etc/azazel/credentials/exposure/exposure-mtls.g1
RestrictAddressFamilies=AF_UNIX
SocketBindDeny=any
InaccessiblePaths=-/run -/var/run -/var/lib/azazel/run
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
CapabilityBoundingSet=
AmbientCapabilities=
IPAddressDeny=any
UMask=0027
"""


def test_exact_telemetry_unit():
    assert render_adapter_unit(Manifest(), commissioning=commissioned()) == TELEMETRY_UNIT


def test_exact_exposure_unit_has_separate_scope_and_no_extra_host_privilege():
    manifest = Manifest(adapter_id="exposure", capability_set=frozenset({"exposure_change"}),
                        egress_allowlist=(), credential_ref="exposure-mtls")
    commissioning = AdapterCommissioning(
        "exposure", None, "/etc/azazel/credentials/exposure",
        {DIGEST: "/opt/azazel/adapters/exposure"},
        CredentialRef("exposure", "exposure-mtls", NOW + timedelta(hours=1)), NOW,
    )
    assert render_adapter_unit(manifest, commissioning=commissioning) == EXPOSURE_UNIT
    assert "CAP_NET_ADMIN" not in EXPOSURE_UNIT
    assert "[Install]" not in EXPOSURE_UNIT


def test_shared_baseline_matches_runtime_declaration_without_importing_runtime():
    tree = ast.parse((ROOT / "runtime/src/azazel_nexus_runtime/hardening.py").read_text())
    baseline = next(node.value for node in tree.body
                    if isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name)
                    and node.target.id == "SHARED_HARDENING")
    assert ast.literal_eval(baseline) == SHARED_HARDENING


def test_baseline_matches_every_committed_unit_except_declared_controller_capability():
    units = sorted((ROOT / "packaging/systemd").glob("*.service"))
    assert units
    for path in units:
        lines = path.read_text().splitlines()
        for key, value in SHARED_HARDENING:
            if (path.name in ("azazel-activated.service", "azazel-activation-recheck.service")
                    and key == "CapabilityBoundingSet"):
                # The controller and its periodic recheck, which runs the same
                # evaluation with the same single capability.
                assert "CapabilityBoundingSet=CAP_DAC_READ_SEARCH" in lines
            elif (path.name in ("azazel-decoy-netd.service", "azazel-decoy-verify.service")
                    and key == "CapabilityBoundingSet"):
                # #196 P1: the one-shot decoy network helper, and (#196 G2)
                # the verify unit that runs its executable, and only they.
                assert "CapabilityBoundingSet=CAP_NET_ADMIN" in lines
            elif path.name == "azazel-decoy-nsd.service" and key in (
                    "CapabilityBoundingSet", "RestrictNamespaces", "SystemCallFilter",
                    "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
                    "ProtectKernelTunables", "ProtectKernelModules",
                    "ProtectControlGroups"):
                # #196 (a): the one-shot decoy namespace unit, and only it;
                # its overrides and omissions are pinned in
                # test_decoy_namespace_unit.py.
                assert f"{key}={value}" not in lines, key
            else:
                assert f"{key}={value}" in lines, (path.name, key)


@pytest.mark.parametrize("egress,families", [
    ((), "AF_UNIX"),
    ((Egress("192.0.2.1", 443),), "AF_UNIX AF_INET"),
    ((Egress("2001:db8::1/128", 443),), "AF_UNIX AF_INET6"),
])
def test_minimal_address_families_and_exact_allowlist(egress, families):
    text = render_adapter_unit(replace(Manifest(), egress_allowlist=egress),
                               commissioning=commissioned())
    assert f"RestrictAddressFamilies={families}\n" in text
    assert [line for line in text.splitlines() if line.startswith("IPAddressAllow=")] == [
        f"IPAddressAllow={entry.address}" for entry in egress
    ]
    assert "IPAddressDeny=any\n" in text
    assert "SocketBindDeny=any\n" in text
    assert "SocketBindAllow=" not in text


def test_deduplicate_addresses_without_collapsing_cidrs_or_hiding_ports():
    egress = (Egress("192.0.2.1/32", 443), Egress("192.0.2.1/32", 8443))
    text = render_adapter_unit(replace(Manifest(), egress_allowlist=egress),
                               commissioning=commissioned())
    assert text.count("IPAddressAllow=192.0.2.1/32\n") == 1
    assert "# Declared destination: 192.0.2.1/32 port 8443\n" in text


INJECTIONS = [
    "payload\nExecStartPre=/bin/sh", "payload\rUser=root", "payload%u", "..",
    "../escape", 'payload"', "payload'", "payload\\", "payload\x00",
    "payload other", "$(id)", "`id`", ";id", "https://evil.example/",
]


@pytest.mark.parametrize("payload", INJECTIONS)
@pytest.mark.parametrize("field", ["adapter_id", "artifact_digest", "credential_ref"])
def test_manifest_rendered_strings_reject_injection(field, payload):
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(replace(Manifest(), **{field: payload}), commissioning=commissioned())


@pytest.mark.parametrize("payload", INJECTIONS)
@pytest.mark.parametrize("field", ["adapter_id", "account", "credential_directory", "executable"])
def test_commissioning_strings_reject_injection(field, payload):
    with pytest.raises(ConfinementRefused):
        if field == "executable":
            commissioned(installed_artifacts={DIGEST: "/opt/" + payload})
        else:
            commissioned(**{field: payload})


@pytest.mark.parametrize("payload", INJECTIONS + [
    "evil.example", "localhost", "192.0.2.1:443", "192.0.2.0/33",
    "192.0.2.1/24", "fe80::1%eth0", "any", "192.0.2.1\n", "127.0.0.1/../32",
    "0.0.0.0/0", "::/0",
])
def test_no_hostnames_urls_or_injected_cidrs(payload):
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(replace(Manifest(), egress_allowlist=(Egress(payload, 443),)),
                            commissioning=commissioned())


@pytest.mark.parametrize("port", [0, -1, 65536, True, 443.0, "443", "443\nUser=root", None])
def test_invalid_or_payload_derived_ports(port):
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(replace(Manifest(), egress_allowlist=(Egress("192.0.2.1", port),)),
                            commissioning=commissioned())


@pytest.mark.parametrize("capabilities", [
    frozenset(), frozenset({"telemetry_read", "exposure_change"}),
    frozenset({"advisory_read", "exposure_change"}),
    frozenset({"CAP_NET_ADMIN"}), frozenset({"telemetry_read\nUser=root"}),
])
def test_invalid_capability_combinations_refused(capabilities):
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(replace(Manifest(), capability_set=capabilities),
                            commissioning=commissioned())


def test_advisory_telemetry_combination_has_no_additional_privilege():
    text = render_adapter_unit(replace(Manifest(), capability_set=frozenset(
        {"advisory_read", "telemetry_read"})), commissioning=commissioned())
    assert "# Capabilities: advisory_read telemetry_read\n" in text
    assert "CapabilityBoundingSet=\n" in text
    assert "AmbientCapabilities=\n" in text


@pytest.mark.parametrize("path", [
    "relative/bin", "/opt/../bin/adapter", "/opt/./adapter", "/opt//adapter",
    "/opt/adapter --command", "/opt/adapter/", "/", "/opt/$SHELL",
    "/bin/sh", "/bin/bash", "/usr/bin/env", "/bin/busybox",
])
def test_executable_cannot_be_shell_command_or_ambiguous_path(path):
    with pytest.raises(ConfinementRefused):
        commissioned(installed_artifacts={DIGEST: path})


@pytest.mark.parametrize("account", ["root", "nobody", "0", "-root", "aztelemetry..", 0])
def test_dedicated_account_required(account):
    with pytest.raises(ConfinementRefused):
        commissioned(account=account)


def test_scopes_and_digest_are_bound_and_mapping_is_snapshotted():
    artifacts = {DIGEST: "/opt/azazel/adapters/telemetry"}
    commissioning = commissioned(installed_artifacts=artifacts)
    artifacts[DIGEST] = "/bin/evil"
    assert render_adapter_unit(Manifest(), commissioning=commissioning) == TELEMETRY_UNIT
    with pytest.raises(TypeError):
        commissioning.installed_artifacts[DIGEST] = "/bin/evil"
    for manifest in (replace(Manifest(), adapter_id="other"),
                     replace(Manifest(), artifact_digest="sha256:" + "b" * 64),
                     replace(Manifest(), credential_ref="other")):
        with pytest.raises(ConfinementRefused):
            render_adapter_unit(manifest, commissioning=commissioning)
    with pytest.raises(ConfinementRefused):
        commissioned(credential_directory="/etc/azazel/credentials")
    with pytest.raises(ConfinementRefused):
        commissioned(credential=CredentialRef("other", "mtls-v1", NOW))


@pytest.mark.parametrize("digest", ["a" * 64, "sha256:" + "A" * 64, "sha512:" + "a" * 64])
def test_artifact_mapping_requires_lane_a_sha256_digest_format(digest):
    with pytest.raises(ConfinementRefused):
        commissioned(installed_artifacts={digest: "/opt/azazel/adapters/telemetry"})


def test_render_has_only_installed_exec_and_no_execution_hooks_or_secret_bytes():
    text = render_adapter_unit(Manifest(), commissioning=commissioned())
    assert [line for line in text.splitlines() if line.startswith("Exec")] == [
        "ExecStart=/opt/azazel/adapters/telemetry"
    ]
    assert [line for line in text.splitlines() if "Credential=" in line] == [
        "LoadCredential=mtls-v1:/etc/azazel/credentials/telemetry/mtls-v1.g1"
    ]
    assert {field.name for field in fields(CredentialRef)} == {
        "adapter_id", "symbol", "expires_at", "generation", "revoked"
    }
    with pytest.raises(ConfinementRefused):
        commissioned(credential=b"TEST-ONLY-secret-bytes")


@pytest.mark.parametrize("payload", INJECTIONS)
def test_credential_symbols_reject_injection(payload):
    with pytest.raises(ConfinementRefused):
        CredentialRef("telemetry", payload, NOW)


@pytest.mark.parametrize("generation", [0, -1, True, "1", 1.0])
def test_credential_generations_are_positive_integers(generation):
    with pytest.raises(ConfinementRefused):
        CredentialRef("telemetry", "mtls-v1", NOW, generation)


def test_rotation_lifecycle_requires_new_admission_and_revokes_old_reference():
    old = commissioned().credential
    revoked, new = rotate_credential(old, symbol="mtls-v2", expires_at=NOW + timedelta(days=1), now=NOW)
    assert revoked == replace(old, revoked=True)
    assert new == CredentialRef("telemetry", "mtls-v2", NOW + timedelta(days=1), 2)
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(Manifest(), commissioning=commissioned(credential=revoked))
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(Manifest(), commissioning=commissioned(credential=new))
    text = render_adapter_unit(replace(Manifest(), credential_ref="mtls-v2"),
                               commissioning=commissioned(credential=new))
    assert "LoadCredential=mtls-v2:/etc/azazel/credentials/telemetry/mtls-v2.g2\n" in text
    with pytest.raises(ConfinementRefused):
        rotate_credential(revoked, symbol="mtls-v3", expires_at=new.expires_at, now=NOW)
    revoked_new, newest = rotate_credential(new, symbol="mtls-v3", expires_at=new.expires_at, now=NOW)
    assert revoked_new.revoked and newest.generation == 3


@pytest.mark.parametrize("offset", [-1, 0])
def test_expired_credentials_refused_but_can_be_rotated(offset):
    expired = CredentialRef("telemetry", "mtls-v1", NOW + timedelta(seconds=offset))
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(Manifest(), commissioning=commissioned(credential=expired))
    revoked, new = rotate_credential(expired, symbol="mtls-v2", expires_at=NOW + timedelta(hours=1), now=NOW)
    assert revoked.revoked and new.generation == 2


@pytest.mark.parametrize("symbol,expiry", [
    ("mtls-v1", NOW + timedelta(days=1)), ("mtls-v2", NOW),
    ("mtls-v2", NOW - timedelta(seconds=1)),
    ("mtls-v2", NOW.replace(tzinfo=None)),
])
def test_rotation_refuses_reused_symbol_or_invalid_expiry(symbol, expiry):
    with pytest.raises(ConfinementRefused):
        rotate_credential(commissioned().credential, symbol=symbol, expires_at=expiry, now=NOW)


def test_naive_commissioning_time_and_reference_expiry_refused():
    with pytest.raises(ConfinementRefused):
        commissioned(reviewed_at=NOW.replace(tzinfo=None))
    with pytest.raises(ConfinementRefused):
        CredentialRef("telemetry", "mtls-v1", NOW.replace(tzinfo=None))


def test_lane_a_string_enums_render_as_values():
    class Capability(str, Enum):
        TELEMETRY_READ = "telemetry_read"

    manifest = replace(Manifest(), capability_set=frozenset({Capability.TELEMETRY_READ}))
    assert render_adapter_unit(manifest, commissioning=commissioned()) == TELEMETRY_UNIT


def test_payload_cannot_substitute_for_reviewed_commissioning():
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(Manifest(), commissioning={"ExecStart": "/bin/sh"})


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "169.254.169.254", "224.0.0.1",
    "240.0.0.1", "::", "::1", "fe80::1", "ff02::1", "::ffff:192.0.2.8", "100::1",
    "10.0.0.0/8", "2001:db8::/32"])
def test_render_rechecks_forbidden_egress(address):
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(replace(Manifest(), egress_allowlist=(Egress(address, 443),)),
                            commissioning=commissioned())


def test_render_wide_exception_management_and_unix_isolation():
    manifest = replace(Manifest(), egress_allowlist=(Egress("10.20.0.0/16", 443),))
    scope = commissioned(wider_egress_allowlist=(("10.20.0.0/16", 443),))
    assert "InaccessiblePaths=-/run -/var/run -/var/lib/azazel/run" in render_adapter_unit(manifest, commissioning=scope)
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(manifest, commissioning=replace(scope, management_prefixes=("10.20.1.0/24",)))


def test_render_requires_current_time_nominal_manifest_and_bounded_lifetime():
    from types import SimpleNamespace
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(SimpleNamespace(**Manifest().__dict__), commissioning=commissioned())
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(Manifest(), commissioning=commissioned(), now=NOW + timedelta(hours=1))
    with pytest.raises(ConfinementRefused):
        render_adapter_unit(Manifest(), commissioning=commissioned(credential=CredentialRef(
            "telemetry", "mtls-v1", NOW + timedelta(hours=24, seconds=1))))
    with pytest.raises(ConfinementRefused):
        rotate_credential(commissioned().credential, symbol="mtls-v2", now=NOW,
                          expires_at=NOW + timedelta(hours=24, seconds=1))
