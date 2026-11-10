"""Static enumeration of the Knowledge Context broker's systemd confinement (unit 29).

STATIC ONLY. This reads the shipped unit files and the installer. It does not
start systemd and proves nothing about what the kernel enforces; actual
enforcement is not verified in the isolated environment (no PID 1 systemd
without privileged containers). See docs/knowledge-context-consumer.md
("systemd: static versus effective").
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BROKER = (REPO / "packaging/systemd/azazel-knowledge-contextd.service").read_text(encoding="utf-8")
LOCALD = (REPO / "packaging/systemd/azazel-mio-locald.service").read_text(encoding="utf-8")
INSTALL = (REPO / "packaging/install.sh").read_text(encoding="utf-8")


def _directives(text: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line and not line.startswith(("#", "[")) and "=" in line:
            key, value = line.split("=", 1)
            values.setdefault(key, []).append(value)
    return values


def test_broker_unit_declares_the_enumerated_confinement():
    d = _directives(BROKER)
    expected_single = {
        "Type": "notify", "User": "azknowledgeegress",
        "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
        "PrivateTmp": "yes", "PrivateDevices": "yes", "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes", "ProtectControlGroups": "yes",
        "RestrictNamespaces": "yes", "RestrictSUIDSGID": "yes", "LockPersonality": "yes",
        "MemoryDenyWriteExecute": "yes", "SystemCallArchitectures": "native",
        "SystemCallFilter": "@system-service", "CapabilityBoundingSet": "",
        "AmbientCapabilities": "", "IPAddressDeny": "any", "UMask": "0027",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
    }
    for key, value in expected_single.items():
        assert d.get(key) == [value], (key, d.get(key))
    assert sorted(d["ReadWritePaths"]) == [
        "/var/lib/azazel/run/knowledge-context", "/var/lib/azazel/state/knowledge-context"]
    # As shipped, no egress is possible: nothing is allowed through IPAddressDeny.
    assert "IPAddressAllow" not in d
    assert d["ConditionPathExists"] == [
        "/run/azazel-activation/granted/azazel-knowledge-contextd.service"]
    # Not given: any group beyond the dedicated account's own.
    assert "SupplementaryGroups" not in d and "Group" not in d


def test_broker_state_and_socket_areas_match_the_installer_and_the_daemon():
    assert re.search(
        r"make_owned_dir 2710 azknowledgeegress azknowledge-context-client "
        r"/var/lib/azazel/run/knowledge-context", INSTALL)
    assert re.search(r"make_owned_dir 0700 azknowledgeegress root "
                     r"/var/lib/azazel/state/knowledge-context", INSTALL)
    assert "systemctl mask azazel-knowledge-contextd.service" in INSTALL
    from azazel_nexus_runtime.runtime_paths import knowledge_context_state_dir, socket_path
    assert str(knowledge_context_state_dir()) == "/var/lib/azazel/state/knowledge-context"
    assert str(socket_path("knowledge-context").parent) == "/var/lib/azazel/run/knowledge-context"
    from azazel_nexus_runtime.principal import REQUIRED_SOCKET_MODE
    assert REQUIRED_SOCKET_MODE == 0o660


def test_locald_unit_reaches_the_broker_group_and_has_no_network():
    d = _directives(LOCALD)
    assert d["User"] == ["azmio"]
    assert any("azknowledge-context-client" in value.split() for value in d["SupplementaryGroups"])
    assert d["PrivateNetwork"] == ["yes"]
    assert d["RestrictAddressFamilies"] == ["AF_UNIX"]
