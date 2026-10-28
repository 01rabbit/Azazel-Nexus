"""Read-only HG-01/HG-04 acquisition; observations require campaign attestation.

These records describe what was read, not hardware qualification. They contain
no hardware-only/synthetic assertion: only an operator can attest the DUT.

Each capture also records the platform it was taken on (schema version 2,
ADR-0003 R3): the reviewed `platform_profile_id` selected from the host
observation and the observed ``uname`` machine. A host no reviewed profile
matches is refused with the reason code. An arm64 lab host is *recorded* as
the lab profile, and `hil_records` refuses that capture as hardware evidence.
The observation is what the host reported, not attestation.
"""

from __future__ import annotations

import argparse
import json
import sys

from azazel_nexus.hil_records.confidentiality import lint_text
from azazel_nexus.hil_records.contracts import anonymous_dut
from azazel_nexus.virtualization import virtualization_not_observed

from .hil_readiness import (
    CAPTURE_UNITS,
    ReadOnlySystemd,
    digest,
    protection_key,
    run_identity,
)
from .netlink import read_links
from .platform_observation import observe as observe_platform
from .platform_observation import select as select_platform
from .virtualization_observation import observe_virtualization


def capture_hg01(manager):
    files = manager.unit_files()
    states = {}
    for unit in CAPTURE_UNITS:
        try:
            props = manager("GetUnitProperties", unit)
            states[unit] = {
                "active_state": props["ActiveState"], "sub_state": props["SubState"],
            }
        except Exception:  # noqa: BLE001 - observation refusal must not expose identifiers
            # Unloaded/missing units have no object. Preserve the uncertainty;
            # a missing object does not prove an inactive unit on its own.
            states[unit] = {"active_state": "unobserved", "sub_state": "unobserved"}
    return {
        "schema": "azazel-nexus/hil-capture/hg-01/2", "gate_id": "HG-01",
        "capture_method": "systemd-system-bus-read-only",
        "systemd_version": manager.version(), "unit_files": files, "units": states,
    }


def capture_hg04(*, links_reader=read_links, key_reader=protection_key):
    key = key_reader()
    interfaces = []
    for link in links_reader():
        reason = getattr(link, "reason", "")
        present = None
        if link.permanent_mac is not None:
            present = True
        elif reason == "the driver reports no permanent address for this interface":
            present = False
        elif reason.startswith("the permanent address is "):
            # The shared reader saw the attribute but refused a zero or
            # non-Ethernet payload. Presence alone must not imply usability.
            present = True
        interfaces.append({
            "nic_fingerprint": digest(link.name or str(link.index), key=key, domain="hil-nic"),
            "ifla_perm_address_present": present,
            "permanent_address_usable": link.permanent_mac is not None,
            "permanent_address_fingerprint": (
                digest(link.permanent_mac, key=key, domain="hil-permanent-address")
                if link.permanent_mac is not None else None
            ),
        })
    return {
        "schema": "azazel-nexus/hil-capture/hg-04/2", "gate_id": "HG-04",
        "capture_method": "RTM_GETLINK/IFLA_PERM_ADDRESS", "interfaces": interfaces,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="az-hil-capture", description=__doc__)
    parser.add_argument("gate", choices=("hg-01", "hg-04"))
    args = parser.parse_args(argv)
    from azazel_nexus.lab_host import is_lab_host
    from azazel_nexus.platform_profile import PlatformRefused

    if is_lab_host():
        print("refused: LAB_HOST_MARKER", file=sys.stderr)
        return 2
    try:
        observations = observe_virtualization()
        if not virtualization_not_observed(observations):
            print("refused: RESERVE_VIRTUALIZATION_OBSERVED", file=sys.stderr)
            return 2
        platform_observed = observe_platform()
        try:
            platform = select_platform(platform_observed)
        except PlatformRefused as refused:
            # A reason code only; the observed values stay off stderr.
            print(f"refused: {refused.reason}", file=sys.stderr)
            return 2
        identity = run_identity()
        if args.gate == "hg-01":
            with ReadOnlySystemd() as manager:
                report = capture_hg01(manager)
        else:
            report = capture_hg04()
        if run_identity() != identity:
            raise ValueError("run identity changed")
        if observe_platform() != platform_observed:
            raise ValueError("platform observation changed")
        report.update(identity)
        report.update(platform_profile_id=platform.profile_id,
                      uname_machine=platform_observed.machine)
        report.update(virtualization_not_observed=True,
                      virtualization_observations=observations)
        report["dut_fingerprint"] = report.pop("host_digest")
        report["dut_id"] = anonymous_dut(report["dut_fingerprint"])
        payload = json.dumps(report, sort_keys=True)
        lint_text(payload.encode("utf-8"))
    except Exception:  # noqa: BLE001 - observation refusal must not expose identifiers
        # Neither parser exceptions nor kernel/manager replies may leak raw identity.
        print("refused: read-only capture or protected run identity unavailable", file=sys.stderr)
        return 2
    print(payload)
    return 0
