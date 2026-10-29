"""Runtime-owned, read-only netlink adapter for the existing operator wizard.

No service is started, no interface is configured, and no role is inferred.
The library retains all commissioning, protected storage and signature rules.
Trust-repin interactive confirmation guards human intent against accidental or
non-root use, not against a malicious root process: a ROOT socket caller can
read and echo the challenge without this CLI or a TTY.
"""

import io
import json
import sys

from azazel_nexus.cli import main as library_main

from .hardware_inventory import HardwareUnavailable, collect_hardware_observations
from .netlink import NetlinkMalformed, NetlinkUnavailable, read_links
from .resource_assessment import assess_resources


class _PermanentAddresses:
    def __init__(self):
        self.snapshot = None

    @staticmethod
    def _read():
        records = read_links()
        table = {}
        indices = set()
        for record in records:
            if not record.name:
                continue
            if record.name in table or record.index in indices:
                raise NetlinkUnavailable("ambiguous link enumeration")
            indices.add(record.index)
            table[record.name] = (record.index, record.permanent_mac)
        return table

    def __call__(self, name):
        if self.snapshot is None:
            self.snapshot = self._read()
        return self.snapshot.get(name, (None, None))[1]

    def unchanged(self):
        return self.snapshot is not None and self._read() == self.snapshot


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["--help"], ["-h"]):
        print("az-nexus-commission {hardware-assess|resources|inventory|commission|commission-review|proposal-export|proposal-review|trust-repin|knowledge-import|knowledge-revocation-accept} [command options]")
        print("Uses the existing wizard with read-only kernel permanent-address evidence; never activates.")
        return 0
    if args and args[0] == "trust-repin":
        if len(args) != 3 or args[1] != "--reason":
            print("Use trust-repin --reason {rotation|recovery|compromise}; no path overrides are accepted.", file=sys.stderr)
            return 2
        from .repin_confirmation import run_interactive

        return run_interactive(args[2])
    if args and args[0] == "knowledge-import":
        if len(args) != 3 or args[1] != "--entry":
            print("Use knowledge-import --entry ENTRY_ID (the inbox artifact's SHA-256 hex); no path is accepted.", file=sys.stderr)
            return 2
        from .lite_operator_cli import run_import

        return run_import(args[2])
    if args == ["knowledge-revocation-accept"]:
        from .lite_operator_cli import run_revocation_accept

        return run_revocation_accept()
    if args and args[0] == "knowledge-revocation-accept":
        print("Use knowledge-revocation-accept with no options; the statement is read from "
              "/etc/azazel/commissioning/lite-revocations.signed.", file=sys.stderr)
        return 2
    if args and args[0] == "proposal-export":
        if len(args) != 3 or args[1] != "--operator":
            print("Use proposal-export --operator LABEL; no path overrides are accepted.", file=sys.stderr)
            return 2
        from .proposal_export import run

        return run(args[2], _PermanentAddresses())
    if args and args[0] == "proposal-review":
        if (len(args) not in {3, 4} or args[1] != "--operator"
                or (len(args) == 4 and args[3] != "--check-current-hardware")):
            print("Use proposal-review --operator LABEL [--check-current-hardware]; no path overrides are accepted.", file=sys.stderr)
            return 2
        from .proposal_review import run

        return run(args[2], current_hardware=len(args) == 4,
                   addresses=_PermanentAddresses() if len(args) == 4 else None)
    if args == ["resources"]:
        result = assess_resources()
        print(json.dumps(result, sort_keys=True))
        return 1 if result["unavailable"] else 0
    if args == ["hardware-assess"]:
        addresses = _PermanentAddresses()
        try:
            observed = collect_hardware_observations(permanent_mac_reader=addresses)
            if not addresses.unchanged():
                raise HardwareUnavailable("link snapshot changed")
            print(json.dumps({
                "schema": "azazel-nexus/hardware-assessment/v1",
                "interfaces_observed": len(observed.interfaces),
                "interfaces_refused": sum(not item.is_commissionable for item in observed.interfaces),
                "loopback_interfaces_excluded": observed.excluded_loopbacks,
                "storage_devices_observed": len(observed.storage_devices),
                "limitations": observed.limitations,
                "admission": "not-evaluated",
            }, sort_keys=True))
            return 0
        except (HardwareUnavailable, NetlinkMalformed, NetlinkUnavailable, OSError):
            print("Hardware assessment unavailable; no record saved or activation attempted.", file=sys.stderr)
            return 1
    if not args or args[0] not in {"inventory", "commission", "commission-review"}:
        print("Choose resources, inventory, commission or commission-review; global path overrides are not accepted.", file=sys.stderr)
        return 2
    command = args[0]
    # Inventory/wizard output contains operator-local physical facts. Do not
    # silently turn that display into a redirected report.
    if command in {"inventory", "commission"} and not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Inventory and commissioning require a local interactive terminal.", file=sys.stderr)
        return 1
    addresses = _PermanentAddresses()
    observation = None

    def proposal_reader():
        nonlocal observation
        observation = collect_hardware_observations(permanent_mac_reader=addresses)
        return observation.commissioning_proposal()

    def snapshot_unchanged():
        if not addresses.unchanged():
            return False
        if observation is None:
            return True  # inventory display uses only the general reader
        latest = collect_hardware_observations(permanent_mac_reader=addresses)
        matches = all(getattr(latest, field) == getattr(observation, field) for field in (
            "interfaces", "platform", "storage_devices", "limitations", "excluded_loopbacks"
        ))
        return matches and addresses.unchanged()

    def ask(prompt, choices):
        return input(prompt + " [" + ", ".join(choices) + "]: ")

    def confirm(summary):
        consent = input(summary + "\nType CONFIRM to accept this set: ") == "CONFIRM"
        if consent and not snapshot_unchanged():
            raise NetlinkUnavailable("link inventory changed during confirmation")
        return consent

    output = io.StringIO() if command == "commission-review" else sys.stdout
    try:
        result = library_main(args, out=output, ask=ask, confirm=confirm,
                              permanent_mac_reader=addresses,
                              commissioning_proposal_reader=proposal_reader)
        if command == "commission-review":
            if result == 0 and not snapshot_unchanged():
                raise NetlinkUnavailable("link inventory changed during review")
            print(output.getvalue(), end="")
        return result
    except (HardwareUnavailable, NetlinkMalformed, NetlinkUnavailable, OSError, EOFError, KeyboardInterrupt):
        print("Commissioning stopped: kernel evidence unavailable, changed, or confirmation interrupted. No activation attempted.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
