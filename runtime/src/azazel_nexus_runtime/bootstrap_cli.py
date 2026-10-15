"""Administrator provisioning command, never a service activation entrypoint."""

import argparse
from hashlib import sha256
import sys

from azazel_nexus.bootstrap_generation import verify_bootstrap_generation
from azazel_nexus.bootstrap_prestart_policy import decode_pinned_prestart_policy
from azazel_nexus.bootstrap_generation_publish import BootstrapGenerationDurabilityUncertain
from azazel_nexus.bootstrap_clock_store import TimeDurabilityUncertain
from azazel_nexus.generation import GenerationRefused
from azazel_nexus.operator_trust import ApprovalRefused

from .bootstrap_loaded_policy import decode_loaded_bootstrap_policy
from .bootstrap_declared_context import load_declared_bootstrap_context
from .bootstrap_provisioning import (
    publish_selected_bootstrap_generation, selected_publication_digest,
    publish_selected_administrator_time, selected_time_digest,
)
from .debian_packages import PackageObservationRefused, observe_installed_packages


def run_package_observation(*, out):
    """Print a digest-only local package observation for reviewed provisioning.

    This is not a trust pin, allowlist, package authenticity result, or runtime
    admission. Package names and versions are deliberately not displayed.
    """
    try:
        snapshot = observe_installed_packages()
    except PackageObservationRefused:
        print("Package observation refused; no package inventory was emitted.", file=out)
        return 1
    print(f"Schema: {snapshot.schema}", file=out)
    print(f"Native architecture: {snapshot.native_architecture}", file=out)
    print(f"Installed package records: {len(snapshot.records)}", file=out)
    print(f"Observation digest: {snapshot.digest}", file=out)
    print("Observation only; not package authenticity, approval, or runtime admission.", file=out)
    return 0


def run_time(*, source, out, recovery):
    """Explicit terminal confirmation; never obtain UTC from the OS clock."""
    try:
        if type(recovery) is not bool or not source.isatty():
            raise ApprovalRefused("interactive exact operation required")

        def line(prompt, limit):
            print(prompt, file=out, flush=True)
            raw = source.buffer.readline(limit + 2)
            if not raw.endswith(b"\n") or len(raw) > limit + 1:
                raise ApprovalRefused("bounded complete input lines required")
            return raw[:-1]

        raw = line("Enter canonical administrator-confirmed UTC anchor JSON (one line):", 4096)
        selected = load_declared_bootstrap_context()
        digest = selected_time_digest(raw=raw, selected=selected, recovery=recovery)
        if load_declared_bootstrap_context() != selected:
            raise ApprovalRefused("administrator selection changed")
        print("Selected time publication digest: " + digest, file=out)
        print("Administrator-asserted UTC bounds; NOT authenticated network time or runtime admission.", file=out)
        if line("Re-enter the reviewed selected time digest (sha256:...):", 71).decode("ascii") != digest:
            raise ApprovalRefused("time confirmation differs")
        word = b"RECOVER" if recovery else b"INITIALIZE"
        if line("Type " + word.decode() + " to confirm this time-record operation:", 16) != word:
            raise ApprovalRefused("operation not confirmed")
        publish_selected_administrator_time(raw=raw, confirmed_digest=digest,
                                            confirmed_operation=True, recovery=recovery)
    except TimeDurabilityUncertain:
        print("Time record may be published; durability UNCONFIRMED. Inspect retained state; do not retry automatically.", file=out)
        return 2
    except (ApprovalRefused, OSError, AttributeError, ValueError):
        print("Time-record operation refused; inspect retained state. No OS clock change or activation performed.", file=out)
        return 1
    print("Time record published; no OS clock change, deadline reset or activation performed.", file=out)
    return 0


def run_generation(*, source, out, publish):
    """Two canonical JSON lines; publication additionally needs two confirmations.

    Preview still reads protected administrator declarations. It checks shape
    and selected byte integrity, not provenance, installed closure or admission.
    """
    try:
        if type(publish) is not bool or bool(source.isatty()) != publish:
            raise ApprovalRefused("preview needs redirected input; publication needs a terminal")

        def line(prompt, limit):
            if publish:
                print(prompt, file=out, flush=True)
            raw = source.buffer.readline(limit + 2)
            if not raw.endswith(b"\n") or len(raw) > limit + 1:
                raise ApprovalRefused("bounded complete input lines required")
            return raw[:-1]

        metadata = line("Enter canonical generation metadata JSON (one line):", 65536)
        config = line("Enter canonical bootstrap config JSON (one line):", 65536)
        if not publish and source.buffer.read(1):
            raise ApprovalRefused("unexpected preview input")
        selected = load_declared_bootstrap_context()
        verify_bootstrap_generation(metadata=metadata, files={"bootstrap.json": config},
                                    expected=selected.context)
        digest = selected_publication_digest(metadata=metadata, config=config, selected=selected)
        if load_declared_bootstrap_context() != selected:
            raise ApprovalRefused("administrator selection changed during preview")
        print("Selected publication digest: " + digest, file=out)
        print("NOT approval, installed closure, runtime admission or activation.", file=out)
        if not publish:
            print("Preview only; no files published.", file=out)
            return 0
        supplied = line("Re-enter the reviewed selected publication digest (sha256:...):", 71).decode("ascii")
        if supplied != digest:
            raise ApprovalRefused("selected publication confirmation differs")
        if line("Type PUBLISH to confirm this new generation publication:", 16) != b"PUBLISH":
            raise ApprovalRefused("publication not confirmed")
        publish_selected_bootstrap_generation(metadata=metadata, config=config,
                                              confirmed_digest=supplied, confirmed_publish=True)
    except BootstrapGenerationDurabilityUncertain:
        print("Generation may be published; durability UNCONFIRMED. Inspect retained state; do not retry automatically.", file=out)
        return 2
    except (ApprovalRefused, GenerationRefused, OSError, AttributeError, ValueError):
        print("Bootstrap generation operation refused; inspect retained state before retry. No activation performed.", file=out)
        return 1
    print("Bootstrap generation published; NOT admitted and no service activated.", file=out)
    return 0


def run_loaded_units_preview(*, source, out):
    """Read-only check of supplied admission.json and loaded-units.json lines.

    Nothing is installed, read from the host, or authorized; live units and the
    systemd profile are still checked at admission.
    """
    try:
        if source.isatty():
            raise ApprovalRefused("preview needs redirected input")

        def line(limit):
            raw = source.buffer.readline(limit + 2)
            if not raw.endswith(b"\n") or len(raw) > limit + 1:
                raise ApprovalRefused("bounded complete input lines required")
            return raw[:-1]

        admission = line(8192)
        loaded_raw = line(65536)
        if source.buffer.read(1):
            raise ApprovalRefused("unexpected preview input")
        # The pin is tautological: only canonicality and type checks apply here.
        digest = "sha256:" + sha256(admission).hexdigest()
        policy = decode_pinned_prestart_policy(admission, expected_digest=digest)
        if policy.loaded_policy_digest is None:
            raise ApprovalRefused("v4 or v5 admission policy required")
        decode_loaded_bootstrap_policy(loaded_raw, prestart_policy=policy)
    except (ApprovalRefused, GenerationRefused, OSError, AttributeError, ValueError,
            RecursionError, TypeError):
        print("Loaded-units preview refused; no changes made.", file=out)
        return 1
    version = "v5" if policy.first_install_genesis is not None else "v4"
    print(f"Loaded-units policy valid against the supplied {version} admission policy; "
          "NOT installed, NOT admitted, NOT authorized.", file=out)
    print("Admission policy SHA-256 (deployment policy_digest): " + digest, file=out)
    print("Loaded-units policy SHA-256 (admission loaded_policy_digest): sha256:"
          + sha256(loaded_raw).hexdigest(), file=out)
    print("Digests are of the supplied bytes only, not verified pins; package, closure, "
          "live loaded units and systemd profile are checked only at admission.", file=out)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="az-nexus-bootstrap")
    parser.add_argument("operation", choices=("generation-preview", "generation-publish",
                                               "time-initialize", "time-recover",
                                               "observe-packages", "loaded-units-preview"))
    args = parser.parse_args(argv)
    if args.operation == "observe-packages":
        return run_package_observation(out=sys.stdout)
    if args.operation == "loaded-units-preview":
        return run_loaded_units_preview(source=sys.stdin, out=sys.stdout)
    if args.operation in {"time-initialize", "time-recover"}:
        return run_time(source=sys.stdin, out=sys.stdout, recovery=args.operation == "time-recover")
    return run_generation(source=sys.stdin, out=sys.stdout,
                          publish=args.operation == "generation-publish")


if __name__ == "__main__":
    raise SystemExit(main())
