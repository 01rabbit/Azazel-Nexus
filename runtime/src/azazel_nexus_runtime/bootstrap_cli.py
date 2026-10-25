"""Administrator provisioning command, never a service activation entrypoint."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys

from azazel_nexus.bootstrap_generation import verify_bootstrap_generation
from azazel_nexus.bootstrap_prestart_policy import decode_pinned_prestart_policy
from azazel_nexus.bootstrap_generation_publish import BootstrapGenerationDurabilityUncertain
from azazel_nexus.bootstrap_approval import (
    bootstrap_payload, parse_bootstrap_time, verify_bootstrap_approval,
)
from azazel_nexus.bootstrap_approval_install import (
    ApprovalPlacementUncertain, install_bootstrap_approval,
)
from azazel_nexus.bootstrap_clock_store import (
    TimeDurabilityUncertain, load_administrator_time_window,
)
from azazel_nexus.bootstrap_selection import decode_bootstrap_selection
from azazel_nexus.bootstrap_selection_store import (
    SelectionDurabilityUncertain, SelectionReadRefused, initialize_bootstrap_selection,
    load_bootstrap_selection,
)
from azazel_nexus.bootstrap_store import load_bootstrap_approval, read_bootstrap_approval_policy
from azazel_nexus.generation import GenerationRefused
from azazel_nexus.operator_store import load_operator_trust
from azazel_nexus.operator_trust import (
    MAX_APPROVAL_BYTES, ApprovalPurpose, ApprovalRefused, approval_message,
)

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


_ACTOR = "az-nexus-bootstrap"


def _record_activation_event(event):
    """Durable, hash-chained record in the activation ledger (as #335 does).

    Returns True only after a confirmed append; anything else raises, so a
    store that requires ``is True`` changes nothing. ``occurred_at`` is the OS
    clock as a label only, never trusted time.
    """
    from azazel_nexus.audit import AuditEntry
    from .activated import _activation_ledger  # lazy: same ledger as the controller

    entry = _activation_ledger(Path("/")).append({
        **event,
        "occurred_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"),
        "actor": _ACTOR,
    })
    if type(entry) is not AuditEntry:
        raise ApprovalRefused("activation ledger record unconfirmed")
    return True


def _record_prior_boot(event):
    """Trusted composition callback for the owner's confirmed operations only."""
    return _record_activation_event(event)


def _terminal_reader(source, out):
    def line(prompt, limit):
        print(prompt, file=out, flush=True)
        raw = source.buffer.readline(limit + 2)
        if not raw.endswith(b"\n") or len(raw) > limit + 1:
            raise ApprovalRefused("bounded complete input lines required")
        return raw[:-1]

    return line


def _time_publication(line, out, *, recovery):
    """The time-record interaction; raises on refusal, publishes on success."""
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
    if recovery:
        publish_selected_administrator_time(raw=raw, confirmed_digest=digest,
                                            confirmed_operation=True, recovery=True)
    else:
        # A time record of a previous boot is recorded and moved aside first.
        publish_selected_administrator_time(raw=raw, confirmed_digest=digest,
                                            confirmed_operation=True, recovery=False,
                                            record_prior_boot=_record_prior_boot)


def run_time(*, source, out, recovery):
    """Explicit terminal confirmation; never obtain UTC from the OS clock."""
    try:
        if type(recovery) is not bool or not source.isatty():
            raise ApprovalRefused("interactive exact operation required")
        _time_publication(_terminal_reader(source, out), out, recovery=recovery)
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


_REQUEST_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def _load_approval_policy():
    """Read the protected bootstrap approval policy exactly as the verifier does."""
    return read_bootstrap_approval_policy()


def _request_times(raw):
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ApprovalRefused("canonical validity JSON required") from None
    if (type(document) is not dict or set(document) != {"expires_at", "granted_at"}
            or json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8") != raw):
        raise ApprovalRefused("canonical validity JSON required")
    granted, expires = document["granted_at"], document["expires_at"]
    if any(type(v) is not str or _REQUEST_TIME.fullmatch(v) is None for v in (granted, expires)):
        raise ApprovalRefused("whole-second UTC required")
    return granted, expires


def _approval_request(raw):
    """Payload bytes for owner-chosen validity bounds; signs and writes nothing."""
    granted, expires = _request_times(raw)
    selected = load_declared_bootstrap_context()
    policy = _load_approval_policy()
    if selected.operator not in policy.operators:
        raise ApprovalRefused("operator not authorized for bootstrap purpose")
    if selected.context.approval_policy_digest != policy.digest():
        raise ApprovalRefused("bootstrap approval policy binding mismatch")
    payload = bootstrap_payload(context=selected.context, operator=selected.operator,
                                granted_at=granted, expires_at=expires)
    # bootstrap_payload already refuses expires <= granted.
    if ((parse_bootstrap_time(expires) - parse_bootstrap_time(granted)).total_seconds()
            > policy.max_seconds):
        raise ApprovalRefused("validity exceeds policy")
    message = approval_message(ApprovalPurpose.SUPPORTING_BOOTSTRAP, payload)
    if load_declared_bootstrap_context() != selected:
        raise ApprovalRefused("administrator selection changed")
    return payload, message


def _print_approval_request(payload, message, out):
    print(payload.decode("ascii"), file=out)
    print("Payload SHA-256: sha256:" + sha256(payload).hexdigest(), file=out)
    print("Signed message = b'azazel-nexus/operator-approval/v1\\x00supporting-bootstrap\\x00' "
          "+ payload; SHA-256: sha256:" + sha256(message).hexdigest(), file=out)
    print("Sign the message off-host with the enrolled operator's Ed25519 key; save the payload "
          "bytes (without a trailing newline) as approval.json and the 64-byte raw signature as "
          "approval.sig, then run: sudo az-nexus-bootstrap approval-install --payload "
          "approval.json --signature approval.sig --confirm-sha256 "
          + sha256(payload).hexdigest() + ". "
          "This command signs nothing and authorizes nothing.", file=out)
    print("Built from the declared context only: package/closure/systemd drift, operator "
          "enrollment or revocation, the trusted time window and a kernel reboot (new boot_id; "
          "soft-reboot keeps the boot_id) "
          "can still make admission refuse a correctly signed approval.", file=out)


def run_approval_request(*, source, out):
    """Print the exact bytes an operator must sign off-host; signs and authorizes nothing.

    Read-only. Context and operator come only from protected declarations;
    validity bounds are owner-chosen stdin values, never defaults.
    """
    try:
        if source.isatty():
            raise ApprovalRefused("request needs redirected input")
        raw = source.buffer.readline(258)
        if not raw.endswith(b"\n") or len(raw) > 257:
            raise ApprovalRefused("bounded complete input line required")
        if source.buffer.read(1):
            raise ApprovalRefused("unexpected request input")
        payload, message = _approval_request(raw[:-1])
    except (ApprovalRefused, GenerationRefused, OSError, AttributeError, ValueError,
            RecursionError, TypeError):
        print("Approval request refused; no changes made.", file=out)
        return 1
    _print_approval_request(payload, message, out)
    return 0


def _read_supplied_file(path, *, limit):
    """An owner-supplied input: a regular single-link file, never a followed link."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
            raise ApprovalRefused("supplied file refused")
        chunks = bytearray()
        while len(chunks) <= limit:
            part = os.read(fd, limit + 1 - len(chunks))
            if not part:
                break
            chunks.extend(part)
        if len(chunks) != info.st_size:
            raise ApprovalRefused("supplied file changed while reading")
        return bytes(chunks)
    finally:
        os.close(fd)


def _verify_supplied_approval(payload, signature):
    """The bootstrap admission's verifier over this boot's whole trusted window.

    Context and operator come from protected declarations, trust from the
    enrolled operator store, time from this boot's administrator time record
    (both bounds, as the entrypoint verifies). Nothing here is relaxed.
    """
    selected = load_declared_bootstrap_context()
    policy = _load_approval_policy()
    trust = load_operator_trust()
    window = load_administrator_time_window(expected=selected.context)
    results = [verify_bootstrap_approval(trust=trust, expected=selected.context, policy=policy,
                                         operator=selected.operator, payload=payload,
                                         signature=signature, now=now)
               for now in (window.earliest_utc, window.latest_utc)]
    if results[0] != results[1]:
        raise ApprovalRefused("bootstrap approval differs across time bounds")
    if (load_declared_bootstrap_context() != selected or _load_approval_policy() != policy
            or load_operator_trust() != trust):
        raise ApprovalRefused("bootstrap inputs changed during verification")
    return results[0]


_HEX = re.compile(r"[0-9a-f]{64}")


def _is_root():
    return os.geteuid() == 0


def run_approval_install(*, payload_path, signature_path, confirm_sha256, out):
    """Verify a signed pair with the existing verifier, then place it (root).

    A verifier refusal changes nothing. A prior boot's pair is recorded in the
    activation ledger and moved aside; a pair of this boot is never replaced.
    Placement is not admission: the bootstrap entrypoint verifies it again.
    """
    stage = "nothing changed"
    try:
        if not _is_root():
            raise ApprovalRefused("approval-install requires root")
        if type(confirm_sha256) is not str or _HEX.fullmatch(confirm_sha256) is None:
            raise ApprovalRefused("--confirm-sha256 must be 64 lowercase hex characters")
        payload = _read_supplied_file(payload_path, limit=MAX_APPROVAL_BYTES)
        signature = _read_supplied_file(signature_path, limit=64)
        if len(signature) != 64:
            raise ApprovalRefused("approval signature must be 64 raw bytes")
        if sha256(payload).hexdigest() != confirm_sha256:
            raise ApprovalRefused("payload SHA-256 differs from --confirm-sha256")
        verified = _verify_supplied_approval(payload, signature)

        def recheck():
            if _verify_supplied_approval(payload, signature) != verified:
                raise ApprovalRefused("bootstrap approval verification changed")

        print(f"Verified bootstrap approval: operator {verified.operator}, valid "
              f"{verified.granted_at} .. {verified.expires_at}.", file=out)
        stage = "approval placement may be incomplete"
        install_bootstrap_approval(payload, signature, recheck=recheck,
                                   record_prior_boot=_record_prior_boot)
        stage = "approval placed; activation ledger record missing"
        _record_activation_event({
            "event_type": "bootstrap.approval_installed",
            "operator": verified.operator,
            "granted_at": verified.granted_at,
            "expires_at": verified.expires_at,
            "payload_sha256": verified.payload_digest,
        })
    except ApprovalPlacementUncertain:
        print("Approval placement durability UNCONFIRMED. Inspect /etc/azazel/bootstrap; "
              "do not retry automatically. Nothing admitted.", file=out)
        return 2
    except Exception:  # noqa: BLE001 - redacted labels only
        if stage == "approval placed; activation ledger record missing":
            print(f"Approval install stopped ({stage}). Inspect before retrying. "
                  "Nothing admitted.", file=out)
            return 2
        print("Approval install refused; inspect retained state before retry. "
              "Nothing admitted.", file=out)
        return 1
    print("Approval installed. This is NOT admission: the bootstrap entrypoint verifies it "
          "again with its own fresh observation.", file=out)
    return 0


_RESUMABLE_SELECTION = frozenset({"required bootstrap input missing",
                                  "boot binding differs from the current boot"})
_STEPS = ("selection", "time", "approval request")


def _selection_current():
    """True when this boot's selection is readable; False when it can be created."""
    try:
        load_bootstrap_selection()
    except SelectionReadRefused as refusal:
        if refusal.reason in _RESUMABLE_SELECTION:
            return False
        raise
    return True


def _selection_publication(line, out):
    raw = line("Enter canonical per-boot selection JSON (not secrets):", 4096)
    decode_bootstrap_selection(raw)
    print("Selection is NOT approval, admission or activation. No deadline is reset.", file=out)
    print("Selection SHA-256: " + sha256(raw).hexdigest(), file=out)
    digest = line("Re-enter the reviewed SHA-256:", 64).decode("ascii")
    if digest != sha256(raw).hexdigest():
        raise ApprovalRefused("digest confirmation differs")
    if line("Type INITIALIZE to confirm this operation:", 16) != b"INITIALIZE":
        raise ApprovalRefused("operation not confirmed")
    # A selection of a previous boot is recorded and moved aside first.
    initialize_bootstrap_selection(raw, confirmed_sha256=digest, confirmed_initialize=True,
                                   record_prior_boot=_record_prior_boot)


def _time_current(selected):
    try:
        load_administrator_time_window(expected=selected.context)
    except ApprovalRefused:
        return False
    return True


def _approval_current(selected):
    try:
        window = load_administrator_time_window(expected=selected.context)
        for now in (window.earliest_utc, window.latest_utc):
            load_bootstrap_approval(expected=selected.context, operator=selected.operator, now=now)
    except ApprovalRefused:
        return False
    return True


def run_boot_initialize(*, source, out):
    """One terminal session for the per-boot records, in order, resumable.

    Every step keeps its own confirmations (digest re-entry and INITIALIZE for
    selection and time; owner-chosen validity for the request). A step already
    complete for this boot is detected from the protected readers and skipped,
    so a re-run continues where a refusal stopped. It signs nothing and places
    no approval: run ``approval-install`` with the signed pair.
    """
    done = []
    step = _STEPS[0]

    def report(outcome):
        print(f"Stopped at step '{step}' ({outcome}). Completed for this boot: "
              + (", ".join(done) if done else "none")
              + ". Re-run az-nexus-bootstrap boot-initialize to continue; completed "
              "steps are skipped.", file=out)

    try:
        if not source.isatty():
            raise ApprovalRefused("interactive confirmation required")
        line = _terminal_reader(source, out)
        print("Step 1/3: per-boot selection", file=out)
        if _selection_current():
            print("Selection for this boot already published; skipped.", file=out)
        else:
            _selection_publication(line, out)
            print("Selection published; NOT approval, admission or activation.", file=out)
        done.append(step)
        step = _STEPS[1]
        print("Step 2/3: administrator time record", file=out)
        selected = load_declared_bootstrap_context()
        if _time_current(selected):
            print("Time record for this boot already valid; skipped.", file=out)
        else:
            _time_publication(line, out, recovery=False)
            print("Time record published; no OS clock change, deadline reset or activation "
                  "performed.", file=out)
        done.append(step)
        step = _STEPS[2]
        print("Step 3/3: approval request", file=out)
        if _approval_current(selected):
            print("A verified approval for this boot is already installed; skipped.", file=out)
        else:
            raw = line('Enter validity JSON {"expires_at":"...","granted_at":"..."} '
                       "(one line, whole-second UTC):", 256)
            payload, message = _approval_request(raw)
            _print_approval_request(payload, message, out)
        done.append(step)
    except (SelectionDurabilityUncertain, TimeDurabilityUncertain):
        report("durability UNCONFIRMED; inspect retained state, do not retry automatically")
        return 2
    except (ApprovalRefused, GenerationRefused, OSError, AttributeError, ValueError,
            RecursionError, TypeError):
        report("refused; inspect retained state")
        return 1
    print("Per-boot records ready. No approval was signed or placed and nothing was "
          "activated.", file=out)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="az-nexus-bootstrap")
    parser.add_argument("operation", choices=("generation-preview", "generation-publish",
                                               "time-initialize", "time-recover",
                                               "observe-packages", "loaded-units-preview",
                                               "approval-request", "approval-install",
                                               "boot-initialize"))
    parser.add_argument("--payload")
    parser.add_argument("--signature")
    parser.add_argument("--confirm-sha256")
    args = parser.parse_args(argv)
    install_options = (args.payload, args.signature, args.confirm_sha256)
    if args.operation == "approval-install":
        if any(value is None for value in install_options):
            parser.error("approval-install requires --payload, --signature and --confirm-sha256")
        return run_approval_install(payload_path=args.payload, signature_path=args.signature,
                                    confirm_sha256=args.confirm_sha256, out=sys.stdout)
    if any(value is not None for value in install_options):
        parser.error("--payload, --signature and --confirm-sha256 apply to approval-install only")
    if args.operation == "boot-initialize":
        return run_boot_initialize(source=sys.stdin, out=sys.stdout)
    if args.operation == "observe-packages":
        return run_package_observation(out=sys.stdout)
    if args.operation == "approval-request":
        return run_approval_request(source=sys.stdin, out=sys.stdout)
    if args.operation == "loaded-units-preview":
        return run_loaded_units_preview(source=sys.stdin, out=sys.stdout)
    if args.operation in {"time-initialize", "time-recover"}:
        return run_time(source=sys.stdin, out=sys.stdout, recovery=args.operation == "time-recover")
    return run_generation(source=sys.stdin, out=sys.stdout,
                          publish=args.operation == "generation-publish")


if __name__ == "__main__":
    raise SystemExit(main())
