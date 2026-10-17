"""Read-only local observations for setup; no service-manager or runtime imports."""

import json
import shlex
from dataclasses import asdict
from pathlib import Path

from .activation import CORE_UNITS
from .bootstrap_deployment_store import load_bootstrap_deployment
from .bootstrap_selection_store import load_bootstrap_selection
from .commissioning import propose
from .commissioning_draft import read_draft_review_inputs, verify_draft_review
from .hil_preflight import collect_readonly_inventory
from .installed_files import measure_installed_files
from .inventory import read_interfaces
from .lite_import import CommissionedLite, LiteImport
from .lite_trust import TrustStore
from .mission_pack import MissionPack
from .mission_pack_cli import _context
from .model_catalog import artifact_filename
from .model_import import CommissionedModels
from .model_paths import bounded_read, load_model_trust
from .operator_flow import NOTICE, Observation, State, evaluate, next_step
from .operator_store import load_operator_trust

KNOWLEDGE_ROOT = Path("/var/lib/azazel/knowledge")


def add_parser(sub):
    parser = sub.add_parser("setup", help="read-only ordered operator setup guidance")
    parser.add_argument("--next", action="store_true", help="show only the first unresolved step")
    parser.add_argument("--json", action="store_true", help="machine-readable guidance")
    parser.add_argument("--installed-manifest", type=Path, help="independently reviewed installed manifest")
    parser.add_argument("--manifest-digest", help="independently reviewed sha256:hex manifest pin")
    parser.add_argument("--operator", help="enrolled label for read-only signed draft review")


def collect(args, *, now, root=Path("/")):
    """Read fixed paths. root is a fixture seam, not a CLI trust override.

    Strict protected readers retain their own fixed paths and ownership rules.
    Exceptions are deliberately redacted: identity, keys and config stay local.
    """
    observations = {}

    def path(absolute):
        return root / absolute.lstrip("/")

    def observe(name, command, reader, reason):
        try:
            detail = reader()
            observations[name] = Observation(State.COMPLETE, detail or reason, command)
        except Exception:  # noqa: BLE001 - read failures cannot become success or disclose inputs
            observations[name] = Observation(State.REFUSED, reason + "; read/verification refused", command)

    def presence(name, paths, command, reason):
        try:
            missing = [item.name for item in paths if not item.is_file()]
            observations[name] = Observation(
                State.MISSING if missing else State.COMPLETE,
                reason + ("; missing: " + ", ".join(missing) if missing else "; present (not verified)"),
                command,
            )
        except OSError:
            observations[name] = Observation(State.REFUSED, reason + "; presence unreadable", command)

    wrappers = tuple(path("/usr/libexec/azazel/" + name) for name in (
        "az-activated", "az-commissiond", "az-auditd", "az-mio-entryd", "az-knowledge-lited"))
    presence("installed-files", wrappers,
             "sudo env PYTHON=/opt/azazel-nexus/venv/bin/python sh packaging/install.sh",
             "selected runtime entrypoints")
    if observations["installed-files"].state is State.COMPLETE:
        observations["installed-files"] = Observation(
            State.UNKNOWN, "entrypoints present; independently reviewed selected-file manifest/pin required",
            "azazel-nexus installed-files-candidate --help")
        if args.installed_manifest and args.manifest_digest:
            command = ("azazel-nexus installed-files-check --manifest-digest "
                       + shlex.quote(args.manifest_digest) + " < " + shlex.quote(str(args.installed_manifest)))
            observe("installed-files", command, lambda: _installed(args),
                    "selected-file measurement only; no dependency closure or runtime admission")

    def host():
        inventory = collect_readonly_inventory(
            interfaces=read_interfaces(), record_directory=path("/etc/azazel/commissioning"))
        missing = inventory.missing
        return Observation(
            State.MISSING if missing else State.COMPLETE,
            "host inventory only; " + ("unestablished: " + ", ".join(missing) if missing
                                       else "A-1 through A-11 observed; operator HIL decisions still required"),
            "azazel-nexus hil-preflight")
    _observation(observations, "host-preflight", host, "azazel-nexus hil-preflight")

    directory = path("/etc/azazel/commissioning")
    record = directory / "commissioning.json"
    draft = directory / "commissioning-draft.json"
    def commissioning():
        presence("commissioning", [record if record.is_file() else draft],
                 "azazel-nexus commission --help", "local commissioning record/draft presence only")
        return observations["commissioning"]
    _observation(observations, "commissioning", commissioning, "azazel-nexus commission --help")
    review_command = ("azazel-nexus commission-review --operator " + shlex.quote(args.operator)
                      if args.operator else "azazel-nexus commission-review --help")
    observations["commission-review"] = Observation(
        State.UNKNOWN, "signed draft review requires an enrolled operator label; presence is not review", review_command)
    if args.operator:
        def review():
            payload, signature = read_draft_review_inputs()
            verify_draft_review(payload=payload, signature=signature, operator=args.operator,
                                trust=load_operator_trust(), current=propose(read_interfaces()))
        observe("commission-review", review_command, review,
                "signed assigned-binding draft review only; no full inventory/profile or activation proof")

    for name, filename, reader in (
        ("bootstrap-deployment", "deployment", load_bootstrap_deployment),
        ("bootstrap-selection", "selection", load_bootstrap_selection),
    ):
        command = "azazel-nexus bootstrap-" + filename + "-initialize"

        def bootstrap(name=name, filename=filename, reader=reader, command=command):
            presence(name, [path("/etc/azazel/bootstrap/" + filename + ".json")], command,
                     "bootstrap " + filename)
            if path("/etc/azazel/bootstrap/" + filename + ".pending").exists():
                return Observation(
                    State.REFUSED, "unfinished publication; inspect retained state before explicit recovery",
                    "azazel-nexus bootstrap-" + filename + "-recover")
            if observations[name].state is State.COMPLETE:
                observe(name, "azazel-nexus setup", lambda: _read_only(reader),
                        "protected bootstrap " + filename + " read; no start grant or activation")
            return observations[name]
        _observation(observations, name, bootstrap, command)

    lite_root = path(str(KNOWLEDGE_ROOT))

    def lite():
        reading = LiteImport(CommissionedLite(lite_root)).read(query_as_of=now)
        return Observation(
            State.COMPLETE if reading.overall == "available" else
            State.REFUSED if reading.overall == "quarantined" else State.MISSING,
            "Knowledge Lite: " + reading.overall + "; integrity: " + reading.integrity.value
            + "; freshness: " + reading.time_bound.value + "; deterministic path continues",
            "azazel-nexus status")
    _observation(observations, "knowledge-store", lite, "azazel-nexus status")

    def trust():
        store = TrustStore(path("/var/lib/azazel/lite-trust"))
        if not store.is_pinned():
            return Observation(State.MISSING, "daemon Lite trust pin absent", "azazel-nexus status")
        store.pinned_at()
        return Observation(State.COMPLETE,
                           "daemon Lite trust pin readable; commissioning binding and store trust remain separate checks",
                           "azazel-nexus status")
    _observation(observations, "knowledge-trust", trust, "azazel-nexus status")

    def pack():
        state = MissionPack(_context()).status(now=now)
        return Observation(State.COMPLETE if state["state"] == "active" else
                           State.REFUSED if state["state"] == "degraded" else State.MISSING,
                           "Mission Pack selection: " + state["state"] + "; no provider admission",
                           "azazel-nexus pack --help")
    _observation(observations, "mission-pack", pack, "azazel-nexus pack --help")
    fetch = path("/var/lib/azazel/fetch/commission")
    presence("fetch-commissioning", [fetch / name for name in (
        "trust.json", "sources.signed", "catalog.signed", "ca.pem", "addresses.json", "consent.json")],
        "systemctl status azazel-model-fetchd.service --no-pager",
        "fetch commissioning required files; runtime owns verification and optional client identity")

    def candidates():
        models = path("/var/lib/azazel/models")
        keys, digest, _ = load_model_trust(models / "trust/trust.json")
        catalog = CommissionedModels(models, keys, digest).catalog()
        ready = path("/var/lib/azazel/fetch/ready")
        entries = sorted((entry for entry in catalog.entries
                          if (ready / artifact_filename(entry)).is_file()), key=lambda entry: entry.model_id)
        ids = [entry.model_id for entry in entries]
        command = "azazel-nexus model-import-fetched --help"
        license_note = ""
        if entries:
            command = "sudo azazel-nexus model-import-fetched " + shlex.quote(ids[0])
            if entries[0].license_acknowledgement_required:
                command += " --acknowledge-license"
                license_note = "; review license before explicitly acknowledging it"
        return Observation(State.MISSING if ids else State.OPTIONAL,
                           "fetched candidates (unverified bytes): " + (", ".join(ids) if ids else "none")
                           + "; import never grants provider admission" + license_note, command)

    _observation(observations, "model-import-fetched", candidates,
                 "azazel-nexus model-import-fetched --help")

    units = tuple(dict.fromkeys(("azazel-activated.service", *(unit.name for unit in CORE_UNITS),
                                "azazel-mio-entryd.service", "azazel-knowledge-lited.service")))

    def unit_state():
        masks = []
        missing_units = []
        for unit in units:
            if not any(path(base + unit).is_file() for base in
                       ("/lib/systemd/system/", "/usr/lib/systemd/system/")):
                missing_units.append(unit)
            link = path("/etc/systemd/system/" + unit)
            if link.is_symlink() and link.readlink() == Path("/dev/null"):
                masks.append(unit)
        return Observation(
            State.UNKNOWN, "live unit state unobserved (no service-manager calls); observed masks: "
            + (", ".join(masks) if masks else "none")
            + "; missing unit files: " + (", ".join(missing_units) if missing_units else "none")
            + "; no enforcement readiness established", unit_command)
    unit_command = "systemctl status " + " ".join(units) + " --no-pager"
    _observation(observations, "activation-units", unit_state, unit_command)
    return observations


def _read_only(reader):
    reader()


def _installed(args):
    result = measure_installed_files(bounded_read(args.installed_manifest, 1024 * 1024),
                                     expected_digest=args.manifest_digest)
    return f"selected files verified: {result.file_count}; no dependency closure or runtime admission"


def _observation(observations, name, reader, command):
    try:
        observations[name] = reader()
    except Exception:  # noqa: BLE001 - redact local configuration and fail closed
        observations[name] = Observation(State.REFUSED, "local state unavailable or verification refused", command)


def run(args, *, now, out):
    if bool(args.installed_manifest) != bool(args.manifest_digest):
        message = "setup requires --installed-manifest and --manifest-digest together"
        print(json.dumps({"schema": "azazel-nexus/setup/1", "read_only": True,
                          "error": message}) if args.json else message, file=out)
        return 2
    steps = evaluate(collect(args, now=now))
    selected = (next_step(steps),) if args.next else steps
    if args.json:
        print(json.dumps({"schema": "azazel-nexus/setup/1", "read_only": True,
                          "hg05": "unmeasured", "provider_admission": "blocked",
                          "enforcement_readiness": "not-established", "notice": NOTICE,
                          "steps": [asdict(step) for step in selected]}, sort_keys=True), file=out)
    else:
        print(NOTICE, file=out)
        for step in selected:
            print(f"{step.name}: {step.status} — {step.reason}\n  next: {step.next_command}", file=out)
    return 0
