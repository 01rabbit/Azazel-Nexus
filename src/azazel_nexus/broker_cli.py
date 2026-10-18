"""Read-only broker status/review. No admission or transition command surface."""

import json
import os
from datetime import datetime
from pathlib import Path

from .commissioning import CommissioningRecord, ConfirmedRole
from .integration_broker.broker import Broker
from .integration_broker.confinement import AdapterCommissioning, CredentialRef
from .model_paths import bounded_read


def broker_root(root=None):
    root = Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else root
    return root / "var/lib/azazel/integration-broker"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _json(path):
    return json.loads(bounded_read(path, 65536), object_pairs_hook=unique_object)


def commissioned_broker(root=None):
    """Fixed commissioner-owned local files, with separate signing role maps."""
    root = Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else root
    directory = root / "etc/azazel/integration-broker"
    doc = _json(directory / "commissioning.json")
    topo = doc["topology"]
    topology = CommissioningRecord(
        tuple(ConfirmedRole(tuple(tuple(pair) for pair in role["composite"]), role["role"],
                            role["confirmed_by"], role["confirmed_at"]) for role in topo["roles"]),
        tuple(topo["profiles_present"]), topo["created_at"])
    if topology.digest() != doc["commissioning_digest"]:
        raise ValueError("commissioning binding")
    def keys(name):
        return {k: bytes.fromhex(v) for k, v in doc[name].items()}
    sibling = {name: keys(name) for name in ("catalog_keys", "registry_keys", "revocation_keys", "bundle_keys")}
    broker = Broker(broker_root(root), trusted_keys=keys("adapter_keys"), topology=topology,
                    sibling_keys=sibling, edge_keys=keys("edge_keys"))
    return broker, directory


def status_summary(*, now, root=None):
    try:
        try:
            broker, _ = commissioned_broker(root)
        except FileNotFoundError:
            broker = Broker(broker_root(root))
        return broker.status(now=now)
    except Exception:  # noqa: BLE001 - corrupt evidence is never readiness
        return {"status_level": "CORE", "adapters": [], "reason": "local_state_refused",
                "core": "deterministic", "enforcement_ready": False,
                "transport": "transport unavailable: Fabric#25"}


def add_parser(sub):
    parser = sub.add_parser("broker", help="local integration assurance (read-only)")
    commands = parser.add_subparsers(dest="broker_command", required=True)
    status = commands.add_parser("status", help="adapters, state and bounded health")
    status.add_argument("--json", action="store_true")
    review = commands.add_parser("review", help="verify and render a signed manifest; no writes")
    review.add_argument("manifest_file", type=Path)


def run(args, *, now, out):
    try:
        if args.broker_command == "status":
            result = status_summary(now=now)
            if args.json:
                print(json.dumps(result, sort_keys=True), file=out)
            else:
                print("Integration broker: " + result["status_level"], file=out)
                for row in result["adapters"]:
                    print(f"  {row['adapter_id']}: {row['state']} ({row['reason']})", file=out)
                print(result.get("reason", result["transport"]), file=out)
                print("Core deterministic; enforcement readiness not established", file=out)
            return 0
        broker, directory = commissioned_broker()
        raw = bounded_read(args.manifest_file, 32832)
        # Verify before using even the adapter identifier to select a local file.
        from .integration_broker.manifest import read_manifest
        manifest = read_manifest(raw, trusted_keys=broker.trusted_keys,
                                 commissioning_digest=broker.topology.digest(), **broker.sibling_keys)
        doc = _json(directory / (manifest.adapter_id + ".json"))
        credential = CredentialRef(manifest.adapter_id, doc["credential_ref"],
                                   datetime.fromisoformat(doc["credential_expires_at"]),
                                   doc["credential_generation"], doc["credential_revoked"])
        commissioning = AdapterCommissioning(
            manifest.adapter_id, doc["account"], doc["credential_directory"],
            doc["installed_artifacts"], credential, datetime.fromisoformat(now))
        manifest, unit = broker.review(raw, commissioning=commissioning, now=now)
        print(f"Would admit {manifest.adapter_id} {manifest.version}; dry-run, no writes", file=out)
        print("Topology: " + ("eligible" if broker.topology.enforcement_ready else "OBSERVE_ONLY"), file=out)
        print(unit, file=out)
        print("Destination ports require separate enforcement; transport unavailable: Fabric#25", file=out)
        return 0
    except Exception:  # noqa: BLE001 - do not disclose commissioning or untrusted values
        print("broker: local state or manifest review refused; Core deterministic", file=out)
        return 1
