"""Administrator pre-start policy bindings, not measured health or admission.

Schemas v3/v4 describe existing-history bootstrap. Schema v5 additionally
carries an explicit, closed first-install genesis record (empty ledger, sequence
0) that is only valid inside the digest the operator signs. External rollback
anchoring and implicit defaults are still not represented.
"""

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re

from .audit import GENESIS_HASH
from .bootstrap_approval import BOOTSTRAP_UNITS, BootstrapContext
from .bootstrap_clock import AdministratorClockLimits
from .operator_store import _unique_object
from .operator_trust import ApprovalRefused


_NODE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
GENESIS_AUDIT_MODE = "first-install-genesis"
EXISTING_AUDIT_MODE = "existing-history"
_V5_SCHEMA = "azazel-nexus/bootstrap-prestart-policy/v5"


@dataclass(frozen=True)
class FirstInstallGenesis:
    """Owner-published record that this node's audit ledger is expected empty."""

    node_digest: str
    provisioning_id: str

    def __post_init__(self):
        if (type(self.node_digest) is not str or not _NODE_DIGEST.fullmatch(self.node_digest)
                or type(self.provisioning_id) is not str
                or not _UUID.fullmatch(self.provisioning_id)):
            raise ApprovalRefused("first-install genesis record refused")


@dataclass(frozen=True, repr=False)
class BootstrapPrestartPolicy:
    """Protected expected values; not a measured health/admission report.

    ``unit_closure_digest`` pins the canonical selected-installed-files
    manifest used by bootstrap admission. The selected-file measurement is
    intentionally narrower than complete process/import/systemd closure.
    """

    package_digest: str
    unit_closure_digest: str
    systemd_profile_digest: str
    min_usable_memory_mib: int
    min_online_logical_cpus: int
    min_mission_available_mib: int
    bootstrap_bytes: int
    bootstrap_inodes: int
    audit_bytes: int
    audit_inodes: int
    audit_sequence: int
    audit_head: str
    max_audit_bytes: int
    max_audit_segments: int
    max_anchor_lifetime_ns: int
    max_uncertainty_ns: int
    drift_ppb: int
    loaded_policy_digest: str | None = None
    first_install_genesis: FirstInstallGenesis | None = None

    @property
    def audit_mode(self) -> str:
        return EXISTING_AUDIT_MODE if self.first_install_genesis is None else GENESIS_AUDIT_MODE

    @property
    def expected_audit_head(self) -> tuple[int, str]:
        return (self.audit_sequence, self.audit_head)

    def __post_init__(self):
        self.clock_limits()
        genesis = self.first_install_genesis
        if genesis is not None:
            if (type(genesis) is not FirstInstallGenesis or self.loaded_policy_digest is None
                    or type(self.audit_sequence) is not int or self.audit_sequence != 0
                    or self.audit_head != GENESIS_HASH):
                raise ApprovalRefused("first-install genesis policy refused")
        for name, value in asdict(self).items():
            if name == "first_install_genesis":
                continue  # Closed record validated by its own type above.
            if name == "audit_sequence" and genesis is not None:
                continue  # Exactly 0, checked above.
            if name == "drift_ppb":
                continue  # Explicit zero is permitted; exact type/range checked above.
            if name == "loaded_policy_digest" and value is None:
                continue
            if name in {"package_digest", "unit_closure_digest", "systemd_profile_digest", "audit_head"}:
                pattern = r"[0-9a-f]{64}" if name == "audit_head" else r"sha256:[0-9a-f]{64}"
                if type(value) is not str or re.fullmatch(pattern, value) is None:
                    raise ApprovalRefused("prestart policy digest refused")
            elif name == "loaded_policy_digest":
                if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                    raise ApprovalRefused("prestart policy digest refused")
            elif type(value) is not int or not 0 < value < 2**63:
                raise ApprovalRefused("explicit bounded prestart policy values required")

    def clock_limits(self) -> AdministratorClockLimits:
        return AdministratorClockLimits(self.max_anchor_lifetime_ns, self.max_uncertainty_ns, self.drift_ppb)


def encode_prestart_policy(policy: BootstrapPrestartPolicy) -> bytes:
    if type(policy) is not BootstrapPrestartPolicy:
        raise ApprovalRefused("explicit prestart policy required")
    genesis = policy.first_install_genesis
    if genesis is not None:
        if policy.loaded_policy_digest is None:
            raise ApprovalRefused("v5 loaded policy digest required")
        version = "v5"
    else:
        version = "v4" if policy.loaded_policy_digest is not None else "v3"
    values = asdict(policy)
    values.pop("first_install_genesis")
    if version == "v3":
        values.pop("loaded_policy_digest")
    extra = {"audit_mode": EXISTING_AUDIT_MODE}
    if version == "v5":
        values.pop("audit_sequence")
        values.pop("audit_head")
        extra = {"audit_mode": GENESIS_AUDIT_MODE, "audit_genesis": {
            "sequence": 0, "head": GENESIS_HASH,
            "node_digest": genesis.node_digest, "provisioning_id": genesis.provisioning_id,
        }}
    return json.dumps({
        "schema": f"azazel-nexus/bootstrap-prestart-policy/{version}",
        "units": BOOTSTRAP_UNITS, "audit_assurance": "LOCAL_CONTINUITY_ONLY",
        **extra, **values,
    }, sort_keys=True, separators=(",", ":")).encode()


def decode_prestart_policy(raw: bytes, *, expected: BootstrapContext) -> BootstrapPrestartPolicy:
    """Bind the independently pinned policy to the complete expected context."""
    try:
        if type(expected) is not BootstrapContext:
            raise ApprovalRefused("independent bootstrap context required")
        policy = decode_pinned_prestart_policy(raw, expected_digest=expected.policy_digest)
        if (policy.package_digest != expected.package_digest
                or policy.unit_closure_digest != expected.unit_closure_digest):
            raise ApprovalRefused("prestart policy scope/bindings differ")
        if (policy.first_install_genesis is not None
                and policy.first_install_genesis.node_digest != expected.node_digest):
            raise ApprovalRefused("genesis policy node differs")
        return policy
    except Exception:
        raise ApprovalRefused("bootstrap prestart policy refused") from None


def decode_pinned_prestart_policy(raw: bytes, *, expected_digest: str) -> BootstrapPrestartPolicy:
    """Decode declared expectations before context construction, not measurements."""
    try:
        if (type(expected_digest) is not str or type(raw) is not bytes
                or not 0 < len(raw) <= 8192
                or "sha256:" + sha256(raw).hexdigest() != expected_digest):
            raise ApprovalRefused("independent full policy digest differs")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if type(document) is not dict:
            raise ApprovalRefused("prestart policy object required")
        schema = document.get("schema")
        has_loaded_digest = "loaded_policy_digest" in document
        if schema == "azazel-nexus/bootstrap-prestart-policy/v3":
            if has_loaded_digest:
                raise ApprovalRefused("v3 policy cannot contain loaded policy digest")
        elif schema == "azazel-nexus/bootstrap-prestart-policy/v4":
            if not has_loaded_digest or document["loaded_policy_digest"] is None:
                raise ApprovalRefused("v4 loaded policy digest required")
        elif schema == _V5_SCHEMA:
            if not has_loaded_digest or document["loaded_policy_digest"] is None:
                raise ApprovalRefused("v5 loaded policy digest required")
        else:
            raise ApprovalRefused("unsupported prestart policy schema")
        if "first_install_genesis" in document:
            raise ApprovalRefused("unexpected genesis field")
        genesis = None
        if schema == _V5_SCHEMA:
            if (document.get("audit_mode") != GENESIS_AUDIT_MODE
                    or "audit_sequence" in document or "audit_head" in document):
                raise ApprovalRefused("v5 genesis audit mode required")
            record = document.pop("audit_genesis", None)
            if (type(record) is not dict
                    or set(record) != {"sequence", "head", "node_digest", "provisioning_id"}
                    or type(record["sequence"]) is not int or record["sequence"] != 0
                    or record["head"] != GENESIS_HASH):
                raise ApprovalRefused("v5 genesis record refused")
            genesis = FirstInstallGenesis(record["node_digest"], record["provisioning_id"])
            document["audit_sequence"] = 0
            document["audit_head"] = GENESIS_HASH
            document["first_install_genesis"] = genesis
        else:
            if document.get("audit_mode") != EXISTING_AUDIT_MODE or "audit_genesis" in document:
                raise ApprovalRefused("existing-history audit mode required")
        for key in ("schema", "units", "audit_assurance", "audit_mode"):
            document.pop(key)
        policy = BootstrapPrestartPolicy(**document)
        if encode_prestart_policy(policy) != raw:
            raise ApprovalRefused("prestart policy scope/bindings differ")
        return policy
    except Exception:
        raise ApprovalRefused("bootstrap prestart policy refused") from None
