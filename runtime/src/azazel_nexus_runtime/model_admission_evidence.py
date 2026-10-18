"""Read-only embedding admission from fixed protected host files.

All admission data is opened relative to directory descriptors starting at /.
The private root-fd seam is solely for tests. No environment paths are consulted.
"""
from __future__ import annotations

import base64
import os
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from azazel_nexus import model_admission as admission
from azazel_nexus.audit import canonical_event_bytes
from azazel_nexus.cognition import LocalModelProvider, ResourceEvidence
from azazel_nexus.compatibility import (
    ADMITTED_ARCHITECTURE,
    HostFacts,
    TestedTuple,
    TestedTupleSet,
)
from azazel_nexus.core_reserve import CoreReserve, parse_record
from azazel_nexus.hil_records import MIO_CAMPAIGN_SCHEMA, Status, validate_record
from azazel_nexus.hil_records.evidence import verified_manifest_bytes
from azazel_nexus.model_catalog import (
    artifact_filename,
    read_catalog_bytes,
    verify_artifact_fd,
)
from azazel_nexus.model_import import generation_from_bytes
from azazel_nexus.model_paths import model_trust_bytes
from azazel_nexus.model_runtime import (
    LLAMA_EXECUTABLE,
    RuntimeRefused,
    llama_server_record,
    runtime_from_fd,
)
from azazel_nexus.operator_store import operator_trust_bytes
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus.resource_profile import ResourceProfile
from azazel_nexus.virtualization import virtualization_not_observed

DIRECTORY = "/etc/azazel/model-admission"
POLL_INTERVAL_SECONDS = 1.0
MAX_SNAPSHOT_RETRIES = 3
_FIXED = (DIRECTORY, DIRECTORY + "/embedding.approval", DIRECTORY + "/policy.json",
          DIRECTORY + "/evidence", "/etc/azazel/operator-trust",
          "/etc/azazel/operator-trust/operators.json", "/etc/azazel/mission-pack.json",
          "/etc/azazel/node.yaml", "/var/lib/azazel/models", "/var/lib/azazel/models/trust/trust.json",
          "/var/lib/azazel/models/trust/catalog.signed", "/var/lib/azazel/models/state/current",
          "/sys/hypervisor/type", "/proc/cpuinfo", "/run/systemd/container", "/.dockerenv",
          "/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name", "/proc/1/cgroup",
          "/var/lib/azazel/secrets/commissioning.key", "/etc/machine-id", "/usr/share/azazel/build-commit", LLAMA_EXECUTABLE)


@dataclass(frozen=True)
class Refused:
    symbol: str


@dataclass(frozen=True)
class Absent:
    pass


@dataclass(frozen=True)
class Admitted:
    evidence: admission.VerifiedModelAdmission
    entry: object
    provider: LocalModelProvider
    host: HostFacts
    tested: TestedTupleSet
    resources: ResourceEvidence
    record: object


@dataclass(frozen=True)
class AdmissionReading:
    embedding: Admitted | Refused | Absent
    watch_paths: tuple[str, ...] = ()
    snapshot: tuple = ()

    def close(self):
        if type(self.embedding) is Admitted:
            self.embedding.evidence.descriptors.close()

    def as_event(self):
        result = self.embedding
        doc = {"event_type": "mio.local.admission", "role": "embedding",
               "outcome": "admitted" if type(result) is Admitted else
               "absent" if type(result) is Absent else "refused",
               "refusal": result.symbol if type(result) is Refused else None,
               "approval_id": None, "payload_digest": None, "model_digest": None,
               "generation_id": None, "catalog_digest": None, "reserve_record_digest": None}
        if type(result) is Admitted:
            evidence = result.evidence
            ctx = evidence.context.bindings
            doc.update(approval_id=evidence.approval_id, payload_digest=evidence.payload_digest,
                       model_digest=ctx["model"]["digest"],
                       generation_id=ctx["generation"]["generation_id"],
                       catalog_digest=ctx["catalog"]["document_digest"],
                       reserve_record_digest=ctx["reserve"]["campaign_record_digest"])
        return doc


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_gid, info.st_nlink)


def fingerprint(paths):
    result = []
    for path in paths:
        try:
            info = os.lstat(path)
            result.append(_stamp(info))
        except OSError as error:
            result.append((type(error).__name__, error.errno))
    return tuple(result)


class ProtectedTree:
    def __init__(self, root_fd, owner):
        self.root_fd, self.owner = root_fd, owner
        self.watched = set(_FIXED)
        self.observed = {}
        self.phase = None
        self.admission_gid = None
        if owner == 0:
            import grp

            try:
                self.admission_gid = grp.getgrnam("azmio").gr_gid
            except KeyError as exc:
                raise ApprovalRefused("EVIDENCE_UNPROTECTED") from exc

    def check(self, fd, directory):
        info = os.fstat(fd)
        if (info.st_uid != self.owner or info.st_mode & 0o022
                or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or (not directory and info.st_nlink != 1)):
            raise ApprovalRefused("EVIDENCE_UNPROTECTED")
        return info

    def open(self, path, *, directory=False):
        parts = Path(path).parts
        if not Path(path).is_absolute() or ".." in parts:
            raise ApprovalRefused("EVIDENCE_UNPROTECTED")
        fd = os.dup(self.root_fd)
        try:
            self.check(fd, True)
            for index, component in enumerate(parts[1:]):
                is_dir = directory or index < len(parts) - 2
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
                if is_dir:
                    flags |= os.O_DIRECTORY
                child = os.open(component, flags, dir_fd=fd)
                os.close(fd)
                fd = child
                info = self.check(fd, is_dir)
                opened = "/" + "/".join(parts[1:index + 2])
                if ((opened == DIRECTORY or opened.startswith(DIRECTORY + "/"))
                        and (stat.S_IMODE(info.st_mode) != (0o750 if is_dir else 0o640)
                             or (self.admission_gid is not None and info.st_gid != self.admission_gid))):
                    raise ApprovalRefused("EVIDENCE_UNPROTECTED")
                self.observed["/" + "/".join(parts[1:index + 2])] = _stamp(info)
                self.watched.add("/" + "/".join(parts[1:index + 2]))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, limit=65536):
        fd = self.open(path)
        try:
            before = self.check(fd, False)
            if not 0 < before.st_size <= limit:
                raise ApprovalRefused("MALFORMED")
            raw = bytearray()
            while len(raw) <= limit:
                chunk = os.read(fd, min(8192, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if _stamp(before) != _stamp(self.check(fd, False)) or len(raw) != before.st_size:
                raise ApprovalRefused("EVIDENCE_CHANGED")
            return bytes(raw)
        finally:
            os.close(fd)

    def bundle(self):
        root = DIRECTORY + "/evidence"
        manifest = self.read(root + "/manifest.json", 4 * 1024 * 1024)
        # Structural parsing only; the signature and every artifact are checked below.
        import json
        doc = json.loads(manifest)
        refs = doc["A"]["artifacts"]
        if type(refs) is not dict or len(refs) > 126:
            raise ApprovalRefused("RESERVE_UNATTESTED")
        files = {"manifest.json": manifest, "manifest.sig": self.read(root + "/manifest.sig", 129)}
        for ref in refs.values():
            name = ref["path"]
            if (type(name) is not str or len(Path(name).parts) != 2
                    or Path(name).parts[0] != "artifacts" or ".." in Path(name).parts):
                raise ApprovalRefused("RESERVE_UNATTESTED")
            files[name] = self.read(root + "/" + name, 4 * 1024 * 1024)
            if sum(map(len, files.values())) > 16 * 1024 * 1024:
                raise ApprovalRefused("RESERVE_UNATTESTED")
        return files


def procfs_available():
    return sys.platform == "linux" and Path("/proc/self/fd").is_dir()


class HeldDescriptors:
    """Own the exact binary and weights inodes through spawn and withdrawal."""
    def __init__(self, binary_fd, model_fd, architecture, entry, license, owner):
        self.binary_fd, self.model_fd = binary_fd, model_fd
        self.architecture, self.entry, self.license = architecture, entry, license
        self.closed = False
        self.validity = None
        self.owner = owner
        self.watch_paths = ()
        self.snapshot = None

    def recheck(self):
        if self.closed or not procfs_available():
            raise RuntimeRefused("PROCFS_REQUIRED")
        if self.snapshot is not None and fingerprint(self.watch_paths) != self.snapshot:
            raise RuntimeRefused("EVIDENCE_CHANGED")
        for descriptor in (self.binary_fd, self.model_fd):
            info = os.fstat(descriptor)
            if info.st_uid != self.owner or info.st_mode & 0o022:
                raise RuntimeRefused("EVIDENCE_UNPROTECTED")
        if self.validity is not None:
            now = datetime.now(UTC)
            if not admission.utc(self.validity[0]) <= now < admission.utc(self.validity[1]):
                raise RuntimeRefused("EXPIRED")
        binary = runtime_from_fd(self.binary_fd, architecture=self.architecture)
        try:
            verify_artifact_fd(self.entry, self.model_fd, license=self.license)
        except Exception as exc:
            raise ApprovalRefused("ARTIFACT_REFUSED") from exc
        return binary

    def close(self):
        if not self.closed:
            self.closed = True
            os.close(self.binary_fd)
            os.close(self.model_fd)


def _host_and_tuples(doc):
    facts = dict(doc["host"])
    facts["profile"] = ResourceProfile(facts["profile"])
    for field in ("cpu_features", "fabric_features", "schema_features"):
        facts[field] = frozenset(facts[field])
    host = HostFacts(**facts)
    tuples = []
    for value in doc["tested_tuples"]:
        value = dict(value)
        value["profile"] = ResourceProfile(value["profile"])
        for name in ("cpu_features", "fabric_features", "schema_features"):
            value[name] = frozenset(value[name])
        tuples.append(TestedTuple(**value))
    return host, TestedTupleSet.of(tuples)


def _collect(tree, *, trust, policy, operator):
    """Independent context collection shared by loader and read-only request CLI."""
    import json

    from .hil_readiness import run_identity
    from .virtualization_observation import observe_virtualization

    if not procfs_available():
        raise ApprovalRefused("PROCFS_REQUIRED")
    tree.phase = "NODE_MISMATCH"
    config = json.loads(tree.read("/etc/azazel/mission-pack.json", 1024 * 1024))
    if config.get("schema") != "azazel-nexus/mission-pack-config/1":
        raise ApprovalRefused("NODE_MISMATCH")
    host, tested = _host_and_tuples(config)
    architecture = os.uname().machine
    if architecture != ADMITTED_ARCHITECTURE or host.architecture != architecture:
        raise ApprovalRefused("WRONG_ARCHITECTURE")
    identity = run_identity()
    observed = observe_virtualization()
    if not virtualization_not_observed(observed):
        raise ApprovalRefused("RESERVE_VIRTUALIZATION_OBSERVED")
    node_digest = admission.digest(tree.read("/etc/azazel/node.yaml", 1024 * 1024))
    tree.phase = "CATALOG_MISMATCH"
    keys, commissioning, _ = model_trust_bytes(tree.read("/var/lib/azazel/models/trust/trust.json"))
    if commissioning != config["commissioning_digest"]:
        raise ApprovalRefused("NODE_MISMATCH")
    catalog_raw = tree.read("/var/lib/azazel/models/trust/catalog.signed", 1024 * 1024 + 64)
    catalog = read_catalog_bytes(catalog_raw, trusted_keys=keys, commissioning_digest=commissioning)
    tree.phase = "GENERATION_MISMATCH"
    number_raw = tree.read("/var/lib/azazel/models/state/current", 32)
    number_raw = number_raw.strip()
    if not number_raw.isdigit() or not 0 < int(number_raw) < 10**12:
        raise ApprovalRefused("GENERATION_MISMATCH")
    number = int(number_raw)
    generation = generation_from_bytes(tree.read(
        f"/var/lib/azazel/models/state/generations/{number}.json", 1024 * 1024),
        number=number, commissioning_digest=commissioning)
    entries = [entry for entry in catalog.entries if entry.role == "embedding"
               and generation.installed.get(entry.model_id) == entry.digest]
    if len(entries) != 1:
        raise ApprovalRefused("GENERATION_MISMATCH")
    entry = entries[0]
    # Existing rollback lineage: an installed successor excludes its ancestors.
    if any(entry.model_id in other.rollback_lineage for other in catalog.entries
           if other.model_id in generation.installed):
        raise ApprovalRefused("CATALOG_MISMATCH")
    tree.phase = "TUPLE_MISMATCH"
    matched, _ = tested.admits(entry.digest, host, model_role="embedding")
    if matched is None or matched.architecture != architecture:
        raise ApprovalRefused("TUPLE_MISMATCH")
    if entry.runtime_abi != "llama.cpp/1" or entry.format != "gguf" or entry.context_limit < admission.EMBEDDING_CTX:
        raise ApprovalRefused("SETTINGS_MISMATCH")
    tree.phase = "RESERVE_UNATTESTED"
    files = tree.bundle()
    manifest, attester = None, None
    for name, public_key in trust.public_keys.items():
        if name in trust.revoked:
            continue
        try:
            manifest = verified_manifest_bytes(files, public_key=public_key)
            attester = public_key
            break
        except ValueError:
            continue
    if manifest is None:
        raise ApprovalRefused("RESERVE_UNATTESTED")
    if attester == trust.public_keys[operator]:
        raise ApprovalRefused("ATTESTER_IS_APPROVER")
    campaigns = []
    for name, raw in files.items():
        if name.startswith("artifacts/") and name.endswith(".json"):
            value = json.loads(raw)
            if type(value) is dict and value.get("schema") == MIO_CAMPAIGN_SCHEMA:
                campaigns.append(value)
    if len(campaigns) != 1:
        raise ApprovalRefused("RUNTIME_EVIDENCE_MISSING")
    campaign = campaigns[0]
    result = validate_record(campaign, bundle_files=files, public_key=attester)
    if result.status is not Status.ATTESTED or result.reserve_mib is None:
        if any("fixture/synthetic" in reason for reason in result.reasons):
            raise ApprovalRefused("RESERVE_FIXTURE")
        if not virtualization_not_observed(campaign.get("virtualization_observations")):
            raise ApprovalRefused("RESERVE_VIRTUALIZATION_OBSERVED")
        if any("runtime" in reason for reason in result.reasons):
            raise ApprovalRefused("RUNTIME_EVIDENCE_MISSING")
        raise ApprovalRefused("RESERVE_UNATTESTED")
    if (campaign["dut_fingerprint"] != identity["host_digest"]
            or campaign["hardware_class"] not in {"8GiB", "16GiB", "32GiB", "64GiB"}):
        raise ApprovalRefused("NODE_MISMATCH")
    first = parse_record(json.dumps(campaign["runs"][0]["measurement"]))
    if first.profile is not host.profile:
        raise ApprovalRefused("RESERVE_MISMATCH")
    reserve = CoreReserve(host.profile, result.reserve_mib, identity["host_digest"],
                          campaign["harness_version"], len(first.samples), first.duration_seconds)
    # Reuse the existing independently commissioned asset memory declarations.
    tree.phase = "RESOURCE_FIT"
    assets = [a for a in config["assets"] if a["kind"] == "model" and a["id"] == entry.model_id
              and a["digest"] == entry.digest]
    if len(assets) != 1:
        raise ApprovalRefused("RESOURCE_FIT")
    need = assets[0]["memory_need_mib"]
    floor = entry.declared_min_ram_mib
    from azazel_nexus.model_paths import bounded_read

    meminfo = bounded_read(Path("/proc/meminfo"), 1024 * 1024).decode()
    import re
    memory = re.search(r"^MemTotal:\s+(\d+) kB$", meminfo, re.MULTILINE)
    if memory is None:
        raise ApprovalRefused("RESOURCE_FIT")
    envelope = int(memory[1]) // 1024
    from azazel_nexus.resource_profile import select_profile

    observed_class = next((name for minimum, name in (
        (64512, "64GiB"), (31744, "32GiB"), (15360, "16GiB"), (7168, "8GiB"))
        if envelope >= minimum), None)
    if (select_profile(envelope) is not host.profile
            or observed_class != campaign["hardware_class"]):
        raise ApprovalRefused("RESOURCE_FIT")
    peak = campaign["embedding_runtime"]["peak_rss_mib"]
    if (type(need) is not int or not 0 < peak <= need <= 3840 or envelope < floor
            or not reserve.fits(memory_need_mib=need + 256, envelope_mib=envelope)):
        raise ApprovalRefused("RESOURCE_FIT")
    binary_fd, model_fd, held = None, None, None
    try:
        tree.phase = "RUNTIME_MISMATCH"
        binary_fd = tree.open(LLAMA_EXECUTABLE)
        tree.phase = "ARTIFACT_REFUSED"
        model_fd = tree.open("/var/lib/azazel/models/store/" + artifact_filename(entry))
        license = "acknowledged" if entry.license_acknowledgement_required else "not-required"
        held = HeldDescriptors(binary_fd, model_fd, architecture, entry, license, tree.owner)
        try:
            binary = held.recheck()
        except RuntimeRefused as exc:
            raise ApprovalRefused("RUNTIME_MISMATCH") from exc
        record = llama_server_record(binary, model_path=Path("/var/lib/azazel/models/store") / artifact_filename(entry),
                                     socket_path=Path("/var/lib/azazel/mio/embedding.sock"),
                                     ctx=admission.EMBEDDING_CTX, threads=admission.EMBEDDING_THREADS,
                                     max_tokens=admission.EMBEDDING_MAX_TOKENS, embedding=True)
        metrics = campaign["embedding_runtime"]
        argv_digest = admission.digest(admission.canonical(list(record.argv)))
        if (metrics["runtime_binary_digest"] != binary.digest or metrics["model_digest"] != entry.digest
                or metrics["argv_digest"] != argv_digest):
            raise ApprovalRefused("SETTINGS_MISMATCH")
        context = admission.AdmissionContext({
            "approval_key": {"fingerprint": admission.digest(trust.public_keys[operator]),
                             "security_epoch": host.security_epoch},
            "node": {"node_digest": node_digest, "commissioning_digest": commissioning,
                     "hardware_class": campaign["hardware_class"], "profile": host.profile.value,
                     "dut_fingerprint": identity["host_digest"]},
            "catalog": {"document_digest": admission.digest(catalog_raw), "schema": catalog.schema,
                        "version": catalog.version, "signer_key_id": catalog.signer,
                        "signer_key_fingerprint": admission.digest(keys[catalog.signer])},
            "model": {"model_id": entry.model_id, "role": entry.role, "format": entry.format,
                      "digest": entry.digest, "size_bytes": entry.size_bytes,
                      "runtime_abi": entry.runtime_abi, "license": license},
            "generation": {"number": number, "generation_id": generation.generation_id,
                           "previous_generation_id": generation.previous_generation_id},
            "runtime": {"runtime_id": binary.runtime_id, "version": binary.version,
                        "architecture": architecture, "binary_digest": binary.digest,
                        "executable": binary.executable},
            "settings": {"argv_digest": argv_digest},
            "compatibility": {"tuple_digest": admission.digest(admission.canonical(matched.as_record()))},
            "reserve": {"campaign_record_digest": admission.digest(canonical_event_bytes(campaign)),
                        "run_id": manifest["run_id"], "attestation_ref": manifest["attestation_ref"],
                        "manifest_digest": admission.digest(files["manifest.json"]),
                        "attestation_key_fingerprint": admission.digest(attester),
                        "reserve_mib": result.reserve_mib, "harness_version": campaign["harness_version"]},
            "runtime_evidence": {"peak_rss_mib": peak},
            "resources": {"memory_need_mib": need, "envelope_floor_mib": floor}})
        provider = LocalModelProvider(entry.model_id, entry.digest, entry.format, "gguf",
                                      binary.version, "catalog-bound", admission.EMBEDDING_CTX, need,
                                      role="embedding")
        return context, held, entry, provider, host, tested, ResourceEvidence(reserve, envelope, admission.digest(canonical_event_bytes(campaign))), record
    except BaseException:
        if held is not None:
            held.close()
        else:
            for fd in (binary_fd, model_fd):
                if fd is not None:
                    os.close(fd)
        raise


def _read_at(root_fd, owner, *, now, trust=None):
    """Private test seam; production callers must use read_admissions()."""
    tree = ProtectedTree(root_fd, owner)
    held = None
    stage = "EVIDENCE_UNPROTECTED"
    try:
        try:
            raw = tree.read(DIRECTORY + "/embedding.approval", 100000)
        except FileNotFoundError:
            return AdmissionReading(Absent())
        stage = "POLICY_REFUSED"
        policy = admission.AdmissionPolicy.from_bytes(tree.read(DIRECTORY + "/policy.json"))
        stage = "MALFORMED"
        wrapper = admission.decode(raw)
        if set(wrapper) != {"schema", "payload_b64", "signature_hex"} or wrapper["schema"] != admission.FILE_SCHEMA:
            raise ApprovalRefused("MALFORMED")
        payload = base64.b64decode(wrapper["payload_b64"], validate=True)
        signature = bytes.fromhex(wrapper["signature_hex"])
        if (base64.b64encode(payload).decode() != wrapper["payload_b64"]
                or signature.hex() != wrapper["signature_hex"] or len(signature) != 64):
            raise ApprovalRefused("MALFORMED")
        doc = admission.decode(payload)
        operator = doc["operator"]
        if operator not in policy.operators:
            raise ApprovalRefused("POLICY_REFUSED")
        stage = "SIGNATURE_REFUSED"
        trust = trust if trust is not None else operator_trust_bytes(tree.read("/etc/azazel/operator-trust/operators.json"))
        trust.verify(operator=operator, purpose=admission.ApprovalPurpose.LOCAL_MODEL_ADMISSION,
                     payload=payload, signature=signature)
        if doc.get("model", {}).get("role") != "embedding":
            raise ApprovalRefused("ROLE_MISMATCH")
        start, end, instant = (admission.utc(doc["issued_at"]), admission.utc(doc["expires_at"]),
                               admission.utc(now))
        if instant < start:
            raise ApprovalRefused("NOT_YET_VALID")
        if instant >= end:
            raise ApprovalRefused("EXPIRED")
        if not 0 < (end - start).total_seconds() <= policy.max_seconds:
            raise ApprovalRefused("VALIDITY_EXCEEDS_POLICY")
        stage = "NODE_MISMATCH"
        context, held, entry, provider, host, tested, resources, record = _collect(
            tree, trust=trust, policy=policy, operator=operator)
        evidence = admission.verify_local_model_admission(
            trust=trust, policy=policy, expected=context, role="embedding", operator=operator,
            payload=payload, signature=signature, now=now, descriptors=held)
        held.validity = (evidence.issued_at, evidence.expires_at)
        result = Admitted(evidence, entry, provider, host, tested, resources, record)
        # Match every opened inode to its current name, including ancestors.
        # Test roots have a different absolute namespace; tests inspect the fd seam directly.
        if owner == 0 and os.fstat(root_fd).st_ino == os.stat("/").st_ino:
            paths = tuple(sorted(tree.observed))
            if fingerprint(paths) != tuple(tree.observed[p] for p in paths):
                raise ApprovalRefused("EVIDENCE_CHANGED")
        paths = tuple(sorted(tree.watched))
        snapshot = fingerprint(paths)
        held.watch_paths, held.snapshot = paths, snapshot
        held = None
        return AdmissionReading(result, paths, snapshot)
    except ApprovalRefused as error:
        return AdmissionReading(Refused(str(error) if str(error).isupper() else stage),
                                tuple(sorted(tree.watched)))
    except Exception:  # noqa: BLE001 - an unexpected reader failure is a refusal
        return AdmissionReading(Refused(tree.phase or stage), tuple(sorted(tree.watched)))
    finally:
        if held is not None:
            held.close()


def read_admissions(*, now):
    # Must precede platform checks, fingerprints, opens, trust loading and audit I/O.
    if admission.LOCAL_MODEL_ADMISSION_ENABLED is not True:
        return AdmissionReading(Refused("ADMISSION_DISABLED"))
    fd = None
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        return _read_at(fd, 0, now=now)
    except Exception:  # noqa: BLE001 - an unexpected reader failure is a refusal
        return AdmissionReading(Refused("EVIDENCE_UNPROTECTED"))
    finally:
        if fd is not None:
            os.close(fd)


class AdmissionHolder:
    """Revalidate per request and every second; additions require a new start."""
    def __init__(self, *, clock=None):
        self.clock = clock or (lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
        self.reading = AdmissionReading(Refused("NOT_STARTED"))
        self._started = False
        self._revision = None

    def start(self, *, audit):
        self.reading = read_admissions(now=self.clock())
        if self.reading.embedding == Refused("ADMISSION_DISABLED"):
            audit(self.reading.as_event())
            return self.reading
        paths = tuple(sorted(set(_FIXED) | set(self.reading.watch_paths)))
        self.reading = AdmissionReading(self.reading.embedding, paths,
                                        self.reading.snapshot or fingerprint(paths))
        self._revision = self.reading.snapshot
        self._started = True
        audit(self.reading.as_event())
        return self.reading

    def refresh(self, *, withdraw, audit):
        now = self.clock()
        result = self.reading.embedding
        if type(result) is not Admitted:
            return
        expired = not admission.utc(result.evidence.issued_at) <= admission.utc(now) < admission.utc(result.evidence.expires_at)
        changed = fingerprint(self.reading.watch_paths) != self._revision
        if expired or changed or admission.LOCAL_MODEL_ADMISSION_ENABLED is not True:
            fresh = read_admissions(now=now)
            # Even valid replacements cannot replace a running model implicitly.
            withdraw()
            self.reading.close()
            self.reading = AdmissionReading(Refused("EXPIRED" if expired else "EVIDENCE_CHANGED"))
            audit(self.reading.as_event())
            fresh.close()

    def close(self):
        self.reading.close()


def request_context(*, operator):
    """Read-only rehearsal uses the same collectors, even while disabled."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        tree = ProtectedTree(fd, 0)
        policy = admission.AdmissionPolicy.from_bytes(tree.read(DIRECTORY + "/policy.json"))
        trust = operator_trust_bytes(tree.read("/etc/azazel/operator-trust/operators.json"))
        if operator not in policy.operators or operator in trust.revoked or operator not in trust.public_keys:
            raise ApprovalRefused("POLICY_REFUSED")
        collected = _collect(tree, trust=trust, policy=policy, operator=operator)
        return policy, collected
    finally:
        os.close(fd)
