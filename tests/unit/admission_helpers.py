"""Ephemeral approval bytes for unit tests; never hardware evidence."""
from uuid import uuid4

from nacl.signing import SigningKey

from azazel_nexus import model_admission as admission
from azazel_nexus.operator_trust import ApprovalPurpose, OperatorTrust, approval_message

NOW = "2026-10-18T00:00:00Z"
END = "2026-10-19T00:00:00Z"
D = "sha256:" + "1" * 64
H = "hmac-sha256:" + "1" * 64


def inputs(*, component=D, model_id="local-model", need=3000, version="1.4.0",
           format="gguf", tuple_digest=D, reserve=2000, descriptors=None, argv_digest=D):
    signer, attester = SigningKey.generate(), SigningKey.generate()
    trust = OperatorTrust({"approver": bytes(signer.verify_key), "attester": bytes(attester.verify_key)})
    policy = admission.AdmissionPolicy(frozenset({"approver"}), 86400, ("embedding",))
    context = admission.AdmissionContext({
        "approval_key": {"fingerprint": admission.digest(bytes(signer.verify_key)), "security_epoch": 4},
        "node": {"node_digest": D, "commissioning_digest": D, "hardware_class": "16GiB",
                 "profile": "lite", "dut_fingerprint": H},
        "catalog": {"document_digest": D, "schema": "azazel-nexus/model-catalog/3", "version": 1,
                    "signer_key_id": "catalog", "signer_key_fingerprint": D},
        "model": {"model_id": model_id, "role": "embedding", "format": format,
                  "digest": component, "size_bytes": 23, "runtime_abi": "llama.cpp/1", "license": "not-required"},
        "generation": {"number": 1, "generation_id": D, "previous_generation_id": ""},
        "runtime": {"runtime_id": "llama-cpp-b11716", "version": version, "architecture": "x86_64",
                    "binary_digest": D, "executable": "/usr/libexec/azazel/llama-server"},
        "settings": {"argv_digest": argv_digest}, "compatibility": {"tuple_digest": tuple_digest},
        "reserve": {"campaign_record_digest": D, "run_id": "unit-test", "attestation_ref": "hil-evidence:unit-test",
                    "manifest_digest": D, "attestation_key_fingerprint": admission.digest(bytes(attester.verify_key)),
                    "reserve_mib": reserve, "harness_version": "unit-test"},
        "runtime_evidence": {"peak_rss_mib": min(need, 1000)},
        "resources": {"memory_need_mib": need, "envelope_floor_mib": 1}})
    payload = admission.admission_payload(context=context, operator="approver", approval_id=str(uuid4()),
                                           issued_at=NOW, expires_at=END)
    signature = signer.sign(approval_message(ApprovalPurpose.LOCAL_MODEL_ADMISSION, payload)).signature
    kwargs = {"trust": trust, "policy": policy, "expected": context, "role": "embedding",
              "operator": "approver", "payload": payload, "signature": signature,
              "now": NOW, "descriptors": descriptors}
    return kwargs, signer, attester


def evidence(**kwargs):
    values, _, _ = inputs(**kwargs)
    return admission.verify_local_model_admission(**values)


def _read_at(root_fd, owner, *, now, trust=None):
    from azazel_nexus_runtime import model_admission_evidence as loader

    class TestTree(loader.ProtectedTree):
        def read(self, path, limit=65536):
            if path == "/etc/azazel/operator-trust/operators.json" and trust is not None:
                return admission.canonical({"schema": "azazel-nexus/operator-trust/v1",
                                            "keys": {name: key.hex() for name, key in trust.public_keys.items()},
                                            "revoked": sorted(trust.revoked)})
            return super().read(path, limit)

    return loader._read_tree(TestTree(root_fd, owner), now=now)


def install_fake_serving(monkeypatch):
    """Explicit test-only process adapter for inert fixture executables on macOS."""
    import subprocess

    from azazel_nexus_runtime import mio_serve, mio_supervisor

    monkeypatch.setattr(admission, "LOCAL_MODEL_ADMISSION_ENABLED", True)
    original_init = mio_serve.LocalServer.__init__

    class FakeDescriptors:
        def recheck(self):
            pass

    class FakeProcess(mio_supervisor.ServingProcess):
        def start(self):
            binary = (self.root / self.record.executable.lstrip("/")).absolute()
            self.process = subprocess.Popen(
                [str(binary), *self.record.argv[1:]], cwd=str(self.root),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": "/nonexistent", "LC_ALL": "C"}, start_new_session=True,
                close_fds=True,
            )

    def initialize(self, *args, **kwargs):
        kwargs.setdefault("descriptors", FakeDescriptors())
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(mio_serve, "ServingProcess", FakeProcess)
    monkeypatch.setattr(mio_serve.LocalServer, "__init__", initialize)
