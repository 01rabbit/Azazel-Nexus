"""Nexus の KnowledgeClient と Knowledge の実 mTLS プロセスを、v1/v2 の組で結ぶ。

製品間の受け渡しが結果を左右するシナリオだけを扱う（各製品の単体試験が直接
証明するものは再利用する。対応表は u70 の SCENARIO-PLAN.md）。ここでの期待値
（どの段で、どの理由で拒否するか）は実行前に固定してある。

  A 正常 v2 と期限の機械照合   B 既定 v1
  C1/C2 v1/v2 混在の拒否       D producer の health 失効   E Nexus 側 health の失効

拒否は例外の `.stage`（refused_before_send / transport / verification）と
`__cause__` で確かめる。ケースごとに listener を起動し直し、前段の拒否を後段の
成功に数えない。Linux のコンテナ専用（run-container.sh）。
"""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from azazel_fabric.knowledge_context_clocklab import ClockContract
from azazel_nexus.knowledge_peer import KnowledgePeer, KnowledgeRegistry
from azazel_nexus.provider_registry import ProviderRecord
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy
from azazel_nexus.spki import spki_pin
from azazel_nexus.technique_knowledge import project_technique_response
from azazel_nexus_runtime.knowledge_clock_contract import ClockHealth
from azazel_nexus_runtime.knowledge_egress import HttpStatusRefused, KnowledgeClient
from azazel_nexus_runtime.knowledge_egress import KnowledgeContextRefused

from test_knowledge_context_process_interop import (  # noqa: F401  (fixture re-export)
    _PREREQUISITE_ERROR, _pki, _ready, service_accessible_root)

pytestmark = pytest.mark.skipif(
    _PREREQUISITE_ERROR is not None,
    reason=_PREREQUISITE_ERROR or "isolated real-process prerequisites unavailable")

HERE = Path(__file__).resolve().parent
CONTRACT = ClockContract(5000)
FRAME = {"techniques": ["T1059", "T1059.001"]}
POLICY = SanitizerPolicy.from_mapping({
    "version": "knowledge-clocklab-process-test-1", "remote_default": "deny",
    "classes": {"P0-public": {"remote": "allow", "fields": ["ip", "question"]}},
    "aliases": [], "redactions": ["secret"], "limits": {"max_bytes": 2048}})
HEALTH_DIR = Path("/run/u70-clock")


def _boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _write_root_file(path: Path, doc: dict) -> None:
    HEALTH_DIR.mkdir(mode=0o755, exist_ok=True)
    HEALTH_DIR.chmod(0o755)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    tmp.chmod(0o644)
    os.replace(tmp, path)


def write_knowledge_health(path: Path, *, age_s: float = 0.0) -> None:
    """Knowledge-side local health, sampled `age_s` seconds ago on this boot."""
    boot, wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    age = int(age_s * 1e9)
    _write_root_file(path, {
        "schema": "azazel-clocklab-health/1", "boot_id": _boot_id(),
        "sample_boottime_ns": boot - age, "sample_wall_ns": wall - age,
        "error_bound_us": 500, "step_counter": 0, "contract_id": CONTRACT.contract_id})


def write_nexus_health(path: Path, *, age_s: float = 0.0) -> None:
    """Nexus-side snapshot as the external observer would write it."""
    boot, wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    observed = boot - int(age_s * 1e9)
    _write_root_file(path, {
        "schema": "azazel-clocklab-health/1", "contract_id": CONTRACT.contract_id,
        "n_boot_id": _boot_id(), "k_boot_id": _boot_id(), "generation": 1,
        "observed_boottime_ns": observed, "valid_until_boottime_ns": observed + 4_900_000_000,
        "n_error_us": 100, "k_error_us": 100, "k_age_at_receipt_us": 0,
        "mapping_bound_us": 0, "step_counter": 0, "wall_minus_boottime_ns": wall - boot})


class Listener:
    def __init__(self, root: Path, mode: str):
        knowledge = Path(os.environ["KNOWLEDGE_TEST_SRC"]).resolve()
        self.pki = _pki(root / f"pki-{mode}")
        self.health = HEALTH_DIR / f"knowledge-{mode}-{os.getpid()}.json"
        if mode == "v2":
            write_knowledge_health(self.health)
        pythonpath = os.pathsep.join([str(knowledge / "src"), str(knowledge / "tests/unit"),
                                      os.environ.get("PYTHONPATH", "")])
        self.process = subprocess.Popen(
            [sys.executable, str(HERE / "_knowledge_context_clocklab_server.py"),
             str(root / f"knowledge-root-{mode}"), str(self.pki), mode, str(self.health)],
            cwd=knowledge / "tests/unit", env={**os.environ, "PYTHONPATH": pythonpath},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.ready = _ready(self.process)
        assert self.ready["pid"] == self.process.pid != os.getpid()

    def client(self, *, v2: bool, nexus_health: Path | None = None) -> KnowledgeClient:
        now = datetime.now(UTC)
        der = ssl.PEM_cert_to_DER_cert((self.pki / "server.pem").read_text())
        endpoint = ProviderRecord(
            provider_id="azazel-knowledge", host="knowledge.test", port=self.ready["port"],
            path_template="/knowledge/{model}", certificate_pin=spki_pin(der),
            client_identity="nexus-process-test", model_id="knowledge-v1",
            max_request_bytes=4096, max_response_bytes=8192, deadline_seconds=8,
            allowed_privacy_classes=(PrivacyClass.P0_PUBLIC,))
        peer = KnowledgePeer(endpoint, ("127.0.0.1",), bytes.fromhex(self.ready["public_key"]), 1)
        registry = KnowledgeRegistry(
            "sha256:" + "a" * 64, {endpoint.provider_id: peer},
            (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"), 1)
        clock = {}
        if v2:
            clock = {"clock_contract": CONTRACT,
                     "clock_health": ClockHealth(CONTRACT, nexus_health)}
        client = KnowledgeClient(
            registry=registry, peer_id=endpoint.provider_id, ca_certificate=str(self.pki / "ca.pem"),
            identities={"nexus-process-test": (str(self.pki / "nexus.pem"), str(self.pki / "nexus.key"))},
            knowledge_context_enabled=True, knowledge_context_max_ttl_seconds=30,
            utc_now=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"), **clock)
        client.posts = 0
        original = client._post_path

        def counted(*args, **kwargs):
            client.posts += 1
            return original(*args, **kwargs)

        client._post_path = counted
        return client

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.health.unlink(missing_ok=True)


def ask(client: KnowledgeClient):
    return client.request_context(frame=FRAME, privacy_class=PrivacyClass.P0_PUBLIC, policy=POLICY,
                                  mission="clocklab-process-test", alias_key=b"process-test-only",
                                  deadline_s=8)


def refused(client: KnowledgeClient) -> KnowledgeContextRefused:
    with pytest.raises(KnowledgeContextRefused) as caught:
        ask(client)
    return caught.value


@pytest.fixture
def listener_factory(service_accessible_root: Path):
    started = []

    def make(mode: str) -> Listener:
        started.append(Listener(service_accessible_root, mode))
        return started[-1]

    yield make
    for item in started:
        item.stop()


def test_a_v2_pair_is_accepted_and_expiry_agrees_on_every_surface(listener_factory, tmp_path, monkeypatch):
    sys.path.insert(0, str(HERE.parent / "unit"))
    from test_clocklab_expiry_surfaces import expiry_surfaces_agree

    listener = listener_factory("v2")
    nexus_health = HEALTH_DIR / f"nexus-{os.getpid()}-a.json"
    write_nexus_health(nexus_health)
    verified = ask(listener.client(v2=True, nexus_health=nexus_health))
    response = verified.response
    assert response.schema_version == "knowledge-context-response/v2"
    assert response.contract_id == CONTRACT.contract_id
    assert verified.contract_id == CONTRACT.contract_id
    assert verified.signed_expires_at == response.expires_at.isoformat().replace("+00:00", "Z") \
        or verified.signed_expires_at.startswith(response.expires_at.strftime("%Y-%m-%dT%H:%M:%S"))
    # The response document as the listener signed it, then the projection a
    # service stores, then every output surface.
    document = response.model_dump(mode="json")
    # The product's own final adoption check produces the validity.
    validity = verified.adoption_validity(
        utc_now=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        monotonic=time.monotonic)
    assert validity["contract_id"] == CONTRACT.contract_id
    record = project_technique_response({"response": document, "validity": validity}, FRAME["techniques"])
    assert record["expires_at"] == document["expires_at"]
    expiry_surfaces_agree(record, tmp_path, monkeypatch, "process-expiry")
    nexus_health.unlink(missing_ok=True)


def test_b_default_v1_pair_stays_v1(listener_factory):
    listener = listener_factory("v1")
    client = listener.client(v2=False)
    assert client.clock_contract is None and client.clock_health is None
    response = ask(client)
    assert response.schema_version == "knowledge-context-response/v1"
    assert getattr(response, "contract_id", None) is None
    assert client.posts == 1


def test_c1_v2_client_against_v1_listener_is_refused_at_verification(listener_factory):
    nexus_health = HEALTH_DIR / f"nexus-{os.getpid()}-c1.json"
    write_nexus_health(nexus_health)
    listener = listener_factory("v1")
    error = refused(listener.client(v2=True, nexus_health=nexus_health))
    assert error.stage == "verification"
    assert isinstance(error.__cause__.__cause__ or error.__cause__, HttpStatusRefused)
    assert getattr(error.__cause__, "status", None) == 422
    # Control: the matching (v1) client is served by the same listener.
    assert ask(listener.client(v2=False)).schema_version == "knowledge-context-response/v1"
    nexus_health.unlink(missing_ok=True)


def test_c2_v1_client_against_v2_listener_is_refused_at_verification(listener_factory):
    nexus_health = HEALTH_DIR / f"nexus-{os.getpid()}-c2.json"
    write_nexus_health(nexus_health)
    listener = listener_factory("v2")
    error = refused(listener.client(v2=False))
    assert error.stage == "verification"
    assert getattr(error.__cause__, "status", None) == 422
    # Control: the matching (v2) client is served by the same listener.
    assert ask(listener.client(v2=True, nexus_health=nexus_health)).response.schema_version.endswith("/v2")
    nexus_health.unlink(missing_ok=True)


def test_d_producer_health_lapse_is_503_at_transport_and_latches(listener_factory):
    nexus_health = HEALTH_DIR / f"nexus-{os.getpid()}-d.json"
    write_nexus_health(nexus_health)
    listener = listener_factory("v2")
    ask(listener.client(v2=True, nexus_health=nexus_health))          # control: served while fresh
    write_knowledge_health(listener.health, age_s=6.0)               # older than the 5000 ms bound
    write_nexus_health(nexus_health)
    error = refused(listener.client(v2=True, nexus_health=nexus_health))
    assert error.stage == "transport"
    assert getattr(error.__cause__, "status", None) == 503
    write_knowledge_health(listener.health)                          # fresh again: the latch holds
    write_nexus_health(nexus_health)
    error = refused(listener.client(v2=True, nexus_health=nexus_health))
    assert error.stage == "transport" and getattr(error.__cause__, "status", None) == 503
    nexus_health.unlink(missing_ok=True)


def test_e_nexus_health_lapse_is_refused_before_send(listener_factory):
    nexus_health = HEALTH_DIR / f"nexus-{os.getpid()}-e.json"
    listener = listener_factory("v2")
    write_nexus_health(nexus_health, age_s=6.0)                      # observation older than 5000 ms
    client = listener.client(v2=True, nexus_health=nexus_health)
    error = refused(client)
    assert error.stage == "refused_before_send"
    assert client.posts == 0                                         # Knowledge was never reached
    nexus_health.unlink(missing_ok=True)
