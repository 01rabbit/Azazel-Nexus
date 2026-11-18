"""Candidate clock contract: signature binding, expiry and final adoption."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from azazel_fabric.knowledge_context_clocklab import ClockContract
from azazel_nexus.knowledge_context_adapter import (
    ENVELOPE_DOMAIN_V2, ENVELOPE_SCHEMA_V2, KnowledgeContextRefused,
    canonical_signed_payload, make_request, read_signed_response)
from azazel_nexus.knowledge_clock_validity import VerifiedContext, read_validity
from azazel_nexus.sanitizer import PrivacyClass
from azazel_nexus.technique_knowledge import display_projection, project_technique_response, read_projection
from _technique_fixture import make_response
from test_knowledge_context_adapter import (
    NOW, POLICY, SIGNING_KEY, KEY_ID, commissioned_registry, response_payload)
from test_knowledge_contextd import OPEN_GATE, _policy, _request
from azazel_nexus_runtime.knowledge_contextd import KnowledgeContextBroker

CONTRACT = ClockContract(skew_budget_us=5000)


def request():
    return make_request({"indicator": "203.0.113.9"}, privacy_class=PrivacyClass.P0_PUBLIC,
                        policy=POLICY, mission="test", alias_key=b"x" * 32,
                        requested_at=NOW, clock_contract=CONTRACT)


def signed(req, *, generated=NOW, expires="2026-11-04T12:00:01Z", contract_id=None):
    doc = response_payload(req)
    doc.update(schema_version="knowledge-context-response/v2", generated_at=generated,
               expires_at=expires, contract_id=contract_id or CONTRACT.contract_id)
    env = {"schema": ENVELOPE_SCHEMA_V2, "key_id": KEY_ID, "issued_at": generated,
           "expires_at": expires, "payload": doc}
    body = canonical_signed_payload(env)
    return SIGNING_KEY.sign(ENVELOPE_DOMAIN_V2 + body).signature + body


def read(req, raw):
    return read_signed_response(raw, request=req, registry=commissioned_registry(),
                                peer_id="knowledge-node-1", now=NOW, max_ttl_seconds=30,
                                clock_contract=CONTRACT)


@pytest.mark.parametrize("delta, accepted", [(-5000, True), (-5001, False), (5000, True), (5001, False)])
def test_signed_v2_clock_bounds(delta, accepted):
    req = request()
    generated = (datetime.fromisoformat(NOW.replace("Z", "+00:00")) + timedelta(microseconds=delta)).isoformat()
    if accepted:
        response, expiry = read(req, signed(req, generated=generated))
        assert response.contract_id == CONTRACT.contract_id and expiry.endswith("01Z")
    else:
        with pytest.raises((ValueError, KnowledgeContextRefused)):
            read(req, signed(req, generated=generated))


def test_expiry_equal_budget_and_policy_mismatch_and_replay_refused():
    req = request()
    with pytest.raises(KnowledgeContextRefused):
        read(req, signed(req, expires="2026-11-04T12:00:00.005Z"))
    with pytest.raises((ValueError, KnowledgeContextRefused)):
        read(req, signed(req, contract_id="sha256:" + "f" * 64))
    with pytest.raises((ValueError, KnowledgeContextRefused)):
        read(request(), signed(req))


class Guard:
    def __init__(self):
        self.valid = True
    def check(self, **kwargs):
        if not self.valid:
            raise ValueError("health expired")
        return ("n", "k", 1, 0)
    def run_validated(self, use, **kwargs):
        self.check(**kwargs)
        return use(lambda: self.check(**kwargs))


def wrapper(*, expires=None, deadline=100, guard=None):
    expiry = expires or (datetime.now(UTC) + timedelta(seconds=30)).isoformat()
    return VerifiedContext({"authority": "advisory_only"}, CONTRACT.contract_id, expiry, expiry,
                           5000, ("n", "k", 1, 0), deadline, guard or Guard())


def test_final_adoption_expiry_deadline_health_and_generation():
    guard = Guard()
    verified = wrapper(expires="2026-11-04T12:00:00.010Z", guard=guard)
    v = verified.adoption_validity(utc_now=lambda: NOW, monotonic=lambda: 99)
    assert v["effective_expires_at"] == "2026-11-04T12:00:00.005000Z"
    for now, mono in [("2026-11-04T12:00:00.005Z", 99), (NOW, 100)]:
        with pytest.raises(ValueError):
            verified.adoption_validity(utc_now=lambda: now, monotonic=lambda: mono)
    guard.valid = False
    with pytest.raises(ValueError):
        verified.adoption_validity(utc_now=lambda: NOW, monotonic=lambda: 1)


def test_broker_refuses_expiry_crossed_after_client_validation():
    # Peer answer was verified, but its effective deadline is already crossed
    # when broker reaches final adoption. No verified audit may be recorded.
    verified = wrapper(expires=(datetime.now(UTC) - timedelta(seconds=1)).isoformat())
    events = []
    client = SimpleNamespace(request_context=lambda **kw: verified)
    # VerifiedContext delegates model_dump to Fabric-like object.
    object.__setattr__(verified, "response", SimpleNamespace(model_dump=lambda **kw: {"authority": "advisory_only"}))
    broker = KnowledgeContextBroker(**OPEN_GATE, client=client, policy=_policy(), mission="lab",
        alias_key=b"x" * 32, enabled=True, audit=events.append, monotonic=lambda: 1,
        grant_marker=lambda: ("grant",))
    result = broker.handle(_request())
    assert "refusal" in result
    assert not any(e.get("outcome") == "verified_advisory" for e in events)


def test_projection_v2_preserves_raw_expiry_and_uses_server_health():
    response = make_response(["T1110"])
    raw_expiry = response["expires_at"]
    expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
    adopted = expiry - timedelta(seconds=1)
    validity = {"schema": "azazel-knowledge-clock-validity/1", "contract_id": CONTRACT.contract_id,
                "signed_expires_at": raw_expiry, "semantic_expires_at": raw_expiry,
                "effective_expires_at": (expiry - timedelta(milliseconds=5)).isoformat().replace("+00:00", "Z"),
                "adopted_at": adopted.isoformat().replace("+00:00", "Z"), "skew_budget_us": 5000, "health_generation": ["n", "k", 1, 0]}
    response.update(schema_version="knowledge-context-response/v2", contract_id=CONTRACT.contract_id)
    record = project_technique_response({"response": response, "validity": validity}, ["T1110"])
    assert record["version"] == "technique-knowledge/2" and record["expires_at"] == raw_expiry
    assert read_projection(record) == record
    assert display_projection(record, adopted.timestamp(), health_check=lambda **kw: True)["server_validity"]["usable"]
    assert not display_projection(record, expiry.timestamp(), health_check=lambda **kw: True)["server_validity"]["usable"]
    def no_health(**kwargs):
        raise ValueError
    assert not display_projection(record, adopted.timestamp(), health_check=no_health)["server_validity"]["usable"]
    validity["effective_expires_at"] = raw_expiry
    with pytest.raises(ValueError):
        read_validity(validity)


def health_snapshot(tmp_path, *, mutate=None):
    import json, os
    from azazel_nexus_runtime.knowledge_clock_contract import ClockHealth
    root = tmp_path / "protected"
    root.mkdir()
    root.chmod(0o700)
    path = root / "health.json"
    doc = {"schema": "azazel-clocklab-health/1", "contract_id": CONTRACT.contract_id,
           "n_boot_id": "n-boot", "k_boot_id": "k-boot", "generation": 1,
           "observed_boottime_ns": 1_000_000_000, "valid_until_boottime_ns": 6_000_000_000,
           "n_error_us": 1000, "k_error_us": 1000, "k_age_at_receipt_us": 0,
           "mapping_bound_us": 0, "step_counter": 0, "wall_minus_boottime_ns": 100_000_000_000}
    if mutate:
        mutate(doc)
    path.write_text(json.dumps(doc))
    path.chmod(0o600)
    clock = {"boot": 2_000_000_000, "wall": 102_000_000_000}
    health = ClockHealth(CONTRACT, path, boot_id="n-boot", boottime=lambda: clock["boot"],
                         wall=lambda: clock["wall"], owner=os.getuid(), trust_root=root)
    return health, clock, path, doc


def test_health_checks_mapping_age_budget_step_and_latches(tmp_path):
    import json
    health, clock, path, doc = health_snapshot(tmp_path)
    assert health.check() == ("n-boot", "k-boot", 1, 0)
    clock.update(boot=6_000_000_000, wall=106_000_000_000)
    with pytest.raises(ValueError, match="age"):
        health.check()
    clock.update(boot=2_000_000_000, wall=102_000_000_000)
    with pytest.raises(ValueError, match="latched"):
        health.check()


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(n_boot_id="old-boot"),
    lambda d: d.update(contract_id="sha256:" + "0" * 64),
    lambda d: d.update(k_age_at_receipt_us=5_000_000),
    lambda d: d.update(mapping_bound_us=1001),
    lambda d: d.update(n_error_us=1001),
    lambda d: d.update(observed_boottime_ns=3_000_000_000),
    lambda d: d.update(generation=True),
    lambda d: d.update(wall_minus_boottime_ns=0),
])
def test_health_refuses_unproven_bounds(tmp_path, mutate):
    health, _, _, _ = health_snapshot(tmp_path, mutate=mutate)
    with pytest.raises(ValueError):
        health.check()


def test_health_file_owner_mode_symlink_and_generation(tmp_path):
    import json
    health, _, path, doc = health_snapshot(tmp_path)
    generation = health.check()
    doc["step_counter"] = 1
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        health.check(expected_generation=generation)


@pytest.mark.parametrize("unsafe", ["writable", "symlink", "duplicate"])
def test_health_reader_refuses_unsafe_file(tmp_path, unsafe):
    health, _, path, doc = health_snapshot(tmp_path)
    if unsafe == "writable":
        path.chmod(0o666)
    elif unsafe == "symlink":
        target = path.with_name("actual.json")
        path.rename(target)
        path.symlink_to(target)
    else:
        path.write_text('{"schema":"azazel-clocklab-health/1","schema":"other"}')
    with pytest.raises((ValueError, OSError)):
        health.check()


def test_v2_grant_marker_binds_policy_evidence_and_boot(tmp_path, monkeypatch):
    import os
    from azazel_nexus_runtime import activation_markers as markers
    monkeypatch.setattr(markers, "_OWNER", os.getuid())
    parent = tmp_path / "run/azazel-activation"
    parent.mkdir(parents=True)
    parent.chmod(0o755)
    binding = {"boot_id": "11111111-1111-1111-1111-111111111111",
               "contract_id": CONTRACT.contract_id, "commissioning_digest": "sha256:" + "a" * 64}
    unit = markers.CONTEXTD_MARKER_UNIT
    markers.write_grant_markers([unit], tmp_path)
    assert markers.inspect_grant_marker(unit, tmp_path) is not None
    assert markers.inspect_clock_grant_binding(binding, tmp_path) is None
    markers.reset_grant_markers(tmp_path)
    markers.write_grant_markers([unit], tmp_path, context_clock_binding=binding)
    assert markers.inspect_clock_grant_binding(binding, tmp_path) is not None
    for key, wrong in [("contract_id", "sha256:" + "f" * 64),
                       ("commissioning_digest", "sha256:" + "b" * 64),
                       ("boot_id", "22222222-2222-2222-2222-222222222222")]:
        assert markers.inspect_clock_grant_binding(dict(binding, **{key: wrong}), tmp_path) is None
    markers.reset_grant_markers(tmp_path)
    assert markers.inspect_clock_grant_binding(binding, tmp_path) is None


def test_clock_policy_binding_must_match_verified_evidence(monkeypatch):
    import hashlib, json
    from azazel_nexus_runtime import knowledge_context_config as config
    body = json.dumps({"schema": "azazel-nexus/commissioning-proposal/v4",
                       "clock_policy": CONTRACT.as_dict()}).encode()
    evidence = SimpleNamespace(payload=body)
    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    bundle = SimpleNamespace(status="commissioned", clock_policy=CONTRACT.as_dict(), commissioning_digest=digest)
    monkeypatch.setattr(config, "load_egress_peer", lambda: bundle)
    config.assert_clock_commissioning_binding(evidence)
    bundle.commissioning_digest = "sha256:" + "f" * 64
    with pytest.raises(ValueError):
        config.assert_clock_commissioning_binding(evidence)
    bundle.commissioning_digest = digest
    bundle.clock_policy = None
    with pytest.raises(ValueError):
        config.assert_clock_commissioning_binding(evidence)


def test_socket_reader_refuses_v2_without_local_validity():
    from azazel_nexus_runtime.knowledge_context_socket import read_context_result, KnowledgeContextUnavailable
    req = request()
    semantic, _ = read(req, signed(req))
    doc = semantic.model_dump(mode="json")
    with pytest.raises(KnowledgeContextUnavailable):
        read_context_result({"response": doc})
    validity = {"schema": "azazel-knowledge-clock-validity/1", "contract_id": CONTRACT.contract_id,
                "signed_expires_at": "2026-11-04T12:00:01Z", "semantic_expires_at": "2026-11-04T12:00:01Z",
                "effective_expires_at": "2026-11-04T12:00:00.995Z", "adopted_at": NOW, "skew_budget_us": 5000, "health_generation": ["n", "k", 1, 0]}
    assert read_context_result({"response": doc, "validity": validity})["response"] == doc
    with pytest.raises(KnowledgeContextUnavailable):
        read_context_result({"response": doc, "validity": dict(validity, contract_id="sha256:" + "f" * 64)})


from test_commissioning_approval import context as commissioning_context


def test_signed_full_proposal_v4_binds_policy_and_restores(commissioning_context):
    import hashlib, json
    from nacl.signing import SigningKey
    from azazel_nexus.commissioning_approval import commissioning_proposal_payload, verify_commissioning_proposal
    from azazel_nexus.fabric_boundary import restore_commissioning_inputs
    from azazel_nexus.operator_trust import ApprovalPurpose, ApprovalRefused, OperatorTrust, approval_message
    args = dict(commissioning_context, mio_profile="FULL", clock_policy=CONTRACT.as_dict())
    payload = commissioning_proposal_payload(**args)
    key = SigningKey.generate()
    signed = key.sign(approval_message(ApprovalPurpose.COMMISSIONING_PROPOSAL, payload)).signature
    trust = OperatorTrust({args["operator"]: bytes(key.verify_key)})
    assert json.loads(payload)["schema"] == "azazel-nexus/commissioning-proposal/v4"
    restored = restore_commissioning_inputs(json.loads(payload))
    assert commissioning_proposal_payload(**restored) == payload
    verify_commissioning_proposal(trust=trust, payload=payload, signature=signed, **args)
    v2_payload = commissioning_proposal_payload(**dict(commissioning_context, mio_profile="FULL"))
    assert hashlib.sha256(payload).digest() != hashlib.sha256(v2_payload).digest()
    with pytest.raises(ApprovalRefused):
        verify_commissioning_proposal(trust=trust, payload=v2_payload, signature=signed,
                                     **dict(commissioning_context, mio_profile="FULL"))


@pytest.mark.parametrize("delay_at", ["health", "marker"])
def test_final_supplier_sampling_rejects_health_or_marker_time_crossing(delay_at, monkeypatch):
    from azazel_nexus_runtime import knowledge_contextd
    base = datetime(2026, 11, 19, tzinfo=UTC)
    clock = {"us": 0, "marker_calls": 0}
    events = []
    class DelayedGuard(Guard):
        def check(self, **kwargs):
            if delay_at == "health":
                clock["us"] += 20_000
            return ("n", "k", 1, 0)
    class FakeDatetime:
        @classmethod
        def now(cls, *_):
            return base + timedelta(microseconds=clock["us"])
    def marker():
        clock["marker_calls"] += 1
        if delay_at == "marker" and clock["marker_calls"] > 1:
            clock["us"] += 30_000
        return ("grant",)
    monkeypatch.setattr(knowledge_contextd, "datetime", FakeDatetime)
    expiry = (base + timedelta(microseconds=30_000)).isoformat()
    response = SimpleNamespace(model_dump=lambda **kw: {"authority": "advisory_only"})
    verified = VerifiedContext(response, CONTRACT.contract_id, expiry, expiry, 5000,
                               ("n", "k", 1, 0), 100, DelayedGuard())
    broker = KnowledgeContextBroker(**OPEN_GATE, client=SimpleNamespace(request_context=lambda **kw: verified),
        policy=_policy(), mission="lab", alias_key=b"x" * 32, enabled=True,
        audit=events.append, monotonic=lambda: 1 + clock["us"] / 1e6, grant_marker=marker)
    result = broker.handle(_request())
    assert "refusal" in result and clock["us"] >= 30_000
    assert not any(e.get("outcome") == "verified_advisory" for e in events)


def test_health_latch_is_serialized_through_adoption_use():
    import threading
    from azazel_nexus_runtime.knowledge_clock_contract import ClockHealth
    health = ClockHealth(CONTRACT, "/not-read", boot_id="n")
    entered, resume, bad_entered, bad_started = (threading.Event() for _ in range(4))
    order = []
    def check(**kw):
        if threading.current_thread().name == "good":
            return ("n", "k", 1, 0)
        bad_entered.set()
        raise ValueError("invalid")
    health._check = check
    health._snapshot = {}
    health._validate_snapshot = lambda *a, **kw: ("n", "k", 1, 0)
    def use(revalidate):
        entered.set()
        assert resume.wait(2)
        assert health._latched is False
        order.append("adopted")
    def good():
        health.run_validated(use, expected_generation=("n", "k", 1, 0))
    def bad():
        bad_started.set()
        try:
            health.check()
        except ValueError:
            order.append("latched")
    tg = threading.Thread(target=good, name="good")
    tb = threading.Thread(target=bad, name="bad")
    tg.start()
    assert entered.wait(2)
    tb.start()
    assert bad_started.wait(2)
    assert not bad_entered.wait(.05)
    resume.set()
    tg.join(2)
    tb.join(2)
    assert not tg.is_alive() and not tb.is_alive()
    assert order == ["adopted", "latched"]
    with pytest.raises(ValueError, match="latched"):
        health.run_validated(lambda revalidate: pytest.fail("must not adopt after latch"), expected_generation=("n", "k", 1, 0))


def test_final_health_snapshot_is_purely_reproved_after_marker_delay(tmp_path):
    health, clock, _, _ = health_snapshot(tmp_path)
    clock.update(boot=5_990_000_000, wall=105_990_000_000)
    reads = []
    original = health._check
    def counted(**kwargs):
        reads.append(True)
        return original(**kwargs)
    health._check = counted
    expiry = "2026-11-04T12:00:30Z"
    verified = VerifiedContext({}, CONTRACT.contract_id, expiry, expiry, 5000,
                               ("n-boot", "k-boot", 1, 0), 100, health)
    def marker():
        clock["boot"] += 30_000_000
        clock["wall"] += 30_000_000
    with pytest.raises(ValueError, match="age"):
        verified.adoption_validity(utc_now=lambda: NOW, monotonic=lambda: 1, grant_check=marker)
    assert len(reads) == 1  # Final proof must not open another I/O time gap.
    assert health._latched is True
