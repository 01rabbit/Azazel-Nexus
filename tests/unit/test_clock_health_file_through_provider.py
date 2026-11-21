"""製品の provider が実際の health ファイルを読んで、送信の前で閉じることを固定する。

`config._clock_health(contract)` が返す本物の ClockHealth を egress client に渡す。
差し替えるのは時計（ClockHealth の既定の注入点 boottime/wall）、ファイルの持ち主と
信頼の根（試験用ディレクトリ）、送信の層（_post_path）だけ。実時刻と sleep は使わない。
実プロセス試験の D/E（Knowledge 側・Nexus 側の失効）と同じ結論を単体で確かめる。
"""
import json
import os

import pytest

pytest.importorskip("azazel_fabric.knowledge_context_clocklab")

from azazel_fabric.knowledge_context_clocklab import ClockContract
from azazel_nexus.sanitizer import PrivacyClass
from azazel_nexus_runtime import knowledge_context_config as config
from azazel_nexus_runtime import knowledge_egress, runtime_paths
from azazel_nexus_runtime.knowledge_clock_contract import ClockHealth
from azazel_nexus_runtime.knowledge_egress import KnowledgeClient
from test_knowledge_context_adapter import POLICY
from test_knowledge_context_transport import NOW, material, registry

CONTRACT = ClockContract(skew_budget_us=5000)
BOOT_ID = "n-boot"
# 一つの時計から作る: ファイルの観測・期限・wall 差と、reader が見る now はすべてここから出る。
OBSERVED, VALID_UNTIL, WALL_OFFSET = 1_000_000_000, 6_000_000_000, 100_000_000_000


@pytest.fixture
def health_env(tmp_path, monkeypatch):
    """ROOT を試験用ディレクトリにし、製品の provider が読む実パスへ health を置く。"""
    root = tmp_path
    root.chmod(0o700)
    directory = root / "run/azazel"
    directory.mkdir(parents=True)
    for part in (root / "run", directory):
        part.chmod(0o755)
    path = directory / "knowledge-clock-health.json"
    clock = {"boot": 2_000_000_000}
    monkeypatch.setattr(runtime_paths, "ROOT", root)
    # 製品の _clock_health は ClockHealth(contract, path) だけを呼ぶ。既定の注入点を差し替える。
    defaults = ClockHealth.__init__.__kwdefaults__
    monkeypatch.setitem(defaults, "boottime", lambda: clock["boot"])
    monkeypatch.setitem(defaults, "wall", lambda: clock["boot"] + WALL_OFFSET)
    monkeypatch.setitem(defaults, "boot_id", BOOT_ID)
    monkeypatch.setitem(defaults, "owner", os.getuid())
    monkeypatch.setitem(defaults, "trust_root", root)

    def write():
        doc = {"schema": "azazel-clocklab-health/1", "contract_id": CONTRACT.contract_id,
               "n_boot_id": BOOT_ID, "k_boot_id": "k-boot", "generation": 1,
               "observed_boottime_ns": OBSERVED, "valid_until_boottime_ns": VALID_UNTIL,
               "n_error_us": 100, "k_error_us": 100, "k_age_at_receipt_us": 0,
               "mapping_bound_us": 0, "step_counter": 0, "wall_minus_boottime_ns": WALL_OFFSET}
        path.write_text(json.dumps(doc))
        path.chmod(0o600)

    return path, clock, write


def _egress(monkeypatch):
    """製品の provider が作る ClockHealth を持つ client。送信の層だけ数える偽物。"""
    health = config._clock_health(CONTRACT)
    assert type(health) is ClockHealth
    peer = KnowledgeClient(
        registry=registry(443), peer_id="knowledge-node-1",
        ca_certificate=material("trusted-ca.crt"),
        identities={"knowledge-test": (material("client.crt"), material("client.key"))},
        knowledge_context_enabled=True, knowledge_context_max_ttl_seconds=300,
        utc_now=lambda: NOW, clock_contract=CONTRACT, clock_health=health)
    assert peer.clock_health is health
    sent = []

    def post(_peer, path, body, _deadline):
        sent.append(path)
        raise OSError("fake transport: nothing is listening")

    monkeypatch.setattr(peer, "_post_path", post)
    return peer, health, sent


def _ask(peer):
    return peer.request_context(
        frame={"indicator": "203.0.113.9"}, privacy_class=PrivacyClass.P0_PUBLIC,
        policy=POLICY, mission="t", alias_key=b"x" * 32, deadline_s=5)


def test_valid_file_is_accepted_and_the_request_reaches_the_send_stage(health_env, monkeypatch):
    path, clock, write = health_env
    write()
    peer, health, sent = _egress(monkeypatch)
    assert health.path == path
    with pytest.raises(Exception) as caught:
        _ask(peer)
    assert len(sent) == 1
    assert caught.value.stage == "transport"
    assert isinstance(caught.value.__cause__, OSError)
    assert health._latched is False


def test_missing_file_refuses_before_any_send(health_env, monkeypatch):
    path, clock, write = health_env
    assert not path.exists()
    peer, health, sent = _egress(monkeypatch)
    with pytest.raises(Exception) as caught:
        _ask(peer)
    assert sent == []
    assert caught.value.stage == "refused_before_send"
    assert type(caught.value.__cause__) is FileNotFoundError
    assert health._latched is True


def test_expired_file_refuses_before_any_send(health_env, monkeypatch):
    path, clock, write = health_env
    write()
    peer, health, sent = _egress(monkeypatch)
    clock["boot"] = VALID_UNTIL + 1  # 同じ時計を進めるだけ。ファイルは有効期限の外になる。
    with pytest.raises(Exception) as caught:
        _ask(peer)
    assert sent == []
    assert caught.value.stage == "refused_before_send"
    assert type(caught.value.__cause__) is ValueError
    assert str(caught.value.__cause__) == "clock health age"
    assert health._latched is True
