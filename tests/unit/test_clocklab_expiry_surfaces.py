"""期限の機械照合: 同じ期限が保存 JSON・Markdown・manifest・UI 向けデータで一致する。

実プロセス試験（real_process/test_knowledge_context_clocklab_interop.py）も、
実際に受け取った応答の投影をこの関数へ渡す。ネットワークなし。
"""
import hashlib
import json
from datetime import datetime, timedelta

from azazel_nexus import handoff
from azazel_nexus.technique_knowledge import display_projection


def expiry_surfaces_agree(record, tmp_path, monkeypatch, name):
    """record の期限を、各出力面から取り出して突き合わせる。一致しなければ assert。"""
    from test_handoff_full_context_ui import _fn

    raw = record["expires_at"]
    validity = record["validity"]
    assert validity["signed_expires_at"] == raw
    expiry = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    effective = validity["effective_expires_at"]
    assert datetime.fromisoformat(effective.replace("Z", "+00:00")) == expiry - timedelta(milliseconds=5)

    ui = display_projection(record, (expiry - timedelta(seconds=1)).timestamp(), health_check=lambda **kw: True)
    assert ui["expires_at"] == raw and ui["validity"]["effective_expires_at"] == effective
    assert ui["server_validity"]["usable"] is True

    fn, package = _fn(tmp_path, monkeypatch, name, None)
    fn["technique_knowledge"] = ui
    files = handoff.encode_files(package)
    stored = json.loads(files[handoff.JSON_NAME])
    stored_tk = stored["knowledge"]["full_node_context"]["technique_knowledge"]
    assert stored_tk["expires_at"] == raw
    assert stored_tk["validity"]["effective_expires_at"] == effective
    markdown = files[handoff.MARKDOWN_NAME].decode()
    assert raw in markdown and effective in markdown
    manifest = json.loads(files[handoff.MANIFEST_NAME])
    for entry in manifest["files"]:
        body = files[entry["name"]]
        assert entry["sha256"] == hashlib.sha256(body).hexdigest() and entry["bytes"] == len(body)
    assert {e["name"] for e in manifest["files"]} == {handoff.JSON_NAME, handoff.MARKDOWN_NAME}


def test_fixed_v2_record_expiry_agrees_on_every_surface(tmp_path, monkeypatch):
    from test_handoff_clock_validity import record

    expiry_surfaces_agree(record(), tmp_path, monkeypatch, "expiry-surfaces")
