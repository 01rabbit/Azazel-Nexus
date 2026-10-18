"""The shipped draft baseline must pass a real structural check, never a skip."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "playbooks" / "baseline" / "azazel-baseline.json"
SPEC = importlib.util.spec_from_file_location("check_playbooks", ROOT / "tools/check_playbooks.py")
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


@pytest.fixture
def layer():
    return checker.check_path(BASELINE)


def encoded(layer):
    return json.dumps(layer, ensure_ascii=False).encode("utf-8")


def test_baseline_passes_structural_check_and_has_all_categories(layer):
    assert layer["library_id"] == "azazel-baseline"
    assert layer["layer"] == "baseline"
    assert layer["version"] == "1.0.0"
    assert layer["disable"] == []
    assert 70 <= len(layer["entries"]) <= 90
    assert {entry["category"] for entry in layer["entries"]} == checker.CATEGORIES
    assert all(entry["status"] == "template" for entry in layer["entries"])
    assert checker.main([str(BASELINE)]) == 0


def test_required_scenarios_have_substantive_bilingual_guidance(layer):
    # Specific scenarios are protected against accidental removal or replacement
    # by a handful of broad entries. This list is independent of the file order.
    expected = {
        "auth-ssh-brute-force", "auth-rdp-brute-force", "auth-password-spraying",
        "auth-credential-stuffing", "auth-mfa-fatigue", "auth-impossible-travel",
        "auth-off-hours-account", "auth-new-privileged-account", "auth-service-account-anomaly",
        "network-recon-port-scan", "network-c2-beacon", "network-dns-tunneling",
        "network-dga-domains", "network-outbound-volume", "network-tor-anonymizer",
        "network-lateral-smb", "network-lateral-rdp", "network-lateral-remote-exec",
        "network-lateral-ssh", "endpoint-pass-the-hash", "endpoint-pass-the-ticket",
        "endpoint-privilege-escalation", "endpoint-lsass-dumping", "endpoint-encoded-powershell",
        "endpoint-lolbin-abuse", "endpoint-persistence-task", "endpoint-persistence-service",
        "endpoint-persistence-run-key", "endpoint-persistence-cron", "endpoint-persistence-systemd",
        "endpoint-audit-clearing", "endpoint-edr-tampering", "endpoint-malware-detection",
        "endpoint-ransomware-encryption", "endpoint-ransom-note", "web-sql-injection",
        "web-cross-site-scripting", "web-path-traversal", "web-ssrf", "web-idor-access-control",
        "web-authentication-bypass", "web-webshell-upload", "web-insecure-deserialization",
        "web-api-rate-abuse", "web-login-brute-force", "email-phishing-report",
        "email-attachment-executed", "email-bec-payment-change", "cloud-access-key-leak",
        "cloud-public-storage", "cloud-iam-policy-change", "cloud-unusual-region",
        "vuln-critical-exposed-service", "vuln-kev-listed", "vuln-missing-patch",
        "exfil-bulk-download", "exfil-removable-media", "exfil-personal-cloud",
        "deception-decoy-touched", "deception-canary-credential", "edge-rogue-dhcp",
        "edge-arp-spoofing", "edge-rogue-access-point", "edge-unknown-device",
        "edge-dns-resolver-change", "edge-misconfiguration", "supply-chain-dependency-update",
    }
    assert expected <= {entry["id"] for entry in layer["entries"]}
    for entry in layer["entries"]:
        for language in ("ja", "en"):
            guidance = entry["guidance"]
            assert len(guidance["checks"][language]) >= 2
            assert guidance["checks"][language][0].startswith("1. ")
            assert guidance["checks"][language][1].startswith("2. ")
            assert len(guidance["missing"][language][0]) >= 20
            if language == "ja":
                for section in guidance.values():
                    assert all(any("\u3040" <= char <= "\u9fff" for char in text)
                               for text in section[language])
    # None of the scenario-specific requests for facts is a repeated placeholder.
    for language in ("ja", "en"):
        requests = [entry["guidance"]["missing"][language][0] for entry in layer["entries"]]
        assert len(set(requests)) == len(requests)


def test_bare_ambiguous_event_ids_need_another_signal(layer):
    entries = {entry["id"]: entry for entry in layer["entries"]}
    for ident, event in (("auth-rdp-brute-force", "4625"),
                         ("endpoint-encoded-powershell", "4688")):
        for language in ("ja", "en"):
            match = entries[ident]["match"]
            hits = sum(keyword.casefold() in event for keyword in match["keywords"][language])
            assert hits < match["min_score"]


@pytest.mark.parametrize("level", ["library", "entry", "title", "reference", "match", "guidance"])
def test_unknown_fields_are_refused(layer, level):
    entry = layer["entries"][0]
    target = {"library": layer, "entry": entry, "title": entry["title"],
              "reference": entry["references"][0], "match": entry["match"],
              "guidance": entry["guidance"]}[level]
    target["unexpected"] = "unexpected"
    with pytest.raises(checker.InvalidPlaybook, match="^invalid fields$"):
        checker.validate(encoded(layer))


@pytest.mark.parametrize("text", [
    "https://invalid.example", "www.invalid.example", "`code`", "$(id)", "a && b",
    "a | b", "text; id", "rm -rf", "sudo id", "chmod file", "curl target",
    "wget target", "powershell -encodedcommand", "iptables rule", "nft rule",
    "enforcement", "block_all",
])
def test_unsafe_prose_is_refused_without_echoing_it(layer, text):
    layer["entries"][0]["guidance"]["checks"]["en"] = [text]
    with pytest.raises(checker.InvalidPlaybook, match="^unsafe text$"):
        checker.validate(encoded(layer))


@pytest.mark.parametrize("source,bad", [
    ("mitre-attack", "T11"), ("mitre-d3fend", "D3-lower"),
    ("owasp-top10-2021", "A11"), ("owasp-asvs", "V1.2.3.4"),
    ("owasp-cheatsheet", "Invalid Topic"), ("nist-sp800-61r3", "execute"),
    ("cisa-kev", "CVE-2021-1"), ("unknown", "T1110"),
])
def test_bad_reference_formats_are_refused(layer, source, bad):
    layer["entries"][0]["references"] = [{"source": source, "id": bad}]
    with pytest.raises(checker.InvalidPlaybook):
        checker.validate(encoded(layer))


@pytest.mark.parametrize("change", [
    "disable", "reviewed", "id", "category", "boolean-score", "zero-score", "keywords",
    "missing-language", "long-item", "empty-guidance", "too-many-guidance", "too-many-entries",
    "duplicate-id", "technique", "unknown-schema", "version", "library-id", "layer",
])
def test_malformed_layers_are_refused(layer, change):
    entry = layer["entries"][0]
    if change == "disable":
        layer["disable"] = [entry["id"]]
    elif change == "reviewed":
        entry["status"] = "reviewed"
    elif change == "id":
        entry["id"] = "Invalid_ID"
    elif change == "category":
        entry["category"] = "unknown"
    elif change == "boolean-score":
        entry["match"]["min_score"] = True
    elif change == "zero-score":
        entry["match"]["min_score"] = 0
    elif change == "keywords":
        entry["match"]["keywords"]["ja"] = ["x" * 49]
    elif change == "missing-language":
        del entry["guidance"]["missing"]["ja"]
    elif change == "long-item":
        entry["guidance"]["checks"]["en"] = ["x" * 161]
    elif change == "empty-guidance":
        entry["guidance"]["checks"]["ja"] = []
    elif change == "too-many-guidance":
        entry["guidance"]["checks"]["ja"] *= 3
    elif change == "too-many-entries":
        layer["entries"] = [copy.deepcopy(entry) for _ in range(513)]
    elif change == "duplicate-id":
        layer["entries"].append(copy.deepcopy(entry))
    elif change == "technique":
        entry["match"]["attack_techniques"] = ["TA0001"]
    elif change == "unknown-schema":
        layer["schema"] = "azazel-nexus/reasoning-playbook/2"
    elif change == "version":
        layer["version"] = "1.0"
    elif change == "library-id":
        layer["library_id"] = "bad/name"
    elif change == "layer":
        layer["layer"] = "customer"
    with pytest.raises(checker.InvalidPlaybook):
        checker.validate(encoded(layer))


@pytest.mark.parametrize("raw", [b"\xff", b"{", b"[]", b'{"schema":1,"schema":2}',
                                 b'{"outer":{"x":1,"x":2}}',
                                 b" " * (2 * 1024 * 1024 + 1)])
def test_bad_json_duplicate_keys_and_oversize_are_refused(raw):
    with pytest.raises(checker.InvalidPlaybook):
        checker.validate(raw)


def test_site_layer_and_each_reference_source_are_supported(layer):
    layer["layer"] = "site"
    layer["library_id"] = "test-site"
    layer["disable"] = ["auth-rdp-brute-force"]
    layer["entries"] = [layer["entries"][0]]
    layer["entries"][0]["status"] = "reviewed"
    layer["entries"][0]["references"] = [
        {"source": "mitre-attack", "id": "TA0001"},
        {"source": "mitre-d3fend", "id": "D3-ANET"},
        {"source": "owasp-top10-2021", "id": "A10"},
        {"source": "owasp-asvs", "id": "V4.1.1"},
        {"source": "owasp-cheatsheet", "id": "session-management"},
        {"source": "nist-sp800-61r3", "id": "respond"},
        {"source": "cisa-kev", "id": "CVE-2021-44228"},
    ]
    assert checker.validate(encoded(layer)) == layer


def test_cli_failure_uses_fixed_reason(tmp_path, capsys):
    path = tmp_path / "invalid.json"
    path.write_text('{"private-payload": "do not echo"}', encoding="utf-8")
    assert checker.main([str(path)]) == 1
    assert capsys.readouterr().out == "playbooks: invalid: invalid fields\n"
    assert checker.main([str(tmp_path / "absent.json")]) == 1
    assert capsys.readouterr().out == "playbooks: invalid: unreadable file\n"
