"""The target-hardware runbooks for #343-#346 state values the code decides.

`test_runbook_references.py` already checks every runbook's commands, flags,
symbols and paths. The four runbooks added for the changes merged on
2026-10-28 also state exact expected values -- unit hardening, socket paths,
reason words, budgets, status lines, refusal texts, the masked unit set. An
operator compares a target's output with them on hardware nobody here can
reach, so each one is read from the code here, never restated.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
RUNBOOKS = REPO / "docs" / "hil-runbooks"
UNITS = REPO / "packaging" / "systemd"


def _text(name: str) -> str:
    return (RUNBOOKS / name).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _unit(name: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in (UNITS / name).read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            key, _, value = line.partition("=")
            values.setdefault(key, []).append(value)
    return values


def _literals(path: Path) -> frozenset[str]:
    return frozenset(node.value for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                     if isinstance(node, ast.Constant) and isinstance(node.value, str))


def test_every_new_runbook_is_linked_from_the_campaign():
    campaign = (REPO / "docs" / "hil-campaign.md").read_text(encoding="utf-8")
    for name in ("mio-reference.md", "noc-observation.md", "edge-issuer.md", "offline-install.md"):
        assert f"(hil-runbooks/{name})" in campaign, name
        assert "Status: **not run; hardware-unverified**" in _text(name), name


# -- #343: the reference service and the deterministic handoff ----------------


def test_reference_runbook_states_the_installed_sandbox():
    text = _text("mio-reference.md")
    ref = _unit("azazel-mio-referenced.service")
    entry = _unit("azazel-mio-entryd.service")
    assert ref["User"] == ["azmioref"] and "`azmioref`" in text
    assert ref["SupplementaryGroups"] == ["azmission-read"] and "`azmission-read` only" in text
    assert entry["User"] == ["azmioentry"] and "`azmioentry`" in text
    assert entry["SupplementaryGroups"] == ["azazel-operator"]
    assert "`azazel-operator` only" in text
    assert ref["PrivateNetwork"] == ["yes"] and "PrivateNetwork" not in entry
    assert "(`PrivateNetwork=yes`)" in text and "(no `PrivateNetwork=`; `IPAddressDeny=any`)" in text
    assert entry["IPAddressDeny"] == ["any"]
    for unit in (ref, entry):
        assert unit["RestrictAddressFamilies"] == ["AF_UNIX"]
        assert unit["SystemCallFilter"] == ["@system-service"]
        assert unit["CapabilityBoundingSet"] == [""]
        assert unit["NoNewPrivileges"] == ["yes"]
        assert unit["Requires"] == ["azazel-activated.service"]
    assert "`SystemCallFilter=@system-service`" in text
    assert "`Requires=azazel-activated.service`" in text


def test_reference_runbook_states_the_socket_and_who_it_admits(monkeypatch):
    monkeypatch.delenv("AZAZEL_ROOT", raising=False)
    from azazel_nexus_runtime import mio_referenced
    from azazel_nexus_runtime.principal import PrincipalClass
    from azazel_nexus_runtime.protocol import Refusal
    from azazel_nexus_runtime.runtime_paths import socket_group, socket_path

    text = _text("mio-reference.md")
    # Composed at runtime, so stated in prose rather than as a code span.
    assert f"socket is {socket_path(mio_referenced.SOCKET_NAME)} (directory" in _flat(text)
    assert f"2710 {mio_referenced.ACCOUNT}:{socket_group(mio_referenced.SOCKET_NAME)}" in text
    verb = mio_referenced.REFERENCE_VERB
    assert mio_referenced.REGISTRY.names() == (verb.name,)
    assert f"`{verb.name}`" in text and verb.admits == frozenset({PrincipalClass.SERVICE})
    source = Path(mio_referenced.__file__).read_text(encoding="utf-8")
    assert 'service_accounts=("azmioentry",)' in source
    assert f"`refused {Refusal.PRINCIPAL_DENIED.value}`" in text
    assert f"`runtime.request_refused {Refusal.PRINCIPAL_DENIED.value} {verb.name}`" in text
    ledger = re.search(r'Path\("([^"]+reference\.jsonl)"\)', text).group(1)
    assert ledger == "/var/lib/azazel/state/mio-reference/reference.jsonl"
    assert ledger.endswith(f"{mio_referenced.SOCKET_NAME}/reference.jsonl")
    assert '"reference.jsonl"' in source


def test_reference_runbook_states_the_record_words():
    from azazel_nexus.incident_explain import CODES, CONTENT_KINDS, CONTENT_LABELS
    from azazel_nexus.routing import Route
    from azazel_nexus_runtime.mio_referenced import REFERENCE_REASONS

    text = _text("mio-reference.md")
    for kind in ("deterministic_reference", "deterministic_notice", "ai_advice"):
        assert kind in CONTENT_KINDS and f"`{kind}`" in text
    assert CONTENT_LABELS["deterministic_reference"] in text
    assert f"route `{Route.DETERMINISTIC_HANDOFF.value}`" in text
    for word in ("no_matching_playbook", "no_pack", "none_selected", "pack_degraded",
                 "reference_service_unavailable"):
        assert word in REFERENCE_REASONS and word in text
    assert "`mio_handoff:no_matching_playbook`" in text
    assert "`mio_unavailable`" in text and "mio_unavailable" in CODES
    assert "`REFERENCE_REASONS`" in text


def test_reference_runbook_states_the_attempts_causes_and_budgets():
    from azazel_nexus_runtime import incident_explaind, mio_entryd, mio_referenced, mio_router

    text = _flat(_text("mio-reference.md"))
    assert mio_router.MAX_AI_ATTEMPTS == 2 and "More than two attempts" in text
    causes = _literals(Path(mio_router.__file__))
    for cause in ("selected", "ai_attempts_exhausted", "ai_attempts_ended", "fallback",
                  "no_permitted_fallback", "deadline_budget_insufficient"):
        assert cause in causes and f"`{cause}`" in text
    for event in ("mio.entry.request", "mio.route.handoff", "mio.entry.handoff"):
        assert event in _literals(Path(mio_router.__file__)) | _literals(Path(mio_entryd.__file__))
        assert f'"{event}"' in text
    budgets = {
        "HANDOFF_RESERVE_MS": mio_router.HANDOFF_RESERVE_MS,
        "MIN_AI_ATTEMPT_MS": mio_router.MIN_AI_ATTEMPT_MS,
        "LEDGER_ALLOWANCE_MS": mio_entryd.LEDGER_ALLOWANCE_MS,
        "MIN_REFERENCE_FETCH_MS": mio_entryd.MIN_REFERENCE_FETCH_MS,
        "ENTRY_DELIVERY_RESERVE_MS": mio_entryd.ENTRY_DELIVERY_RESERVE_MS,
    }
    for name, value in budgets.items():
        assert f"`{name}` ({value})" in text, name
    deadline = incident_explaind.ADVISE_DEADLINE_MS
    margin = incident_explaind.ADVISE_CALLER_MARGIN_MS
    assert deadline == mio_referenced.REFERENCE_DEADLINE_MS
    assert f"`deadline_ms` {deadline} (`ADVISE_DEADLINE_MS`" in text
    assert f"waits {margin} ms longer (`ADVISE_CALLER_MARGIN_MS`)" in text
    assert f"within {deadline + margin} ms" in text
    assert f"below {deadline} ms" in text
    assert "software budgets written in the code, not measurements" in text


# -- #344: the NOC observation command -----------------------------------------


def test_noc_runbook_states_the_command_and_its_fixed_output():
    import tomllib

    from azazel_nexus_runtime import noc_observe

    text = _flat(_text("noc-observation.md"))
    scripts = tomllib.loads((REPO / "runtime" / "pyproject.toml").read_text())["project"]["scripts"]
    assert scripts["az-nexus-noc"] == "azazel_nexus_runtime.noc_observe:main"
    assert f"`{noc_observe.SCHEMA}`" in text
    assert f"`{noc_observe.COLLECTION_FAILED.strip()}`" in text
    assert (f"outside {noc_observe.MIN_INTERVAL_SECONDS}–{noc_observe.MAX_INTERVAL_SECONDS} "
            "seconds") in text
    literals = _literals(Path(noc_observe.__file__))
    assert "AF_NETLINK/NETLINK_ROUTE only" in literals
    assert "`AF_NETLINK/NETLINK_ROUTE only`" in text
    for request in ("RTM_GETADDR", "RTM_GETLINK", "RTM_GETROUTE"):
        assert request in literals and f"`{request}`" in text
    assert len(noc_observe.REQUEST_TYPES) == 3
    for reason in ("active_check_not_performed", "role_evidence_not_provided",
                   "speed_not_reported", "no_lease_file"):
        assert reason in noc_observe.UNKNOWN_REASONS and f"`{reason}`" in text
    assert any("SO-10" in item for item in literals)


# -- #345: issuer anchor, revocation and floor --------------------------------


def test_issuer_runbook_states_paths_schemas_and_words():
    from azazel_nexus import edge_issuer
    from azazel_nexus.edge_package import PINS

    raw = _text("edge-issuer.md")
    text = _flat(raw)
    assert str(edge_issuer.CONFIG_DIR / edge_issuer.ANCHOR_FILENAME) in text
    assert str(edge_issuer.CONFIG_DIR / edge_issuer.REVOCATION_FILENAME) in text
    assert str(edge_issuer.STATE_DIR / edge_issuer.FLOOR_FILENAME) in text
    assert edge_issuer.ANCHOR_SCHEMA in text and edge_issuer.REVOCATION_SCHEMA in text
    domain = edge_issuer.REVOCATION_DOMAIN.decode().replace("\0", "\\000")
    assert f"printf '{domain}'" in raw
    assert f"/opt/azazel/edge-core/{PINS['x86_64'].manifest_name}" in text
    for word in ("not_configured", "authenticated", "signature_invalid", "trust_refused"):
        assert word in edge_issuer.ISSUER_REASONS and word in text
    words = _literals(Path(edge_issuer.__file__)) | _literals(REPO / "src" / "azazel_nexus" / "edge_package.py")
    for word in ("in_force", "rolled_back", "revoked_version", "revoked_digest", "not_evaluated",
                 "absent", "held", "replayed"):
        assert word in words and word in text
    assert re.fullmatch(edge_issuer._ISSUER, "hil-test-only")


def test_issuer_runbook_examples_decode_with_the_verifier():
    from azazel_nexus.edge_issuer import EdgeRevocations, canonical_json

    raw = _text("edge-issuer.md")
    payload = re.search(r"printf '%s' '(\{\"issued_at[^']+)'", raw).group(1).encode()
    document = __import__("json").loads(canonical_json(payload))
    revocations = EdgeRevocations(
        sequence=document["sequence"], issued_at=document["issued_at"],
        package=document["package"],
        revoked_versions=frozenset(document["revoked_versions"]),
        revoked_digests=frozenset(document["revoked_digests"]),
    )
    assert revocations.as_payload() == canonical_json(payload)
    assert f"sequence {revocations.sequence}" in raw


def test_issuer_runbook_states_the_status_lines_and_the_floor_writer():
    from azazel_nexus_runtime import activated, edge_issuer_floor

    text = _flat(_text("edge-issuer.md"))
    # The status screen is rendered by status_view from its read model (U1).
    cli = _literals(REPO / "src" / "azazel_nexus" / "status_view.py")
    cli_source = (REPO / "src" / "azazel_nexus" / "status_view.py").read_text(encoding="utf-8")
    for prefix in ("issuer_authenticated: ", "rollback floor: ", "revocation: ", "digest_verified: "):
        assert prefix.strip() in cli_source and prefix.strip() in text
    assert "  SECURITY FINDING" in cli and "`SECURITY FINDING`" in text
    source = Path(activated.__file__).read_text(encoding="utf-8")
    assert '"activation.edge_issuer_floor"' in source
    assert "az-activated edge issuer floor" in source and "`az-activated edge issuer floor`" in text
    doc = edge_issuer_floor.raise_floor_after_grant.__doc__
    for label in ("raised", "held"):
        assert f"`{label}`" in doc and f"activation.edge_issuer_floor {label}" in text
    unit = _unit("azazel-activated.service")
    assert unit["User"] == ["root"] and unit["ProtectSystem"] == ["strict"]
    assert unit["UMask"] == ["0027"] and unit["CapabilityBoundingSet"] == ["CAP_DAC_READ_SEARCH"]
    assert "/var/lib/azazel/state" in unit["ReadWritePaths"]
    for value in ("`ProtectSystem=strict`", "`UMask=0027`", "`CapabilityBoundingSet=CAP_DAC_READ_SEARCH`",
                  "`ReadWritePaths=/var/lib/azazel/state`"):
        assert value in text
    assert "`root:root 644 1`" in text and "`root:root 755`" in text


# -- #346: offline install bundle ----------------------------------------------


def test_offline_runbook_states_the_refusals(tmp_path, monkeypatch):
    from azazel_nexus.edge_package import PINS
    from tools import offline_bundle

    text = _flat(_text("offline-install.md"))
    root = next(value for value in _literals(REPO / "tools" / "offline_bundle.py")
                if value.startswith("install runs as root"))
    assert f'"{root}"' in text
    PIN = PINS["x86_64"]  # the runbook installs the deployment baseline
    for name in (PIN.manifest_name, PIN.artifact_name):
        (tmp_path / name).write_bytes(b"")
    monkeypatch.setattr(offline_bundle, "reviewed_edge_digest", lambda root=None, target=None: None)
    with pytest.raises(offline_bundle.BundleRefused) as refused:
        offline_bundle.verify_edge_slot(tmp_path)
    assert f'"{refused.value}"' in text
    assert not (REPO / offline_bundle.EDGE_ARTIFACT_PIN).exists()
    assert "`\"bundle_authenticated\": false`" in text


def test_offline_runbook_states_the_report_and_the_systemd_stage():
    text = _flat(_text("offline-install.md"))
    tool = _literals(REPO / "tools" / "offline_bundle.py")
    assert "azazel-nexus-offline-bundle-report@1" in tool
    assert "`azazel-nexus-offline-bundle-report@1`" in text
    from tools.offline_bundle import BASELINE_TARGET, TARGETS

    target = TARGETS[BASELINE_TARGET]
    probe = f"{target['architecture']} cpython {target['python_version'][0]} {target['python_version'][1]}"
    assert f"`'{probe}'`" in text
    install_doc = (REPO / "docs" / "debian-live-install.md").read_text(encoding="utf-8")
    for path in ("--into /var/lib/azazel-offline/bundle", "--venv /opt/azazel-nexus/venv"):
        assert path in install_doc and path in text
    for flag in ("--bundle", "--into", "--venv", "--python", "--run-installer"):
        assert flag in tool and flag in text
    for word in ("install", "verify"):
        assert word in tool
    installer = (REPO / "packaging" / "install.sh").read_text(encoding="utf-8")
    masked = re.findall(r"^systemctl mask (\S+)$", installer, flags=re.MULTILINE)
    enabled = re.findall(r"^systemctl enable (\S+)$", installer, flags=re.MULTILINE)
    assert masked and enabled
    stated = set(re.findall(r"`(azazel-[a-z-]+\.service)`",
                            text.split("Expect every governed operational unit", 1)[1]
                            .split("`enabled`", 1)[0]))
    assert stated == set(masked) | set(enabled)
    for line in ("Azazel-Nexus installed. Operational units are masked.",
                 "SERVICE-MANAGER STAGE NOT EXECUTED: no unit was masked or enabled."):
        assert line in installer and f"`{line}`" in text
    stages = (REPO / "tools" / "e2e_stages.py").read_text(encoding="utf-8")
    assert '"units masked and disabled"' in stages and '"units masked and disabled"' in text
    for path in ("tools/build_wheelhouse.py", "tools/build_offline_bundle.py"):
        assert f"python3 {path} --output" in text
    for flag in ("--output", "--wheelhouse", "--edge-package", "--edge-source"):
        assert flag in _literals(REPO / "tools" / "build_offline_bundle.py")
    assert "--output" in _literals(REPO / "tools" / "build_wheelhouse.py")


# -- review follow-ups: values the operator compares byte for byte -----------


def _closing_echoes(script: str) -> list[str]:
    """The lines `install.sh` prints after its last other command, in order."""

    lines = [line.strip() for line in script.splitlines()]
    lines = [line for line in lines if line and not line.startswith("#")]
    closing = []
    for line in reversed(lines):
        match = re.fullmatch(r'echo "([^"]*)"', line)
        if match is None:
            break
        closing.append(match.group(1))
    return closing[::-1]


def test_offline_runbook_states_where_the_installed_line_is_in_the_tail():
    installer = (REPO / "packaging" / "install.sh").read_text(encoding="utf-8")
    closing = _closing_echoes(installer)
    installed = "Azazel-Nexus installed. Operational units are masked."
    assert closing and installed in closing
    after = len(closing) - 1 - closing.index(installed)
    tool = (REPO / "tools" / "offline_bundle.py").read_text(encoding="utf-8")
    kept = int(re.search(r'"stdout_tail": result\.stdout\.strip\(\)\.splitlines\(\)\[-(\d+):\]',
                         tool).group(1))
    # The report keeps enough lines to hold the installed line and what follows it.
    assert after + 1 <= kept
    text = _flat(_text("offline-install.md"))
    words = {0: "no", 1: "one", 2: "two", 3: "three"}
    assert f"follows it with {words[after]} more lines, the last being `{closing[-1]}`" in text
    raw = _text("offline-install.md")
    assert f'"{installed}" in t' in raw
    assert "stdout_tail[-1:]" not in raw


def test_offline_runbook_reads_only_report_keys_the_code_writes():
    tree = ast.parse((REPO / "tools" / "offline_bundle.py").read_text(encoding="utf-8"))
    keys = {key.value for node in ast.walk(tree) if isinstance(node, ast.Dict)
            for key in node.keys if isinstance(key, ast.Constant)}
    keys |= {node.slice.value for node in ast.walk(tree) if isinstance(node, ast.Subscript)
             and isinstance(node.ctx, ast.Store) and isinstance(node.slice, ast.Constant)}
    raw = _text("offline-install.md")
    script = next(line for line in raw.splitlines() if "offline-install-report.json\"))" in line)
    used = set(re.findall(r'\["(\w+)"\]', script))
    assert {"schema", "bundle_authenticated", "signature", "present", "install", "pip_check",
            "imports", "recheck", "installer", "exit", "slots", "state", "stdout_tail"} <= used
    assert used <= keys, sorted(used - keys)
    values = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)}
    for value in ("pass", "empty"):
        assert value in values
    install = next(node for node in ast.walk(tree) if isinstance(node, ast.Dict)
                   and any(isinstance(k, ast.Constant) and k.value == "pip_check" for k in node.keys))
    fields = {k.value: v for k, v in zip(install.keys, install.values) if isinstance(k, ast.Constant)}
    assert fields["pip_check"].value == "pass" and fields["imports"].value == "pass"


def test_issuer_runbook_states_the_floor_modes_the_writer_sets():
    source = (REPO / "runtime" / "src" / "azazel_nexus_runtime" / "edge_issuer_floor.py").read_text(
        encoding="utf-8")
    leaf = re.search(r"os\.mkdir\(_LEAF, 0o(\d+)", source).group(1)
    assert f"os.fchmod(fd, 0o{leaf})" in source
    floor = re.search(r"0o(\d+), dir_fd=leaf_fd\)", source).group(1)
    assert f"os.fchmod(fd, 0o{floor})" in source
    text = _text("edge-issuer.md")
    assert f"`root:root {leaf}`" in text and f"`root:root {floor} 1`" in text


def test_issuer_runbook_names_the_manifest_and_signature_by_variable():
    from azazel_nexus.edge_issuer import SIGNATURE_SUFFIX
    from azazel_nexus.edge_package import EDGE_PACKAGE_ROOT, PINS

    raw = _text("edge-issuer.md")  # a deployment-baseline (x86_64) runbook
    assert f"MANIFEST={EDGE_PACKAGE_ROOT / PINS['x86_64'].manifest_name}\n" in raw
    assert f'SIG="$MANIFEST{SIGNATURE_SUFFIX}"' in raw
    assert "MANIFEST.sig" not in raw.replace('"$MANIFEST.sig"', "")
    assert 'sudo rm "$SIG"' in raw and '"$SIG"`' in raw


def test_noc_runbook_ties_the_runs_to_the_recorders_stress_events():
    events = _literals(REPO / "tools" / "service_objectives.py")
    text = _flat(_text("noc-observation.md"))
    for event in ("independent-capture-stress-start", "independent-capture-stress-stop"):
        assert event in events and f"`{event}`" in text
    assert '"runs", n, "failed", f + 0, "max_gap_s"' in _text("noc-observation.md")
    assert "`failed` is `0`: **every** run of the command exited 0" in text
    assert "**inconclusive**" in text
