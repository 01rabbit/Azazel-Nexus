"""Commissioning without hand-editing, and the display that reports it (#29).

The wizard's whole job is to let an operator finish commissioning through a
conversation. Its constraint is that it must do so while suggesting nothing:
every fact that would let it propose a role is a fact
`docs/commissioning.md` §4 forbids reading.

The prompt is injected in every test here. A wizard that called `input()`
could only be exercised by a person, which would make the path that writes the
commissioning record the one path never tested.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from azazel_nexus.cli import main
from azazel_nexus.commissioning import CommissioningRefused, propose
from azazel_nexus.edge_package import CHECKS
from azazel_nexus.inventory import read_interfaces
from azazel_nexus.wizard import WizardAbandoned, commission, render_rows

NOW = "2026-09-20T00:00:00Z"
OPERATOR = "operator@console"
PROFILES = ("hardware", "resource", "topology")
KERNEL_NAMES = ("enp4s0", "enp5s0")


@pytest.fixture(autouse=True)
def probe_account(monkeypatch):
    import os

    monkeypatch.setattr("azazel_nexus.edge_package._probe_owner_uid", os.geteuid)


def _tree(tmp_path: Path, names=KERNEL_NAMES) -> Path:
    root = tmp_path / "sys"
    net = root / "class" / "net"
    for index, name in enumerate(names):
        slot = f"0000:0{index + 4}:00.0"
        bus = root / "devices" / "pci0000:00" / slot
        bus.mkdir(parents=True)
        (bus / "vendor").write_text("0x8086\n")
        (bus / "device").write_text(f"0x15b{index}\n")
        (bus / "label").write_text(f"LAN{index + 1}\n")
        interface = net / name
        interface.mkdir(parents=True)
        (interface / "device").symlink_to(f"../../../devices/pci0000:00/{slot}")
    return net


def _proposal(tmp_path: Path, names=KERNEL_NAMES):
    readouts = read_interfaces(
        _tree(tmp_path, names),
        permanent_mac_reader=lambda name: f"aa:bb:cc:dd:ee:{names.index(name):02x}",
    )
    return propose(readouts)


def _scripted(answers):
    """An operator who answers in order. Records what they were asked."""

    asked = []
    iterator = iter(answers)

    def ask(prompt, choices):
        asked.append((prompt, tuple(choices)))
        return next(iterator)

    ask.asked = asked  # type: ignore[attr-defined]
    return ask


# -- the wizard suggests nothing ----------------------------------------


def test_the_wizard_offers_every_role_and_ranks_none(tmp_path):
    """No default, no pre-selection, no ordering that hints.

    The order is the proposal's, which is the interface order, which is the
    kernel's enumeration -- and the kernel name is never shown, so it cannot
    function as a hint either.
    """

    proposal = _proposal(tmp_path)
    ask = _scripted(["skip", "skip"])
    commission(
        proposal,
        ask=ask,
        confirm=lambda summary: True,
        operator=OPERATOR,
        at=NOW,
        profiles_present=PROFILES,
    )
    for _, choices in ask.asked:
        assert choices == ("skip", *proposal.offerable_roles)


def test_the_operator_is_never_shown_a_kernel_name(tmp_path):
    proposal = _proposal(tmp_path)
    ask = _scripted(["observation", "skip"])
    commission(
        proposal,
        ask=ask,
        confirm=lambda summary: True,
        operator=OPERATOR,
        at=NOW,
        profiles_present=PROFILES,
    )
    prompts = " ".join(prompt for prompt, _ in ask.asked)
    for name in KERNEL_NAMES:
        assert name not in prompts


def test_refused_interfaces_are_listed_rather_than_dropped(tmp_path):
    """An adapter that silently vanished is the one they hunt for behind the rack."""

    net = _tree(tmp_path)
    broken = net / "enp9s0"
    broken.mkdir()
    readouts = read_interfaces(net, permanent_mac_reader=lambda n: None)
    rows = render_rows(propose(readouts))
    assert rows, "every interface was dropped from the operator's view"
    assert all(not row["commissionable"] for row in rows)
    assert all(row["blocked_by"] for row in rows)


def test_wizard_screen_and_prompts_exclude_raw_identity(tmp_path):
    net = _tree(tmp_path)
    for device in (tmp_path / "sys" / "devices").glob("pci0000:00/*"):
        (device / "serial").write_text("private-serial\n")
    proposal = propose(read_interfaces(net, permanent_mac_reader=lambda name: "aa:bb:cc:dd:ee:01"))
    rows = render_rows(proposal)
    assert rows
    for row in rows:
        assert set(row["description"]) <= {"physical_label", "bus_path"}
    ask = _scripted(["skip", "skip"])
    commission(proposal, ask=ask, confirm=lambda summary: True,
               operator=OPERATOR, at=NOW, profiles_present=PROFILES)
    displayed = repr(rows) + repr(ask.asked)
    for raw in ("private-serial", "aa:bb:cc:dd:ee:01", "0x8086", "0x15b0"):
        assert raw not in displayed


# -- nothing is applied without confirmation ----------------------------


def test_a_set_the_operator_did_not_confirm_writes_nothing(tmp_path):
    proposal = _proposal(tmp_path)
    with pytest.raises(WizardAbandoned):
        commission(
            proposal,
            ask=_scripted(["observation", "management"]),
            confirm=lambda summary: False,
            operator=OPERATOR,
            at=NOW,
            profiles_present=PROFILES,
        )


def test_the_set_confirmation_shows_what_the_record_would_contain(tmp_path):
    """The per-interface answers were given with the next row unseen.

    So the second question is not ceremony: the set is the thing that gets
    written, and it is the first time the operator sees it whole.
    """

    seen = []
    commission(
        _proposal(tmp_path),
        ask=_scripted(["observation", "management"]),
        confirm=lambda summary: seen.append(summary) or True,
        operator=OPERATOR,
        at=NOW,
        profiles_present=PROFILES,
    )
    assert "observation" in seen[0] and "management" in seen[0]


def test_an_answer_that_was_not_understood_is_not_a_skip(tmp_path):
    """A typo must not leave an interface silently unassigned.

    Treating an unparsed answer as a skip turns an operator's slip into a
    decision nobody made.
    """

    with pytest.raises(CommissioningRefused):
        commission(
            _proposal(tmp_path),
            ask=_scripted(["obervation", "obervation", "obervation", "observation"]),
            confirm=lambda summary: True,
            operator=OPERATOR,
            at=NOW,
            profiles_present=PROFILES,
        )


def test_a_mistyped_answer_may_be_corrected(tmp_path):
    record = commission(
        _proposal(tmp_path),
        ask=_scripted(["obervation", "observation", "skip"]),
        confirm=lambda summary: True,
        operator=OPERATOR,
        at=NOW,
        profiles_present=PROFILES,
    )
    assert [role.role for role in record.roles] == ["observation"]


# -- what a completed commissioning is ----------------------------------


def test_confirming_no_role_is_a_completed_commissioning(tmp_path):
    """Observe-only is a record. It is not the absence of one.

    Somebody looked and confirmed nothing, which an operator and an activation
    controller both need to tell apart from nobody having looked.
    """

    record = commission(
        _proposal(tmp_path),
        ask=_scripted(["skip", "skip"]),
        confirm=lambda summary: True,
        operator=OPERATOR,
        at=NOW,
        profiles_present=PROFILES,
    )
    assert record.observe_only
    assert record.enforcement_ready is False
    assert record.missing_profiles == ()


def test_a_completed_commissioning_records_who_and_when(tmp_path):
    record = commission(
        _proposal(tmp_path),
        ask=_scripted(["observation", "skip"]),
        confirm=lambda summary: True,
        operator=OPERATOR,
        at=NOW,
        profiles_present=PROFILES,
    )
    assert record.roles[0].confirmed_by == OPERATOR
    assert record.roles[0].confirmed_at == NOW


def test_a_host_with_nothing_commissionable_refuses_rather_than_proceeding(tmp_path):
    net = tmp_path / "sys" / "class" / "net"
    (net / "enp4s0").mkdir(parents=True)
    proposal = propose(read_interfaces(net, permanent_mac_reader=lambda n: None))
    with pytest.raises(CommissioningRefused):
        commission(
            proposal,
            ask=_scripted([]),
            confirm=lambda summary: True,
            operator=OPERATOR,
            at=NOW,
            profiles_present=PROFILES,
        )


# -- the CLI ------------------------------------------------------------


def _run(argv, tmp_path, edge_root=None, **kwargs):
    """Run a command against an isolated tree.

    `--edge-root` is pointed at a directory under `tmp_path` rather than
    left at its default. The default is a real path on the host, and a test
    machine that happened to have an Edge package installed would otherwise
    read a different node than the one the test built.
    """

    out = io.StringIO()
    root = tmp_path / "edge-root" if edge_root is None else edge_root
    code = main(
        ["--sysfs", str(_tree(tmp_path)), "--edge-root", str(root), *argv],
        out=out,
        **kwargs,
    )
    return code, out.getvalue()


def test_every_subcommand_runs_with_no_network(tmp_path):
    """Structural, not aspirational.

    `test_boundary_static.py` refuses a package import that could open a
    socket, so these commands cannot depend on connectivity. This runs them.
    """

    for index, command in enumerate(["inventory", "profile", "status", "health"]):
        root = tmp_path / str(index)
        root.mkdir()
        code, text = _run([command], root)
        assert code == 0, f"{command} exited {code}"
        assert text.strip(), f"{command} printed nothing"


def test_status_shows_what_continues_and_not_only_what_was_lost(tmp_path):
    _, text = _run(["status"], tmp_path)
    assert "continuing:" in text
    assert "audit" in text.split("continuing:")[1].split("\n")[0]


#: Words that would make an absent module read as a working one.
_REASSURANCE = ("connected", "reachable", "up to date", ": ok")


def _module_section(text: str) -> list[str]:
    """The `external modules:` block alone.

    Scoped to the section rather than matched across the whole screen: the
    integration view (#55) also names AZ-04 and AZ-06 -- as *suppliers*, to
    say their absence is unavailable and not a defect -- and a count over the
    whole screen would break on a correct addition. The reassurance check
    below stays screen-wide, so nothing is given up by narrowing the count.
    """

    lines = text.splitlines()
    start = lines.index("external modules:") + 1
    section: list[str] = []
    for line in lines[start:]:
        if not line.strip():
            break
        section.append(line)
    return section


def test_status_never_calls_an_absent_module_connected(tmp_path):
    _, text = _run(["status"], tmp_path)
    section = _module_section(text)
    # Three rows, and no longer four. The local Edge Core used to be listed
    # here, when all this node could say about it was that it had not looked;
    # #44 gives it its own section, because `ModuleState` has four words for a
    # peer and the Edge Core needs eight. Pinned so that a row disappearing is
    # a failure rather than a smaller number nobody notices.
    assert len(section) == 3
    named = [
        line
        for line in section
        if any(name in line for name in ("AZ-04", "AZ-06", "Remote M.I.O."))
    ]
    assert len(named) == 3
    for line in section:
        assert "absent" in line
        assert "--" in line, "an absent module must carry the reason it is absent"
        lowered = line.lower()
        for reassurance in _REASSURANCE:
            assert reassurance not in lowered


def test_no_line_anywhere_calls_an_absent_module_connected(tmp_path):
    """Screen-wide, so narrowing the count above gives nothing up."""

    _, text = _run(["status"], tmp_path)
    for line in text.splitlines():
        if not any(name in line for name in ("AZ-04", "AZ-06", "Remote M.I.O.")):
            continue
        lowered = line.lower()
        for reassurance in _REASSURANCE:
            assert reassurance not in lowered, line


def test_status_does_not_claim_enforcement_ready_on_an_uncommissioned_node(tmp_path):
    _, text = _run(["status"], tmp_path)
    assert "enforcement ready: no" in text
    assert "no commissioning record exists on this node" in text


def test_status_never_prints_a_kernel_name(tmp_path):
    _, text = _run(["status"], tmp_path)
    for name in KERNEL_NAMES:
        assert name not in text


def test_health_reports_the_service_manager_as_unknown_not_healthy(tmp_path):
    """This status read does not query the service manager.

    Reporting that as healthy would be the absence of evidence rendered as
    health, which is the failure the hardware-gate register exists for.
    """

    _, text = _run(["health"], tmp_path)
    assert "systemd units: unknown" in text
    assert "HG-01" in text


def test_health_reports_a_broken_chain_as_failed(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(
        '{"sequence":1,"previous_hash":"' + "0" * 64 + '","event_hash":"deadbeef",'
        '"event":{"event_type":"x"}}\n',
        encoding="utf-8",
    )
    out = io.StringIO()
    main(
        ["--sysfs", str(_tree(tmp_path)), "--ledger", str(ledger), "health"], out=out
    )
    assert "audit chain: FAILED" in out.getvalue()


def test_commission_refuses_when_no_operator_can_be_asked(tmp_path):
    """No prompt means no confirmation, and no confirmation means no record."""

    code, text = _run(
        ["commission", "--operator", OPERATOR, "--at", NOW], tmp_path
    )
    assert code == 2
    assert "will not proceed" in text


@pytest.mark.parametrize("answers", [["observation", "skip"], ["skip", "skip"]])
def test_commission_prepares_only_an_unsigned_in_memory_draft(tmp_path, answers):
    code, text = _run(
        [
            "commission",
            "--operator",
            OPERATOR,
            "--at",
            NOW,
            "--profiles",
            *PROFILES,
        ],
        tmp_path,
        ask=_scripted(answers),
        confirm=lambda summary: True,
        permanent_mac_reader=lambda name: f"aa:bb:cc:dd:ee:{KERNEL_NAMES.index(name):02x}",
    )
    assert code == 0
    assert "commissioning draft prepared" in text
    assert "not signed, not persisted" in text
    assert "not an activation approval" in text
    assert "not measured profile evidence" in text
    assert "commissioning recorded" not in text
    assert "sha256:" not in text
    if answers == ["skip", "skip"]:
        assert "does not establish a running" in text
    for name in KERNEL_NAMES:
        assert name not in text


def test_a_cli_commissioning_the_operator_abandons_writes_nothing(tmp_path):
    code, text = _run(
        ["commission", "--operator", OPERATOR, "--at", NOW],
        tmp_path,
        ask=_scripted(["observation", "skip"]),
        confirm=lambda summary: False,
        permanent_mac_reader=lambda name: f"aa:bb:cc:dd:ee:{KERNEL_NAMES.index(name):02x}",
    )
    assert code == 2
    assert "abandoned" in text


@pytest.mark.parametrize("consent", [True, False])
def test_explicit_cli_draft_export_obeys_wizard_confirmation(tmp_path, monkeypatch, consent):
    from azazel_nexus import commissioning_draft
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *a, **kw: True)
    monkeypatch.setattr(commissioning_draft, "read_protection_key", lambda path: b"synthetic-test-only")
    output = tmp_path / "commissioning-draft.json"
    code, text = _run(
        ["commission", "--operator", OPERATOR, "--at", NOW, "--draft-output", str(output)],
        tmp_path, ask=_scripted(["observation", "skip"]), confirm=lambda summary: consent,
        permanent_mac_reader=lambda name: f"aa:bb:cc:dd:ee:{KERNEL_NAMES.index(name):02x}",
    )
    assert output.exists() is consent
    if consent:
        assert code == 0
        assert json.loads(output.read_bytes())["status"] == "unsigned-draft"
        assert "not signed" in text
        assert "in memory only" not in text
    else:
        assert code == 2


@pytest.mark.parametrize("fault", [None, "tamper", "wrong-purpose", "revoked", "inventory-change"])
def test_cli_export_sign_review_flow_with_ephemeral_keys(tmp_path, monkeypatch, fault):
    from nacl.signing import SigningKey
    from azazel_nexus import commissioning_draft, cli
    from azazel_nexus.operator_trust import OperatorTrust, ApprovalPurpose, approval_message
    monkeypatch.setattr(commissioning_draft, "COMMISSIONING_DIR", tmp_path)
    monkeypatch.setattr(commissioning_draft, "luks_backed", lambda *a, **kw: True)
    monkeypatch.setattr(commissioning_draft, "read_protection_key", lambda path: b"synthetic-only")
    reader = lambda name: f"aa:bb:cc:dd:ee:{KERNEL_NAMES.index(name):02x}"  # noqa: E731
    destination = tmp_path / "commissioning-draft.json"
    code, _ = _run(
        ["commission", "--operator", "operator-a", "--at", NOW, "--draft-output", str(destination)],
        tmp_path, ask=_scripted(["observation", "skip"]), confirm=lambda summary: True,
        permanent_mac_reader=reader,
    )
    assert code == 0
    key = SigningKey.generate()
    trust = OperatorTrust({"operator-a": bytes(key.verify_key)},
                          frozenset({"operator-a"}) if fault == "revoked" else frozenset())
    monkeypatch.setattr(cli, "load_operator_trust", lambda: trust)
    purpose = ApprovalPurpose.ACTIVATION if fault == "wrong-purpose" else ApprovalPurpose.COMMISSIONING
    signature = key.sign(approval_message(purpose, destination.read_bytes())).signature
    sidecar = tmp_path / "commissioning-draft.sig"
    sidecar.write_bytes(signature)
    sidecar.chmod(0o600)
    if fault == "tamper":
        destination.write_bytes(destination.read_bytes() + b"\n")
    if fault == "inventory-change":
        reader = lambda name: "aa:bb:cc:dd:ff:00"  # noqa: E731
    before = destination.read_bytes()
    # Reuse the already created sysfs fixture; no second _tree creation.
    out = io.StringIO()
    code = main(["--sysfs", str(tmp_path / "sys" / "class" / "net"),
                 "commission-review", "--operator", "operator-a"],
                out=out, permanent_mac_reader=reader)
    assert code == (0 if fault is None else 1)
    assert destination.read_bytes() == before
    if fault is None:
        assert "assigned bindings verified" in out.getvalue()
        assert "Nothing was imported or activated" in out.getvalue()
    else:
        assert "review refused" in out.getvalue()


def test_the_console_script_points_at_the_entry_point():
    text = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text("utf-8")
    assert 'azazel-nexus = "azazel_nexus.cli:main"' in text


# -- the local Edge Core, which this node has not looked for --------------


def test_status_names_the_edge_core_rather_than_omitting_it(tmp_path):
    """A screen with no Edge row reads as a node with no Edge concern.

    Nexus#44: the local Edge Core has its own section now, and it reports
    what was established at the fixed package location rather than that
    nobody asked.
    """

    _, text = _run(["status"], tmp_path)
    line = next(l for l in text.splitlines() if l.startswith("edge core (local):"))
    assert "absent" in line
    assert str(tmp_path / "edge-root") in line


def test_status_prints_all_five_checks_whatever_the_leading_word_says(tmp_path):
    """Stopping at the first failure hides what comes after it."""

    _, text = _run(["status"], tmp_path)
    for check in CHECKS:
        assert f"    {check}: " in text


def test_status_prints_the_unsigned_caveat_beside_the_edge_section(tmp_path):
    _, text = _run(["status"], tmp_path)
    assert "caveat: " in text
    assert "not authenticity" in text


def test_status_says_edge_baseline_ready_is_no(tmp_path):
    _, text = _run(["status"], tmp_path)
    assert "edge-baseline-ready: no" in text


def test_status_never_claims_edge_baseline_ready_on_a_node_with_no_package(tmp_path):
    """The one string that would be a claim, refused wherever it appears."""

    _, text = _run(["status"], tmp_path)
    assert "edge-baseline-ready: yes" not in text
    assert "verified-ready" not in text


def test_the_edge_line_carries_no_reassuring_word(tmp_path):
    """A leading word is not a place to put a finding.

    An earlier version allowed any reassuring word on a line that also said
    "not claimed" -- which let the name itself become "Edge Core (local)
    running and healthy", because the reason on the same line carried the
    exemption. The section's first line is now checked on its own.
    """

    _, text = _run(["status"], tmp_path)
    line = next(l for l in text.splitlines() if l.startswith("edge core (local):"))
    lowered = line.lower()
    for reassurance in ("ready", "healthy", "verified", "running", "connected"):
        assert reassurance not in lowered, line


def test_the_edge_baseline_line_follows_the_inspection(tmp_path):
    """Not a constant. A hard-coded "no" is right until the day it is wrong.

    A node whose five checks all pass must print `yes`, or the line is
    decoration rather than a report -- and then nothing would catch a node
    that reached ready and kept saying no.
    """

    from azazel_nexus.cli import _render_edge, _render_status
    from azazel_nexus.edge_package import Evidence, Finding, UNSIGNED_CAVEAT
    from azazel_nexus.edge_package import EdgeInspection
    from azazel_nexus.integration import EdgePresence

    ready = EdgeInspection(
        findings=tuple(
            Finding(check, Evidence.PASSED, "established in this test")
            for check in CHECKS
        ),
        presence=EdgePresence.VERIFIED_READY,
        caveats=(UNSIGNED_CAVEAT,),
        root="/somewhere",
    )
    out = io.StringIO()
    _render_status(_report_for(tmp_path), out, None, ready)
    assert "edge-baseline-ready: yes" in out.getvalue()


def _report_for(tmp_path):
    from azazel_nexus.cli import _report

    return _report(_tree(tmp_path), None)


def _tampered_package(tmp_path):
    """A package whose artifact is not the one its manifest describes."""

    import hashlib
    import json

    from azazel_nexus.edge_package import PIN

    root = tmp_path / "edge-tampered"
    root.mkdir()
    (root / PIN.artifact_name).write_bytes(b"swapped")
    (root / PIN.manifest_name).write_text(
        json.dumps(
            {
                "contract": PIN.manifest_contract,
                "package": PIN.package,
                "version": PIN.version,
                "architecture": PIN.architecture,
                "artifact": PIN.artifact_name,
                "digest": "sha256:" + hashlib.sha256(b"original").hexdigest(),
                "signed": False,
                "health": {"contract": PIN.health_contract},
                "posture": {"observe_only": True, "enforcement": False},
            }
        ),
        encoding="utf-8",
    )
    return root


def test_status_marks_a_digest_mismatch_as_a_security_finding(tmp_path):
    """Survived a mutation that dropped the marker, so it is asserted here.

    "Edge is not installed" and "Edge is installed and its artifact is not the
    one its manifest describes" are different operator actions, and only the
    second is a finding. A screen that printed the second as an ordinary
    failed check would have nobody treat it as one.
    """

    _, text = _run(["status"], tmp_path, edge_root=_tampered_package(tmp_path))
    line = next(l for l in text.splitlines() if l.strip().startswith("digest_matches:"))
    assert "SECURITY FINDING" in line
    assert "failed" in line


def test_the_integration_edge_axis_follows_the_same_inspection(tmp_path):
    """Survived a mutation that pinned the axis to `absent`.

    The section and the axis are rendered from one inspection. If the axis
    were a constant, one screen would describe two nodes -- the section
    reporting a tampered package and the axis reporting an empty one.
    """

    _, text = _run(["status"], tmp_path, edge_root=_tampered_package(tmp_path))
    assert "edge core (local): digest-mismatch" in text
    axis = next(l for l in text.splitlines() if l.strip().startswith("edge [edge_core]:"))
    assert "digest-mismatch" in axis
    assert "absent" not in axis


def test_the_edge_axis_reason_names_the_security_finding(tmp_path):
    _, text = _run(["status"], tmp_path, edge_root=_tampered_package(tmp_path))
    assert "This is a security finding" in text


def _verified_package(tmp_path):
    """A package whose three file-derived checks all pass."""

    import hashlib
    import json

    from azazel_nexus.edge_package import PIN

    root = tmp_path / "edge-verified"
    root.mkdir()
    payload = b"edge-core-payload"
    (root / PIN.artifact_name).write_bytes(payload)
    (root / PIN.manifest_name).write_text(
        json.dumps(
            {
                "contract": PIN.manifest_contract,
                "package": PIN.package,
                "version": PIN.version,
                "architecture": PIN.architecture,
                "artifact": PIN.artifact_name,
                "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
                "signed": False,
                "health": {"contract": PIN.health_contract},
                "posture": {"observe_only": True, "enforcement": False},
            }
        ),
        encoding="utf-8",
    )
    return root, "sha256:" + hashlib.sha256(payload).hexdigest()


def _probe_state(tmp_path, digest, *, observed_at="2026-09-21T04:00:00Z", **overrides):
    import json

    from azazel_nexus.edge_package import PIN, PROBE_CONTRACT

    document = {
        "contract": PROBE_CONTRACT,
        "observed_at": observed_at,
        "ttl_seconds": 300,
        "package_version": PIN.version,
        "package_digest": digest,
        "health": "passed",
        "health_reason": "all four conditions held",
        "health_security": False,
        "running": "passed",
        "running_reason": "azazel-edge-core.service is active/running",
    }
    document.update(overrides)
    path = tmp_path / "edge-probe.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _status_with_edge(tmp_path, root, state, *, as_of="2026-09-21T04:01:00Z"):
    out = io.StringIO()
    main(
        [
            "--sysfs",
            str(_tree(tmp_path)),
            "--edge-root",
            str(root),
            "--edge-probe",
            str(state),
            "--as-of",
            as_of,
            "status",
        ],
        out=out,
    )
    return out.getvalue()


def test_status_reads_the_probe_result_rather_than_probing(tmp_path):
    """The whole point of Nexus#72, asserted on the screen an operator reads.

    This was missing while the wiring silently was not applied: every test
    passed against a `status` that never looked at a probe result at all.
    """

    root, digest = _verified_package(tmp_path)
    text = _status_with_edge(tmp_path, root, _probe_state(tmp_path, digest))
    assert "edge core (local): verified-ready" in text
    assert "edge-baseline-ready: yes" in text
    assert "az-edge-probed at 2026-09-21T04:00:00Z" in text


def test_status_withholds_when_the_probe_result_is_stale(tmp_path):
    root, digest = _verified_package(tmp_path)
    state = _probe_state(tmp_path, digest)
    text = _status_with_edge(tmp_path, root, state, as_of="2026-09-21T04:10:00Z")
    assert "edge-baseline-ready: no" in text
    assert "stale" in text
    assert "health_endpoint_healthy: not-checked" in text


def test_status_withholds_when_the_probe_reports_another_package(tmp_path):
    root, _ = _verified_package(tmp_path)
    state = _probe_state(tmp_path, "sha256:" + "0" * 64)
    text = _status_with_edge(tmp_path, root, state)
    assert "edge-baseline-ready: no" in text
    assert "A result about a different package" in text


def test_status_says_so_when_the_probe_state_is_garbage_and_carries_on(tmp_path):
    """Something wrote it. Swallowing that would hide the one case worth seeing."""

    root, _ = _verified_package(tmp_path)
    state = tmp_path / "edge-probe.json"
    state.write_text("{ truncated", encoding="utf-8")
    text = _status_with_edge(tmp_path, root, state)
    assert "was refused" in text
    assert "edge-baseline-ready: no" in text
    assert "running: not-checked" in text


def test_status_with_no_probe_state_leaves_both_checks_unchecked(tmp_path):
    """A node where the probe has never run is not a node with a broken probe."""

    root, _ = _verified_package(tmp_path)
    text = _status_with_edge(tmp_path, root, tmp_path / "never-written.json")
    assert "was refused" not in text
    assert "health_endpoint_healthy: not-checked" in text
    assert "edge-baseline-ready: no" in text


def test_status_never_runs_anything_to_produce_the_edge_section():
    """`status` is read-only, and that is checked against the source.

    The library cannot import `subprocess` at all
    (`test_boundary_static.py`); this is the narrower statement that the CLI
    does not reach the probe module either. A status command that started the
    component it reports on would be a status command with a side effect.
    """

    import ast

    cli = Path(__file__).resolve().parents[2] / "src" / "azazel_nexus" / "cli.py"
    tree = ast.parse(cli.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "azazel_nexus_runtime" not in imported
    assert "subprocess" not in imported
    assert "edge_package" in {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    } | {m.lstrip(".") for m in imported}, "a vacuous scan: the CLI imports nothing"


def test_edge_package_is_the_only_producer_of_an_edge_baseline_state():
    """The rule that keeps the row from becoming a stub, narrowed rather than dropped.

    Before Nexus#44 nothing in the product could build one: a producer
    written ahead of the package would have reported on nothing while looking
    exactly like a check. The package exists now, so exactly **one** module
    derives the state, from a package actually on disk. Any second producer
    is what this still forbids -- a state assembled somewhere else is a state
    assembled from something other than the five checks.
    """

    import ast
    from pathlib import Path

    package = Path(__file__).resolve().parents[2] / "src" / "azazel_nexus"
    runtime = (
        Path(__file__).resolve().parents[2]
        / "runtime"
        / "src"
        / "azazel_nexus_runtime"
    )
    producers = []
    for root in (package, runtime):
        for path in sorted(root.rglob("*.py")):
            if path.name == "activation.py":
                continue  # where the type is declared
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and getattr(node.func, "id", "") == "EdgeBaselineState"
                ):
                    producers.append(path.name)
    assert set(producers) == {"edge_package.py"}, (
        f"{producers} construct an EdgeBaselineState. Only edge_package.py may, "
        "and it only from a package it verified on disk (Nexus#44)"
    )


# -- the six axes, on the node the operator actually has -------------------
#
# `integration.py` produces the rows and its own tests hold the rules. What is
# checked here is the thing those tests cannot see: that `azazel-nexus status`
# actually reaches them. A library nobody calls is how `lite_cache.py` came to
# sit unused for a whole stage (#59), and the only guard against a repeat is a
# test that runs the command.

_LITE_ARGS = ("--knowledge-lite", "/nonexistent/knowledge-lite", "--as-of", "2026-09-21T00:00:00Z")


def _status(tmp_path):
    return _run([*_LITE_ARGS, "status"], tmp_path)[1]


def test_status_prints_every_one_of_the_six_axes(tmp_path):
    from azazel_nexus.integration import AXES

    text = _status(tmp_path)
    assert "integration:" in text
    for axis in AXES:
        assert axis in text, axis


def test_status_prints_a_reason_under_every_axis(tmp_path):
    """An unexplained state reads as agreement."""

    from azazel_nexus.integration import AXES

    lines = _status(tmp_path).splitlines()
    for index, line in enumerate(lines):
        if any(line.strip().startswith(f"{axis}") for axis in AXES) and ":" in line:
            following = lines[index + 1] if index + 1 < len(lines) else ""
            assert following.strip(), f"no reason under {line.strip()}"


def test_status_does_not_claim_enforcement_or_baseline_readiness(tmp_path):
    text = _status(tmp_path)
    assert "enforcement capable: no" in text
    assert "baseline ready: no" in text
    assert "enforcement capable: yes" not in text
    assert "baseline ready: yes" not in text


def test_status_never_says_edge_decisions_continue_on_a_node_with_no_edge(tmp_path):
    """The reassurance an operator most wants, and least may be given falsely."""

    text = _status(tmp_path)
    assert "edge [edge_core]: absent" in text
    assert "Edge deterministic decisions" not in text


def test_status_prints_what_continues_after_the_losses_not_before(tmp_path):
    """Printed last and always, not as a footnote a long red list pushes off."""

    text = _status(tmp_path)
    continuing = text.index("continuing regardless:")
    assert continuing > text.index("integration:")
    assert continuing > text.index("edge [edge_core]")
    tail = text[continuing:].splitlines()[0]
    for expected in ("audit", "operator plane", "deterministic explanations"):
        assert expected in tail


def test_an_absent_data_tier_is_not_a_defect(tmp_path):
    """A node that has not been commissioned is not a broken one.

    `missing` and its DEFECT marker are for an embedded feature that is not
    there at all. Neither is the case here, so no DEFECT is printed.
    """

    text = _status(tmp_path)
    assert "DEFECT" not in text
    # Missing historical M.I.O. evidence is independent of the optional data tier.
    assert "missing" not in "\n".join(line for line in text.splitlines()
                                        if not line.startswith("M.I.O.:"))


def test_the_status_screen_says_which_kind_of_gap_each_embedded_feature_has(tmp_path):
    """Three features, three different facts, three different words.

    Knowledge Lite is **functional** (#67): a correct bundle can be imported
    offline and its claims served, so it reports its own state -- on a node
    with no bundle, `unavailable`. Local M.I.O. has no functional layer.
    Deception Lite has one that reaches only this host (#69).

    Reporting one word for all three would tell the operator who connected a
    supply route that the decoys were waiting on the same thing.
    """

    text = _status(tmp_path)
    assert "freshness [knowledge_lite]: unavailable" in text
    assert "freshness [deception_lite]: loopback-only" in text
    assert "local M.I.O. control-plane-only" in text
    assert "freshness [knowledge_lite]: control-plane-only" not in text
    for issue in ("Nexus#68", "Nexus#69"):
        assert issue in text, f"{issue} is not named on the screen"


def test_the_screen_says_a_loopback_decoy_reaches_only_this_host(tmp_path):
    """Otherwise `loopback-only` is a word an operator has to go and look up."""

    text = _status(tmp_path)
    assert "reaches only this host" in text
    assert "not the capability being supplied" in text


def test_the_screen_does_not_describe_an_embedded_gap_as_an_absent_peer(tmp_path):
    """The distinction, on the screen rather than only in the data.

    The peer rows say their absence is *not a defect* and is the designed
    state. The embedded rows say the functional layer does not exist. A reader
    who saw one word for both would treat a required feature as optional.
    """

    text = _status(tmp_path)
    assert "AZ-04 peer is a capability extension and its absence is unavailable, not a defect" in text
    assert "not the same fact as an external peer being absent" in text


def test_status_is_identical_for_the_same_instant(tmp_path):
    """`--as-of` is an input, so two runs of one node do not differ.

    The tree is built once and `main` is called twice against it: rebuilding
    it would make this a test about two nodes agreeing, which is a different
    and weaker claim.
    """

    sysfs = str(_tree(tmp_path))

    def once() -> str:
        out = io.StringIO()
        main(["--sysfs", sysfs, *_LITE_ARGS, "status"], out=out)
        return out.getvalue()

    assert once() == once()


def test_status_works_without_an_as_of_by_reading_the_clock_in_main(tmp_path):
    """The one place a wall clock legitimately enters.

    Checked by parsing: `_integration_view` must not read a clock, because a
    status built from one cannot be replayed from its inputs.
    """

    import ast
    import pathlib

    from azazel_nexus import cli as cli_module

    code, text = _run(["status"], tmp_path)
    assert code == 0
    assert "integration:" in text

    tree = ast.parse(pathlib.Path(cli_module.__file__).read_text(encoding="utf-8"))
    builder = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_integration_view"
    )
    called = {
        node.func.attr
        for node in ast.walk(builder)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert "now" not in called and "utcnow" not in called
    # And `main` really is where it comes from, so the assertion is not
    # satisfied by nothing reading a clock at all.
    assert "_now" in {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


def test_the_status_screen_keeps_the_words_apart(tmp_path):
    """`disabled` and `control-plane-only` appear, and are not one word.

    Both are on the M.I.O. row and they are different facts: remote is off by
    decision, and the local side has no functional layer.
    """

    text = _status(tmp_path)
    assert "remote M.I.O. disabled" in text
    assert "local M.I.O. control-plane-only" in text
    assert "remote M.I.O. unavailable" not in text
    assert "remote M.I.O. control-plane-only" not in text


def test_a_defect_row_is_marked_on_the_screen(tmp_path):
    """The renderer's DEFECT marker, exercised.

    The CLI never produces a defect today -- both embedded features are
    present on any node this package installs -- so nothing else here reaches
    that branch. A marker no test renders is a marker that can be deleted
    without a failure, which is how the DEFECT case would quietly stop being
    visible on the one screen it matters.
    """

    from azazel_nexus.capability import CapabilityState
    from azazel_nexus.cli import _render_integration
    from azazel_nexus.cognition import read_cognition
    from azazel_nexus.compatibility import TestedTupleSet
    from azazel_nexus.decoy import IsolationCheck, evaluate as evaluate_decoy
    from azazel_nexus.integration import EdgePresence, build_view
    from azazel_nexus.resource_profile import ResourceProfile

    view = build_view(
        capability=CapabilityState.CORE,
        knowledge=None,  # the embedded feature is not there at all
        cognition=read_cognition(
            [], profile=ResourceProfile.CORE, tested=TestedTupleSet(), host=None
        ),
        decoy=evaluate_decoy(
            "deception-lite",
            catalogue=None,
            commissioning=None,
            isolation=IsolationCheck(passed=None),
        ),
        edge=EdgePresence.ABSENT,
    )
    out = io.StringIO()
    _render_integration(view, out)
    text = out.getvalue()

    assert "missing" in text
    assert "DEFECT" in text
    assert text.count("DEFECT") == 1, "only the absent embedded feature is a defect"
    # The peer rows are on the same screen and are not marked.
    assert "AZ-04 peer is a capability extension" in text


def test_status_vm_lab_guidance_and_unknown_mio(tmp_path, monkeypatch):
    from azazel_nexus import lab_host
    marker = tmp_path / "LAB-HOST"
    marker.touch()
    monkeypatch.setattr(lab_host, "LAB_HOST_MARKER", marker)
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    code, text = _run(["status"], tmp_path)
    assert code == 0
    assert "M.I.O.: recorded ceiling: unknown; capability state: unknown" in text
    assert "not a grant or admission" in text
    assert "azazel-nexus commission" not in text
    assert "commissioning step unavailable on a lab host" in text
    assert "source: entryd route ledger" in text
    assert "CLI baseline capability state: CORE (fixed CORE component set; no live provider assessment)" in text
    assert "\ncapability state:" not in text
    assert "ships no daemon" not in text
    assert "audit: unknown -- no readable auditd status snapshot" in text
    assert "the path given" not in text


def test_status_reports_recorded_mio_ceiling_without_raising_capability(tmp_path, monkeypatch):
    from azazel_nexus.audit import AuditLedger
    from azazel_nexus.mio_status import ROUTE_LEDGER
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    path = tmp_path / ROUTE_LEDGER.lstrip("/")
    path.parent.mkdir(parents=True)
    AuditLedger(path).append({"event_type": "mio.capability.transition", "to": "CORE",
                              "occurred_at": "2026-10-19T00:00:00Z",
                              "reasons": {"profile": "LITE", "resource": "core_reserve_unmeasured",
                                          "trust": "not-checked", "topology": "no_verified_egress",
                                          "health": {"local": "unavailable", "remote": "not_admitted"}}})
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    code, text = _run(["status"], tmp_path)
    assert code == 0
    assert "recorded ceiling: LITE; capability state: CORE" in text
    assert "core_reserve_unmeasured" in text
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_launchable_inactive_edge_is_not_ready_in_status_or_projection(tmp_path):
    root, digest = _verified_package(tmp_path)
    state = _probe_state(tmp_path, digest, running="failed", running_reason="inactive/dead")
    text = _status_with_edge(tmp_path, root, state)
    assert "edge-baseline-ready: no" in text
    assert "edge-baseline-ready: yes" not in text
    assert "edge core (local): not-running" in text
    assert "baseline-ready: yes" not in text
    from azazel_nexus.edge_package import inspect, load_probe_result
    inspection = inspect(root, probe=load_probe_result(state), now="2026-09-21T04:01:00Z")
    assert inspection.state().launchable
    assert not inspection.as_event()["ready"]
    assert not inspection.ready
