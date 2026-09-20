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
from pathlib import Path

import pytest

from azazel_nexus.cli import main
from azazel_nexus.commissioning import CommissioningRefused, propose
from azazel_nexus.inventory import read_interfaces
from azazel_nexus.wizard import WizardAbandoned, commission, render_rows

NOW = "2026-09-20T00:00:00Z"
OPERATOR = "operator@console"
PROFILES = ("hardware", "resource", "topology")
KERNEL_NAMES = ("enp4s0", "enp5s0")


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


def _run(argv, tmp_path, **kwargs):
    out = io.StringIO()
    code = main(["--sysfs", str(_tree(tmp_path)), *argv], out=out, **kwargs)
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


def test_status_never_calls_an_absent_module_connected(tmp_path):
    _, text = _run(["status"], tmp_path)
    module_lines = [
        line
        for line in text.splitlines()
        if any(name in line for name in ("AZ-04", "AZ-06", "Remote M.I.O."))
    ]
    assert len(module_lines) == 3
    for line in module_lines:
        assert "absent" in line
        assert "--" in line, "an absent module must carry the reason it is absent"
        lowered = line.lower()
        for reassurance in ("connected", "reachable", "up to date", ": ok"):
            assert reassurance not in lowered


def test_status_does_not_claim_enforcement_ready_on_an_uncommissioned_node(tmp_path):
    _, text = _run(["status"], tmp_path)
    assert "enforcement ready: no" in text
    assert "no commissioning record exists on this node" in text


def test_status_never_prints_a_kernel_name(tmp_path):
    _, text = _run(["status"], tmp_path)
    for name in KERNEL_NAMES:
        assert name not in text


def test_health_reports_the_service_manager_as_unknown_not_healthy(tmp_path):
    """This build ships no daemon and speaks to no service manager.

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


def test_commission_writes_a_record_through_the_cli(tmp_path):
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
        ask=_scripted(["observation", "skip"]),
        confirm=lambda summary: True,
        permanent_mac_reader=lambda name: f"aa:bb:cc:dd:ee:{KERNEL_NAMES.index(name):02x}",
    )
    assert code == 0
    assert "commissioning recorded" in text
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


def test_the_console_script_points_at_the_entry_point():
    text = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text("utf-8")
    assert 'azazel-nexus = "azazel_nexus.cli:main"' in text


# -- the local Edge Core, which this node has not looked for --------------


def test_status_names_the_edge_core_rather_than_omitting_it(tmp_path):
    """A screen with no Edge row reads as a node with no Edge concern.

    Nexus#44: what is reported is the absence, with the reason. There is no
    producer of `EdgeBaselineState` in this repository and the row does not
    pretend otherwise.
    """

    _, text = _run(["status"], tmp_path)
    line = next(l for l in text.splitlines() if "Edge Core (local)" in l)
    assert "absent" in line
    assert "not built yet" in line
    assert "Azazel-Edge#424" in line


def test_status_says_edge_baseline_ready_is_no(tmp_path):
    _, text = _run(["status"], tmp_path)
    assert "edge-baseline-ready: no" in text


def test_status_never_claims_edge_baseline_ready(tmp_path):
    """The one string that would be a claim, refused wherever it appears.

    `EdgeBaselineState` is what the decision needs and nothing here builds
    one, so any rendering of "yes" would be a claim with nothing behind it.
    """

    from azazel_nexus.cli import EDGE_BASELINE

    _, text = _run(["status"], tmp_path)
    assert "edge-baseline-ready: yes" not in text

    # The *name* and the *reason* are checked separately. An earlier version
    # allowed any reassuring word on a line that also said "not claimed" --
    # which let the name itself become "Edge Core (local) running and
    # healthy", because the reason on the same line carried the exemption.
    name, reason = EDGE_BASELINE
    lowered = name.lower()
    for reassurance in ("ready", "healthy", "verified", "running", "connected"):
        assert reassurance not in lowered, (
            f"the module's name says {reassurance!r}; a name is not a place "
            "to put a finding"
        )
    assert "not claimed" in reason.lower()


def test_nothing_in_the_package_produces_an_edge_baseline_state():
    """The rule that keeps the row from becoming a stub.

    A producer written before the package exists would report on nothing
    while looking exactly like a check. Construction in tests is how the
    decision is exercised; construction in the product is what is forbidden.
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
    offenders = []
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
                    offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == [], (
        f"{offenders} construct an EdgeBaselineState. Nothing in the product "
        "may, until there is a package to derive one from (Azazel-Edge#424)"
    )
