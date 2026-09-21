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
    # Four rows: the three external modules and the local Edge Core, which is
    # named rather than omitted (#44). Pinned so that a row disappearing is a
    # failure rather than a smaller number nobody notices.
    assert len(section) == 4
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


def test_an_absent_data_tier_is_unavailable_and_not_a_defect(tmp_path):
    """A node that has not been commissioned is not a broken one.

    `missing` and its DEFECT marker are for an embedded feature that is not
    there. A Knowledge Lite whose store has never been written reports
    `unavailable` through its own reading, which is the routine state of a
    fresh install.
    """

    text = _status(tmp_path)
    assert "freshness [knowledge_lite]: unavailable" in text
    assert "DEFECT" not in text


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


def test_the_status_screen_keeps_the_five_words_apart(tmp_path):
    """`disabled` and `unavailable` appear, and they are not the same line."""

    text = _status(tmp_path)
    assert "remote M.I.O. disabled" in text
    assert "freshness [knowledge_lite]: unavailable" in text
    assert "remote M.I.O. unavailable" not in text


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
