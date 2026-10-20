"""The README says what exists, and is checked against what exists (#115).

A front page is the one document everybody reads and nobody re-derives. Two
ways it goes wrong:

- a capability is described in the shape somebody hoped for rather than the
  shape it has -- "always available" about a provider no node can run
- a number is written in prose and the thing it counts changes underneath it

So each status row is pinned, and every count is compared against the
manifest it claims to describe rather than against a number typed here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
README = REPO / "README.md"


def _flat() -> str:
    return " ".join(README.read_text(encoding="utf-8").split())


@pytest.mark.parametrize(
    "row",
    [
        "software implementation complete; hardware-unverified",
        "a correct bundle is imported offline by an operator and its claims served read-only",
        "**loopback-only.**",
        "External reachability, redirection and field engagement are **not demonstrated**",
        "M.I.O. routing and commissioning control plane implemented; provider execution "
        "unavailable pending hardware evidence and provider integration",
        "target-local preflight implemented",
        "**8 GiB target evidence pending**",
        "**do not increase the baseline node's authority**",
    ],
)
def test_the_status_table_states_each_capability_as_it_stands(row):
    assert row in _flat(), f"the status table lost: {row}"


@pytest.mark.parametrize(
    "claim",
    [
        "local/offline assistance is always available",
        "always available within provisioned capacity",
        "field-proven",
        "production-ready",
        "military-grade",
    ],
)
def test_the_readme_makes_no_claim_the_build_cannot_support(claim):
    """The first of these was there: it read as a promise about a provider
    no node can run, because the resource gate refuses every one of them."""

    assert claim not in _flat(), f"the README claims {claim!r}"


def test_the_roadmap_is_a_link_and_not_the_entry_point():
    """A front page whose first offer is a plan tells a reader what is
    intended before it tells them what is there."""

    text = README.read_text(encoding="utf-8")
    plan = text.index("[Implementation roadmap](docs/roadmap.md)")
    table = text.index("| Capability | State today |")
    assert table < plan, "the roadmap comes before what exists"
    assert "this page's table is what exists" in _flat()


def test_no_count_of_units_is_written_in_prose():
    """`four daemons` was true of a build with four. Counting in prose is
    how a sentence goes stale without anybody editing it."""

    flat = _flat()
    for number in ("one", "two", "three", "four", "five", "six", "seven", "eight", "nine"):
        for noun in ("daemons", "units", "services", "subcommands"):
            assert f"{number} {noun}" not in flat, f"{number} {noun!r} is counted in prose"


def test_every_shipped_unit_is_one_the_runtime_provides():
    """The manifest and the distribution, compared rather than described."""

    shipped = {
        path.stem for path in sorted((REPO / "packaging" / "systemd").glob("*.service"))
    }
    entry_points = (REPO / "runtime" / "pyproject.toml").read_text(encoding="utf-8")
    assert "azazel-edge-core" in shipped
    shipped.remove("azazel-edge-core")  # The verified Edge package supplies its binary.
    # The boot preflight runs the probe's own entry point (#206 P5).
    assert "azazel-edge-probe-preflight" in shipped
    shipped.remove("azazel-edge-probe-preflight")
    preflight = (REPO / "packaging" / "systemd" / "azazel-edge-probe-preflight.service")
    assert "ExecStart=/usr/libexec/azazel/az-edge-probed\n" in preflight.read_text(
        encoding="utf-8")
    for unit in sorted(shipped):
        script = unit.replace("azazel-", "az-")
        assert f"{script} =" in entry_points, f"{unit} has no entry point"


def test_the_subcommand_table_is_exactly_what_the_cli_accepts():
    """Read from the parser, so a subcommand added or removed without the
    table fails here rather than in front of an operator."""

    import io
    import contextlib

    from azazel_nexus.cli import main

    out = io.StringIO()
    with contextlib.suppress(SystemExit), contextlib.redirect_stdout(out):
        main(["--help"])
    usage = out.getvalue()
    accepted = set(
        re.search(r"\{([a-z,\-]+)\}", usage).group(1).split(",")
    )

    documented = set(
        re.findall(r"^\| `([a-z-]+)` \|", README.read_text(encoding="utf-8"), re.M)
    )
    assert documented == accepted, (
        f"documented {sorted(documented)} but the CLI accepts {sorted(accepted)}"
    )


def test_the_preflight_is_published_without_arguments():
    assert "It takes **no arguments**" in _flat()
    assert re.search(r"hil-preflight\s+--", README.read_text(encoding="utf-8")) is None
