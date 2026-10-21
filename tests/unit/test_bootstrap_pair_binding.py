"""The bootstrap pair stays bound to the controller (#258 item A).

A soft-reboot keeps /run, so an interrupted bootstrap attempt can leave the
overlay that unmasks auditd and commissiond while the controller is skipped
by its once condition. The pair still does not start because each unit has
Requires=, BindsTo= and After= on the controller: a unit bound with After=
to a condition-skipped unit is not started (checked on the rehearsal VM).
These lines are load-bearing and must not be relaxed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

UNITS = Path(__file__).resolve().parents[2] / "packaging" / "systemd"
CONTROLLER = "azazel-activated.service"


def _unit_lines(name: str) -> dict[str, list[str]]:
    lines: dict[str, list[str]] = {}
    section = None
    for raw in (UNITS / name).read_text(encoding="ascii").splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line
        elif section == "[Unit]" and "=" in line and not line.startswith(("#", ";")):
            key, value = line.split("=", 1)
            lines.setdefault(key, []).append(value)
    return lines


@pytest.mark.parametrize("unit", ["azazel-auditd.service", "azazel-commissiond.service"])
def test_the_pair_is_bound_to_the_controller(unit):
    lines = _unit_lines(unit)
    for key in ("Requires", "BindsTo", "After"):
        assert CONTROLLER in lines.get(key, []), f"{unit} lost {key}={CONTROLLER}"


def test_the_controller_keeps_its_once_condition():
    lines = _unit_lines(CONTROLLER)
    assert "!/run/azazel-nexus-bootstrap/controller-used" in lines.get("ConditionPathExists", [])
