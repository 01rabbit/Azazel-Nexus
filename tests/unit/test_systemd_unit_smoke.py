"""Pure parsing and command tests; never invoke a service manager."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.systemd_unit_smoke import UNITS, build_command, parse_service, validate_reply

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("name", UNITS)
def test_every_installed_service_directive_is_carried(name):
    source = ROOT / "packaging/systemd" / (name + ".service")
    properties = parse_service(source.read_text())
    command = build_command(name, properties)
    assert command[:3] == ["systemd-run", "--unit=azazel-smoke-" + name, "--no-block"]
    for key, value in properties.items():
        if key != "ExecStart":
            assert f"--property={key}={value}" in command
    assert "--property=CapabilityBoundingSet=" in command
    assert "--property=RuntimeDirectoryPreserve=yes" in command
    assert command[-2:] == ["--", properties["ExecStart"]]
    assert not any(word in command for word in ("enable", "unmask", "start"))


def test_lists_continuations_reset_and_other_sections():
    props = parse_service('''[Unit]
Requires=real.service
[Service]
User=test
ExecStart=/bin/true
ReadWritePaths=/old
ReadWritePaths=
ReadWritePaths=/one \\
 /two
ReadWritePaths=/three
CapabilityBoundingSet=
PrivateNetwork=yes
Group=operator
FutureHardening=yes
[Install]
WantedBy=multi-user.target
''')
    assert props["ReadWritePaths"].split() == ["/one", "/two", "/three"]
    assert props["CapabilityBoundingSet"] == ""
    assert "Requires" not in props and "WantedBy" not in props
    command = build_command("azazel-mio-entryd", props)
    for property in ("Group=operator", "PrivateNetwork=yes", "FutureHardening=yes"):
        assert "--property=" + property in command


@pytest.mark.parametrize("source", ["[Service]\nUser=x", "[Service]\nUser=x\nExecStart=/a\nExecStart=/b",
                                    "[Service]\nUser=x\nExecStart=/a\nBroken"])
def test_incomplete_or_ambiguous_service_refused(source):
    with pytest.raises(ValueError):
        parse_service(source)


def test_command_does_not_use_a_shell_or_expand_unit_specifiers():
    with pytest.raises(ValueError):
        build_command("azazel-mio-entryd", {"ExecStart": "/bin/%n", "User": "x"})
    command = build_command("azazel-mio-entryd", {"ExecStart": '/bin/echo "$(id)"', "User": "x"})
    assert command[-1] == "$(id)"


def test_bounded_replies():
    validate_reply("azazel-mio-entryd", {"route": "deterministic handoff", "outcome": "refused",
                                         "reason": "no provider", "ledger_seq": 1})
    validate_reply("azazel-knowledge-lited", {"state": "unavailable", "reason_code": "no_bundle",
                                             "generation": None, "freshness": "absent"})
    with pytest.raises(ValueError):
        validate_reply("azazel-knowledge-lited", {"state": "available", "reason_code": "x" * 65,
                                                 "generation": None, "freshness": "absent"})
