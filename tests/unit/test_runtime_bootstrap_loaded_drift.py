"""Drift between the loaded-unit pins and the shipped bootstrap pair (#93).

`bootstrap_loaded` pins what systemd must report over D-Bus for auditd and
commissiond. The units it inspects are the overlay rendered from
`hardening.PROFILES`, which is also what `packaging/systemd/` ships. When the
profile gained `SupplementaryGroups=azknowledge` (#86) the pin stayed empty,
and the shipped supporting-only bootstrap refused commissiond on the VM.

This test reads the `[Service]` directives of both the packaged unit file and
the rendered overlay payload, turns them into the value systemd reports for
each pinned D-Bus property (defaults, accumulation and resets included), and
requires every pin to equal it exactly, type included. A pin with no model
below fails too, so a new pin cannot skip the comparison.
"""

from pathlib import Path
import shlex
import signal

import pytest

from azazel_nexus_runtime import bootstrap_loaded
from azazel_nexus_runtime.bootstrap_overlay_files import _fixed_payloads
from azazel_nexus_runtime.hardening import PROFILES
from azazel_nexus_runtime.units import UNIT_NAMES, UnitKey

UNIT_DIR = Path(__file__).resolve().parents[2] / "packaging" / "systemd"
PAIR = (UnitKey.AUDITD, UnitKey.COMMISSIOND)
SOURCES = ("packaged", "overlay")

_TRUE = {"1", "yes", "y", "true", "t", "on"}
_FALSE = {"0", "no", "n", "false", "f", "off"}


def _service_directives(text):
    """`[(key, value), ...]` of the `[Service]` section, in file order."""

    directives, section = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        assert not line.endswith("\\"), "continuation lines are not modelled"
        key, separator, value = line.partition("=")
        assert separator, line
        if section == "Service":
            directives.append((key.strip(), value.strip()))
    return directives


def _assignments(directives, key):
    return [value for name, value in directives if name == key]


def _string(default):
    def model(directives, key):
        values = _assignments(directives, key)
        return values[-1] if values and values[-1] else default
    return "s", model


def _boolean(default):
    def model(directives, key):
        values = _assignments(directives, key)
        if not values or not values[-1]:
            return default
        word = values[-1].lower()
        assert word in _TRUE | _FALSE, (key, word)
        return word in _TRUE
    return "b", model


def _signal(default):
    def model(directives, key):
        values = _assignments(directives, key)
        if not values or not values[-1]:
            return default
        word = values[-1]
        if word.isdigit():
            return int(word)
        name = word if word.startswith("SIG") else "SIG" + word
        return int(signal.Signals[name])
    return "i", model


def _words():
    """A list setting: each assignment appends its words, an empty one resets."""

    def model(directives, key):
        result = []
        for value in _assignments(directives, key):
            if not value:
                result = []
            else:
                result.extend(shlex.split(value))
        return result
    return "as", model


def _environment_files(directives, key):
    result = []
    for value in _assignments(directives, "EnvironmentFile"):
        if not value:
            result = []
        else:
            optional = value.startswith("-")
            result.append([value[1:] if optional else value, optional])
    return result


def _notify_access(directives, key):
    values = _assignments(directives, key)
    if values and values[-1]:
        return values[-1]
    # systemd defaults NotifyAccess=main for the notify service types.
    service_type = _string("simple")[1](directives, "Type")
    return "main" if service_type in {"notify", "notify-reload"} else "none"


#: D-Bus property -> (signature, model of the value systemd reports).
MODELS = {
    "Type": _string("simple"),
    "NotifyAccess": ("s", _notify_access),
    "Restart": _string("no"),
    "RemainAfterExit": _boolean(False),
    "KillMode": _string("control-group"),
    "SendSIGKILL": _boolean(True),
    "TimeoutStartFailureMode": _string("terminate"),
    "TimeoutStopFailureMode": _string("terminate"),
    "FinalKillSignal": _signal(int(signal.SIGKILL)),
    "KillSignal": _signal(int(signal.SIGTERM)),
    "ExitType": _string("main"),
    "DynamicUser": _boolean(False),
    "Group": _string(""),
    "Environment": _words(),
    "EnvironmentFiles": ("a(sb)", _environment_files),
    "PassEnvironment": _words(),
    "UnsetEnvironment": _words(),
    "PAMName": _string(""),
    "SupplementaryGroups": _words(),
    "RootDirectory": _string(""),
    "RootImage": _string(""),
}


def _profile(unit):
    (profile,) = [item for item in PROFILES if item.unit == UNIT_NAMES[unit]]
    return profile


def _text(unit, source):
    if source == "packaged":
        return (UNIT_DIR / UNIT_NAMES[unit]).read_text(encoding="utf-8")
    return _fixed_payloads()[UNIT_NAMES[unit]].decode("utf-8")


@pytest.mark.parametrize("unit", PAIR)
def test_every_service_pin_has_a_drift_model(unit):
    assert set(bootstrap_loaded._service_expected(unit)) == set(MODELS)


def test_per_unit_pins_cover_exactly_the_pair_and_do_not_overlap():
    assert set(bootstrap_loaded._SERVICE_EXPECTED_BY_UNIT) == set(PAIR)
    for pins in bootstrap_loaded._SERVICE_EXPECTED_BY_UNIT.values():
        assert not set(pins) & set(bootstrap_loaded._SERVICE_EXPECTED)


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("unit", PAIR)
def test_service_pins_equal_the_shipped_unit(unit, source):
    directives = _service_directives(_text(unit, source))
    differences = {}
    for key, (signature, pinned) in bootstrap_loaded._service_expected(unit).items():
        model_signature, model = MODELS[key]
        shipped = model(directives, key)
        if (signature != model_signature or type(pinned) is not type(shipped)
                or pinned != shipped):
            differences[key] = {"pinned": (signature, pinned),
                                "shipped": (model_signature, shipped)}
    assert differences == {}


@pytest.mark.parametrize("source", SOURCES)
@pytest.mark.parametrize("unit", PAIR)
def test_user_and_commands_equal_the_shipped_unit(unit, source):
    # `_projection` pins User to the profile account and every Exec*Ex but
    # ExecStartEx to empty, and ExecStartEx to the bare executable.
    directives = _service_directives(_text(unit, source))
    profile = _profile(unit)
    assert _assignments(directives, "User") == [profile.account]
    assert _assignments(directives, "ExecStart") == [profile.executable]
    for command in bootstrap_loaded._COMMANDS:
        assert _assignments(directives, command.removesuffix("Ex")) == []


def test_commissiond_pin_is_exactly_the_shipped_group():
    """The value the VM refused in #93, stated literally."""

    assert bootstrap_loaded._service_expected(UnitKey.COMMISSIOND)[
        "SupplementaryGroups"] == ("as", ["azknowledge"])
    assert bootstrap_loaded._service_expected(UnitKey.AUDITD)[
        "SupplementaryGroups"] == ("as", [])


def test_models_follow_systemd_list_semantics():
    directives = [("SupplementaryGroups", "a b"), ("SupplementaryGroups", "c"),
                  ("UnsetEnvironment", "X"), ("UnsetEnvironment", ""),
                  ("UnsetEnvironment", "Y"), ("EnvironmentFile", "-/e")]
    assert MODELS["SupplementaryGroups"][1](directives, "SupplementaryGroups") == [
        "a", "b", "c"]
    assert MODELS["UnsetEnvironment"][1](directives, "UnsetEnvironment") == ["Y"]
    assert MODELS["EnvironmentFiles"][1](directives, "EnvironmentFiles") == [
        ["/e", True]]
    assert MODELS["NotifyAccess"][1]([("Type", "notify")], "NotifyAccess") == "main"
    assert MODELS["KillSignal"][1]([("KillSignal", "TERM")], "KillSignal") == 15
