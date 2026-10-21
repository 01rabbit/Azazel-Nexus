"""The one-way dependency, checked from both directions (#37).

`azazel_nexus` holds what the node decides and imports nothing that can spawn
a process, open a socket or touch host storage. That property is why its
decisions can be tested at all, and it is not relaxed to let the runtime layer
exist -- the runtime layer exists beside it, in its own distribution.

Two directions, and both need checking:

*The library must not reach the runtime.* One import would let the
non-privileged half drag the privileged half in, and every guard on the
library's source would then be a guard on half the code that runs.

*The runtime must not smuggle the operational surface back.* It legitimately
imports `socket` and `subprocess`. What it may not do is give the library a
reason to.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LIBRARY = REPO_ROOT / "src" / "azazel_nexus"
RUNTIME = REPO_ROOT / "runtime" / "src" / "azazel_nexus_runtime"


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_the_library_never_imports_the_runtime():
    offenders = [
        path.name
        for path in sorted(LIBRARY.rglob("*.py"))
        if "azazel_nexus_runtime" in _imported_roots(path)
    ]
    assert offenders == [], (
        f"{offenders} import the privileged layer. The dependency runs one "
        "way: the library is what stays testable because it cannot act"
    )


def test_the_existing_operational_scan_still_covers_the_library():
    """The guard that started all of this must not have been narrowed.

    The easy way to make the runtime layer 'pass' would have been to point
    `test_the_package_contains_no_operational_code` somewhere else, or to add
    the runtime's directory to what it skips. Then the library would be
    unguarded and every test would still be green.
    """

    source = (REPO_ROOT / "tests" / "unit" / "test_boundary_static.py").read_text(
        encoding="utf-8"
    )
    assert 'PACKAGE_ROOT = Path(__file__).resolve().parents[2] / "src" / "azazel_nexus"' in source, (
        "the operational-code scan no longer points at the library"
    )
    for name in ("socket", "subprocess", "ctypes", "ssl"):
        assert f'"{name}"' in source, f"{name} was removed from the refused set"


def test_the_runtime_exists_as_its_own_distribution():
    """Separate `pyproject.toml`, so the library installs without it."""

    manifest = (REPO_ROOT / "runtime" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "azazel-nexus-runtime"' in manifest
    assert 'dependencies = ["azazel-nexus", "dbus-next==0.2.3", "PyYAML==6.0.3"]' in manifest

    library = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "azazel-nexus-runtime" not in library, (
        "the library declares the runtime as a dependency; installing the "
        "library would then install the privileged layer"
    )


#: The three modules in the runtime distribution permitted to reach the network,
#: for artifact fetching, remote inference and commissioned Knowledge advisory.
#:
#: This list is the record of a boundary that moved. Until Nexus#105 the scan
#: below asserted that **nothing** here could reach an internet address
#: family; the artifact fetch service needed to, so the assertion is now
#: "nothing except the named transports". Naming the exemption in the suite is the point: a
#: guarantee that quietly weakened and left no trace is one nobody can audit
#: afterwards, and "the test still passes" would have been true either way.
#:
#: Adding another name here is a deliberate act with a reviewer attached.
# Knowledge needs mTLS negotiation and retrieval, confined to its named transport.
EGRESS_EXEMPT = {"artifact_egress.py", "inference_egress.py", "knowledge_egress.py"}


#: The runtime modules permitted to **listen** on an internet address family,
#: and nothing else (#196 P1, `docs/deception-redirect-prerequisites.md` §5 D1,
#: owner decision §7 Q7).
#:
#: The first ingress entry, kept apart from `EGRESS_EXEMPT` so that the two
#: permissions never share a list: a listener may name `AF_INET`/`AF_INET6`
#: to bind and listen, and is still refused every way to initiate traffic
#: (`LISTENER_FORBIDDEN`). Like the egress list, each name is a module at the
#: top of the runtime package, matched by **full path** (`_exempt`): a file of
#: the same name in a subpackage is not exempt.
LISTENER_EXEMPT = {"decoy_listener.py"}

#: What the default scan refuses everywhere outside the exemptions.
INTERNET_FORBIDDEN = {"AF_INET", "AF_INET6", "AF_PACKET", "create_connection"}

#: What a listener module may still not name: every way to initiate traffic
#: (including asyncio's, and raw, paired or adopted sockets) and the raw
#: packet family. `bind`, `listen` and `accept` are what it is for.
LISTENER_FORBIDDEN = {
    "AF_PACKET", "SOCK_RAW", "create_connection", "connect", "connect_ex",
    "sendto", "sendmsg", "open_connection", "sock_connect",
    "create_datagram_endpoint", "socketpair", "fromfd",
}

#: Modules whose star import would bring a forbidden name in unseen.
_SOCKET_MODULES = {"socket", "_socket", "asyncio", "ssl"}


def _exempt(path: Path, names, root: Path = RUNTIME) -> bool:
    """True only for the exact file `root / name`, never a same-named file elsewhere."""

    return any(path == root / name for name in names)


def _attributes(path: Path, names: set[str]) -> list[str]:
    """Each of `names` the module reaches as an attribute or imports by name.

    A star import from a socket-family module is reported as ``*``: it would
    bring every forbidden name in without naming one.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in names:
            found.add(node.attr)
        elif isinstance(node, ast.ImportFrom):
            found.update(alias.name for alias in node.names if alias.name in names)
            if (node.module and node.module.split(".")[0] in _SOCKET_MODULES
                    and any(alias.name == "*" for alias in node.names)):
                found.add("*")
    return sorted(found)


def _internet_offenders(root: Path) -> dict[str, list[str]]:
    """The default scan: every module but the exact exempt files."""

    offenders: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*.py")):
        if _exempt(path, EGRESS_EXEMPT, root) or _exempt(path, LISTENER_EXEMPT, root):
            continue
        found = _attributes(path, INTERNET_FORBIDDEN)
        if found:
            offenders[path.relative_to(root).as_posix()] = found
    return offenders


def _listener_offenders(root: Path) -> dict[str, list[str]]:
    """The stricter scan, over the exact listener files."""

    offenders: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*.py")):
        if _exempt(path, LISTENER_EXEMPT, root):
            found = _attributes(path, LISTENER_FORBIDDEN)
            if found:
                offenders[path.relative_to(root).as_posix()] = found
    return offenders


def test_the_runtime_opens_no_internet_socket_outside_the_named_service():
    """`AF_UNIX` only, outside the named transport and listener modules.

    A daemon that could construct an `AF_INET` socket is a daemon whose
    `IPAddressDeny=any` is the only thing standing between it and the network
    -- and that setting is enforced by systemd, which CI does not run.

    The exemption is by **full path**, not by a marker a file can grant
    itself and not by a bare file name a subpackage could reuse. A module
    that wanted egress by writing a comment would be a module that granted
    itself egress. A listener module is scanned too, by the stricter test
    below, never skipped.
    """

    offenders = _internet_offenders(RUNTIME)
    assert offenders == {}, f"{offenders} reach an internet address family"


def test_a_listener_module_binds_and_listens_and_never_initiates():
    """The ingress exemption allows `bind`/`listen` only (§7 Q7).

    Every way to initiate traffic stays forbidden in the listener module: a
    decoy accepts and never initiates. Replies on an accepted connection
    (`send`/`sendall`) go back to whoever connected and are not an
    initiation.
    """

    assert _listener_offenders(RUNTIME) == {}
    for name in sorted(LISTENER_EXEMPT):
        path = RUNTIME / name
        assert path.exists(), f"{name} is exempt and does not exist"
        source = path.read_text(encoding="utf-8")
        # An exemption nothing uses is a hole held open for nothing.
        assert _attributes(path, {"bind"}) == ["bind"]
        assert _attributes(path, {"listen"}) == ["listen"]
        assert _attributes(path, {"AF_INET", "AF_INET6"}) == ["AF_INET", "AF_INET6"]
        assert "import ssl" not in source and "subprocess" not in source


def test_the_listener_scan_catches_what_it_forbids(tmp_path):
    """The stricter scan is not vacuous: each forbidden name is found."""

    for forbidden in sorted(LISTENER_FORBIDDEN):
        module = tmp_path / f"probe_{forbidden}.py"
        module.write_text(f"import socket\nsocket.{forbidden}\n", encoding="utf-8")
        assert _attributes(module, LISTENER_FORBIDDEN) == [forbidden]
        imported = tmp_path / f"import_{forbidden}.py"
        imported.write_text(f"from socket import {forbidden}\n", encoding="utf-8")
        assert _attributes(imported, LISTENER_FORBIDDEN) == [forbidden]


@pytest.mark.parametrize("module", sorted(_SOCKET_MODULES))
def test_a_star_import_from_a_socket_module_is_refused_by_both_scans(tmp_path, module):
    probe = tmp_path / "probe_star.py"
    probe.write_text(f"from {module} import *\n", encoding="utf-8")
    assert _attributes(probe, LISTENER_FORBIDDEN) == ["*"]
    assert _attributes(probe, INTERNET_FORBIDDEN) == ["*"]


def _fake_runtime(tmp_path: Path) -> Path:
    root = tmp_path / "azazel_nexus_runtime"
    (root / "sub").mkdir(parents=True)
    for name in EGRESS_EXEMPT:
        (root / name).write_text(
            "import socket\nsocket.AF_INET\nsocket.create_connection\n", encoding="utf-8")
    (root / "decoy_listener.py").write_text(
        "import socket\ns = socket.socket(socket.AF_INET)\ns.bind(('x', 1))\ns.listen(1)\n",
        encoding="utf-8")
    return root


def test_the_exact_exempt_files_pass_in_a_fake_runtime(tmp_path):
    root = _fake_runtime(tmp_path)
    assert _internet_offenders(root) == {}
    assert _listener_offenders(root) == {}


@pytest.mark.parametrize("name", sorted(LISTENER_EXEMPT | EGRESS_EXEMPT))
def test_a_same_named_file_elsewhere_is_not_exempt(tmp_path, name):
    """Matching by bare name let `sub/decoy_listener.py` connect freely (review M2)."""

    root = _fake_runtime(tmp_path)
    (root / "sub" / name).write_text(
        "import socket\nsocket.socket(socket.AF_INET).connect(('x', 1))\n", encoding="utf-8")
    assert _internet_offenders(root) == {f"sub/{name}": ["AF_INET"]}
    assert not _exempt(root / "sub" / name, EGRESS_EXEMPT | LISTENER_EXEMPT, root)


def test_the_exact_listener_file_that_connects_is_refused(tmp_path):
    root = _fake_runtime(tmp_path)
    (root / "decoy_listener.py").write_text(
        "import socket\nsocket.socket(socket.AF_INET).connect(('x', 1))\n", encoding="utf-8")
    assert _listener_offenders(root) == {"decoy_listener.py": ["connect"]}


def test_the_ingress_and_egress_exemptions_never_share_a_module():
    assert not LISTENER_EXEMPT & EGRESS_EXEMPT
    assert LISTENER_EXEMPT == {"decoy_listener.py"}
    assert all("/" not in name for name in LISTENER_EXEMPT | EGRESS_EXEMPT)


def test_the_exemption_names_a_module_that_exists_and_uses_it():
    """An exemption for a file that is gone, or that never needed one, is an
    exemption nobody would notice had stopped meaning anything.

    Both directions: every exempt name is a real module, and every exempt
    module actually reaches the network. A stale entry is a hole held open
    for nothing.
    """

    for name in sorted(EGRESS_EXEMPT):
        path = RUNTIME / name
        assert path.exists(), f"{name} is exempt and does not exist"
        source = path.read_text(encoding="utf-8")
        assert "socket" in source and "ssl" in source, (
            f"{name} is exempt from the egress scan and does not reach the "
            "network. An exemption nothing uses is a hole held open for nothing"
        )


def test_exactly_the_three_egress_modules_are_exempt():
    """The count is asserted, so widening is a diff a reviewer sees rather
    than a set that grew."""

    assert EGRESS_EXEMPT == {"artifact_egress.py", "inference_egress.py", "knowledge_egress.py"}


def test_the_runtime_uses_only_the_librarys_public_names():
    """No `_private` name crosses the distribution boundary.

    A privileged layer reaching into a library's internals makes the
    library's refusals negotiable: the private helper below a public refusal
    is the refusal with the check removed.
    """

    offenders: dict[str, list[str]] = {}
    for path in sorted(RUNTIME.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        private = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            if not node.module.startswith("azazel_nexus"):
                continue
            if node.module.startswith("azazel_nexus_runtime") or node.level:
                continue
            private.extend(
                alias.name for alias in node.names if alias.name.startswith("_")
            )
        if private:
            offenders[path.name] = sorted(private)
    assert offenders == {}, f"{offenders} import private names from the library"


#: The daemons the unit files name. `az-edge-probed` is the one-shot Edge
#: probe (Nexus#72): it reads, writes one bounded file, and exits.
EXPECTED_SCRIPTS = (
    "az-activated",
    "az-auditd",
    "az-commissiond",
    "az-edge-probed", "az-edge-intaked", "az-incident-explaind",
    "az-mio-entryd",
    "az-knowledge-lited",
    "az-mio-locald",
    "az-mio-remoted",
    "az-model-fetchd",
    "az-watchdog",
    # The Deception Lite exposure units (#196 P1, #196 (a)); all three refuse
    # and exit in this build.
    "az-decoy-nsd",
    "az-decoy-netd",
    "az-decoyd",
)

#: Console scripts an **operator** runs on a host, which correspond to no
#: unit because no node runs them by itself. Contained the way
#: `EXECUTING_MODULE` contains the one module allowed to start a process: the
#: exemption is by name, so a new daemon cannot acquire it by accident, and
#: `test_the_operator_tools_really_have_no_unit` checks that each one has
#: stayed unit-less rather than quietly gaining one.
#:
#: `az-core-reserve-probe` measures the Core reserve during a campaign that
#: happens once per hardware class (Nexus#68,
#: `docs/core-reserve-measurement.md`). A masked unit for it would sit on
#: every node describing work no node performs.
# az-nexus-bootstrap prepares only administrator-selected generation files;
# it is not a daemon, unit, widening backend or service-start command.
# az-activation publishes the observe-baseline generation, prints an unsigned
# approval request and installs a signed one (#206 P3); it grants nothing and
# az-activated does not import it.
OPERATOR_TOOLS = (
    "az-core-reserve-probe", "az-nexus-commission", "az-nexus-bootstrap",
    "az-hil-readiness", "az-hil-capture", "az-nexus-model-admission",
    "az-activation",
)


@pytest.mark.parametrize("option", ["--root", "--generation", "--expected-context"])
def test_bootstrap_operator_command_rejects_target_overrides_before_input(option, monkeypatch):
    from azazel_nexus_runtime import bootstrap_cli

    def forbidden(**kwargs):
        pytest.fail("invalid override reached provisioning")

    monkeypatch.setattr(bootstrap_cli, "run_generation", forbidden)
    with pytest.raises(SystemExit) as result:
        bootstrap_cli.main(["generation-publish", option, "untrusted"])
    assert result.value.code == 2


def _declared_scripts() -> dict[str, str]:
    manifest = (REPO_ROOT / "runtime" / "pyproject.toml").read_text(encoding="utf-8")
    scripts = {}
    for line in manifest.splitlines():
        if line.startswith("az-") and "=" in line:
            name, target = line.split("=", 1)
            scripts[name.strip()] = target.strip().strip('"')
    return scripts


def _governed_units() -> set:
    from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT, CORE_UNITS

    return {d.name for d in CORE_UNITS} | {ACTIVATION_CONTROLLER_UNIT}


def _script_for(unit: str) -> str:
    """`azazel-auditd.service` -> `az-auditd`. The one naming rule."""

    return "az-" + unit[len("azazel-") : -len(".service")]


def test_the_runtime_declares_exactly_the_daemons_the_units_name():
    assert sorted(_declared_scripts()) == sorted(EXPECTED_SCRIPTS + OPERATOR_TOOLS + ("az-mio-identity",))
    units = _governed_units()
    for script in EXPECTED_SCRIPTS:
        assert f"azazel-{script[3:]}.service" in units, (
            f"{script} corresponds to no governed unit"
        )


def test_every_governed_unit_has_an_executable_to_start():
    """The other direction, which nothing checked.

    The check above runs script -> unit, so a unit added without its console
    script passed. `azazel-model-fetchd.service` was added that way: the unit,
    the profile, the preset line and the installer's required-binary list all
    named `az-model-fetchd`, and nothing produced it. `install.sh` refuses to
    install when a unit's `ExecStart` is missing, so the product could not be
    installed on any node -- with every check green.

    A unit whose `ExecStart` does not exist is not a disabled unit. It is a
    unit that fails the moment anything starts it, on somebody else's
    hardware, long after the diff that introduced it.
    """

    declared = _declared_scripts()
    missing = sorted(
        unit for unit in _governed_units()
        if unit != "azazel-edge-core.service" and _script_for(unit) not in declared
    )
    assert missing == [], (
        f"{missing} are governed units whose executable nothing declares. "
        "Add the console script, or the unit starts nothing"
    )


def test_the_installer_requires_exactly_the_unit_backed_executables():
    """`install.sh` holds a fourth copy of the list, and it is the one that
    stops an install. Until now it was reconciled against nothing.

    Not a subset check: a binary the installer does not require is one a node
    can boot without, and a binary it requires that nothing builds is the
    refusal above.
    """

    installer = (REPO_ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")
    match = re.search(r"for binary in ([^;]+); do", installer)
    assert match, "the installer no longer checks that the unit executables exist"
    required = set(match.group(1).split())
    assert required == {_script_for(unit) for unit in _governed_units()
                        if unit != "azazel-edge-core.service"} | {"az-mio-identity"}, (
        "the installer's required binaries and the governed units disagree"
    )


def test_the_preset_names_every_governed_unit():
    """A unit absent from the preset is a unit `systemctl preset-all` may
    enable, which is the failure the preset file exists to prevent."""

    preset = (REPO_ROOT / "packaging" / "azazel-nexus.preset").read_text(
        encoding="utf-8"
    )
    stated = {
        line.split()[1]
        for line in preset.splitlines()
        if line.startswith(("enable ", "disable "))
    }
    # Plus the ungoverned Edge probe preflight, which the preset enables.
    assert stated == _governed_units() | {"azazel-edge-probe-preflight.service"}


def test_the_operator_tools_really_have_no_unit():
    """A named exemption for a tool that gained a unit is a hole in the list above.

    The daemon check passes for every script in `EXPECTED_SCRIPTS`, so a tool
    that quietly acquired a unit would simply be in the wrong list -- and
    nothing would say so. This is what says so.
    """

    from azazel_nexus.activation import ACTIVATION_CONTROLLER_UNIT, CORE_UNITS

    units = {d.name for d in CORE_UNITS} | {ACTIVATION_CONTROLLER_UNIT}
    assert OPERATOR_TOOLS, "the exemption list is empty and should be deleted"
    for script in OPERATOR_TOOLS:
        assert f"azazel-{script[3:]}.service" not in units, (
            f"{script} has a unit now; it belongs in EXPECTED_SCRIPTS"
        )
        assert script not in EXPECTED_SCRIPTS, f"{script} is in both lists"
    # And the tools really are declared, so the assertions above are not
    # satisfied by a name nothing ships.
    assert set(OPERATOR_TOOLS) <= set(_declared_scripts())


def test_an_entry_point_with_no_module_yet_is_matched_by_an_installer_that_refuses():
    """Declaring a console script does not ship a working one.

    The daemon modules arrive in #38-#41. Until each exists, `install.sh` must
    keep refusing -- an installer that succeeds while enabling a unit whose
    `ExecStart` is absent is one that fails at boot instead, which is later
    and on someone else's hardware.

    This is not a placeholder: it stays meaningful after the modules land,
    because it then requires the preflight to actually check for them.
    """

    installer = (REPO_ROOT / "packaging" / "install.sh").read_text(encoding="utf-8")
    for script, target in sorted(_declared_scripts().items()):
        module = target.split(":")[0].split(".")[-1]
        if (RUNTIME / f"{module}.py").is_file():
            continue
        assert "refusing to install" in installer, (
            f"{script} has no module and the installer does not refuse"
        )
        assert script in installer, (
            f"{script} has no module and the installer's preflight does not "
            "check for it, so the refusal would miss exactly this one"
        )


def test_identity_helper_is_the_only_privileged_prestart():
    from azazel_nexus_runtime.hardening import PROFILES

    prestarts = [(p.unit, value) for p in PROFILES for key, value in p.extra if key == "ExecStartPre"]
    assert prestarts == [("azazel-mio-locald.service", "+/usr/libexec/azazel/az-mio-identity")]
