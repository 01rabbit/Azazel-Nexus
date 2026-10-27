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
import subprocess
import sys
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
        found = _attributes(path, INTERNET_FORBIDDEN) + _family_violations(path)
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


#: Everything `az-decoyd` loads from this distribution (#196 decoy body,
#: `docs/deception-redirect-prerequisites.md` §12): the import closure of
#: `decoyd.py`, by full path. The decoy accepts and never initiates, so the
#: listener rule (`LISTENER_FORBIDDEN`) is applied to **every** module here,
#: not only to the listener -- with one exception, `DECOY_SENDER`.
DECOY_PROCESS = {
    "decoyd.py", "decoy_listener.py", "decoy_netns.py", "decoy_sender.py",
    "decoy_report.py", "decoy_loopback.py",
}

#: The decoy's one outgoing path: one line to the intake's decoy socket
#: (P2, §11). The only module of the decoy process that may name `connect`,
#: and only in the shape `_sender_violations` pins: `AF_UNIX` stream sockets,
#: one `connect(_PATH)`, `_PATH` assigned only `DECOY_INTAKE_SOCKET`, and that
#: a literal equal to the layout's decoy-intake socket. Matched by full path.
DECOY_SENDER = "decoy_sender.py"

#: The intake's decoy socket under `/` (`runtime_paths.socket_path`; the
#: test below keeps them equal).
DECOY_INTAKE_SOCKET = "/var/lib/azazel/run/decoy-intake/decoy-intake.sock"

#: What the sender may still not name: everything the listener may not,
#: except `connect`, plus every internet or datagram family and every way
#: to accept traffic.
SENDER_FORBIDDEN = (LISTENER_FORBIDDEN - {"connect"}) | {
    "AF_INET", "AF_INET6", "SOCK_DGRAM", "bind", "listen", "accept",
}

#: No module of the decoy process reads the environment, runs a process,
#: resolves a name, opens a server, reaches a module's namespace or a
#: function's internals, or looks a name up dynamically: nothing outside the
#: unit file may steer it, and no binding below can be made in a way the AST
#: rules do not see (review of #272). Matched as attributes, imported names
#: and bare names.
DECOY_PROCESS_FORBIDDEN = {
    "environ", "getenv", "putenv", "subprocess", "system", "popen", "ctypes",
    # Every `os.exec*`, `os.spawn*`, `fork`/`forkpty`, `posix_spawn*`, the
    # `pty` module and asyncio's process calls (#276 F4: `execvp`, `spawnv`
    # and `forkpty` passed the first list).
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
    "spawnvpe", "fork", "forkpty", "posix_spawn", "posix_spawnp", "pty",
    "create_subprocess_exec", "create_subprocess_shell",
    # A method or attribute looked up by a computed name is `getattr` again
    # (#276 F4: `methodcaller('con' + 'nect', ...)` passed). `AddressFamily`
    # makes a family from a number.
    "methodcaller", "attrgetter", "AddressFamily",
    "globals", "locals", "setattr", "delattr", "vars", "getattr", "__import__",
    "eval", "exec", "compile", "importlib",
    "getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
    "create_server",
    "__globals__", "__dict__", "__defaults__", "__kwdefaults__", "__code__",
    "__builtins__", "__class__", "__subclasses__",
}

#: Forbidden as a bare (builtin) name only: `re.compile` is not `compile`.
_BARE_ONLY = {"compile"}

#: The sender's path, which no other module of the decoy process may name.
_SENDER_PATH_NAMES = {"_PATH", "DECOY_INTAKE_SOCKET"}

_SENDER_IMPORTS = {"__future__", "socket", "azazel_nexus.decoy_interaction"}


def _names(path: Path, names: set[str]) -> list[str]:
    """`_attributes`, plus bare names (`globals()`, `setattr(...)`) and modules."""

    found = set(_attributes(path, names - _BARE_ONLY))
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Name) and node.id in names:
            found.add(node.id)
        elif isinstance(node, ast.alias) and node.asname in names:
            found.add(node.asname)
        elif isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names
                         if alias.name.split(".")[0] in names)
        elif isinstance(node, ast.ImportFrom) and node.module and (
                node.module.split(".")[0] in names):
            found.add(node.module.split(".")[0])
    return sorted(found)


def _bindings(tree: ast.AST, name: str) -> list[ast.AST]:
    """Every construct that binds `name`, in any scope.

    Assignment targets (also in tuples, `for`, `with ... as`, walrus,
    `del`), function arguments, imports (`as` or bare), `except ... as`,
    `global`/`nonlocal`, definitions and `match` captures.
    """

    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == name and isinstance(
                node.ctx, (ast.Store, ast.Del)):
            found.append(node)
        elif isinstance(node, ast.arg) and node.arg == name:
            found.append(node)
        elif isinstance(node, ast.alias) and (
                node.asname or node.name.split(".")[0]) == name:
            found.append(node)
        elif isinstance(node, ast.ExceptHandler) and node.name == name:
            found.append(node)
        elif isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            found.append(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (
                node.name == name):
            found.append(node)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == name:
            found.append(node)
        elif isinstance(node, ast.MatchMapping) and node.rest == name:
            found.append(node)
    return found


def _bound_once_at_module_level(tree: ast.Module, name: str, value) -> bool:
    """`name` is bound exactly once, by `name = <value>` at module level."""

    bindings = _bindings(tree, name)
    if len(bindings) != 1:
        return False
    for statement in tree.body:
        if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and statement.targets[0] is bindings[0]):
            return value(statement.value)
    return False


def _local_imports(path: Path, root: Path) -> set[str]:
    """Paths (relative to `root`) of the runtime modules `path` imports.

    `from .pkg import name` is the module `pkg/name.py` when that file exists,
    and `pkg.py` (or `pkg/__init__.py`) otherwise.
    """

    found = set()

    def add(package: str, names=()):
        base = package.replace(".", "/")
        submodules = [f"{base}/{name}.py" if base else f"{name}.py" for name in names]
        existing = [name for name in submodules if (root / name).is_file()]
        if existing:
            found.update(existing)
        if base and len(existing) < len(submodules) or base and not names:
            package_file = (f"{base}/__init__.py" if (root / base).is_dir()
                            else f"{base}.py")
            found.add(package_file)

    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            names = [alias.name for alias in node.names]
            if node.level >= 1 and node.module is None:
                found.update(f"{name}.py" for name in names)
            elif node.level >= 1:
                add(node.module, names)
            elif node.module and node.module.startswith("azazel_nexus_runtime."):
                add(node.module.split(".", 1)[1], names)
            elif node.module == "azazel_nexus_runtime":
                found.update(f"{name}.py" for name in names)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("azazel_nexus_runtime."):
                    add(alias.name.split(".", 1)[1])
    return found


#: The socket constructor's names: `socket.socket`, `socket.SocketType`.
_CONSTRUCTORS = {"socket", "SocketType"}

#: `socket.AF_UNIX`. The one family a constructor may be given as a number.
_AF_UNIX_VALUE = 1


def _integer(node: ast.AST):
    """The integer a literal (`2`, `-2`) evaluates to, else None."""

    try:
        value = ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None
    return value if type(value) is int else None


def _family_violations(path: Path) -> list[str]:
    """Socket constructors whose family is not a named constant or `AF_UNIX` (#276 F4).

    The name scans see `AF_INET`, not `socket.socket(2, 1)`. A constructor is
    `<anything>.socket(...)`/`.SocketType(...)`, a name bound by `from socket
    import socket as S`, or a name assigned one of those (`_S = socket.socket`).
    Its family (first argument or `family=`) is refused when it is a literal
    number other than `AF_UNIX`'s (1), a name assigned such a number anywhere in
    the module, an expression that is neither a name nor a literal, or absent
    (the default is `AF_INET`).
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    by_name: set[str] = set()
    numbers: dict[str, set[int]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {"socket", "_socket"}:
            by_name.update(alias.asname or alias.name for alias in node.names
                           if alias.name in _CONSTRUCTORS)
        pairs = []
        if isinstance(node, ast.Assign):
            pairs = [(target, node.value) for target in node.targets]
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            pairs = [(node.target, node.value)]
        for target, value in pairs:
            if not isinstance(target, ast.Name):
                continue
            if isinstance(value, ast.Attribute) and value.attr in _CONSTRUCTORS:
                by_name.add(target.id)
            elif _integer(value) is not None:
                numbers.setdefault(target.id, set()).add(_integer(value))
    problems = []
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not ((isinstance(call.func, ast.Attribute) and call.func.attr in _CONSTRUCTORS)
                or (isinstance(call.func, ast.Name) and call.func.id in by_name)):
            continue
        family = call.args[0] if call.args else next(
            (keyword.value for keyword in call.keywords if keyword.arg == "family"), None)
        if family is None:
            problems.append("socket family defaulted (AF_INET)")
        elif _integer(family) is not None:
            if _integer(family) != _AF_UNIX_VALUE:
                problems.append(f"socket family {_integer(family)}")
        elif isinstance(family, ast.Name):
            if numbers.get(family.id, set()) - {_AF_UNIX_VALUE}:
                problems.append(f"socket family {family.id} = "
                                f"{sorted(numbers[family.id])}")
        elif not isinstance(family, ast.Attribute):
            problems.append(f"socket family {ast.unparse(family)}")
    return problems


def _closure(start: str, root: Path = RUNTIME) -> set[str]:
    """The runtime modules `start` imports, transitively, by path relative to `root`."""

    seen, todo = set(), [start]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        if (root / name).is_file():
            todo.extend(sorted(_local_imports(root / name, root) - seen))
    return seen


def _decoy_closure(root: Path = RUNTIME) -> set[str]:
    return _closure("decoyd.py", root)


def _sender_violations(path: Path, expected: str = DECOY_INTAKE_SOCKET) -> list[str]:
    """Every way `path` departs from the one shape the sender may have."""

    tree = ast.parse(path.read_text(encoding="utf-8"))
    problems = [f"names {name}" for name in _attributes(path, SENDER_FORBIDDEN)]
    problems += [f"names {name}" for name in _names(path, DECOY_PROCESS_FORBIDDEN)]
    if _attributes(path, {"AF_UNIX"}) != ["AF_UNIX"]:
        problems.append("no AF_UNIX")
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(("." * node.level) + (node.module or ""))
    if not imports <= _SENDER_IMPORTS:
        problems.append(f"imports {sorted(imports - _SENDER_IMPORTS)}")
    # Every name the socket constructor is reachable by: `socket.socket`,
    # `socket.SocketType`, and whatever `from socket import socket as S` binds.
    constructors = {"socket", "SocketType"}
    by_name = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module in {"socket", "_socket"}:
            by_name.update(alias.asname or alias.name for alias in node.names
                           if alias.name in constructors)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    connects = [call for call in calls if isinstance(call.func, ast.Attribute)
                and call.func.attr == "connect"]
    if len(connects) != 1 or connects[0].keywords or [
            ast.dump(arg) for arg in connects[0].args] != [ast.dump(ast.Name("_PATH", ast.Load()))]:
        problems.append("connect is not exactly one connect(_PATH)")
    for call in calls:
        if ((isinstance(call.func, ast.Attribute) and call.func.attr in constructors)
                or (isinstance(call.func, ast.Name) and call.func.id in by_name)):
            families = [arg.attr if isinstance(arg, ast.Attribute)
                        else arg.id if isinstance(arg, ast.Name) else ast.dump(arg)
                        for arg in call.args]
            if families != ["AF_UNIX", "SOCK_STREAM"] or call.keywords:
                problems.append(f"socket{tuple(families)}")
    if not _bound_once_at_module_level(
            tree, "_PATH",
            lambda value: isinstance(value, ast.Name) and value.id == "DECOY_INTAKE_SOCKET"):
        problems.append("_PATH is not bound exactly once, to DECOY_INTAKE_SOCKET")
    if not _bound_once_at_module_level(
            tree, "DECOY_INTAKE_SOCKET",
            lambda value: isinstance(value, ast.Constant) and value.value == expected):
        problems.append("DECOY_INTAKE_SOCKET is not bound exactly once, to the "
                        "layout's decoy-intake socket")
    return problems


def _decoy_rule_offences(path: Path) -> list[str]:
    """The rule for every module of the decoy process but the sender."""

    return sorted(set(_attributes(path, LISTENER_FORBIDDEN))
                  | set(_names(path, DECOY_PROCESS_FORBIDDEN | _SENDER_PATH_NAMES))
                  | set(_family_violations(path)))


def _decoy_offenders(root: Path) -> dict[str, list[str]]:
    """The decoy process's modules, each under the rule that applies to it."""

    offenders: dict[str, list[str]] = {}
    closure = _decoy_closure(root)
    if closure != DECOY_PROCESS:
        offenders["closure"] = sorted(closure ^ DECOY_PROCESS)
    for name in sorted(closure):
        path = root / name
        if not path.is_file():
            continue
        if _exempt(path, {DECOY_SENDER}, root):
            found = _sender_violations(path) + _family_violations(path)
        else:
            found = _decoy_rule_offences(path)
        if found:
            offenders[name] = found
    return offenders


def test_the_decoy_process_initiates_nothing_but_its_one_line_to_the_intake():
    """The listener rule covers everything the decoy loads (§12).

    `decoy_listener.py` keeps its own, unchanged rule. The decoy's report to
    the intake (P2, §11) needs one `AF_UNIX` connect; that connect lives in
    `decoy_sender.py` alone, pinned to the fixed intake path.
    """

    from azazel_nexus_runtime import decoy_sender
    from azazel_nexus_runtime.runtime_paths import ROOT, socket_path

    if str(ROOT) == "/":
        assert str(socket_path("decoy-intake")) == DECOY_INTAKE_SOCKET
    assert decoy_sender.DECOY_INTAKE_SOCKET == DECOY_INTAKE_SOCKET
    assert _decoy_closure() == DECOY_PROCESS
    assert _decoy_offenders(RUNTIME) == {}
    assert DECOY_SENDER in DECOY_PROCESS
    assert DECOY_SENDER not in LISTENER_EXEMPT | EGRESS_EXEMPT


def _decoy_runtime(tmp_path: Path) -> Path:
    """A copy of the decoy process's real modules, for mutation."""

    root = tmp_path / "azazel_nexus_runtime"
    (root / "sub").mkdir(parents=True)
    for name in DECOY_PROCESS:
        (root / name).write_text((RUNTIME / name).read_text(encoding="utf-8"),
                                 encoding="utf-8")
    return root


#: Each mutation of a real module the decoy rules must catch:
#: (module, old text, new text). Every `old` occurs in the real file.
DECOY_MUTATIONS = [
    ("decoy_sender.py", "socket.AF_UNIX, socket.SOCK_STREAM",
     "socket.AF_INET, socket.SOCK_STREAM"),
    ("decoy_sender.py", "socket.AF_UNIX, socket.SOCK_STREAM",
     "socket.AF_INET6, socket.SOCK_STREAM"),
    ("decoy_sender.py", "socket.AF_UNIX, socket.SOCK_STREAM",
     "socket.AF_UNIX, socket.SOCK_DGRAM"),
    ("decoy_sender.py", "connection.connect(_PATH)",
     "connection.connect(('192.0.2.1', 80))"),
    ("decoy_sender.py", "connection.connect(_PATH)",
     "connection.connect('/run/other.sock')"),
    ("decoy_sender.py", "connection.connect(_PATH)",
     "connection.connect(_PATH)\n            connection.connect(_PATH)"),
    ("decoy_sender.py", "connection.connect(_PATH)",
     "connection.connect_ex(_PATH)"),
    ("decoy_sender.py", "connection.sendall(line)",
     "connection.sendto(line, _PATH)"),
    ("decoy_sender.py", "connection.sendall(line)",
     "connection.sendall(line)\n            connection.listen(1)"),
    ("decoy_sender.py", "_PATH = DECOY_INTAKE_SOCKET",
     "_PATH = __import__('os').environ.get('X', DECOY_INTAKE_SOCKET)"),
    ("decoy_sender.py", "_PATH = DECOY_INTAKE_SOCKET",
     "_PATH = DECOY_INTAKE_SOCKET\n_PATH = '/run/other.sock'"),
    ("decoy_sender.py", "    if type(interaction) is not DecoyInteraction:",
     "    global _PATH\n    if type(interaction) is not DecoyInteraction:"),
    ("decoy_sender.py",
     'DECOY_INTAKE_SOCKET = "/var/lib/azazel/run/decoy-intake/decoy-intake.sock"',
     'DECOY_INTAKE_SOCKET = "/var/lib/azazel/run/edge-intake/edge-intake.sock"'),
    ("decoy_sender.py", "import socket\n", "import socket\nimport ssl\n"),
    ("decoyd.py", "from . import decoy_listener, decoy_netns, decoy_sender",
     "from . import decoy_listener, decoy_netns, decoy_sender, artifact_egress"),
    ("decoyd.py", "sock, _ = listener.accept()",
     "sock, _ = listener.accept()\n            sock.connect(_)"),
    ("decoyd.py", "import selectors\n", "import selectors\nfrom os import environ\n"),
    ("decoy_netns.py", "status = os.stat(path)",
     "status = os.stat(os.environ.get('NS', path))"),
    ("decoy_loopback.py", "connection.sendall(entry.banner)",
     "connection.sendto(entry.banner, '/x')"),
    ("decoy_report.py", "from .decoy_loopback import",
     "from .edge_intaked import main\nfrom .decoy_loopback import"),
    ("decoy_listener.py", "        listener.listen(BACKLOG)\n    except BaseException:\n"
     "        listener.close()\n        raise\n    return listener\n",
     "        listener.listen(BACKLOG)\n        listener.connect(('192.0.2.1', 1))\n"
     "    except BaseException:\n        listener.close()\n        raise\n"
     "    return listener\n"),
]


def test_the_real_decoy_modules_pass_in_a_copy(tmp_path):
    assert _decoy_offenders(_decoy_runtime(tmp_path)) == {}


@pytest.mark.parametrize("module,old,new", DECOY_MUTATIONS,
                         ids=[f"{m}-{i}" for i, (m, _, _) in enumerate(DECOY_MUTATIONS)])
def test_each_mutation_of_the_decoy_process_is_caught(tmp_path, module, old, new):
    """The sender's exception is exactly as wide as intended, and no wider."""

    root = _decoy_runtime(tmp_path)
    path = root / module
    source = path.read_text(encoding="utf-8")
    assert old in source, f"stale mutation for {module}: {old!r}"
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
    assert _decoy_offenders(root), f"{module} mutated and nothing caught it"


_SENDER_CALL = "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection"
_SENDER_ENTRY = "    if type(interaction) is not DecoyInteraction:\n"
_SENDER_PATH = "_PATH = DECOY_INTAKE_SOCKET\n"
_OTHER = "'/run/other.sock'"

#: The mutations the independent review of #272 found the first rules
#: missed, and their neighbours: (name, module, [(old, new), ...]).
REVIEW_MUTATIONS = [
    ("default-argument", "decoy_sender.py", [(
        "def send_interaction(interaction: DecoyInteraction) -> bool:",
        f"def send_interaction(interaction: DecoyInteraction, _PATH={_OTHER}) -> bool:")]),
    ("tuple-assignment", "decoy_sender.py", [(
        _SENDER_PATH, f"{_SENDER_PATH}_PATH, _SPARE = {_OTHER}, 0\n")]),
    ("walrus", "decoy_sender.py", [(
        _SENDER_ENTRY, f"    if (_PATH := {_OTHER}):\n        pass\n{_SENDER_ENTRY}")]),
    ("for-target", "decoy_sender.py", [(
        _SENDER_ENTRY, f"    for _PATH in ({_OTHER},):\n        pass\n{_SENDER_ENTRY}")]),
    ("with-as", "decoy_sender.py", [(
        _SENDER_ENTRY, f"    with open({_OTHER}) as _PATH:\n        pass\n{_SENDER_ENTRY}")]),
    ("except-as", "decoy_sender.py", [(
        _SENDER_ENTRY,
        f"    try:\n        pass\n    except ValueError as _PATH:\n        pass\n{_SENDER_ENTRY}")]),
    ("import-as", "decoy_sender.py", [(
        "import socket\n", "import socket\nimport socket as _PATH\n")]),
    ("annotated", "decoy_sender.py", [(
        _SENDER_PATH, f"{_SENDER_PATH}_PATH: str = {_OTHER}\n")]),
    ("delete", "decoy_sender.py", [(_SENDER_PATH, f"{_SENDER_PATH}del _PATH\n")]),
    ("globals-subscript", "decoy_sender.py", [(
        _SENDER_PATH, f"{_SENDER_PATH}globals()['_PATH'] = {_OTHER}\n")]),
    ("vars-subscript", "decoy_sender.py", [(
        _SENDER_PATH, f"{_SENDER_PATH}vars()['_PATH'] = {_OTHER}\n")]),
    ("setattr", "decoy_sender.py", [(
        _SENDER_PATH, f"{_SENDER_PATH}setattr(send_interaction, '_PATH', {_OTHER})\n")]),
    ("constructor-by-name", "decoy_sender.py", [
        ("import socket\n", "import socket\nfrom socket import socket as S\n"),
        (_SENDER_CALL, "S(2, 1) as connection")]),
    ("constructor-by-name-one-family", "decoy_sender.py", [
        ("import socket\n", "import socket\nfrom socket import socket as S\n"),
        (_SENDER_CALL, "S(socket.AF_UNIX) as connection")]),
    ("constructor-keyword", "decoy_sender.py", [(
        _SENDER_CALL,
        "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, proto=0) as connection")]),
    ("getaddrinfo", "decoy_sender.py", [(
        "connection.sendall(line)",
        "connection.sendall(line)\n            socket.getaddrinfo('example.invalid', 80)")]),
    ("gethostbyname", "decoy_report.py", [(
        "from .decoy_loopback import", "from socket import gethostbyname\nfrom .decoy_loopback import")]),
    ("create-server", "decoyd.py", [(
        "import selectors\n", "import selectors\nfrom socket import create_server\n")]),
    ("decoyd-sets-the-path", "decoyd.py", [(
        "    server = DecoyServer(listeners)\n",
        f"    decoy_sender._PATH = {_OTHER}\n    server = DecoyServer(listeners)\n")]),
    ("netns-getattr", "decoy_netns.py", [(
        "    status = os.stat(path)\n", "    status = getattr(os, 'stat')(path)\n")]),
]


@pytest.mark.parametrize("module,edits", [(m, e) for _, m, e in REVIEW_MUTATIONS],
                         ids=[name for name, _, _ in REVIEW_MUTATIONS])
def test_each_mutation_the_review_found_is_caught(tmp_path, module, edits):
    """Every binding of the path, every constructor spelling, every resolver."""

    root = _decoy_runtime(tmp_path)
    path = root / module
    source = path.read_text(encoding="utf-8")
    for old, new in edits:
        assert old in source, f"stale mutation for {module}: {old!r}"
        source = source.replace(old, new, 1)
    path.write_text(source, encoding="utf-8")
    ast.parse(source)
    assert _decoy_offenders(root), f"{module} mutated and nothing caught it"


def test_a_same_named_sender_elsewhere_gets_no_exception(tmp_path):
    """The sender is matched by full path, as the other exemptions are."""

    root = _decoy_runtime(tmp_path)
    sub = root / "sub" / DECOY_SENDER
    sub.write_text((RUNTIME / DECOY_SENDER).read_text(encoding="utf-8"), encoding="utf-8")
    decoyd = root / "decoyd.py"
    decoyd.write_text(decoyd.read_text(encoding="utf-8").replace(
        "from . import decoy_listener, decoy_netns, decoy_sender",
        "from . import decoy_listener, decoy_netns\nfrom .sub import decoy_sender"),
        encoding="utf-8")
    assert not _exempt(sub, {DECOY_SENDER}, root)
    offenders = _decoy_offenders(root)
    assert "connect" in offenders["sub/decoy_sender.py"]


#: The process names #276 F4 added, each written as `os.<name>(...)`.
_F4_PROCESS_NAMES = (
    "execl", "execle", "execlp", "execlpe", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp",
    "spawnvpe", "forkpty", "posix_spawn", "posix_spawnp",
)
_NETNS_STAT = "    status = os.stat(path)\n"
_LOOPBACK_SOCKET = "server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)"
_ACCEPT = "sock, _ = listener.accept()"

#: The mutations the cross-PR review of #268-#274 (#276 F4) found passing,
#: and their neighbours: (name, module, [(old, new), ...], what must be found).
F4_MUTATIONS = [
    (f"os-{name}", "decoy_netns.py",
     [(_NETNS_STAT, f"    os.{name}('/bin/sh')\n{_NETNS_STAT}")], name)
    for name in _F4_PROCESS_NAMES
] + [
    ("execvp-imported", "decoyd.py",
     [("import selectors\n", "import selectors\nfrom os import execvp\n")], "execvp"),
    ("pty", "decoy_netns.py",
     [("import os\n", "import os\nimport pty\n")], "pty"),
    ("asyncio-process", "decoyd.py",
     [("import selectors\n", "import selectors\nfrom asyncio import create_subprocess_exec\n")],
     "create_subprocess_exec"),
    ("socket-2-1", "decoy_loopback.py",
     [(_LOOPBACK_SOCKET, "server = socket.socket(2, 1)")], "socket family 2"),
    ("socket-default-family", "decoy_loopback.py",
     [(_LOOPBACK_SOCKET, "server = socket.socket()")], "socket family defaulted (AF_INET)"),
    ("socket-family-keyword", "decoy_loopback.py",
     [(_LOOPBACK_SOCKET, "server = socket.socket(family=10)")], "socket family 10"),
    ("socket-family-arithmetic", "decoy_loopback.py",
     [(_LOOPBACK_SOCKET, "server = socket.socket(1 + 1, 1)")], "socket family 1 + 1"),
    ("socket-family-variable", "decoy_loopback.py",
     [(_LOOPBACK_SOCKET, "_f = 2\n        server = socket.socket(_f, socket.SOCK_STREAM)")],
     "socket family _f = [2]"),
    ("socket-family-call", "decoy_loopback.py",
     [(_LOOPBACK_SOCKET, "server = socket.socket(int('2'), 1)")], "socket family int('2')"),
    ("socket-address-family", "decoy_loopback.py",
     [(_LOOPBACK_SOCKET, "server = socket.socket(socket.AddressFamily(2), 1)")],
     "AddressFamily"),
    ("listener-numeric-family", "decoy_listener.py",
     [("_SOCKET(socket.AF_INET, socket.SOCK_STREAM)", "_SOCKET(10, socket.SOCK_STREAM)")],
     "socket family 10"),
    ("sender-numeric-family", "decoy_sender.py",
     [(_SENDER_CALL, "socket.socket(2, 1) as connection")], "socket family 2"),
    ("methodcaller-connect", "decoyd.py",
     [("import selectors\n", "import operator\nimport selectors\n"),
      (_ACCEPT, (f"{_ACCEPT}\n            operator.methodcaller('con' + 'nect', "
                 "('192.0.2.1', 80))(sock)"))], "methodcaller"),
    ("methodcaller-imported", "decoy_report.py",
     [("from .decoy_loopback import",
       "from operator import methodcaller\nfrom .decoy_loopback import")], "methodcaller"),
    ("attrgetter-connect", "decoyd.py",
     [("import selectors\n", "import operator\nimport selectors\n"),
      (_ACCEPT, (f"{_ACCEPT}\n            operator.attrgetter('con' + 'nect')(sock)"
                 "(('192.0.2.1', 80))"))], "attrgetter"),
]


@pytest.mark.parametrize("module,edits,expected", [(m, e, x) for _, m, e, x in F4_MUTATIONS],
                         ids=[name for name, _, _, _ in F4_MUTATIONS])
def test_each_mutation_the_cross_review_found_is_caught(tmp_path, module, edits, expected):
    """`execvp`, `spawnv`, `forkpty`, `socket.socket(2, 1)` and `methodcaller` (#276 F4)."""

    root = _decoy_runtime(tmp_path)
    path = root / module
    source = path.read_text(encoding="utf-8")
    for old, new in edits:
        assert source.count(old) == 1, f"stale mutation for {module}: {old!r}"
        source = source.replace(old, new, 1)
    path.write_text(source, encoding="utf-8")
    ast.parse(source)
    assert expected in _decoy_offenders(root).get(module, []), (
        f"{module} mutated ({expected}) and nothing caught it")


def test_the_family_scan_allows_only_named_constants_and_af_unix(tmp_path):
    module = tmp_path / "probe_family.py"
    module.write_text(
        "import socket\nfrom socket import socket as S\n_C = socket.socket\nf = 1\n"
        "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\nS(1, 1)\n_C(f)\n"
        "socket.socket(family=socket.AF_UNIX)\n", encoding="utf-8")
    assert _family_violations(module) == []
    module.write_text(
        "import socket\nfrom socket import socket as S\n_C = socket.socket\n"
        "S(2)\n_C(10, 1)\n", encoding="utf-8")
    assert sorted(_family_violations(module)) == ["socket family 10", "socket family 2"]


#: Everything `az-decoy-netd` loads from the runtime (#276 F4), by full
#: path. It is root; a new import is a diff a reviewer sees, never a module
#: that arrived through another one. The namespace unit loads nothing: it
#: runs `/usr/bin/ip` from its unit file and no Python (G4 follow-up).
#: #196 G2: `decoy_watch.py`, the verify unit's reads and judgement, runs in
#: the helper's executable (`az-decoy-netd verify`) and under the same rules:
#: no socket (it reads rules and routes through the fixed `ip -j` commands of
#: `decoy_network.WATCH_READS`), no process of its own, no environment.
#: #196 G6 preparation A: the watch's reads and judgements of reachability §6
#: moved to `decoy_reachability.py`, shared with the pass's judgement (not
#: wired), under the same rules.
NETD_PROCESS = {"decoy_netd.py", "decoy_isolation_check.py", "decoy_network.py",
                "decoy_addresses.py", "decoy_netns.py", "decoy_watch.py",
                "decoy_reachability.py"}

#: What no module of either helper may name: everything the decoy process
#: may not, but `posix_spawn` (pinned to `decoy_network.py` alone, below),
#: and no socket at all, internet or otherwise (they reach the kernel only
#: through the fixed `ip` and `nft` commands).
HELPER_FORBIDDEN = ((DECOY_PROCESS_FORBIDDEN - {"posix_spawn"})
                    | LISTENER_FORBIDDEN | INTERNET_FORBIDDEN | {"socket", "_socket"})


def _helper_offences(path: Path) -> list[str]:
    return sorted(set(_names(path, HELPER_FORBIDDEN)) | set(_family_violations(path)))


def _helper_offenders(root: Path) -> dict[str, list[str]]:
    offenders: dict[str, list[str]] = {}
    start = "decoy_netd.py"
    closure = _closure(start, root)
    if closure != NETD_PROCESS:
        offenders[f"{start} closure"] = sorted(closure ^ NETD_PROCESS)
    for name in sorted(closure):
        if (root / name).is_file() and _helper_offences(root / name):
            offenders[name] = _helper_offences(root / name)
    return offenders


def _helper_runtime(tmp_path: Path) -> Path:
    root = tmp_path / "azazel_nexus_runtime"
    root.mkdir(parents=True)
    for name in NETD_PROCESS:
        (root / name).write_text((RUNTIME / name).read_text(encoding="utf-8"),
                                 encoding="utf-8")
    return root


def test_the_decoy_helpers_import_exactly_their_pinned_runtime_modules():
    assert _closure("decoy_netd.py") == NETD_PROCESS
    assert not (RUNTIME / "decoy_nsd.py").exists()
    assert _helper_offenders(RUNTIME) == {}


HELPER_MUTATIONS = [
    ("netd-new-import", "decoy_netd.py",
     ("from .decoy_network import", "from .systemd_bus import connect\nfrom .decoy_network import"),
     "decoy_netd.py closure"),
    ("network-socket", "decoy_network.py",
     ("import os\n", "import os\nimport socket\n"), "decoy_network.py"),
    ("network-execvp", "decoy_network.py",
     ("import os\n", "import os\nfrom os import execvp\n"), "decoy_network.py"),
    ("check-environ", "decoy_isolation_check.py",
     ("import os\n", "import os\nfrom os import environ\n"), "decoy_isolation_check.py"),
    # #196 G2: the watch may not open a netlink socket of its own, nor start
    # a process, nor read the environment.
    ("watch-socket", "decoy_watch.py",
     ("import sys\n", "import sys\nimport socket\n"), "decoy_watch.py"),
    ("watch-fork", "decoy_watch.py",
     ("import sys\n", "import sys\nfrom os import fork\n"), "decoy_watch.py"),
    ("watch-environ", "decoy_watch.py",
     ("import sys\n", "import sys\nfrom os import environ\n"), "decoy_watch.py"),
    ("watch-new-import", "decoy_watch.py",
     ("from .decoy_isolation_check import",
      "from .systemd_bus import connect\nfrom .decoy_isolation_check import"),
     "decoy_netd.py closure"),
    # #196 G6 preparation A: the shared reachability reads, likewise.
    ("reachability-socket", "decoy_reachability.py",
     ("import os\n", "import os\nimport socket\n"), "decoy_reachability.py"),
    ("reachability-fork", "decoy_reachability.py",
     ("import os\n", "import os\nfrom os import fork\n"), "decoy_reachability.py"),
    ("reachability-environ", "decoy_reachability.py",
     ("import os\n", "import os\nfrom os import environ\n"), "decoy_reachability.py"),
    ("reachability-new-import", "decoy_reachability.py",
     ("from .decoy_addresses import",
      "from .systemd_bus import connect\nfrom .decoy_addresses import"),
     "decoy_netd.py closure"),
    ("netns-methodcaller", "decoy_netns.py",
     ("import os\n", "import os\nfrom operator import methodcaller\n"), "decoy_netns.py"),
]


@pytest.mark.parametrize("module,edit,key", [(m, e, k) for _, m, e, k in HELPER_MUTATIONS],
                         ids=[name for name, _, _, _ in HELPER_MUTATIONS])
def test_each_mutation_of_a_decoy_helper_is_caught(tmp_path, module, edit, key):
    root = _helper_runtime(tmp_path)
    assert _helper_offenders(root) == {}
    path = root / module
    source = path.read_text(encoding="utf-8")
    old, new = edit
    assert source.count(old) == 1, f"stale mutation for {module}: {old!r}"
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
    assert key in _helper_offenders(root), f"{module} mutated and nothing caught it"


#: What each decoy executable loads from either distribution (#276 F3), as
#: `sys.modules` names after importing its module in a fresh `python -I`.
#: Before #276 the decoy and the helper loaded about forty library modules,
#: through `edge_package`'s boot id reader; the reader is now the leaf
#: `boot_id`. A library module added to a closure is a diff here.
DECOY_IMPORT_CLOSURES = {
    "decoyd": {
        "azazel_nexus", "azazel_nexus.boot_id", "azazel_nexus.content_store",
        "azazel_nexus.decoy", "azazel_nexus.decoy_interaction",
        "azazel_nexus.decoy_isolation",
        "azazel_nexus_runtime", "azazel_nexus_runtime.decoy_listener",
        "azazel_nexus_runtime.decoy_loopback", "azazel_nexus_runtime.decoy_netns",
        "azazel_nexus_runtime.decoy_report", "azazel_nexus_runtime.decoy_sender",
        "azazel_nexus_runtime.decoyd",
    },
    # #196 G1b: the helper reads its one input, the scope file, with the
    # standard-library leaf `decoy_scope`; one module more, and only here
    # (the namespace unit and the decoy do not load it).
    # #196 G2: and the watch (`az-decoy-netd verify`), a runtime module that
    # brings no library module with it.
    "decoy_netd": {
        "azazel_nexus", "azazel_nexus.boot_id", "azazel_nexus.decoy_isolation",
        "azazel_nexus.decoy_scope",
        "azazel_nexus_runtime", "azazel_nexus_runtime.decoy_addresses",
        "azazel_nexus_runtime.decoy_isolation_check", "azazel_nexus_runtime.decoy_netd",
        "azazel_nexus_runtime.decoy_netns", "azazel_nexus_runtime.decoy_network",
        "azazel_nexus_runtime.decoy_watch",
        # #196 G6 preparation A: the watch's reachability reads, moved.
        "azazel_nexus_runtime.decoy_reachability",
    },
}


def _loaded(module: str) -> set[str]:
    """`azazel*` modules loaded by importing `azazel_nexus_runtime.<module>`, in isolation."""

    paths = [str(REPO_ROOT / "src"), str(REPO_ROOT / "runtime" / "src")]
    code = (f"import sys; sys.path[:0] = {paths!r}; import azazel_nexus_runtime.{module}; "
            "print(sorted(m for m in sys.modules if m.startswith('azazel')))")
    result = subprocess.run([sys.executable, "-I", "-B", "-c", code],
                            capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr
    return set(ast.literal_eval(result.stdout.strip()))


def _module_file(name: str) -> Path:
    package, _, leaf = name.partition(".")
    assert "." not in leaf, name
    base = {"azazel_nexus": LIBRARY, "azazel_nexus_runtime": RUNTIME}[package]
    return base / (f"{leaf}.py" if leaf else "__init__.py")


@pytest.mark.parametrize("module", sorted(DECOY_IMPORT_CLOSURES))
def test_each_decoy_executable_loads_exactly_its_pinned_modules(module):
    assert _loaded(module) == DECOY_IMPORT_CLOSURES[module]


def test_the_pinned_closures_agree_with_the_runtime_scans():
    """The runtime half of each closure is the set the AST rules cover."""

    for module, pinned in (("decoyd", DECOY_PROCESS), ("decoy_netd", NETD_PROCESS)):
        runtime = {name.split(".", 1)[1] + ".py"
                   for name in DECOY_IMPORT_CLOSURES[module]
                   if name.startswith("azazel_nexus_runtime.")}
        assert runtime == pinned, module
    for names in DECOY_IMPORT_CLOSURES.values():
        assert all(_module_file(name).is_file() for name in names)
        assert "azazel_nexus.edge_package" not in names


def test_the_library_modules_the_decoy_and_its_helpers_load_obey_their_rules():
    """The decoy's rules reach the library modules it loads, not only its own (§12)."""

    for module, rule in (("decoyd", _decoy_rule_offences), ("decoy_netd", _helper_offences)):
        for name in sorted(DECOY_IMPORT_CLOSURES[module]):
            # The runtime's own modules are scanned with their copies above;
            # its package `__init__` and the library's modules are checked here.
            if name == "azazel_nexus_runtime" or not name.startswith("azazel_nexus_runtime."):
                assert rule(_module_file(name)) == [], (module, name)


def test_the_boot_id_reader_is_a_leaf_that_edge_package_shares():
    """One reader and one validator (#276 F3), importing nothing from either package."""

    from azazel_nexus import boot_id, edge_package

    tree = ast.parse((LIBRARY / "boot_id.py").read_text(encoding="utf-8"))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, ast.Import) for alias in node.names}
    imported |= {("." * node.level) + (node.module or "") for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom)}
    assert imported == {"__future__", "os", "stat", "pathlib"}
    assert edge_package.is_boot_id is boot_id.is_boot_id
    assert edge_package.BOOT_ID_PATH is boot_id.BOOT_ID_PATH
    source = (LIBRARY / "edge_package.py").read_text(encoding="utf-8")
    assert "_BOOT_ID_MAX_BYTES" not in source and "def is_boot_id" not in source


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
    # The Deception Lite exposure units (#196 P1, #196 (a)). Their bodies
    # are implemented (§12, §13); the units are never granted in this build.
    # The namespace unit has none: it runs /usr/bin/ip (G4 follow-up).
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
# az-nexus-noc prints a read-only, passive network observation for an
# operator (docs/noc-observation.md); it opens only an AF_NETLINK socket and
# no node runs it by itself.
OPERATOR_TOOLS = (
    "az-core-reserve-probe", "az-nexus-commission", "az-nexus-bootstrap",
    "az-hil-readiness", "az-hil-capture", "az-nexus-model-admission",
    "az-activation", "az-nexus-noc",
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


#: Governed units whose executable Nexus does not stage: Edge Core's own
#: package binary, and the system's iproute2 `ip`, which the decoy namespace
#: unit runs from its unit file with no Python body (#196 G4 follow-up).
NOT_STAGED_UNITS = frozenset({"azazel-edge-core.service", "azazel-decoy-nsd.service"})


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
        if unit not in NOT_STAGED_UNITS and _script_for(unit) not in declared
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
                        if unit not in NOT_STAGED_UNITS} | {"az-mio-identity"}, (
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


#: The one module that starts a process with `posix_spawn` (#196 §13): the
#: decoy network's fixed `ip` and `nft` commands, refused for any argument
#: list that is not one of its constants. Matched by full path, like the
#: socket exemptions.
SPAWN_EXEMPT = {"decoy_network.py"}


def _names_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    names |= {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    names |= {alias.name for node in ast.walk(tree)
              if isinstance(node, ast.ImportFrom) for alias in node.names}
    return names


def test_only_the_decoy_network_module_names_posix_spawn():
    spawning = {"posix_spawn", "posix_spawnp"}
    offenders = sorted(
        str(path.relative_to(REPO_ROOT))
        for root in (RUNTIME, LIBRARY)
        for path in root.rglob("*.py")
        if _names_in(path) & spawning and not _exempt(path, SPAWN_EXEMPT)
    )
    assert offenders == []
    assert _names_in(RUNTIME / "decoy_network.py") & spawning == {"posix_spawn"}


def test_the_decoy_network_module_is_scanned_like_every_other_runtime_module():
    """No socket exemption: it names no internet family, opens no socket."""

    path = RUNTIME / "decoy_network.py"
    assert not _exempt(path, EGRESS_EXEMPT) and not _exempt(path, LISTENER_EXEMPT)
    assert not _names_in(path) & (INTERNET_FORBIDDEN | {"socket", "subprocess"})
    # Only the helper imports it, and the helper's watch (#196 G2,
    # `az-decoy-netd verify`), which runs in the helper's executable. The
    # namespace unit runs no Python (G4 follow-up).
    importers = sorted(
        source.name for source in RUNTIME.rglob("*.py")
        if any(isinstance(node, ast.ImportFrom) and node.module
               and node.module.split(".")[-1] == "decoy_network"
               for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))))
    )
    assert importers == ["decoy_netd.py", "decoy_watch.py"]
