"""The six things acquisition may never do, each scanned for by name (#105).

The design names six prohibitions. Four of them were already enforced by
other checks — the argument type system has no free-text kind, the import
scans refuse `subprocess`, the catalog cannot spell a location, and
`plan_acquisition` has no parameter a location could arrive through.

**Two were not scanned for at all**: silent retry and background
auto-download. The properties held, and nothing said so — which is the shape
that outlives the person who arranged it. The issue singled those two out
precisely because they are the ones built for convenience and missed when
something goes wrong.

Everything here is a scan over the acquisition path's syntax trees. A scan
rather than a behavioural test because these are absences: a test can only
show that the thing did not happen on the path it drove, and an absence has
to hold on every path.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "runtime" / "src"))

from azazel_nexus import model_acquisition, model_catalog, source_registry  # noqa: E402
from azazel_nexus_runtime import (  # noqa: E402
    artifact_egress,
    model_fetch,
    model_fetchd,
)

#: Every module on the path from "a catalog names a model" to "bytes land in
#: staging". A prohibition that held in four of five modules would be a
#: prohibition with one way round it.
ACQUISITION_PATH = (
    model_acquisition,
    model_catalog,
    source_registry,
    model_fetch,
    model_fetchd,
    artifact_egress,
)

#: The names that actually move bytes. A loop around one of these is a retry
#: the caller did not ask for.
TRANSFER_CALLS = {
    "fetch_artifact",
    "drive_fetch",
    "_transfer",
    "transfer",
    "sendall",
    "recv",
}


def tree_of(module) -> ast.Module:
    return ast.parse(pathlib.Path(module.__file__).read_text(encoding="utf-8"))


def imports_of(module) -> set:
    roots = set()
    for node in ast.walk(tree_of(module)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def ids(modules):
    return [module.__name__.rsplit(".", 1)[-1] for module in modules]


# -- 1. no arbitrary URL ---------------------------------------------------


@pytest.mark.parametrize("module", ACQUISITION_PATH, ids=ids(ACQUISITION_PATH))
def test_no_module_builds_a_url(module) -> None:
    """Not "refuses a bad URL" -- has no way to express one.

    A scheme literal anywhere on this path would be a place a location could
    be assembled, and assembly is how an allowlist gets bypassed without
    anybody writing `http://` in a config.
    """

    source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
    body = source.split('"""', 2)[2] if source.startswith('"""') else source
    for scheme in ("http://", "https://", "ftp://", "file://", "://"):
        assert scheme not in body, f"{module.__name__} spells {scheme!r}"


def test_the_request_type_system_has_no_free_text_kind() -> None:
    """The reason a URL cannot arrive over the socket."""

    from azazel_nexus_runtime.protocol import ArgumentKind

    names = {kind.name for kind in ArgumentKind}
    assert names & {"STRING", "TEXT", "FREE_TEXT", "URL", "PATH", "RAW"} == set()


# -- 2. no shell command ---------------------------------------------------


#: Names that mean "run something" wherever they appear, whatever the
#: receiver is spelled. `compile` is deliberately absent: `re.compile` is a
#: pattern, not a command, and a scan that confused the two would have to be
#: silenced by whoever next wrote a regular expression -- which is how a scan
#: stops being enforced.
EXECUTION_ATTRIBUTES = {
    "system", "popen", "execv", "execve", "execvp", "execl", "execlp",
    "spawnv", "spawnve", "spawnl", "fork", "forkpty", "posix_spawn",
    "check_output", "check_call", "Popen",
}

#: Bare calls. `compile` and `exec` belong here and only here: unqualified,
#: they are the builtins, and the builtins turn text into code.
EXECUTION_BUILTINS = {"eval", "exec", "compile", "system", "popen"}


def dotted(call: ast.Call) -> str:
    """`re.compile` as `"re.compile"`, so a scan can tell it from `compile`."""

    parts = []
    node = call.func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


@pytest.mark.parametrize("module", ACQUISITION_PATH, ids=ids(ACQUISITION_PATH))
def test_no_module_can_run_a_command(module) -> None:
    assert imports_of(module) & {
        "subprocess", "os_exec", "pty", "shlex", "commands", "popen2",
    } == set()
    offenders = []
    for node in ast.walk(tree_of(module)):
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node)
        if not name:
            continue
        tail = name.rsplit(".", 1)[-1]
        if "." in name:
            if tail in EXECUTION_ATTRIBUTES or name in {
                "builtins.eval", "builtins.exec", "builtins.compile",
            }:
                offenders.append(f"line {node.lineno}: {name}")
        elif tail in EXECUTION_BUILTINS:
            offenders.append(f"line {node.lineno}: {name}")
    assert offenders == [], f"{module.__name__} runs a command: {offenders}"


# -- 3. no endpoint inside the catalog ------------------------------------


def test_a_catalog_entry_carries_no_location_field() -> None:
    fields = set(model_catalog.ModelEntry.__dataclass_fields__)
    assert fields & {
        "host", "port", "url", "endpoint", "path", "scheme", "address", "uri",
    } == set()


def test_a_catalog_source_is_a_symbol_the_registry_resolves() -> None:
    """The catalog names; the registry locates. Neither does both."""

    registry_fields = set(source_registry.SourceRecord.__dataclass_fields__)
    assert {"host", "port", "path_template"} <= registry_fields
    assert registry_fields & {"model_id", "digest", "size_bytes"} == set()


# -- 4. no operator-supplied URL ------------------------------------------


def test_no_entry_point_takes_a_location_from_its_caller() -> None:
    for function in (
        model_acquisition.plan_acquisition,
        source_registry.resolve_candidate,
        model_fetch.endpoint_for,
    ):
        parameters = set(inspect.signature(function).parameters)
        for forbidden in ("url", "host", "port", "endpoint", "address", "proxy"):
            assert not any(forbidden in name for name in parameters), (
                f"{function.__name__} takes {forbidden!r} from its caller"
            )


def test_the_service_verb_takes_only_symbols() -> None:
    from azazel_nexus_runtime.protocol import ArgumentKind

    kinds = {argument.kind for argument in model_fetchd.FETCH_VERB.arguments}
    assert kinds <= {
        ArgumentKind.IDENTIFIER, ArgumentKind.DIGEST, ArgumentKind.ORDINAL
    }


# -- 5. no silent retry ----------------------------------------------------


@pytest.mark.parametrize("module", ACQUISITION_PATH, ids=ids(ACQUISITION_PATH))
def test_nothing_loops_around_a_transfer(module) -> None:
    """A retry the caller did not ask for is a failure that looks like none.

    `fetch_artifact` is one attempt. The attempt budget is an **input**, and
    it is the caller who spends it -- so a failure surfaces to whoever
    decided to try, every time, instead of being absorbed three times over
    and reported once as something slower than usual.

    The bytes of one transfer are of course read in a loop. What must not
    exist is a loop that starts a transfer again.
    """

    starting = TRANSFER_CALLS - {"sendall", "recv"}
    for node in ast.walk(tree_of(module)):
        if not isinstance(node, (ast.For, ast.While, ast.AsyncFor)):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            name = (
                inner.func.attr
                if isinstance(inner.func, ast.Attribute)
                else getattr(inner.func, "id", "")
            )
            assert name not in starting, (
                f"{module.__name__} line {inner.lineno}: {name} is called "
                "inside a loop. A retry the caller did not ask for is a "
                "failure nobody sees"
            )


def test_the_attempt_budget_is_spent_by_the_caller_not_the_fetcher() -> None:
    """`attempts_used` comes in; `attempts_remaining` goes out. Nothing here
    decrements it on its own, because nothing here tries again on its own."""

    parameters = inspect.signature(model_acquisition.plan_acquisition).parameters
    assert "attempts_used" in parameters
    assert parameters["attempts_used"].default == 0
    plan = model_acquisition.AcquisitionPlan(
        model_id="m",
        source_id=model_acquisition.KNOWN_SOURCES[0],
        expected_digest="sha256:" + "0" * 64,
        expected_size_bytes=1,
        resume_from=0,
    )
    assert plan.attempts_remaining == model_acquisition.MAX_ATTEMPTS
    assert model_acquisition.MAX_ATTEMPTS < 10, "a budget this large is not one"


def test_a_refusal_is_returned_rather_than_retried() -> None:
    """Every refusal on this path raises or returns. None of them re-enters
    the thing that just failed."""

    for module in (model_acquisition, source_registry):
        for node in ast.walk(tree_of(module)):
            if not isinstance(node, (ast.ExceptHandler,)):
                continue
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    name = (
                        inner.func.attr
                        if isinstance(inner.func, ast.Attribute)
                        else getattr(inner.func, "id", "")
                    )
                    assert name not in TRANSFER_CALLS, (
                        f"{module.__name__} retries inside an except handler"
                    )


# -- 6. no background auto-download ---------------------------------------


@pytest.mark.parametrize("module", ACQUISITION_PATH, ids=ids(ACQUISITION_PATH))
def test_nothing_can_start_a_transfer_on_its_own(module) -> None:
    """No thread, no timer, no scheduler, no exit hook.

    A download an operator did not ask for is communication they did not
    consent to, and the whole confirmation structure above it is decoration
    if something can start one unattended.
    """

    assert imports_of(module) & {
        "threading", "asyncio", "sched", "signal", "atexit", "multiprocessing",
        "concurrent", "selectors", "timeit",
    } == set(), sorted(imports_of(module))
    called = {
        node.func.attr if isinstance(node.func, ast.Attribute) else
        getattr(node.func, "id", "")
        for node in ast.walk(tree_of(module))
        if isinstance(node, ast.Call)
    }
    assert called & {
        "Thread", "Timer", "start_new_thread", "register", "create_task",
        "run_in_executor", "fork",
    } == set()


@pytest.mark.parametrize("module", ACQUISITION_PATH, ids=ids(ACQUISITION_PATH))
def test_importing_a_module_transfers_nothing(module) -> None:
    """Module level runs on import, which is the one moment nobody chose."""

    for node in tree_of(module).body:
        if isinstance(node, (ast.Expr, ast.Assign, ast.AnnAssign)):
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    name = (
                        inner.func.attr
                        if isinstance(inner.func, ast.Attribute)
                        else getattr(inner.func, "id", "")
                    )
                    assert name not in TRANSFER_CALLS, (
                        f"{module.__name__} moves bytes at import time"
                    )


def test_the_service_refuses_to_start_unattended() -> None:
    """And the daemon that would host one does not run at all in this build."""

    with pytest.raises(SystemExit) as caught:
        model_fetchd.main([])
    assert "no transport wired" in str(caught.value)


def test_the_shipped_registry_offers_nothing_to_download_unattended() -> None:
    """Even if something did start, there is nowhere to start towards."""

    assert model_fetch.ENDPOINT_FOR == {}


# -- the scan is not vacuous ----------------------------------------------


def test_the_scans_would_notice() -> None:
    """Each scan run against source that violates it, so a pass means it
    looked. A scan that cannot fail is a scan nobody should trust."""

    loop_around_transfer = ast.parse(
        "def go():\n    for _ in range(3):\n        fetch_artifact(x=1)\n"
    )
    found = [
        inner
        for node in ast.walk(loop_around_transfer)
        if isinstance(node, (ast.For, ast.While))
        for inner in ast.walk(node)
        if isinstance(inner, ast.Call)
        and getattr(inner.func, "id", "") in TRANSFER_CALLS
    ]
    assert found, "the silent-retry scan would not have noticed a retry loop"

    def execution_offenders(source: str) -> list:
        found = []
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            name = dotted(node)
            if not name:
                continue
            tail = name.rsplit(".", 1)[-1]
            if "." in name:
                if tail in EXECUTION_ATTRIBUTES:
                    found.append(name)
            elif tail in EXECUTION_BUILTINS:
                found.append(name)
        return found

    assert execution_offenders("import os\nos.system('true')\n") == ["os.system"]
    assert execution_offenders("eval('1')\n") == ["eval"]
    assert execution_offenders("compile('1', '<s>', 'eval')\n") == ["compile"]

    # The relaxation that lets `re.compile` through is itself a thing the next
    # change could widen into nothing. It has to be a named property, or the
    # scan is one careless edit from forbidding only what nobody writes.
    assert execution_offenders("import re\nre.compile('x')\n") == []

    threaded = ast.parse("import threading\nthreading.Thread(target=go).start()\n")
    roots = {
        alias.name.split(".")[0]
        for node in ast.walk(threaded)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert "threading" in roots, "the background scan would not have noticed a thread"


@pytest.mark.parametrize("module", ACQUISITION_PATH, ids=ids(ACQUISITION_PATH))
def test_no_acquisition_module_reaches_the_decoy_network_runner(module) -> None:
    """`decoy_network` is the one module that spawns (#196 §13); nothing on
    the acquisition path may import it or its executables."""

    names = set()
    for node in ast.walk(tree_of(module)):
        if isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[-1])
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            names.update(alias.name.split(".")[-1] for alias in node.names)
    assert not names & {"decoy_network", "decoy_nsd", "decoy_netd"}
