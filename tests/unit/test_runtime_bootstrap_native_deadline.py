"""Linux-only native checks isolate every fatal timer in a disposable child.

No service, media, loop device or test-runner process is a signal target.
Missing or unrelated compiled backends are an explicit skip, not native success.
"""

import importlib.machinery
from pathlib import Path
import subprocess
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPO_ROOT / "runtime" / "src"
PACKAGE_DIR = SOURCE_ROOT / "azazel_nexus_runtime"
PACKAGE_ORIGIN = PACKAGE_DIR / "__init__.py"
_spec = importlib.machinery.PathFinder.find_spec(
    "azazel_nexus_runtime._bootstrap_deadline", [str(PACKAGE_DIR)],
)
EXPECTED_EXTENSION = (
    Path(_spec.origin).resolve()
    if _spec is not None and isinstance(_spec.loader, importlib.machinery.ExtensionFileLoader)
    else None
)
AVAILABLE = (
    sys.platform == "linux"
    and EXPECTED_EXTENSION is not None
    and EXPECTED_EXTENSION.parent == PACKAGE_DIR.resolve()
    and any(
        EXPECTED_EXTENSION.name.endswith(suffix)
        for suffix in importlib.machinery.EXTENSION_SUFFIXES
    )
)
pytestmark = pytest.mark.skipif(
    not AVAILABLE,
    reason="compiled deadline backend unavailable in the expected source package",
)


def _child_source(body):
    assert EXPECTED_EXTENSION is not None
    prefix = (
        "import importlib.machinery,sys\n"
        f"sys.path.insert(0,{str(SOURCE_ROOT)!r})\n"
        "import azazel_nexus_runtime as package\n"
        "from azazel_nexus_runtime import _bootstrap_deadline as native\n"
        f"assert package.__spec__.origin == {str(PACKAGE_ORIGIN)!r}\n"
        "assert type(native.__loader__) is importlib.machinery.ExtensionFileLoader\n"
        f"assert native.__spec__.origin == {str(EXPECTED_EXTENSION)!r}\n"
    )
    return prefix + body


def _run(source, *, timeout):
    return subprocess.run(
        [sys.executable, "-IS", "-c", _child_source(source)],
        timeout=timeout,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize("drop_handle", [False, True])
def test_absolute_boottime_timer_kills_only_its_isolated_child(drop_handle):
    source = (
        "import gc,time\n"
        "h=native.arm(time.clock_gettime_ns(time.CLOCK_BOOTTIME)+200_000_000)\n"
        "native.check(h)\n"
        "print('CHECKED',flush=True)\n"
        + ("del h\n" if drop_handle else "")
        + "gc.collect()\n"
        + ("print('DROPPED_AND_COLLECTED',flush=True)\n" if drop_handle
           else "print('COLLECTED',flush=True)\n")
        + "time.sleep(5)\n"
    )
    result = _run(source, timeout=8)
    assert result.returncode == -9, (result.stdout, result.stderr)
    after_gc = "DROPPED_AND_COLLECTED" if drop_handle else "COLLECTED"
    expected_markers = ["CHECKED", after_gc]
    assert result.stdout.splitlines() == expected_markers


def test_invalid_arm_inputs_do_not_consume_process_deadline_and_release_is_final():
    source = (
        "import time\n"
        "now=time.clock_gettime_ns(time.CLOCK_BOOTTIME)\n"
        "for invalid,error in ((True,TypeError),(1.5,TypeError),(1<<100,OverflowError),(now-1,RuntimeError)):\n"
        "    try: native.arm(invalid)\n"
        "    except error: pass\n"
        "    else: raise AssertionError('invalid deadline accepted')\n"
        "h=native.arm(time.clock_gettime_ns(time.CLOCK_BOOTTIME)+5_000_000_000)\n"
        "native.check(h)\n"
        "try: native.arm(time.clock_gettime_ns(time.CLOCK_BOOTTIME)+6_000_000_000)\n"
        "except RuntimeError: pass\n"
        "else: raise AssertionError('active timer was rearmed')\n"
        "native.check(h)\n"
        "native.release(h); native.release(h)\n"
        "for operation in (lambda: native.check(h), lambda: native.arm(time.clock_gettime_ns(time.CLOCK_BOOTTIME)+1_000_000_000)):\n"
        "    try: operation()\n"
        "    except RuntimeError: pass\n"
        "    else: raise AssertionError('released or consumed deadline reused')\n"
        "print('VALIDATION_COMPLETE',flush=True)\n"
    )
    result = _run(source, timeout=5)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.splitlines() == ["VALIDATION_COMPLETE"]


def test_explicit_release_survives_original_deadline_and_cannot_be_renewed():
    source = (
        "import time\n"
        "h=native.arm(time.clock_gettime_ns(time.CLOCK_BOOTTIME)+2_000_000_000)\n"
        "native.check(h); native.release(h)\n"
        "time.sleep(2.1)\n"
        "try: native.arm(time.clock_gettime_ns(time.CLOCK_BOOTTIME)+1_000_000_000)\n"
        "except RuntimeError: pass\n"
        "else: raise AssertionError('timer renewed after release')\n"
        "print('RELEASE_SURVIVED_DEADLINE',flush=True)\n"
    )
    result = _run(source, timeout=5)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.splitlines() == ["RELEASE_SURVIVED_DEADLINE"]


def test_forked_child_cannot_release_parent_timer_and_has_bounded_lifetime():
    source = (
        "import os,signal,time\n"
        "h=native.arm(time.clock_gettime_ns(time.CLOCK_BOOTTIME)+4_000_000_000)\n"
        "pid=os.fork()\n"
        "if pid == 0:\n"
        "    signal.signal(signal.SIGALRM,signal.SIG_DFL)\n"
        "    signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGALRM})\n"
        "    signal.alarm(2)\n"
        "    try: native.release(h)\n"
        "    except RuntimeError: os._exit(0)\n"
        "    os._exit(1)\n"
        "_,status=os.waitpid(pid,0)\n"
        "native.check(h); native.release(h)\n"
        "assert os.waitstatus_to_exitcode(status)==0\n"
        "print('FORK_CHECK_COMPLETE',flush=True)\n"
    )
    result = _run(source, timeout=6)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.splitlines() == ["FORK_CHECK_COMPLETE"]
