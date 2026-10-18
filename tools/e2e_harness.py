"""The integration harness's shared types (Nexus#43).

Separated from `e2e.py` so that the stages and the runner hold the *same*
class objects. When both lived in one file the runner imported it as
`__main__` and the stages imported it again as `e2e`, which made two
`NotExecuted` classes -- and the runner's `except NotExecuted` did not catch
the stages'. Every skipped stage was reported as a failure.

A duplicated module is two modules. The harness found it on its first run,
which is the sort of thing an integration harness is for.
"""

from __future__ import annotations

import json
import grp
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import os

ROOT = Path(__file__).resolve().parents[1]

STAGE_DEADLINE_SECONDS = 30.0

#: How long to wait for a daemon's socket to appear before calling it failed.
STARTUP_DEADLINE_SECONDS = 10.0

EXECUTED = "executed"
NOT_EXECUTED = "not_executed"
FAILED = "failed"


@dataclass
class StageResult:
    name: str
    status: str
    detail: str = ""
    seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.status not in (EXECUTED, NOT_EXECUTED, FAILED):
            raise ValueError(f"{self.status!r} is not a stage status")
        if self.status is not EXECUTED and not self.detail.strip():
            raise ValueError(
                f"stage {self.name!r} is {self.status} and says nothing about "
                "why; an unexplained skip reads as a pass"
            )


@dataclass
class Report:
    stages: list[StageResult] = field(default_factory=list)

    def summary(self) -> dict:
        """Counted so that `not_executed` can never be mistaken for a pass."""

        return {
            "passed": sum(1 for s in self.stages if s.status == EXECUTED),
            "not_executed": sum(1 for s in self.stages if s.status == NOT_EXECUTED),
            "failed": sum(1 for s in self.stages if s.status == FAILED),
            "total": len(self.stages),
        }

    def ok(self, *, require_all: bool = False) -> bool:
        counts = self.summary()
        if counts["failed"]:
            return False
        return not (require_all and counts["not_executed"])

    def render(self) -> str:
        lines = ["# Azazel-Nexus integration report", ""]
        for stage in self.stages:
            mark = {EXECUTED: "ok", NOT_EXECUTED: "NOT RUN", FAILED: "FAILED"}[
                stage.status
            ]
            lines.append(f"{mark:8} {stage.name}  ({stage.seconds:.2f}s)")
            if stage.detail:
                lines.append(f"         {stage.detail}")
        counts = self.summary()
        lines += [
            "",
            f"passed {counts['passed']}, not executed {counts['not_executed']}, "
            f"failed {counts['failed']}, of {counts['total']}",
            "",
            "A stage that was not executed is not a stage that passed. This "
            "harness establishes that the distribution is internally "
            "consistent; it establishes nothing about real hardware, and "
            "nothing about what systemd enforces.",
        ]
        return "\n".join(lines)


#: The longest root that still leaves the declared socket paths bindable.
#:
#: `/var/lib/azazel/run/knowledge-read/knowledge-read.sock` is 54 bytes and a unix address holds
#: 107, so a root beyond this pushes the daemons over -- which the kernel
#: reports as `AF_UNIX path too long` from inside a subprocess, where it is a
#: puzzle. Refused here instead, with the arithmetic in the message.
LONGEST_DECLARED_SOCKET = len("/var/lib/azazel/run/knowledge-read/knowledge-read.sock")
MAX_ROOT_BYTES = 107 - LONGEST_DECLARED_SOCKET


class Harness:
    def __init__(self, root: Path) -> None:
        encoded = str(root).encode("utf-8")
        if len(encoded) > MAX_ROOT_BYTES:
            raise ValueError(
                f"--root is {len(encoded)} bytes and must be at most "
                f"{MAX_ROOT_BYTES}: a unix socket address holds 107 and the "
                f"longest declared socket path is {LONGEST_DECLARED_SOCKET}. "
                "Choose a shorter root"
            )
        self.root = root
        self.report = Report()
        self.env = {
            **os.environ,
            "AZAZEL_ROOT": str(root),
            "PYTHONPATH": f"{ROOT / 'src'}:{ROOT / 'runtime' / 'src'}",
        }

    def executed(self, name: str) -> bool:
        return any(
            stage.name == name and stage.status == EXECUTED for stage in self.report.stages
        )

    def stage(
        self,
        name: str,
        run: Callable[[], Optional[str]],
        *,
        requires: tuple[str, ...] = (),
    ) -> None:
        """Run a stage, unless something it needs did not run.

        A stage blocked by a skipped prerequisite is `not_executed`, not
        `failed`: nothing about the product went wrong, and reporting it as a
        failure would bury the one skip that explains all of them.

        The dependency is named in the reason, so a reader can tell a stage
        that was blocked from one that decided for itself it could not run.
        """

        missing = [required for required in requires if not self.executed(required)]
        if missing:
            self.report.stages.append(
                StageResult(
                    name,
                    NOT_EXECUTED,
                    f"depends on {missing[0]!r}, which was not executed",
                )
            )
            return
        started = time.monotonic()
        try:
            detail = run()
        except NotExecuted as skipped:
            self.report.stages.append(
                StageResult(name, NOT_EXECUTED, str(skipped), time.monotonic() - started)
            )
            return
        except Exception as failure:  # noqa: BLE001 - reported, not raised
            self.report.stages.append(
                StageResult(
                    name,
                    FAILED,
                    f"{type(failure).__name__}: {failure}",
                    time.monotonic() - started,
                )
            )
            return
        elapsed = time.monotonic() - started
        if elapsed > STAGE_DEADLINE_SECONDS:
            self.report.stages.append(
                StageResult(
                    name,
                    FAILED,
                    f"took {elapsed:.1f}s against a {STAGE_DEADLINE_SECONDS:.0f}s "
                    "deadline; a stage that overruns is a failure, not a slow pass",
                    elapsed,
                )
            )
            return
        self.report.stages.append(StageResult(name, EXECUTED, detail or "", elapsed))


class NotExecuted(Exception):
    """This stage could not run here, and says why."""


def request(path: Path, document: dict) -> dict:
    from azazel_nexus_runtime.transport import read_frame, send_frame

    original_gid = os.getegid()
    try:
        if os.geteuid() == 0:
            # These metadata verbs admit operators; root alone is not one.
            os.setegid(grp.getgrnam("azazel-operator").gr_gid)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5.0)
            client.connect(str(path))
            send_frame(client, document)
            client.shutdown(socket.SHUT_WR)
            return json.loads(read_frame(client))
    finally:
        if os.geteuid() == 0:
            os.setegid(original_gid)


class Daemon:
    """One daemon as a real subprocess, stopped in bounded time."""

    def __init__(self, harness: Harness, module: str, socket_name: str) -> None:
        self.harness = harness
        self.module = module
        # Each daemon binds inside its own leaf directory (runtime_paths).
        self.path = (
            harness.root / "var/lib/azazel/run" / socket_name / f"{socket_name}.sock"
        )
        self.process: Optional[subprocess.Popen] = None

    def __enter__(self) -> "Daemon":
        self.process = subprocess.Popen(
            [sys.executable, "-m", f"azazel_nexus_runtime.{self.module}"],
            env=self.harness.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + STARTUP_DEADLINE_SECONDS
        while time.monotonic() < deadline:
            if self.path.exists():
                return self
            if self.process.poll() is not None:
                _, err = self.process.communicate()
                raise RuntimeError(
                    f"{self.module} exited before binding: "
                    f"{err.decode('utf-8', 'replace').strip()[:400]}"
                )
            time.sleep(0.02)
        self.__exit__()
        raise RuntimeError(
            f"{self.module} did not bind {self.path} within "
            f"{STARTUP_DEADLINE_SECONDS:.0f}s"
        )

    def __exit__(self, *exc) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


