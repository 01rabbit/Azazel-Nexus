"""SO-06 `evaluation_outcomes`: the real observe-only Edge Core on a pinned clock.

Edge Core stamps its own wall clock into two fields of every observation it
forwards: `normalized.ingest_epoch` and `enforcement.metadata.release_due_epoch`
(the release lease it would hold, `now + TTL`). Two runs on the same `eve.json`
therefore differ in exactly those fields. SO-06 compares records byte for byte
and its exclusion list is not widened, so this harness pins Edge's clock.

The Edge binary has no clock argument and none is added: the shipped
entrypoint must not have a way to be told the time. The pin lives entirely in
this test process. A small preload library, compiled here with the instant
fixed at compile time, answers `CLOCK_REALTIME` (and `gettimeofday`/`time`)
with `PINNED_EPOCH`; every other clock, `CLOCK_MONOTONIC` included, is the
real one, so Edge's polling and forward-report timers run as shipped. The
library reads no environment variable and nothing outside this file chooses
the instant.

A pin that did not take effect is refused, never compared: every observation
must carry exactly the pinned instant. Edge's decision fields never come from
the clock; `decisions_ignore_clock` checks that on a real binary.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from tools import so06_loop

#: One instant for Edge, intake and explainer.
PINNED_EPOCH = int(so06_loop.FIXED_NOW)
#: Edge's `AZAZEL_DEFENSE_ACTION_TTL_SEC` default; the unit does not set it.
EDGE_ACTION_TTL_S = 300
#: The only two Edge fields that read the wall clock.
CLOCK_FIELDS = (("normalized", "ingest_epoch"), ("enforcement", "metadata", "release_due_epoch"))
FORWARD_STATS_SCHEMA = "azazel-edge/forward-stats/v1"
WAIT_S = 10

SHIM_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/time.h>
#include <time.h>

#ifndef AZ_PINNED_EPOCH
#error "the instant is fixed at compile time"
#endif

typedef int (*clock_fn)(clockid_t, struct timespec *);

static int wall(clockid_t id) {
    return id == CLOCK_REALTIME || id == CLOCK_REALTIME_COARSE;
}

int clock_gettime(clockid_t id, struct timespec *ts) {
    if (wall(id)) {
        ts->tv_sec = AZ_PINNED_EPOCH;
        ts->tv_nsec = 0;
        return 0;
    }
    static clock_fn real;
    if (!real) real = (clock_fn)dlsym(RTLD_NEXT, "clock_gettime");
    return real(id, ts);
}

int gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    if (tv) {
        tv->tv_sec = AZ_PINNED_EPOCH;
        tv->tv_usec = 0;
    }
    return 0;
}

time_t time(time_t *out) {
    if (out) *out = AZ_PINNED_EPOCH;
    return AZ_PINNED_EPOCH;
}
"""


class EdgeUnavailable(RuntimeError):
    """The pinned Edge run cannot be performed here; never a pass."""


def build_shim(directory: Path) -> Path:
    """Compile the preload library into `directory` (Linux, a C compiler)."""
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None or not Path("/proc/self").exists():
        raise EdgeUnavailable("pinning Edge's clock needs Linux and a C compiler")
    source, library = directory / "pinned_clock.c", directory / "pinned_clock.so"
    source.write_text(SHIM_SOURCE)
    try:
        subprocess.run(
            [compiler, "-shared", "-fPIC", "-O2", f"-DAZ_PINNED_EPOCH={PINNED_EPOCH}L",
             "-o", str(library), str(source), "-ldl"],
            check=True, capture_output=True, timeout=60)
    except subprocess.SubprocessError as exc:
        raise EdgeUnavailable(f"the pinned-clock library did not build: {exc}") from exc
    return library


def edge_environment(directory: Path, intake: Path) -> dict:
    """The shipped unit's Environment=, with only test paths relocated."""
    from azazel_nexus_runtime.hardening import PROFILES

    profile = next(p for p in PROFILES if p.unit == "azazel-edge-core.service")
    environment = dict(value.split("=", 1) for key, value in profile.extra
                       if key == "Environment")
    environment.update(AZAZEL_AI_SOCKET=str(intake), AZAZEL_EVE_PATH=str(directory / "eve.json"),
                       AZAZEL_DEFENSE_RELEASE_LEDGER=str(directory / "release-ledger.json"),
                       AZAZEL_EVE_FROM_START="true", PATH=os.defpath)
    return environment


class Collector:
    """The receiving end of Edge's forward socket: one line per connection."""

    def __init__(self, path: Path):
        self.lines: list[bytes] = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen(16)
        self.server.settimeout(0.05)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.server.accept()
            except TimeoutError:
                continue
            with connection:
                connection.settimeout(2)
                data = b""
                while chunk := connection.recv(65536):
                    data += chunk
            self.lines.extend(data.splitlines())

    def close(self):
        self.stop.set()
        self.thread.join(WAIT_S)
        self.server.close()


def observations(lines: list[bytes]) -> list[bytes]:
    """Edge's evaluated events; its forward-count reports are not observations."""
    return [line for line in lines if json.loads(line).get("schema") != FORWARD_STATS_SCHEMA]


def field(record: dict, path: tuple) -> object:
    for key in path:
        record = record[key]
    return record


def require_pinned(lines: list[bytes]) -> None:
    """Refuse a run whose clock fields are not the pinned instant.

    Every line is checked, and a run with no observation proves nothing.
    """
    if not lines:
        raise EdgeUnavailable("no Edge observation to check the pinned clock against")
    for line in lines:
        record = json.loads(line)
        due = field(record, CLOCK_FIELDS[1])
        if (field(record, CLOCK_FIELDS[0]) != PINNED_EPOCH
                or due not in (None, PINNED_EPOCH + EDGE_ACTION_TTL_S)):
            raise EdgeUnavailable("Edge's clock was not pinned: the preload did not take effect")


def run_edge(binary: Path, events: list[dict], *, expected: int,
             shim: Path | None) -> list[bytes]:
    """Run Edge once on fresh state; return its observation lines in order.

    `shim=None` runs on the real wall clock. It exists only for the mutation
    check (`main`, tests); the SO-06 replay refuses it (`so06_replay`).
    """
    return run_edge_in(binary, events, expected=expected, shim=shim)[0]


def run_edge_in(binary: Path, events: list[dict], *, expected: int, shim: Path | None,
                environment: dict | None = None, wrap=None, collect=None):
    """`run_edge`, for a caller that runs Edge somewhere else (`so06_lease`).

    `environment` is laid over the shipped unit's, `wrap(argv)` returns the
    command that starts Edge, and `collect(directory)` reads what Edge left
    in its state directory while Edge is still running and before it is
    removed. Returns `(observations, collect(directory))`.
    """
    if expected < 1:
        raise EdgeUnavailable("an Edge run must expect at least one observation")
    if wrap is None and (environment or {}).get("AZAZEL_DEFENSE_ENFORCE", "false") != "false":
        # An enforcing posture runs only inside isolation a caller provides.
        raise EdgeUnavailable("an enforcing Edge runs only inside the harness's isolation")
    with tempfile.TemporaryDirectory(prefix="azso06e-", dir="/tmp") as temporary:
        directory = Path(temporary)
        (directory / "eve.json").write_text("".join(json.dumps(e) + "\n" for e in events))
        unit = edge_environment(directory, directory / "intake.sock")
        unit.update(environment or {})
        if shim is not None:
            unit["LD_PRELOAD"] = str(shim)
        argv = [str(binary)] if wrap is None else wrap([str(binary)])
        collector = Collector(directory / "intake.sock")
        collected = None
        try:
            process = subprocess.Popen(argv, env=unit, cwd=directory,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
        except BaseException:
            collector.close()
            raise
        try:
            until = time.monotonic() + WAIT_S
            while len(observations(collector.lines)) < expected:
                if process.poll() is not None or time.monotonic() > until:
                    raise EdgeUnavailable(
                        f"Edge sent {len(observations(collector.lines))} of {expected} "
                        "observations")
                time.sleep(0.02)
            if collect is not None:
                collected = collect(directory)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(WAIT_S)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(WAIT_S)
            collector.close()
        found = observations(collector.lines)
    if len(found) != expected:
        raise EdgeUnavailable(f"Edge sent {len(found)} observations, expected {expected}")
    if shim is not None:
        require_pinned(found)
    return found, collected


def without_clock(lines: list[bytes]) -> list[dict]:
    """The observations with the two clock fields removed, for the check below."""
    records = []
    for line in lines:
        record = json.loads(line)
        for path in CLOCK_FIELDS:
            parent = field(record, path[:-1])
            parent.pop(path[-1])
        records.append(record)
    return records


def decisions_ignore_clock(pinned: list[bytes], wall: list[bytes]) -> bool:
    """Everything Edge decided is the same on the pinned and the real clock."""
    return without_clock(pinned) == without_clock(wall)


def main(argv: list[str] | None = None) -> int:
    """Check one Edge binary: pinned runs match, wall-clock runs do not."""
    from tools.e2e_loop import eve_events

    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("--edge-core", type=Path, required=True)
    args = parser.parse_args(argv)
    events = eve_events()
    alerts = sum(e["event_type"] == "alert" for e in events)
    with tempfile.TemporaryDirectory(prefix="azso06s-") as temporary:
        shim = build_shim(Path(temporary))
        pinned = [run_edge(args.edge_core, events, expected=alerts, shim=shim) for _ in range(2)]
        wall = [run_edge(args.edge_core, events, expected=alerts, shim=None) for _ in range(2)]
    report = {
        "pinned_identical": pinned[0] == pinned[1],
        "wall_identical": wall[0] == wall[1],
        "decisions_ignore_clock": decisions_ignore_clock(pinned[0], wall[0]),
        "observations": len(pinned[0]),
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if (report["pinned_identical"] and not report["wall_identical"]
                 and report["decisions_ignore_clock"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
