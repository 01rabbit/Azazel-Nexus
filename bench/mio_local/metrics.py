"""Linux /proc sampling; missing metrics stay null rather than becoming zero."""
from __future__ import annotations

import math
import os
import threading
import time
from pathlib import Path


def percentile(values, percent):
    """Nearest rank, reported only with at least twenty observations."""
    values = sorted(values)
    if len(values) < 20:
        return None
    return values[math.ceil(percent / 100 * len(values)) - 1]


def distribution(values):
    return {"n": len(values), "p50": percentile(values, 50), "p95": percentile(values, 95)}


class ProcessMeter:
    """Sample the server identified by its unique socket argv, excluding load.

    CPU seconds are accumulated from /proc/PID/stat. RSS includes server
    threads (shared address space once), not background load or the runner.
    llama-server does not fork workers. VmHWM supplements sampled VmRSS.
    """
    def __init__(self, socket_path):
        self.marker = str(socket_path).encode()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.pid = None
        self.peak = None
        self.cpu = None
        self.samples = 0
        self.started = None
        self.elapsed = 0

    def _sample(self):
        if self.pid is None:
            for path in Path("/proc").glob("[0-9]*/cmdline"):
                try:
                    if self.marker in path.read_bytes().split(b"\0"):
                        self.pid = path.parent.name
                        break
                except OSError:
                    continue
        if self.pid is None:
            return
        root = Path("/proc") / self.pid
        try:
            stat = (root / "stat").read_text().rsplit(")", 1)[1].split()
            self.cpu = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
            status = (root / "status").read_text().splitlines()
            rss = [int(line.split()[1]) * 1024 for line in status
                   if line.startswith(("VmRSS:", "VmHWM:"))]
            if rss:
                self.peak = max(self.peak or 0, *rss)
            self.samples += 1
        except (OSError, ValueError, IndexError):
            pass

    def _run(self):
        while not self.stop_event.is_set():
            self._sample()
            self.stop_event.wait(0.05)

    def __enter__(self):
        self.started = time.monotonic()
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop_event.set()
        self.thread.join(timeout=1)
        self._sample()
        self.elapsed = time.monotonic() - self.started

    def record(self):
        return {"peak_rss_bytes": self.peak, "cpu_seconds": self.cpu,
                "cpu_percent_one_core": self.cpu / self.elapsed * 100
                if self.cpu is not None and self.elapsed else None,
                "resource_samples": self.samples, "resource_window_s": self.elapsed}


def memory_limit():
    values = []
    for name in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        try:
            value = int(Path(name).read_text().strip())
            if 0 < value < 2 ** 60:
                values.append(value)
        except (OSError, ValueError):
            pass
    try:
        values.append(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError):
        pass
    return min(values) if values else None
