"""Bounded synthetic CPU duty cycle and resident memory, not actual Edge work."""
from __future__ import annotations

import multiprocessing
import time
from dataclasses import dataclass


def _worker(stop, ready, cpu_fraction: float, memory_bytes: int, duration_s: float):
    memory = bytearray(memory_bytes)
    for offset in range(0, len(memory), 4096):
        memory[offset] = 1
    ready.set()
    end = time.monotonic() + duration_s
    cycle = 0
    while not stop.is_set() and time.monotonic() < end:
        started = time.monotonic()
        # Dirty each page periodically so the allocation remains resident.
        if cycle % 20 == 0:
            for offset in range(0, len(memory), 4096):
                memory[offset] = (memory[offset] + 1) % 256
        while time.monotonic() - started < cpu_fraction * 0.05:
            sum(i * i for i in range(128))
        stop.wait(max(0, 0.05 - (time.monotonic() - started)))
        cycle += 1


@dataclass(frozen=True)
class LoadConfig:
    workers: int = 1
    cpu_fraction: float = 0.25
    memory_mib: int = 256  # total, divided across workers
    duration_s: float = 3600

    def __post_init__(self):
        if not 1 <= self.workers <= 4 or not 0 <= self.cpu_fraction <= 1:
            raise ValueError("load requires 1..4 workers and CPU fraction 0..1")
        if not 0 <= self.memory_mib <= 1024 or not 0 < self.duration_s <= 21600:
            raise ValueError("load requires 0..1024 MiB and duration <=21600s")


class EdgeLoad:
    def __init__(self, config: LoadConfig):
        self.config = config
        self.context = multiprocessing.get_context("spawn")
        self.stop_event = self.context.Event()
        self.processes = []

    def __enter__(self):
        try:
            for _ in range(self.config.workers):
                ready = self.context.Event()
                process = self.context.Process(target=_worker, args=(
                    self.stop_event, ready, self.config.cpu_fraction,
                    self.config.memory_mib * 1024 * 1024 // self.config.workers,
                    self.config.duration_s,
                ))
                process.start()
                self.processes.append(process)
                if not ready.wait(timeout=5) or not process.is_alive():
                    raise RuntimeError("background load did not become ready")
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, *_):
        self.stop_event.set()
        for process in self.processes:
            process.join(timeout=1)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
