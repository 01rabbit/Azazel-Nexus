"""Fail-closed lab clock health, using only local BOOTTIME for freshness.

A privileged external observer writes a protected snapshot. K timestamps are
mapped to N receipt BOOTTIME by that observer, never subtracted from N clocks.
No missing snapshot or age can enable the nonzero contract.
"""
import json
import os
import stat
import time
from threading import RLock
from pathlib import Path

# Each reader permits at most this much unobserved local wall displacement.
# Both nodes can move in opposite directions after the same observation.
PER_NODE_STEP_MARGIN_US = 1000
PAIR_STEP_MARGIN_US = 2 * PER_NODE_STEP_MARGIN_US
# K can publish a newer sample before this N snapshot is replaced. Reserve
# every accepted K snapshot's hard error ceiling, not the old K sample's error.
MAX_PEER_ERROR_US = 1000
HEALTH_SCHEMA = "azazel-clocklab-health/1"
_KEYS = {"schema", "contract_id", "n_boot_id", "k_boot_id", "generation",
         "observed_boottime_ns", "valid_until_boottime_ns", "n_error_us", "k_error_us",
         "k_age_at_receipt_us", "mapping_bound_us", "step_counter", "wall_minus_boottime_ns"}


def boottime_ns():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class ClockHealth:
    def __init__(self, contract, path, *, boot_id=None, boottime=boottime_ns,
                 wall=time.time_ns, owner=0, trust_root=Path("/")):
        # Reject old Fabric/configuration even if a mixed installation can
        # still construct a policy/1 object under the previous weaker rules.
        if contract.as_dict().get("schema") != "azazel-clocklab-policy/2":
            raise ValueError("clock policy revision")
        self.contract, self.path = contract, Path(path)
        self._trust_root = Path(trust_root)
        self.path.relative_to(self._trust_root)
        self._boot_id = boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self._boottime, self._wall, self._owner = boottime, wall, owner
        self._initial = None
        self._latched = False
        self._lock = RLock()

    def check(self, *, expected_generation=None):
        with self._lock:
            if self._latched:
                raise ValueError("clock health latched")
            try:
                return self._check(expected_generation=expected_generation)
            except Exception:
                self._latched = True
                raise

    def run_validated(self, use, *, expected_generation):
        """Keep the fail-closed latch serialized through the adoption decision."""
        with self._lock:
            self.check(expected_generation=expected_generation)
            snapshot = dict(self._snapshot)
            def revalidate():
                # No file I/O here: re-prove the same evidence at final adoption.
                try:
                    return self._validate_snapshot(snapshot, expected_generation=expected_generation)
                except Exception:
                    self._latched = True
                    raise
            return use(revalidate)

    def _check(self, *, expected_generation=None):
        # Check every ancestor without following symlinks.
        for parent in reversed([p for p in self.path.parents if p == self._trust_root or self._trust_root in p.parents]):
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != self._owner or info.st_mode & 0o022:
                raise ValueError("clock health directory")
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self._owner
                    or info.st_mode & 0o022 or info.st_nlink != 1 or not 0 < info.st_size <= 8192):
                raise ValueError("clock health file")
            raw = os.read(fd, 8193)
            after = os.fstat(fd)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(raw) != info.st_size:
                raise ValueError("clock health changed")
        finally:
            os.close(fd)
        def pairs(items):
            d = {}
            for key, value in items:
                if key in d:
                    raise ValueError("clock duplicate")
                d[key] = value
            return d
        d = json.loads(raw, object_pairs_hook=pairs)
        generation = self._validate_snapshot(d, expected_generation=expected_generation)
        self._snapshot = dict(d)
        return generation

    def _validate_snapshot(self, d, *, expected_generation=None):
        if (type(d) is not dict or set(d) != _KEYS or d["schema"] != HEALTH_SCHEMA
                or d["contract_id"] != self.contract.contract_id or d["n_boot_id"] != self._boot_id
                or type(d["k_boot_id"]) is not str or not d["k_boot_id"]):
            raise ValueError("clock health binding")
        nums = _KEYS - {"schema", "contract_id", "n_boot_id", "k_boot_id"}
        if any(type(d[k]) is not int for k in nums):
            raise ValueError("clock health number")
        positive = nums - {"wall_minus_boottime_ns"}
        if any(d[k] < 0 for k in positive):
            raise ValueError("clock health range")
        now = self._boottime()
        age_ns = now - d["observed_boottime_ns"]
        max_age_ns = self.contract.max_observation_age_ms * 1_000_000
        if (not 0 <= age_ns < max_age_ns or not now < d["valid_until_boottime_ns"]
                or d["valid_until_boottime_ns"] > d["observed_boottime_ns"] + max_age_ns):
            raise ValueError("clock health age")
        # Conservative ceil drift: both node ages accrue at 100ppm.
        n_age_us = (age_ns + 999) // 1000
        k_age_us = n_age_us + d["k_age_at_receipt_us"]
        budget = (d["n_error_us"] + MAX_PEER_ERROR_US + PAIR_STEP_MARGIN_US + d["mapping_bound_us"]
                  + (100 * (n_age_us + k_age_us) + 999999) // 1000000)
        if (d["n_error_us"] > 1000 or d["k_error_us"] > 1000
                or k_age_us >= 5_000_000 or budget > self.contract.skew_budget_us):
            raise ValueError("clock health budget")
        # Acquisition bracket includes BOOTTIME/wall syscall and scheduling skew.
        wall_delta = self._wall() - now
        if abs(wall_delta - d["wall_minus_boottime_ns"]) > PER_NODE_STEP_MARGIN_US * 1000:
            raise ValueError("clock stepped")
        generation = (d["n_boot_id"], d["k_boot_id"], d["generation"], d["step_counter"])
        if expected_generation is not None and generation != expected_generation:
            raise ValueError("clock health generation")
        if self._initial is None:
            self._initial = (d["n_boot_id"], d["k_boot_id"], d["step_counter"])
        if self._initial != (d["n_boot_id"], d["k_boot_id"], d["step_counter"]):
            raise ValueError("clock health changed")
        return generation
