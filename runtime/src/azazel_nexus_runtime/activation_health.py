"""`node_health` for the activation pass: fixed local checks only (#206).

`docs/activation-observe-baseline.md` §3.3. `healthy` is computed from five
controller-owned prerequisites, with thresholds from the activation policy:

1. the activation ledger verifies, accepts an append, and verifies again;
2. state capacity and resources meet the policy floors (the bootstrap
   capacity and resource checks, reused unchanged);
3. operator trust loads with at least one active key;
4. no lab marker;
5. the watchdog fence store is readable and holds no fence.

It never asks a service how it is: no socket, status file or self-report is
consulted, so a daemon cannot vouch for itself. Any exception, absence or
unexpected type is a failed check, and one failed check makes the node
unhealthy. Findings are fixed labels; no exception text leaves this module.

Inert in phase P2: `az-activated` does not call it yet.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import pwd
import stat
from typing import Callable

from azazel_nexus.activation_policy import ActivationPolicy
from azazel_nexus.audit import AuditLedger
from azazel_nexus.bootstrap_approval import parse_bootstrap_time
from azazel_nexus.lab_host import is_lab_host
from azazel_nexus.operator_store import load_operator_trust
from azazel_nexus.operator_trust import OperatorTrust

from .bootstrap_resources import BootstrapResourceThresholds, require_bootstrap_resources
from .bootstrap_state_capacity import BootstrapStateFloors, require_bootstrap_state_capacity
from .runtime_paths import watchdog_state_dir

__all__ = [
    "HEALTH_CHECKS",
    "NodeHealthProbes",
    "PRODUCTION_PROBES",
    "collect_node_health",
    "read_watchdog_fences",
]

HEALTH_CHECKS = (
    "activation_ledger", "state_capacity", "resources",
    "operator_trust", "lab_marker", "watchdog_fences",
)
_FENCE_LIMIT = 65536
_FENCES = "fences.json"


class _Unhealthy(Exception):
    pass


def read_watchdog_fences() -> dict:
    """The watchdog's stored fences, read without following links.

    The store directory must exist, belong to `azwatch` and not be writable
    by anyone else. A missing `fences.json` inside it is the watchdog's own
    "never fenced" state (`FenceStore.load`) and reads as empty; any other
    failure is raised, so the caller treats it as a fence.
    """
    owner = pwd.getpwnam("azwatch").pw_uid
    directory = os.open(watchdog_state_dir(),
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise _Unhealthy("watchdog state directory protection")
        try:
            fd = os.open(_FENCES, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory)
        except FileNotFoundError:
            return {}
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner
                    or before.st_mode & 0o022 or not 0 < before.st_size <= _FENCE_LIMIT):
                raise _Unhealthy("watchdog fence file protection")
            raw = os.read(fd, _FENCE_LIMIT + 1)
            after = os.fstat(fd)
            if (len(raw) != before.st_size
                    or (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise _Unhealthy("watchdog fence file changed")
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    fences = json.loads(raw.decode("utf-8"))
    if type(fences) is not dict:
        raise _Unhealthy("watchdog fence store malformed")
    return fences


@dataclass(frozen=True)
class NodeHealthProbes:
    """The fixed readers behind each check. Production uses `PRODUCTION_PROBES`."""

    state_capacity: Callable[[BootstrapStateFloors], None]
    resources: Callable[[BootstrapResourceThresholds], None]
    operator_trust: Callable[[], OperatorTrust]
    lab_host: Callable[[], bool]
    watchdog_fences: Callable[[], dict]


PRODUCTION_PROBES = NodeHealthProbes(
    state_capacity=require_bootstrap_state_capacity,
    resources=require_bootstrap_resources,
    operator_trust=load_operator_trust,
    lab_host=is_lab_host,
    watchdog_fences=read_watchdog_fences,
)


def _ledger(ledger, now):
    if type(ledger) is not AuditLedger:
        raise _Unhealthy("activation ledger required")
    ledger.verify()
    _, head = ledger.head()
    ledger.append({"event_type": "activation.health_ledger_probe", "occurred_at": now},
                  expected_head=head)
    ledger.verify()


def _trust(probes):
    trust = probes.operator_trust()
    if type(trust) is not OperatorTrust or not set(trust.public_keys) - set(trust.revoked):
        raise _Unhealthy("no active operator key")


def _lab(probes):
    if probes.lab_host() is not False:
        raise _Unhealthy("lab marker present")


def _fences(probes):
    fences = probes.watchdog_fences()
    if type(fences) is not dict or fences:
        raise _Unhealthy("watchdog fence present")


def collect_node_health(
    *, policy: ActivationPolicy, ledger: AuditLedger, now: str,
    probes: NodeHealthProbes = PRODUCTION_PROBES,
) -> tuple[bool, tuple[tuple[str, str], ...]]:
    """`(healthy, findings)`; every check runs, each finding is `ok` or `failed`.

    Without a decoded `ActivationPolicy` there are no floors, so the node is
    unhealthy. The ledger append is the one write: it proves the ledger the
    pass will record into is writable now, not that anything was granted.
    """
    try:
        if type(probes) is not NodeHealthProbes:
            raise _Unhealthy("fixed health probes required")
        parse_bootstrap_time(now)
        valid_policy = type(policy) is ActivationPolicy
        state = resources = None
        if valid_policy:
            state = BootstrapStateFloors(**policy.state_floor_values())
            resources = BootstrapResourceThresholds(**policy.resource_floor_values())
    except Exception:  # noqa: BLE001 - no inputs means no health
        return False, tuple((name, "failed") for name in HEALTH_CHECKS)

    def floors_state():
        if state is None:
            raise _Unhealthy("no state floors")
        probes.state_capacity(state)

    def floors_resources():
        if resources is None:
            raise _Unhealthy("no resource floors")
        probes.resources(resources)

    checks = {
        "activation_ledger": lambda: _ledger(ledger, now),
        "state_capacity": floors_state,
        "resources": floors_resources,
        "operator_trust": lambda: _trust(probes),
        "lab_marker": lambda: _lab(probes),
        "watchdog_fences": lambda: _fences(probes),
    }
    findings = []
    for name in HEALTH_CHECKS:
        try:
            checks[name]()
            findings.append((name, "ok"))
        except Exception:  # noqa: BLE001 - any failure is unhealthy, text withheld
            findings.append((name, "failed"))
    healthy = valid_policy and all(result == "ok" for _, result in findings)
    return healthy, tuple(findings)
