"""`node_health` for the activation pass: fixed local checks only (#206).

`docs/activation-observe-baseline.md` §3.3. `healthy` is computed from the
five controller-owned prerequisites of §3.3, reported as six findings
(capacity and resources separately), with thresholds from the activation
policy, in this order:

1. ``state_capacity`` and 2. ``resources`` meet the policy floors (the
   bootstrap capacity and resource checks, reused unchanged);
3. ``activation_ledger``: the injected activation ledger, if present, is a
   single-link regular file owned by root and writable by its owner only, and
   its chain verifies. The check is **read-only**: it never creates, appends
   to or modifies the ledger. A missing ledger is an empty chain and passes;
   whether the ledger can be written is proven by the controller's own
   decision record, which a pass must append anyway;
4. ``operator_trust`` loads with at least one active key;
5. ``lab_marker``: no lab marker;
6. ``watchdog_fences``: the watchdog fence store is readable and holds no
   fence.

It never asks a service how it is: no socket, status file or self-report is
consulted, so a daemon cannot vouch for itself. Any exception, absence or
unexpected type is a failed check, and one failed check makes the node
unhealthy. Findings are fixed labels; no exception text leaves this module.

Since phase P4 the activation pass calls it, after narrowing, through
`activation_pass`; it still only reports.
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
from azazel_nexus.lab_host import is_lab_host
from azazel_nexus.operator_store import load_operator_trust
from azazel_nexus.operator_trust import OperatorTrust

from .bootstrap_resources import BootstrapResourceThresholds, require_bootstrap_resources
from .bootstrap_state_capacity import BootstrapStateFloors, require_bootstrap_state_capacity

__all__ = [
    "HEALTH_CHECKS",
    "NodeHealthProbes",
    "PRODUCTION_PROBES",
    "collect_node_health",
    "read_watchdog_fences",
]

HEALTH_CHECKS = (
    "state_capacity", "resources", "activation_ledger",
    "operator_trust", "lab_marker", "watchdog_fences",
)
_FENCE_LIMIT = 65536
_FENCES = "fences.json"
_WATCHDOG = ("var", "lib", "azazel", "state", "watchdog")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
#: The owner of every path component above the watchdog's own directory, and
#: of the activation ledger. Private test seam only.
_OWNER = 0


class _Unhealthy(Exception):
    pass


def _directory(fd: int, owner: int) -> None:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise _Unhealthy("store directory protection")


def read_watchdog_fences() -> dict:
    """The watchdog's stored fences, read without following any link.

    Traverses `/var/lib/azazel/state/watchdog` from `/`: each component above
    it root-owned and not writable by group or others, the store directory
    owned by `azwatch`. A missing `fences.json` inside it is the watchdog's
    own "never fenced" state (`FenceStore.load`) and reads as empty; any other
    failure is raised, so the caller treats it as a fence.
    """
    owner = pwd.getpwnam("azwatch").pw_uid
    directory = os.open("/", _DIR_FLAGS)
    try:
        for component in _WATCHDOG:
            _directory(directory, _OWNER)
            child = os.open(component, _DIR_FLAGS, dir_fd=directory)
            os.close(directory)
            directory = child
        _directory(directory, owner)
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


def _ledger_entry(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != _OWNER or info.st_nlink != 1
            or not info.st_mode & stat.S_IWUSR or info.st_mode & 0o022):
        raise _Unhealthy("activation ledger protection")
    return info.st_dev, info.st_ino


def _ledger(ledger):
    """Read-only: protection, one chain verification, unchanged identity."""
    if type(ledger) is not AuditLedger:
        raise _Unhealthy("activation ledger required")
    before = _ledger_entry(ledger.path)
    ledger.verify()
    if _ledger_entry(ledger.path) != before:
        raise _Unhealthy("activation ledger changed during verification")


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
    *, policy: ActivationPolicy, ledger: AuditLedger,
    probes: NodeHealthProbes = PRODUCTION_PROBES,
) -> tuple[bool, tuple[tuple[str, str], ...]]:
    """`(healthy, findings)`; every check runs, each finding is `ok` or `failed`.

    Without a decoded `ActivationPolicy` there are no floors, so the node is
    unhealthy. Nothing here writes: the capacity checks run first, and the
    ledger is only inspected and verified.
    """
    if type(probes) is not NodeHealthProbes:
        return False, tuple((name, "failed") for name in HEALTH_CHECKS)
    valid_policy = type(policy) is ActivationPolicy
    state = resources = None
    if valid_policy:
        try:
            state = BootstrapStateFloors(**policy.state_floor_values())
            resources = BootstrapResourceThresholds(**policy.resource_floor_values())
        except Exception:  # noqa: BLE001 - no floors means no health
            valid_policy = False

    def floors_state():
        if state is None:
            raise _Unhealthy("no state floors")
        probes.state_capacity(state)

    def floors_resources():
        if resources is None:
            raise _Unhealthy("no resource floors")
        probes.resources(resources)

    checks = {
        "state_capacity": floors_state,
        "resources": floors_resources,
        "activation_ledger": lambda: _ledger(ledger),
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
