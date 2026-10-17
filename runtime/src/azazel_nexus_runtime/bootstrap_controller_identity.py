"""Fixed local controller identity inputs, not systemd admission by themselves."""

import os
from pathlib import Path
import re

from .bootstrap_cgroup_mount import CONTROLLER_GROUP, _namespaces, _read_proc
from .bootstrap_controller import BootstrapControllerIdentity
from .runtime_paths import ROOT
from .units import UnitOperationFailed

_GROUP = CONTROLLER_GROUP


def current_bootstrap_controller_identity():
    """Bind the current process to fixed service context without learning from D-Bus.

    Environment is not authentication. The observer must independently match
    these values against the admitted system manager, with the existing cgroup
    namespace/mount checks held by composition. No alternate path/identity API.
    """
    try:
        if ROOT != Path("/") or os.geteuid() != 0:
            raise UnitOperationFailed("fixed root service context required")
        pid = os.getpid()
        invocation = os.environ.get("INVOCATION_ID", "")
        if type(invocation) is not str or re.fullmatch(r"[0-9a-fA-F]{32}", invocation) is None:
            raise UnitOperationFailed("controller invocation unavailable")
        identity = BootstrapControllerIdentity(pid, bytes.fromhex(invocation), _GROUP)
        namespaces = _namespaces()
        path = f"/proc/{pid}/cgroup"
        raw = _read_proc(path, 4096)
        if raw != f"0::{_GROUP}\n".encode("ascii"):
            raise UnitOperationFailed("controller unified cgroup differs")
        if (_read_proc(path, 4096) != raw or os.getpid() != pid
                or os.geteuid() != 0 or os.environ.get("INVOCATION_ID", "") != invocation
                or _namespaces() != namespaces):
            raise UnitOperationFailed("local controller identity changed")
        return identity
    except Exception:
        raise UnitOperationFailed("local bootstrap controller identity refused") from None
