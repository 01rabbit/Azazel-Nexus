"""Fixed protected pre-start policy reader; no creation or fallback."""

import os

from .activation_store import _read_file_at
from .bootstrap_prestart_policy import decode_prestart_policy, decode_pinned_prestart_policy
from .bootstrap_deployment import BootstrapDeployment
from .bootstrap_store import _bootstrap_directory
from .operator_trust import ApprovalRefused


def _read_at(fd, *, owner):
    return _read_file_at(fd, "admission.json", owner=owner, limit=8192)


def load_bootstrap_prestart_policy(*, expected):
    return _load(lambda raw: decode_prestart_policy(raw, expected=expected))


def load_declared_prestart_policy(*, deployment):
    """Declared expectations pinned by administrator record; not measured health."""
    if type(deployment) is not BootstrapDeployment:
        raise ApprovalRefused("protected deployment declaration required")
    return _load(lambda raw: decode_pinned_prestart_policy(raw, expected_digest=deployment.policy_digest))


def _load(decode):
    try:
        with _bootstrap_directory() as fd:
            identity = os.fstat(fd)
            raw = _read_at(fd, owner=0)
            policy = decode(raw)
            with _bootstrap_directory() as current:
                fresh = os.fstat(current)
                if ((identity.st_dev, identity.st_ino) != (fresh.st_dev, fresh.st_ino)
                        or _read_at(current, owner=0) != raw):
                    raise ApprovalRefused("prestart policy changed")
            return policy
    except Exception:
        raise ApprovalRefused("protected bootstrap prestart policy refused") from None
