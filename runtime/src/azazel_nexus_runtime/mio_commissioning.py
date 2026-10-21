"""Read a signed commissioning ceiling, without admitting any provider."""

import hashlib
import json
from threading import Lock

from azazel_nexus.commissioning_approval import verify_retained_commissioning_proposal
from azazel_nexus.commissioning_draft import read_mio_verification_inputs
from azazel_nexus.mio_profile import MioProfile
from azazel_nexus.operator_store import operator_trust_bytes

from .node_config import _decode as declared_node_bytes

_PROFILES = {"CORE": MioProfile.CORE, "LITE": MioProfile.LOCAL_ONLY,
             "FULL": MioProfile.FASTEST_PERMITTED}
# The unit's SetCredential fallback when a credential source (the proposal
# files, node.yaml or operators.json) is missing. systemd drops an empty
# `SetCredential=ID:` as invalid syntax, so the fallback must be a non-empty
# value, and it means "no source": CORE.
MISSING_CREDENTIAL = b"absent"
_cache_key = None
_cache_result = MioProfile.CORE
_cache_lock = Lock()


def commissioned_profile() -> MioProfile:
    """Hash all five bounded inputs; verify only changed credential bytes.

    Credentials refresh on unit restart, including enrollment and revocation.
    Historical confirmation proves neither current hardware nor admission.
    """
    global _cache_key, _cache_result
    try:
        from azazel_nexus.lab_host import is_lab_host

        # The host safety marker can change independently of credentials.
        if is_lab_host():
            return MioProfile.CORE
        with _cache_lock:
            inputs = read_mio_verification_inputs()
            key = tuple(hashlib.sha256(value).digest() for value in inputs)
            if key == _cache_key:
                return _cache_result
            # Do not let an unexpected verification failure reuse old success.
            _cache_key, _cache_result = key, MioProfile.CORE
            expected, payload, signature, trust_raw, node_raw = inputs
            if MISSING_CREDENTIAL in inputs:
                return MioProfile.CORE
            node = declared_node_bytes(node_raw)
            trust = operator_trust_bytes(trust_raw)
            document = json.loads(expected)
            verify_retained_commissioning_proposal(
                trust=trust, payload=payload, signature=signature,
                expected_payload=expected, operator=document["operator"], node_id=node.node_id,
            )
            if read_mio_verification_inputs() != inputs:
                _cache_key = None
                return MioProfile.CORE
            # v3 is v2 plus the Deception Lite scope (#196 G1a): both carry the
            # signed M.I.O. selection, verified above under the same signature.
            if document["schema"] in {"azazel-nexus/commissioning-proposal/v2",
                                      "azazel-nexus/commissioning-proposal/v3"}:
                _cache_result = _PROFILES[document["mio_profile"]]
            return _cache_result
    except Exception:
        return MioProfile.CORE
