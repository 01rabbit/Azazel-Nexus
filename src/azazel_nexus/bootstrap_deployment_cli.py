"""Explicit local administrator publication; never service admission."""

from hashlib import sha256

from .bootstrap_deployment import decode_bootstrap_deployment
from .bootstrap_deployment_store import (
    DeploymentDurabilityUncertain, initialize_bootstrap_deployment, recover_bootstrap_deployment,
)
from .operator_trust import ApprovalRefused


def run_publication(*, source, out, recovery=False):
    """Terminal framing is removed, but declaration bytes are not normalized."""
    try:
        if not source.isatty():
            raise ApprovalRefused("interactive confirmation required")

        def line(prompt, limit):
            print(prompt, file=out, flush=True)
            raw = source.buffer.readline(limit + 2)
            if not raw.endswith(b"\n") or len(raw) > limit + 1:
                raise ApprovalRefused("bounded complete input required")
            return raw[:-1]

        raw = line("Enter canonical deployment JSON (not secrets):", 4096)
        decode_bootstrap_deployment(raw)
        print("NOT a start grant. No service will be installed or activated.", file=out)
        print("Declaration SHA-256: " + sha256(raw).hexdigest(), file=out)
        digest = line("Re-enter the reviewed SHA-256:", 64).decode("ascii")
        if digest != sha256(raw).hexdigest():
            raise ApprovalRefused("digest confirmation differs")
        word = b"RECOVER" if recovery else b"INITIALIZE"
        answer = line("Type " + word.decode() + " to confirm this operation:", 16)
        if answer != word:
            raise ApprovalRefused("operation not confirmed")
        if recovery:
            recover_bootstrap_deployment(raw, confirmed_sha256=digest, confirmed_recovery=True)
        else:
            initialize_bootstrap_deployment(raw, confirmed_sha256=digest, confirmed_initialize=True)
    except DeploymentDurabilityUncertain:
        print("Declaration may be published; durability UNCONFIRMED. Inspect retained state; do not retry automatically. No activation performed.",
              file=out)
        return 2
    except (ApprovalRefused, OSError, AttributeError, ValueError):
        print("Deployment operation refused; inspect retained state before retry. No activation performed.",
              file=out)
        return 1
    print("Declaration publication completed; NOT admitted or authorized for runtime start.", file=out)
    return 0
