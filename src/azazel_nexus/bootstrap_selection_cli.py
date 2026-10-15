"""Interactive local administrator intent publication; never runtime admission."""

from hashlib import sha256

from .bootstrap_selection import decode_bootstrap_selection
from .bootstrap_selection_store import (
    SelectionDurabilityUncertain, initialize_bootstrap_selection, recover_bootstrap_selection,
)
from .operator_trust import ApprovalRefused


def run_publication(*, source, out, recovery=False):
    try:
        if not source.isatty():
            raise ApprovalRefused("interactive confirmation required")

        def line(prompt, limit):
            print(prompt, file=out, flush=True)
            raw = source.buffer.readline(limit + 2)
            if not raw.endswith(b"\n") or len(raw) > limit + 1:
                raise ApprovalRefused("bounded complete input required")
            return raw[:-1]

        raw = line("Enter canonical per-boot selection JSON (not secrets):", 4096)
        decode_bootstrap_selection(raw)
        print("Selection is NOT approval, admission or activation. No deadline is reset.", file=out)
        print("Selection SHA-256: " + sha256(raw).hexdigest(), file=out)
        digest = line("Re-enter the reviewed SHA-256:", 64).decode("ascii")
        if digest != sha256(raw).hexdigest():
            raise ApprovalRefused("digest confirmation differs")
        word = b"RECOVER" if recovery else b"INITIALIZE"
        if line("Type " + word.decode() + " to confirm this operation:", 16) != word:
            raise ApprovalRefused("operation not confirmed")
        if recovery:
            recover_bootstrap_selection(raw, confirmed_sha256=digest, confirmed_recovery=True)
        else:
            initialize_bootstrap_selection(raw, confirmed_sha256=digest, confirmed_initialize=True)
    except SelectionDurabilityUncertain:
        print("Selection may be published; durability UNCONFIRMED. Inspect retained state; do not retry automatically.", file=out)
        return 2
    except (ApprovalRefused, OSError, AttributeError, ValueError):
        print("Selection operation refused; inspect retained state before retry. No activation performed.", file=out)
        return 1
    print("Selection published; NOT approval, admission or activation.", file=out)
    return 0
