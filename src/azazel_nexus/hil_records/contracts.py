"""Canonical exported HIL identity formats (lowercase hexadecimal only)."""

import re

HMAC = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")
ANONYMOUS_ID = re.compile(r"dut-[0-9a-f]{32}\Z")


def anonymous_dut(fingerprint: str) -> str:
    """Derive the stable anonymous label from the protected host fingerprint."""
    if HMAC.fullmatch(fingerprint) is None:
        raise ValueError("protected host fingerprint required")
    return "dut-" + fingerprint.removeprefix("hmac-sha256:")[:32]
