"""Closed character repertoire for normalized, optional model prose."""

import re


def is_typed_content_digest(value):
    """Exact content ID, checked before normalization; never grants membership."""
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


_ASCII = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_-. ,;!?()[]{}\"'%&+/*#@~^|<>=$")
# Explicit ordinary Japanese letters and punctuation, not whole Unicode blocks.
# Combining marks, fillers, variation selectors and unassigned gaps stay out.
_JAPANESE = (
    (0x3001, 0x3002), (0x3005, 0x3007), (0x3008, 0x3011), (0x3014, 0x301B),
    (0x3041, 0x3096), (0x309D, 0x309F), (0x30A1, 0x30FF),
    (0x3400, 0x4DBF), (0x4E00, 0x9FFF),
)


def allowed_model_text(normalized):
    """Caller supplies NFKC text; any unsupported character closes the lane."""
    return all(char in _ASCII or any(lo <= ord(char) <= hi for lo, hi in _JAPANESE)
               for char in normalized)
