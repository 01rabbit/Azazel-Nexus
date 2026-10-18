"""Shared export lint for HIL bundles and on-device acquisition output."""

import ipaddress
import json
import re

from .contracts import ANONYMOUS_ID, HMAC


class ConfidentialityRefused(ValueError):
    """Identifier-bearing or uninspectable export."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ConfidentialityRefused(reason)


MAC = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
DOTTED_MAC = re.compile(r"(?i)\b[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}\b")
LABEL = re.compile(
    r"(?i)\b(?:serial(?:[ _-]?(?:number|no))?|s/n|asset(?:[ _-]?(?:tag|id|number))?"
    r"|host(?:[ _-]?name)|fqdn)\b[\s\"']*[:=]"
)
SERIAL = re.compile(
    r"\b(?i:SN|SNA|SERIAL|ASSET)[-_]?[A-Za-z0-9]{4,}\b"
    r"|\b(?=[A-Z0-9]{10,32}\b)(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*[0-9])[A-Z0-9]+\b"
)
HOST = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}\b")

FILE_SUFFIXES = {
    "json", "jsonl", "txt", "log", "csv", "yaml", "yml", "md",
    "service", "slice", "target", "socket", "timer", "path", "mount", "scope",
}


def _hostname(text: str) -> bool:
    return any(match.group().rsplit(".", 1)[1].lower() not in FILE_SUFFIXES
               for match in HOST.finditer(text))


def lint_text(payload: bytes) -> None:
    """Refuse uninspectable or identifier-bearing text without echoing it."""
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ConfidentialityRefused("confidentiality: UTF-8 text required") from exc
    require("\0" not in text, "confidentiality: binary text refused")
    for pattern, reason in (
        (MAC, "MAC"), (DOTTED_MAC, "MAC"), (LABEL, "identifier label"),
        (SERIAL, "serial-like token"),
    ):
        require(not pattern.search(text), f"confidentiality: {reason} refused")
    require(not _hostname(text), "confidentiality: hostname refused")
    # Escaped JSON strings are inspected after decoding too (e.g. \\u003a).
    try:
        value = json.loads(text)
    except ValueError:
        value = None
    if isinstance(value, (dict, list)):
        _protected_fields(value)
        normalized = json.dumps(value, ensure_ascii=False)
        if normalized != text:
            for pattern in (MAC, DOTTED_MAC, LABEL, SERIAL):
                require(not pattern.search(normalized), "confidentiality: identifier refused")
        require(not _hostname(normalized), "confidentiality: hostname refused")
        text += "\n" + normalized
    candidates = re.findall(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])", text)
    for token in re.findall(r"[0-9A-Za-z_.:%-]+", text):
        if ":" in token:
            # Also inspect suffixes: a log label may touch an address directly.
            candidates.append(token)
            candidates.extend(token[index + 1:] for index, char in enumerate(token)
                              if char == ":")
    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate.rstrip(".").split("%", 1)[0])
        except ValueError:
            continue
        raise ConfidentialityRefused("confidentiality: raw IP address refused")



def _protected_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "dut_id":
                require(isinstance(child, str) and ANONYMOUS_ID.fullmatch(child) is not None,
                        "confidentiality: anonymous DUT id required")
            if ((key == "host_digest" or key.endswith("fingerprint"))
                    and (key != "permanent_address_fingerprint" or child is not None)):
                require(isinstance(child, str) and HMAC.fullmatch(child) is not None,
                        "confidentiality: protected HMAC fingerprint required")
            _protected_fields(child)
    elif isinstance(value, list):
        for child in value:
            _protected_fields(child)
