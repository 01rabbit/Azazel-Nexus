"""What the read-only UI sends to a browser, projected from the read model (U5).

The browser receives one JSON document, schema `azazel-nexus/ui-model/1`,
built here from:

* the status read model (`status_view`, schema `azazel-nexus/status-view/1`),
  which is already an allowlist of what strict readers checked. Only the
  sections the screens use are copied (`UI_SECTIONS`); the interface list
  is not (NOC belongs to its own section, and interface identity stays on
  the operator's terminal, inventory-confidentiality §6);
* the setup guide (`azazel-nexus setup --json`), copied field by field;
* the UI's own reading of which snapshot files this account may open
  (`access`), so that a section this account cannot read is shown as
  **permission denied** rather than as merely absent.

Sections that later work adds to the read model (`PENDING_SECTIONS`: NOC,
unit state and storage, U2/U3) are passed through once they exist. Until
then each is listed under `pending` with a fixed reason code, and the page
says "not collected" with that code -- never a healthy word.

Nothing here decides anything: the document states that Edge decides and
enforces and that Edge's decisions reach this node as `would`, never as
executed (`authority`, copied from the read model).
"""

from __future__ import annotations

import json
from typing import Optional

__all__ = [
    "ACCESS_WORDS", "PENDING_SECTIONS", "SCHEMA", "SETUP_FIELDS", "UI_SECTIONS",
    "browser_json", "project",
]

SCHEMA = "azazel-nexus/ui-model/1"

#: The status read model's sections the screens render. Not `interfaces`.
UI_SECTIONS = (
    "profile", "mio", "capability", "enforcement", "external_modules",
    "knowledge_lite", "edge_core", "integration", "fabric", "edge_loop",
    "health", "next_actions",
)

#: Sections other work adds to the read model, and the fixed reason the page
#: shows until it does. Copied through unchanged once the read model has them.
PENDING_SECTIONS = {
    "noc": "noc_snapshot_not_wired",
    "services": "unit_state_snapshot_not_wired",
    "storage": "storage_snapshot_not_wired",
}

SETUP_FIELDS = ("schema", "provider_admission", "hg05", "enforcement_readiness",
                "notice", "read_only")
SETUP_STEP_FIELDS = ("name", "status", "reason", "next_command")
SETUP_SCHEMA = "azazel-nexus/setup/1"

#: What the UI's account found when it tried each snapshot it reads.
ACCESS_WORDS = frozenset({"readable", "permission_denied", "absent", "not_regular",
                          "unreadable", "not_probed"})


def _copy(value):
    """A detached copy of a JSON value."""
    return json.loads(json.dumps(value, allow_nan=False))


def _setup(value) -> dict:
    if not isinstance(value, dict) or value.get("schema") != SETUP_SCHEMA:
        return {"status": "unavailable", "reason_code": "setup_guide_unavailable"}
    steps = value.get("steps")
    if not isinstance(steps, list):
        return {"status": "unavailable", "reason_code": "setup_guide_unavailable"}
    copied = {key: _copy(value[key]) for key in SETUP_FIELDS if key in value}
    copied["steps"] = [{key: _copy(step[key]) for key in SETUP_STEP_FIELDS if key in step}
                       for step in steps if isinstance(step, dict)]
    return {"status": "read", "reason_code": None, **copied}


def project(view, *, origin: dict, served_at: str, setup=None,
            setup_reason: Optional[str] = None, access: Optional[dict] = None,
            read_reason: Optional[str] = None) -> dict:
    """The document the browser receives. Never raises on a bad `view`."""

    from .status_view import AUTHORITY, SCHEMA as VIEW_SCHEMA

    model = {
        "schema": SCHEMA,
        "origin": _copy(origin),
        "served_at": served_at,
        # Fixed, never derived: who decides, and that nothing executed here.
        "authority": dict(AUTHORITY),
        "access": {name: word if word in ACCESS_WORDS else "unreadable"
                   for name, word in sorted((access or {}).items())},
        "sections": {},
        "pending": {},
    }
    if setup is not None:
        model["setup"] = _setup(setup)
    else:
        model["setup"] = {"status": "not_collected",
                          "reason_code": setup_reason or "setup_guide_not_collected"}
    sections = view.get("sections") if isinstance(view, dict) else None
    if (read_reason is not None or not isinstance(view, dict)
            or view.get("schema") != VIEW_SCHEMA or not isinstance(sections, dict)):
        model["read_model"] = {"status": "unavailable",
                               "reason_code": read_reason or "read_model_refused"}
        model.update(as_of=None, clock={"status": "unknown", "reason_code": "read_model_unavailable"},
                     lab_host=None)
        model["pending"] = {name: "read_model_unavailable"
                            for name in (*UI_SECTIONS, *PENDING_SECTIONS)}
        return model
    model["read_model"] = {"status": "read", "reason_code": None, "schema": VIEW_SCHEMA}
    model["as_of"] = view.get("as_of") if isinstance(view.get("as_of"), str) else None
    clock = view.get("clock")
    model["clock"] = _copy(clock) if isinstance(clock, dict) else {
        "status": "unknown", "reason_code": "clock_unknown"}
    model["lab_host"] = view.get("lab_host") is True
    for name in UI_SECTIONS:
        if name in sections:
            model["sections"][name] = _copy(sections[name])
        else:
            model["pending"][name] = "section_absent_from_read_model"
    for name, reason in PENDING_SECTIONS.items():
        if name in sections:
            model["sections"][name] = _copy(sections[name])
        else:
            model["pending"][name] = reason
    return model


def browser_json(value) -> bytes:
    """JSON safe to hand to a page: no `<`, `>`, `&` or line separators raw.

    The page parses it with `JSON.parse` and writes with `textContent`, so
    this is a second line: even a mistaken HTML sink would see no tag.
    """

    text = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True)
    for raw, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                         (" ", "\\u2028"), (" ", "\\u2029")):
        text = text.replace(raw, escaped)
    return text.encode("utf-8")
