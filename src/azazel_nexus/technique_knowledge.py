"""ATT&CK technique knowledge: request grammar, response validator, closed projection.

An observation-triggered Full Context query asks about techniques with typed
entities (`attack-technique/v1`, one per technique). The signed answer never
reaches M.I.O.: after the signature layer, `validate_technique_response`
accepts or refuses the whole response, `project_technique_response` reduces it
to the closed record `full_node_context.technique_knowledge`, and only that
record is stored, shown and handed off.

Four axes are kept apart and never merged into one "available" word:

* transport: `received` (a signed envelope arrived), `unavailable` (no usable
  answer), `refused` (declined locally or by the peer, an HTTP 422 included);
* verification: `ok`, `failed` (a 422 counts as failed) or `not_run`;
* coverage per technique: `found`, `no_match`, `stale`, `unavailable`;
* useful_content per technique: true exactly when coverage is `found`.

`name` and `tactics` are display-only labels. They are never copied into
observations, hypotheses, next checks, actions, the reasoning trace or
unknowns. A value outside the closed grammar fails the verification of the
whole response; a name that passes the grammar but reads like an instruction or
a causal claim is omitted (never truncated). Nothing here performs I/O.
"""

from __future__ import annotations

import re
from datetime import datetime

__all__ = [
    "COVERAGE_WORDS", "ENTITY_TYPE", "LIMITATIONS", "NAME_MAX", "NO_MATCH_UNKNOWN",
    "PROJECTION_VERSION", "SNAPSHOT_REF_PREFIX", "TACTICS", "TECHNIQUE_ID",
    "TRANSPORT_WORDS", "VERIFICATION_WORDS", "TechniqueVerificationFailed",
    "name_is_displayable", "not_run_projection", "project_technique_response",
    "read_projection", "request_ids", "validate_technique_response",
]

PROJECTION_VERSION = "technique-knowledge/1"
ENTITY_TYPE = "attack-technique/v1"
TECHNIQUE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?", re.ASCII)
MAX_TECHNIQUES = 8
#: One limit for the stored name, the UI and the handoff.
NAME_MAX = 120
TRANSPORT_WORDS = ("received", "unavailable", "refused")
VERIFICATION_WORDS = ("ok", "failed", "not_run")
COVERAGE_WORDS = ("found", "no_match", "stale", "unavailable")
_PAIRS = frozenset({("received", "ok"), ("received", "failed"), ("refused", "failed"),
                    ("refused", "not_run"), ("unavailable", "not_run")})
SNAPSHOT_STATES = ("complete", "partial", "stale")
TACTICS = ("collection", "command-and-control", "credential-access", "defense-evasion",
           "discovery", "execution", "exfiltration", "impact", "initial-access",
           "lateral-movement", "persistence", "privilege-escalation", "reconnaissance",
           "resource-development")
_VERSION = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}", re.ASCII)
SNAPSHOT_REF_PREFIX = "attack-stix@"
_REF = re.compile(r"attack-stix@(?:[0-9]{1,3}\.[0-9]{1,3}|none)", re.ASCII)
COVERAGE_PROVENANCE = ("knowledge:attack-coverage",)
CONTENT_PROVENANCE = ("knowledge:attack-stix",)
_PREDICATES = ("coverage", "technique_name", "tactics", "attack_version")
LIMITATIONS = (
    "ATT&CK technique labels are reference information and not evidence that the technique occurred.",
    "ATT&CK technique labels are not instructions for any response action.",
)
NO_MATCH_UNKNOWN = "At least one requested technique has no entry in the ATT&CK corpus."
_FACT_ID = re.compile(r"tq-([0-9]+)-([0-3])", re.ASCII)
# Letters and digits of any script, spaces and a few punctuation marks of real
# ATT&CK names. No dot, so an address or a host name cannot be written; no
# angle bracket, quote-less markup, backslash or scheme separator. A slash only
# between two letters ("Shutdown/Reboot"); two in a row would be a scheme.
_NAME_CHARS = re.compile(r"(?:[^\W_]|[ :,()'&+-]|(?<=[^\W_])/(?=[^\W_]))+")
#: Words an ATT&CK technique name has no use for: instructions and causal
#: claims. A name containing one is omitted from the projection.
_NAME_DENY = frozenset({
    "now", "immediately", "urgent", "urgently", "must", "should", "please", "ignore", "block",
    "isolate", "quarantine", "blacklist", "whitelist", "proves", "proof", "proven", "prove",
    "caused", "causes", "cause", "because", "therefore", "confirms", "confirmed", "confirm",
    "indicates", "indicating", "means", "culprit", "attributed", "instruct", "instructs",
    "run", "execute", "delete", "apply", "ban", "deny", "allow", "stop", "kill",
})


class TechniqueVerificationFailed(ValueError):
    """The response is not an acceptable technique answer; nothing of it is used."""


def _fail(*_):
    raise TechniqueVerificationFailed("technique_response_refused")


def _require(condition) -> None:
    if not condition:
        _fail()


def request_ids(ids) -> list[str]:
    """The sorted, unique technique ids of a request, or ValueError."""
    if type(ids) not in (list, tuple):
        raise ValueError("invalid_technique_set")
    codes = list(ids)
    if (not 1 <= len(codes) <= MAX_TECHNIQUES
            or any(type(c) is not str or not TECHNIQUE_ID.fullmatch(c) for c in codes)
            or codes != sorted(set(codes))):
        raise ValueError("invalid_technique_set")
    return codes


def _name_syntax(value) -> bool:
    return (type(value) is str and 1 <= len(value) <= NAME_MAX and value == value.strip()
            and "  " not in value and all(c.isprintable() for c in value)
            and _NAME_CHARS.fullmatch(value) is not None)


def name_is_displayable(value) -> bool:
    """Grammar plus the instruction and causal-claim screen (display only)."""
    if not _name_syntax(value):
        return False
    words = re.findall(r"[^\W_]+", value.lower())
    return not any(w in _NAME_DENY for w in words)


def _tactics_value(value) -> list[str]:
    _require(type(value) is str and value)
    parts = value.split(",")
    _require(all(p in TACTICS for p in parts) and parts == sorted(set(parts)))
    return parts


def _instant(value):
    _require(type(value) is str)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail()
    _require(parsed.tzinfo is not None)
    return parsed


def validate_technique_response(response, technique_ids) -> dict:
    """Accept or refuse a signature-verified response as a whole.

    `response` is the Fabric response in its JSON form; `technique_ids` the
    request's ids. Returns `{"snapshot_state", "techniques"}` with one entry
    per requested technique, or raises TechniqueVerificationFailed. A single
    violation anywhere refuses everything; nothing is repaired or truncated.
    """
    ids = request_ids(technique_ids)
    _require(type(response) is dict)
    _require(response.get("schema_version") == "knowledge-context-response/v1"
             and response.get("authority") == "advisory_only")
    snapshot = response.get("snapshot")
    _require(type(snapshot) is dict and set(snapshot) == {"ref", "state", "as_of"}
             and type(snapshot["ref"]) is str and _REF.fullmatch(snapshot["ref"])
             and snapshot["state"] in SNAPSHOT_STATES)
    _require(response.get("inferences") == [])
    facts = response.get("facts")
    _require(type(facts) is list and 0 < len(facts) <= 4 * MAX_TECHNIQUES)
    index = {tid: i for i, tid in enumerate(ids)}
    cursor = 0
    techniques: list[dict] = []
    for i, tid in enumerate(ids):
        # Coverage first, exactly once; found continues with three content facts.
        _require(cursor < len(facts))
        coverage = _fact(facts[cursor], index, i, 0, tid)
        _require(coverage in COVERAGE_WORDS)
        cursor += 1
        entry = {"technique_id": tid, "coverage": coverage, "useful_content": coverage == "found",
                 "name": None, "tactics": [], "attack_version": None}
        if coverage == "found":
            _require(cursor + 3 <= len(facts))
            entry["name"] = _fact(facts[cursor], index, i, 1, tid)
            _require(_name_syntax(entry["name"]))
            entry["tactics"] = _tactics_value(_fact(facts[cursor + 1], index, i, 2, tid))
            entry["attack_version"] = _fact(facts[cursor + 2], index, i, 3, tid)
            _require(type(entry["attack_version"]) is str and _VERSION.fullmatch(entry["attack_version"]))
            cursor += 3
        techniques.append(entry)
    _require(cursor == len(facts))
    coverages = [t["coverage"] for t in techniques]
    for uniform in ("stale", "unavailable"):
        _require(uniform not in coverages or all(c == uniform for c in coverages))
    found_versions = {t["attack_version"] for t in techniques if t["useful_content"]}
    state = snapshot["state"]
    generated, as_of = _instant(response.get("generated_at")), _instant(snapshot["as_of"])
    _require(as_of <= generated and _instant(response.get("expires_at")) > generated)
    if all(c == "found" for c in coverages):
        _require(state == "complete")
    elif "stale" in coverages or "unavailable" in coverages:
        _require(state == "stale")
    else:
        _require(state == "partial")
    if "unavailable" in coverages:
        _require(as_of == generated)
    # One corpus version: a found answer names it, and the snapshot agrees.
    if found_versions:
        _require(len(found_versions) == 1
                 and snapshot["ref"] == SNAPSHOT_REF_PREFIX + next(iter(found_versions)))
    unknowns, limitations = response.get("unknowns"), response.get("limitations")
    _require(unknowns == ([NO_MATCH_UNKNOWN] if "no_match" in coverages else []))
    _require(limitations == list(LIMITATIONS))
    return {"snapshot_state": state, "techniques": techniques}


def _fact(fact, index, i, n, tid):
    """The value of the n-th fact of technique i, after its fixed envelope."""
    _require(type(fact) is dict
             and set(fact) == {"claim_class", "fact_id", "subject", "predicate", "value", "provenance"}
             and fact["claim_class"] == "source_reported_fact")
    subject = fact["subject"]
    _require(type(subject) is dict and set(subject) == {"entity_type", "value"}
             and subject["entity_type"] == ENTITY_TYPE and subject["value"] == tid
             and index.get(subject["value"]) == i)
    _require(fact["fact_id"] == f"tq-{i}-{n}" and fact["predicate"] == _PREDICATES[n])
    _require(fact["provenance"] == list(COVERAGE_PROVENANCE if n == 0 else CONTENT_PROVENANCE))
    _require(type(fact["value"]) is str)
    return fact["value"]


def project_technique_response(response, technique_ids) -> dict:
    """The closed record for a validated response (validates again first)."""
    checked = validate_technique_response(response, technique_ids)
    rows = []
    for item in checked["techniques"]:
        row = dict(item)
        if row["name"] is not None and not name_is_displayable(row["name"]):
            row["name"] = None
        rows.append(row)
    return {"version": PROJECTION_VERSION, "transport": "received", "verification": "ok",
            "snapshot_state": checked["snapshot_state"], "techniques": rows}


def not_run_projection(transport: str, verification: str) -> dict:
    """The record of an attempt that produced no accepted answer."""
    value = {"version": PROJECTION_VERSION, "transport": transport, "verification": verification,
             "snapshot_state": None, "techniques": []}
    return read_projection(value)


def read_projection(value) -> dict:
    """Strict reader of the stored record; ValueError on anything else."""
    def bad():
        raise ValueError("technique_knowledge_refused")

    if (type(value) is not dict
            or set(value) != {"version", "transport", "verification", "snapshot_state", "techniques"}
            or value["version"] != PROJECTION_VERSION
            or type(value["transport"]) is not str or type(value["verification"]) is not str
            or (value["transport"], value["verification"]) not in _PAIRS):
        bad()
    rows = value["techniques"]
    if type(rows) is not list or len(rows) > MAX_TECHNIQUES:
        bad()
    if value["verification"] != "ok":
        if rows or value["snapshot_state"] is not None:
            bad()
        return value
    if (not rows or type(value["snapshot_state"]) is not str
            or value["snapshot_state"] not in SNAPSHOT_STATES):
        bad()
    seen = []
    for row in rows:
        if (type(row) is not dict
                or set(row) != {"technique_id", "coverage", "useful_content", "name", "tactics",
                                "attack_version"}):
            bad()
        tid, coverage = row["technique_id"], row["coverage"]
        if (type(tid) is not str or not TECHNIQUE_ID.fullmatch(tid)
                or type(coverage) is not str or coverage not in COVERAGE_WORDS
                or row["useful_content"] is not (coverage == "found")):
            bad()
        seen.append(tid)
        if coverage == "found":
            tactics = row["tactics"]
            if (row["name"] is not None and not name_is_displayable(row["name"])):
                bad()
            if (type(tactics) is not list or not tactics
                    or any(type(t) is not str or t not in TACTICS for t in tactics)
                    or tactics != sorted(set(tactics))
                    or type(row["attack_version"]) is not str
                    or not _VERSION.fullmatch(row["attack_version"])):
                bad()
        elif row["name"] is not None or row["tactics"] != [] or row["attack_version"] is not None:
            bad()
    if seen != sorted(set(seen)):
        bad()
    return value
