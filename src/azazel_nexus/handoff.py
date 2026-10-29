"""The expert handoff package (goal 2 F, S-19): one offline, read-only bundle.

`azazel-nexus handoff export` gathers what this node already recorded about
one incident and writes three files into a directory the operator names:

* `handoff.json` -- schema `azazel-nexus/handoff-package/1`;
* `handoff.ja.md` -- the same content for a person, in Japanese;
* `manifest.json` -- schema `azazel-nexus/handoff-manifest/1`: the SHA-256
  and size of the two files above. Its own digest is printed on the terminal
  so that it can be written down beside the media.

**What it reads, and nothing else.** Every source is an existing file read
through the reader its writer's tests already hold (`incident_explain`,
`edge_intake`, `operator_snapshots`, `noc_status`, `audit`):

| source | path | readable by |
| --- | --- | --- |
| incident ledger | `/var/lib/azazel/edge-incidents/*.jsonl` | root (`azincident-read`) |
| explanation ledger | `/var/lib/azazel/incident-explain/explanations/*.jsonl` | root |
| audit chain | `/var/lib/azazel/state/audit/*.jsonl` | root |
| Knowledge clock floor | `/var/lib/azazel/state/knowledge/clock-floor.json` | root |
| recent incidents, explainer and intake status | `/var/lib/azazel/run/{incident-explain,edge-intake}-status/` | operator group |
| Knowledge Lite, M.I.O., NOC snapshots | `/var/lib/azazel/run/{knowledge,mio,noc}-status/status.json` | operator group |
| timesyncd marker | `/run/systemd/timesync/synchronized` | everyone |

Root reads all of them. A member of `azazel-operator` reads the snapshots
only, and every ledger section then says `not_readable_by_principal` -- no
read permission is added for this command. Nothing opens a socket, starts a
process, or reads Edge's private evidence store (it holds raw payloads).

**What it never claims.** Edge's decisions reach Nexus observe-only
(`edge_intake` refuses anything else), so every action is `would` with
`executed: false`, no lease, no expiry and nothing to release. A section with
no material is `unavailable` with a reason code, never a healthy default. The
four kinds of statement are separate sections, each with its `authority`:
`observed_facts` (Edge's observation), `edge_decision` (Edge's deterministic
rules), `execution` (results: none), `ai_assessment` (advice, not fact).

**Confidentiality.** Built by allowlist, as `status_view` is. Addresses, rule
ids, ports, producer free text and operator identities are not copied; free
text that is copied (AI advice, Knowledge names and citations) has address,
MAC, path, URL and secret-like forms replaced, and every suppression is
counted in `confidentiality.suppressed`. A final scan refuses to write any
package in which such a form is still present. There is no upload: this
module has no transport and the package is only written to local storage.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import stat
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

__all__ = [
    "MANIFEST_SCHEMA", "SCHEMA", "HandoffRefused", "build_package", "encode_files",
    "find_incident", "principal_class", "render_markdown", "scan_for_leaks", "write_package",
]

SCHEMA = "azazel-nexus/handoff-package/1"
MANIFEST_SCHEMA = "azazel-nexus/handoff-manifest/1"
JSON_NAME = "handoff.json"
MARKDOWN_NAME = "handoff.ja.md"
MANIFEST_NAME = "manifest.json"
OPERATOR_GROUP = "azazel-operator"

#: A wall clock earlier than this is not a date this software ran on.
MIN_PLAUSIBLE_EPOCH = 1767225600  # 2026-01-01T00:00:00Z
#: A record dated this far after the generating clock is evidence of a clock
#: that moved backwards (the snapshot readers use the same five seconds).
FUTURE_SKEW_S = 5
#: Node-level audit events shown from this long before the incident opened.
AUDIT_WINDOW_BEFORE_S = 3600
#: Bounds: one incident is small; a ledger is not read without a ceiling.
MAX_TRANSITIONS = 256
MAX_EXPLANATIONS = 16
MAX_AUDIT_EVENTS = 128
MAX_SEGMENT_BYTES = 64 * 1024 * 1024
MAX_LEDGER_BYTES = 512 * 1024 * 1024
#: Room left beyond the package bytes, and per-file allocation slack.
SPACE_HEADROOM_BYTES = 1024 * 1024
SPACE_PER_FILE_BYTES = 64 * 1024
#: The output directory may not be inside product state.
REFUSED_OUTPUT_PREFIXES = ("/var/lib/azazel", "/etc/azazel", "/run", "/proc", "/sys", "/dev")

_INCIDENT_ID = re.compile(r"inc-[0-9a-f]{16}")
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}\.jsonl", re.ASCII)

# -- suppression patterns -----------------------------------------------------

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4 = re.compile(rf"(?<![0-9A-Za-z.]){_OCTET}(?:\.{_OCTET}){{3}}(?![0-9A-Za-z])")
#: Full eight-group IPv6, or any compressed form with `::`.
_HEX4 = r"[0-9A-Fa-f]{1,4}"
_IPV6 = re.compile(
    rf"(?<![0-9A-Za-z:])(?:(?:{_HEX4}:){{7}}{_HEX4}"
    rf"|{_HEX4}(?::{_HEX4}){{0,6}}::(?:{_HEX4}(?::{_HEX4}){{0,6}})?"
    rf"|::{_HEX4}(?::{_HEX4}){{0,6}})"
    r"(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])")
_MAC = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Za-z])")
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+|(?:^|(?<=\s))//\S+")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PATH = re.compile(r"(?:(?<=^)|(?<=[\s(\[`'\"=]))(?:~|\.{1,2})?/[\w.\-]+(?:/[\w.\-]*)*")
#: A host:port form (`gw.example:8443`).
_HOST_PORT = re.compile(r"(?<![\w.-])[A-Za-z][\w.-]*\.[A-Za-z]{2,}:\d{1,5}(?!\d)")
#: Interface names a Linux host gives (eth0, enp3s0, wlan0, wlp2s0, ...).
_INTERFACE = re.compile(r"(?<![\w-])(?:eth|en[opsx]|wl[opsx]?|wlan|ww[a-z]|br|bond|vlan|veth|tun|tap)"
                        r"[0-9][\w.-]*(?![\w-])")
_SECRET = re.compile(
    r"-----BEGIN [A-Z ]+-----|"
    r"(?i:\b(?:password|passwd|passphrase|secret|token|api[_-]?key|authorization|bearer)\b"
    r"\s*[:=]\s*\S+)|"
    r"(?<![\w:])(?![0-9a-f]{64}\b)[A-Za-z0-9+/_-]{40,}={0,2}(?![\w])")

#: In order: what each pattern is counted as.
_FREE_TEXT_RULES = (
    ("secret_like", _SECRET),
    ("url", _URL),
    ("email", _EMAIL),
    ("mac_address", _MAC),
    ("network_address", _IPV4),
    ("network_address", _IPV6),
    ("host_port", _HOST_PORT),
    ("interface_name", _INTERFACE),
    ("path", _PATH),
)

SUPPRESSION_CATEGORIES = (
    "network_address", "rule_identifier", "service_port", "producer_free_text",
    "operator_identity", "mac_address", "interface_name", "url", "email", "path",
    "host_port", "secret_like", "citation_text",
)


class HandoffRefused(Exception):
    """A fixed code; never exception text from below, which can quote a value."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Suppressor:
    """Counts what was left out, so that the package can say how much."""

    def __init__(self):
        self.counts = {name: 0 for name in SUPPRESSION_CATEGORIES}

    def drop(self, category: str, n: int = 1) -> None:
        self.counts[category] += n

    def text(self, value: str, limit: int = 4096) -> str:
        """Copy free text with every suppression form replaced by a marker."""

        text = unicodedata.normalize("NFKC", value)[:limit]
        text = "".join(c if c.isprintable() or c in "\n\t" else " " for c in text)
        for category, pattern in _FREE_TEXT_RULES:
            text, n = pattern.subn(f"[伏字:{category}]", text)
            if n:
                self.drop(category, n)
        return text


def scan_for_leaks(raw: bytes) -> list[str]:
    """Categories whose form survived into an encoded package (should be empty)."""

    text = raw.decode("utf-8")
    found = []
    for category, pattern in (("network_address", _IPV4), ("network_address", _IPV6),
                              ("mac_address", _MAC), ("url", _URL), ("email", _EMAIL),
                              ("secret_like", re.compile(r"-----BEGIN [A-Z ]+-----"))):
        if pattern.search(text) and category not in found:
            found.append(category)
    return found


# -- small readers ------------------------------------------------------------


def _iso(epoch) -> Optional[str]:
    if type(epoch) not in (int, float):
        return None
    try:
        return datetime.fromtimestamp(int(epoch), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _epoch(text) -> Optional[float]:
    if type(text) is not str or not text.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(text[:-1] + "+00:00").timestamp()
    except ValueError:
        return None


def _open_regular(path: Path, limit: int) -> tuple[Optional[bytes], str]:
    """`(bytes, "read")`, or `(None, code)`: absent, unreadable, or refused.

    No symbolic link is followed and only a regular file is read.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, "absent"
    except PermissionError:
        return None, "not_readable_by_principal"
    except OSError as exc:
        return None, "not_readable_by_principal" if exc.errno == errno.EACCES else "refused"
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, "refused"
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                return None, "refused"
            chunks.append(chunk)
        return b"".join(chunks), "read"
    except OSError:
        return None, "refused"
    finally:
        os.close(fd)


def _list_days(directory: Path) -> tuple[Optional[list[Path]], str]:
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        return None, "absent"
    except PermissionError:
        return None, "not_readable_by_principal"
    if not stat.S_ISDIR(info.st_mode):
        return None, "refused"
    try:
        names = os.listdir(directory)
    except PermissionError:
        return None, "not_readable_by_principal"
    except OSError:
        return None, "refused"
    return sorted(directory / name for name in names if _DAY.fullmatch(name)), "read"


def _snapshot(path: Path, reader, limit: int):
    raw, code = _open_regular(path, limit)
    if raw is None:
        return None, code
    try:
        value = reader(raw)
    except Exception:  # noqa: BLE001 - a reader that raises refuses
        value = None
    return (value, "read") if value is not None else (None, "refused")


# -- principals -----------------------------------------------------------------


def principal_class() -> Optional[str]:
    """`root`, `operator` (member of azazel-operator), or None (refused)."""
    if os.geteuid() == 0:
        return "root"
    try:
        import grp

        gid = grp.getgrnam(OPERATOR_GROUP).gr_gid
    except (KeyError, ImportError):
        return None
    return "operator" if gid in os.getgroups() or gid == os.getegid() else None


# -- sources ------------------------------------------------------------------


class Sources:
    """The fixed paths, under `AZAZEL_ROOT` when a test or the harness sets it."""

    def __init__(self, root=None):
        from . import runtime_paths as paths

        self.root = Path(os.environ.get("AZAZEL_ROOT", "/")) if root is None else Path(root)
        under = lambda p: self.root / p.lstrip("/")  # noqa: E731
        self.incidents = under("/var/lib/azazel/edge-incidents")
        self.explanations = under("/var/lib/azazel/incident-explain/explanations")
        self.audit = under("/var/lib/azazel/state/audit")
        self.knowledge_floor = under("/var/lib/azazel/state/knowledge/clock-floor.json")
        self.timesync = under("/run/systemd/timesync/synchronized")
        self.recent = paths.incident_recent_path(self.root)
        self.explainer_status = paths.incident_explain_status_path(self.root)
        self.intake_status = paths.edge_intake_status_path(self.root)
        self.knowledge_status = paths.knowledge_status_path(self.root)
        self.mio_status = paths.mio_status_path(self.root)
        self.noc_status = paths.noc_status_path(self.root)


def _chain_lines(path: Path, budget: list):
    """Parsed `(sequence, previous_hash, event_hash, event)` for each line.

    Each link is checked for its own hash; continuity is the caller's.
    """
    from .audit import canonical_event_bytes

    raw, code = _open_regular(path, MAX_SEGMENT_BYTES)
    if raw is None:
        raise HandoffRefused(code)
    budget[0] -= len(raw)
    if budget[0] < 0:
        raise HandoffRefused("ledger_too_large")
    if raw and not raw.endswith(b"\n"):
        raise HandoffRefused("ledger_tail_incomplete")
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line.decode("utf-8"))
            sequence, previous, digest, event = (entry["sequence"], entry["previous_hash"],
                                                 entry["event_hash"], entry["event"])
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise HandoffRefused("chain_broken") from None
        if (type(sequence) is not int or type(event) is not dict or type(previous) is not str
                or hashlib.sha256(previous.encode("ascii", "replace")
                                  + canonical_event_bytes(event)).hexdigest() != digest):
            raise HandoffRefused("chain_broken")
        yield sequence, previous, digest, event


def _read_chain(directory: Path, keep: Callable[[dict], bool], *, days_from=None):
    """Walk the daily segments in order; keep the matching events.

    Returns `(status, reason_code, kept, controls)`. `status` is `read`
    (continuity verified across what was read), `broken` or an access code.
    """
    days, code = _list_days(directory)
    if days is None:
        return code, code, [], []
    if days_from is not None:
        days = [d for d in days if d.name[:10] >= days_from]
    kept, controls, head, budget = [], [], None, [MAX_LEDGER_BYTES]
    try:
        for day in days:
            for sequence, previous, digest, event in _chain_lines(day, budget):
                if head is not None and (sequence != head[0] + 1 or previous != head[1]):
                    return "broken", "chain_broken", kept, controls
                head = (sequence, digest)
                if keep(event):
                    kept.append(event)
                elif event.get("event_type") in _CONTROL_TYPES:
                    controls.append(event)
    except HandoffRefused as refused:
        return ("broken" if refused.code in {"chain_broken", "ledger_tail_incomplete"}
                else refused.code), refused.code, kept, controls
    return "read", None, kept, controls


_CONTROL_TYPES = frozenset({"edge.incident.retention", "edge.incident.reset",
                            "edge.incident.truncated", "edge.incident.ledger_recovered"})


def find_incident(selector: str, *, root=None) -> Optional[str]:
    """An explicit id, or `latest`: the newest in the recent snapshot or ledger."""
    if _INCIDENT_ID.fullmatch(selector):
        return selector
    if selector != "latest":
        return None
    from .incident_explain import RECENT_BYTES, read_recent_incidents

    sources = Sources(root)
    recent, _ = _snapshot(sources.recent, read_recent_incidents, RECENT_BYTES)
    if recent and recent["incidents"]:
        return recent["incidents"][0]["incident_id"]
    _, _, kept, _ = _read_chain(
        sources.incidents, lambda e: str(e.get("event_type", "")).startswith("edge.incident.")
        and _INCIDENT_ID.fullmatch(str(e.get("incident_id", ""))) is not None)
    if kept:
        return max(kept, key=lambda e: (e.get("last_update", 0), e["incident_id"]))["incident_id"]
    return None


# -- the package --------------------------------------------------------------


def _unavailable(code, **extra) -> dict:
    return {"status": "unavailable", "reason_code": code, **extra}


def build_package(incident_id: str, *, now: float, principal: str, root=None,
                  provenance: str = "node") -> dict:
    """The package for one incident as a dict, or `HandoffRefused`.

    `provenance` is `node` from the CLI; the documentation's example passes
    `fixture` so that it can never be mistaken for a real node's record.
    """
    from .edge_intake import read_intake_status
    from .incident_explain import (
        CONTENT_LABELS, POLICY_REASONS, RECENT_BYTES, read_explainer_status,
        read_recent_incidents, read_record, read_transition,
    )
    from .noc_status import NOC_BYTES, read_noc_status
    from .operator_snapshots import (
        KNOWLEDGE_BYTES, MIO_BYTES, read_knowledge_status, read_mio_status,
    )

    if not _INCIDENT_ID.fullmatch(incident_id):
        raise HandoffRefused("incident_id_refused")
    if provenance not in ("node", "fixture") or principal not in ("root", "operator"):
        raise HandoffRefused("generator_refused")
    sources = Sources(root)
    hide = Suppressor()
    read_log = []
    future = []

    def note(name, code, readable_by):
        read_log.append({"source": name, "status": "read" if code == "read" else "unavailable",
                         "reason_code": None if code == "read" else code,
                         "readable_by": readable_by})

    def seen(epoch, what):
        if type(epoch) in (int, float) and epoch > now + FUTURE_SKEW_S:
            future.append(what)

    # Snapshots (operator group).
    recent, code = _snapshot(sources.recent, read_recent_incidents, RECENT_BYTES)
    note("recent_incidents_snapshot", code, "operator")
    explainer, code = _snapshot(sources.explainer_status, read_explainer_status, 8192)
    note("explainer_status_snapshot", code, "operator")
    intake, code = _snapshot(sources.intake_status, read_intake_status, 8192)
    note("intake_status_snapshot", code, "operator")
    knowledge_now, code = _snapshot(sources.knowledge_status, read_knowledge_status,
                                    KNOWLEDGE_BYTES)
    note("knowledge_status_snapshot", code, "operator")
    mio_now, code = _snapshot(sources.mio_status, read_mio_status, MIO_BYTES)
    note("mio_status_snapshot", code, "operator")
    noc, code = _snapshot(sources.noc_status, read_noc_status, NOC_BYTES)
    note("noc_status_snapshot", code, "operator")
    for value, what in ((recent, "recent"), (explainer, "explainer"), (intake, "intake"),
                        (knowledge_now, "knowledge"), (mio_now, "mio"), (noc, "noc")):
        if value is not None:
            seen(value.get("written_at"), what + "_snapshot")
    row = None
    if recent is not None:
        row = next((r for r in recent["incidents"] if r["incident_id"] == incident_id), None)

    # Incident ledger (root).
    def mine(event):
        return event.get("incident_id") == incident_id
    ledger_status, ledger_code, events, controls = _read_chain(sources.incidents, mine)
    transitions = []
    for event in events[:MAX_TRANSITIONS]:
        try:
            transitions.append(read_transition(event))
        except ValueError:
            ledger_status, ledger_code = "broken", "transition_refused"
    if ledger_status == "read" and not transitions:
        # Read, but this incident is not in what is retained.
        ledger_status, ledger_code = "not_retained", "incident_not_in_ledger"
    note("incident_ledger", "read" if ledger_status == "read" else ledger_code, "root")
    if not transitions and row is None:
        raise HandoffRefused("incident_not_found")

    # Explanation ledger (root). Plain JSON lines, not chained.
    explanations, explanation_code = [], "read"
    days, code = _list_days(sources.explanations)
    if days is None:
        explanation_code = code
    else:
        for day in days:
            raw, code = _open_regular(day, MAX_SEGMENT_BYTES)
            if raw is None:
                explanation_code = code
                break
            for line in raw.splitlines():
                if incident_id.encode() not in line:
                    continue
                try:
                    record = read_record(json.loads(line.decode("utf-8")))
                except (ValueError, UnicodeError):
                    explanation_code = "record_refused"
                    continue
                if record["incident_id"] == incident_id:
                    explanations.append(record)
    note("explanation_ledger", explanation_code, "root")
    explanations = explanations[-MAX_EXPLANATIONS:]

    # Audit chain (root).
    first_seen = (transitions[0]["first_seen"] if transitions
                  else row["first_seen"] if row else now)
    window_from = first_seen - AUDIT_WINDOW_BEFORE_S
    day_from = (_iso(window_from) or "0000-00-00")[:10]

    def relevant(event):
        kind = str(event.get("event_type", ""))
        if kind.startswith("edge.incident."):
            return event.get("incident_id") == incident_id
        at = _epoch(event.get("occurred_at"))
        return kind in OPERATOR_EVENT_FIELDS and at is not None and window_from <= at
    audit_status, audit_code, audit_events, _ = _read_chain(sources.audit, relevant,
                                                            days_from=day_from)
    note("audit_chain", "read" if audit_status == "read" else audit_code, "root")

    # Clock.
    clock = _clock(sources, now, note)
    for t in transitions:
        for key in ("first_seen", "last_seen", "last_update"):
            seen(t[key], "incident_ledger")
    for record in explanations:
        seen(record["explained_at"], "explanation_ledger")
    for event in audit_events:
        seen(_epoch(event.get("occurred_at")), "audit_chain")
    if row is not None:
        seen(row["last_seen"], "recent_snapshot")
    for snap, name in ((intake, "intake"), (explainer, "explainer")):
        if snap is not None and snap["refused"].get("segment_from_future"):
            clock["signals"].append(name + "_segment_from_future")
    if future:
        clock["signals"].append("records_dated_after_generation")
        clock["future_dated_sources"] = sorted(set(future))
    if clock["signals"]:
        clock["status"] = "untrusted"
        clock["reason_code"] = clock["signals"][0]

    # Observed facts, decisions, execution.
    observed = _observed(transitions, row, ledger_status, ledger_code, controls, hide)
    decision = _decision(transitions, row, POLICY_REASONS)
    execution = _execution(decision, intake)
    evidence = _evidence(transitions, ledger_status, ledger_code)

    ai = _ai(explanations, explanation_code, row, mio_now, now, CONTENT_LABELS, hide)
    knowledge = _knowledge(explanations, explanation_code, row, knowledge_now, now, hide)
    operator = _operator(audit_events, audit_status, audit_code, window_from, now,
                         hide)
    impact = _impact(noc, now, execution)
    loop = _loop(intake, explainer, now)

    package = {
        "schema": SCHEMA,
        "provenance": provenance,
        "generated_at": _iso(now),
        "generator": {"command": "azazel-nexus handoff export", "principal_class": principal,
                      "network_used": False, "uploaded": False,
                      "nexus_version": _version()},
        "authority": {
            "decision_and_enforcement": "edge",
            "nexus": "observe_explain_advise",
            "edge_decisions": "would_not_executed",
            "ai": "advisory_only_not_fact",
            "this_package": "record_not_instruction",
        },
        "incident": {"incident_id": incident_id,
                     "state": ("closed" if any(t["event_type"] == "edge.incident.closed"
                                               for t in transitions)
                               else row["state"] if row else "open")},
        "time": {"occurred_at": _iso(first_seen) if (transitions or row) else None,
                 "occurred_at_source": ("incident_ledger.first_seen" if transitions
                                        else "recent_snapshot.first_seen"),
                 "last_seen": _iso(max(t["last_seen"] for t in transitions) if transitions
                                   else row["last_seen"]),
                 "basis": "node_wall_clock_at_intake",
                 "clock": clock},
        "observed_facts": observed,
        "edge_decision": decision,
        "execution": execution,
        "ai_assessment": ai,
        "business_impact": impact,
        "evidence_refs": evidence,
        "knowledge": knowledge,
        "operator_actions": operator,
        "loop_health": loop,
    }
    package["sources"] = read_log
    package["unconfirmed"] = _unconfirmed(package)
    package["confidentiality"] = {
        "policy": "allowlist_default_suppressed",
        "suppressed": {k: v for k, v in hide.counts.items()},
        "suppressed_total": sum(hide.counts.values()),
        "not_read": ["edge_evidence_payloads", "decoy_evidence", "commissioning_record",
                     "secrets_directory", "interface_identity", "torn_tail_quarantine"],
        "raw_payload_included": False,
        "upload": "none",
        "external_release": "operator_decision_outside_this_tool",
    }
    return package


def _version() -> str:
    from . import __version__

    return __version__


def _clock(sources: Sources, now: float, note) -> dict:
    clock = {"status": "unverified", "reason_code": "no_synchronization_evidence",
             "generated_at": _iso(now), "signals": []}
    if now < MIN_PLAUSIBLE_EPOCH:
        clock["signals"].append("wall_clock_implausible")
    # timesyncd's marker, read as `activation_clock_sync` reads it.
    marker = "absent"
    try:
        directory = os.lstat(sources.timesync.parent)
        info = os.lstat(sources.timesync)
        if (stat.S_ISDIR(directory.st_mode) and stat.S_ISREG(info.st_mode)
                and not (directory.st_mode | info.st_mode) & 0o022):
            marker = "present"
        else:
            marker = "refused"
    except FileNotFoundError:
        marker = "absent"
    except OSError:
        marker = "refused"
    clock["synchronized_this_boot"] = {
        "status": marker, "source": "timesyncd_marker",
        "means": "a synchronization happened in this boot; not that it is still synchronized "
                 "or that the time source was authenticated"}
    note("timesyncd_marker", "read" if marker != "refused" else "refused", "everyone")
    raw, code = _open_regular(sources.knowledge_floor, 256)
    floor = {"status": "unavailable", "reason_code": code, "floor_utc": None}
    if raw is not None:
        try:
            document = json.loads(raw.decode("utf-8"))
            if (type(document) is not dict
                    or set(document) != {"floor_utc", "schema"}
                    or document["schema"] != "azazel-nexus/knowledge-clock-floor/v1"
                    or _epoch(document["floor_utc"]) is None
                    or json.dumps(document, sort_keys=True, separators=(",", ":")).encode() + b"\n"
                    != raw):
                raise ValueError
            at = _epoch(document["floor_utc"])
            floor = {"status": "read", "reason_code": None, "floor_utc": document["floor_utc"],
                     "now_behind_floor": now < at}
            if now < at:
                clock["signals"].append("wall_clock_behind_knowledge_floor")
        except (ValueError, UnicodeError):
            code = "refused"
            floor = {"status": "unavailable", "reason_code": "refused", "floor_utc": None}
    note("knowledge_clock_floor", code if raw is None or floor["status"] != "read" else "read",
         "root")
    clock["knowledge_floor"] = floor
    if marker == "present":
        clock["status"], clock["reason_code"] = "synchronized_this_boot", None
    return clock


def _observed(transitions, row, ledger_status, ledger_code, controls, hide) -> dict:
    from .incident_explain import CATEGORIES

    if transitions:
        rows = []
        for t in transitions:
            # Never copied: src_ip, sid, target_port, attack_type (producer text).
            hide.drop("network_address", 1 if t["src_ip"] else 0)
            hide.drop("rule_identifier")
            hide.drop("service_port")
            hide.drop("producer_free_text", 1 + ("category" in t and t["category"] not in CATEGORIES))
            rows.append({
                "event_type": t["event_type"].removeprefix("edge.incident."),
                "at": _iso(t["last_update"]),
                "first_seen": _iso(t["first_seen"]), "last_seen": _iso(t["last_seen"]),
                "count": t["count"], "most_severe": t["most_severe"],
                "technique_ids": list(t["technique_ids"]),
                "category": t.get("category") if t.get("category") in CATEGORIES else "other",
                "protocol": t.get("protocol") if t.get("protocol") in ("tcp", "udp", "icmp") else "other",
                "close_reason": t.get("reason"),
                "evidence_stored": "evidence_stored" not in t,
            })
        section = {
            "status": "available" if ledger_status == "read" else "partial",
            "reason_code": None if ledger_status == "read" else ledger_code,
            "authority": "edge_observation", "source": "incident_ledger",
            "summary": {"first_seen": _iso(transitions[0]["first_seen"]),
                        "last_seen": _iso(max(t["last_seen"] for t in transitions)),
                        "count": max(t["count"] for t in transitions),
                        "most_severe": min(t["most_severe"] for t in transitions),
                        "technique_ids": sorted({i for t in transitions for i in t["technique_ids"]}),
                        "category": rows[-1]["category"], "protocol": rows[-1]["protocol"],
                        "severity_scale": "1 = most severe (Suricata priority)"},
            "transitions": rows,
            "ledger": {"chain": "verified_continuity_of_retained_segments"
                       if ledger_status == "read" else ledger_status,
                       "gaps": [{"kind": c["event_type"].removeprefix("edge.incident."),
                                 "at": _iso(c.get("at"))} for c in controls[:32]]},
            "withheld_fields": ["source_address", "rule_id", "destination_port", "signature_text"],
        }
        return section
    section = _unavailable(ledger_code, authority="edge_observation")
    if row is not None:
        section.update(status="partial", source="recent_snapshot", summary={
            "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"]),
            "count": row["count"], "most_severe": row["most_severe"],
            "technique_ids": list(row["technique_ids"]),
            "severity_scale": "1 = most severe (Suricata priority)"},
            transitions=[], ledger={"chain": ledger_status, "gaps": []})
    return section


def _decision(transitions, row, reasons) -> dict:
    decisions = [{"at": _iso(t["last_update"]), "action": t["edge_would"],
                  "policy_reason": t["policy_reason"] if t["policy_reason"] in reasons else "other",
                  "kind": "would", "executed": False} for t in transitions]
    if not decisions and row is not None:
        decisions = [{"at": _iso(row["last_seen"]), "action": row["edge_would"],
                      "policy_reason": row["policy_reason"], "kind": "would", "executed": False}]
    if not decisions:
        return _unavailable("no_decision_recorded", authority="edge_deterministic_rules")
    return {"status": "available", "reason_code": None, "authority": "edge_deterministic_rules",
            "decided_by": "edge", "latest": decisions[-1], "decisions": decisions[-MAX_TRANSITIONS:]}


def _execution(decision, intake) -> dict:
    actions = []
    for d in decision.get("decisions", []):
        if d["action"] != "observe" and d["action"] not in [a["action"] for a in actions]:
            actions.append({"action": d["action"], "state": "would", "executed": False,
                            "lease": {"status": "not_applicable", "reason_code": "not_executed"},
                            "expires_at": None,
                            "release": {"status": "not_applicable", "reason_code": "not_executed"}})
    refusals = None if intake is None else intake["refused"].get("EDGE_NOT_OBSERVE_ONLY", 0)
    return {"status": "not_executed", "reason_code": "nexus_accepts_observe_only",
            "authority": "execution_result",
            "automatic_actions": actions,
            "executed_count": 0,
            "means": "Edge reported what it would do; Nexus accepts observe-only events, "
                     "so no restriction, redirect or isolation was executed through Nexus",
            "intake_refused_not_observe_only": refusals}


def _evidence(transitions, ledger_status, ledger_code) -> dict:
    refs, seen = [], set()
    for t in transitions:
        for role, key in (("first", "first_evidence"), ("latest", "latest_evidence")):
            digest = t[key]
            if digest in seen:
                continue
            seen.add(digest)
            refs.append({"kind": "edge_evidence_record", "source": "edge-core",
                         "digest": digest, "role": role, "cited_at": _iso(t["last_update"]),
                         "content_included": False,
                         "held_at": "node private evidence store (retention 14 days or 256 MiB)"})
    missing = sum(1 for t in transitions if "evidence_stored" in t)
    if not transitions:
        return _unavailable(ledger_code or "no_transition", refs=[],
                            raw_payload_included=False)
    return {"status": "available" if not missing else "partial",
            "reason_code": None if not missing else "evidence_not_stored",
            "refs": refs[:64], "transitions_with_evidence_not_stored": missing,
            "raw_payload_included": False,
            "retention_checked": False,
            "note": "digests only; whether the record is still retained was not checked "
                    "(the store is private)"}


def _ai(explanations, explanation_code, row, mio_now, now, labels, hide) -> dict:
    capability = _unavailable("snapshot_unavailable")
    if mio_now is not None:
        capability = {"status": "read", "recorded": mio_now["recorded"], "state": mio_now["state"],
                      "ceiling": mio_now["ceiling"], "observed_at": mio_now["observed_at"],
                      "record_uncertain": mio_now["record_uncertain"],
                      "snapshot_age_s": max(0, int(now - mio_now["written_at"]))}
    base = {"authority": "advisory_only_not_fact", "route_capability_now": capability,
            "label_basis": "the explainer's content_kind: every answered local-route reply is "
                           "labelled AI advice, whether a model generated text or the local "
                           "route matched deterministically; which one is not recorded",
            "model_identity": _unavailable("model_identity_not_recorded_in_explanation_ledger"),
            "remote_route": "not_used_by_incident_explainer"}
    if explanations:
        items = []
        for record in explanations:
            m = record["mio"]
            from .incident_explain import content_kind

            kind = content_kind(m)
            items.append({
                "explained_at": _iso(record["explained_at"]), "transition": record["transition"],
                "route": m["route"], "outcome": m["outcome"],
                "local_route_answered": m["route"] == "local" and m["outcome"] == "answered",
                "content_kind": kind, "content_label": labels.get(kind, kind),
                "labelled_ai_output": kind == "ai_advice",
                "generation_method": "not_recorded",
                "text": hide.text(m["text"]) if m["text"] else None,
                "notice": m.get("notice"),
                "failure_codes": list(record["failure_codes"])})
        return {"status": "available", "reason_code": None, "source": "explanation_ledger",
                **base, "explanations": items}
    if row is not None and row["explanation"]["state"] != "pending":
        e = row["explanation"]
        kind = e.get("content_kind")
        return {"status": "partial", "reason_code": explanation_code,
                "source": "recent_snapshot", **base, "explanations": [{
                    "explained_at": None, "transition": None, "route": e["route"],
                    "outcome": e["outcome"],
                    "local_route_answered": e["route"] == "local" and e["outcome"] == "answered",
                    "content_kind": kind, "content_label": labels.get(kind, "unlabelled"),
                    "labelled_ai_output": e["state"] == "explained",
                    "generation_method": "not_recorded",
                    "text": hide.text(e["summary"]) if e["summary"] else None,
                    "text_is_summary": True, "notice": e.get("notice"),
                    "failure_codes": list(e["failure_codes"])}]}
    code = explanation_code if explanation_code != "read" else (
        "explanation_pending" if row is not None and row["explanation"]["state"] == "pending"
        else "no_explanation_recorded")
    return {**_unavailable(code), **base, "explanations": []}


def _knowledge(explanations, explanation_code, row, knowledge_now, now, hide) -> dict:
    current = _unavailable("snapshot_unavailable")
    if knowledge_now is not None:
        current = {"status": "read", "state": knowledge_now["state"],
                   "reason_code": knowledge_now["reason_code"],
                   "generation": knowledge_now["generation"],
                   "freshness": knowledge_now["freshness"],
                   "snapshot_written_at": _iso(knowledge_now["written_at"]),
                   "snapshot_age_s": max(0, int(now - knowledge_now["written_at"]))}

    def ref_age(as_of):
        at = _epoch(as_of)
        return None if at is None else int(now - at)

    citations, state = [], None
    if explanations:
        seen = set()
        for record in explanations:
            state = record["knowledge_state"]
            for ref in record["knowledge_refs"]:
                key = (ref["claim_id"], ref["bundle_digest"], ref["generation"])
                if key in seen:
                    continue
                seen.add(key)
                citation = ref["citation"]
                if citation and (hide.text(citation, 160) != citation):
                    hide.drop("citation_text")
                    citation, citation_state = "", "withheld"
                else:
                    citation_state = "shown" if citation else "none"
                citations.append({
                    "technique_id": ref["technique_id"], "claim_id": ref["claim_id"],
                    "name": hide.text(ref["name"], 120), "summary": hide.text(ref["summary"], 240),
                    "bundle_digest": ref["bundle_digest"], "generation": ref["generation"],
                    "freshness_at_lookup": ref["freshness"], "looked_up_at": ref["as_of"],
                    "age_s_at_generation": ref_age(ref["as_of"]),
                    "trust_check": ref["trust_check"], "source_kind": ref["source_kind"],
                    "citation": citation, "citation_state": citation_state,
                    "generation_now": current.get("generation"),
                    "superseded": (type(current.get("generation")) is int
                                   and current["generation"] != ref["generation"])})
        source, status = "explanation_ledger", "available" if citations else "unavailable"
        code = None if citations else ("knowledge_" + (state or "skipped"))
    elif row is not None and row["explanation"]["knowledge_refs"]:
        for ref in row["explanation"]["knowledge_refs"]:
            citations.append({
                "technique_id": ref["technique_id"], "claim_id": ref["claim_id"],
                "name": hide.text(ref["name"], 120),
                "bundle_digest_short": ref.get("bundle_digest_short"),
                "generation": ref.get("generation"),
                "freshness_at_lookup": ref.get("freshness"), "looked_up_at": ref.get("as_of"),
                "age_s_at_generation": ref_age(ref.get("as_of")),
                "citation_state": ref.get("citation_state", "none")})
        source, status, code = "recent_snapshot", "partial", explanation_code
    else:
        source, status = None, "unavailable"
        code = explanation_code if explanation_code != "read" else "no_citation_recorded"
    return {"status": status, "reason_code": code, "authority": "knowledge_advisory",
            "source": source, "citations": citations, "lite_now": current}


#: Node-level audit events an operator or administrator causes, and the
#: fields copied from each (identities, digests and paths never).
OPERATOR_EVENT_FIELDS = {
    "activation.unit_granted": ("unit", "generation"),
    "activation.unit_withheld": ("unit", "generation", "reason"),
    "knowledge.lite.import_admitted": ("bundle_version",),
    "knowledge.lite.import_refused": ("code",),
    "knowledge.lite.import_quarantined": ("gate",),
    "knowledge.lite.revocation_requested": (),
    "knowledge.lite.revocation_accepted": ("generation",),
    "knowledge.lite.revocation_refused": ("code",),
    "watchdog.fenced": ("unit", "reason"),
    "bootstrap.ready": ("unit_key",),
    "bootstrap.stopped": (),
}


def _operator(events, status, code, window_from, now, hide) -> dict:
    incident_audit, node = [], []
    for event in events:
        kind = event["event_type"]
        if kind.startswith("edge.incident."):
            incident_audit.append({"event_type": kind, "occurred_at": event.get("occurred_at"),
                                   "most_severe": event.get("most_severe"),
                                   "edge_would": event.get("edge_would")})
            continue
        if "actor" in event:
            hide.drop("operator_identity")
        node.append({"event_type": kind, "occurred_at": event.get("occurred_at"),
                     **{k: event.get(k) for k in OPERATOR_EVENT_FIELDS[kind]},
                     "actor": "withheld" if "actor" in event else None})
    section = {
        "status": "available" if status == "read" else "unavailable",
        "reason_code": None if status == "read" else code,
        "source": "audit_chain",
        "chain": "verified_continuity_of_segments_read" if status == "read" else status,
        "incident_scoped": _unavailable("no_operator_action_record_type_for_incidents"),
        "window": {"from": _iso(window_from), "to": _iso(now)},
        "node_actions": node[-MAX_AUDIT_EVENTS:],
        "node_actions_omitted": max(0, len(node) - MAX_AUDIT_EVENTS),
        "incident_audit": incident_audit[-MAX_AUDIT_EVENTS:],
        "means": "Nexus records no acknowledgement or approval of an incident; listed are "
                 "node-level actions in the window, not actions taken on this incident",
    }
    return section


def _impact(noc, now, execution) -> dict:
    observed = _unavailable("noc_snapshot_unavailable")
    if noc is not None and noc["collection"] == "failed":
        observed = _unavailable(noc["reason_code"] or "collection_failed",
                                observed_at=_iso(noc["written_at"]))
    elif noc is not None:
        listed = noc["interfaces"]
        listed = listed["value"] if listed["state"] == "observed" else None
        interfaces = [i for i in listed or ()
                      if not (i["loopback"]["state"] == "observed" and i["loopback"]["value"])]

        def count(name, wanted):
            return sum(1 for i in interfaces
                       if i[name]["state"] == "observed" and i[name]["value"] == wanted)
        routes = None
        try:
            family = noc["uplink"]["ipv4"]
            if family["state"] == "observed":
                routes = family["value"]["table_main"]["default_routes"]
        except (KeyError, TypeError):
            routes = None
        observed = {"status": "observed", "reason_code": noc["reason_code"],
                    "observation": "passive", "observed_at": _iso(noc["written_at"]),
                    "snapshot_age_s": max(0, int(now - noc["written_at"])),
                    "interfaces": None if listed is None else len(interfaces),
                    "interfaces_omitted": noc["interfaces_omitted"],
                    "carrier_up": count("carrier", True),
                    "carrier_down": count("carrier", False),
                    "ipv4_default_routes": routes,
                    "reachability": {"status": "not_measured",
                                     "reason_code": "active_check_not_performed"},
                    "identity": "interfaces counted only; names, addresses and gateways withheld"}
    return {"assessment": _unavailable("business_impact_not_assessed_by_node"),
            "connectivity_observed": observed,
            "restrictions_executed_by_nexus": execution["executed_count"],
            "means": "The node does not know which services matter to the business. The "
                     "operator states the impact to the expert directly."}


def _loop(intake, explainer, now) -> dict:
    def snap(value, fields):
        if value is None:
            return _unavailable("snapshot_unavailable")
        return {"status": "read", "written_at": _iso(value["written_at"]),
                "age_s": max(0, int(now - value["written_at"])),
                **{k: value[k] for k in fields},
                "refused": {k: v for k, v in sorted(value["refused"].items())}}
    return {"intake": snap(intake, ("storage_failed",)),
            "explainer": snap(explainer, ("chain_broken", "storage_failed", "mio_available",
                                          "knowledge_available"))}


_UNCONFIRMED_JA = {
    "edge_judgement_unreviewed": "Edge の判断（would）が妥当かは人が確認していない",
    "evidence_content_not_included": "証拠の中身（生データ）は含めていない。必要なら digest で現地に依頼する",
    "business_impact_not_assessed": "業務影響はノードでは評価していない。担当者が直接伝える",
    "source_address_withheld": "送信元アドレス・ルール番号・宛先ポートは伏せている",
    "ai_advice_unverified": "AI の見解は推測であり検証されていない",
    "no_ai_answer": "AI の回答はない（決定論的経路または利用不可）",
    "clock_untrusted": "時計が信頼できない兆候がある。時刻は前後し得る",
    "clock_unverified": "時計の同期を示す証拠がない",
    "incident_ledger_unavailable": "インシデント台帳を読めていない（root で実行すると読める）",
    "explanation_ledger_unavailable": "説明台帳を読めていない（root で実行すると読める）",
    "audit_unavailable": "監査記録を読めていない（root で実行すると読める）",
    "ledger_gap": "インシデント台帳に欠落・切詰め・回復の記録がある",
    "evidence_not_stored": "一部の証拠は保存されていない（容量上限）",
    "knowledge_superseded": "引用した Knowledge の世代は現在の世代と異なる",
    "knowledge_unavailable": "Knowledge の引用がない、または読めていない",
    "incident_open": "インシデントはまだ閉じていない（生成後も続く可能性がある）",
}


def _unconfirmed(p) -> list:
    items = ["edge_judgement_unreviewed", "evidence_content_not_included",
             "business_impact_not_assessed", "source_address_withheld"]
    explanations = p["ai_assessment"].get("explanations", [])
    if any(e["labelled_ai_output"] for e in explanations):
        items.append("ai_advice_unverified")
    else:
        items.append("no_ai_answer")
    clock = p["time"]["clock"]["status"]
    if clock == "untrusted":
        items.append("clock_untrusted")
    elif clock == "unverified":
        items.append("clock_unverified")
    sources = {s["source"]: s for s in p["sources"]}
    if sources["incident_ledger"]["status"] != "read":
        items.append("incident_ledger_unavailable")
    if sources["explanation_ledger"]["status"] != "read":
        items.append("explanation_ledger_unavailable")
    if sources["audit_chain"]["status"] != "read":
        items.append("audit_unavailable")
    if p["observed_facts"].get("ledger", {}).get("gaps"):
        items.append("ledger_gap")
    if p["evidence_refs"].get("transitions_with_evidence_not_stored"):
        items.append("evidence_not_stored")
    if any(c.get("superseded") for c in p["knowledge"]["citations"]):
        items.append("knowledge_superseded")
    if p["knowledge"]["status"] == "unavailable":
        items.append("knowledge_unavailable")
    if p["incident"]["state"] != "closed":
        items.append("incident_open")
    return [{"code": code, "text_ja": _UNCONFIRMED_JA[code]} for code in items]


# -- rendering ----------------------------------------------------------------

_MD_SPECIAL = re.compile(r"([\\`*_\[\]{}()<>#+!|~])")


def _md(value) -> str:
    """Inline text with Markdown and HTML syntax escaped."""
    if value is None:
        return "（なし）"
    text = str(value).replace("\r", " ").replace("\n", " ")
    return _MD_SPECIAL.sub(r"\\\1", text)


def _state_ja(section) -> str:
    status = section.get("status")
    code = section.get("reason_code")
    words = {"available": "あり", "partial": "一部のみ", "unavailable": "なし",
             "read": "読取済", "observed": "観測済", "not_executed": "実行なし"}
    word = words.get(status, str(status))
    if status in ("read", "available", "observed"):
        return word
    return word + (f"（理由: `{code}`）" if code else "")


def render_markdown(p: dict) -> str:
    lines = []
    add = lines.append
    add("# 専門家への引継ぎパッケージ")
    add("")
    if p["provenance"] == "fixture":
        add("> **これは試験用 fixture から生成した例です。実在のノード・インシデントの記録ではありません。**")
        add("")
    add(f"- インシデント: `{p['incident']['incident_id']}`（状態: {_md(p['incident']['state'])}）")
    add(f"- 生成時刻: {_md(p['generated_at'])}（ノードの時計。信頼性は §1）")
    add(f"- 生成者の権限区分: {_md(p['generator']['principal_class'])}"
        "（root 以外では台帳を読めず、その欄は「なし」になる）")
    add("- 送信: していない。このパッケージはローカルに保存しただけで、どこにもアップロードしていない。")
    add("- 判断と執行の権限は Edge にある。Nexus は観測・説明・助言のみ。AI の見解は事実ではない。")
    add("")
    add("各欄は「観測事実」「Edge の判断」「実行結果」「AI の推測」を分けて書いている。"
        "材料がない欄は正常値で埋めず「なし」と理由を書いている。")
    add("")

    t = p["time"]
    c = t["clock"]
    add("## 1. 発生時刻と時刻の信頼性")
    add("")
    add(f"- 発生時刻（初観測）: {_md(t['occurred_at'])}（出典: `{t['occurred_at_source']}`）")
    add(f"- 最終観測: {_md(t['last_seen'])}")
    add(f"- 時計の状態: `{c['status']}`" + (f"（`{c['reason_code']}`）" if c["reason_code"] else ""))
    add(f"- 起動後の時刻同期の記録: {_md(c['synchronized_this_boot']['status'])}"
        "（同期が一度あったことを示すだけで、今も正しいこと・時刻源の真正性は示さない）")
    floor = c["knowledge_floor"]
    add(f"- Knowledge の時計の床: {_md(floor['floor_utc'])}（{_state_ja(floor)}）")
    if c["signals"]:
        add("- 時計を疑う兆候: " + "、".join(f"`{s}`" for s in c["signals"]))
    add("")

    o = p["observed_facts"]
    add("## 2. 観測事実（Edge の観測）")
    add("")
    add(f"状態: {_state_ja(o)}")
    s = o.get("summary")
    if s:
        add("")
        add(f"- 観測期間: {_md(s['first_seen'])} 〜 {_md(s['last_seen'])}")
        add(f"- 件数: {s['count']}、最も高い重大度: {s['most_severe']}（1 が最も重い）")
        add(f"- ATT&CK 技術: {_md(', '.join(s['technique_ids']) or 'なし')}")
        if "category" in s:
            add(f"- 分類: {_md(s['category'])}、プロトコル: {_md(s['protocol'])}")
    if o.get("transitions"):
        add("")
        add("| 時刻 | 遷移 | 件数 | 重大度 | 証拠保存 |")
        add("| --- | --- | --- | --- | --- |")
        for r in o["transitions"]:
            add(f"| {_md(r['at'])} | {_md(r['event_type'])} | {r['count']} | {r['most_severe']} | "
                f"{'あり' if r['evidence_stored'] else '**なし**'} |")
    if o.get("ledger", {}).get("gaps"):
        add("")
        add("台帳の欠落・切詰め・回復: " + "、".join(
            f"{_md(g['kind'])}（{_md(g['at'])}）" for g in o["ledger"]["gaps"]))
    add("")
    add("伏せた欄: 送信元アドレス、ルール番号、宛先ポート、シグネチャ本文。")
    add("")

    d = p["edge_decision"]
    add("## 3. Edge の判断（決定論的規則による would）")
    add("")
    add(f"状態: {_state_ja(d)}")
    if d.get("latest"):
        add(f"- 最新: Edge なら **{_md(d['latest']['action'])}** する"
            f"（規則: `{d['latest']['policy_reason']}`）。**実行されていない**。")
    add("")

    e = p["execution"]
    add("## 4. 自動対処・期限・解除（実行結果）")
    add("")
    add(f"- 実行結果: **実行なし**（`{e['reason_code']}`）。Nexus は observe-only の事象だけを受け付ける。")
    for a in e["automatic_actions"]:
        add(f"- {_md(a['action'])}: would（未実行）。期限: なし、リース: 該当なし、解除: 該当なし（未実行のため）")
    if not e["automatic_actions"]:
        add("- 対処の候補: observe のみ")
    add("")

    ai = p["ai_assessment"]
    add("## 5. AI の見解（推測。事実ではない）")
    add("")
    add(f"状態: {_state_ja(ai)}")
    cap = ai["route_capability_now"]
    add(f"- モデルの識別: なし（`{ai['model_identity']['reason_code']}`）")
    add(f"- 現在の M.I.O. 経路の能力: {_state_ja(cap)}"
        + (f" 記録された能力 `{cap.get('state')}`" if cap.get("status") == "read" else ""))
    add("- 外部（リモート）AI: インシデント説明では使っていない")
    add("- 注意: 説明器はローカル経路の回答をすべて「AI の助言」と区分する。モデルが文章を生成したのか、"
        "決定論的な照合で答えたのかは記録されていない（`generation_method: not_recorded`）。")
    for x in ai.get("explanations", []):
        add("")
        label = ("説明器の区分では AI の助言" if x["labelled_ai_output"]
                 else "AI の出力ではない")
        add(f"### {_md(x['explained_at'] or '時刻不明')} — 経路 `{x['route']}`（{label}: {_md(x['content_label'])}）")
        add("")
        if x.get("text"):
            add("> " + _md(x["text"]))
        if x.get("notice"):
            add("")
            add("> " + _md(x["notice"]))
        if x["failure_codes"]:
            add("")
            add("失敗・制限の記録: " + "、".join(f"`{f}`" for f in x["failure_codes"]))
    add("")

    b = p["business_impact"]
    add("## 6. 業務影響")
    add("")
    add(f"- 評価: なし（`{b['assessment']['reason_code']}`）。担当者が専門家へ直接伝える。")
    n = b["connectivity_observed"]
    if n.get("status") == "observed":
        add(f"- 通信の受動観測（{_md(n['observed_at'])}、{n['snapshot_age_s']} 秒前）: "
            f"インターフェース {n['interfaces']}、リンクあり {n['carrier_up']}、なし {n['carrier_down']}、"
            f"IPv4 既定経路 {_md(n['ipv4_default_routes'])}。到達性は測っていない。")
    else:
        add(f"- 通信の観測: {_state_ja(n)}")
    add(f"- Nexus 経由で実行した通信制限: {b['restrictions_executed_by_nexus']} 件")
    add("")

    ev = p["evidence_refs"]
    add("## 7. 証拠参照（digest のみ）")
    add("")
    add(f"状態: {_state_ja(ev)}。生データは含めていない。")
    for r in ev.get("refs", []):
        add(f"- {_md(r['role'])}: `{r['digest']}`（{_md(r['cited_at'])}）")
    add("")

    k = p["knowledge"]
    add("## 8. Knowledge の出典・世代・鮮度")
    add("")
    add(f"状態: {_state_ja(k)}")
    now_k = k["lite_now"]
    add(f"- 現在の Knowledge Lite: {_state_ja(now_k)}"
        + (f" 世代 {now_k.get('generation')}、鮮度 `{now_k.get('freshness')}`"
           if now_k.get("status") == "read" else ""))
    for ref in k["citations"]:
        digest = ref.get("bundle_digest") or ref.get("bundle_digest_short")
        add(f"- {_md(ref['technique_id'])} {_md(ref['name'])}: 世代 {_md(ref.get('generation'))}、"
            f"参照時の鮮度 `{ref.get('freshness_at_lookup')}`、参照時刻 {_md(ref.get('looked_up_at'))}、"
            f"bundle `{digest}`"
            + ("、**現在の世代と異なる**" if ref.get("superseded") else ""))
    add("")

    op = p["operator_actions"]
    add("## 9. 担当者の操作（監査記録）")
    add("")
    add(f"状態: {_state_ja(op)}")
    add("- このインシデントに対する担当者の承認・確認の記録: なし（Nexus にその記録種別がない）")
    add(f"- 対象期間 {_md(op['window']['from'])} 〜 {_md(op['window']['to'])} のノード操作（操作者名は伏字）:")
    for a in op["node_actions"]:
        add(f"  - {_md(a['occurred_at'])} `{a['event_type']}`")
    if not op["node_actions"]:
        add("  - なし")
    add("")

    add("## 10. 未確認事項")
    add("")
    for u in p["unconfirmed"]:
        add(f"- {u['text_ja']}（`{u['code']}`）")
    add("")

    conf = p["confidentiality"]
    add("## 11. 機密の扱い")
    add("")
    add("既定で抑制している。秘密情報・生 payload・内部識別情報（IP・MAC・インターフェース名・"
        "経路・操作者名）は含めない。自由文中の該当形式は `[伏字:種別]` に置換した。")
    add("")
    add(f"抑制した件数（合計 {conf['suppressed_total']}）:")
    for name, value in conf["suppressed"].items():
        if value:
            add(f"- `{name}`: {value}")
    add("- 読んでいないもの: " + "、".join(f"`{x}`" for x in conf["not_read"]))
    add("")

    add("## 12. 読んだ情報源")
    add("")
    add("| 情報源 | 状態 | 理由 | 読める権限 |")
    add("| --- | --- | --- | --- |")
    for src in p["sources"]:
        add(f"| `{src['source']}` | {src['status']} | {src['reason_code'] or ''} | {src['readable_by']} |")
    add("")
    return "\n".join(lines)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2,
                      allow_nan=False).encode("utf-8") + b"\n"


def encode_files(package: dict) -> dict:
    """`{name: bytes}` for the three files; the manifest last. Refuses a leak."""
    body = _canonical(package)
    markdown = render_markdown(package).encode("utf-8")
    for raw in (body, markdown):
        leaks = scan_for_leaks(raw)
        if leaks:
            raise HandoffRefused("suppression_incomplete:" + ",".join(leaks))
    files = {JSON_NAME: body, MARKDOWN_NAME: markdown}
    manifest = {
        "schema": MANIFEST_SCHEMA, "package_schema": SCHEMA,
        "incident_id": package["incident"]["incident_id"],
        "generated_at": package["generated_at"], "provenance": package["provenance"],
        "upload": "none",
        "files": [{"name": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                   "media_type": "application/json" if name.endswith(".json")
                   else "text/markdown; charset=utf-8"}
                  for name, raw in files.items()],
    }
    files[MANIFEST_NAME] = _canonical(manifest)
    return files


# -- writing ------------------------------------------------------------------

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_output(parent: Path) -> int:
    """Open `parent` from `/`, one component at a time, never through a link."""
    text = os.fspath(parent)
    if not os.path.isabs(text) or "\x00" in text:
        raise HandoffRefused("output_path_not_absolute")
    parts = [p for p in text.split("/") if p]
    if any(p in (".", "..") for p in parts):
        raise HandoffRefused("output_path_refused")
    logical = "/" + "/".join(parts)
    if any(logical == prefix or logical.startswith(prefix + "/")
           for prefix in REFUSED_OUTPUT_PREFIXES):
        raise HandoffRefused("output_in_product_state")
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in parts:
            try:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except OSError as exc:
                raise HandoffRefused("output_path_refused" if exc.errno in (
                    errno.ELOOP, errno.ENOTDIR) else "output_dir_unavailable") from None
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_mode & 0o022:
            raise HandoffRefused("output_dir_shared_writable")
        return fd
    except BaseException:
        os.close(fd)
        raise


def package_name(package: dict) -> str:
    stamp = package["generated_at"].replace("-", "").replace(":", "")
    return f"azazel-handoff-{package['incident']['incident_id']}-{stamp}"


def write_package(parent: Path, name: str, files: dict, *,
                  statvfs=os.fstatvfs, write=os.write) -> Path:
    """Write `files` as directory `parent/name`, atomically, or nothing.

    The files go into a private temporary directory beside it, each created
    exclusively and synced; the directory is renamed into place only when
    all are written. Any failure -- including no space -- removes the
    temporary directory and what it held.
    """
    if not re.fullmatch(r"azazel-handoff-inc-[0-9a-f]{16}-[0-9TZ]{16}", name):
        raise HandoffRefused("package_name_refused")
    parent_fd = _open_output(parent)
    temporary = None
    temporary_fd = None
    created = []
    try:
        try:
            os.lstat(name, dir_fd=parent_fd)
            raise HandoffRefused("output_exists")
        except FileNotFoundError:
            pass
        need = (sum(len(raw) for raw in files.values()) + SPACE_HEADROOM_BYTES
                + SPACE_PER_FILE_BYTES * (len(files) + 1))
        space = statvfs(parent_fd)
        if space.f_bavail * space.f_frsize < need:
            raise HandoffRefused("insufficient_space")
        temporary = f".{name}.partial-{secrets.token_hex(8)}"
        os.mkdir(temporary, 0o700, dir_fd=parent_fd)
        temporary_fd = os.open(temporary, _DIR_FLAGS, dir_fd=parent_fd)
        info = os.fstat(temporary_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise HandoffRefused("output_path_refused")
        for file_name, raw in files.items():
            fd = os.open(file_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600, dir_fd=temporary_fd)
            created.append(file_name)
            try:
                view = memoryview(raw)
                while view:
                    n = write(fd, view)
                    if n <= 0:
                        raise OSError(errno.EIO, "short write")
                    view = view[n:]
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(temporary_fd)
        try:
            os.lstat(name, dir_fd=parent_fd)
            raise HandoffRefused("output_exists")
        except FileNotFoundError:
            pass
        os.rename(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temporary = None
        os.fsync(parent_fd)
        return Path(parent) / name
    except OSError as exc:
        raise HandoffRefused("insufficient_space" if exc.errno in (errno.ENOSPC, errno.EDQUOT)
                             else "write_failed") from None
    finally:
        if temporary is not None:
            if temporary_fd is not None:
                for file_name in created:
                    try:
                        os.unlink(file_name, dir_fd=temporary_fd)
                    except OSError:
                        pass
            try:
                os.rmdir(temporary, dir_fd=parent_fd)
            except OSError:
                pass
        if temporary_fd is not None:
            os.close(temporary_fd)
        os.close(parent_fd)
