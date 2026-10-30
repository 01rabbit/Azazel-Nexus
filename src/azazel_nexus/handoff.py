"""The expert handoff package (goal 2 F, S-19): one offline, read-only bundle.

`azazel-nexus handoff export` gathers what this node already recorded about
one incident and writes three files into a new directory under the one the
operator names:

* `handoff.json` -- schema `azazel-nexus/handoff-package/1`;
* `handoff.ja.md` -- the same content for a person, in Japanese;
* `manifest.json` -- schema `azazel-nexus/handoff-manifest/1`: the SHA-256
  and size of the two files above, written last. Its own digest is printed
  on the terminal so that it can be written down beside the media. A
  directory without a manifest whose digests verify is not a package.

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
no material is `unavailable` with a reason code, never a healthy default; a
snapshot past its freshness bound is the last record, not the current state.
The four kinds of statement are separate sections, each with its `authority`.

**Confidentiality, by allowlist.** Addresses, rule ids, ports, producer text
and operator identities are never copied. Text that did not come from this
code is copied only when it is a fixed text this product ships (an advisory
banner, a handoff notice) or a short phrase of plain words; anything else is
withheld and counted. A final scan walks every string of the package and
refuses to write it if any identifier, path, encoded or secret-like form is
present outside the fields whose form is fixed (digests, codes, timestamps).
There is no upload: this module has no transport.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

__all__ = [
    "MANIFEST_SCHEMA", "SCHEMA", "HandoffRefused", "WriteResult", "build_package",
    "encode_files", "find_incident", "principal_class", "render_markdown", "scan_package",
    "write_package",
]

SCHEMA = "azazel-nexus/handoff-package/1"
MANIFEST_SCHEMA = "azazel-nexus/handoff-manifest/1"
JSON_NAME = "handoff.json"
MARKDOWN_NAME = "handoff.ja.md"
MANIFEST_NAME = "manifest.json"
OPERATOR_GROUP = "azazel-operator"

#: A time earlier than this is not a date this software ran on.
MIN_PLAUSIBLE_EPOCH = 1767225600  # 2026-01-01T00:00:00Z
#: A record dated this far after the generating clock is evidence of a clock
#: that moved backwards (the snapshot readers use the same five seconds).
FUTURE_SKEW_S = 5
#: Node-level audit events shown from this long before the incident opened.
AUDIT_WINDOW_BEFORE_S = 3600
#: What is *shown*. Every bound below is on display only: totals, the latest
#: state and the latest decision are computed from every record read, and
#: what is not shown is counted with its range.
SHOW_TRANSITIONS = 256
SHOW_EXPLANATIONS = 16
SHOW_EVIDENCE_REFS = 64
SHOW_CITATIONS = 64
SHOW_AUDIT_EVENTS = 128
MAX_SEGMENT_BYTES = 64 * 1024 * 1024
MAX_LEDGER_BYTES = 512 * 1024 * 1024
#: Room left beyond the package bytes, and per-file allocation slack.
SPACE_HEADROOM_BYTES = 1024 * 1024
SPACE_PER_FILE_BYTES = 64 * 1024
#: The output directory may not be inside product state.
REFUSED_OUTPUT_PREFIXES = ("/var/lib/azazel", "/etc/azazel", "/run", "/proc", "/sys", "/dev")
#: The incident loop's snapshots are rewritten every few seconds
#: (`status_view.LOOP_STALE_S`).
LOOP_STALE_S = 30

GENESIS_HASH = "0" * 64
_INCIDENT_ID = re.compile(r"inc-[0-9a-f]{16}")
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}\.jsonl", re.ASCII)

# -- detection ----------------------------------------------------------------

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4 = re.compile(rf"(?<![0-9A-Za-z.]){_OCTET}(?:\.{_OCTET}){{3}}(?![0-9A-Za-z])")
_HEX4 = r"[0-9A-Fa-f]{1,4}"
#: Full eight-group IPv6, or a compressed form with `::` and a group.
_IPV6 = re.compile(
    rf"(?<![0-9A-Za-z:])(?:(?:{_HEX4}:){{7}}{_HEX4}"
    rf"|{_HEX4}(?::{_HEX4}){{0,6}}::(?:{_HEX4}(?::{_HEX4}){{0,6}})?"
    rf"|::{_HEX4}(?::{_HEX4}){{0,6}})"
    r"(?:%[0-9A-Za-z]+)?(?![0-9A-Za-z:])")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"

#: Every form the final scan refuses, by the category it reports.
DETECTORS = (
    ("secret_like", re.compile(
        r"-----BEGIN [A-Z ]+-----|(?i:\b(?:password|passwd|passphrase|secret|token|api[_-]?key"
        r"|authorization|bearer|cookie|session)\b\s*[:=]\s*\S+)")),
    ("network_address", _IPV4),
    ("network_address", _IPV6),
    ("mac_address", re.compile(
        r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Za-z])")),
    ("url", re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://|(?:^|(?<=\s))//\S")),
    ("email", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("windows_path", re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]|\\\\[^\\\s]+\\|\\[\w$.-]+\\")),
    ("unix_path", re.compile(r"(?:^|(?<=[\s(\[`'\"=:,;]))(?:~|\.{1,2})?/[^\s/]+")),
    ("host_port", re.compile(r"(?<![\w.-])[A-Za-z][\w.-]*:\d{1,5}(?![\d.])")),
    ("host_name", re.compile(
        rf"(?<![\w.@/-]){_LABEL}(?:\.{_LABEL})*\.[A-Za-z][A-Za-z0-9-]*[A-Za-z0-9](?![\w-]|\.\w)")),
    ("interface_name", re.compile(
        r"(?<![\w-])(?:eth|en[opsx]|wl[opsx]?|wlan|ww[a-z]|br|bond|vlan|veth|tun|tap)"
        r"[0-9][\w.-]*(?![\w-])")),
    ("percent_encoded", re.compile(r"%[0-9A-Fa-f]{2}")),
    ("hex_value", re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{24,}(?![0-9A-Za-z])")),
    ("base64_value", re.compile(
        r"(?<![A-Za-z0-9+/=_-])(?=[A-Za-z0-9+/_-]*[0-9+/_=])(?=[A-Za-z0-9+/_-]*[A-Z])"
        r"(?=[A-Za-z0-9+/_-]*[a-z])[A-Za-z0-9+/_-]{8,}={0,2}(?![A-Za-z0-9+/=_-])"
        r"|(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{4,}==?(?![A-Za-z0-9+/=])")),
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
#: Keys whose value has one fixed form: checked against it, never scanned.
_FIXED_FORM = {
    "digest": _DIGEST, "bundle_digest": _DIGEST,
    "bundle_digest_short": re.compile(r"sha256:[0-9a-f]{12}"),
    "sha256": re.compile(r"[0-9a-f]{64}"),
    "schema": re.compile(r"azazel-nexus/[a-z-]+/[0-9]+"),
    "package_schema": re.compile(r"azazel-nexus/[a-z-]+/[0-9]+"),
    "nexus_version": re.compile(r"[0-9]+(?:\.[0-9]+)*(?:\.?(?:dev|rc|a|b)[0-9]+)*"),
    "name": re.compile(r"handoff\.(?:json|ja\.md)"),
    "media_type": re.compile(r"application/json|text/markdown; charset=utf-8"),
}
#: Forms that are safe wherever they appear: dotless codes, timestamps, ids.
#: A dotted code is safe only when it is in `fixed_vocabulary()`: a dotted
#: lower-case string is also what a host name looks like.
_SAFE = re.compile(
    r"[a-z][a-z0-9_]{0,63}(?::[a-z][a-z0-9_]{0,39})*"
    r"|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
    r"|inc-[0-9a-f]{16}|T[0-9]{4}(?:\.[0-9]{3})?"
    r"|[0-9]{4}-[0-9]{2}-[0-9]{2}\.jsonl", re.ASCII)


def detect(text: str) -> list[str]:
    """The categories of identifier, path, encoded or secret form in `text`."""
    text = unicodedata.normalize("NFKC", text)
    found = []
    for category, pattern in DETECTORS:
        if category not in found and pattern.search(text):
            found.append(category)
    return found


def _walk(value, key=None):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from _walk(v, key)
    elif isinstance(value, str):
        yield key, value


def fixed_vocabulary() -> frozenset:
    """The dotted words this product writes itself: event types and sources.

    Taken from the event types this module copies (a subset of auditd's
    declared `EVENT_SCHEMAS`, checked against it in the tests) and the
    incident transitions; an event type outside it is never copied.
    """
    return frozenset(OPERATOR_EVENT_FIELDS) | frozenset(INCIDENT_AUDIT_TYPES) | frozenset(
        {"incident_ledger.first_seen", "recent_snapshot.first_seen"})


def scan_package(value) -> list[str]:
    """Every category found in any string of a package or manifest value."""
    found = []
    vocabulary = fixed_vocabulary()
    for key, text in _walk(value):
        form = _FIXED_FORM.get(key)
        if form is not None and form.fullmatch(text):
            continue
        if text in vocabulary:
            continue
        # A code-shaped string is still checked for encoded and secret forms.
        found_here = detect(text)
        if _SAFE.fullmatch(text):
            found_here = [c for c in found_here
                          if c in ("hex_value", "base64_value", "secret_like")]
        for category in found_here:
            if category not in found:
                found.append(category)
    return found


def scan_markdown(text: str) -> list[str]:
    """The rendered document, with its digests, timestamps and fixed words out.

    The same allowance as `scan_package`: only the product's own dotted
    words are taken out, each as a whole word; anything else is scanned.
    """
    text = _DIGEST.sub(" ", text)
    words = sorted(fixed_vocabulary(), key=len, reverse=True)
    text = re.sub(r"(?<![\w.-])(?:" + "|".join(map(re.escape, words)) + r")(?![\w.-])", " ", text)
    text = re.sub(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", " ", text)
    return detect(text)


# -- the allowlist ------------------------------------------------------------
#
# Text from outside this code is shown only when it is identical to a text
# this product ships. Nothing tries to tell natural language from an encoded
# value by its shape: Knowledge's names, summaries and citations are
# withheld, and the technique id, claim id, bundle digest and generation --
# which an expert can look up -- are kept.


def _knowledge_text(text) -> tuple[Optional[str], str]:
    """Knowledge free text is withheld; `(None, "none")` when there is none."""
    return (None, "withheld") if text else (None, "none")


def _fixed_texts() -> dict:
    """Every fixed text an explanation may carry, and what produced it."""
    from .incident_explain import private_text
    from .local_advisory import _DELIVERY_BANNERS, _TEMPLATE_NOTES, HANDOFF_NOTICE

    method = {"model": "local_model_inference", "embedding": "embedding_matching",
              "keyword": "deterministic_keyword_matching"}
    texts = {}

    def put(text, produced_by):
        # A text two producers share (the ASCII summary of every Japanese
        # banner is the same word) says nothing about which one it was.
        if texts.get(text, produced_by) != produced_by:
            produced_by = "not_recorded"
        texts[text] = produced_by

    for source, banners in _DELIVERY_BANNERS.items():
        for i, banner in enumerate(banners):
            for note in ("", _TEMPLATE_NOTES[i]):
                put(banner + note, method[source])
                put(private_text((banner + note)[:280], 280), method[source])
    for notice in HANDOFF_NOTICE.values():
        put(notice, "fixed_handoff_notice")
    return texts


class HandoffRefused(Exception):
    """A fixed code; never exception text from below, which can quote a value.

    `remnant` names what is left at the package's name after a failure:
    `incomplete` -- the directory this call made, without a verified
    manifest; `unverified` -- something there that this call cannot vouch
    for, into which nothing was written.
    """

    def __init__(self, code: str, remnant: Optional[Path] = None,
                 remnant_kind: Optional[str] = None):
        super().__init__(code)
        self.code = code
        self.remnant = remnant
        self.remnant_kind = remnant_kind if remnant is not None else None
        #: Clean-up steps that also failed (`file_close_failed`, ...); the
        #: code above stays the first, original failure.
        self.problems: tuple = ()


class Suppressor:
    """Counts what was left out, so that the package can say how much."""

    CATEGORIES = ("network_address", "rule_identifier", "service_port", "producer_free_text",
                  "operator_identity", "ai_free_text", "knowledge_free_text", "audit_value")

    def __init__(self):
        self.counts = {name: 0 for name in self.CATEGORIES}

    def drop(self, category: str, n: int = 1) -> None:
        self.counts[category] += n


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


def _freshness(value, now, stale_after) -> dict:
    """`operator_snapshots.freshness` of one snapshot, as package fields."""
    from .operator_snapshots import freshness

    status, code, age = freshness(value["written_at"], now, stale_after)
    return {"freshness": status, "freshness_reason": code, "age_s": age,
            "stale_after_s": stale_after, "written_at": _iso(value["written_at"])}


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


@dataclass
class Chain:
    """What a chain walk read: its verdict, the kept events and the range."""

    status: str
    reason_code: Optional[str]
    kept: list
    controls: list
    anchored: bool = False
    anchor: Optional[str] = None
    first_segment: Optional[str] = None
    last_segment: Optional[str] = None
    entries: int = 0

    def verified(self) -> dict:
        return {"status": self.status, "reason_code": self.reason_code,
                "anchored": self.anchored, "anchor": self.anchor,
                "segments": {"first": self.first_segment, "last": self.last_segment},
                "entries": self.entries}


def _read_chain(directory: Path, keep: Callable[[dict], bool], *, start=None, days=None,
                anchor=None) -> Chain:
    """Walk daily segments in order from `start` (`(sequence, hash)`).

    With `start`, the first entry must continue it -- genesis or a verified
    retention boundary -- so a removed first line or first segment is a
    break. Without it the first entry is taken as found, and the walk is
    said to be unanchored.
    """
    if days is None:
        days, code = _list_days(directory)
        if days is None:
            return Chain(code, code, [], [])
    chain = Chain("read", None, [], [], anchored=start is not None, anchor=anchor)
    if days:
        chain.first_segment, chain.last_segment = days[0].name, days[-1].name
    head, budget = start, [MAX_LEDGER_BYTES]
    try:
        for day in days:
            for sequence, previous, digest, event in _chain_lines(day, budget):
                if head is not None and (sequence != head[0] + 1 or previous != head[1]):
                    chain.status, chain.reason_code = "broken", "chain_broken"
                    return chain
                head = (sequence, digest)
                chain.entries += 1
                if keep(event):
                    chain.kept.append(event)
                elif event.get("event_type") in _CONTROL_TYPES:
                    chain.controls.append(event)
    except HandoffRefused as refused:
        chain.status = ("broken" if refused.code in {"chain_broken", "ledger_tail_incomplete"}
                        else refused.code)
        chain.reason_code = refused.code
    return chain


def _read_incident_chain(directory: Path, keep) -> Chain:
    """The incident chain, anchored the way `IncidentLedger` anchors it.

    From genesis, or from `retained-boundary.json`: the boundary's `oldest`
    must be the first retained segment, and the first entry must continue
    its `(sequence, hash)`. Segments at or before its `deleted` -- left by a
    crash between the boundary and the unlink -- are ignored, as the
    intake and the explainer ignore them.
    """
    from .edge_intake import _object
    from .incident_explain import read_retention_boundary

    days, code = _list_days(directory)
    if days is None:
        return Chain(code, code, [], [])
    raw, code = _open_regular(directory / "retained-boundary.json", 4096)
    if raw is None and code != "absent":
        return Chain(code, code, [], [])
    if raw is None:
        return _read_chain(directory, keep, start=(0, GENESIS_HASH), days=days,
                           anchor="genesis")
    try:
        boundary = read_retention_boundary(json.loads(raw.decode("utf-8"),
                                                      object_pairs_hook=_object))
    except (ValueError, TypeError, KeyError, UnicodeError):
        return Chain("broken", "retention_boundary_refused", [], [])
    days = [d for d in days if d.name > boundary["deleted"]]
    if not days or days[0].name != boundary["oldest"]:
        return Chain("broken", "retention_boundary_mismatch", [], [])
    return _read_chain(directory, keep, start=(boundary["sequence"], boundary["hash"]),
                       days=days, anchor="retention_boundary")


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
    chain = _read_incident_chain(
        sources.incidents, lambda e: str(e.get("event_type", "")).startswith("edge.incident.")
        and _INCIDENT_ID.fullmatch(str(e.get("incident_id", ""))) is not None)
    kept = [e for e in chain.kept if type(e.get("last_update")) in (int, float)]
    if kept:
        return max(kept, key=lambda e: (e["last_update"], e["incident_id"]))["incident_id"]
    return None


# -- the package --------------------------------------------------------------


def _unavailable(code, **extra) -> dict:
    return {"status": "unavailable", "reason_code": code, **extra}


def _shown(items: list, limit: int, at) -> tuple[list, dict]:
    """The latest `limit` items, and what was not shown."""
    omitted = items[:-limit] if len(items) > limit else []
    return items[-limit:], {
        "total": len(items), "shown": min(len(items), limit), "omitted": len(omitted),
        "omitted_range": ({"from": at(omitted[0]), "to": at(omitted[-1])} if omitted else None)}


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
        KNOWLEDGE_BYTES, KNOWLEDGE_STALE_S, MIO_BYTES, MIO_STALE_S, read_knowledge_status,
        read_mio_status,
    )

    if not _INCIDENT_ID.fullmatch(incident_id):
        raise HandoffRefused("incident_id_refused")
    if provenance not in ("node", "fixture") or principal not in ("root", "operator"):
        raise HandoffRefused("generator_refused")
    sources = Sources(root)
    hide = Suppressor()
    read_log = []
    future = []

    def note(name, code, readable_by, **extra):
        read_log.append({"source": name, "status": "read" if code == "read" else "unavailable",
                         "reason_code": None if code == "read" else code,
                         "readable_by": readable_by, **extra})

    def seen(epoch, what):
        if type(epoch) in (int, float) and epoch > now + FUTURE_SKEW_S:
            future.append(what)

    # Snapshots (operator group), each with its freshness.
    snaps = {}
    for name, path, reader, limit, stale in (
            ("recent_incidents_snapshot", sources.recent, read_recent_incidents, RECENT_BYTES,
             LOOP_STALE_S),
            ("explainer_status_snapshot", sources.explainer_status, read_explainer_status, 8192,
             LOOP_STALE_S),
            ("intake_status_snapshot", sources.intake_status, read_intake_status, 8192,
             LOOP_STALE_S),
            ("knowledge_status_snapshot", sources.knowledge_status, read_knowledge_status,
             KNOWLEDGE_BYTES, KNOWLEDGE_STALE_S),
            ("mio_status_snapshot", sources.mio_status, read_mio_status, MIO_BYTES, MIO_STALE_S),
            ("noc_status_snapshot", sources.noc_status, read_noc_status, NOC_BYTES, None)):
        from .noc_status import NOC_STALE_S

        value, code = _snapshot(path, reader, limit)
        fresh = _freshness(value, now, stale or NOC_STALE_S) if value is not None else None
        snaps[name] = (value, fresh)
        note(name, code, "operator", **({"freshness": fresh["freshness"]} if fresh else {}))
        if value is not None:
            seen(value.get("written_at"), name)
    recent, recent_fresh = snaps["recent_incidents_snapshot"]
    explainer = snaps["explainer_status_snapshot"][0]
    intake = snaps["intake_status_snapshot"][0]
    row = None
    if recent is not None:
        row = next((r for r in recent["incidents"] if r["incident_id"] == incident_id), None)

    # Incident ledger (root), anchored at genesis or the retention boundary.
    chain = _read_incident_chain(sources.incidents,
                                 lambda event: event.get("incident_id") == incident_id)
    ledger_status, ledger_code = chain.status, chain.reason_code
    transitions = []
    for event in chain.kept:
        try:
            transitions.append(read_transition(event))
        except ValueError:
            ledger_status, ledger_code = "broken", "transition_refused"
    if ledger_status == "read" and not transitions:
        # Read, but this incident is not in what is retained.
        ledger_status, ledger_code = "not_retained", "incident_not_in_ledger"
    note("incident_ledger", "read" if ledger_status == "read" else ledger_code, "root",
         verified=chain.verified())
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

    # Audit chain (root): from the day before the window; anchored at
    # genesis only when no earlier segment exists (auditd retires none).
    first_seen = (min(t["first_seen"] for t in transitions) if transitions
                  else row["first_seen"])
    window_from = first_seen - AUDIT_WINDOW_BEFORE_S
    day_from = (_iso(window_from) or "0000-00-00")[:10]

    def relevant(event):
        kind = str(event.get("event_type", ""))
        if kind.startswith("edge.incident."):
            return event.get("incident_id") == incident_id
        at = _epoch(event.get("occurred_at"))
        return kind in OPERATOR_EVENT_FIELDS and at is not None and window_from <= at
    audit_days, code = _list_days(sources.audit)
    if audit_days is None:
        audit = Chain(code, code, [], [])
    else:
        selected = [d for d in audit_days if d.name[:10] >= day_from]
        if len(selected) == len(audit_days):
            audit = _read_chain(sources.audit, relevant, start=(0, GENESIS_HASH),
                                days=selected, anchor="genesis")
        else:
            audit = _read_chain(sources.audit, relevant, days=selected)
    note("audit_chain", "read" if audit.status == "read" else audit.reason_code, "root",
         verified=audit.verified())

    # Sections.
    knowledge = _knowledge(explanations, explanation_code, row, snaps, now, hide)
    # Every reference read, before duplicates are merged or the display is
    # bounded: one future lookup time anywhere is a sign about the clock.
    every_ref = [ref for record in explanations for ref in record["knowledge_refs"]]
    if row is not None:
        every_ref += row["explanation"]["knowledge_refs"]
    for ref in every_ref:
        seen(_epoch(ref.get("as_of")), "knowledge_citation")
    clock = _generation_clock(sources, now, note)
    occurrence = _occurrence(transitions, row, explanations, audit.kept, now, seen)
    for snap, name in ((intake, "intake"), (explainer, "explainer")):
        if snap is not None and snap["refused"].get("segment_from_future"):
            clock["signals"].append(name + "_segment_from_future")
    if future:
        clock["signals"].append("records_dated_after_generation")
        clock["future_dated_sources"] = sorted(set(future))
        occurrence["signals"].append("records_dated_after_generation")
    if clock["signals"]:
        clock["status"] = "untrusted"
        clock["reason_code"] = clock["signals"][0]
        occurrence["signals"].append("generation_clock_untrusted")
    if occurrence["signals"]:
        occurrence["status"] = "untrusted"
        occurrence["reason_code"] = occurrence["signals"][0]

    observed = _observed(transitions, row, recent_fresh, ledger_status, ledger_code,
                         chain.controls, hide)
    decision = _decision(transitions, row, POLICY_REASONS)
    execution = _execution(transitions, row, intake)
    evidence = _evidence(transitions, ledger_status, ledger_code)
    ai = _ai(explanations, explanation_code, row, snaps["mio_status_snapshot"], CONTENT_LABELS,
             hide)
    operator = _operator(audit, window_from, now, hide)
    impact = _impact(snaps["noc_status_snapshot"], execution)
    loop = _loop(snaps)

    closed = [t for t in transitions if t["event_type"] == "edge.incident.closed"]
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
                     "state": ("closed" if closed and transitions[-1] is closed[-1]
                               else "open" if transitions
                               else row["state"])},
        "time": {"occurred_at": _iso(first_seen),
                 "occurred_at_source": ("incident_ledger.first_seen" if transitions
                                        else "recent_snapshot.first_seen"),
                 "last_seen": _iso(max(t["last_seen"] for t in transitions) if transitions
                                   else row["last_seen"]),
                 "basis": "node_wall_clock_at_intake",
                 "occurrence": occurrence,
                 "generation_clock": clock},
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
    package["confidentiality"] = {
        "policy": "allowlist_default_suppressed",
        "suppressed": dict(hide.counts),
        "suppressed_total": sum(hide.counts.values()),
        "free_text_rule": "fixed product texts and plain-word phrases only; anything else withheld",
        "not_read": ["edge_evidence_payloads", "decoy_evidence", "commissioning_record",
                     "secrets_directory", "interface_identity", "torn_tail_quarantine"],
        "raw_payload_included": False,
        "upload": "none",
        "external_release": "operator_decision_outside_this_tool",
    }
    package["unconfirmed"] = _unconfirmed(package)
    return package


def _version() -> str:
    from . import __version__

    return __version__


def _generation_clock(sources: Sources, now: float, note) -> dict:
    """The clock that generated the package -- not the one at the incident."""
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
        "means": "a synchronization happened in this boot; not that it is still synchronized, "
                 "that the time source was authenticated, or that it happened before the incident"}
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


def _occurrence(transitions, row, explanations, audit_events, now, seen) -> dict:
    """How far the recorded incident times can be believed, apart from now.

    No record says whether the clock was synchronized when the incident was
    observed, so the best this can be is `unverified`; impossible or
    inconsistent times make it `untrusted`.
    """
    signals = []
    first = (min(t["first_seen"] for t in transitions) if transitions else row["first_seen"])
    if first < MIN_PLAUSIBLE_EPOCH:
        signals.append("occurred_before_plausible_date")
    previous = None
    for t in transitions:
        for key in ("first_seen", "last_seen", "last_update"):
            seen(t[key], "incident_ledger")
        if t["last_seen"] < t["first_seen"] or t["last_update"] < t["first_seen"]:
            signals.append("last_seen_before_first_seen")
        if previous is not None and t["last_update"] < previous:
            signals.append("transitions_out_of_order")
        previous = t["last_update"]
    if row is not None:
        seen(row["last_seen"], "recent_snapshot")
        if row["last_seen"] < row["first_seen"]:
            signals.append("last_seen_before_first_seen")
    for record in explanations:
        seen(record["explained_at"], "explanation_ledger")
        if record["explained_at"] + FUTURE_SKEW_S < first:
            signals.append("explained_before_occurrence")
    for event in audit_events:
        seen(_epoch(event.get("occurred_at")), "audit_chain")
    return {"status": "unverified", "reason_code": "no_synchronization_evidence_at_occurrence",
            "signals": sorted(set(signals), key=signals.index)}


def _observed(transitions, row, recent_fresh, ledger_status, ledger_code, controls,
              hide) -> dict:
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
        shown, display = _shown(rows, SHOW_TRANSITIONS, lambda r: r["at"])
        return {
            "status": "available" if ledger_status == "read" else "partial",
            "reason_code": None if ledger_status == "read" else ledger_code,
            "authority": "edge_observation", "source": "incident_ledger",
            "summary": {"first_seen": _iso(min(t["first_seen"] for t in transitions)),
                        "last_seen": _iso(max(t["last_seen"] for t in transitions)),
                        "count": max(t["count"] for t in transitions),
                        "most_severe": min(t["most_severe"] for t in transitions),
                        "technique_ids": sorted({i for t in transitions for i in t["technique_ids"]}),
                        "category": rows[-1]["category"], "protocol": rows[-1]["protocol"],
                        "latest_transition": rows[-1]["event_type"],
                        "transitions_with_evidence_not_stored": sum(
                            1 for r in rows if not r["evidence_stored"]),
                        "computed_from": "all_transitions_read",
                        "severity_scale": "1 = most severe (Suricata priority)"},
            "transitions": shown,
            "transitions_display": display,
            "ledger": {"chain": ledger_status,
                       "gaps": [{"kind": c["event_type"].removeprefix("edge.incident."),
                                 "at": _iso(c.get("at"))} for c in controls[-32:]],
                       "gaps_total": len(controls)},
            "withheld_fields": ["source_address", "rule_id", "destination_port", "signature_text"],
        }
    section = _unavailable(ledger_code, authority="edge_observation")
    section.update(status="partial", source="recent_snapshot", snapshot=recent_fresh, summary={
        "first_seen": _iso(row["first_seen"]), "last_seen": _iso(row["last_seen"]),
        "count": row["count"], "most_severe": row["most_severe"],
        "technique_ids": list(row["technique_ids"]),
        "computed_from": "recent_snapshot_row",
        "severity_scale": "1 = most severe (Suricata priority)"},
        transitions=[], ledger={"chain": ledger_status, "gaps": [], "gaps_total": 0})
    return section


def _decisions(transitions, row, reasons=None) -> list:
    decisions = [{"at": _iso(t["last_update"]), "action": t["edge_would"],
                  "policy_reason": (t["policy_reason"] if reasons is None
                                    or t["policy_reason"] in reasons else "other"),
                  "kind": "would", "executed": False} for t in transitions]
    if not decisions and row is not None:
        decisions = [{"at": _iso(row["last_seen"]), "action": row["edge_would"],
                      "policy_reason": row["policy_reason"], "kind": "would", "executed": False}]
    return decisions


def _decision(transitions, row, reasons) -> dict:
    decisions = _decisions(transitions, row, reasons)
    if not decisions:
        return _unavailable("no_decision_recorded", authority="edge_deterministic_rules")
    shown, display = _shown(decisions, SHOW_TRANSITIONS, lambda d: d["at"])
    return {"status": "available", "reason_code": None, "authority": "edge_deterministic_rules",
            "decided_by": "edge", "latest": decisions[-1], "decisions": shown,
            "decisions_display": display}


def _execution(transitions, row, intake) -> dict:
    actions = []
    for d in _decisions(transitions, row):
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
    shown, display = _shown(refs, SHOW_EVIDENCE_REFS, lambda r: r["cited_at"])
    return {"status": "available" if not missing else "partial",
            "reason_code": None if not missing else "evidence_not_stored",
            "refs": shown, "refs_display": display,
            "transitions_with_evidence_not_stored": missing,
            "raw_payload_included": False,
            "retention_checked": False,
            "note": "digests only; whether the record is still retained was not checked "
                    "(the store is private)"}


def _text_of(value, fixed, hide) -> tuple[Optional[str], str]:
    """An explanation's text if it is a fixed product text, else withheld."""
    if not value:
        return None, "none"
    if value in fixed and fixed[value] == "not_recorded":
        # Only the producer-independent summary is left: it is not shown,
        # and it is not counted as withheld producer text either.
        return None, "ambiguous_summary"
    if value in fixed:
        return value, fixed[value]
    hide.drop("ai_free_text")
    return None, "withheld"


def _ai(explanations, explanation_code, row, mio, labels, hide) -> dict:
    from .incident_explain import content_kind

    fixed = _fixed_texts()
    value, fresh = mio
    capability = _unavailable("snapshot_unavailable")
    if value is not None:
        capability = {"status": "read" if fresh["freshness"] == "fresh" else "stale_last_recorded",
                      "reason_code": fresh["freshness_reason"], "snapshot": fresh,
                      "recorded": value["recorded"], "state": value["state"],
                      "ceiling": value["ceiling"], "observed_at": value["observed_at"],
                      "record_uncertain": value["record_uncertain"]}
    base = {"authority": "advisory_only_not_fact", "route_capability_now": capability,
            "label_basis": "the explainer's content_kind: every answered local-route reply is "
                           "labelled AI advice; the fixed banner it carries says whether a model, "
                           "embedding matching or keyword matching produced it",
            "model_identity": _unavailable("model_identity_not_recorded_in_explanation_ledger"),
            "remote_route": "not_used_by_incident_explainer"}
    if explanations:
        items = []
        for record in explanations:
            m = record["mio"]
            kind = content_kind(m)
            text, method = _text_of(m["text"], fixed, hide)
            notice, _ = _text_of(m.get("notice"), fixed, hide)
            items.append({
                "explained_at": _iso(record["explained_at"]), "transition": record["transition"],
                "route": m["route"], "outcome": m["outcome"],
                "local_route_answered": m["route"] == "local" and m["outcome"] == "answered",
                "content_kind": kind, "content_label": labels.get(kind, kind),
                "labelled_ai_output": kind == "ai_advice",
                "generation_method": method if text else "not_recorded",
                "text": text, "text_state": "shown" if text else (
                    method if method in ("withheld", "ambiguous_summary") else "none"),
                "notice": notice,
                "failure_codes": list(record["failure_codes"])})
        shown, display = _shown(items, SHOW_EXPLANATIONS, lambda x: x["explained_at"])
        return {"status": "available", "reason_code": None, "source": "explanation_ledger",
                **base, "explanations": shown, "explanations_display": display}
    if row is not None and row["explanation"]["state"] != "pending":
        e = row["explanation"]
        kind = e.get("content_kind")
        text, method = _text_of(e["summary"], fixed, hide)
        notice, _ = _text_of(e.get("notice"), fixed, hide)
        return {"status": "partial", "reason_code": explanation_code,
                "source": "recent_snapshot", **base, "explanations": [{
                    "explained_at": None, "transition": None, "route": e["route"],
                    "outcome": e["outcome"],
                    "local_route_answered": e["route"] == "local" and e["outcome"] == "answered",
                    "content_kind": kind, "content_label": labels.get(kind, "unlabelled"),
                    "labelled_ai_output": e["state"] == "explained",
                    "generation_method": method if text else "not_recorded",
                    "text": text, "text_state": "shown" if text else (
                        method if method in ("withheld", "ambiguous_summary") else "none"),
                    "text_is_summary": True, "notice": notice,
                    "failure_codes": list(e["failure_codes"])}]}
    code = explanation_code if explanation_code != "read" else (
        "explanation_pending" if row is not None and row["explanation"]["state"] == "pending"
        else "no_explanation_recorded")
    return {**_unavailable(code), **base, "explanations": []}


def _knowledge(explanations, explanation_code, row, snaps, now, hide) -> dict:
    value, fresh = snaps["knowledge_status_snapshot"]
    current = _unavailable("snapshot_unavailable")
    is_fresh = False
    if value is not None:
        is_fresh = fresh["freshness"] == "fresh"
        current = {"status": "read" if is_fresh else "stale_last_recorded",
                   "reason_code": fresh["freshness_reason"], "snapshot": fresh,
                   "state": value["state"], "state_reason": value["reason_code"],
                   "generation": value["generation"], "freshness": value["freshness"]}

    def ref_age(as_of):
        at = _epoch(as_of)
        return None if at is None else int(now - at)

    def phrase(text, limit):
        kept, state = _knowledge_text(text)
        if state == "withheld":
            hide.drop("knowledge_free_text")
        return kept, state

    def compare(generation):
        if not is_fresh or type(current.get("generation")) is not int:
            return None, "current_generation_not_fresh_or_unknown"
        return current["generation"] != generation, "fresh_snapshot"

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
                name, name_state = phrase(ref["name"], 120)
                summary, summary_state = phrase(ref["summary"], 240)
                citation, citation_state = phrase(ref["citation"], 160)
                superseded, basis = compare(ref["generation"])
                citations.append({
                    "technique_id": ref["technique_id"], "claim_id": ref["claim_id"],
                    "name": name, "name_state": name_state,
                    "summary": summary, "summary_state": summary_state,
                    "bundle_digest": ref["bundle_digest"], "generation": ref["generation"],
                    "freshness_at_lookup": ref["freshness"], "looked_up_at": ref["as_of"],
                    "age_s_at_generation": ref_age(ref["as_of"]),
                    "trust_check": ref["trust_check"], "source_kind": ref["source_kind"],
                    "citation": citation, "citation_state": citation_state,
                    "generation_now": current.get("generation") if is_fresh else None,
                    "superseded": superseded, "superseded_basis": basis})
        source, status = "explanation_ledger", "available" if citations else "unavailable"
        code = None if citations else ("knowledge_" + (state or "skipped"))
    elif row is not None and row["explanation"]["knowledge_refs"]:
        for ref in row["explanation"]["knowledge_refs"]:
            name, name_state = phrase(ref["name"], 120)
            citations.append({
                "technique_id": ref["technique_id"], "claim_id": ref["claim_id"],
                "name": name, "name_state": name_state,
                "bundle_digest_short": ref.get("bundle_digest_short"),
                "generation": ref.get("generation"),
                "freshness_at_lookup": ref.get("freshness"), "looked_up_at": ref.get("as_of"),
                "age_s_at_generation": ref_age(ref.get("as_of")),
                "citation_state": "withheld" if ref.get("citation") else "none"})
            if ref.get("citation"):
                hide.drop("knowledge_free_text")
        source, status, code = "recent_snapshot", "partial", explanation_code
    else:
        source, status = None, "unavailable"
        code = explanation_code if explanation_code != "read" else "no_citation_recorded"
    shown, display = _shown(citations, SHOW_CITATIONS, lambda c: c.get("looked_up_at"))
    return {"status": status, "reason_code": code, "authority": "knowledge_advisory",
            "source": source, "citations": shown, "citations_display": display,
            "lite_now": current}


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
_AUDIT_WORD = re.compile(r"[a-z][a-z0-9_]{0,63}")
#: The incident event types the explainer forwards to auditd.
INCIDENT_AUDIT_TYPES = ("edge.incident.opened", "edge.incident.escalated",
                        "edge.incident.closed")


def _operator(audit: Chain, window_from, now, hide) -> dict:
    from .edge_intake import ACTIONS

    def value(v):
        if type(v) is int and 0 <= v < 2**63:
            return v
        if type(v) is str and _AUDIT_WORD.fullmatch(v):
            return v
        hide.drop("audit_value")
        return "withheld"

    def at(v):
        return v if type(v) is str and _epoch(v) is not None else None

    incident_audit, node = [], []
    for event in audit.kept:
        kind = event["event_type"]
        if kind.startswith("edge.incident."):
            incident_audit.append({
                "event_type": kind if kind in INCIDENT_AUDIT_TYPES else "other",
                "occurred_at": at(event.get("occurred_at")),
                "most_severe": event.get("most_severe") if type(event.get("most_severe")) is int
                and 0 <= event["most_severe"] <= 10 else None,
                "edge_would": event.get("edge_would") if event.get("edge_would") in ACTIONS
                else None})
            continue
        if "actor" in event:
            hide.drop("operator_identity")
        node.append({"event_type": kind, "occurred_at": at(event.get("occurred_at")),
                     **{k: value(event.get(k)) for k in OPERATOR_EVENT_FIELDS[kind]},
                     "actor": "withheld" if "actor" in event else None})
    node_shown, node_display = _shown(node, SHOW_AUDIT_EVENTS, lambda a: a["occurred_at"])
    inc_shown, inc_display = _shown(incident_audit, SHOW_AUDIT_EVENTS,
                                    lambda a: a["occurred_at"])
    return {
        "status": "available" if audit.status == "read" else "unavailable",
        "reason_code": None if audit.status == "read" else audit.reason_code,
        "source": "audit_chain",
        "chain": audit.verified(),
        "incident_scoped": _unavailable("no_operator_action_record_type_for_incidents"),
        "window": {"from": _iso(window_from), "to": _iso(now)},
        "node_actions": node_shown, "node_actions_display": node_display,
        "incident_audit": inc_shown, "incident_audit_display": inc_display,
        "means": "Nexus records no acknowledgement or approval of an incident; listed are "
                 "node-level actions in the window, not actions taken on this incident",
    }


def _impact(noc_snap, execution) -> dict:
    noc, fresh = noc_snap
    observed = _unavailable("noc_snapshot_unavailable")
    if noc is not None and noc["collection"] == "failed":
        observed = _unavailable(noc["reason_code"] or "collection_failed", snapshot=fresh)
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
        observed = {"status": "observed" if fresh["freshness"] == "fresh" else "stale_last_recorded",
                    "reason_code": fresh["freshness_reason"], "snapshot": fresh,
                    "observation": "passive",
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


def _loop(snaps) -> dict:
    def snap(name, fields):
        value, fresh = snaps[name]
        if value is None:
            return _unavailable("snapshot_unavailable")
        return {"status": "read" if fresh["freshness"] == "fresh" else "stale_last_recorded",
                "reason_code": fresh["freshness_reason"], "snapshot": fresh,
                **{k: value[k] for k in fields},
                "refused": {k: v for k, v in sorted(value["refused"].items())}}
    return {"intake": snap("intake_status_snapshot", ("storage_failed",)),
            "explainer": snap("explainer_status_snapshot",
                              ("chain_broken", "storage_failed", "mio_available",
                               "knowledge_available"))}


_UNCONFIRMED_JA = {
    "edge_judgement_unreviewed": "Edge の判断（would）が妥当かは人が確認していない",
    "evidence_content_not_included": "証拠の中身（生データ）は含めていない。必要なら digest で現地に依頼する",
    "business_impact_not_assessed": "業務影響はノードでは評価していない。担当者が直接伝える",
    "source_address_withheld": "送信元アドレス・ルール番号・宛先ポートは伏せている",
    "ai_advice_unverified": "AI の見解は推測であり検証されていない",
    "no_ai_answer": "AI の回答はない（決定論的経路または利用不可）",
    "occurrence_time_unverified": "発生当時に時計が同期していた証拠はない",
    "occurrence_time_untrusted": "記録された発生時刻に矛盾・異常がある",
    "clock_untrusted": "生成時の時計が信頼できない兆候がある。時刻は前後し得る",
    "clock_unverified": "生成時の時計の同期を示す証拠がない",
    "incident_ledger_unavailable": "インシデント台帳を検証付きで読めていない",
    "explanation_ledger_unavailable": "説明台帳を読めていない（root で実行すると読める）",
    "audit_unavailable": "監査記録を読めていない（root で実行すると読める）",
    "audit_unanchored": "監査記録は読んだ範囲の連続性だけを確かめた（先頭からは検証していない）",
    "ledger_gap": "インシデント台帳に欠落・切詰め・回復の記録がある",
    "evidence_not_stored": "一部の証拠は保存されていない（容量上限）",
    "knowledge_superseded": "引用した Knowledge の世代は現在の世代と異なる",
    "knowledge_current_unknown": "Knowledge の現在の世代は最新の記録で確認できない",
    "knowledge_unavailable": "Knowledge の引用がない、または読めていない",
    "stale_snapshot": "期限切れの状態記録がある（最終記録であり、現在の状態は未確認）",
    "free_text_withheld": "許可した固定文・単純な語句でない自由文は伏せた",
    "display_truncated": "表示件数を超えた記録は省略した（集計と最新状態は全件から計算）",
    "incident_open": "インシデントはまだ閉じていない（生成後も続く可能性がある）",
}


def _unconfirmed(p) -> list:
    items = ["edge_judgement_unreviewed", "evidence_content_not_included",
             "business_impact_not_assessed", "source_address_withheld"]
    explanations = p["ai_assessment"].get("explanations", [])
    items.append("ai_advice_unverified" if any(e["labelled_ai_output"] for e in explanations)
                 else "no_ai_answer")
    occurrence = p["time"]["occurrence"]["status"]
    items.append("occurrence_time_untrusted" if occurrence == "untrusted"
                 else "occurrence_time_unverified")
    clock = p["time"]["generation_clock"]["status"]
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
    elif not sources["audit_chain"]["verified"]["anchored"]:
        items.append("audit_unanchored")
    if p["observed_facts"].get("ledger", {}).get("gaps"):
        items.append("ledger_gap")
    if p["evidence_refs"].get("transitions_with_evidence_not_stored"):
        items.append("evidence_not_stored")
    citations = p["knowledge"]["citations"]
    if any(c.get("superseded") for c in citations):
        items.append("knowledge_superseded")
    if any(c.get("superseded") is None and "superseded_basis" in c for c in citations):
        items.append("knowledge_current_unknown")
    if p["knowledge"]["status"] == "unavailable":
        items.append("knowledge_unavailable")
    if any(s.get("freshness") not in (None, "fresh") for s in p["sources"]):
        items.append("stale_snapshot")
    suppressed = p.get("confidentiality", {}).get("suppressed") or {}
    if any(suppressed.get(k) for k in ("ai_free_text", "knowledge_free_text", "audit_value")):
        items.append("free_text_withheld")
    displays = [p["observed_facts"].get("transitions_display"),
                p["ai_assessment"].get("explanations_display"),
                p["evidence_refs"].get("refs_display"),
                p["knowledge"].get("citations_display"),
                p["operator_actions"].get("node_actions_display")]
    if any(d and d["omitted"] for d in displays):
        items.append("display_truncated")
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


_WORDS_JA = {"available": "あり", "partial": "一部のみ", "unavailable": "なし",
             "read": "読取済", "observed": "観測済", "not_executed": "実行なし",
             "stale_last_recorded": "最終記録のみ（現在は未確認）"}


def _state_ja(section) -> str:
    status = section.get("status")
    code = section.get("reason_code")
    word = _WORDS_JA.get(status, str(status))
    if status in ("read", "available", "observed"):
        return word
    return word + (f"（理由: `{code}`）" if code else "")


def _age_ja(section) -> str:
    snap = section.get("snapshot")
    if not snap:
        return ""
    age = "不明" if snap["age_s"] is None else f"{snap['age_s']} 秒前"
    return f"（記録 {_md(snap['written_at'])}、{age}、期限 {snap['stale_after_s']} 秒）"


def _omitted_ja(display) -> str:
    if not display or not display["omitted"]:
        return ""
    r = display["omitted_range"]
    return (f"（全 {display['total']} 件のうち古い {display['omitted']} 件を省略: "
            f"{_md(r['from'])} 〜 {_md(r['to'])}）")


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
        "材料がない欄は正常値で埋めず「なし」と理由を書いている。"
        "期限を過ぎた状態記録は「最終記録のみ（現在は未確認）」と書いている。")
    add("")

    t = p["time"]
    o_clock = t["occurrence"]
    c = t["generation_clock"]
    add("## 1. 発生時刻と時刻の信頼性")
    add("")
    add(f"- 発生時刻（初観測）: {_md(t['occurred_at'])}（出典: `{t['occurred_at_source']}`）")
    add(f"- 最終観測: {_md(t['last_seen'])}")
    add(f"- 発生時刻の信頼性: `{o_clock['status']}`（`{o_clock['reason_code']}`）。"
        "発生当時に時計が同期していたことを示す記録はない。")
    if o_clock["signals"]:
        add("- 発生時刻の異常: " + "、".join(f"`{s}`" for s in o_clock["signals"]))
    add(f"- 生成時の時計: `{c['status']}`" + (f"（`{c['reason_code']}`）" if c["reason_code"] else ""))
    add(f"- 起動後の時刻同期の記録: {_md(c['synchronized_this_boot']['status'])}"
        "（同期が一度あったことを示すだけで、今も正しいこと・時刻源の真正性・発生より前に同期したことは示さない）")
    floor = c["knowledge_floor"]
    add(f"- Knowledge の時計の床: {_md(floor['floor_utc'])}（{_state_ja(floor)}）")
    if c["signals"]:
        add("- 生成時の時計を疑う兆候: " + "、".join(f"`{s}`" for s in c["signals"]))
    add("")

    o = p["observed_facts"]
    add("## 2. 観測事実（Edge の観測）")
    add("")
    add(f"状態: {_state_ja(o)}{_age_ja(o)}")
    s = o.get("summary")
    if s:
        add("")
        add(f"- 観測期間: {_md(s['first_seen'])} 〜 {_md(s['last_seen'])}")
        add(f"- 件数: {s['count']}、最も高い重大度: {s['most_severe']}（1 が最も重い）")
        add(f"- ATT&CK 技術: {_md(', '.join(s['technique_ids']) or 'なし')}")
        if "category" in s:
            add(f"- 分類: {_md(s['category'])}、プロトコル: {_md(s['protocol'])}、"
                f"最新の遷移: {_md(s['latest_transition'])}")
    if o.get("transitions"):
        add("")
        add("遷移の履歴" + _omitted_ja(o.get("transitions_display")) + ":")
        add("")
        add("| 時刻 | 遷移 | 件数 | 重大度 | 証拠保存 |")
        add("| --- | --- | --- | --- | --- |")
        for r in o["transitions"]:
            add(f"| {_md(r['at'])} | {_md(r['event_type'])} | {r['count']} | {r['most_severe']} | "
                f"{'あり' if r['evidence_stored'] else '**なし**'} |")
    ledger = o.get("ledger", {})
    if ledger.get("gaps"):
        add("")
        add(f"台帳の欠落・切詰め・回復（{ledger['gaps_total']} 件）: " + "、".join(
            f"{_md(g['kind'])}（{_md(g['at'])}）" for g in ledger["gaps"]))
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
        if d["decisions_display"]["omitted"]:
            add("- 判断の履歴" + _omitted_ja(d["decisions_display"]))
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
    add(f"- 現在の M.I.O. 経路の能力: {_state_ja(cap)}{_age_ja(cap)}"
        + (f" 記録された能力 `{cap.get('state')}`" if "state" in cap else ""))
    add("- 外部（リモート）AI: インシデント説明では使っていない")
    add("- 注意: 説明器はローカル経路の回答をすべて「AI の助言」と区分する。"
        "生成方式は本文の固定文（banner）から判定し、判定できない本文は伏せる。")
    for x in ai.get("explanations", []):
        add("")
        label = ("説明器の区分では AI の助言" if x["labelled_ai_output"]
                 else "AI の出力ではない")
        add(f"### {_md(x['explained_at'] or '時刻不明')} — 経路 `{x['route']}`（{label}: {_md(x['content_label'])}）")
        add("")
        add(f"生成方式: `{x['generation_method']}`、本文: `{x['text_state']}`")
        if x.get("text"):
            add("")
            add("> " + _md(x["text"]))
        if x.get("notice"):
            add("")
            add("> " + _md(x["notice"]))
        if x["failure_codes"]:
            add("")
            add("失敗・制限の記録: " + "、".join(f"`{f}`" for f in x["failure_codes"]))
    if ai.get("explanations_display", {}).get("omitted"):
        add("")
        add("説明の記録" + _omitted_ja(ai["explanations_display"]))
    add("")

    b = p["business_impact"]
    add("## 6. 業務影響")
    add("")
    add(f"- 評価: なし（`{b['assessment']['reason_code']}`）。担当者が専門家へ直接伝える。")
    n = b["connectivity_observed"]
    if n.get("status") in ("observed", "stale_last_recorded"):
        add(f"- 通信の受動観測: {_state_ja(n)}{_age_ja(n)} "
            f"インターフェース {_md(n['interfaces'])}、リンクあり {n['carrier_up']}、なし {n['carrier_down']}、"
            f"IPv4 既定経路 {_md(n['ipv4_default_routes'])}。到達性は測っていない。")
    else:
        add(f"- 通信の観測: {_state_ja(n)}")
    add(f"- Nexus 経由で実行した通信制限: {b['restrictions_executed_by_nexus']} 件")
    add("")

    ev = p["evidence_refs"]
    add("## 7. 証拠参照（digest のみ）")
    add("")
    add(f"状態: {_state_ja(ev)}。生データは含めていない。" + _omitted_ja(ev.get("refs_display")))
    for r in ev.get("refs", []):
        add(f"- {_md(r['role'])}: `{r['digest']}`（{_md(r['cited_at'])}）")
    add("")

    k = p["knowledge"]
    add("## 8. Knowledge の出典・世代・鮮度")
    add("")
    add(f"状態: {_state_ja(k)}" + _omitted_ja(k.get("citations_display")))
    now_k = k["lite_now"]
    add(f"- 現在の Knowledge Lite: {_state_ja(now_k)}{_age_ja(now_k)}"
        + (f" 世代 {now_k.get('generation')}、鮮度 `{now_k.get('freshness')}`"
           if "generation" in now_k else ""))
    for ref in k["citations"]:
        digest = ref.get("bundle_digest") or ref.get("bundle_digest_short")
        name = ref["name"] if ref["name"] else f"（名前は伏せた: {ref['name_state']}）"
        superseded = {True: "、**現在の世代と異なる**", False: "、現在の世代と同じ",
                      None: "、現在の世代は未確認"}[ref.get("superseded")]
        add(f"- {_md(ref['technique_id'])} {_md(name)}: 世代 {_md(ref.get('generation'))}、"
            f"参照時の鮮度 `{ref.get('freshness_at_lookup')}`、参照時刻 {_md(ref.get('looked_up_at'))}、"
            f"bundle `{digest}`" + superseded)
    add("")

    op = p["operator_actions"]
    add("## 9. 担当者の操作（監査記録）")
    add("")
    add(f"状態: {_state_ja(op)}（chain: `{op['chain']['status']}`、"
        f"{'先頭から検証' if op['chain']['anchored'] else '読んだ範囲のみ検証'}）")
    add("- このインシデントに対する担当者の承認・確認の記録: なし（Nexus にその記録種別がない）")
    add(f"- 対象期間 {_md(op['window']['from'])} 〜 {_md(op['window']['to'])} のノード操作（操作者名は伏字）"
        + _omitted_ja(op.get("node_actions_display")) + ":")
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
        "ホスト名・パス・経路・操作者名）は含めない。製品の固定文と、単純な英単語だけの語句以外の"
        "自由文は伏せた。書く前に全文字列を検査し、識別子・パス・符号化値・秘密らしい形が"
        "残っていれば書かない。")
    add("")
    add(f"抑制した件数（合計 {conf['suppressed_total']}）:")
    for name, value in conf["suppressed"].items():
        if value:
            add(f"- `{name}`: {value}")
    add("- 読んでいないもの: " + "、".join(f"`{x}`" for x in conf["not_read"]))
    add("")

    add("## 12. 読んだ情報源")
    add("")
    add("| 情報源 | 状態 | 理由 | 鮮度 | 読める権限 |")
    add("| --- | --- | --- | --- | --- |")
    for src in p["sources"]:
        add(f"| `{src['source']}` | {src['status']} | {src['reason_code'] or ''} | "
            f"{src.get('freshness') or ''} | {src['readable_by']} |")
    add("")
    return "\n".join(lines)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2,
                      allow_nan=False).encode("utf-8") + b"\n"


def encode_files(package: dict) -> dict:
    """`{name: bytes}` for the three files; the manifest last. Refuses a leak."""
    leaks = scan_package(package)
    markdown = render_markdown(package)
    for category in scan_markdown(markdown):
        if category not in leaks:
            leaks.append(category)
    if leaks:
        raise HandoffRefused("suppression_incomplete:" + ",".join(sorted(leaks)))
    files = {JSON_NAME: _canonical(package), MARKDOWN_NAME: markdown.encode("utf-8")}
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
    leaks = scan_package(manifest)
    if leaks:
        raise HandoffRefused("suppression_incomplete:" + ",".join(sorted(leaks)))
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
        if info.st_uid != os.geteuid():
            raise HandoffRefused("output_dir_not_owned")
        return fd
    except BaseException:
        os.close(fd)
        raise


def package_name(package: dict) -> str:
    stamp = package["generated_at"].replace("-", "").replace(":", "")
    return f"azazel-handoff-{package['incident']['incident_id']}-{stamp}"


@dataclass(frozen=True)
class WriteResult:
    """Where the package is, and whether its directory entries were synced.

    `durable` is False when every file was written and synced but syncing
    the directory or its parent failed: the package exists and its manifest
    verifies, but a power cut could still lose it.
    """

    path: Path
    durable: bool
    #: Steps after the files were synced that failed (closing a file or a
    #: directory). The package is in place; its state is to be verified.
    problems: tuple = ()


def write_package(parent: Path, name: str, files: dict, *, statvfs=os.fstatvfs,
                  write=os.write, fsync=os.fsync, mkdir=os.mkdir,
                  close=os.close) -> WriteResult:
    """Write `files` into a new directory `parent/name`, or say what is left.

    Nothing that exists is replaced: the directory is made with `mkdir`
    (which fails on any existing entry: a file, a directory, a link) and
    each file with `O_CREAT | O_EXCL` inside it. The manifest is written
    last, so a directory without one whose digests verify is not a package.

    Nothing is deleted on failure. Deleting by name after a check is a race
    with whatever else can write the directory, so a failure after `mkdir`
    reports the path that is left (incomplete: no verified manifest). The
    files this call opened are truncated through their own descriptors, so
    a full disk gets its space back without touching any name.

    Scope: `parent` must belong to this user and not be group or world
    writable (`_open_output`), so only this user or root can race it.
    """
    if not re.fullmatch(r"azazel-handoff-inc-[0-9a-f]{16}-[0-9TZ]{16}", name):
        raise HandoffRefused("package_name_refused")
    if list(files)[-1] != MANIFEST_NAME:
        raise HandoffRefused("manifest_not_last")
    parent_fd = _open_output(parent)
    target = Path(parent) / name
    made = False
    directory_fd = None
    opened = []
    failure = None
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
        try:
            mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise HandoffRefused("output_exists") from None
        made = True
        directory_fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        info = os.fstat(directory_fd)
        # What was opened must look like what mkdir just made: this user's,
        # private, and empty. Anything else is not written into.
        if (info.st_uid != os.geteuid() or info.st_mode & 0o077
                or os.listdir(directory_fd)):
            raise HandoffRefused("output_replaced", remnant=target, remnant_kind="unverified")
        for file_name, raw in files.items():
            fd = os.open(file_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
            opened.append(fd)
            view = memoryview(raw)
            while view:
                n = write(fd, view)
                if n <= 0:
                    raise OSError(errno.EIO, "short write")
                view = view[n:]
            fsync(fd)
    except OSError as exc:
        _truncate(opened)
        failure = HandoffRefused("insufficient_space" if exc.errno in (errno.ENOSPC, errno.EDQUOT)
                                 else "write_failed", remnant=target if made else None,
                                 remnant_kind="incomplete")
    except HandoffRefused as refused:
        _truncate(opened)
        if made and refused.remnant is None:
            refused.remnant, refused.remnant_kind = target, "incomplete"
        failure = refused
    # Every descriptor is closed, whatever else failed; a close that fails
    # is recorded beside the original outcome and never replaces it.
    problems = [] if _close_all(opened, close) else ["file_close_failed"]
    if failure is not None:
        if not _close_all((fd for fd in (directory_fd, parent_fd) if fd is not None), close):
            problems.append("directory_close_failed")
        failure.problems = tuple(problems)
        raise failure from None
    # Published: every file is complete and synced. What remains is making
    # the directory entries durable; failing that is reported, not undone.
    durable = True
    for fd in (directory_fd, parent_fd):
        try:
            fsync(fd)
        except OSError:
            durable = False
    if not _close_all((directory_fd, parent_fd), close):
        problems.append("directory_close_failed")
    return WriteResult(target, durable, tuple(problems))


def _close_all(descriptors, close=None) -> bool:
    """Close each descriptor; False if any close failed. Never stops early."""
    close = close or os.close
    ok = True
    for fd in list(descriptors):
        try:
            close(fd)
        except OSError:
            ok = False
    return ok


def _truncate(descriptors) -> None:
    """Give back the space of files this call opened, through their fds only."""
    for fd in descriptors:
        try:
            os.ftruncate(fd, 0)
        except OSError:
            pass
