"""Read-only operator projection; missing components never hide the baseline."""
from __future__ import annotations

import io
import os
import re
import stat

from .edge_intake import read_intake_status
from .incident_explain import RECENT_BYTES, read_explainer_status, read_recent_incidents


def _read(path, reader, limit):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            return reader(stream.read(limit + 1))
    except (OSError, ValueError):
        return None


def _availability(value):
    return "unattempted/skipped" if value is None else "available" if value else "unavailable"


def _guarded(out, fallback, render):
    # Buffered so a failure part-way prints one fixed line, never half a
    # section or exception text, and the rest of status still renders.
    buffer = io.StringIO()
    try:
        render(buffer)
    except Exception:  # noqa: BLE001 - presentation only; status continues
        print(fallback, file=out)
        return
    out.write(buffer.getvalue())


def render_edge_loop(out, *, now):
    """``now`` is None when the caller could not establish the time."""
    _guarded(out, "edge loop: unavailable (internal)", lambda o: _render_edge_loop(o, now))


def _render_edge_loop(out, now):
    if type(now) not in (int, float):
        raise ValueError("time")
    print("edge loop:", file=out)
    from .runtime_paths import (
        edge_intake_status_path, incident_explain_status_path, incident_recent_path,
    )
    intake = _read(edge_intake_status_path(), read_intake_status, 8192)
    explain = _read(incident_explain_status_path(), read_explainer_status, 8192)
    recent = _read(incident_recent_path(), read_recent_incidents, RECENT_BYTES)
    for name, value in (("intake", intake), ("explainer", explain)):
        if value is None:
            print(f"    {name}: unavailable (snapshot absent or refused)", file=out)
            continue
        stale = now - value["written_at"] > 30 or value["written_at"] > now + 5
        print(f"    {name}: {'stale (snapshot expired)' if stale else 'running'}", file=out)
        if name == "intake":
            # Processed includes events tracked while evidence was full, so a
            # live Edge does not look stopped when accepted stops growing.
            at = value["last_processed_at"]
            age = "never" if at is None else f"{max(0, int(now-at))}s"
            print(f"        last processed age: {age}; processed: {value['processed']}; accepted: {value['accepted']}; storage_failed: {value['storage_failed']}", file=out)
            if value["ledger_recovered"]:
                # Each is a torn incident tail cut off at start and kept in
                # the intake's private state; the ledger records the cut.
                print(f"        ledger_recovered: {value['ledger_recovered']} (torn incident tail quarantined; see integration-loop.md)", file=out)
        else:
            print(f"        explained: {value['explained']}; chain_broken: {value['chain_broken']}; storage_failed: {value['storage_failed']}", file=out)
            if value["chain_broken"]:
                print("        inspect_incident_chain_then_remove_cursor_and_restart", file=out)
            print(f"        last attempt: mio {_availability(value['mio_available'])}; knowledge {_availability(value['knowledge_available'])}; audit_forward_dropped: {value['audit_forward_dropped']}; audit_forward_refused: {value['audit_forward_refused']}", file=out)
        refusals = sorted(value["refused"].items(), key=lambda kv: (-kv[1], kv[0]))[:4]
        # Never let a full evidence day or a segment from the future hide
        # behind more frequent refusals.
        for code in ("evidence_segment_full", "segment_from_future"):
            count = value["refused"].get(code)
            if count and (code, count) not in refusals:
                refusals.append((code, count))
        print("        refusals: " + (", ".join(f"{k}={v}" for k, v in refusals) or "none"), file=out)
    if recent is None:
        print("    recent incidents: unavailable (snapshot absent or refused)", file=out)
        return
    stale = now - recent["written_at"] > 30 or recent["written_at"] > now + 5
    print("    recent incidents:" + (" stale (snapshot expired)" if stale else ""), file=out)
    for row in recent["incidents"][:5]:
        # most_severe is the minimum seen, edge_would is the latest decision:
        # label both so they are not read as one severity/action pair.
        unstored = " (evidence not stored)" if "evidence_stored" in row else ""
        print(f"        {row['incident_id']} {row['state']} most severe {row['most_severe']} count={row['count']}{unstored}; latest: Edge would {row['edge_would']} (observe-only, not executed); " + ", ".join(row["technique_ids"]), file=out)
        e = row["explanation"]
        codes = " (" + ", ".join(e["failure_codes"]) + ")" if e["failure_codes"] else ""
        summary = e["summary"] or ("awaiting explanation" if e["state"] == "pending" else "no summary")
        print(f"            {e['state']}{codes}: {summary}", file=out)
        for ref in e["knowledge_refs"]:
            print(f"            {ref['technique_id']} {ref['name']} [claim {ref['claim_id']}]", file=out)


def render_fabric_status(report, out):
    _guarded(out, "fabric status view: unavailable (internal)",
             lambda o: _render_fabric_status(report, o))


def _render_fabric_status(report, out):
    try:
        from .fabric_boundary import project_capability
        projection = project_capability(report.capabilities.state, report.capabilities.available)
        if projection.available:
            version = projection.fabric_version
            if type(version) is not str or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:rc[0-9]+|a[0-9]+|b[0-9]+)?", version):
                result = "refused (projection_refused)"
            else:
                result = f"projected (v{version})"
        elif projection.fabric_version is None:
            result = "not available (extra not installed)"
        else:
            result = "refused (projection_refused)"
    except Exception:  # noqa: BLE001 - optional presentation cannot stop status
        result = "refused (projection_refused)"
    print("fabric status view: " + result, file=out)
