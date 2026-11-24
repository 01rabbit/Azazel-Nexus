"""#467: a ledger that cannot take a record does not end a daemon, and a write of unknown outcome is settled.

Each case starts the daemon's real `main()` in a child process (`_w467_child.py`),
serves on a real unix socket (real `serve_forever`, `SocketServer`, registry and
handler), injects the fault at `os.open` / `os.fsync` / `Path.open` for that
daemon's ledger files only, and checks what the caller sees, whether the process
lives, whether diagnostics answer, how many operations and sends happened, what
the ledger holds (the whole chain verifies) and what the next legitimate request
does. Faults: (1) the append fails before anything is written, (2) a complete
line is written and its fsync fails (the line stays), (3) the fault continues and
the ledger cannot be read either.

Peer calls are stubs that count calls (see `_w467_child.py`). SO_PEERCRED does not
exist on macOS, so the child patches the peer credentials; nothing else of the
transport is replaced.

Observed values are written only when `W467_OUT` names a directory:

    W467_OUT=<dir> PYTHONPATH=<clone>/src:<clone>/runtime/src python -m pytest tests/unit/test_w467_audit_unavailable.py
"""

from __future__ import annotations

import json
from collections import Counter
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from azazel_nexus.audit import AuditChainBroken, AuditLedger, GENESIS_HASH
from azazel_nexus_runtime.transport import read_frame, send_frame

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
CHILD = HERE / "_w467_child.py"
OUT = os.environ.get("W467_OUT")

STATE = "r/var/lib/azazel/state"
APP = "r/var/lib/azazel"

# daemon -> directories to create, socket (leaf, name), ledger root, status verb
SPECS = {
    "auditd": dict(dirs=[f"{STATE}/audit", f"{STATE}/auditd", f"{APP}/run/audit",
                         f"{APP}/run/audit-submit"],
                   socket=("audit", "audit"), ledger=f"{STATE}/audit",
                   status="audit.verify"),
    "mio-entryd": dict(dirs=[f"{STATE}/mio", f"{APP}/run/mio-entry", f"{APP}/run/mio-advise"],
                       socket=("mio-entry", "mio-entry"), ledger=f"{STATE}/mio/route",
                       status="mio.remote.opt_in.status"),
    "mio-locald": dict(dirs=[f"{APP}/mio", f"{APP}/run/mio"], socket=("mio", "mio"),
                       ledger=f"{APP}/mio", status="mio.local.admission"),
    "mio-referenced": dict(dirs=[f"{STATE}/mio-reference", f"{APP}/run/mio-reference"],
                           socket=("mio-reference", "mio-reference"),
                           ledger=f"{STATE}/mio-reference", status=None),
    "mio-contextobsd": dict(dirs=[f"{STATE}/mio-contextobs", f"{APP}/run/mio-contextobs"],
                            socket=("mio-contextobs", "mio-contextobs"),
                            ledger=f"{STATE}/mio-contextobs", status=None),
    "knowledge-contextd": dict(dirs=[f"{STATE}/knowledge-context",
                                     f"{APP}/run/knowledge-context"],
                               socket=("knowledge-context", "knowledge-context"),
                               ledger=f"{STATE}/knowledge-context", status=None),
}

ADVICE_FRAME = {"request_id": "w467-unit", "privacy_class": "P0-public",
                "question": "SSH brute-force observations; technique T1110",
                "context": [{"kind": "auth_log", "text": "redacted test fixture"}]}


def _now_z() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _obs_frame() -> dict:
    from test_mio_contextobsd import obs_frame

    return obs_frame()


def request_for(daemon: str, entry: str, variant: int = 0) -> dict:
    """The frame one entry sends. `refusal` is the transport's refusal path."""
    if entry == "refusal":
        return {"verb": "w467.no.such.verb", "arguments": {}}
    if entry in ("opt_in_set", "opt_in_set_other", "opt_in_withdraw"):
        from azazel_nexus.mio_profile import PREREQUISITES
        from azazel_nexus_runtime.mio_entryd import WITHDRAWAL_REASONS

        if entry == "opt_in_withdraw":
            return {"verb": "mio.remote.opt_in.withdraw",
                    "arguments": {"reason": WITHDRAWAL_REASONS[0]}}
        index = 1 if entry == "opt_in_set_other" else 0
        return {"verb": "mio.remote.opt_in.set",
                "arguments": {"prerequisite": list(PREREQUISITES)[index].value}}
    if entry == "verify":
        return {"verb": "audit.verify", "arguments": {}}
    if entry == "observe":
        return {"verb": "mio.contextobs.observe", "arguments": {"deadline_ms": 320},
                "event": _obs_frame()}
    if daemon == "auditd":
        return {"verb": "audit.append",
                "arguments": {"event_type": "commissioning.permanent_mac_read"},
                "event": {"ordinal": 1 + variant, "snapshot": "sha256:" + "a" * 64, "readable": True,
                          "occurred_at": _now_z(), "actor": "w467"}}
    if daemon == "mio-entryd":
        return {"verb": "mio.advise", "arguments": {"deadline_ms": 3000}, "event": ADVICE_FRAME}
    if daemon == "mio-locald":
        return {"verb": "mio.local.infer", "arguments": {"deadline_ms": 3000},
                "event": ADVICE_FRAME}
    if daemon == "mio-referenced":
        return {"verb": "mio.reference", "arguments": {"deadline_ms": 300}, "event": ADVICE_FRAME}
    if daemon == "mio-contextobsd":
        return {"verb": "mio.contextobs.observe", "arguments": {"deadline_ms": 320},
                "event": _obs_frame()}
    techniques = ["T1059", "T1059.001"] + (["T1110"] if variant >= 2 else [])
    return {"verb": "knowledge.context",
            "arguments": {"deadline_ms": 2000, "deadline_monotonic_ns": 2**62},
            "event": {"frame": {"privacy_class": "P0-public", "techniques": techniques}}}


ENTRIES = {
    "auditd": ["append", "verify"],
    "mio-entryd": ["advise", "refusal", "opt_in_set", "opt_in_withdraw", "tick"],
    "mio-locald": ["infer", "refusal"],
    "mio-referenced": ["reference", "refusal"],
    "mio-contextobsd": ["observe", "refusal"],
    "knowledge-contextd": ["context", "refusal"],
}


class Daemon:
    def __init__(self, name: str) -> None:
        self.name, self.spec = name, SPECS[name]
        # The root is relative to the child's cwd, so the socket path is short
        # wherever this directory is.
        self.run = Path(tempfile.mkdtemp(prefix="w467-" + name + "-"))
        for relative in self.spec["dirs"] + ["log"]:
            (self.run / relative).mkdir(parents=True, exist_ok=True)
        if name == "mio-entryd":
            (self.run / f"{STATE}/mio").chmod(0o700)
        self.proc: subprocess.Popen | None = None
        self.ctl_seq = 0
        self.starts = 0

    # -- process ---------------------------------------------------------

    def start(self, timeout: float = 25.0) -> bool:
        self.starts += 1
        for leftover in ("ready", "stop"):
            (self.run / leftover).unlink(missing_ok=True)
        env = {**os.environ, "AZAZEL_ROOT": "r", "PYTHONDONTWRITEBYTECODE": "1"}
        self.stderr_path = self.run / f"log/stderr-{self.starts}.txt"
        self.proc = subprocess.Popen(
            [sys.executable, str(CHILD), self.name], cwd=self.run, env=env,
            stdout=subprocess.DEVNULL, stderr=self.stderr_path.open("wb"))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if (self.run / "ready").exists():
                return True
            if self.proc.poll() is not None:
                return False
            time.sleep(0.05)
        return False

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def exit_info(self) -> dict:
        if self.proc is None or self.proc.poll() is None:
            return {"alive": self.alive()}
        text = self.stderr_path.read_text(errors="replace").strip().splitlines()
        return {"alive": False, "returncode": self.proc.returncode,
                "stderr_last": text[-1][:200] if text else ""}

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            (self.run / "stop").write_text("1")
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def cleanup(self) -> None:
        self.stop()
        shutil.rmtree(self.run, ignore_errors=True)

    # -- faults and log --------------------------------------------------

    def arm(self, mode: str, n: int = 1) -> None:
        self.ctl_seq += 1
        tmp = self.run / "ctl.tmp"
        tmp.write_text(json.dumps({"seq": self.ctl_seq, "mode": mode, "n": n}))
        os.replace(tmp, self.run / "ctl.json")

    def log_lines(self, name: str) -> list:
        path = self.run / "log" / name
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    # -- requests --------------------------------------------------------

    def ask(self, frame: dict, timeout: float = 10.0) -> dict:
        leaf, name = self.spec["socket"]
        path = f"r/var/lib/azazel/run/{leaf}/{name}.sock"
        began = time.monotonic()
        previous = os.getcwd()
        os.chdir(self.run)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout)
                try:
                    connection.connect(path)
                except OSError as error:
                    return {"transport": "connect_failed", "error": type(error).__name__}
                try:
                    send_frame(connection, frame)
                    connection.shutdown(socket.SHUT_WR)
                    raw = read_frame(connection)
                except socket.timeout:
                    return {"transport": "timeout"}
                except Exception as error:  # noqa: BLE001 - closed without a reply
                    return {"transport": "no_reply", "error": type(error).__name__,
                            "elapsed_ms": int((time.monotonic() - began) * 1000)}
                return {"transport": "reply", "reply": _shrink(json.loads(raw)),
                        "elapsed_ms": int((time.monotonic() - began) * 1000)}
        finally:
            os.chdir(previous)

    # -- ledger ----------------------------------------------------------

    def ledger(self) -> dict:
        root = self.run / self.spec["ledger"]
        files = sorted(root.rglob("*.jsonl")) if root.exists() else []
        entries, verdict = [], "ok"
        expected_sequence, expected_hash = 0, GENESIS_HASH
        try:
            for path in files:
                for entry in AuditLedger(path):
                    entries.append(entry)
                    if (entry.sequence != expected_sequence + 1
                            or entry.previous_hash != expected_hash
                            or entry.recomputed() != entry.event_hash):
                        verdict = f"broken at sequence {entry.sequence}"
                        raise AuditChainBroken(verdict)
                    expected_sequence, expected_hash = entry.sequence, entry.event_hash
        except AuditChainBroken as error:
            verdict = verdict if verdict != "ok" else f"broken: {str(error)[:80]}"
        raw_lines = sum(len([line for line in path.read_text().splitlines() if line.strip()])
                        for path in files)
        return {"files": len(files), "lines": raw_lines, "verify": verdict,
                "records": [dict(entry.event) for entry in entries],
                "last_sequence": entries[-1].sequence if entries else 0,
                "last_event": entries[-1].event.get("event_type") if entries else None,
                "events": [entry.event.get("event_type") for entry in entries]}


def _shrink(value, depth: int = 0):
    """Replies keep their shape but not their bulk."""
    if isinstance(value, dict):
        if depth >= 3:
            return "{...}"
        return {key: _shrink(item, depth + 1) for key, item in list(value.items())[:12]}
    if isinstance(value, list):
        return [_shrink(item, depth + 1) for item in value[:4]]
    if isinstance(value, str) and len(value) > 80:
        return value[:80] + "..."
    return value


def _count(lines: list, key: str) -> dict:
    counts: dict = {}
    for line in lines:
        if key in line:
            counts[line[key]] = counts.get(line[key], 0) + 1
    return counts


def measure(daemon: str, entry: str, case: str, n: int = 1) -> dict:
    """One case on a fresh daemon. `case`: clean, pre (1), fsync (2), persist (3)."""
    harness = Daemon(daemon)
    result: dict = {"daemon": daemon, "entry": entry, "case": case, "n": n}
    try:
        if not harness.start():
            result["start"] = harness.exit_info()
            return result
        # One legitimate request first, so the chain is not empty and the
        # daemon is warm. Its ledger writes do not count for the fault.
        warm = WARMUP.get((daemon, entry), entry)
        result["warmup"] = harness.ask(request_for(daemon, warm)) if warm else None
        before = harness.ledger()
        result["ledger_before"] = {key: before[key] for key in ("lines", "last_sequence", "verify")}
        ops_before = len(harness.log_lines("ops.log"))
        faults_before = len(harness.log_lines("faults.log"))
        harness.arm({"clean": "off", "pre": "pre", "fsync": "fsync",
                     "persist": "persist"}[case], n)
        if entry == "tick":
            # No request: the periodic capability reconcile writes the record.
            (harness.run / "flip").write_text("1")
            end = time.monotonic() + 16
            while harness.alive() and time.monotonic() < end:
                time.sleep(0.25)
                if harness.ledger()["lines"] > before["lines"] and case in ("clean", "fsync"):
                    time.sleep(1.0)
                    break
            result["fault_request"] = {"transport": "tick (no request)",
                                       "waited_ms": int((16 - (end - time.monotonic())) * 1000)}
        else:
            result["fault_request"] = harness.ask(request_for(daemon, entry, 1))
        time.sleep(0.3)
        result["process"] = harness.exit_info()
        faults = harness.log_lines("faults.log")[faults_before:]
        result["appends_seen"] = sum(1 for line in faults if line.get("seen") == "write-open")
        result["fsyncs_seen"] = sum(1 for line in faults if line.get("seen") == "ledger-fsync")
        result["faults_fired"] = [line["fault"] for line in faults if "fault" in line]
        result["fault_details"] = [line for line in faults if "fault" in line]
        result["ops_during_fault_request"] = _count(
            harness.log_lines("ops.log")[ops_before:], "op")
        after = harness.ledger()
        result["records_before"] = before["records"]
        result["ledger_after_fault"] = {key: after[key] for key in
                                        ("lines", "last_sequence", "last_event", "verify")}
        result["events_added_by_fault_request"] = after["events"][before["last_sequence"]:]
        status = harness.spec["status"]
        if case == "persist" and harness.alive():
            # A second request while the fault continues.
            result["second_request_during_fault"] = harness.ask(request_for(daemon, entry, 1))
            result["process_after_second"] = harness.exit_info()
        if status is None:
            result["status_verb"] = "none (no diagnostic verb on this daemon)"
        elif harness.alive():
            result["status_verb"] = harness.ask({"verb": status, "arguments": {}})
            result["process_after_status"] = harness.exit_info()
        else:
            result["status_verb"] = "daemon not running"
        # Fault removed; one legitimate request.
        harness.arm("off")
        # Long enough for the daemon with a tick (entryd) to settle on its own first.
        time.sleep(1.0)
        ops_mid = len(harness.log_lines("ops.log"))
        again = RECOVERY.get((daemon, entry), entry)
        if harness.alive():
            result["recovery"] = {"via": "same process",
                                  "reply": harness.ask(request_for(daemon, again, 2))}
        else:
            ok = harness.start()
            result["recovery"] = {"via": "restart (supervisor stand-in)", "restart_ok": ok,
                                  "start": harness.exit_info() if not ok else None}
            if ok:
                result["recovery"]["reply"] = harness.ask(request_for(daemon, again, 2))
        if entry == "tick" and harness.alive():
            # The next tick writes (or settles) the capability record.
            end = time.monotonic() + 8
            while time.monotonic() < end:
                kinds = harness.ledger()["events"]
                if kinds.count("mio.capability.transition") >= 2:
                    break
                time.sleep(0.25)
            (harness.run / "flip").unlink(missing_ok=True)
        if status is not None and harness.alive():
            result["status_after_recovery"] = harness.ask({"verb": status, "arguments": {}})
        final = harness.ledger()
        result["ledger_final"] = {key: final[key] for key in
                                  ("lines", "last_sequence", "last_event", "verify")}
        result["records_final"] = final["records"]
        result["records_after_fault"] = after["records"]
        result["events_added_by_recovery"] = final["events"][after["last_sequence"]:]
        result["ops_recovery"] = _count(harness.log_lines("ops.log")[ops_mid:], "op")
        result["ops_total"] = _count(harness.log_lines("ops.log"), "op")
        result["alive_end"] = harness.alive()
        return result
    finally:
        harness.cleanup()


#: Request sent before the fault, and the one sent after it is lifted, when
#: they differ from the entry's own request.
WARMUP = {("auditd", "verify"): "append", ("mio-entryd", "refusal"): None, ("mio-entryd", "tick"): None,
          ("mio-entryd", "opt_in_set"): "opt_in_set_other",
          ("mio-entryd", "opt_in_withdraw"): "opt_in_set"}
RECOVERY = {("mio-entryd", "refusal"): "advise", ("mio-entryd", "tick"): "advise"}


CASES = [(d, e) for d, entries in ENTRIES.items() for e in entries]

#: Records that are not a request's own line: the guard's, the transport's, startup's.
SYSTEM = frozenset({"audit.outcome_settled", "audit.late_record", "runtime.request_refused",
                    "mio.entry.started", "mio.capability.transition", "mio.capability.carried",
                    "mio.local.playbook_selection", "mio.local.admission", "mio.local.refused",
                    "mio.local.readiness", "knowledge.context.commissioning"})

#: Entries whose success needs a record: a success reply there is an unaudited result.
NEEDS_RECORD = {("auditd", "append"), ("mio-entryd", "advise"), ("mio-entryd", "opt_in_set"),
                ("mio-entryd", "opt_in_withdraw"), ("mio-locald", "infer"),
                ("mio-referenced", "reference"), ("knowledge-contextd", "context")}


def served(daemon: str, entry: str, reply: dict) -> bool:
    """Whether `reply` is the entry's real answer (not a refusal or an in-band failure)."""
    if reply.get("transport") != "reply":
        return False
    body = reply["reply"]
    if body.get("ok") is not True:
        return False
    result = body.get("result", {})
    if (daemon, entry) == ("knowledge-contextd", "context"):
        return "response" in result
    if (daemon, entry) == ("mio-locald", "infer"):
        return result.get("outcome") == "failed" and result.get("refusal") == "not_admitted"
    if (daemon, entry) == ("mio-referenced", "reference"):
        return result.get("outcome") == "unavailable"
    return True


def duplicated(events: list) -> list:
    """Request lines written more than once by one request."""
    counts = Counter(event for event in events if event not in SYSTEM)
    return [event for event, count in counts.items() if count > 1]


#: Entries that never write to the ledger on success: a fault is not expected to fire for 1 and 2.
NO_WRITE = {("mio-contextobsd", "observe"), ("auditd", "verify")}


def expected_records(daemon: str, entry: str, case: str, n: int) -> tuple[int, int]:
    """(settlement records, late records) the whole run must end with, exactly."""
    if (daemon, entry) in NO_WRITE:
        return 0, 0
    if (daemon, entry) == ("mio-entryd", "opt_in_withdraw"):
        # The withdrawal is made before its records: each request owes two (marker, withdrawn).
        if case == "pre":
            return 0, 1
        if case == "persist":
            # The resends are answered from the withdrawal in force, never made again.
            return 0, 2
    if (daemon, entry) == ("knowledge-contextd", "context") and case == "pre" and n == 2:
        return 0, 1
    return (1 if case == "fsync" else 0), 0


def check(result: dict, *, clean: dict) -> None:
    daemon, entry, case, n = result["daemon"], result["entry"], result["case"], result["n"]
    where = f"{daemon}:{entry} {case} n={n}"
    assert "start" not in result, (where, result)
    # The process never ends, whatever the ledger does (alive at every look).
    assert result["process"]["alive"], (where, result["process"])
    assert result.get("process_after_second", {"alive": True})["alive"], where
    assert result.get("process_after_status", {"alive": True})["alive"], where
    assert result["alive_end"], where
    assert result["recovery"]["via"] == "same process", (where, result["recovery"])
    # The caller always gets an answer.
    if entry != "tick":
        assert result["fault_request"].get("transport") == "reply", (where, result["fault_request"])
    # Diagnostics answer while the ledger is failing.
    status = result["status_verb"]
    if isinstance(status, dict):
        assert status.get("transport") == "reply" and status["reply"].get("ok") is True, (where, status)
    else:
        assert status.startswith("none"), (where, status)
    # The next legitimate request is served, and the whole chain verifies.
    again = RECOVERY.get((daemon, entry), entry)
    recovered = result["recovery"]["reply"]
    if again == "refusal":
        assert recovered["reply"] == {"ok": False, "refusal": "unknown_verb"}, (where, recovered)
    else:
        assert served(daemon, again, recovered), (where, recovered)
    assert result["ledger_final"]["verify"] == "ok", (where, result["ledger_final"])
    assert result["ledger_after_fault"]["verify"] == "ok", (where, result["ledger_after_fault"])
    if case == "clean":
        return

    fired = bool(result["faults_fired"])
    # The planned fault really fired, at the planned place.
    if (daemon, entry) not in NO_WRITE or (daemon, entry, case) == ("auditd", "verify", "persist"):
        assert fired, (where, "the injected fault never fired")
    clean_events = [e for e in clean["events_added_by_fault_request"]]
    if fired and case == "pre":
        assert result["fault_details"][0]["fault"] == "open" and result["fault_details"][0]["opens"] == n, (where, result["fault_details"])
    if fired and case == "fsync":
        detail = result["fault_details"][0]
        assert detail["fault"] == "fsync" and detail["fsyncs"] == n, (where, detail)
        # The sync that failed was the one of the planned line.
        if n <= len(clean_events):
            assert detail["event"] == clean_events[n - 1], (where, detail, clean_events)
    # A request that needs its record is never answered with a result while the record failed.
    if (daemon, entry) in NEEDS_RECORD and fired:
        assert not served(daemon, entry, result["fault_request"]), (where, result["fault_request"])
    if case == "persist" and (daemon, entry) in NEEDS_RECORD:
        second = result["second_request_during_fault"]
        assert not served(daemon, entry, second), (where, second)
    # No request line is written twice: over the fault and the recovery together, each kind of
    # line is at most as many as the requests that ran, times what one request writes.
    records = result["records_final"]
    per_request = Counter(e for e in clean_events if e not in SYSTEM)
    requests = ((1 if result.get("warmup") else 0) + (0 if entry == "tick" else 1)
                + (1 if "second_request_during_fault" in result else 0) + 1)
    totals = Counter(r["event_type"] for r in records if r["event_type"] not in SYSTEM)
    for kind, count in totals.items():
        assert count <= requests * max(per_request.get(kind, 1), 1), (where, kind, count, requests)
    settled = [r for r in records if r["event_type"] == "audit.outcome_settled"]
    late = [r for r in records if r["event_type"] == "audit.late_record"]
    # A line of unknown outcome is settled by its sequence and hash, once.
    want_settled, want_late = expected_records(daemon, entry, case, n)
    assert (len(settled), len(late)) == (want_settled, want_late), (where, len(settled), len(late))
    if case == "fsync" and fired:
        assert all(r["outcome"] == "present" for r in settled), (where, settled)
        assert len({r["settled_sequence"] for r in settled}) == len(settled), (where, settled)
    if case == "persist" and fired and entry != "tick":
        # Nothing was written while the ledger could not be read.
        assert result["events_added_by_fault_request"] == [], (where, result["events_added_by_fault_request"])
    # Every owed debt is paid after the fault is lifted.
    assert len({r["settled_sequence"] for r in settled}) == len(settled), where

    ops = result.get("ops_total", {})
    during = result.get("ops_during_fault_request", {})
    kinds = [r["event_type"] for r in records]
    if daemon == "knowledge-contextd" and entry == "context":
        sends = ops.get("send:knowledge-peer.request_context", 0)
        fault_sends = during.get("send:knowledge-peer.request_context", 0)
        # One send per request that got to send: warmup, (fault), recovery. Never a resend.
        assert fault_sends == (1 if (n == 2 and case in ("pre", "fsync")) else 0), (where, during)
        assert sends == 2 + fault_sends, (where, ops, during)
        # Record before send: every send has a `requested` line (a line without a send is fine).
        assert kinds.count("knowledge.context.requested") >= sends, (where, kinds)
        verified = [r for r in records if r["event_type"] == "knowledge.context.completed"
                    and r.get("outcome") == "verified_advisory"]
        owed = [r for r in late if r["late_event"].get("outcome") == "verified_advisory"]
        owed += [r for r in settled if r.get("late_event", {}).get("outcome") == "verified_advisory"]
        # Each send's verified outcome is on the chain once: as its own line or as a late record.
        assert len(verified) + len(owed) == sends, (where, kinds, late, settled)
        reply = result["fault_request"]["reply"]["result"]
        if fault_sends:
            # Sent and not recorded: not reported as "refused before send", and no second `completed`.
            assert reply == {"refusal": "unavailable", "stage": "unrecorded"}, (where, reply)
            added = result["events_added_by_fault_request"]
            assert added.count("knowledge.context.completed") <= 1, (where, added)
        else:
            assert reply == {"refusal": "unavailable", "stage": "refused_before_send"}, (where, reply)
    if daemon == "mio-entryd" and entry == "advise":
        markers = kinds.count("mio.entry.request")
        assess = ops.get("peer-call:locald.assess", 0)
        reference = ops.get("peer-call:referenced.reference", 0)
        # Each peer call follows its request's own marker line, once.
        assert assess <= markers and reference <= assess, (where, ops, markers)
        assert assess == 2 + (1 if during.get("peer-call:locald.assess") else 0), (where, ops, during)
        if case == "persist" or n == 1:
            assert not during, (where, during)
    if daemon == "mio-entryd" and entry == "opt_in_set":
        # Not committed: the record comes first, and the grant is unchanged.
        final = result["status_after_recovery"]["reply"]["result"]
        assert final["generation"] == 2 and final["granted"] == ["privacy policy", "remote use"], (where, final)
        after = result["status_verb"]["reply"]["result"]
        assert after.get("generation") == 1 and after["granted"] == ["privacy policy"], (where, after)
    if daemon == "mio-entryd" and entry == "opt_in_withdraw":
        after = result["status_verb"]["reply"]["result"]
        assert after["status"] == "withdrawn", (where, after)
        withdrawn = kinds.count("mio.remote.opt_in.withdrawn")
        withdrawn += sum(1 for r in late if r["late_event"].get("event_type") == "mio.remote.opt_in.withdrawn")
        withdrawn += sum(1 for r in settled if r.get("late_event", {}).get("event_type") == "mio.remote.opt_in.withdrawn")
        # One withdrawal per request that commits: the fault request and the recovery. The second
        # request while the fault continues (persist) is answered from the first, never committed
        # again. Each withdrawal is recorded exactly once.
        made = 2
        assert withdrawn == made, (where, kinds, late, settled)
    if daemon == "mio-entryd" and entry == "tick":
        assert kinds.count("mio.capability.transition") == 2, (where, kinds)
    if daemon == "mio-contextobsd" and entry == "observe":
        assert result["ledger_final"]["lines"] == result["ledger_before"]["lines"], where
        assert served(daemon, entry, result["fault_request"]), where
    if daemon == "auditd" and entry == "append":
        # Each distinct event is on the chain at most once.
        events = [r for r in records if r["event_type"] == "commissioning.permanent_mac_read"]
        ordinals = Counter(r["ordinal"] for r in events)
        assert all(count == 1 for count in ordinals.values()), (where, ordinals)
        assert ordinals[3] == 1 and ordinals[1] == 1, (where, ordinals)
        # The faulted event (ordinal 2) is on the chain at most once.
        assert ordinals.get(2, 0) <= 1, (where, ordinals)


@pytest.mark.parametrize("daemon,entry", CASES, ids=[f"{d}:{e}" for d, e in CASES])
def test_ledger_failure_is_survived_and_settled(daemon, entry):
    clean = measure(daemon, entry, "clean")
    results = [clean]
    appends = clean.get("appends_seen") or 0
    positions = sorted({1, appends}) if appends > 0 else [1]
    for n in positions:
        results.append(measure(daemon, entry, "pre", n))
        results.append(measure(daemon, entry, "fsync", n))
    results.append(measure(daemon, entry, "persist", 1))
    if OUT:
        Path(OUT).mkdir(parents=True, exist_ok=True)
        path = Path(OUT) / f"acceptance-{daemon}.json"
        existing = json.loads(path.read_text()) if path.exists() else {}
        existing[entry] = results
        path.write_text(json.dumps(existing, indent=1, sort_keys=True))
    assert "reply" in clean.get("fault_request", {}) or entry == "tick", clean
    for result in results:
        check(result, clean=clean)


def test_auditd_resend_of_a_settled_line_returns_the_line_not_a_second_one():
    """The caller of a write of unknown outcome resends the same event: it is answered, not appended again."""
    harness = Daemon("auditd")
    try:
        assert harness.start()
        harness.ask(request_for("auditd", "append", 0))
        harness.arm("fsync", 1)
        frame = request_for("auditd", "append", 1)
        refused = harness.ask(frame)
        assert refused["reply"] == {"ok": False, "refusal": "verb_unavailable"}
        harness.arm("off")
        again = harness.ask(frame)
        assert again["reply"]["ok"] is True and again["reply"]["result"]["sequence"] == 2
        # Another event goes in between; the resend is still answered with the same line.
        other = harness.ask(request_for("auditd", "append", 2))
        assert other["reply"]["result"]["sequence"] == 4
        third = harness.ask(frame)
        assert third["reply"]["result"] == again["reply"]["result"]
        final = harness.ledger()
        assert final["verify"] == "ok" and harness.alive()
        kinds = [r["event_type"] for r in final["records"]]
        assert kinds == ["commissioning.permanent_mac_read", "commissioning.permanent_mac_read",
                         "audit.outcome_settled", "commissioning.permanent_mac_read"], kinds
        assert [r["ordinal"] for r in final["records"] if "ordinal" in r] == [1, 2, 3]
    finally:
        harness.cleanup()


def test_knowledge_resend_of_a_sent_and_unrecorded_request_is_not_sent_again():
    harness = Daemon("knowledge-contextd")
    try:
        assert harness.start()
        harness.ask(request_for("knowledge-contextd", "context", 0))        # one send
        harness.arm("pre", 2)                                               # the `completed` line fails
        frame = request_for("knowledge-contextd", "context", 1)
        first = harness.ask(frame)
        assert first["reply"]["result"] == {"refusal": "unavailable", "stage": "unrecorded"}
        harness.arm("off")
        again = harness.ask(frame)                                          # the same request
        assert again["reply"]["result"] == {"refusal": "unavailable", "stage": "unrecorded"}
        sends = [line for line in harness.log_lines("ops.log")
                 if line["op"] == "send:knowledge-peer.request_context"]
        assert len(sends) == 2                                              # warm-up, the faulted one
        third = harness.ask(frame)                                          # the memory ended
        assert "response" in third["reply"]["result"]
        sends = [line for line in harness.log_lines("ops.log")
                 if line["op"] == "send:knowledge-peer.request_context"]
        assert len(sends) == 3
        final = harness.ledger()
        assert final["verify"] == "ok"
        kinds = [r["event_type"] for r in final["records"]]
        assert kinds.count("knowledge.context.requested") == 3
        assert kinds.count("audit.late_record") == 1 and kinds.count("audit.outcome_settled") == 0
        verified = [r for r in final["records"] if r["event_type"] == "knowledge.context.completed"
                    and r.get("outcome") == "verified_advisory"]
        assert len(verified) == 2     # warm-up and the third; the faulted one is the late record
    finally:
        harness.cleanup()
