"""Child for `test_mio_remote_consent_w471.py` (not collected).

Real `MioEntryService` processes, one per call.

`first <root> <fifo> <plan-json>`: grants the four prerequisites, then
withdraws as the operator. `plan` keys:
  stop      "before_record" (block when the withdrawal record is about to be
            written; the store already holds it), or "after_reply"
  fault     "unavailable" | "unknown_present": the ledger fault applied to
            the withdrawal's line (and to nothing else)
  settle_unknown  after the fault, let the guard settle, but make the
            late record's own write of unknown outcome (line present)
  internal  make an internal withdrawal (ENTRYD_ACTOR) instead
  at_days_ago the store stamps the withdrawal that many days ago
It posts one JSON line to the FIFO and then blocks until it is killed.

`restart <root> <plan-json>`: composes the service on the same state (the
verification of the ledger included), then, when the code has one, runs the
start-up recovery of the withdrawal record and prints JSON. `plan` keys:
  fault     "unavailable" | "unknown_present" | "unavailable_until"
            (a file named by `flag` exists: appends fail)
  park      <fifo>: after recovering, post and block (killed by the parent)
  then      "withdraw": a new operator withdrawal while the debt is open
  heal      remove the flag and settle (the tick) before printing

`oldrows <root>`: one row of a process; the parent renames its segment
to a day 20 days ago and runs it again (retention keeps 14 days).

`plant <root> <events-json>`: rows of any shape written through the ledger.

`setonly <root> <expected>`: one `set` naming `expected` (a later generation).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace


def _compose(root: str):
    from azazel_nexus_runtime import mio_entryd as entry
    from azazel_nexus_runtime import mio_socket_client as client
    from azazel_nexus_runtime import runtime_paths
    from azazel_nexus_runtime.principal import Principal, PrincipalClass

    os.environ["AZAZEL_ROOT"] = root
    runtime_paths.ROOT = Path(root)
    client.pwd.getpwnam = lambda _: SimpleNamespace(pw_uid=os.getuid())
    client.grp.getgrnam = lambda _: SimpleNamespace(gr_gid=os.getgid())
    state = runtime_paths.mio_state_dir()
    if not state.exists():
        state.mkdir(parents=True)
        state.chmod(0o700)
    operator = Principal(1001, 1001, 1, frozenset({PrincipalClass.OPERATOR}))
    return entry, operator


def _post(fifo: str, payload: dict) -> None:
    deadline = time.monotonic() + 30
    while True:
        try:
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            break
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.01)
    os.write(fd, json.dumps(payload).encode() + b"\n")
    os.close(fd)


def _fault_append(service, kind: str, only=lambda event: True, flag: str | None = None):
    """Wrap the ledger's single-line write: `unavailable` writes nothing;
    `unknown_present` writes the line and then reports an unknown outcome."""
    from azazel_nexus.audit import AuditOutcomeUnknown, AuditUnavailable

    ledger = service.router.ledger
    real = ledger._append_once
    fired = {"n": 0}

    def append(event, **kw):
        if not only(event) or (flag is not None and not os.path.exists(flag)):
            return real(event, **kw)
        fired["n"] += 1
        if kind.startswith("unknown") and fired["n"] > 1:
            return real(event, **kw)
        if kind == "unknown_present" and fired["n"] == 1:
            entry = real(event, **kw)
            raise AuditOutcomeUnknown(
                "injected", entry=entry, path=ledger._target(),
                absent_head=(entry.sequence - 1, entry.previous_hash))
        if kind == "unknown_absent" and fired["n"] == 1:
            # A complete line that is not in the file: the outcome is unknown
            # and a settling finds the head where it would have been.
            from azazel_nexus.audit import AuditEntry

            head = ledger.head()
            draft = AuditEntry(head[0] + 1, head[1], "", event)
            entry = AuditEntry(draft.sequence, draft.previous_hash, draft.recomputed(), event)
            raise AuditOutcomeUnknown("injected", entry=entry, path=ledger._target(),
                                      absent_head=head)
        raise AuditUnavailable("injected")

    ledger._append_once = append
    return fired


def _is_withdrawn(event) -> bool:
    return event.get("event_type") == "mio.remote.opt_in.withdrawn"


def _is_late_withdrawn(event) -> bool:
    return (event.get("event_type") == "audit.late_record"
            and event.get("late_event", {}).get("event_type") == "mio.remote.opt_in.withdrawn")


def first(root: str, fifo: str, plan: dict) -> None:
    entry, operator = _compose(root)
    from azazel_nexus.mio_profile import PREREQUISITES

    service = entry.MioEntryService()
    for expected, prerequisite in enumerate(PREREQUISITES):
        service.handle(SimpleNamespace(
            verb=entry.OPT_IN_SET_VERB, principal=operator,
            arguments={"prerequisite": prerequisite.value, "expected_generation": expected}))
    granted = service.consent.reading()
    base = {"granted_generation": granted.generation, "granted_status": granted.status}
    if plan.get("at_days_ago"):
        then = (datetime.now(UTC) - timedelta(days=plan["at_days_ago"])).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        service.consent._clock = lambda: then
    if plan.get("max_two"):
        # At the highest generation a withdrawal is written at the same
        # generation: two withdrawals then differ only by their time.
        from azazel_nexus_runtime.mio_remote_consent import ConsentRecord, _MAX_GENERATION

        service.consent._change(
            lambda cur, g: ConsentRecord(generation=_MAX_GENERATION, granted=cur.granted,
                                         operator=cur.operator, at=cur.at),
            over_rollback=True)
        service.consent._clock = lambda: "2026-11-24T10:00:00Z"
        service.handle(SimpleNamespace(
            verb=entry.OPT_IN_WITHDRAW_VERB, principal=operator,
            arguments={"reason": "operator_request"}))
        service.consent._clock = lambda: "2026-11-24T10:00:05Z"
    if plan.get("internal"):
        service.consent.withdraw("opt_in_not_confirmed", operator=entry.ENTRYD_ACTOR,
                                 drain=False)
        _post(fifo, {**base, "internal": True})
        time.sleep(600)
    real_record = service.router._record
    if plan.get("stop") == "before_record":
        def record(event, **kw):
            if _is_withdrawn(event):
                _post(fifo, base)
                time.sleep(600)
            return real_record(event, **kw)

        service.router._record = record
    if plan.get("fault"):
        fired = _fault_append(service, plan["fault"], only=_is_withdrawn)
    if plan.get("settle_unknown"):
        # The withdrawal's own line fails (unavailable); its late record is
        # then written, present, with an unknown outcome.
        _fault_append(service, "unknown_present", only=_is_late_withdrawn)
    try:
        reply = {"returned": service.handle(SimpleNamespace(
            verb=entry.OPT_IN_WITHDRAW_VERB, principal=operator,
            arguments={"reason": "operator_request"}))}
    except entry.RequestRefused as exc:
        reply = {"refused": exc.detail}
    if plan.get("settle_unknown"):
        service.guard.settle_owed()
    _post(fifo, {**base, "reply": reply})
    time.sleep(600)


def _view(service) -> dict:
    reading = service.consent.reading()
    return {"generation": reading.generation, "status": reading.status,
            "permits": reading.permits}


def restart(root: str, plan: dict) -> None:
    entry, operator = _compose(root)
    service = entry.MioEntryService()
    flag = plan.get("flag")
    if plan.get("fault") == "unavailable_until":
        _fault_append(service, "unavailable", flag=flag)
    elif plan.get("fault"):
        _fault_append(service, plan["fault"], only=_is_late_withdrawn)
    recover = getattr(service, "recover_withdrawal", None)
    out = {"has_recovery": recover is not None}
    if recover is not None:
        out["recovery"] = recover()
    def recovered_rows() -> int:
        return sum(1 for item in service.router.ledger
                   if item.event.get("recovered_from") == "consent_store")

    if plan.get("settle"):
        out["rows_before_settle"] = recovered_rows()
        out["settled"] = service.guard.settle_owed()
        out["rows_after_settle"] = recovered_rows()
    if plan.get("park"):
        _post(plan["park"], {"parked": True})
        time.sleep(600)
    status = lambda: service.handle(SimpleNamespace(  # noqa: E731
        verb=entry.OPT_IN_STATUS_VERB, principal=operator, arguments={}))
    out["status_1"] = status()
    out["store_1"] = _view(service)
    if plan.get("then") == "withdraw":
        try:
            out["new_withdraw"] = {"returned": service.handle(SimpleNamespace(
                verb=entry.OPT_IN_WITHDRAW_VERB, principal=operator,
                arguments={"reason": "operator_request"}))}
        except entry.RequestRefused as exc:
            out["new_withdraw"] = {"refused": exc.detail}
        out["store_after_new_withdraw"] = _view(service)
    if plan.get("heal"):
        os.unlink(flag)
        service.guard.settle_owed()
        out["status_2"] = status()
    out["store_2"] = _view(service)
    print(json.dumps(out))


def oldrows(root: str) -> None:
    """One row of a process that ran today (the parent then dates its segment 20 days back)."""
    entry, _ = _compose(root)
    service = entry.MioEntryService()
    service.router.ledger.prepare()
    service.router._record({"event_type": "mio.entry.started"}, reserved=True)


def plant(root: str, events: list) -> None:
    """Hash-valid rows of any shape, written through the ledger (not by hand)."""
    entry, _ = _compose(root)
    service = entry.MioEntryService()
    service.router.ledger.prepare()
    for event in events:
        service.router._record(event, reserved=True)


def setonly(root: str, expected: int) -> None:
    entry, operator = _compose(root)
    from azazel_nexus.mio_profile import PREREQUISITES

    service = entry.MioEntryService()
    service.handle(SimpleNamespace(
        verb=entry.OPT_IN_SET_VERB, principal=operator,
        arguments={"prerequisite": PREREQUISITES[0].value, "expected_generation": expected}))
    print(json.dumps(_view(service)))


if __name__ == "__main__":
    if sys.argv[1] == "first":
        first(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]))
    elif sys.argv[1] == "restart":
        restart(sys.argv[2], json.loads(sys.argv[3]))
    elif sys.argv[1] == "plant":
        plant(sys.argv[2], json.loads(sys.argv[3]))
    elif sys.argv[1] == "oldrows":
        oldrows(sys.argv[2])
    else:
        setonly(sys.argv[2], int(sys.argv[3]))
