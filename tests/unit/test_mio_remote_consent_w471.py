"""#471: the audit row of an operator withdrawal that was committed to the store
but never recorded (entryd stopped between the two).

Real processes. One entryd process (`first`) is stopped with SIGKILL between
the store commit and the ledger record; a second one composes on the same
state; the sender is a third. Order is made with FIFOs; nothing is timed.
"""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from azazel_nexus_runtime.mio_remote_consent import ConsentStore

from azazel_nexus.route_ledger import RouteChain

import test_mio_remote_consent_w465 as w465

# The tests that start a process carry `real_process` one by one (#114): the
# direct function checks at the end of this file are not process evidence.

HERE = Path(__file__).resolve().parent
CHILD = HERE / "_mio_remote_consent_w471_child.py"
OUT = Path(os.environ["W471_OUT"]) if os.environ.get("W471_OUT") else None


def dump(name, data):
    if OUT is not None:
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def age_ledger(root):
    """A route chain whose first segment is 20 days old and whose second is today's.

    The chain does not depend on a segment's date, so the first process's
    segment is renamed; the next process then retires it (retention: 14 days)
    and writes the boundary.
    """
    from datetime import UTC, datetime, timedelta

    for _ in range(2):
        subprocess.run([sys.executable, str(CHILD), "oldrows", str(root)], check=True,
                       env=w465._env(), timeout=60)
        if _ == 0:
            route = state_of(root) / "route"
            (today,) = route.glob("????-??-??.jsonl")
            old = (datetime.now(UTC) - timedelta(days=20)).strftime("%Y-%m-%d")
            today.rename(route / f"{old}.jsonl")


def run_first(tmp_path, plan, tag="first"):
    """Run `first` until it posts, SIGKILL it, and return what it posted."""
    root, fifo = plan.pop("root", None) or tmp_path / "root", tmp_path / f"{tag}.fifo"
    root.mkdir(parents=True, exist_ok=True)
    if plan.get("old_ledger"):
        age_ledger(root)
    os.mkfifo(fifo)
    rfd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    child = subprocess.Popen(
        [sys.executable, str(CHILD), "first", str(root), str(fifo), json.dumps(plan)],
        env=w465._env(), stderr=subprocess.PIPE)
    try:
        buf, deadline = b"", time.monotonic() + 60
        while b"\n" not in buf:
            left = deadline - time.monotonic()
            if left <= 0 or child.poll() is not None:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=10)
                raise AssertionError(child.stderr.read().decode() or "no sync point")
            ready, _, _ = select.select([rfd], [], [], min(left, 1))
            if ready:
                buf += os.read(rfd, 65536)
        posted = json.loads(buf.splitlines()[0])
        child.send_signal(signal.SIGKILL)
        child.wait(timeout=10)
    finally:
        os.close(rfd)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        child.stderr.close()
    assert child.returncode == -signal.SIGKILL
    return posted, root


def run_restart(root, plan=None):
    done = subprocess.run(
        [sys.executable, str(CHILD), "restart", str(root), json.dumps(plan or {})],
        capture_output=True, text=True, timeout=120, env=w465._env())
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def state_of(root):
    return Path(root) / "var/lib/azazel/state/mio"


def withdrawal_rows(root, generation, at=None):
    """Rows that record the withdrawal of `generation` (made at `at`), by kind."""
    chain = RouteChain(state_of(root) / "route")
    found = {"original": 0, "late": 0, "recovered": 0, "settled": 0}
    for item in chain:
        event = item.event
        if event.get("event_type") == "mio.remote.opt_in.withdrawn":
            if event.get("generation") == generation and at in (None, event.get("at")):
                found["original"] += 1
            continue
        late = event.get("late_event")
        if (isinstance(late, dict) and late.get("event_type") == "mio.remote.opt_in.withdrawn"
                and late.get("generation") == generation and at in (None, late.get("at"))):
            if event["event_type"] == "audit.late_record":
                found["recovered" if event.get("recovered_from") else "late"] += 1
            else:
                found["settled"] += 1
    return found


def total(found):
    return sum(found.values())


def store_view(root):
    return w465.store_view(state_of(root))


def store_bytes(root):
    """Every byte the opt-in store holds (record, seal, gate): to show it was not touched."""
    found = {}
    base = state_of(root)
    for path in sorted(base.rglob("*")):
        if path.is_file() and "route" not in path.relative_to(base).parts:
            found[str(path.relative_to(base))] = path.read_bytes().hex()
    return found


def killed(tmp_path, plan):
    """A withdrawal committed to the store and not recorded (SIGKILL at the record)."""
    posted, root = run_first(tmp_path, {"stop": "before_record", **plan})
    return posted, root, store_view(root)["generation"]


def sends(root, posted, generation):
    return {"on_granted_generation": w465.send_in_new_process(
                state_of(root), posted["granted_generation"]),
            "on_withdrawal_generation": w465.send_in_new_process(
                state_of(root), generation)}


def zero_sends(sent):
    return all(one["calls"] == 0 and one["refusal"] == "opt_in_not_granted"
               for one in sent.values())


RECORDED = "audit.late_record"


def recovered_event(root, generation):
    for item in RouteChain(state_of(root) / "route"):
        if (item.event.get("event_type") == RECORDED
                and item.event.get("recovered_from")
                and item.event["late_event"]["generation"] == generation):
            return item.event
    return None


# -- before and after ------------------------------------------------------


@pytest.mark.real_process
def test_a_missing_row_is_recovered_once_and_the_store_is_not_touched(tmp_path):
    posted, root, generation = killed(tmp_path, {})
    before = {"store": store_view(root), "bytes": store_bytes(root),
              "rows": withdrawal_rows(root, generation)}
    assert before["store"] == {"generation": 6, "status": "withdrawn", "permits": False}
    assert total(before["rows"]) == 0
    first = run_restart(root)
    assert first["has_recovery"] and first["recovery"] == {"generation": 6, "state": "recorded"}
    after = withdrawal_rows(root, generation)
    assert after == {"original": 0, "late": 0, "recovered": 1, "settled": 0}
    assert store_bytes(root) == before["bytes"]
    event = recovered_event(root, generation)
    assert event["performed"] is True and event["recovered_from"] == "consent_store"
    assert set(event["late_event"]) == {"event_type", "operator", "at", "reason", "generation"}
    assert "drained" not in event["late_event"] and "drained" not in event
    # A second start, and a third, add nothing.
    second = run_restart(root)
    assert second["recovery"] == {"generation": 6, "state": "present"}
    run_restart(root)
    assert withdrawal_rows(root, generation) == after
    sent = sends(root, posted, generation)
    assert zero_sends(sent)
    assert store_bytes(root) == before["bytes"]
    dump("after-recovered-once.json", {
        "before": before["rows"], "after_first_restart": after,
        "after_third_restart": withdrawal_rows(root, generation),
        "recovered_row": event, "status_after_first_restart": first["status_1"],
        "store_unchanged": True, "sends": sent})


@pytest.mark.real_process
def test_an_original_row_means_no_recovery(tmp_path):
    posted, root = run_first(tmp_path, {})
    generation = store_view(root)["generation"]
    assert withdrawal_rows(root, generation) == {"original": 1, "late": 0, "recovered": 0,
                                                 "settled": 0}
    restarted = run_restart(root)
    assert restarted["recovery"] == {"generation": generation, "state": "present"}
    assert withdrawal_rows(root, generation) == {"original": 1, "late": 0, "recovered": 0,
                                                 "settled": 0}
    dump("after-original-present.json", {"restart": restarted["recovery"]})


@pytest.mark.real_process
def test_a_stop_right_after_the_recovery_adds_nothing(tmp_path):
    posted, root, generation = killed(tmp_path, {})
    park_restart(root, {}, tmp_path, "park")
    mid = withdrawal_rows(root, generation)
    assert mid == {"original": 0, "late": 0, "recovered": 1, "settled": 0}
    run_restart(root)
    assert withdrawal_rows(root, generation) == mid
    dump("after-stop-right-after-recovery.json", {
        "after_kill_of_the_recovering_process": mid,
        "after_next_start": withdrawal_rows(root, generation)})




def park_restart(root, plan, tmp_path, tag):
    """A restart that is SIGKILLed right after its recovery."""
    fifo = tmp_path / f"{tag}.fifo"
    os.mkfifo(fifo)
    rfd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    child = subprocess.Popen(
        [sys.executable, str(CHILD), "restart", str(root),
         json.dumps({**plan, "park": str(fifo)})], env=w465._env(), stderr=subprocess.PIPE)
    try:
        deadline, buf = time.monotonic() + 60, b""
        while b"\n" not in buf:
            assert time.monotonic() < deadline and child.poll() is None, child.stderr.read()
            if select.select([rfd], [], [], 1)[0]:
                buf += os.read(rfd, 4096)
        child.send_signal(signal.SIGKILL)
        child.wait(timeout=10)
    finally:
        os.close(rfd)
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        child.stderr.close()


# -- the audit cannot be written ------------------------------------------


@pytest.mark.real_process
def test_a_failing_audit_leaves_the_withdrawal_in_force_unresolved_then_one_row(tmp_path):
    posted, root, generation = killed(tmp_path, {})
    flag = tmp_path / "fail"
    flag.write_text("x")
    bytes_before = store_bytes(root)
    out = run_restart(root, {"fault": "unavailable_until", "flag": str(flag),
                             "then": "withdraw", "heal": True})
    assert out["recovery"] == {"generation": generation, "state": "owed"}
    shown = out["status_1"]
    assert shown["status"] == "withdrawn" and shown["audit"]["audit"] == "owed"
    assert shown["audit"]["withdrawal_record"] == {"generation": generation, "state": "owed"}
    assert out["store_1"]["permits"] is False
    # A new withdrawal is not held back by the open debt: the store moves on.
    assert out["new_withdraw"] == {"refused": "ledger"}
    assert out["store_after_new_withdraw"] == {"generation": generation + 1,
                                               "status": "withdrawn", "permits": False}
    assert "withdrawal_record" not in out["status_2"].get("audit", {})
    assert withdrawal_rows(root, generation) == {"original": 0, "late": 0, "recovered": 1,
                                                 "settled": 0}
    assert withdrawal_rows(root, generation + 1) == {"original": 0, "late": 1, "recovered": 0,
                                                     "settled": 0}
    assert zero_sends(sends(root, posted, generation + 1))
    run_restart(root)
    assert withdrawal_rows(root, generation)["recovered"] == 1
    assert withdrawal_rows(root, generation + 1) == {"original": 0, "late": 1, "recovered": 0,
                                                     "settled": 0}
    assert store_bytes(root) != bytes_before  # only the new withdrawal moved it
    dump("after-audit-failure.json", {
        "status_while_failing": shown, "new_withdraw": out["new_withdraw"],
        "store_after_new_withdraw": out["store_after_new_withdraw"],
        "rows_after_recovery_of_audit": {
            "recovered_generation": withdrawal_rows(root, generation),
            "new_generation": withdrawal_rows(root, generation + 1)}})


# -- what cannot be shown --------------------------------------------------


def retire_everything_before(root):
    """Date the chain's segment 20 days back and start a process today: retention
    retires that segment, and with it every row written so far."""
    from datetime import UTC, datetime, timedelta

    route = state_of(root) / "route"
    (today,) = route.glob("????-??-??.jsonl")
    old = (datetime.now(UTC) - timedelta(days=20)).strftime("%Y-%m-%d")
    today.rename(route / f"{old}.jsonl")
    # `oldrows` composes, prepares (retention runs) and records a start row. The
    # first process opens today's segment; the second sees both and retires the old.
    for _ in range(2):
        subprocess.run([sys.executable, str(CHILD), "oldrows", str(root)], check=True,
                       env=w465._env(), timeout=60)
    return json.loads((route / "retained-boundary.json").read_text())


@pytest.mark.real_process
def test_no_earlier_row_retained_writes_nothing_and_says_why_even_with_a_later_date(tmp_path):
    """The withdrawal's own date is today, after the retired segment's date. A clock
    comparison would call the row missing; the order does not: no opt-in row of an
    earlier generation is left, so nothing shows the withdrawal's row was kept."""
    posted, root, generation = killed(tmp_path, {})
    boundary = retire_everything_before(root)
    out = run_restart(root)
    assert out["recovery"] == {"generation": generation, "state": "unverifiable",
                               "reason": "no_earlier_anchor"}
    assert total(withdrawal_rows(root, generation)) == 0
    assert out["status_1"]["audit"]["withdrawal_record"]["reason"] == "no_earlier_anchor"
    assert zero_sends(sends(root, posted, generation))
    dump("after-no-earlier-anchor.json", {"boundary": boundary, "recovery": out["recovery"],
                                           "status": out["status_1"]})


@pytest.mark.real_process
def test_an_earlier_row_retained_after_a_boundary_means_the_withdrawal_row_would_be(tmp_path):
    posted, root = run_first(tmp_path, {"stop": "before_record", "old_ledger": True})
    generation = store_view(root)["generation"]
    assert (state_of(root) / "route/retained-boundary.json").exists()
    assert run_restart(root)["recovery"] == {"generation": generation, "state": "recorded"}
    assert withdrawal_rows(root, generation)["recovered"] == 1


@pytest.mark.real_process
def test_a_grant_that_is_running_says_what_was_observed_and_nothing_more(tmp_path):
    posted, root = run_first(tmp_path, {"no_withdraw": True})
    out = run_restart(root)
    assert out["recovery"] == {"state": "not_applicable",
                               "reason": "latest_record_not_a_withdrawal",
                               "checked_generation": posted["granted_generation"]}


@pytest.mark.real_process
def test_only_unusable_rows_remain_so_nothing_is_written(tmp_path):
    """After retirement the only rows left are a withdrawal row of generation 0, a grant
    row of generation 0 and a withdrawal row whose generation is not an int."""
    posted, root, generation = killed(tmp_path, {})
    retire_everything_before(root)
    sample = {"operator": "uid:1001", "at": "2026-11-24T00:00:00Z",
              "reason": "operator_request"}
    rows = [{"event_type": "mio.remote.opt_in.withdrawn", "generation": 0, **sample},
            {"event_type": "mio.remote.opt_in.set", "generation": 0, "operator": "uid:1001"},
            {"event_type": "mio.remote.opt_in.withdrawn", "generation": [1], **sample},
            # An int generation below the withdrawal's, but a field that is not text.
            {"event_type": "mio.remote.opt_in.withdrawn", "generation": 1,
             **{**sample, "operator": {"x": 1}}}]
    subprocess.run([sys.executable, str(CHILD), "plant", str(root), json.dumps(rows)],
                   check=True, env=w465._env(), timeout=60)
    out = run_restart(root)
    assert out["recovery"]["reason"] == "no_earlier_anchor"
    assert out["recovery"]["malformed_candidates"] == 2
    assert total(withdrawal_rows(root, generation)) == 0


@pytest.mark.real_process
@pytest.mark.parametrize("row", [
    {"event_type": "mio.remote.opt_in.set", "generation": 1},  # no operator, no prerequisite
    {"event_type": "mio.remote.opt_in.set", "generation": 1, "operator": "uid:1001",
     "prerequisite": ["remote use"]},
    {"event_type": "mio.remote.opt_in", "generation": 1, "operator": "uid:1001"},
    {"event_type": "mio.remote.opt_in.set", "generation": 1, "operator": "uid:1001",
     "prerequisite": "not a prerequisite"},
    {"event_type": "mio.remote.opt_in", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z", "granted": ["remote use"], "missing": []},
    {"event_type": "mio.remote.opt_in", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z", "granted": ["nothing known"], "missing": [],
     "withdrawn": None},
    {"event_type": "mio.remote.opt_in", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z", "granted": ["remote use"], "missing": ["remote use"],
     "withdrawn": None},
    {"event_type": "mio.remote.opt_in", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z",
     "granted": ["remote use", "privacy policy", "provider", "comms permission"],
     "missing": [], "withdrawn": {}},
    {"event_type": "mio.remote.opt_in", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z",
     "granted": ["remote use", "privacy policy", "provider", "comms permission"],
     "missing": [], "withdrawn": None, "opens_generation": 7},
    {"event_type": "mio.remote.opt_in", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z", "granted": ["remote use"],
     "missing": ["privacy policy", "provider", "comms permission"], "withdrawn": None},
    {"event_type": "mio.remote.opt_in.withdrawn", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z", "reason": "operator_request"},
    {"event_type": "mio.remote.opt_in.withdrawn", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z", "reason": "not a reason", "drained": True,
     "occurred_at": "2026-11-24T00:00:00Z"},
    {"event_type": "mio.remote.opt_in", "generation": 1, "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z", "occurred_at": "2026-11-24T00:00:00Z",
     "granted": ["provider", "remote use", "privacy policy", "comms permission"],
     "missing": [], "withdrawn": None, "opens_generation": 2},
    {"event_type": "mio.remote.opt_in", "generation": "1", "operator": "uid:1001",
     "at": "2026-11-24T00:00:00Z", "occurred_at": "2026-11-24T00:00:00Z",
     "granted": sorted(["remote use", "privacy policy", "provider", "comms permission"]),
     "missing": [], "withdrawn": None, "opens_generation": 2},
], ids=["set-without-fields", "set-with-a-list-prerequisite", "grant-without-lists",
        "set-with-an-unknown-prerequisite", "grant-without-withdrawn",
        "grant-with-an-unknown-prerequisite", "grant-not-a-partition",
        "grant-with-an-empty-withdrawn", "grant-with-a-wrong-opens-generation",
        "grant-partial-without-opens", "withdrawn-row-without-drained",
        "withdrawn-with-an-unknown-reason",
        "grant-unsorted", "grant-with-a-text-generation"])
def test_a_grant_row_of_the_wrong_shape_does_not_anchor(tmp_path, row):
    """Only rows of the shape entryd writes anchor the order argument: a positive
    generation alone does not prove an earlier grant was retained."""
    posted, root, generation = killed(tmp_path, {})
    retire_everything_before(root)
    subprocess.run([sys.executable, str(CHILD), "plant", str(root), json.dumps([row])],
                   check=True, env=w465._env(), timeout=60)
    out = run_restart(root)
    assert out["recovery"]["reason"] == "no_earlier_anchor"
    assert total(withdrawal_rows(root, generation)) == 0


@pytest.mark.real_process
def test_retirement_that_moves_after_the_scan_takes_the_anchor_away(tmp_path):
    posted, root, generation = killed(tmp_path, {})
    out = run_restart(root, {"advance_boundary": True})
    assert out["recovery"] == {"generation": generation, "state": "unverifiable",
                               "reason": "no_earlier_anchor"}
    assert total(withdrawal_rows(root, generation)) == 0


@pytest.mark.real_process
def test_a_valid_settlement_row_names_the_withdrawal_so_nothing_is_added(tmp_path):
    posted, root, generation = killed(tmp_path, {})
    operator, at, reason = ConsentStore(state_of(root)).latest_record().withdrawn
    row = {"event_type": "audit.outcome_settled", "settled_sequence": 1,
           "settled_event_hash": "0" * 64, "outcome": "absent", "performed": True,
           "late_event": {"event_type": "mio.remote.opt_in.withdrawn", "operator": operator,
                          "at": at, "reason": reason, "generation": generation}}
    subprocess.run([sys.executable, str(CHILD), "plant", str(root), json.dumps([row])],
                   check=True, env=w465._env(), timeout=60)
    out = run_restart(root)
    assert out["recovery"] == {"generation": generation, "state": "present"}
    assert withdrawal_rows(root, generation) == {"original": 0, "late": 0, "recovered": 0,
                                                 "settled": 1}


@pytest.mark.real_process
def test_while_the_recovery_row_is_owed_a_set_is_refused_and_after_it_a_set_passes(tmp_path):
    """Only the control reserve is short: the caller's share and the segment have room,
    the start-up rows fit, the recovery row does not. The grant is held back (a
    narrowing is not, see the main() test), the store is not touched, and once the
    row can be written the same `set` goes through."""
    posted, root, generation = killed(tmp_path, {})
    out = run_restart(root, {"tight_reserve": True})
    assert out["recovery"] == {"generation": generation, "state": "owed"}
    assert out["owed_before_set"] is True
    assert out["set_while_owed"] == {"refused": "ledger"}
    assert out["store_after_refused_set"] == out["store_1"] == {
        "generation": generation, "status": "withdrawn", "permits": False}
    assert out["set_after_recovery"]["returned"]["generation"] == generation + 1
    assert out["owed_after"] is False
    assert withdrawal_rows(root, generation)["recovered"] == 1
    dump("after-set-while-owed.json", {k: out[k] for k in (
        "set_while_owed", "store_after_refused_set", "set_after_recovery", "store_after_set")})


@pytest.mark.real_process
def test_the_ledger_writes_generations_in_order(tmp_path):
    """The premise of the anchor: every opt-in row precedes the commit it names, so
    rows are non-decreasing in generation along the chain."""
    posted, root = run_first(tmp_path, {})
    seen = [item.event["generation"] for item in RouteChain(state_of(root) / "route")
            if str(item.event.get("event_type", "")).startswith("mio.remote.opt_in")
            and "generation" in item.event]
    assert seen and seen == sorted(seen)


@pytest.mark.real_process
def test_a_later_generation_overwrote_the_store_nothing_is_made_up(tmp_path):
    posted, root, generation = killed(tmp_path, {})
    done = subprocess.run([sys.executable, str(CHILD), "setonly", str(root), str(generation)],
                          capture_output=True, text=True, env=w465._env(), timeout=60)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["generation"] == generation + 1
    out = run_restart(root)
    expected = {"state": "not_applicable", "reason": "latest_record_not_a_withdrawal",
                "checked_generation": generation + 1}
    assert out["recovery"] == expected
    assert out["status_1"]["audit"]["withdrawal_record"] == expected
    assert total(withdrawal_rows(root, generation)) == 0
    dump("after-later-generation.json", {"restart": out["recovery"],
                                          "rows": withdrawal_rows(root, generation)})


@pytest.mark.real_process
def test_an_internal_withdrawal_is_not_recovered_and_says_why(tmp_path):
    posted, root = run_first(tmp_path, {"internal": True})
    generation = store_view(root)["generation"]
    out = run_restart(root)
    assert out["recovery"] == {"generation": generation, "state": "unverifiable",
                               "reason": "not_operator_withdrawal"}
    assert total(withdrawal_rows(root, generation)) == 0
    dump("after-internal.json", {"restart": out["recovery"]})


@pytest.mark.real_process
def test_the_ceiling_generation_is_never_recovered_because_two_withdrawals_collide(tmp_path):
    from azazel_nexus_runtime.mio_remote_consent import _MAX_GENERATION

    posted, root, generation = killed(tmp_path, {"max_two": True})
    assert generation == _MAX_GENERATION
    first_at, second_at = "2026-11-24T10:00:00Z", "2026-11-24T10:00:05Z"
    assert total(withdrawal_rows(root, generation, first_at)) == 1
    assert total(withdrawal_rows(root, generation, second_at)) == 0
    out = run_restart(root)
    assert out["recovery"] == {"generation": generation, "state": "unverifiable",
                               "reason": "ceiling_ambiguous"}
    assert total(withdrawal_rows(root, generation, second_at)) == 0
    assert withdrawal_rows(root, generation, first_at)["original"] == 1
    dump("after-ceiling.json", {"recovery": out["recovery"],
                                "second": withdrawal_rows(root, generation, second_at)})


@pytest.mark.real_process
def test_malformed_and_unrelated_rows_do_not_match_do_not_crash_and_are_counted(tmp_path):
    posted, root, generation = killed(tmp_path, {})
    sample = {"operator": "uid:1001", "reason": "operator_request"}
    at = ConsentStore(state_of(root)).latest_record().withdrawn[1]
    rows = [
        # Well-formed shape, wrong outer type: not a candidate.
        {"event_type": "mio.route", "at": at, "generation": generation, **sample},
        # A late record of something else: not a candidate.
        {"event_type": "audit.late_record", "performed": True,
         "late_event": {"event_type": "mio.route", "at": at, "generation": generation, **sample}},
        # Candidates with the wrong types: counted, never matched, never a crash.
        {"event_type": "mio.remote.opt_in.withdrawn", "at": at, "generation": [generation],
         **sample},
        {"event_type": "mio.remote.opt_in.withdrawn", "at": at, "generation": True, **sample},
        {"event_type": "audit.late_record", "performed": True, "late_event": "withdrawn"},
        {"event_type": "audit.outcome_settled", "outcome": "absent",
         "late_event": {"event_type": "mio.remote.opt_in.withdrawn", "generation": generation,
                        "operator": {"x": 1}, "at": at, "reason": "operator_request"}},
    ]
    subprocess.run([sys.executable, str(CHILD), "plant", str(root), json.dumps(rows)],
                   check=True, env=w465._env(), timeout=60)
    out = run_restart(root)
    assert out["recovery"] == {"generation": generation, "state": "recorded",
                               "malformed_candidates": 4}
    assert out["status_1"]["audit"]["withdrawal_record"]["malformed_candidates"] == 4
    assert withdrawal_rows(root, generation)["recovered"] == 1
    dump("after-malformed.json", {"recovery": out["recovery"]})


def test_the_audit_read_does_not_move_the_rollback_floor(tmp_path):
    """`latest_record` compares with what the process saw but never raises it: a store
    that is rolled back after the audit read is judged by `reading` as before."""
    import shutil

    from azazel_nexus.mio_profile import PREREQUISITES

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    store = ConsentStore(state)
    store.set_prerequisite(PREREQUISITES[0], operator="uid:1", expected_generation=0)
    leaf = state / "remote-consent"
    old = (leaf / "opt-in.json").read_bytes()
    store.set_prerequisite(PREREQUISITES[1], operator="uid:1", expected_generation=1)

    audited = ConsentStore(state)
    assert audited.latest_record().generation == 2
    (leaf / "opt-in.json").write_bytes(old)  # rolled back to generation 1
    shutil.copymode(leaf, leaf)
    assert audited._seen == 0
    assert audited.reading().generation == 1  # not `unavailable`

    reading_first = ConsentStore(state)
    # (the file is generation 1 again)
    reading_first._seen = 2
    assert reading_first.reading().status == "unavailable"  # the floor still works when read
    with pytest.raises(Exception):
        reading_first.latest_record()  # and the audit read honours it as a comparison


# -- overlap with the owed of #469 -----------------------------------------


@pytest.mark.real_process
def test_overlap_i_the_owed_late_record_was_never_written(tmp_path):
    posted, root = run_first(tmp_path, {"fault": "unavailable"})
    generation = store_view(root)["generation"]
    assert posted["reply"] == {"refused": "ledger"}
    assert total(withdrawal_rows(root, generation)) == 0
    run_restart(root)
    assert withdrawal_rows(root, generation) == {"original": 0, "late": 0, "recovered": 1,
                                                 "settled": 0}
    run_restart(root)
    assert total(withdrawal_rows(root, generation)) == 1
    dump("after-overlap-i.json", {"rows": withdrawal_rows(root, generation)})


@pytest.mark.real_process
def test_overlap_ii_the_late_record_is_present_before_its_settlement(tmp_path):
    posted, root = run_first(tmp_path, {"fault": "unavailable", "settle_unknown": True})
    generation = store_view(root)["generation"]
    assert withdrawal_rows(root, generation) == {"original": 0, "late": 1, "recovered": 0,
                                                 "settled": 0}
    run_restart(root)
    assert withdrawal_rows(root, generation) == {"original": 0, "late": 1, "recovered": 0,
                                                 "settled": 0}
    dump("after-overlap-ii.json", {"rows": withdrawal_rows(root, generation)})


@pytest.mark.real_process
def test_overlap_ii_b_the_line_itself_is_present_with_an_unknown_outcome(tmp_path):
    posted, root = run_first(tmp_path, {"fault": "unknown_present"})
    generation = store_view(root)["generation"]
    assert withdrawal_rows(root, generation) == {"original": 1, "late": 0, "recovered": 0,
                                                 "settled": 0}
    run_restart(root)
    assert withdrawal_rows(root, generation) == {"original": 1, "late": 0, "recovered": 0,
                                                 "settled": 0}
    dump("after-overlap-ii-b.json", {"rows": withdrawal_rows(root, generation)})


@pytest.mark.real_process
@pytest.mark.parametrize("fault, written", [("unknown_present", 1), ("unknown_absent", 0)])
def test_overlap_iii_unknown_outcome_of_the_recovery_row_is_settled_in_the_same_process(
        tmp_path, fault, written):
    """The row's write raises `AuditOutcomeUnknown` with the candidate line. The same
    process then settles: a line found present adds nothing, one found absent is written
    again, and either way there is one row."""
    posted, root, generation = killed(tmp_path, {})
    out = run_restart(root, {"fault": fault, "settle": True})
    assert (out["rows_before_settle"], out["rows_after_settle"], out["settled"]) == (
        written, 1, True)
    assert withdrawal_rows(root, generation) == {"original": 0, "late": 0, "recovered": 1,
                                                 "settled": 0}
    run_restart(root)
    assert total(withdrawal_rows(root, generation)) == 1
    dump(f"after-overlap-iii-settle-{fault}.json", {
        "before_settle": out["rows_before_settle"], "after_settle": out["rows_after_settle"],
        "after_next_start": withdrawal_rows(root, generation)})


@pytest.mark.real_process
@pytest.mark.parametrize("fault, expected", [
    ("unknown_present", {"original": 0, "late": 0, "recovered": 1, "settled": 0}),
    ("unknown_absent", {"original": 0, "late": 0, "recovered": 0, "settled": 0}),
])
def test_overlap_iii_unknown_outcome_then_stop_before_the_settling(
        tmp_path, fault, expected):
    posted, root, generation = killed(tmp_path, {})
    park_restart(root, {"fault": fault}, tmp_path, "iii")
    assert withdrawal_rows(root, generation) == expected
    run_restart(root)
    assert withdrawal_rows(root, generation) == {"original": 0, "late": 0, "recovered": 1,
                                                 "settled": 0}
    run_restart(root)
    assert total(withdrawal_rows(root, generation)) == 1
    dump(f"after-overlap-iii-{fault}.json", {
        "after_stop": expected, "after_restart": withdrawal_rows(root, generation)})


# -- the real main() ---------------------------------------------------------

MAIN_CHILD = HERE / "_mio_remote_consent_w471_main_child.py"


@pytest.fixture
def entryd(monkeypatch):
    import test_w467_audit_unavailable as w467

    monkeypatch.setattr(w467, "CHILD", MAIN_CHILD)
    monkeypatch.setattr(w467, "_shrink", lambda value, depth=0: value)
    daemon = w467.Daemon("mio-entryd")
    yield daemon
    daemon.cleanup()


STATUS = {"verb": "mio.remote.opt_in.status", "arguments": {}}
WITHDRAW = {"verb": "mio.remote.opt_in.withdraw", "arguments": {"reason": "operator_request"}}


def until(condition, what, timeout=40):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return
        time.sleep(0.1)
    raise AssertionError("timed out: " + what)


def main_log(daemon):
    return daemon.log_lines("main.log")


@pytest.mark.real_process
def test_main_recovers_before_serving_retries_on_the_tick_and_sends_stay_zero(
        tmp_path, entryd):
    root = entryd.run / "r"
    posted, _ = run_first(tmp_path, {"stop": "before_record", "root": root})
    generation = store_view(root)["generation"]
    (entryd.run / "fault").write_text("unavailable")
    assert entryd.start(), entryd.exit_info()
    log = main_log(entryd)
    # Called by `main()`, with the socket not yet announced as ready.
    assert log[0] == {"event": "recover_withdrawal", "ready_file_exists": False}
    assert log[1]["result"] == {"generation": generation, "state": "owed"}
    shown = entryd.ask(STATUS)["reply"]["result"]
    assert shown["audit"]["withdrawal_record"] == {"generation": generation, "state": "owed"}
    # While the fault lasts, in another process: the generation allowed before the
    # withdrawal and the withdrawal's own.
    during = sends(root, posted, generation)
    assert zero_sends(during)
    # A new withdrawal is not held back; its record is a debt behind the first.
    reply = entryd.ask(WITHDRAW)
    assert reply["reply"] == {"ok": False, "refusal": "verb_unavailable"}
    assert store_view(root) == {"generation": generation + 1, "status": "withdrawn",
                                "permits": False}
    during_after = sends(root, posted, generation + 1)
    assert zero_sends(during_after)
    assert total(withdrawal_rows(root, generation)) == 0
    # The fault ends; only the tick (nothing else is asked of entryd) writes the rows.
    (entryd.run / "fault").unlink()
    until(lambda: withdrawal_rows(root, generation)["recovered"] == 1
          and withdrawal_rows(root, generation + 1)["late"] == 1, "the tick settles the debts")
    after = (withdrawal_rows(root, generation), withdrawal_rows(root, generation + 1))
    entryd.stop()
    assert entryd.start(), entryd.exit_info()
    assert (withdrawal_rows(root, generation), withdrawal_rows(root, generation + 1)) == after
    dump("after-main-audit-failure.json", {
        "main_log": log, "status_during_fault": shown, "sends_during_fault": [during, during_after],
        "rows_after_tick": {"recovered_generation": after[0], "new_generation": after[1]}})


@pytest.mark.real_process
@pytest.mark.parametrize("fault", ["unknown_present", "unknown_absent"])
def test_main_unknown_outcome_of_the_recovery_row_is_settled_once(tmp_path, entryd, fault):
    root = entryd.run / "r"
    posted, _ = run_first(tmp_path, {"stop": "before_record", "root": root})
    generation = store_view(root)["generation"]
    (entryd.run / "fault").write_text(fault)
    assert entryd.start(), entryd.exit_info()
    first = [line for line in main_log(entryd) if line.get("event") == "recovered"]
    # The injected unknown outcome did fire on the recovery row, and the start's
    # result was a debt (owed), not a row written at the first try.
    assert first and first[0]["fired"] == 1, first
    assert first[0]["result"]["state"] == "owed", first
    until(lambda: "withdrawal_record" not in entryd.ask(STATUS)["reply"]["result"].get("audit", {})
          and withdrawal_rows(root, generation)["recovered"] == 1, "settled")
    assert withdrawal_rows(root, generation) == {"original": 0, "late": 0, "recovered": 1,
                                                 "settled": 0}
    entryd.stop()
    assert entryd.start(), entryd.exit_info()
    assert total(withdrawal_rows(root, generation)) == 1



def test_an_anchor_is_exactly_a_row_entryd_writes():
    """The router adds `occurred_at` to every row, so a row without it cannot come
    from entryd and does not anchor; the same row with it does (#471)."""
    from azazel_nexus_runtime import mio_entryd as entry_mod

    written = {"event_type": "mio.remote.opt_in.withdrawn", "generation": 1,
               "operator": "uid:1001", "at": "2026-11-24T00:00:00Z",
               "reason": "operator_request", "drained": True,
               "occurred_at": "2026-11-24T00:00:00+00:00"}
    assert entry_mod._anchor_row(written) is True
    assert entry_mod._anchor_row({k: v for k, v in written.items() if k != "occurred_at"}) is False
    assert entry_mod._anchor_row({**written, "generation": "1"}) is False
    assert entry_mod._anchor_row({**written, "generation": 2**63}) is False
    grant = {"event_type": "mio.remote.opt_in", "operator": "uid:1001",
             "at": "2026-11-24T00:00:00Z", "occurred_at": "2026-11-24T00:00:00+00:00",
             "granted": sorted(["remote use", "privacy policy", "provider", "comms permission"]),
             "missing": [], "withdrawn": None}
    assert entry_mod._anchor_row({**grant, "generation": 4, "opens_generation": 5}) is True
    # Four prerequisites take four generations from an empty store.
    assert entry_mod._anchor_row({**grant, "generation": 1, "opens_generation": 2}) is False
    for key in ("operator", "at", "occurred_at"):
        assert entry_mod._anchor_row({**written, key: ""}) is False, key
    assert entry_mod._anchor_row({**written, "operator": "someone"}) is False


def test_anchor_values_are_the_writers_formats():
    """`uid:` and a canonical decimal uid, the store's UTC time for `at`, the
    router's UTC ISO time for `occurred_at` (#471)."""
    from azazel_nexus_runtime import mio_entryd as entry_mod

    written = {"event_type": "mio.remote.opt_in.withdrawn", "generation": 1,
               "operator": "uid:1001", "at": "2026-11-24T00:00:00Z",
               "reason": "operator_request", "drained": True,
               "occurred_at": "2026-11-24T00:00:00.123456+00:00"}
    assert entry_mod._anchor_row(written) is True
    assert entry_mod._anchor_row({**written, "operator": "uid:2147483647",
                                  "occurred_at": "2026-11-24T00:00:00+00:00"}) is True
    for key, value in (("operator", "uid:0001"), ("operator", "uid:²"),
                       ("at", "x"), ("at", "2026-11-24T00:00:00+00:00"),
                       ("occurred_at", "x"), ("occurred_at", "2026-11-24T00:00:00"),
                       ("at", "2026-1-2T3:4:5Z"), ("occurred_at", "2026-11-24T00:00:00Z"),
                       ("occurred_at", "2026-11-24 00:00:00+00:00"),
                       ("operator", "uid:" + "1" * 4301), ("operator", "uid:2147483648"),
                       ("occurred_at", "2026-11-24T00:00:00.000000+00:00")):
        assert entry_mod._anchor_row({**written, key: value}) is False, (key, value)


def test_settlement_and_late_records_are_recounted_to_the_control_reserve(tmp_path, monkeypatch):
    """They are written to the control reserve; a restart's recount charges them
    there too, not to the caller of the request before them (#467, #471)."""
    from azazel_nexus_runtime import mio_entryd as entry_mod
    from azazel_nexus_runtime import runtime_paths

    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    runtime_paths.mio_state_dir().mkdir(parents=True, exist_ok=True)
    attribute = entry_mod.MioEntryService()._attribution()
    assert attribute({"event_type": entry_mod.REQUEST_MARKER, "caller": "uid:1001"}) == "uid:1001"
    for kind in ("audit.outcome_settled", "audit.late_record"):
        assert attribute({"event_type": kind}) == entry_mod.CONTROL
