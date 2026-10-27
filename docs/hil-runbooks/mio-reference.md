# M.I.O. playbook reference and deterministic handoff — target hardware

## 概要（日本語）

[#343](https://github.com/01rabbit/Azazel-Nexus/pull/343) の対象実機（Debian 13
x86_64）での確認手順。モデルを持たない参照サービス `azazel-mio-referenced.service`
と `azazel-mio-entryd.service` を、通常の活性化経路で起動した実 unit として確かめる。
確認すること：

- seccomp・`PrivateNetwork=yes`・AF_UNIX 以外のソケットが無いこと、参照ソケットは
  `azmioentry` だけを受け付け、root と operator は `principal_denied` になること。
- 署名済み Mission Pack が有効なら参照（`deterministic_reference`）が、playbook が
  無ければ固定の通知と理由（`deterministic_notice`、`mio_handoff:<理由>`）が記録されること。
- AI の試行が 2 回を超えず、必ず決定論的な引き継ぎに終わること。
- 実負荷での 1 要求あたりの所要時間（壁時計による近似）が 500 ms の期限に収まること。

コード中の期限（500・200・100・50・30 ms など）は**ソフトウェア上の予算**であり、
実測値ではない。この手順で得る数値だけが実測で、それも測った実機・負荷・構成に限る。
VM・コンテナの結果は証跡にならない。ゲートの状態は変えない。

Status: **not run; hardware-unverified**. Owner: [#343](https://github.com/01rabbit/Azazel-Nexus/pull/343)
(merged software); campaign parent [#4](https://github.com/01rabbit/Azazel-Nexus/issues/4).

Use the [campaign prerequisites and stop conditions](../hil-campaign.md), the
[evidence rules](../hil-evidence-records.md) and the
[M.I.O. runtime contract](../mio-runtime.md). Where this runbook and the code
disagree, the code wins and this runbook is defective:
`tests/unit/test_runbook_references.py` and
`tests/unit/test_hil_runbook_merged_features.py` check the commands, paths,
symbols and expected values named here against the code.

## 0. Scope and what exists already

| Evidence class | What exists for #343 | What it does not show |
| --- | --- | --- |
| mock | `tests/unit/test_mio_router_deadline.py`, `tests/unit/test_mio_reference.py`: the single deadline, `MAX_AI_ATTEMPTS`, every handoff cause, the reply shapes | anything about a kernel, systemd or a real clock under load |
| real process | `tests/unit/test_mio_reference_socket.py`: the daemons over real Unix sockets, peer credentials included | the systemd sandbox, the installed accounts |
| Linux service integration | a systemd container rehearsal (PR #343 description) | the target's kernel, systemd version and load; it is not hardware evidence |
| target hardware | **none** — this runbook | — |

This runbook produces target-hardware observations only. It does not admit a
model, does not exercise an AI answer and does not close HG-05: local model
admission stays closed (`LOCAL_MODEL_ADMISSION_ENABLED` is `False`, the loader
answers `ADMISSION_DISABLED`). **Never enable admission, start
`azazel-mio-locald.service` or `azazel-mio-remoted.service`, set `AZAZEL_ROOT`
or patch code to make a step run.** A step that cannot run is `not-run` with
its reason.

## 1. Preconditions

1. The DUT satisfies the [campaign](../hil-campaign.md) prerequisites (approved
   image, preflight A/B, local console, protected archive outside every
   checkout). Nexus is installed from a reviewed checkout at a commit that
   contains #343 (`az-mio-referenced` exists under `/usr/libexec/azazel/`).
2. **The owner has ratified the scope change** in
   [activation-observe-baseline §6](../activation-observe-baseline.md#6-owner-decisions)
   (the proposed addition of `azazel-mio-referenced.service` to decision 2).
   Until then the reference unit must not be granted on a DUT, and §3–§6 are
   `not-run` with the reason "scope change pending owner ratification".
3. The units start only through the **regular activation path**: an activation
   policy, an observe-baseline generation and a signed approval that name
   `azazel-mio-referenced.service` and `azazel-mio-entryd.service`, produced
   by `az-activation` and signed off-host
   ([activation rehearsal](activation-rehearsal.md) for the mechanics). The
   rehearsal-only hand start of the
   [integrated loop rehearsal §6](integration-loop-rehearsal.md#6-rehearsal-only-start-alternative-to-activation)
   is forbidden on hardware. Never `systemctl start`, `restart`, unmask or
   drop-in a governed unit by hand: every one carries
   `Requires=azazel-activated.service`, and a second pass in the same boot
   re-masks everything and ends with `RollbackFailed`.
4. The explainer path that sends `mio.advise` (`azazel-incident-explaind.service`,
   `azazel-edge-intaked.service`, and the Edge Core deployment of [HG-07](hg-07.md))
   is granted in the same approval, so that requests arrive the way they do in
   service. There is no operator client for `mio.advise`; this runbook does
   not add one.
5. For §4.1 only: an **owner-signed, owner-approved Mission Pack** carrying a
   `reasoning_playbook`, staged and activated through `azazel-nexus pack`
   ([Mission Packs](../mission-pack.md#operations)), with its playbook assets
   under `/var/lib/azazel/playbooks`. Never sign a pack with a test key for
   this, and never enroll a test signer on a DUT. With no such pack, §4.1 is
   `not-run`.

Below, `PYTHON` is `/opt/azazel-nexus/venv/bin/python`; commands spell the
full path and run from `/`. `START` is the wall-clock time the exercise began
(`START=$(date -u +%Y-%m-%dT%H:%M:%SZ)`).

## 2. The activation pass granted both units

```sh
sudo journalctl -b -u azazel-activated.service -o cat
ls /run/azazel-activation/granted/
systemctl is-active azazel-mio-referenced.service azazel-mio-entryd.service
```

Expect the pass to complete with both units granted (a grant marker named
after each unit) and both units `active` after the controller's READY. If the
reference unit is not granted, the policy does not name it: the handoff then
reports `reference_service_unavailable`, which is the documented behaviour of
a node without the unit, and §3–§6 are `not-run`. Record the outcome line
(`granted=`), not the ledger contents.

## 3. Sandbox of the running units

For each of the two units, with `UNIT` set to the unit name:

```sh
PID=$(systemctl show -p MainPID --value UNIT)
sudo grep -E '^(Uid|Gid|Groups|NoNewPrivs|Seccomp|CapEff|CapBnd):' /proc/$PID/status
sudo readlink /proc/$PID/ns/net /proc/1/ns/net
sudo nsenter -t $PID -n ss -H -a -p | grep -F "pid=$PID," | awk '{print $1}' | sort | uniq -c
sudo ss -H -a -p | grep -F "pid=$PID," | awk '{print $1}' | sort | uniq -c
systemctl show UNIT -p User -p SupplementaryGroups -p PrivateNetwork -p RestrictAddressFamilies -p SystemCallArchitectures -p NoNewPrivileges
sudo systemd-analyze security --no-pager UNIT
```

| Check | `azazel-mio-referenced.service` | `azazel-mio-entryd.service` |
| --- | --- | --- |
| account | `azmioref`, supplementary group `azmission-read` only | `azmioentry`, supplementary group `azazel-operator` only |
| `Seccomp:` | `2` (filter; the unit declares `SystemCallFilter=@system-service`) | `2` |
| `NoNewPrivs:` | `1` | `1` |
| `CapEff:` and `CapBnd:` | all zero (`CapabilityBoundingSet=` empty) | all zero |
| network namespace | differs from PID 1's (`PrivateNetwork=yes`) | same as PID 1's (no `PrivateNetwork=`; `IPAddressDeny=any`) |
| socket kinds in either listing | Unix only (`u_str`, `u_seq` or `u_dgr`); no `tcp`, `udp`, `raw`, `p_raw`, `p_dgr` or `nl` | Unix only |
| `RestrictAddressFamilies` | `AF_UNIX` | `AF_UNIX` |

Compare every `systemctl show` value with the installed unit file under
`/lib/systemd/system/`, not with this table alone: the unit files are
generated from `azazel_nexus_runtime.hardening` and the running manager's
reading is what is being observed. A value the running systemd reports
differently from the file, or ignores, is a finding. Record the
`systemd-analyze security` exposure level of each unit and the systemd
version.

## 4. Who may ask for a reference

The reference socket is /var/lib/azazel/run/mio-reference/mio-reference.sock
(directory `2710 azmioref:azazel-operator`, socket `0660`). Its only verb,
`mio.reference`, admits the service account `azmioentry` and nobody else.
Ask it as root, then as the responsible operator's own account (a member of
`azazel-operator`, substituted for OPERATOR_ACCOUNT):

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -c 'from azazel_nexus_runtime.mio_socket_client import _exchange, ServiceRefused
try:
    _exchange("mio-reference", "azmioref", "mio.reference", {"deadline_ms": 100}, payload={}, deadline_s=0.5); print("answered")
except ServiceRefused as exc:
    print("refused", exc.refusal)'
sudo runuser -u OPERATOR_ACCOUNT -- /opt/azazel-nexus/venv/bin/python -I -c 'from azazel_nexus_runtime.mio_socket_client import _exchange, ServiceRefused
try:
    _exchange("mio-reference", "azmioref", "mio.reference", {"deadline_ms": 100}, payload={}, deadline_s=0.5); print("answered")
except ServiceRefused as exc:
    print("refused", exc.refusal)'
```

Both must print `refused principal_denied`. `answered` from either is a
failure: stop and keep the unit's state. An account outside `azazel-operator`
cannot reach the socket at all (the connect fails with a permission error);
that is also a pass for this check. Each denial is recorded in the reference
ledger as `runtime.request_refused`:

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -c 'from pathlib import Path; from azazel_nexus.audit import AuditLedger
[print(e.event["event_type"], e.event.get("reason"), e.event.get("verb")) for e in list(AuditLedger(Path("/var/lib/azazel/state/mio-reference/reference.jsonl")))[-5:]]'
```

Expect `runtime.request_refused principal_denied mio.reference` for each
attempt. Do not export the `uid`, `gid` or `pid` of those records.

## 5. What a handoff carries

Drive the loop as in the
[integrated loop rehearsal §8](integration-loop-rehearsal.md#8-drive-the-loop),
with real traffic or the synthetic eve lines, and read the explanation records:

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -c 'import json; from pathlib import Path; from azazel_nexus.incident_explain import read_record; from azazel_nexus.local_advisory import HANDOFF_NOTICE
for p in sorted(Path("/var/lib/azazel/incident-explain/explanations").glob("*.jsonl")):
    for line in p.read_text().splitlines():
        m = read_record(json.loads(line))["mio"]; print(m["route"], m["reason"], m.get("content_kind"), m.get("notice") in HANDOFF_NOTICE.values(), m["text"] is not None)'
```

Every record of this run must show route `deterministic handoff` (no AI is
admitted) and a `content_kind`. A record whose route is not
`deterministic handoff`, or that shows `ai_advice`, is a failure.

### 5.1 With the signed Mission Pack active

Expect `content_kind` `deterministic_reference`, reason `mio_handoff`, the
notice check `True` and text present (the reference's banner) for incidents
the active playbook covers. An incident it does not cover gives
`deterministic_notice` with `mio_handoff:no_matching_playbook`. At least one
`deterministic_reference` is needed for this check to pass; if none of the
exercised incidents is covered, record `not-run` with that reason, not a pass.
A reference must never be presented as AI output: `azazel-nexus status` shows
it as a "deterministic playbook reference (not AI)".

### 5.2 Without a playbook

Roll the pack back (`azazel-nexus pack rollback`) or exercise before one is
staged. Expect `deterministic_notice`, the notice check `True`, no text, and a
reason of the form `mio_handoff:<word>` where the word names why there was no
reference: `no_pack` with no pack, `none_selected` with a pack that selects no
playbook, `pack_degraded` when the pack's signature, signer, epoch or validity
no longer verifies. Any word outside the code's `REFERENCE_REASONS` is a
failure.

## 6. AI attempts and the deterministic handoff

Read the route ledger (read-only; never instantiate the writer):

```sh
sudo /opt/azazel-nexus/venv/bin/python -I -c 'import datetime as d; from pathlib import Path; from azazel_nexus.route_ledger import RouteChain
t, h, out = None, None, []
for e in RouteChain(Path("/var/lib/azazel/state/mio/route")):
    v = e.event; k = v["event_type"]
    if k == "mio.entry.request": t, h = d.datetime.fromisoformat(v["occurred_at"]), None
    elif k == "mio.route.handoff": h = (v["cause"], v["ai_attempts"])
    elif k == "mio.entry.handoff" and t is not None:
        out.append(((d.datetime.fromisoformat(v["occurred_at"]) - t).total_seconds() * 1000, h, v["reference_status"], v["reference_reason"])); t = None
print("handoffs", len(out), "max_ms", max((o[0] for o in out), default=None))
[print(round(o[0], 1), *o[1:]) for o in out[-30:]]'
```

On a node where no AI provider is admitted (every node today), each request
must show `mio.route.handoff` with cause `selected` and `ai_attempts` 0: the
selection itself is the deterministic handoff, and no AI is called. In every
case `ai_attempts` must be 0, 1 or 2 and the request must end in
`mio.entry.handoff`. More than two attempts, or a request without a handoff
or an answer, is a failure.

The causes `ai_attempts_exhausted`, `ai_attempts_ended`, `fallback`,
`no_permitted_fallback` and `deadline_budget_insufficient` need an admitted
AI route, so the "two AI failures, then the deterministic terminal" path is
**not reachable on hardware** while admission is closed. Record it as
`not-run` (reason: no AI route admitted); its evidence remains the mock and
real-process tests of §0. Stopping a model that was never started proves
nothing, and enabling one to make it fail is forbidden (§0).

## 7. The request deadline under load

The explainer asks with `deadline_ms` 500 (`ADVISE_DEADLINE_MS`, equal to
`REFERENCE_DEADLINE_MS`) and waits 250 ms longer (`ADVISE_CALLER_MARGIN_MS`).
Inside it, `HANDOFF_RESERVE_MS` (200), `MIN_AI_ATTEMPT_MS` (100),
`LEDGER_ALLOWANCE_MS` (50), `MIN_REFERENCE_FETCH_MS` (50) and
`ENTRY_DELIVERY_RESERVE_MS` (30) divide it. **These are software budgets
written in the code, not measurements**, and no value here is a hardware
latency until this section has been run.

1. Run under the campaign's declared load: the Edge Core subsystems,
   audit, evidence capture and the lease journal doing actual work, as for
   the [HG-05 reserve](../core-reserve-measurement.md#5-the-procedure).
   Record the load declaration with the run. An idle node measures an idle
   node.
2. Drive at least 30 handoffs (the explainer sends at most six requests a
   minute, so at least five minutes), half with the pack active and half
   without, then run the §6 script.
3. The script's figure for each request is the wall-clock difference between
   the request's `mio.entry.request` record and its `mio.entry.handoff`
   record. It is an approximation: it starts after the frame was read and
   ends before the reply is written, and a wall-clock step during the run
   invalidates it. The ledgers carry no monotonic elapsed field; do not
   present this figure as the caller's latency.
4. Count explanation records of the window whose `failure_codes` contain
   `mio_unavailable` (the explainer did not get a reply within 750 ms).

Pass only if every measured figure is below 500 ms **and** no record of the
window has `mio_unavailable`. One figure at or above 500 ms, or one
`mio_unavailable`, fails the check: keep it, and record the load at the time.
Record the count, the maximum and the median, the reference status split,
and the hardware class. These numbers are measurements of this class, image
and load only.

## 8. Restore and record

Restore only through the regular path: a reboot lets the next pass decide;
roll a test-only pack selection back with `azazel-nexus pack rollback`. Keep
every failure.

Retain in the protected HIL archive (not in Git, an issue or a PR): the
activation outcome line, the §3 table filled in with the systemd version,
the §4 refusal words, the §5 `content_kind`/reason pairs, the §6 cause and
attempt counts, the §7 count/maximum/median and load declaration, the class
facts (Debian release, kernel, systemd, architecture, memory class) and the
installed Nexus commit. Never record keys, signatures, approvals, explanation
record contents, incident ids, digests, uids, pids, boot ids, addresses, MACs
or interface names; replace incident ids with `inc-<redacted>`.

There is no hardware record schema for this exercise yet: its outcome is
`passed`, `failed` or `not-run` in the [vocabulary](../hil-evidence-records.md),
for field review. It changes no gate, admits no model and is no owner
approval of the §6 scope change.
