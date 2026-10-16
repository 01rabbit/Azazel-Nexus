# Design: clean operator stop vs. helper BindsTo ordering (Issue #93, Q9 trace finding 4)

Paths: R = runtime/src/azazel_nexus_runtime, U = packaging/systemd. HEAD 58dfde1 (not a git repo here; read-only study).

## 1. Verdict on the trace: CONFIRMED (with two additions)

Code facts
- Handler only sets an Event: R/bootstrap_lifetime.py:84-86 (SIGTERM, SIGINT: :15). Loop exits on `_cancelled()` at R/bootstrap.py:851; `wait()` wakes on the Event (lifetime:71-82).
- `run()` -> `_finish_transaction()` at R/bootstrap.py:944 (exception) / :947 (normal).
- `_finish_transaction` (bootstrap.py:528-567): advance grant to `closing` (:536-542); if `_live_audit` set, `_record("bootstrap.stopping")`, any Exception stored as `audit_error` (:545-549); `_contain()` (:551-555); `failure = close_error or audit_error` -> `_mark_recovery(failure)` + `ApprovalRefused("bootstrap transaction close was not fully recorded")` (:557-560). Exit 1 via activated.py main's `except Exception` (~:534-542). `_mark_recovery` is :516-526 (journal -> `recovery_required`).
- `_record` (bootstrap.py:342-354) builds the event and calls `self.record` = `BootstrapAuditClient.__call__` (R/bootstrap_audit_client.py:178-220); every failure there is collapsed to `AuditUnavailable` (:218-220). Needs a live auditd socket plus fresh peer proof; both fail when auditd is inactive.
- Units: `hardening.py:353-354` / `:389-390` (and the commissiond/auditd profiles near :470-520) declare After= + Requires= + BindsTo= the controller; rendered at hardening.py:605-615; the generated files are U/azazel-auditd.service (After/Requires/BindsTo=azazel-activated.service) and U/azazel-commissiond.service:14-23 (also Requires/BindsTo=azazel-auditd.service). Controller unit: Type=notify, KillMode=control-group, KillSignal=SIGTERM, TimeoutStopSec=10s, TimeoutStopFailureMode=kill, Conflicts=shutdown.target, and no ExecStop (U/azazel-activated.service).

systemd semantics (from the documented model, not run here; no systemd on this host)
- `systemctl stop A` creates a stop job for A. Requires= and BindsTo= on A both propagate an explicit stop of A to the dependents, so stop jobs are queued for commissiond and auditd in the same transaction.
- Ordering: start order is "A before B" when B has After=A; stop order is the reverse. So B's stop job must complete before A's stop job *starts*. A's stop job (which includes ExecStop, if any, and the SIGTERM) only begins after commissiond (After auditd and controller) and then auditd are inactive.
- Hence SIGTERM reaches the controller only after auditd is gone. `_record("bootstrap.stopping")` must fail. Confirmed.

Additions to the trace
1. ExecStop= on the controller does NOT help: it is part of the controller's stop job, which is ordered after the helpers' stop. (ExecStop on a helper could run before that helper dies but cannot reach the controller without new authority; see option D.)
2. Same ordering applies to system shutdown (every unit has `Conflicts=shutdown.target`, helpers `Before=shutdown.target`), so every ordinary reboot/poweroff ends the controller in `recovery_required`, exit 1. On next boot `run()` loads that existing journal, runs `_contain`, and refuses with "existing bootstrap transaction requires manual review" (bootstrap.py:~925-943). This makes the defect more than an operator-stop nuisance.
3. There is a second race: during the helpers' stop window (up to 10s each) the controller is still running; the 10 s poll can hit `_ready` -> "bootstrap helper readiness lost" (bootstrap.py:575-578, loop :851-853) and the exception path (:943-945) reaches the same result with `_cancelled()` still False. Any fix must cover both observations (signal-after-helpers and readiness-lost-during-stop).
4. Side issue to qualify natively: C1's `BootstrapJobDrain` lists ALL jobs (`ListJobs`) and `CancelJob`s each (R/bootstrap_job_drain.py:~88-103). During an operator stop this includes systemd's own stop job for the controller. Behaviour of CancelJob on a running stop job is unverified; must be checked in the native stop qualification.

## 2. What cannot be done

- Recording "stopping" when the stop is first observed: the controller has no signal before the helpers die (SIGTERM comes last). The only early observation is polling (a `stop` job for the controller visible via ListJobs) every <=10 s, which is racy by construction (helpers stop in ms). Usable as corroboration, not as the primary record.
- A post-hoc record: auditd is the single writer (U/azazel-auditd.service comment), the controller has CAP_DAC_READ_SEARCH only, and `_contain` masks/withdraws auditd. Starting it again to append would reopen the helper window. Not acceptable.
- Therefore the ledger will, for a systemd-initiated stop, end WITHOUT `bootstrap.stopping` unless the stop is controller-first (option A/B). Any "fix" must say plainly how that absence is evidenced elsewhere.

## 3. Options

### Option A: operator stop entry that stops the controller first (no unit change)
`systemctl kill --kill-whom=main -s SIGTERM azazel-activated.service`, then wait for inactive (or a tiny packaged wrapper `az-activated-stop` doing the same through the existing allowlisted systemd bus calls). Controller sees SIGTERM with helpers still up: today's clean path (bootstrap.py:851 -> :947; tests already cover it, tests/unit/test_runtime_bootstrap.py:1088-1104). Controller exit then BindsTo-follows helpers (already stopped by `_contain` C3).
- Pros: zero change to audit semantics or fail-closed logic; the full `stopping`..`closed` sequence is in the ledger.
- Cons: does not fix plain `systemctl stop` or shutdown/reboot (finding 2 above); a wrapper adds a new CLI surface (KillUnit is not in the SystemdUnitCalls allowlist, R/systemd_bus.py:328-339, would need adding = new authority; `systemctl kill` by the operator needs no code but is only a runbook). Operators will still type `systemctl stop`.
- Security: no new authority if documented as `systemctl kill` (operator already holds systemd rights). Do not add KillUnit to the controller's bus allowlist.

### Option B: change units so the controller is stopped first
Remove BindsTo/Requires from helpers (keep After= only). Then `systemctl stop azazel-activated` SIGTERMs the controller first, records `stopping` while auditd is up, contains, exits 0.
- Cons (blocking): After= alone gives no stop-follow. E3.b (kernel deadline SIGKILL, bootstrap_deadline) and watchdog SIGKILL (WatchdogSignal=SIGKILL) of the controller would leave helpers running with no supervisor and no containment: loses the fail-closed property that BindsTo currently provides, and helpers' Restart=no does not stop them. The hardening test (tests/unit/test_runtime_hardening.py) pins this rendering, and hardening.py's "Its notify startup waits for auditd, and loss of auditd also stops commissioning" rationale depends on BindsTo. `PartOf`/`PropagatesStopTo` do not recreate it: PartOf propagates stop/restart from the controller to the helper but not a crash/kill (no BindsTo semantics), and PropagatesStopTo= (v249+) on the controller would again create stop jobs in the same transaction (ordering still helpers-first since After= is kept). Rejected.

### Option C (recommended): accept the missing `stopping` record only on a proven systemd-initiated stop, recorded durably in the grant journal
In `_finish_transaction`, when `_record("bootstrap.stopping")` raises, do not unconditionally set `audit_error`. Instead evaluate a narrow, all-of proof AFTER `_contain()` has returned successfully (so containment is confirmed); otherwise keep today's behaviour (`audit_error` -> recovery_required).

Proof (all must hold):
1. The failure is exactly `AuditUnavailable` from `_record` (not a close_error, not a containment failure; `_contain()` returned its evidence digest).
2. Systemd-initiated stop of THIS controller is evidenced by the manager, read BEFORE `_contain` (C1 drains jobs): the controller unit has a stop job (ListJobs row, job type `stop`, unit `azazel-activated.service`) or ActiveState is `deactivating`. This is a read-only observation through the existing bus inspector/ListJobs reader (R/bootstrap_stop.py `_call`, already used by job_drain); no new bus member. It must be sampled once, before C1, and its result held in memory.
3. Auditd and commissiond are observed inactive by the existing `_contain` C4/C6 `confirm_empty_pair` (already required for a `closed` result).
4. A durable earlier record exists: `self._audit_head` (last verified live head from `_check`, bootstrap.py:326-327,:326) and the receipt of the last successful `_record` (e.g. `bootstrap.ready` COMMISSIONED, bootstrap.py:850) are non-None, so the ledger provably covers everything up to the stop.
5. Either `_cancelled()` is True (SIGTERM after helpers died) or the exception that ended `_supervise` was the readiness-lost refusal AND condition 2 holds (the helper-stop-window race).

Result: advance the grant to `closed` with a close evidence digest that binds the reason, e.g. sha256 of `{"schema":"azazel-nexus/bootstrap-close-evidence/v2","stopping_record":"absent-manager-stop","last_head_sequence":N,"last_head_digest":...,"containment":<existing evidence>}`. Exit 0 with a distinct stdout line ("stopped by manager after helpers; stopping record unavailable"), so operators and tests can tell it from a full close. Never emit `bootstrap.stopped`.

- Pros: fixes `systemctl stop`, reboot and shutdown without touching units; ordinary stops no longer require manual review; only the ONE record that physically cannot be written is waived, and the waiver is itself durable (journal evidence digest) and requires manager corroboration plus confirmed containment.
- Cons: ledger for this path ends at the last heartbeat-era record with no terminal record (explicit, documented gap; a verifier must accept "journal closed with v2 evidence" as a legitimate end). More code in the most security-sensitive function; new journal evidence schema; condition 2 depends on systemd job semantics that are only qualifiable on a real host (the CancelJob interaction in finding 4 above especially).
- Security: no new authority, flag or env bypass. Condition 2 is not a user-controllable input: a process lacking root cannot create a stop job for the controller, and an attacker who can SIGTERM the root controller already owns it. Residual risk: auditd killed by an unrelated fault concurrently with an operator stop would be excused; mitigated by cond. 1,3,4 and by the evidence digest showing exactly which head was last verified. If any of the proof inputs cannot be read (bus error), fall back to recovery_required (fail closed).

### Option D (not recommended): helper ExecStop signals/asks controller first
auditd `ExecStop=` (runs as azaudit, before auditd is killed, after commissiond is gone) would need to reach the controller (root) to make it record `stopping` first, then wait for acknowledgement. That requires a new controller-listening channel or a signal privilege (azaudit cannot signal root; polkit would add authority), or auditd authoring a record for the controller (breaks peer-proven authorship, bootstrap_audit_client/peer). Large new attack surface for a one-record gap. Rejected.

## 4. Recommendation

Implement **Option C** (in code, no unit change), and document **Option A** as the preferred controller-first operator command for when a complete ledger close is wanted (`systemctl kill --kill-whom=main -s TERM azazel-activated.service`; wait inactive). Keep the current unit ordering (it is the fail-closed backstop for SIGKILL/watchdog/deadline).

Touch points: R/bootstrap.py `_finish_transaction` :545-560 (classification) and :536/:564 (`_advance_grant("closed", evidence_digest=...)`), a pre-`_contain` snapshot method (new, calls the manager's existing job reader; the manager interface for BootstrapSupervisor and `_PrototypeBootstrapManager`/production manager must gain a read-only `controller_stop_observed() -> bool`), `_close_intent_digest`/new `_manager_stop_digest` next to bootstrap.py:486-514, R/activated.py:523-525 for the distinct exit message. Journal needs no schema change if the v2 digest is carried in the existing `close_evidence_digest` field (src/azazel_nexus/bootstrap_grant_transaction.py:53,:93-101 only requires a sha256 string).

## 5. Tests (tests/unit/test_runtime_bootstrap.py harness, `Harness`, `h.record`, `h.manager`)

Positive:
- stop after helpers: set `h.stop=True` and make `h.record` raise for `bootstrap.stopping` while `h.manager.controller_stop_observed=True`; assert run() returns without exception, grant phase `closed`, evidence digest equals expected v2 digest (reason + last head), all units inactive+masked, no `bootstrap.stopped`, no `recovery_required`.
- readiness-lost during stop window: `h.manager.is_ready` returns False once, stop job observed, `record` fails -> same closed outcome; assert the original readiness exception is not swallowed unless proof holds.
Negative (must stay fail-closed):
- record fails, no stop job observed (auditd crash) -> `ApprovalRefused("... not fully recorded")`, grant `recovery_required` (existing behaviour).
- record fails with stop job but `_contain` raises -> `recovery_required`, containment exception propagates.
- stop job observed but one helper still active at confirm -> BootstrapContainmentFailed.
- bus error while sampling stop job -> treated as not observed -> recovery_required.
- `_audit_head`/last receipt None (stop before first record) -> not eligible.
- record raising a non-AuditUnavailable error type, or a `close_error` (grant advance failure) -> not waived.
- evidence tamper: v2 digest differs when last head differs; grant store rejects a non-sha256 digest.
Other:
- hardening test (tests/unit/test_runtime_hardening.py) unchanged and still green, proving no unit change.
- auditd/ledger verifier test (tests/unit/test_runtime_auditd.py:435-459 style) that a chain ending without `bootstrap.stopping` verifies when journal says v2.
- Native qualification (cannot be unit-tested): real `systemctl stop azazel-activated`, `systemctl reboot` in a VM, and Option A command; capture ListJobs timing, whether C1's drain cancels the controller's own stop job, and total containment time vs TimeoutStopSec=10s (the earlier 9.5 s measurement in the Q9 doc E2 last bullet is a SIGKILL risk (TimeoutStopFailureMode=kill) independent of this design and should be measured first).

## 6. Open questions / unverified
- No systemd available; stop ordering above is from documented systemd semantics, not an executed trace. Qualify natively.
- Exact job row shape for a pending stop job of the controller and whether ActiveState is already `deactivating` while the job waits on dependents (unit enters deactivating only when its own stop job runs, so for the readiness-lost race rely on the ListJobs row).
- Whether `CancelJob` in job drain can or should be allowed to remove the controller's own stop job (finding 4).
