# Bootstrap ninth real start of azazel-activated.service (build af370f3) - deadline expiry on a real host - run record

Date: 2026-10-17. Status: first real-host observation of approval deadline expiry on the test VM. The controller ran steady for the full window with both helpers active, then the kernel deadline timer killed it with SIGKILL at the deadline (`Result=signal`, status 9/KILL). The monitor sent nothing. The helpers were follow-stopped by `BindsTo` within about 1 ms. The crash state (overlay files, journal `published`, grant `commissiond_ready`) was left durable and, after a reboot, stayed fail-closed. This is the designed K1 outcome (no in-process shutdown), not a clean close.
Related: `docs/evidence/bootstrap-eighth-real-start-long-steady-2026-10-17.md` (run 8, stopped by monitor condition 3 about 634 s before the deadline), `docs/evidence/bootstrap-qualification-q7r-2026-10-16.md` (fixture K1 deadline test), `docs/evidence/bootstrap-design-journal-lifecycle-2026-10-16.md` (Case B, stale published journal after reboot).

## 1. Claim and scope

Shown on the Debian 13 TEST VM, with a continuously running (unpaused) guest:
- Both helpers (auditd, commissiond) stayed active under the controller from S9 to the deadline; 220 heartbeats, maximum gap 12.32 s against the 28 s alert limit and `WatchdogSec` 30 s; monitor loop lag 0.000 s.
- At the deadline the kernel timer killed the controller: `azazel-activated.service: Main process exited, code=killed, status=9/KILL`, `Result=signal`, `ExecMainStatus=9`. The timeline has no `ACTION:` line (the monitor's only mutating verb, the controller-first SIGTERM, was never issued).
- The helpers followed within about 1 ms (commissiond stopped 09:48:32.3625, auditd 09:48:32.3638; controller exit 09:48:32.3614).
- The crash state was durable (section 5) and a reboot did not clear the record of unfinished containment (section 6).

NOT shown / not executed:
- the renewed-records attempt after the crash. That a later attempt would not auto-retire the stale journal and would refuse for manual review is derived from code (section 6), not executed;
- hardware; power loss;
- the K2 race (controller exiting cleanly at the deadline); this run was K1 only.

Caveats: VM only; approval is synthetic (owner-signed test approval); the records quarantine is test scaffolding, not a product feature. Issue #93 remains open until its acceptance criteria are reviewed.

## 2. Setup (orchestrator-observed; checked against retained files)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257, kernel 6.12.111+deb13-arm64 |
| Product build | af370f3 |
| Boot | `c19168be-c3a4-462b-ac92-5e2d5c3852da` (reboot after full records quarantine; kernel start 09:04:16 JST) |
| Admission | existing-history v4 re-pinned to ledger head sequence 26 (hash `86d2b5a9...`); admission digest `sha256:fb216f76...` |
| Approval payload | `sha256:92b119ac...` (synthetic, owner-signed; expires 00:50:31Z) |
| Records | full quarantine: 17 files moved, nothing deleted; ledger kept (9955 B, 26 records) |
| Deadline | `deadline_boottime_ns` 2658320441133 (about boot+2658 s; T0 at 09:06:09.68 JST, so the kill at T+2542.75 is consistent with it) |
| Preparations after run 8 | host kept awake with `caffeinate`; OS maintenance timers (apt-daily, apt-daily-upgrade, fwupd-refresh, man-db, logrotate, e2scrub_all) stopped for the run and restored after (enable state not changed); monitor autostop disabled (`RS_AUTOSTOP_S=100000`) |

The preparations address the run 8 finding: no host/VM pause occurred (the journal window 09:04:00 - 09:49:30 JST has regular `session-N.scope` activity roughly every 20 s throughout), and no job on a unit outside the controller/pair appeared, so stop condition 3 did not fire.

## 3. Timeline (T0 = `systemctl start --no-block`, 09:06:09.68 JST)

| T+ (s) | Event |
|---|---|
| 5.5 | S1: admission, deadline retained, grant `pair_grant_intent` |
| 17.5 | S2: overlay journal intent -> partial -> published; both overlay files present |
| 19.3 | S3: Reload; both helpers `loaded` |
| 22.8 | S4: READY=1, controller active |
| 29.8 | S5: first heartbeat |
| 40.8 | S6: auditd active |
| 50.3 | S7: grant `audit_intent_recorded` (ledger 10-17 file 1528 B) |
| 74.8 | S8: grant `commissiond_ready` |
| 77.0 | S9: steady loop (monitor labelled it EARLY, +2.3 s after S8; tolerance only, as in runs 7 and 8) |
| 77 - 2531 | Steady: both helpers active; heartbeats #1-#220, steady gap about 12.2 s |
| 2542.750 | Monitor poll: controller `active/running -> failed/failed`; auditd and commissiond `active/running -> inactive/dead` |
| 2542.761 | Monitor: `CONTROLLER ENDED: ActiveState=failed Result=signal ExecMainStatus=9` |
| 2554.794 | Monitor done: controller failed, helpers inactive/inactive, overlay `azazel-auditd.service:2106,azazel-commissiond.service:2299` (bytes), journal `published`, grant `commissiond_ready` |

VM journal at the kill (JST 2026-10-17):
- 09:48:32.361358 `azazel-activated.service: Main process exited, code=killed, status=9/KILL`; 361402 `Failed with result 'signal'`; 361557 `Consumed 8min 11.521s CPU time`;
- 09:48:32.362077 `Stopping azazel-commissiond.service`; 362544 `Deactivated successfully`;
- 09:48:32.363373 `Stopping azazel-auditd.service`; 363838 `Deactivated successfully`.

The monitor's two `FAIL` lines (`controller left active/activating unexpectedly`, `systemd kill/timeout text in journal`) are the monitor's generic stop-condition labels for an unexpected end; here the end was the expected deadline kill. No `ACTION:` line exists in the timeline, so the kill is attributable to the kernel deadline timer, not to the monitor. Stage times S1-S8 were all within tolerance.

## 4. Comparison with Q7-R fixture expectations (K1)

| Property | Q7-R fixture K (expected) | This run (real controller) |
|---|---|---|
| Kill | `Result=signal`, status 9, no `RESULT` line (K1, not the K2 race) | `Result=signal`, `ExecMainStatus=9`, `code=killed, status=9/KILL` |
| Helpers | both inactive at the first sample after the controller failed (follow-stop) | both stopped within about 1 ms of the controller exit (`BindsTo`) |
| Journal | `published` with 2 owned files | `published`; overlay files remained (2106 B, 2299 B) |
| Grant | `commissiond_ready` | `commissiond_ready`, no recovery digest |
| Teardown | none (SIGKILL) | none: no `stopping` ledger record, no withdrawal, no reload |

Difference: Q7-R used a fixture manager and units; units there were garbage-collected after the crash. Here, after the kill the units stayed `LoadState=loaded` from the overlay but inactive (overlay files still in `/run/systemd/system.control`). The Q7-R same-boot recovery steps (`close_starts`, stops, withdraw) were not run in this run; the next real start was after a reboot (section 6).

## 5. Post-kill state (before reboot; orchestrator-observed)

- Overlay: both files present in `/run/systemd/system.control` (2106 B, 2299 B); units loaded from the overlay, inactive.
- Overlay journal: `phase: published`, 2 owned files.
- Grant (boot `c19168be`): `phase: commissiond_ready`; `recovery_evidence_digest` null (no recovery ran).
- Audit ledger: head sequence 32, `bootstrap.ready`; this run appended records 27-32: `grant_intent`, `controller_ready_intent`, `start_intent` (auditd), `ready`, `start_intent` (commissiond), `ready`. No `stopping` record, as expected for SIGKILL (run 8 had `stopping` as record 26 because its SIGTERM path ran). The journal-window monitor shows ledger files 2026-10-16.jsonl 9955 B plus 2026-10-17.jsonl 2313 B at the last change (T+75.0), i.e. nothing was appended during steady state.
- Controller-used marker present.

## 6. After reboot (boot `9ce872a4-fb47-4f38-b84c-992e14b6aa12`; orchestrator-observed except where marked)

- `/run` was cleared: the overlay files are gone. Both helpers are masked and inactive (the `/etc` masks, symlinks to `/dev/null`, win again).
- The boot-time controller refused with `ApprovalRefused`: the approval selection is bound to the previous boot. It created no state.
- The stale journal (`published`) and the unclosed grant (`commissiond_ready`) persist on disk. They are the durable record that the previous boot did not finish containment.

Code-derived, NOT executed: a later attempt after renewing the records (new selection, admission and approval for the new boot) would not auto-retire this journal.
- `_retire_prior_boot_journal` (`runtime/src/azazel_nexus_runtime/bootstrap_manager.py`) only acts on a journal whose boot id differs from the current boot and requires the prior boot's preserved grant to exist with the same grant id, context digest and payload digests and `phase == "closed"`; this grant is `commissiond_ready`, so it raises `ApprovalRefused("prior boot grant identity differs from journal")` and publication is refused with the journal left in place. Its docstring also states that `recovery_required` or any unfinished phase keeps manual review.
- Per the same docstring and the design record (Case B), a stale `published`/`closing` journal normally fails even earlier, in `close_starts` (the overlay file is gone, so the closure candidate stat fails with `ApprovalRefused`). Either way the outcome is a refusal that needs manual review.
- `BootstrapWithdrawalFiles.retire_prior_boot` (`bootstrap_withdrawal.py`) is the removal step and is never reached on this path.

This matches the design record's finding that the journal outlives its boot in a crash and that production has no automatic path to a clean journal after a SIGKILL; the fail-closed refusal is the intended behaviour, and manual review/cleanup is the remaining (unimplemented as an automated step) recovery.

## 7. Findings and follow-ups

- Real-host deadline expiry behaves as the Q7-R fixture predicted: kernel SIGKILL, helper follow-stop, journal `published`, grant `commissiond_ready`, no teardown.
- Crash state is durable and fail-closed across a reboot: the previous boot's approval cannot be reused and the unclosed grant is not silently discarded.
- Run 8's controls (caffeinate, OS maintenance timers stopped, autostop off) were sufficient: no pause, no unrelated job, full-window steady state.
- Not executed: the renewed-records attempt after the crash (manual-review refusal is code-derived). Recommended next: run that attempt on the VM to confirm the refusal and that nothing is created, and decide the manual-review/cleanup procedure for a stale published journal with an unclosed grant.
- Monitor S9 tolerance still labels the steady stage EARLY (+2.3 s after S8; expected 10..23 s): a tolerance adjustment only. A monitor outcome of `FAIL` on an expected deadline kill is a labelling matter: when a deadline run is intended, the end by `Result=signal` status 9 at the deadline should be classed as the expected end.
- Cross-boot renewal remains unimplemented (`docs/evidence/bootstrap-finding-reboot-rerun-2026-10-16.md`); this run again used owner-approved test quarantine and a reboot.

## 8. Evidence retention

Raw outputs (VM journal window `journal-window.txt`, run artifacts including `timeline.log`, `events.log` and `monitor.state`, before/after diagnostics, owner-tool output) are retained in the operator's scratch area; this record summarises them and does not embed them. Note: the first copy of `realstart-out9.tar` was not a valid archive (operator tooling mixed a restore log into the stream); it was re-fetched from the VM as a valid archive afterwards. The stage, heartbeat, kill and post-kill facts above were read from the first copy as text and match the run artifacts. The post-reboot facts in section 6 are orchestrator observations and are not in the retained window.
