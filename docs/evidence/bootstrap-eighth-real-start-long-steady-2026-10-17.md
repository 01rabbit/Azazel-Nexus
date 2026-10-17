# Bootstrap eighth real start of azazel-activated.service (build af370f3) - long steady state, stopped by monitor condition 3 - run record

Date: 2026-10-17. Status: the full supporting-only path ran to steady state on the test VM and stayed there for about 30 minutes (first long-duration steady state on a real host). The run was intended to observe deadline expiry. About 10 minutes before the deadline the monitor's stop condition 3 fired after a host/VM pause, and the monitor sent the controller-first SIGTERM (owner decision D4). The controller confirmed containment, closed the grant and exited 0 (`Result=success`). The monitor labelled the run `FAIL` only because a stop condition fired; the product end state is the designed controller-first outcome.
Related: `docs/evidence/bootstrap-seventh-real-start-option-c-2026-10-17.md` (run 7, Option C), `docs/evidence/bootstrap-sixth-real-start-2026-10-16.md` (run 6, controller-first stop), `docs/evidence/bootstrap-finding-reboot-rerun-2026-10-16.md`.

## 1. Claim and scope

On the Debian 13 TEST VM, both helpers (auditd, commissiond) stayed active under the controller with heartbeats continuing for 1902 s (168 heartbeats, maximum gap 12.38 s against the 28 s alert limit and `WatchdogSec` 30 s). The ledger chain continued from sequence 19 through the re-pinned v4 existing-history admission (the third continuation).

NOT shown by this run:
- deadline expiry on a real host. The run was stopped at T+1902 s, about 634 s before the deadline (see section 3); expiry is still covered only by the fixture-scoped Q7-R kernel-deadline SIGKILL;
- hardware;
- behavior of a continuously running (unpaused) guest across the full deadline window.

Caveats: VM only; approval is synthetic (owner-signed test approval); the records quarantine is test scaffolding, not a product feature. fwupd was started by the OS's own timer; no firmware operation was performed by the operator or tooling. Issue #93 remains open until its acceptance criteria are reviewed.

## 2. Setup (orchestrator-observed; checked against retained files)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257 |
| Product build | af370f3 |
| Boot | `0b2c1001-d4fb-4ed2-920c-09fa36646d1c` (reboot after full records quarantine; first journal entry 08:11:48 JST) |
| Admission | existing-history v4 re-pinned to ledger head sequence 19 (hash `e70b9844...`); admission digest `sha256:150bc2ef...` |
| Approval payload | `sha256:b3506a43...` (synthetic, owner-signed; expires 23:57:48Z; granted_at 2026-10-16T23:12:48Z) |
| Records | full quarantine: 17 files moved, nothing deleted; ledger kept (7275 B, 19 records) |
| Deadline | `deadline_boottime_ns` 2643986334836 (about boot+2644 s; T0 was at about boot+108 s, so about T+2536 s) |
| Monitor | safeguard autostop disabled (`RS_AUTOSTOP_S=100000`) because the intent was a real-host deadline-expiry test; stop conditions otherwise active |

Owner decision for this run: stop method is the controller-first SIGTERM sent by the monitor on a stop condition (D4), not Option C.

## 3. Timeline (T0 = `systemctl start --no-block`, 23:13:34Z = 08:13:34 JST)

| T+ (s) | Event |
|---|---|
| 5.5 | S1: admission, deadline retained, grant `pair_grant_intent` |
| 17.5 | S2: overlay journal intent -> partial -> published; both overlay files present |
| 19.3 | S3: Reload; both helpers `loaded` |
| 23.0 | S4: READY=1, controller active |
| 29.8 | S5: first heartbeat |
| 40.8 | S6: auditd active |
| 50.3 | S7: grant `audit_intent_recorded` (ledger 7275 -> 8803 -> 9199 B) |
| 74.8 | S8: grant `commissiond_ready` (ledger 9588 B) |
| 77.0 | S9: steady loop, both helpers active (monitor labelled it EARLY vs tolerance, as in run 7) |
| 77 - 1901.5 | Steady: both helpers active; heartbeats #19-#168 about every 12.2 s |
| 1902.261 | Monitor stop condition 3: job on a unit outside the controller/pair (`fwupd.service`, job 10523, start running); controller-first SIGTERM sent |
| 1904.75 - 1906.25 | Overlay withdrawn (reloads #11-#15); journal `withdrawing` -> `closed` |
| 1906.50 | Controller `inactive`, grant `closed` (`Result=success`, `ExecMainStatus=0`) |
| 1918.5 | Monitor done: helpers inactive, overlay empty, journal closed, grant closed |

The SIGTERM at T+1902.26 is 08:45:16.71 JST; the deadline was about T+2536, so the stop came about 634 s (10.6 min) before it.

Heartbeats: 168 in total; first-phase gaps 1.8 - 8.0 s, then steady about 12.2 s; maximum gap 12.38 s (heartbeat #98, T+1046.0). No gap approached the 28 s alert limit. Monitor loop lag stayed 0.000 s over 7675 ticks. The monitor and heartbeats saw no discontinuity because a paused guest's monotonic clock also stops (see below).

## 4. Host/VM pause and the OS maintenance timers (VM journal, `journal-window.txt`, 08:12:00 - 08:46:30 JST)

- The retained window has no VM journal entries between 08:32:04 (`session-66.scope` closed) and 08:45:16.46; the orchestrator observed the quiet period as starting about 08:40. Either way the VM journal was silent for over 13 minutes while T+ advanced only by the guest clock, and the VM did not answer ping or ssh at 08:45:08 JST.
- Interpretation (orchestrator, not proven from guest data alone): the host or VM was paused. A paused guest's boottime clock stops as well, so the kernel deadline (boot+2644 s) would have been delayed by the pause length. The monitor's poll and heartbeat clocks, also guest-side, show no gap, which is consistent with this.
- At 08:45:16.46 `fwupd-refresh.service` and `man-db.service` started together (the `fwupd-refresh.timer` and `man-db.timer` catch-up after resume); `fwupd-refresh` ran `fwupdmgr refresh`, which D-Bus-activated `fwupd.service` (starting 08:45:16.56). This was the OS's own timer activity; no firmware operation was performed by the operator or tooling.
- 08:45:16.71 `azazel-activated.service: Sent signal SIGTERM to main process 2664 (az-activated) on client request`.

## 5. Stop sequence and end state

Stop (VM journal, controller-first, as in run 6):
- 08:45:16.71 SIGTERM to the controller; 08:45:16.76 the controller requested a daemon-reload;
- 08:45:16.97 `azazel-commissiond.service` stopped, then 08:45:16.98 `azazel-auditd.service` stopped (the controller stopped its helpers; man-db finished 08:45:17.01 meanwhile);
- repeated daemon-reloads while the overlay was withdrawn (15 reloads in the run);
- 08:45:20.76 controller message `az-activated supporting bootstrap stopped after confirmed containment`;
- 08:45:20.78 `azazel-activated.service: Deactivated successfully` (exit 0).

End state:
- Overlay empty; overlay journal `phase: closed`; helpers masked and inactive; controller inactive (dead), exit 0.
- Grant `phase: closed`; no recovery digest (`recovery_evidence_digest: null`).
- Audit ledger: records 1-19 unchanged. Run 8 appended 7 records: 20 `grant_intent`, 21 `controller_ready_intent`, 22 `start_intent` (auditd), 23 `ready` (auditd), 24 `start_intent` (commissiond), 25 `ready` (commissiond), 26 `stopping` (the controller-first terminal record, present because auditd was still up when the controller began stopping). Ledger size 7275 B -> 9955 B.
- Monitor final line: `outcome: FAIL: stop condition 3: job on unit outside the controller/pair: 10523 fwupd.service start running`; `ctl_terminal` inactive / `success` / status 0; no refusal; note `S9 earlier than tolerance`.

## 6. Findings and follow-ups

- Steady state is stable over about 30 minutes on a real host: no heartbeat gap above 12.4 s, no watchdog event, no drift in the pair.
- Deadline expiry on a real host is still NOT observed. A deadline run must prevent interruptions of the host and OS: keep the host awake (for example `caffeinate`) so the VM is not paused, and stop or mask OS maintenance timers (`fwupd-refresh.timer`, `man-db.timer`, and apt timers) in the VM for the duration. Repeat the run with those controls.
- Stop condition 3 worked as designed: it caught a job outside the controller/pair and stopped the run before an unattributable event could overlap the deadline. Because the pause also delays the kernel deadline, a paused run cannot be used as expiry evidence.
- Monitor S9 tolerance still labels the steady stage EARLY (+2.3 s after S8; expected 10..23 s); a tolerance adjustment only.
- Cross-boot renewal remains unimplemented (`docs/evidence/bootstrap-finding-reboot-rerun-2026-10-16.md`); this run again used owner-approved test quarantine and a reboot.

## 7. Evidence retention

Raw outputs (VM journal window, run artifacts including `timeline.log`, `events.log` and `monitor.state`, post-run diagnostics, owner-tool output) are retained in the operator's scratch area; this record summarises them and does not embed them.
