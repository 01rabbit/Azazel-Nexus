# Bootstrap factory qualification: Q7-R notify controller lifecycle, expiry mid-run, overlay left behind, same-boot recovery (test VM, 2026-10-16)

Scope: Debian 13 test VM, systemd 257.13, build c79291b, same boot as Q4-R3 and Q6; not hardware evidence; production factory unchanged.
Method: the UNMODIFIED `BootstrapSupervisor` (`run`, steady loop with 10 s poll, `_heartbeat`, `_contain`, `_finish_transaction`, `_mark_recovery`, the recovery branch) ran inside a transient `Type=notify` fixture controller `azn-q7-ctl.service` with the packaged sandbox properties, `WatchdogSec=30s`, `WatchdogSignal=SIGKILL`, using the product `notify_ready` / `notify_watchdog`, `BootstrapProcessLifetime`, `BootstrapKernelDeadline` (CLOCK_BOOTTIME timer, SIGKILL), grant store, overlay journal store and lock. The controller was ended four ways (K, R, W, T), then a second transient unit `azn-q7-rec.service` ran the supervisor twice as the "next start". Harness and procedure: Q7 design notes (`README-q7.md`, `q7-harness.py`, `q7-run.sh`, kept outside the repo); review definition: `docs/evidence/bootstrap-factory-switch-review-2026-10-16.md` (Q7).
Harness fixes made before the run (no product source changed): (1) pure-Python Ed25519 for the ephemeral synthetic approval, because pynacl is absent on the VM; (2) DHCP lease-lifetime counters (`valid_lft`/`preferred_lft`) excluded from the network snapshot diff, because the first smoke flagged only that countdown.
Smoke: imports-ok, synthetic approval ok, kernel-deadline backend ok, stores/lock ok (`RESULT outcome=smoke-ok`); notify canary ok (READY + 4 watchdog pings, `WatchdogUSec=30s`).

## Substitutions (declared before the run)

| ID | Substitution |
|---|---|
| S1 | `FixtureManager` replaces the real `BootstrapManager`: publishes fixture unit files to `/run/systemd/system.control`, journals them with the real `OverlayJournalStore`, and implements `close_starts`, `withdraw_pair`, `confirm_empty_pair` with `systemctl`. The recovery result is a property of the fixture manager's containment, not the packaged one. |
| S2 | Fixture helpers `azn-q7-a/b.service` (`Type=notify` Python loops, `User=nobody`, `BindsTo=` the controller, B also binds A), with persistent `/etc` masks as in Q2. |
| S3 | Product pair strings (`azazel-auditd.service` etc.) appear only as inert data in the journal/grant records under `/var/lib/azn-q7/`. Owner-approved. No systemd call named a product unit. |
| S4 | Stores opened by descriptor on private state dirs `/var/lib/azn-q7/<scenario>/`, not `/var/lib/azazel/state`. |
| S5 | SYNTHETIC approval: in-process ephemeral Ed25519 key, never written, operator `q7-synthetic-operator`, lifetime 90 s (K) or 300 s. Not an owner approval; real admission is not exercised. Audit is an in-memory fixture. |
| S6 | Controller is the transient `azn-q7-ctl.service` with packaged sandbox properties, plus `RuntimeMaxSec` (absent from the packaged unit) and, for R only, `KillSignal=SIGKILL`. |
| S7 | Same-boot recovery is a substitution: the per-boot grant means the "existing transaction requires manual review" branch is only reachable in the same boot, which the packaged unit cannot do (`controller-used` marker). A real crash is followed by a next-boot start that takes the fresh path. |
| S8 | Fixture timing (every `step seconds=`) is fixture speed, not product timing. |

## Results

| Scenario | Trigger | Controller end | Result |
|---|---|---|---|
| K (kernel deadline) | synthetic approval 90 s, kernel timer | `Result=signal`, `ExecMainStatus=9`, no `RESULT` line in harness.out: this is K1, not the K2 race; failed at +90.44 s | PASS (post-crash 2 harness FAIL, see below) |
| R (RuntimeMaxSec) | `RuntimeMaxSec=45`, `KillSignal=SIGKILL` | `Result=timeout`, `ExecMainStatus=9`; stop at +45.50 s | PASS (same 2 FAIL) |
| W (watchdog) | `SIGSTOP` of the controller at +30.77 s (wall 1792130140.05) | `Result=watchdog`, `ExecMainStatus=9`; stop at +60.75 s, about 30 s after SIGSTOP | PASS (same 2 FAIL) |
| T (SIGTERM control) | `RuntimeMaxSec=45`, packaged `KillSignal=SIGTERM` | exit within `TimeoutStopSec`; `RESULT outcome=supervisor-returned-stopped`, 45.92 s; `close_starts`, `stop_and_wait` x2, `confirm_empty_pair`, `withdraw_pair`, `confirm_empty_pair`, `deadline-release`; journal `closed`, grant `closed`, overlay empty, helpers masked and inactive | PASS (0 FAIL) |

For K, R and W (post-crash, `checks-post-crash.txt`), all PASS except the two lines noted below:
- READY reached; both fixture helpers started by the real supervisor (`helper-started` a then b, 0.03 to 0.05 s each).
- Steady-loop heartbeats from the supervisor: K 11, R 7, W 6 steady-loop beats. Gaps were about 10.02 s (max 10.03 s), well under 25 s (`WatchdogSec=30s`).
- Journal `published` with 2 owned files; overlay inodes equal the journal ownership record; grant `commissiond_ready`.
- Overlay files left behind (a 615 bytes, b 689 bytes), units still `LoadState=loaded` from `/run/systemd/system.control/`.
- Helpers `inactive`, MainPID 0, empty cgroup.

Follow-stop, how measured: `events-relative.log` is a change-only log written by a background `systemctl show` poller (sleep 0.25 s per cycle, so about 4 Hz, plus sample cost). The first logged sample in which the controller is `failed` (K +90.44 s, R +45.78 s, W +61.04 s) already shows both helpers `ActiveState=inactive`, MainPID 0. In R and W the preceding sample (controller `deactivating`) already showed helper B inactive and A `deactivating`, i.e. the follow-stop began when the controller stop began. Because the poller samples about every 0.25 s, this bounds ctl-failed to helper-inactive to roughly one poll interval (about 0.25 s), not a systemd-timestamp measurement. This is well inside the 10 s limit but is a sampled bound.

Recovery x2 for K, R, W (`checks-post-recover1/2.txt`, `recover1/2.out`, 14 PASS each, 0 FAIL):
- `RESULT outcome=expected-manual-review detail=ApprovalRefused(existing bootstrap transaction requires manual review)`, no `READY-SENT`, no `helper-started`.
- First run steps: `close_starts`, `stop_and_wait` x2, `confirm_empty_pair`, `withdraw_pair` (0.26 s), `confirm_empty_pair`. Overlay empty, journal `closed` with no owned files, grant `recovery_required`, helpers `masked`/`inactive` with FragmentPath the `/etc` mask, no job queued, persistent masks intact, helpers not restarted (InvocationID and ActiveEnter unchanged from post-crash).
- Second run idempotent: same outcome and end state, `withdraw_pair` took 0.000 s (already closed), nothing restarted.
- T recovery x2: same refusal outcome; only `close_starts` and the stops ran (no withdrawal call), grant stays `closed`, 0 FAIL.

## FAIL lines (harness assumption, not a product failure)

Six FAIL lines: "was started exactly once and never restarted", for helper A and helper B in each of K, R and W (`K|R|W/checks-post-crash.txt` lines 16 and 20). The check required a non-empty InvocationID after the crash. systemd garbage-collected the inactive fixture units, so every post-crash property reads 0 or empty (`InvocationID=""`, `ActiveEnterTimestampMonotonic=0`, `ExecMainStatus=0`, see `postcrash-props.json`). The same garbage collection made the properties-based "follow-stop within 10 s" check unusable and it was skipped; it is replaced by the poller-based observation above. These checks did NOT pass. "Started exactly once" is supported only indirectly: harness.out shows exactly one `helper-started` per helper in each scenario. The post-recovery "not restarted" check passed, but it compares against the same empty post-crash values, so it is weak evidence for the no-restart claim; the stronger evidence is that the recovery runs emitted no `helper-started` and no READY.

## Cleanup and side effects

`before-after.diff` is empty (0 bytes): the product unit state, unit files, failed-unit list, network (lease counters excluded, see fixes), manager and tree snapshots before and after are identical. `azazel-activated.service` appears in `failed.txt` both before and after (unchanged). No product unit was named by any systemd call.

## Limits

- VM only; one run per scenario; nothing here is hardware evidence.
- The real packaged manager was not used (S1). The product `withdraw_pair` published branch (`BootstrapWithdrawalFiles.bind`, loaded-unit fences with a leftover overlay, fresh process) is covered by Q4-R, not here.
- Next-boot recovery (journal stale `published`, `/run` empty, fresh path via `_retire_prior_boot_journal`) is not covered; it needs Q3 (reboot, owner G1). The same-boot recovery here is a substitution (S7).
- Fixture timing is not product timing; the timing budget is Q8.
- The packaged `azazel-activated.service` has no `RuntimeMaxSec`; R is a stand-in for an external expiry, and the SIGKILL in R is fixture-only (`KillSignal=SIGKILL`).
- Real admission, installed-file measurement, peer proofs, audit ledger and the real helpers are not exercised (S5, S2).
- Issue #93 remains open.
