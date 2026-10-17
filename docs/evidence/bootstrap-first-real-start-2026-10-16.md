# Bootstrap first real start of azazel-activated.service (build ee5cdd2) - run record

Date: 2026-10-16. Status: the real controller started, admitted, published the pair and contained it, then refused inside its own pre-ready controller inspection (`UnitOperationFailed`). READY was NOT reached. Contained, no genesis.
Raw outputs (realstart-out tar: before/after listings, `run/events.log`, `run/timeline.log`, PID 1 / unit / full journals, `run/cgroups.log`, monitor state, `systemctl show` of the failed controller, diagnosis README) are retained in the operator's scratch area; this record cites them by name only.
Related: `docs/evidence/bootstrap-factory-switch-rereview-2026-10-16.md` (Gate A section 6, owner decisions D1-D9), `docs/evidence/bootstrap-qualification-q4r4-ee5cdd2-2026-10-16.md`, `docs/evidence/bootstrap-qualification-q10-q3-2026-10-16.md`.

## 1. What this is, and what it is not

- This is the first real start on the test VM. It exercised real admission, the real deadline, the real grant, real publication of the pair by the real controller, and real containment (withdraw, journal and grant close).
- It did NOT reach READY, helper start, peer proofs, genesis, heartbeat or operator stop.
- It is a product defect, found only by a real start (exactly the risk the re-review predicted: the controller inspector was stubbed in Q4-R4). It is not a hardware result.
- Approval is synthetic (test VM only). Issue #93 remains open.

## 2. Setup (as observed)

| Item | Value |
|---|---|
| Target | test VM, Debian 13 |
| Product build | ee5cdd2 (factory switch dc3e6fd + O1 ee5cdd2) |
| Loaded-units record | `sha256:305fc910...` (measured) |
| Boot | `110d6f7e-b98d-422a-af87-d692c6ab1dfa` |
| Approval payload | `sha256:cf2a7093...` (synthetic, owner-signed) |
| Substitutions | none: real inspector, real sd_notify, real manager (unlike Q4-R4 D3/D5/D6) |

Owner decisions applied: D1 genesis allowed on the test VM (not reached); D2 a 30 s miss is a failed attempt (not reached); D4 controller-first SIGTERM (not used, controller had already ended); D5 controller stays enabled (`enabled` at the end); D9 Q4-R4 first (done).

Preparation: reboot to the boot above. The still-enabled boot-time run refused at selection binding and left no state. `/data` tmpfs remounted (`size=512M`, `noexec,nosuid,nodev`). The five boot-bound records (selection, time, approval, approval signature, `initial.json`/`checkpoint.json`) were quarantined with `mv -n` (owner-approved test scaffolding, as in Q10; not precedent). The owner renewed selection, time and approval for the new boot and signed. Preflight: 0 failures. `apt-daily` and `apt-daily-upgrade` timers were stopped for the run and restored afterwards (both `enabled`, left `inactive` at the verify capture until `restore`).

T0 = `systemctl start --no-block azazel-activated.service` at 17:46:01 local (08:46:01Z).

## 3. Timeline (seconds from T0, monitor at 4 Hz)

| T+ | Event | Gate A |
|---|---|---|
| 0.006 | T0 returned (rc 0); controller `activating/start`; helpers inactive/masked | |
| 0.013 | `/proc` evidence for pid 2786 captured | R1 literal |
| 1.22 | first PID 1 Reload, requested by `az-activated` (controller startup close) | |
| 1.26 | tree note: `/run/azazel` added | see section 6 |
| 5.5 | S1 grant `pair_grant_intent`, `initial.json` present | expected 6..9: OK (early, within tolerance 4.2..11.7) |
| 9.0 / 10.5 | old journal closed -> none -> `intent` | |
| 12.25 | auditd overlay file (2106 bytes) | |
| 14.0 | journal `partial` | |
| 15.5 | commissiond overlay file (2299 bytes) | |
| 17.25 | journal `published`; S2 | expected 8..21: OK |
| 19.0 | journal and grant `closing`; both files size 0 | containment |
| 19.8 - 23.3 | 13 uniformly spaced (~0.29 s) PID 1 Reloads (close loop) | |
| 20.0 | journal `withdrawing` | |
| 20.5 / 21.5 | commissiond file unlinked / auditd file unlinked (overlay empty) | |
| 22.25 | journal `closed` | |
| 22.75 | controller `failed`, `Result=exit-code`, status 1; grant `closed` | |
| 22.76 | monitor: `FAIL: controller left active/activating unexpectedly` | |
| 23.27 | controller journal: `az-activated failed before completing a safe pass: UnitOperationFailed` | |
| 34.78 | monitor done: controller failed, helpers inactive, overlay empty, journal closed, grant closed | |

Controller CPU 20.1 s, memory peak 75.5M. S3 onward never occurred. The monitor sent no signal (no stop condition was reached before the controller ended on its own).

## 4. End state (verified from the after capture)

- Overlay directory empty; `/run/systemd/system.control` empty; no `/etc/systemd/system.control`.
- Overlay journal `closed`, `owned_files=[]`, bound to this boot.
- Grant for this boot `closed`, `close_evidence_digest` `sha256:bfe9a876...`, `recovery_evidence_digest` null, `audit_receipt_digest` null.
- Marker `/run/azazel-nexus-bootstrap/controller-used` present (consumed). A second start in this boot is impossible.
- Helpers `LoadState=masked`, `inactive`, `InactiveExitTimestampMonotonic=0`: never started. Mask symlinks `-> /dev/null`, mask stamps unchanged.
- Audit ledger: 0 records (no genesis).
- Records (selection, time, deployment, approval, installed-files) unchanged; unit and venv digests unchanged; no new `.pyc`; prior-boot grant byte-identical.
- Controller `/proc/2786/cgroup` literal: `0::/system.slice/azazel-activated.service` (R1 controller literal captured). The B1 helper literals were not captured (helpers never ran).
- Manager `degraded` (only the failed controller). Controller `failed`, still `enabled` (D5); not `reset-failed`.

## 5. Verify FAIL lines

The `verify` stage is written for the success path (controller-first stop). The console output of `verify` was not in the retained tar; the list below is reconstructed from the check logic in `realstart.sh` applied to the retained after capture. Items 1-8 are expectations that do not apply to a refusal and are not defects of the end state (item 7 is separately classified in section 6).

| # | verify check | Observed | Why it does not apply |
|---|---|---|---|
| 1 | monitor did not record FAIL | status FAIL | monitor treats a controller that leaves `activating` unexpectedly as FAIL; correct for the plan, here it is the refusal |
| 2 | controller `ActiveState=inactive` | `failed` | success-path stop expected; a refusal ends `failed` |
| 3 | controller exit status 0 / `Result=success` | status 1 / `exit-code` | same |
| 4 | auditd was started (`InactiveExitTimestampMonotonic != 0`) | 0 | helper never started |
| 5 | commissiond was started | 0 | same |
| 6 | stop order commissiond before auditd | both timestamps 0 | no stop happened |
| 7 | no tree change outside approved/declared locations | `/run/systemd/transient/session-2x.scope` | operator login sessions, see section 6 |
| 8 | auditd and commissiond literal cgroup strings (B1) | not captured | helpers never ran |

(Item 8 is two checks, so the success-path count is 9 failing checks in total.) The remaining checks pass: helpers inactive, cgroups empty, masked, `FragmentPath` and mask symlinks, overlay empty, journal and grant closed with digest, no recovery digest, marker present, no queued jobs, mask stamps / `.pyc` / digests / records / prior grant unchanged, apt services inactive, controller cgroup literal.

Tooling defect found by this run: the monitor and `verify` count PID 1 Reloads by grepping `Reloading requested`, which does not occur on Debian 13 / systemd 257 (the text is `Reload requested from client PID ...` and `Reloading...`). The monitor therefore reported `reloads=0` and the Gate A stop condition 3 limit (15) was blind in this run. The Reload count was recovered from the PID 1 journal by hand: 28 `Reloading` lines = 14 Reloads. Fix in the owner tool before the next run.

## 6. Tree changes outside the Gate A four

Gate A approved locations: `/run/systemd/system.control`, `state/bootstrap`, `state/bootstrap-overlay`, `state/audit`, `/run/azazel-nexus-bootstrap`. In the tree diff (from `after/tree-diff.txt`) the approved changes were: marker created, `initial.json`, `checkpoint.json`, this boot's grant created, overlay journal rewritten. Outside the four:

| Path | Cause | Classification |
|---|---|---|
| `/run/systemd/transient/session-22.scope` (gone), `session-23.scope`, `session-25.scope` (new) | operator ssh login sessions opened and closed around the run (PID 1 journal shows session-22 deactivated and `user@1000` stopped before T0) | Unrelated to the product; transient systemd runtime state of the operator's own logins. Not a product change. The tool's verify check flags it because the scan is path-based; the in-run monitor logged no violation (`tree-violations.log` absent). |
| `/run/azazel` | created at T+1.26 by the controller unit start (RuntimeDirectory of the unit, shared by the three azazel units; helper-declared path, listed in README section 3 as "not in the Gate A four") | Legitimate, declared by the unit files; noted by the monitor as a tree note, not a stop condition. Not part of the verify tree listing, so it is recorded from `timeline.log` only. |

No change in `/opt/azazel-nexus`, `/etc`, unit directories or the venv.

## 7. Diagnosis

Failing check (from the operator diagnosis, verified against the source): the controller inspector's one-use start condition check in `runtime/src/azazel_nexus_runtime/bootstrap_controller.py` (`_unit_projection`, about line 113). It requires the `Conditions` property (`a(sbbsi)`) to equal exactly `["ConditionPathExists", False, True, <marker path>, 1]`, i.e. per-condition state 1 (succeeded), and `ConditionResult` true; otherwise it raises `UnitOperationFailed("controller one-use start condition refused")`.

Cause: systemd resets the per-condition state to 0 (untested) on every daemon-reload; only the aggregate `ConditionResult` and `ConditionTimestamp` persist. The controller's own startup close triggers a Reload at T+1.22, before the inspector ever reads the controller, so the real inspector can never see state 1.

Evidence:
1. Live read-only probe after the run: `Conditions = ("ConditionPathExists", false, true, "/run/azazel-nexus-bootstrap/controller-used", 0)`, `ConditionResult=true`, `ConditionTimestamp` 17:46:00.99 (before the 17:46:01.22 Reload). Matches the expected tuple in every field except the last (0 observed, 1 required). A control unit of the same shape that was tested at boot also shows state 0 after Reloads.
2. Reload count 14 here (1 at T+1.22 plus 13 close-loop Reloads at ~0.29 s) versus 15 in the Q4-R4 READY run (those 14 plus one publication Reload at T+18.3). There is no publication Reload and no ~3.5 s gap in this run, so the refusal occurred after `published` (T+17.25) and before the Reload inside the inspection, i.e. in the first controller inspection.
3. Every other compared property of the failed unit matches the expected shape (single `Id`/`Names`, `DefaultDependencies=no`, `NeedDaemonReload=no`, `Type=notify`, `NotifyAccess=main`, `Restart=no`, 30 s start/watchdog, `TimeoutStopUSec=10s`, `User=root`, bounding set, no Exec*Pre/Post/Stop/Reload, controller cgroup).
4. Why it did not surface earlier: the Q4-R4 harness's D3 stub replaced the whole controller inspector.

Not provable from logs alone: the product log carries only the exception class (`UnitOperationFailed`), not the failing check. The identification is by timing elimination plus the live property showing the exact mismatch the code rejects.

Observability gap (product): the final refusal line hides the message of the failing check. All such messages are static strings; logging them would not leak data.

Next-risk (unverified): the real controller inspector has never passed once. Other parts of it (ExecStartEx integer ranges, the `ready` phase, the post-Reload second pass and fingerprint stability) are exercised only by a real run.

## 8. Next steps (owner decision required)

1. Fix proposal (product): accept per-condition state 0 or 1 while keeping every other field exact (tuple must still be exactly the one-use `ConditionPathExists` with trigger false, negate true, the marker path; `ConditionResult` must remain true; states -1, -2 and others refused). Drop the state integer from the snapshot projection so snapshots straddling a Reload compare equal. The one-use property remains enforced by systemd (`ConditionPathExists`) and by the preserved `ConditionResult`. Update `tests/unit/test_runtime_bootstrap_controller.py` with a state-0 case.
2. Observability (product): log the static message of the refusal, not only the exception class.
3. Owner tool: Reload-count pattern for Debian 13 (section 5); Q4-R4 harness should pass the real controller inspector through before any stub.
4. Then: a new build (the build digest changes; the loaded-units record does not contain the controller inspector), new records and approval, and one more real start. The marker makes a second start in this boot impossible, so a reboot and the preparation sequence repeat.

Until the owner decides: no retry in place; the VM keeps the failed controller (not `reset-failed`), pair masked, ledger empty.
