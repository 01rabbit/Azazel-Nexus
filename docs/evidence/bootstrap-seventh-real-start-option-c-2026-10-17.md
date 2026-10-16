# Bootstrap seventh real start of azazel-activated.service (build af370f3) - Option C manager stop - run record

Date: 2026-10-17. Status: full supporting-only path ran to steady state on the test VM, then the operator ran `systemctl stop --no-block azazel-activated.service` (Option C). Systemd stopped commissiond, then auditd, then the controller; the controller confirmed containment, closed the grant with manager-stop close evidence and exited 0 (`Result=success`). This is the designed Option C outcome.
Related: `docs/evidence/bootstrap-sixth-real-start-2026-10-16.md` (run 6, controller-first stop), `docs/evidence/bootstrap-design-operator-stop-2026-10-16.md` (Option C design), `docs/evidence/bootstrap-finding-reboot-rerun-2026-10-16.md`.

## 1. Claim and scope

On the Debian 13 TEST VM, a plain systemd stop of the controller after both helpers were up (the first real-host exercise of Option C) ended with: overlay withdrawn, overlay journal closed, grant `closed` with the v2 manager-stop close evidence, no recovery state, exit 0, and a ledger that continues the existing chain without a `bootstrap.stopping` record. The ledger chain continued from sequence 13 through the re-pinned v4 existing-history admission (the second continuation).

NOT shown by this run:
- deadline expiry on a real host (covered only by the fixture-scoped Q7-R kernel-deadline SIGKILL);
- long-duration steady state (about 68 s from S9 to the stop; 24 heartbeats over the run);
- hardware.

Caveats: VM only; approval is synthetic (owner-signed test approval); the records quarantine is test scaffolding, not a product feature. Issue #93 remains open until its acceptance criteria are reviewed.

## 2. Setup (orchestrator-observed; checked against retained files)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257 |
| Product build | af370f3 |
| Boot | `1817e37f-3699-4a5c-9f74-87a74a06f5a2` (reboot after full records quarantine) |
| Admission | existing-history v4 re-pinned to ledger head sequence 13 (hash `ef2a005a...`); admission digest `sha256:6ddbeb66...` |
| Approval payload | `sha256:f4812159...` (synthetic, owner-signed) |
| Records | full quarantine: 17 files moved, nothing deleted; ledger kept (4962 B, 13 records) |
| Monitor | updated to ignore operator `session-*.scope` (the run 6 false positive) and to support `RS_STOP_MODE=systemd` |

Owner decision for this run: stop method is Option C (`systemctl stop --no-block`), not the controller-first SIGTERM used in run 6.

## 3. Timeline (T0 = `systemctl start --no-block`, about 22:51:09 UTC / 07:51:09 VM local)

| T+ (s) | Event |
|---|---|
| 5.5 | S1: admission, deadline retained, grant `pair_grant_intent` |
| 17.0 | S2: overlay journal intent -> partial -> published; both overlay files present |
| 18.8 | S3: Reload; both helpers `loaded` |
| 22.3 | S4: READY=1, controller active |
| 29.0 | S5: first heartbeat |
| 39.5 | S6: auditd active |
| 48.8 | S7: grant `audit_intent_recorded` (chain continued, ledger 4962 -> 5333 B and growing) |
| 73.3 | S8: grant `commissiond_ready` (ledger 7275 B) |
| 75.3 | S9: steady loop, both helpers active (monitor labelled it EARLY vs tolerance) |
| 143.25 | Option C stop; controller `deactivating`, grant `closing` |
| 147.25 | controller `inactive`, grant `closed` |

Steady observation: both helpers active and heartbeats continuing until the stop (maximum heartbeat gap 12.2 s against the 28 s alert limit and `WatchdogSec` 30 s).

Stop sequence (VM journal, `journal-window.txt`, 07:50:30 - 07:54:30 VM local):
- 22:53:32.11Z (07:53:32.11) `systemctl stop --no-block azazel-activated.service`;
- 07:53:32.113 `azazel-commissiond.service` stopped, then 07:53:32.115 `azazel-auditd.service` stopped (BindsTo/Requires stop propagation, helpers first);
- 07:53:32.116 `Stopping azazel-activated.service`; the controller then withdrew the overlay with repeated daemon-reloads (15 reloads in the run);
- 07:53:36.02 controller message `az-activated supporting bootstrap stopped by manager after helpers; stopping record unavailable`;
- 07:53:36.04 controller exited 0 (`Result=success`).

## 4. End state

- Overlay empty; overlay journal `phase: closed`; helpers masked and inactive; controller inactive (dead), exit 0.
- Grant `phase: closed`, close evidence `sha256:0f7479b2...`, `recovery_evidence_digest: null` (no recovery). The close evidence differs from the controller-first close evidence of run 6 (`sha256:bfe9a876...`) because it is the v2 manager-stop digest (section 5).
- Monitor final line: `outcome: operator stop complete: Result=success status=0`, controller inactive, helpers inactive, overlay empty, journal closed, grant closed; no stop reasons, no refusal.
- Audit ledger: records 1-13 unchanged (runs 4 and 6). Run 7 appended: 14 `grant_intent`, 15 `controller_ready_intent`, 16 `start_intent` (auditd), 17 `ready` (auditd), 18 `start_intent` (commissiond), 19 `ready` (commissiond). There is no `bootstrap.stopping` record.

## 5. Why this is the designed outcome

Code path (`runtime/src/azazel_nexus_runtime/bootstrap.py`, `activated.py`):
- Unit ordering makes a systemd stop reach the controller last: commissiond, then auditd, then the controller (design doc, section 1). The controller's `_record("bootstrap.stopping")` therefore fails with `AuditUnavailable`.
- `_finish_transaction` normally turns that failure into `audit_error` and `recovery_required`. The waiver applies only if all hold: the failure is `AuditUnavailable`; the grant reached `closing` with no close error; the stop cause is eligible (`_stop_cause_eligible`); and `_observe_manager_stop()` (a single read-only manager sample taken before containment) is true.
- `_contain()` must then succeed (confirmed containment).
- `_manager_stop_digest` runs `_post_containment_chain`: a read-only re-read of the on-disk chain after auditd is confirmed inactive. The observed tip must be at least the last verified head and last receipt, with matching digests at equal sequences, otherwise `audit chain not intact after containment`.
- On success the close evidence becomes the v2 digest (`azazel-nexus/bootstrap-close-evidence/v2`, `stopping_record: absent-manager-stop`, binding the last head, last receipt, post-containment tip and the containment digest), the grant is advanced to `closed`, and `activated.py` prints the distinct line and returns 0. Any unprovable input keeps `recovery_required`.

Observed: the manager-stop message was printed, `Result=success`, close evidence differs from the controller-first digest, no recovery digest, and no `bootstrap.stopping` in the ledger. This matches the waiver conditions: manager stop observed, containment confirmed, chain re-read intact after containment.

## 6. Tool follow-ups

- The monitor change (ignore `session-*.scope`, support `RS_STOP_MODE=systemd`) worked: no false positive occurred.
- Monitor S9 tolerance still labels the steady stage EARLY (+2.0 s after S8; expected 10..23 s); a tolerance adjustment only.
- A verifier of the ledger must accept "journal closed with v2 manager-stop evidence and no terminal ledger record" as a legitimate end (design doc, Option C cons).
- Cross-boot renewal remains unimplemented (`docs/evidence/bootstrap-finding-reboot-rerun-2026-10-16.md`); this run again used owner-approved test quarantine and a reboot.

## 7. Evidence retention

Raw outputs (VM journal window, run artifacts, post-run diagnostics, owner-tool output) are retained in the operator's scratch area; this record summarises them and does not embed them.
