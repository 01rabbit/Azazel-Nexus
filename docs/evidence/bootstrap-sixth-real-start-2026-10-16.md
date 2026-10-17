# Bootstrap sixth real start of azazel-activated.service (build af370f3) - run record

Date: 2026-10-16. Status: full supporting-only path completed end to end on the test VM, then stopped by the operator (controller-first SIGTERM) with confirmed containment, exit 0 (`Result=success`). The monitor reported FAIL because of a monitor false positive (section 6), not a product fault.
Related: `docs/evidence/bootstrap-fifth-real-start-2026-10-16.md` (run 5, refused in prestart), `docs/evidence/bootstrap-fourth-real-start-2026-10-16.md` (run 4), `docs/evidence/bootstrap-factory-switch-rereview-2026-10-16.md` (Gate A, section 6).

## 1. Claim and scope

On the Debian 13 TEST VM, the full supporting-only acceptance path ran end to end for the first time: installer-provisioned records -> selected bootstrap admission -> publication -> READY -> auditd start + authenticated readiness -> audit chain continuation (owner-signed head pin) -> commissiond start + authenticated readiness -> steady loop -> operator controller-first stop -> confirmed containment and cleanup, exit 0. Failure behaviour was confirmed across runs 1-5 (each refusal contained, grant closed, no recovery).

NOT shown by this run:
- deadline expiry on a real host (covered only by the fixture-scoped Q7-R kernel-deadline SIGKILL);
- Option C systemd-stop on a real host;
- long-duration steady state (steady loop observed for about 13 s before the stop);
- hardware.

Caveats: VM only; approvals are synthetic (owner-signed test approvals); the records quarantine is test scaffolding, not a product feature. Issue #93 remains open until its acceptance criteria are reviewed.

## 2. Setup (orchestrator-observed; checked against retained files)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257 |
| Product build | af370f3 |
| Boot | `eaf1ab8a-81ad-4b7d-a11e-8c66fbd5d2e7` (reboot after run 5); `/data` tmpfs remounted |
| Installed files | `sha256:13a691c4...` (`installed-files.json`) |
| Admission | existing-history v4: `audit_mode` `existing-history`, `audit_sequence` 6, `audit_head` `a6ebb5b2...a373`; admission (policy) digest `sha256:fb785065...` |
| Approval payload | `sha256:61423685...` (synthetic, owner-signed); installed 23:18:49 |
| Preflight | 0 failures |

Owner decisions before the run:
- Continue the existing ledger via an existing-history v4 admission (the option recorded in run 5, section 7), using the owner tool v4 support (`README-v4-admission.md` in the owner bundle): the owner reads the head read-only and pins it in the signed admission; the tool never reads the ledger.
- Records re-provisioned after a full quarantine: 13 files moved, nothing deleted.
- The audit ledger was kept untouched (2285 B, 6 records, head sequence 6 = `bootstrap.stopping` of run 4).
- D4: controller-first SIGTERM as the stop method.

## 3. Timeline (T0 = `systemctl start --no-block`, about 23:18:51.5 VM local)

| T+ (s) | Event |
|---|---|
| 5.5 | S1: admission, deadline retained, grant `pair_grant_intent` |
| 17.0 | S2: overlay journal intent -> partial -> published; both overlay files present |
| 18.8 | S3: Reload; both helpers `loaded` (from `system.control`) |
| 20.75 | grant `pair_grant_opened` |
| 22.3 | S4: READY=1, controller active |
| 29.0 | S5: first heartbeat |
| 30.5 | grant `auditd_start_intent` |
| 39.75 | S6: auditd active (pid 4209) |
| 49.0 | grant `audit_intent_recorded`; ledger 2285 -> 3810 B (chain continued from sequence 7) |
| 52.75 | grant `commissiond_start_intent` |
| 62.75 | commissiond active (pid 4939) |
| 73.0 | S8: `commissiond_ready` (commissiond authenticated readiness) |
| 75.0 | S9: steady loop, both helpers active, heartbeats continuing (monitor labelled it EARLY vs tolerance) |
| 88.5 | monitor stop condition 6 trips on `/run/systemd/transient/session-31.scope`; controller-first SIGTERM sent |

Stop sequence (VM journal, `journal-window.txt`):
- 23:20:20.02 `azazel-activated.service: Sent signal SIGTERM to main process 2793 (az-activated) on client request`;
- 23:20:20.29 `azazel-commissiond.service` stopped, then `azazel-auditd.service` stopped (order: commissiond -> auditd);
- 23:20:20.4 - 23:20:23.4 overlay withdrawal with repeated daemon-reloads (reloads #1-#15 in the run, helpers back to masked);
- 23:20:23.79 controller message `az-activated supporting bootstrap stopped after confirmed containment`; `Result=success`, `status=0/SUCCESS`, invocation `e8fa93a0...`.

Controller `Duration` 1min 10.1 s; ledger final size 4962 B.

## 4. End state

- Overlay empty; overlay journal `phase: closed`, bound to boot `eaf1ab8a-...`, `owned_files: []`.
- Grant `phase: closed`, generation 1, close evidence `sha256:bfe9a876...`, `recovery_evidence_digest: null` (no recovery).
- Controller-used marker present in `/run/azazel-nexus-bootstrap/`.
- Helpers masked (`/etc/systemd/system/azazel-*.service -> /dev/null`) and inactive; controller inactive (dead), exit 0.
- Audit ledger: 13 records.
  - Run 4 (unchanged): 1 `grant_intent`, 2 `controller_ready_intent`, 3 `start_intent`, 4 `ready`, 5 `start_intent`, 6 `stopping`.
  - Run 6 (appended): 7 `grant_intent`, 8 `controller_ready_intent`, 9 `start_intent` (auditd), 10 `ready` (auditd), 11 `start_intent` (commissiond), 12 `ready` (commissiond), 13 `stopping`.

## 5. Verify output: FAIL lines are tool artifacts

The post-run verify reported several FAIL lines. Each is a tool or wording artifact, not a product defect:
- "was started" check: the check wording does not match the supporting-bootstrap message form;
- "stop order not shown": the journal does show commissiond then auditd (section 3);
- "prior-boot grant byte-identical": a fresh precondition has no prior-boot grant to compare;
- tree changes: the operator's own SSH session scopes (`session-30.scope` removed, `session-32.scope` added); `audit.sock` / `commission.sock` removal and the audit segment change are the helpers' own declared paths;
- monitor status FAIL: the false positive in section 6.

## 6. Monitor false positive

The monitor's stop condition 6 ("change outside approved locations") fired on `/run/systemd/transient/session-31.scope`, created by the operator's own SSH login during `observe`. The monitor sent the controller-first SIGTERM at about T+88.5 (owner decision D4). The stop was therefore operator-triggered, which is the designed controller-first stop path; the product behaviour observed afterwards (section 3, 4) is correct. The monitor's final line: controller inactive, helpers inactive, overlay empty, journal closed, grant closed.

## 7. Known tool follow-ups (not product changes)

- Monitor: ignore `/run/systemd/transient/session-*.scope` (operator logins) in the approved-locations check.
- Verify: fix the "was started" wording check; recognise the commissiond -> auditd stop order from the journal; drop the prior-boot grant check for fresh preconditions; classify operator SSH session scopes in the tree diff.
- Observability: consider allowlisting fixed, non-secret refusal labels from `bootstrap_audit` and `bootstrap_prestart` (carried over from run 5, section 6).
- Cross-boot renewal finding (docs/evidence/bootstrap-finding-reboot-rerun-2026-10-16.md): a node bootstraps once until an owner renewal path exists; each run here used owner-approved test quarantine instead.

## 8. Evidence retention

Raw outputs (VM journal window, run artifacts, post-run diagnostics, owner-tool output) are retained in the operator's scratch area; this record summarises them and does not embed them.
