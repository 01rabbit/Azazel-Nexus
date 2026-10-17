# Bootstrap factory qualification: Q4-R re-run, published-pair withdrawal (test VM, 2026-10-16)

Scope: Debian 13 ARM64 test VM, systemd 257.13; not hardware evidence. The production factory is unchanged.
Purpose: re-run Q4-R (see `bootstrap-qualification-q4r-2026-10-16.md`) against build 58dfde1, which fixes the defect that
run found (`is_inactive` refused on `masked-runtime`, ending in `BootstrapContainmentFailed`; Nexus#93).
Method: unchanged from the first run. The production `run_selected_bootstrap` runs in a transient unit with the controller's
sandbox; a `_PrototypeBootstrapManager` subclass publishes the pair and refuses at `confirm_controller_ready`,
`start_and_wait` and `is_ready`. The five declared in-process substitutions D1-D5 apply (D1 cgroup constant, D2 controller
identity, D3 controller-inspector stub, D4 manager class, D5 sd_notify refused). This is Q4-R (D1-D5), not real-controller
evidence. Raw outputs are retained in the operator's scratch area (harness.out, events.log, pid1-journal.txt,
journal-all.txt, smoke.out, before/after capture directories); they are not committed.

## Setup
- Snapshot revert, then boot_id `8c3dd0e1-89fd-4abc-8427-e1d3c304277f` (before/after `clock.txt`). Build 58dfde1 installed by
  Phase 2g; installed-files digest `sha256:525cda372417a3e12c3bb91f8b807370276b5839afebfe832cac6bdfd4827290`.
- Approval: a synthetic, owner-signed TEST approval, payload `sha256:353c32fa57bd31973fa0784971d8058d55d6388404b8c1490c866cdfe90aff2b`
  (the grant and checkpoint records carry this digest), granted 04:39:28Z, expires 05:24:28Z. It is **not** a real deployment approval.
- Owner records script: it was run twice by mistake. The second run was refused at every step (records already present,
  initialisers refused) except the approval request, which was regenerated against the first run's persisted selection
  (approval_id d6be95f4-...). This is observed fail-closed behaviour; no record was overwritten.

## Smoke (read-only rehearsal, 04:42:07Z)
`smoke.out`: cgroup-mount admission ok, overlay directories ok, identity ok, admission verify ok in 1.865 s, `RESULT outcome=smoke-ok`
(rc 0). The only tree difference between the before and after captures is the mtime of `/run/systemd/transient`; the harness
itself runs as a transient unit, so this is a harness artifact, not a product write.

## Observed (one run, started 04:42:17Z, process 41.5 s)
- Admission, deadline retention, grant `pair_grant_intent` (+9.4 s `open_pair-begin`).
- Publication (events.log), in order: journal `intent` → `azazel-auditd.service` file in `/run/systemd/system.control` → journal
  `partial` → `azazel-commissiond.service` file → journal `published`. Both files non-empty (2106 and 2299 bytes). `open_pair`
  took 28.1 s, with 12 publish checkpoints of about 2.32 s each (2.311-2.342 s).
- Then the start-closure inspector refused ("start closure root policy differs"; `RESULT outcome=unexpected
  detail=UnitOperationFailed(...)`, harness exit 10). Same cause as the first run: the root controller unit was `failed`
  (`Result=protocol`, `after/units.txt`), not `activating`, because the harness is not the controller (D3 scope). This is a
  harness artifact, **not** the designed Q4Stop point.
- Containment, now completing: `close_starts` truncated both files to 0 bytes (journal `closing`, grant `closing`); all 16
  `is_inactive` calls returned without error (first run: every one failed with `UnitOperationFailed`). This is the 58dfde1 fix
  working under a runtime mask.
- Withdrawal through the **published** `withdraw_pair` branch (first host exercise of that branch; the first run never reached
  it): journal `withdrawing`, files unlinked commissiond first, then auditd; FragmentPath back to the `/etc` masks; journal
  `closed`, `owned_files=[]`; grant `closed`. `withdraw_pair` took 3.56 s.
- Final state (`after/`): overlay directory empty; both units `LoadState=masked`, `UnitFileState=masked`, `ActiveState=inactive`,
  no job, FragmentPath `/etc/systemd/system/<unit>`; the seven mask-symlink stamps are unchanged from before; the grant record has
  phase `closed` with a close-evidence digest and `recovery_evidence_digest: null`; the journal has phase `closed`; the marker
  `controller-used` is present (consumed); never started (no helper cgroup, `InvocationID` empty, `MainPID=0`). The operator's
  `verify` run reported the close evidence equal to the recomputed digest with `grant_withdrawal=confirmed`.
- Reload lines: 15 "Reload requested" entries from the harness PID in the retained PID 1 journal, matching the roughly 15
  derived from the code. The `reload-count.txt` before/after files read 0 and 0 because the counter's grep pattern
  ("Reloading requested") did not match this journal's wording. The Reload count was therefore not measured by the harness's own counter.

## Verify
All checks passed except "no systemd jobs queued". The queued job was `apt-daily.service` (a Debian timer, unrelated to Azazel;
`systemctl list-jobs` showed job 18614 `apt-daily.service` start running; PID 1 journal shows "Starting apt-daily.service" at
04:42:55Z, during the run). Not a product finding. Manager state `degraded` both before and after (not changed by the run).

## Conclusion
The 58dfde1 fix (`is_inactive` uses `observe_inactive` under a runtime mask) is verified on this VM for the published branch:
after real publication and a refusal, containment confirmed inactivity, withdrew both files, restored the `/etc` masks and closed
the grant with confirmed withdrawal. The first run's failure mode (`BootstrapContainmentFailed`, grant `recovery_required`) did
not recur.

## Limits (not shown by this run)
- Test VM only; not hardware. Synthetic TEST approval; not a deployment approval.
- Reduced-fidelity harness with declared substitutions D1-D5. The real `BootstrapControllerInspector` against an `activating`
  controller is not exercised.
- The stop came from the harness artifact (failed controller unit), not the designed Q4Stop point.
- READY, helper start, heartbeat, operator stop and deadline expiry are still not reached.
- Builds after 58dfde1 (ca26568..b1a99d7) have not yet been run on the VM; this evidence applies to 58dfde1 only.
- Issue #93 remains open.
