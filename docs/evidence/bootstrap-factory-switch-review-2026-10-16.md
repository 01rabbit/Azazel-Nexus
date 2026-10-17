# Factory switch review (HEAD 36343fa), read-only

Paths: R = runtime/src/azazel_nexus_runtime, S = src/azazel_nexus. Line numbers are from the working tree as read. Nothing was run and no repo file was edited.

## Verdict: NO-GO for switching the factory now

Reasons, in order of weight:
1. Every step the prototype adds past `open_pair` has no real-system-manager evidence. The Debian 13 VM runs of 2026-10-16 (retrospective s6-8) stopped exactly at the refusal, which is before any publication, Reload with the pair published, StartUnit or peer socket exchange.
2. The project's own gate text requires "C2 product-unit native lifecycle + F1-F4 + native qualification" first (docs/evidence/bootstrap-composition-status-2026-10-15.json, C1 and production_factory_gate; docs/runtime-activation-remaining.md, "Finite source-prototype work boundary"). C2 is not done. The retrospective s8 says READY, helper start, heartbeat, operator stop and deadline expiry "remain unreachable until a separately reviewed production-factory decision". That makes a circular dependency, and the next step is to break it with contained qualifications that do not touch the factory (section 3).
3. The first real widening is irreversible in several ways (section 4): auditd writes a genesis ledger, the once-per-boot marker is consumed, and the one-shot deadline and grant records are consumed. A failure costs a VM snapshot revert, and there is no cross-boot retry.
4. The prototype's only containment evidence is for the unpublished baseline (run 6). Withdrawal of a published pair (journal, unlink, Reload, restore) has only synthetic evidence.

## 1. What the prototype path does on a real host

Entry: `_PrototypeBootstrapManager` (R/bootstrap_manager.py:1166-1197). Nothing selects it. The factory `bootstrap_narrowing_manager_in_transaction` (:60-83) constructs `BootstrapNarrowingManager` and sets `manager._publication_inputs`. The base refusals are `open_pair` :969-976, `unmask` :676-680, `start_and_wait` :1153-1157 and `is_ready` :1159-1163 (always False).

Note that the retrospective cites open_pair at 963-969, which has drifted. The functions are authoritative.

### 1a. `open_pair` -> `_publish_and_inspect_pair` (:689-913)
Filesystem (all via held fds, O_EXCL, O_NOFOLLOW):
- Rendered unit files `azazel-auditd.service` and `azazel-commissiond.service` are created, mode 0644, owner root, fsync'd. Source: `_create_candidate` R/bootstrap_overlay_files.py:207-246. Payload is `render_unit(PROFILES)` via `_fixed_payloads` :49-57. Order is `_publish_candidates_at` :249-307, one file at a time with a journal replace between them.
- Target directory is `/run/systemd/system.control` (volatile tmpfs). Source: R/bootstrap_directory_paths.py:18-26.
- Overlay journal: `/var/lib/azazel/state/bootstrap-overlay/overlay-journal.json` (persistent). Source: S/bootstrap_overlay_journal.py:33 and :28. Sequence is `journal_store.create` (:285, durable intent before the files), then `journal_store.replace` once per file (:299).
- No file is written to `/etc/systemd/system`. The installer masks (`/etc/systemd/system/azazel-*.service -> /dev/null`) are only stamp-checked (`_mask_paths` :108; `_check_published_pair_at` :348-372). `/etc/systemd/system.control` (higher priority) must be absent. The overlay in `/run/systemd/system.control` overrides the `/etc` masks through unit-path precedence, with no MaskUnitFiles or UnmaskUnitFiles call.

systemd (via `SystemdBusSession`):
- Preliminary: `confirm_empty_pair` (:229-273), meaning GetUnit, GetUnitFileState and cgroup checks.
- `BootstrapControllerInspector(phase="pre-ready")` (R/bootstrap_controller.py) reads properties of the controller unit.
- `Manager.Reload` (:776). This is a global daemon-reload and it loads the overlay units.
- `BootstrapStartClosureInspector` (`load_roots`=the pair) uses LoadUnit and GetAll over the dependency closure. `BootstrapPrerequisiteInspector` and `BootstrapLoadedUnitInspector(load_first=True)` use LoadUnit (R/bootstrap_stop.py:204-219) and property reads. `_observe_profile` reads Manager properties.
- Everything is repeated by `retained_check` (:829-910) before every later step.
- Retained state: `_controller_binding`, `_controller_grant`, `_publication_check`.
- Not called: UnmaskUnitFiles, EnableUnitFiles, StartTransientUnit, SetUnitProperties, drop-ins or `.d` directories. The only Unmask/Enable calls in the tree are the old `DbusUnitManager` (R/units.py:196-241) and the activation module, not this path. Confirm this by a test (section 3, Q9).

### 1b. `confirm_controller_ready` (:915-967), not prototype-specific but only reachable after open_pair
- `notify_ready` (sd_notify READY=1). It is sent once and never retried (:947).
- It polls `BootstrapControllerInspector(phase="ready")` over the bus until the controller is active.
- Real effect: systemd releases the helpers' After= ordering on the controller unit.

### 1c. `start_and_wait` (:1182-1187)
- AUDITD -> `_start_bound_audit` (:517-549). `check_start` is invoked at the checkpoints, then `_run_owned_start` (:498-515) runs `BootstrapStartJobs._start_with_checkpoint`.
- The bus sequence is in R/bootstrap_stop.py:`_job` (~:300-420). Steps: GetNameOwner pin; AddMatch (JobRemoved); `Subscribe`; LoadUnit if `load_first`; **`StartUnit(name, "fail")`** (:360); wait for JobRemoved "done"; state must be active; Unsubscribe and RemoveMatch.
- Then `_capture_audit_peer_binding` (:647-665) calls `BootstrapAuditIdentityInspector` (MainPID, cgroup, ExecMainStartTimestamp, owner, profile) twice around `check_start`.
- COMMISSIOND -> `_start_bound_commission` (:586-636), the same StartUnit path, then `BootstrapCommissionIdentityInspector`.
- StartUnit is submitted with mode "fail", so it fails on conflicting queued jobs. Because the helper units have Requires/BindsTo on the controller (`render_unit` R/hardening.py:612-615, 579+), the start pulls nothing new if the closure inspection holds. The closure inspector is the guard.

### 1d. Peer authentication sockets
- Audit: `/var/lib/azazel/run/audit/audit.sock` (R/bootstrap_audit_peer.py:25). A directory chain walk is checked for ownership and mode (0711 for azazel/run, 0710-class for leaf). `peer_credentials(connection)` must equal `(captured MainPID, azaudit uid, primary gid)` (:150-158). `/proc/<pid>/cgroup` must equal `0::<unit cgroup>`. Both the identity and the socket are revalidated before and after the exchange.
- Commission: `/var/lib/azazel/run/commission/commission.sock` (R/bootstrap_commission_peer.py:20, :60). It has the same structure and is used by `CommissionPeerBinding.proof`.
- Clients: R/bootstrap_audit_client.py:100 (AF_UNIX connect) and R/bootstrap_commission_client.py:33.
- `is_ready` (:1189-1197) brackets `_bound_helper_ready` (:638-645, `observe_head` or `observe_inventory`, an actual socket exchange each call) with two `_check_retained_publication` runs. The supervisor calls it on every loop iteration (R/bootstrap.py:575-579, :866-869), roughly every 10 s via `poll_seconds`.

### 1e. Audit ledger writes
- Performed by auditd (not the controller) as it appends. The controller drives them through the same authenticated client (`manager._bootstrap_audit_client()`, R/bootstrap_entrypoint.py:96).
- Sequence from R/bootstrap.py: `verify_startup` (:~800), then `bootstrap.grant_intent` (:803), `controller_ready_intent`, `start_intent` AUDITD, `ready` AUDITD, `start_intent` COMMISSIOND, `ready` COMMISSIOND, and finally `bootstrap.stopping` in `_finish_transaction` (:542-546).
- Location is `/var/lib/azazel/state/audit/` (persistent). The first record is the genesis, accepted only against an existing empty 0700 ledger (known_limitations in the composition-status JSON: a single use enforced only by the non-empty-ledger refusal).

### 1f. Other state the full path consumes (via the supervisor, partly already exercised)
- Grant store records (`grant-<boot>.json`) advanced through pair_grant_opened, auditd_start_intent, auditd_ready, audit_intent_recorded, commissiond_start_intent, commissiond_ready, then closing and closed. Source: R/bootstrap.py:743-860.
- Kernel deadline (CLOCK_BOOTTIME SIGEV_SIGNAL SIGKILL): R/_bootstrap_deadline.c:91-103. It is armed in `_check()` #1, released only by `release_after_stop` (R/bootstrap_kernel_deadline.py:65). It has no atexit and no GC disarm (C:31-33).
- Watchdog heartbeats (`notify_watchdog`) from `_heartbeat` (R/bootstrap.py:868-888) against WatchdogSec=30s.

## 2. What is qualified on a real system manager, and what is not

### Qualified on the Debian 13 VM (systemd 257.13)
- Admission, retention and containment up to the refusal, with the production manager: retrospective s8 (run 6) and docs/evidence/bootstrap-first-selected-attempt-2026-10-15.json. This covers MaskUnitFiles and GetUnitFileState, StopUnit on inactive units, ListJobs drain, Reload against the installer masks only (the unpublished baseline), BootstrapMaskedPairInspector and BootstrapStoppedPairInspector, cgroup mount admission, and the deadline arm and release (not the expiry).
- Kernel deadline expiry (SIGKILL, Result=signal) with release, for a transient fixture under the controller's sandbox subset: docs/evidence/bootstrap-deadline-sandbox-attempt2-2026-10-15.json. This is Type=exec fixtures, not the notify controller.
- Fixture mechanics only, transient `azazel-nexus-readyorder-*` units: Type=notify READY ordering, controller-death follow-stop with drained cgroups, a once-marker, queued-start containment, and audit-death follow-stop (bootstrap-ready-order-sandbox and bootstrap-lifecycle-containment evidence). The latter states "not product admission or deployment". The `run_marker_mount_view` case also exists in that file.

### Regular-file / fake-transport / synthetic evidence only
- Everything in 1a that happens after publication: file creation under the real `/run/systemd/system.control`, the Reload that picks it up, the loaded-unit, closure and prerequisite inspectors against the real overlay-loaded pair, and the property shapes they pin (docs/evidence/bootstrap-manager-publication-2026-10-15.json, "ordinary-file publication and fake-systemd reload/pair inspection").
- Withdrawal of a published pair: docs/evidence/bootstrap-manager-withdrawal-2026-10-15.json and bootstrap-restore-2026-10-15.json ("synthetic bus and ordinary files"; "remaining: installed systemd D-Bus runtime end-to-end verification").
- StartUnit of the real product units, JobRemoved handling, identity inspectors for the actual units, the audit and commission peer proof (bootstrap-audit-peer limits: "no Linux VM ... real service operation"; "identity snapshots are not full loaded-hardening, process closure ..."), `observe_head` and `observe_inventory` against real daemons, and the 10 s job timeout against the native start/stop budgets (bootstrap-native-timeouts limits).
- The prototype's own test files use fake bus, tmp_path and synthetic seams: tests/unit/test_runtime_bootstrap_prototype_{manager,publication,entrypoint}.py (14 tests). The Linux run of 89 tests (prototype-manager evidence) exercises the same fakes.
- The final-stage behaviour is unqualified: heartbeat to the 30 s watchdog under real ReadWritePaths, operator stop via SIGTERM (R/bootstrap_lifetime.py:84), deadline expiry on the real notify controller with live helpers, reboot, and suspend.

## 3. Prerequisite real-runtime qualifications (each can run on the VM without switching the factory)

Run in order, under the same discipline as Gate C and D (snapshot, written expected outcome, one run, stop on deviation). Items marked R are read-only. Items marked C are contained, meaning they use transient or fixture units, or the real units only inside a sandbox that cannot start them.

- Q1 (R): Dry-run `_publish_and_inspect_pair`'s observation set against the installer-masked state. Run every inspector (`BootstrapControllerInspector(pre-ready)`, `StartClosure`, `Prerequisite`, `LoadedUnit` with `load_first`) and compare the property sets to the loaded-units policy. The expected result is "pair masked, refusal at the expected inspector". This catches property-shape divergences with no side effect.
- Q2 (C): Overlay precedence on systemd 257.13. With transient names (not product), write a 0644 unit into `/run/systemd/system.control`, with an `/etc/systemd/system/<name> -> /dev/null` mask; Reload; LoadUnit; confirm `LoadState=loaded`, `FragmentPath=/run/systemd/system.control/...`, the mask unchanged, then unlink, Reload, LoadState=masked. The product design depends on this precedence, yet no real-manager evidence exists in the tree.
- Q3 (C): Reboot persistence of the overlay and journal. Perform Q2 with a fixture, reboot the VM (owner approval required, G1), and verify the `/run` overlay is gone and the `/etc` mask is intact while the journal in `/var/lib/azazel/state/bootstrap-overlay/` is recoverable. Also test the journal-with-no-files case on `overlay_journal` recovery: BootstrapWithdrawalFiles.bind with a published journal and absent files.
- Q4 (C): Real `withdraw_pair` of a published pair against a fixture-named pair on the real manager. This exercises the `BootstrapWithdrawalFiles` -> unlink -> Reload -> `BootstrapRestoreSequence` -> `_observe_withdrawal_fence` mixed states. Today this path is only synthetic, and it is the exact path that a failure after a real open will take (R/bootstrap_manager.py:978-1035, :1087-1147).
- Q5 (C): The real StartUnit/JobRemoved/identity code (`_run_owned_start`, `BootstrapStartJobs`, the two identity inspectors) against two transient fixture services with the same property subset as the product units (Type=notify, User, ReadWritePaths, BindsTo/After the controller fixture). Verify `StartUnit "fail"` against queued jobs, the 10 s observer against `TimeoutStartSec`, and that the cgroup/MainPID identity checks match.
- Q6 (C): The audit and commission peer proofs against a fixture daemon (a stub server that listens at a copy of the path chain in a private fixture root is not possible, since the paths are fixed; so use the actual installed `azazel-auditd` binary in a **sandboxed transient unit with `PrivateMounts`/overlayed state dirs**, not the product unit). The goal is `peer_credentials` equality, the 0711/0710 chain, `/proc/<pid>/cgroup` string, and namespaces. If this cannot be done without the fixed paths, record that as a blocking finding, because it then can only be qualified by the first real start.
- Q7 (C): Full notify controller lifecycle with `RuntimeMaxSec`, WatchdogSec=30s heartbeat from the real supervisor loop's cadence (poll 10 s, `_heartbeat`) with fixture helpers; expiry mid-run (SIGKILL of the controller) -> helpers follow-stopped, overlay left behind in `/run`, journal in published state. Then verify the next-start recovery (R/bootstrap.py:run, "existing transaction requires manual review") leaves the pair contained. This is the crash and expiry containment path that is missing.
- Q8 (C): Timing budget. Measure each synchronous checkpoint (`retained_check` runs 5-6 bus sessions and several inspectors, called at nearly every `check_start`) against the 10 s job budget (`_JOB_TIMEOUT_SECONDS`, R/bootstrap_entrypoint.py:20) and 30 s TimeoutStartSec before READY. Run 3 died on this very class of defect (retrospective s1 run 3: verify 43.7 s vs 30 s).
- Q9 (R/desk): Static check that the prototype path never calls Unmask/Enable/StartTransient/SetUnitProperties and never writes outside `/run/systemd/system.control`, `/var/lib/azazel/state/{bootstrap,bootstrap-overlay,audit}`, and `/run/azazel-nexus-bootstrap`. Pair it with a Gate A trace for the new path, reproduced by an independent reviewer (retrospective s4 Gate A), citing the classes selected by the changed factory.
- Q10 (R): Real-endpoint audit semantics: confirm `verify_startup`'s genesis rule with an empty ledger on the VM image (the first-install-genesis policy) and the reboot behaviour of `/var/lib/azazel/state/audit` and `/run/azazel-nexus-bootstrap/controller-used` (next boot has no marker -> the enabled controller can run again; see risk 4.2).
- Q11 (owner inputs): F1-F4 and C2 (product units installed under reviewed procedure). Phase 2g already placed installer masks, records and the approval for runs 5 and 6, so the remaining open items are the reviewer's independent trace and the written expected outcome.

Gate order: Q9 and Q1 first (zero side effects), then Q2, Q4, Q5, Q7, Q8, Q6, and Q3 last (needs a reboot authorization).

## 4. Risks if the factory is switched now

4.1 Persistent next-boot enable
- The installer already enables `azazel-activated.service` (WantedBy=multi-user.target; docs/debian-live-install.md:448-454) while masking the other units. The controller runs on every boot that lacks `/run/azazel-nexus-bootstrap/controller-used` (ConditionPathExists=!). With a selection record for the current `boot_id`, a next boot attempts the bootstrap again. After a switch, that path would open the pair on a boot that has not been explicitly attended.
- Mitigation exists in design: the selection and approval records are per-boot (`boot_id`) and expire, so a rebooted node should refuse at admission. That behaviour is untested across a reboot (G1) and "cross-boot renewal does not exist" (known_limitations).

4.2 Reboot persistence of the overlay
- Designed volatile: `/run/systemd/system.control` is tmpfs, so a reboot clears the pair files while the `/etc` masks remain. The journal at `/var/lib/azazel/state/bootstrap-overlay/overlay-journal.json` and the grant records persist. After a crash mid-run the next boot sees a journal saying "published" with no files. R/bootstrap.py:run takes the `existing is not None` branch, which contains and then requires manual review. This recovery has not been run for a published journal on a real host (Q3, Q4).
- Only individual file operations are fsync'd, not a power-loss test. The status JSON lists B16 as "implemented (file phase); reboot additional_approval".

4.3 Containment on crash
- In-process failure: `_finish_transaction` -> `_contain` -> `withdraw_pair`. This is the unqualified published-pair branch of withdraw_pair (:1000-1035), which depends on `BootstrapWithdrawalFiles.bind`, `resume_closure` and the loaded-unit fences with the overlay. A bug here repeats run 4's `BootstrapContainmentFailed` and leaves the helpers' overlay in `/run` with `recovery_required`. In that state helpers could still be running (stopped=False -> "grant-retained", R/bootstrap.py:~417-421) and `emergency_narrow` (masks) does not override a higher-priority `/run` overlay; masks in `/etc` do not win over `system.control`, which is exactly why the overlay must be unlinked and reloaded.
- Controller SIGKILL (deadline or watchdog): the fixture evidence says BindsTo/After follow-stop kills the helpers, with drained cgroups (lifecycle containment). The overlay files remain until reboot and no process is left to withdraw them. Next-start recovery (Q7) is unverified for the real units.
- Hard OOM, host power loss: no evidence.

4.4 Deadline expiry path
- The timer is one-shot, relative to CLOCK_BOOTTIME, SIGKILL, and "does not wake a suspended machine" (R/bootstrap_kernel_deadline.py docstring). Expiry on the notify controller with live helpers is unqualified (the sandbox ran Type=exec fixtures with a sandbox subset, and said so).
- `StartUnit` is invoked with `fail` mode and `TimeoutStartSec=30s` and TimeoutStartFailureMode=kill. The 10 s job observer can expire before the 30 s native start timeout (bootstrap-native-timeouts limits), which then produces "refusal" while the job may still take effect ("a submitted job may still take effect", R/bootstrap_start.py:1-5). `_contain` stops units, but timing was never measured against the native budget.
- Retrospective s3 item 4 lists "no explicit timing budget" as a process cause of earlier failures.

4.5 One-way state consumed by a first real run
- Audit genesis ledger (not erasable without breaking the chain; the single-use rule lives only in the non-empty-ledger check).
- Once-per-boot marker, deadline and grant records (create-only). A failed run can be repeated only by a VM snapshot revert.

4.6 Review-surface and rule risk
- The switch would be the first code path that gives the production controller the ability to widen the helper pair. The project rules (no new authority, no approval boolean or env bypass, no promotion of test keys or signatures, native fixture success is not deployment admission) leave only a reviewed code change as the legitimate route. A change made before Q1-Q9 would rest on the very kind of fake-versus-real divergence that retrospective s3 item 2 documents (RecordingManager marking the pair open before refusing).
- `_publish_and_inspect_pair`'s docstring (:689-697) says "There is intentionally no production caller while open_pair's remaining admission obligations are unmet." The `BootstrapStartJobs` docstring (R/bootstrap_start.py) says "There is no production factory yet", and the `_check_published_pair_at` and `_publish_candidates_at` docstrings say the same. Those text claims would all need updating, and the prototype class docstring (:1167-1175) says "Native system-manager qualification and a separately reviewed factory change remain necessary".

## 5. Decision for the owner

Verdict: NO-GO now. Do not authorize the factory change until the following are done and reviewed.
- The owner decides two things:
  1. Approve the qualification programme Q1-Q10 (above) as the precondition, in the stated order, as contained fixture or read-only runs. Q3 needs a reboot and the G1 authorization from the owner. Q6 may require a real first start if it cannot be done in a sandbox; the owner must decide whether a first real start of auditd (genesis, irreversible, snapshot-revert-only) counts as a qualification step or as the factory switch itself. This is the one decision I cannot make from the code, since the fixed socket paths make some peer-proof checks impossible with fixtures.
  2. State the policy for the next-boot controller (whether the enabled controller should stay enabled while the factory can open the pair), since the persistent enable is the only mechanism that gives the opened path a second boot to run.
- After Q1-Q9 pass: an independent desk trace in the Gate A format for the changed factory (opening path, all exit paths), reproduced by a second reviewer, then a single reviewed code change that selects the existing delegation (no flag, env var or approval boolean; `unmask` stays refusing; docstring updates; keep `test_production_narrowing_manager_remains_closed` in tests/unit/test_runtime_bootstrap_prototype_manager.py:242 flipped deliberately, not deleted), then Gate D with a snapshot.
- Not an owner question (decided): option-1 deadline, A2 genesis audit, B1 epoch/revocation (composition-status JSON, owner_decisions_2026_10_15).

Files cited: R/bootstrap_manager.py, R/bootstrap_overlay_files.py, R/bootstrap_directory_paths.py, R/bootstrap.py, R/bootstrap_entrypoint.py, R/bootstrap_stop.py, R/bootstrap_start.py, R/bootstrap_audit_peer.py, R/bootstrap_commission_peer.py, R/bootstrap_kernel_deadline.py, R/_bootstrap_deadline.c, S/bootstrap_overlay_journal.py, packaging/systemd/azazel-activated.service, docs/runtime-bootstrap-retrospective-2026-10-16.md, docs/runtime-activation-remaining.md, docs/evidence/bootstrap-composition-status-2026-10-15.json, docs/evidence/bootstrap-gate-a-trace-2026-10-16.md and the evidence JSON files named in section 2.
