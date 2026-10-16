# Factory switch re-review for a FIRST real start on the Debian 13 test VM (read-only desk review)

Reviewer: independent of the author of the prior evidence. Code basis: HEAD fb74ad9. Code is identical to c79291b for
runtime/ and src/ (git diff c79291b..HEAD touches only five evidence files). R = runtime/src/azazel_nexus_runtime,
S = src/azazel_nexus. Nothing was run; no VM, no network, no repo file edited except this one new file.
Scope of the question: switching the production factory `bootstrap_narrowing_manager_in_transaction`
(R/bootstrap_manager.py:70-94) from `BootstrapNarrowingManager` to the prototype path, for a first real start on the
TEST VM only. Not hardware, not deployment.

## 1. Verdict

**GO-with-conditions** for one attended, snapshot-protected first real start on the test VM. It is NO-GO again if
conditions C1-C6 (section 5) are not all met. The original NO-GO of `bootstrap-factory-switch-review-2026-10-16.md`
was right for its time (nothing past the refusal had real-manager evidence). Since then Q1, Q2, Q4-R (x3), Q5, Q6, Q7-R,
Q3/Q10 and the fixes they found (58dfde1 masked-runtime inactivity, checkpoint budgets, operator-stop Option C, journal
retirement) removed the cheap and the containment-class unknowns. What remains cannot be reduced further without a real
start (B1, B2, B3, R1, real READY, real helper start, real peer proof, real loaded-unit properties). Every remaining
failure before the first audit record is fail-closed and recoverable with a snapshot revert on a test VM, and the
containment code that handles it has real-host evidence for the unstarted published pair. The one step that is
irreversible on the real ledger (genesis) is behind auditd start and is already covered by the owner's decisions (Q6
counts as qualification; A2 genesis policy).

I do not recommend GO without conditions because:
- the only desk trace of the changed path (Q9 section 4) was written at 81d4530, before 13 code commits that changed the
  exact path (checkpoint removals, READY/start budgets, heartbeat, operator-stop Option C, journal retirement);
- the pre-READY time is a derived number that sits 2-7 s under a hard `TimeoutStartFailureMode=kill` cliff;
- the real loaded-unit/prerequisite/controller-ready inspectors have never run against a published pair (see Q4 row).

## 2. Per-Q table (Q1..Q10, as defined in bootstrap-factory-switch-review-2026-10-16.md section 3)

| Q | Status | Evidence | Exact residual gap |
|---|---|---|---|
| Q1 read-only observation set vs masked state | Covered (for the masked state) | bootstrap-qualification-q1-q2-2026-10-16.md | Predicted refusals observed. Controller properties matched except `ControlGroup`, but only for a `failed` unit; the `activating` (pre-ready) and `active` (ready) shapes were never read. Helper properties "cannot be compared until a publication loads them" (the note defers to Q4), and Q4-R never got that far (Q4 row). |
| Q2 overlay precedence over /etc mask | Covered | q1-q2 | Fixture names only, never started; no `masked-runtime` empty-stub case (that case was found later in Q4-R). |
| Q3 reboot persistence | Partially covered | bootstrap-qualification-q10-q3-2026-10-16.md, bootstrap-finding-reboot-rerun-2026-10-16.md | Covered: `/run` marker gone, enabled controller refuses at selection binding without side effects (2 reboots), `state/audit` persists empty, closed prior-boot journal retired. NOT covered: a stale `published`/`closing` journal with no files after a crash across a reboot (`_retire_prior_boot_journal` is reached only for `closed`; the other case still ends in manual review, untested on a host); cross-boot renewal does not exist (test scaffolding only). Several post-checks are "orchestrator-reported", not re-derivable. |
| Q4 real withdraw of a published pair | Partially covered (as Q4-R with D1-D5) | q4r, q4r2, q4r3 | Covered 3x: real publication (journal-before-files order), refusal, `close_starts`, published `withdraw_pair`, masks restored, grant closed, `masked-runtime` defect fixed and re-verified. NOT covered: all three runs stopped at the SAME harness artifact (section 4, item 7) inside the first `BootstrapStartClosureInspector`, i.e. before `BootstrapPrerequisiteInspector`, `BootstrapLoadedUnitInspector(load_first=True)` for either helper, the repeat closure/controller comparison, and `retained_check` ever ran against a real overlay-loaded pair. The pre-ready `BootstrapControllerInspector` was stubbed (D3). The closure walk also never reached the helper roots or the device/target/mount nodes. These are the most likely first-real-start refusal points. |
| Q5 StartUnit/JobRemoved/identity code | Partially covered | bootstrap-qualification-q5-2026-10-16.md | Real code on two static fixtures; product names/identity constants substituted in memory, so product-name binding is not covered. S4 (never-READY) was INCONCLUSIVE. Ran before f119576 (separate sync budgets, `START_SYNC_CEILING_SECONDS`), so the current bridge/ceiling code has not been run against a real manager. Stop path noted "completion unconfirmed" on an unmasked fixture. |
| Q6 peer proofs | Partially covered (fixture-scoped, 15/15 PASS) | bootstrap-qualification-q6-2026-10-16.md | Covered: `peer_credentials` equality with negative controls, 0711 chain, 2710 leaf/0660 socket, exact-byte cgroup string comparison via a mimic cgroup namespace, real clients, empty-ledger genesis accepted (tmpfs). NOT covered: B1 literal `/proc/<pid>/cgroup` of the product units, B2 retained manager identities (Id/ControlGroup/owner/InvocationID/profile digest) from the real manager, B3 product hardening (ProtectSystem, seccomp, MDWE, caps) on the helpers, R1 real leaf owner/mode (shadowed by tmpfs). Run history shows 2 failed attempts (harness) before PASS; the review text said 0710, code needs 2710 (doc drift, not a defect). |
| Q7 controller lifecycle / expiry containment | Partially covered | bootstrap-qualification-q7r-2026-10-16.md | Real `BootstrapSupervisor`, kernel deadline, notify/watchdog helpers, K/R/W/T endings, same-boot recovery x2 idempotent. NOT covered: packaged manager (S1 `FixtureManager`, so the recovery result is a property of the fixture's containment), real units, next-boot stale journal (S7), product `azazel-activated.service` (no `RuntimeMaxSec`; the SIGKILL `KillSignal` is fixture-only). Six harness FAIL lines were explained by unit garbage collection; "started exactly once" is supported only indirectly; follow-stop timing is a 0.25 s sampled bound. Fixture timing is not product timing. |
| Q8 timing budget | Partially covered | bootstrap-checkpoint-profile-2026-10-16.md, q4r2, q4r3, bootstrap-design-ready-budget-2026-10-16.md | Measured: one checkpoint 1.68-1.76 s (7 in `open_pair`, 12.08-12.24 s), admission verify 1.36 s, `withdraw_pair` 3.3-3.6 s, process 23.1 s to the harness stop. NOT measured: any end-to-end time to READY, the real inspector tail of `open_pair`, a helper start, a `retained_check`, `is_ready`, or a steady-loop iteration against `WatchdogSec=30s`. The profile's per-primitive model (1.0-1.7 s) leaves a 0.6-1.3 s residual "by inference" (import-routing/loaded-modules, unmeasurable out of context). |
| Q9 static side-effect check + Gate A trace | Partially covered (stale) | bootstrap-q9-prototype-static-check-2026-10-16.md, bootstrap-gate-a-trace-2026-10-16.md | Q9 PASS on forbidden members and the four write locations was done at 81d4530. Since then ca26568..c79291b changed the path (retire journal unlinks/creates under the journal dir; `controller_stop_observed`; heartbeat after READY; budgets; ~10 checkpoint removals). No re-run at HEAD, no independent reproduction, and the recommended source-level member-literal test does not exist (grep of tests/ finds no such guard). The Gate A trace doc covers only the OLD designed refusal. Q9's own caveat stands: the member allowlist is a call-site audit, not enforced at `BootstrapStopJobs._call`. |
| Q10 audit semantics | Partially covered | q10-q3, q6 | Covered: real VM `state/audit` is 0700 empty and unchanged across two reboots; boot-time controller writes no genesis; a fixture auditd accepts an empty ledger and `observe_head` returns (0, 64 zeros). NOT covered: genesis with the live product auditd on the real ledger, `verify_startup` first-live-head vs stopped-writer head against the real daemon, and whether starting auditd (before the first `_record`) writes anything into `state/audit`. |

Q11 (F1-F4/C2, owner inputs) is not an evidence item: the composition-status gate text still lists C2 as not done. A first
real start on the test VM IS the C2 evidence, so the owner must record that explicitly (section 7, D1).

## 3. Open-risk analysis for a first real start

### (1) READY timing: unmeasured end-to-end, thin margin

Derived from code at HEAD (the "12" is supported, as a lower bound):
- Full `_check()` equivalents before the first `notify_ready`: `_check` after `retain` (R/bootstrap.py `_admit_first` path)
  1, `_publication_checkpoint` 1, inside `open_pair` 7 (manager checkpoint before the journal retire
  R/bootstrap_manager.py:894, overlay `checkpoint()` before `journal_store.create` and two per unit
  R/bootstrap_overlay_files.py:280,283,294, manager checkpoint :914; matches the 7 measured), `check_publish()` after
  `open_pair` 1, first checkpoint inside `confirm_controller_ready` 1 = **11 full checks**. Plus three partial verifications
  before the first `_check`: `initial_admission.verify()` (~1.36 s), `_require_generation` (~0.4-0.8 s), `retain` (~1.4 s). That
  is ~12-13 full-check equivalents, so "12" is fair and slightly low.
- Cost: 11 x 1.69 s = 18.6 s, plus partials ~3.2-3.6 s = ~21.8-22.2 s. Add the first `_contain`, prestart (4 helper-state
  sessions), `narrow()` (5 MaskUnitFiles), process/wrapper start, and the part of `open_pair` after Reload that the harness
  never ran (loaded-unit x2, prerequisite x2, closure repeat, controller x2, ~8 `check_manager`).
- Two bounds: (a) measurement-anchored: Q4-R2 had `open_pair-begin` at +9.4 s at 2.32 s/checkpoint; scaling by the 27% drop gives
  ~6.9 s; + `open_pair` 12.1 s (to the closure refusal) + unmeasured remaining inspectors ~0.5-2 s + `check_publish` 1.7 + first READY
  checkpoint 1.7 = **~23-24.5 s**. (b) count-anchored upper bound ~28 s. Central estimate ~24 s against `TimeoutStartSec=30s`
  (packaging/systemd/azazel-activated.service, `TimeoutStartFailureMode=kill`): margin ~2-7 s (7-23%). The clock starts at
  the start job, not at `main()`. Unmeasured end-to-end; this is not a measured READY time and must not be quoted as one.
- After `READY=1`: `READY_TOTAL_SECONDS=25.0` (R/bootstrap_manager.py:65) from `confirm_controller_ready` entry; remaining
  3 checkpoints + inspector ~5-7 s, comfortably under 25 s and not subject to `TimeoutStartSec`. First heartbeat ~7-8 s after
  READY, well inside `WatchdogSec=30s`.
- Steady loop (R/bootstrap.py): one `_check` (1.7 s) + 2 x `is_ready` (each 2 `retained_check` + one proof, all unmeasured, a
  `retained_check` is one bus session of ~25-35 calls plus two local checks) + 10 s wait, before the next `_heartbeat`. My
  guess is 14-22 s vs `WatchdogSec=30s` with `WatchdogSignal=SIGKILL`. Unmeasured.
- Consequence of a miss: SIGKILL of the controller mid-publication or mid-READY. No genesis (auditd not started). Overlay
  files stay in `/run/systemd/system.control`, journal `published`, marker consumed, grant not closed. Recovery is a snapshot
  revert (same-boot recovery for this case is Q7-R fixture only). Cheap on a test VM, but one attempt gone. The packaged unit has no
  `RuntimeMaxSec`; only the kernel deadline of the approval bounds the run.

### (2) B1/B2: provable only by the first real start
B1 (literal `0::/system.slice/azazel-{auditd,commissiond}.service` and namespace) and B2 (retained `Id`, `ControlGroup`,
owner, `InvocationID`, profile digest) are checked AFTER the helper is already running (`_capture_audit_peer_binding`,
R/bootstrap_manager.py near :647, before the first `_record`). A divergence means auditd/commissiond is up and the
controller must contain a STARTED product helper (`stop_and_wait` of a live unit through the real manager, follow-stop,
withdraw). That path has only fixture evidence (Q5 stop on a fixture; Q7-R fixture manager). The audit ledger should still
be empty at that point, but whether auditd's own start touches `state/audit` is unobserved (Q6 used a tmpfs ledger).
B3 (real hardening on the helpers) is in the same class: a sandbox that denies something the daemon needs makes the helper
fail READY inside the 10 s job budget (Q5 S3: refusal can coexist with a start that completes at 14 s; the code then stops it).

### (3) Genesis is irreversible on the real ledger
The first record (`bootstrap.grant_intent` replay, R/bootstrap.py after `auditd_ready`) is the genesis; later failures leave
`grant_intent`, `controller_ready_intent`, `start_intent`/`ready` AUDITD permanently (Q9 finding 6). Recovery is snapshot revert
only. The owner already decided A2 genesis (composition-status JSON `owner_decisions_2026_10_15.audit_expectation`) and,
per the task statement, that the first real auditd start counts as qualification. I treat both as given, but D1 below asks
for them to be written into the Gate A record for this run. Nothing before `auditd_ready` writes the ledger by controller code.

### (4) Operator stop (Option C) never exercised on a host
Option C (R/bootstrap.py `_finish_transaction`, `_manager_stop_digest`, `controller_stop_observed` ce24cb8) is unit-tested only.
Real `systemctl stop azazel-activated.service` makes systemd stop commissiond then auditd first (Requires/BindsTo/After), so
the controller sees SIGTERM with auditd gone, `bootstrap.stopping` fails with `AuditUnavailable`, and the new proof must accept
it (stop job or `deactivating` read before `_contain`, containment confirmed, last audit head non-None). Untested: the ListJobs/
`deactivating` observation on 257.13, `TimeoutStopSec=10s` vs containment (~3.5 s `withdraw_pair` alone plus 8 sessions;
`TimeoutStopFailureMode=kill`), and shutdown ordering. Stale-evidence correction: the operator-stop design doc worries that
`BootstrapJobDrain` cancels ALL jobs including the controller's stop job; at HEAD `_rows` (R/bootstrap_job_drain.py:16-40)
selects only pair-unit jobs, so that side issue does not apply. Safe fallback that needs no code: a controller-first stop
(`systemctl kill --kill-whom=main -s SIGTERM azazel-activated.service`), the clean path unit-tested and matched by Q7-R scenario T.

### (5) Helper start bridge / peer binding never run against product units
Q5 used fixtures with substituted names; Q6 used synthetic identities. Never run on product units: `StartUnit` of the real
pair with real `TimeoutStartSec=30s` Type=notify helpers inside the 10 s async budget (`_JOB_TIMEOUT_SECONDS`,
R/bootstrap_entrypoint.py:25) and `START_SYNC_CEILING_SECONDS=25` (R/bootstrap_start_bridge.py:24); the AuditIdentity/
CommissionIdentity inspectors on real properties; commissiond `commission.inventory` against real netlink; `StartUnit "fail"`
with the real closure. The closure inspector is the only guard against extra jobs being pulled (Q9 U5).

### (6) Cross-boot renewal absent
A node bootstraps once per clean state. On the test VM this is acceptable by construction (snapshot revert). Boot-time
behaviour of the still-enabled controller is now observed (refuses at selection binding, no state, unit `failed`), and the
factory switch does not change that path: the refusal occurs before `run_selected_bootstrap`. One conditional hazard remains
(finding doc): with NO `selection.json` the ordinary `_run_once` path runs, which does not use this factory.

### (7) "start closure root policy differs": what it is and whether the real controller hits it
Source: R/bootstrap_start_closure.py:204-207. The closure walk starts from `_ROOTS` = (`azazel-activated.service`,
`azazel-auditd.service`, `azazel-commissiond.service`) (:19). For any root it requires `ActiveState in {inactive, activating,
active}` and `DefaultDependencies == False`; otherwise it raises "start closure root policy differs". The controller root
is visited first. In Q4-R the harness is a transient unit, not `azazel-activated.service`; the real unit was `failed`
(`Result=protocol` in q4r2) from an earlier refusal, so the state check failed. The three Q4-R runs and the second Q10 run all stop there
(4 of 4 harness runs that got that far), which is consistent with a single deterministic artifact, not a product defect.
The real controller will NOT hit it for the state test: while `main()` runs, Type=notify and no READY yet, the unit is
`activating` (publication inspection runs pre-READY) and `active` afterwards; both are allowed. `DefaultDependencies=no` is in
all three packaged units (packaging/systemd/azazel-{activated,auditd,commissiond}.service) and emitted by
R/hardening.py:603. Residual: the real run is the first time the helper roots (loaded after Reload, `inactive`) and the
device/target/mount nodes pass this walk, including the "infrastructure not active and idle" test (:208); a transient job on
a closure node (the VM had `apt-daily.service` run during Q4-R, which is a service and not in the closure) would refuse.

### Additional risks found in this review
- R-A: Q4-R never showed `retained_check` on a real pair; it is called at nearly every `check_start`/`is_ready`. A property-
  shape divergence in the loaded-unit policy would first appear there (Q1 flagged this class).
- R-B: Q9 (81d4530) and the design docs are stale vs HEAD; the independent Gate A reproduction the original review required
  has not been done for the changed path.
- R-C: several key facts are "orchestrator-reported" (installed digest in q4r3, Q10 post-checks); raw outputs are not in the repo.
- R-D: apt-daily overlapping the run produced the only failed verify check twice; harmless to the closure, but a job on a pair
  unit (not possible here) or an unrelated manager `Reload` race is not excluded. Run with timers stopped is a cheap mitigation.
- R-E: the existing unit test that looks like a factory pin (`test_production_narrowing_manager_remains_closed`,
  tests/unit/test_runtime_bootstrap_prototype_manager.py:242) constructs `BootstrapNarrowingManager` directly and does NOT
  pin the factory's return type; the factory is only exercised through a monkeypatched constructor
  (tests/unit/test_runtime_bootstrap_directory_integration.py:174). Nothing today would fail loudly if the factory flipped
  silently, and the integration test would silently stop intercepting.

## 4. What the factory switch would touch (do NOT implement here)

| File:line (HEAD) | Change |
|---|---|
| R/bootstrap_manager.py:87 | `BootstrapNarrowingManager(` becomes `_PrototypeBootstrapManager(`. Keywords at :88-92 are valid because the prototype class (:1341) defines no `__init__`. No flag, env var, argument or approval boolean. The name resolves at call time (class defined later in the module). |
| R/bootstrap_manager.py:71-80 | Factory docstring says "prepares only narrowing ... nor calls systemd ... enables starts": rewrite. |
| R/bootstrap_manager.py:848-849 | `_publish_and_inspect_pair` docstring "intentionally no production caller": rewrite. |
| R/bootstrap_manager.py:1341-1349 | Prototype class docstring "Not selected by the production factory ... remain necessary": rewrite. Owner decision whether to rename (D7). |
| R/bootstrap_overlay_files.py:259 and :4 | "remain unreachable until independent systemd gates" / "no production path opener": rewrite. |
| R/bootstrap_start.py:19 | "There is no production factory yet": rewrite. Also R/bootstrap_withdraw_files.py:4, R/bootstrap_withdrawal.py:1, R/bootstrap_cgroup.py:5 mention "no production opener"; check each for truth. |
| R/bootstrap_entrypoint.py:89 | Call site; unchanged. |
| `unmask` (R/bootstrap_manager.py base) | Must stay refusing. |

Tests needed (the existing tests pass unchanged except where noted):
1. NEW: factory returns exactly `_PrototypeBootstrapManager` via the real constructor path (type, not isinstance), `unmask` still refuses, and the base `BootstrapNarrowingManager` still refuses open_pair/start/is_ready (keep `test_production_narrowing_manager_remains_closed`; it then pins the base class, which is what remains true).
2. FIX: tests/unit/test_runtime_bootstrap_directory_integration.py:174 patches `module.BootstrapNarrowingManager`; retarget to `_PrototypeBootstrapManager` or the test stops intercepting.
3. NEW source-level guard: scan R/ for D-Bus member literals and pin against the Q9 table 1.2 (adds the regression guard Q9 recommended; Unmask/Enable only in the ordinary-path modules).
4. NEW: no env/CLI/config selects the manager (grep-style test that `os.environ`/argv are not consulted in the factory).
5. NEW fake-order test over the whole supervised run: a fresh `_check` immediately precedes publication create, Reload, `notify_ready`, StartUnit submission, peer-binding capture; failing the check at each position stops the next irreversible step (Option C of the budget design requires this after C1-C10 removals).
6. NEW end-to-end fake-bus supervisor test through the factory to steady loop and to each exit (refusal pre-READY, post-READY, helper loss, SIGTERM, manager-stop).
7. Re-run the full unit suite on the VM Python (the Q-series evidence covers specific builds only).

## 5. Conditions for the GO (all required)

- C1 (blocking): refresh Q9 at HEAD (both (a) members and (b) write locations, plus a Gate A trace of the changed factory and its exit paths) and have a second reviewer reproduce it. The Q9 doc at 81d4530 is not acceptable evidence for the current tree.
- C2: the switch is the single-token change above plus docstrings and the tests of section 4; no other source change in the same commit; the pre-switch tree is reachable (revert commit) and the VM has a fresh snapshot S0 taken after installing the switched build and BEFORE the owner issues selection/time/approval records.
- C3: test VM only; installed build digest recorded; ledger `state/audit` observed 0700 empty before; product pair masked/inactive before; `/data` tmpfs mounted (the Q10 attempt-1 refusal) and `azazel-activated.service` start explicitly via `systemctl start` after records exist (the boot-time run refuses by design).
- C4: the approval/kernel-deadline window is deliberately short (about 10 minutes) and the attended session has live `journalctl -f` and PID 1 journal capture; `apt-daily*` timers stopped for the run; no concurrent `daemon-reload`.
- C5: a written expected outcome and stop conditions (section 6) are signed off before the run; any deviation not on the list means stop the controller (controller-first SIGTERM) and treat the VM as dirty (snapshot revert), not retry in place.
- C6: the owner records D1-D4 (section 7) in the Gate A record.
Strongly recommended, not blocking: P1, a "Q4-R4" re-run with one more declared substitution that lets the harness pass the controller-root check (for example the root state test only), so the real loaded-unit, prerequisite and second-closure inspectors and `retained_check` run once against a real published pair with no helper start. It converts the most likely first-run refusal point (R-A) into a no-risk precursor.

## 6. Proposed Gate A for the first real start (written expected outcome)

Preconditions: C1-C4 met. S0 snapshot. `azazel-activated.service` is `failed` (boot-time refusal) with `Result=exit-code`; no marker; pair masked/inactive; `state/audit` empty; journal absent; no grant for this boot.
Start: `systemctl start azazel-activated.service` at T0 (owner present).

Expected timeline (PID 1 and journald timestamps; all times from T0, estimates, tolerance +/- 30%):

| Stage | Expected | Observable |
|---|---|---|
| S1 admission, deadline retained, kernel timer armed, grant `pair_grant_intent` | T0+6..9 s | `initial.json`, `checkpoint.json`, `grant-<boot>.json` |
| S2 journal `intent`, `azazel-auditd.service`, `partial`, `azazel-commissiond.service`, `published` in `/run/systemd/system.control` | T0+8..21 s | files 0644, ~2.1 and ~2.3 KB; journal phases |
| S3 `Reload` once; `LoadState=loaded`, FragmentPath `/run/systemd/system.control/...` for both helpers; start closure, prerequisites, loaded-unit inspectors pass | T0+19..22 s | first time this is seen |
| S4 `READY=1` | T0+23..28 s (hard limit 30 s) | controller `active`; grant `pair_grant_opened` |
| S5 first heartbeat | S4+7..9 s | `WATCHDOG=1` |
| S6 auditd `StartUnit`, `JobRemoved done`, identity captured, peer proof | S4+10..25 s | `Starting azazel-auditd` in PID 1 journal |
| S7 `verify_startup`, then audit genesis record `grant_intent`, then `controller_ready_intent`, `start_intent`, `ready` | S6+3..6 s | IRREVERSIBLE ledger records |
| S8 commissiond start, identity, `commission.inventory`, `bootstrap.ready` | S7+10..25 s | grant `commissiond_ready` |
| S9 steady loop, heartbeat every <= 25 s, both helpers ready | until stop | |

Run ends by the owner's chosen stop (D4). Expected end state for a controller-first stop: both helpers stopped (commissiond then auditd), `bootstrap.stopping` recorded, overlay files unlinked, journal `closed`, grant `closed`, pair `masked`, kernel timer released, controller exit 0, marker present, audit ledger with the records above. Expected end state for the Option C stop (`systemctl stop`): `stopping_record=absent-manager-stop`, no `bootstrap.stopping` record, grant `closed` with the manager-stop close-evidence digest, controller exit 0.

Stop conditions (act immediately with `systemctl kill --kill-whom=main -s SIGTERM azazel-activated.service`, then verify, then S0 revert if dirty):
1. Any stage later than its tolerance, or S4 not before T0+28 s (the controller will otherwise be SIGKILLed at 30 s; do not interfere, record, revert).
2. Any `Starting azazel-auditd` or `-commissiond` BEFORE S4 or by anyone but the controller.
3. Any unit other than the two pair units appearing in a job, or `Reload` count above the PID 1 journal expectation (about 15 for the full containment path, derived from code; the harness counter does not match the journal wording).
4. Any refusal text outside the expected list: `controller READY context expired or changed`, `start closure ... differs`, `bootstrap helper readiness lost`, `ApprovalRefused` of a record already known to be unrenewed are designed outcomes (contained); `BootstrapContainmentFailed`, `recovery_required` grant, `emergency narrowing unconfirmed` are FAIL.
5. Heartbeat gap above 20 s (alert), or any watchdog/timeout kill.
6. Any change outside the four approved locations (`/run/systemd/system.control`, `state/bootstrap`, `state/bootstrap-overlay`, `state/audit` by auditd, `/run/azazel-nexus-bootstrap`) in the before/after tree diff.
Designed non-success outcomes to be treated as informative, not failures of the plan: pre-READY refusal with containment and `closed` grant (property-shape divergence, R-A); timeout kill at 30 s (revert). Success criterion is therefore two-sided: a clean refusal that leaves the system contained counts as a valid result and is not retried in place.
Evidence to keep: PID 1 journal and journald with timestamps, before/after trees, grant/journal JSON, ledger head, `systemctl show` for the controller and both helpers (ControlGroup, MainPID, InvocationID), `/proc/<pid>/cgroup` of both helpers (B1/B2/R1), unit file digests.

## 7. Owner decisions required

- D1: Record that the first real start on the test VM is the C2/F1-F4 evidence for this purpose (the composition-status gate text still lists C2 as pending), that Q6 counts as qualification, A2 genesis stands, and that the irreversible genesis may be created on the test-VM ledger (revert by snapshot).
- D2: Accept that a miss of `TimeoutStartSec=30s` (estimated ~24 s, range 23-28 s, unmeasured) is an acceptable failed attempt, or require a measured READY time first. Do NOT raise `TimeoutStartSec` in this step; that is a unit policy change (hardening declaration plus the pinning test).
- D3: Approval/kernel-deadline window length for the run, and whether `apt-daily` timers are stopped.
- D4: Which stop ends run 1: controller-first SIGTERM (well understood), or `systemctl stop` (first host exercise of Option C). Recommendation: run 1 controller-first; Option C in a second snapshot-reverted run after run 1 is clean.
- D5: Whether `azazel-activated.service` stays enabled on the VM after the switch (boot-time behaviour observed safe: refuses at selection binding, no state).
- D6: Accept "bootstraps once per clean state" for the VM test (no cross-boot renewal work needed for this step); accept the finding that renewal remains a separate owner design (options A/B/C in the finding doc).
- D7: Whether the class stays named `_PrototypeBootstrapManager` once selected by production, or is renamed with the docstring change (naming of a production class as "prototype" will be misleading).
- D8: Identity of the second reviewer for C1 and sign-off of the written Gate A.
- D9: Whether P1 (Q4-R4) is required before the real start (recommended).

## 8. Limits of this review
Desk review of docs and code only. Raw VM outputs are not in the repo, so quantities cited from them are as the evidence files state; items marked "orchestrator-reported" there are not independently derivable. My timing is an estimate with the stated bounds. I did not re-trace every exit path of the changed factory; that is C1.
