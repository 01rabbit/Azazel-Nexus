# Design: READY / helper-start checkpoint budget (Azazel-Nexus, HEAD 58dfde1)

Paths: R = runtime/src/azazel_nexus_runtime, S = src/azazel_nexus. Read-only study; nothing measured here.
Timings (2.2 s per _check = files 0.2 + admission verify 1.8 + generation 0.4) are taken from the Q5/Q9 evidence, not re-measured.

## 1. What one "full re-verification" is

`BootstrapSupervisor._check()` (R/bootstrap.py:288-336) does, every call:
1. `_check_transaction()` (:291), then `self.refresh()` (:292) = `ProtectedBootstrapInputs.__call__` (R/bootstrap_inputs.py:~447-465) -> `_verified_observation` (:~408-436): `observe()` twice (each = observe_context x2 + load_bootstrap_deployment + load_administrator_time_window, :~381-395) and `_verify_observation` twice (:319-333, each 1-2 `load_bootstrap_approval`, S/bootstrap_store.py:190-220, which re-reads policy/payload/signature/trust twice and runs `trust.verify` signature check, S/bootstrap_approval.py:150). That is the "admission verify" (~1.8 s): up to 4 signature verifications plus >=4 context observations per _check.
2. `revalidate_deadline` (:307, S/bootstrap_deadline.py:92-110), `deadline_guard(current)` (:315, kernel guard).
3. `_require_generation` (:317, :~676) = `ProtectedBootstrapGenerationAdmission.__call__` (R/bootstrap_inputs.py:~575-625): dpkg snapshot x2, `measure_bootstrap_installed_files` x2, `load_bootstrap_generation` x2 + semantic admit (policy x3, capacity), profile x2, policy x2.
4. audit continuation / `_live_audit.observe()` (:320-328), elapsed clock check (:329-336), `_check_transaction()` (:338).

Wrappers: `_intent_checkpoint` (:588-610) = `_check()` + cancel + `_grant_store.load_optional` compare + elapsed. `_publication_checkpoint` (:580) = `_intent_checkpoint`. `_start_checkpoint` (:612-642) = `_check()` + store compare (+ `_ready(AUDITD)` for commissiond = live audit head read via manager.is_ready) + elapsed. So every checkpoint callback in the system costs one full _check (~2.2 s).

## 2. Count before controller READY (supervisor path R/bootstrap.py `_supervise` :688-775 with initial_admission)

| step | where | full _check |
|---|---|---|
| `_require_generation` in `_admit_first` | bootstrap.py:687 | 1 admit_generation only (~0.8 s, no refresh) |
| `initial_admission.retain` | :697 | 1 `_verified_observation` only (~1.8 s, no generation) |
| `_check()` after retain | :703 | 1 |
| publication: `_publication_checkpoint` | :~748 | 1 |
| `open_pair` -> `_publish_and_inspect_pair` checkpoint() at mgr:738, 750, 768, 844 | bootstrap_manager.py | 4 (each: guard + directories.check + check_publish -> `_publication_checkpoint`) |
| `_publish_verified_approval_at` check_publish: R/bootstrap_overlay_files.py:273, 279, loop x2 units (282, 293, 300) | | 8 (2 + 3 x 2 units) |
| supervisor `check_publish()` after open_pair + `_check()` after advance | bootstrap.py:~756-758 | 2 |
| Subtotal publication/pre-READY-handshake | | ~16 full _check (+2 partial) |
| READY handshake: `check_ready()` before | bootstrap.py:~776 | 1 |
| inside `confirm_controller_ready` (see below) | bootstrap_manager.py:934-986 | 5 minimum |
| `check_ready()` after + `_check()` | bootstrap.py:~780-782 | 2 |

Total to READY: ~24 full _check ~ 24 x 2.2 s ~ 53 s. This is a derived estimate, but it exceeds Controller `TimeoutStartSec=30s` (Type=notify: READY must arrive within it) even before the 10 s READY window matters. Needs a VM wall-clock confirmation of the publication phase (the evidence only measured per-checkpoint cost). If the retained admission deadline (`deadline_boottime_ns`, approval-defined) is shorter than ~60 s it also expires first. This is a second, larger problem than the 10 s window and any fix must address it (option B/C help, A alone does not).

### Inside `confirm_controller_ready` (R/bootstrap_manager.py:934-986)
`deadline = time.monotonic() + self._timeout` (:945, _timeout = 10.0 from R/bootstrap_entrypoint.py:25). `checkpoint()` (:947-958) checks `time.monotonic() >= deadline` (:949, :957) around `check_ready()` (:955) which is a full _check. Calls:
- :960 pre-notify (1), :964 post-notify (2), loop top :967 (3, immediately after #2 with no intervening step), :983 after successful inspect (4), :985 after loop (5, immediately after #4).
- Each NotReady retry adds 2 more (:978 and :967).
So minimum 5 x 2.2 = 11 s > 10 s: checkpoint #5 (or #4's post-check at :957) raises "controller READY context expired" even when the controller is already ready. The inspector gets `timeout_seconds=deadline - time.monotonic()` (:971), which also shrinks to ~2-4 s after three sync checks. This is Q5 S5 (11 s sync checkpoint > 10 s budget). Notification is sent exactly once at :962 before expiry, so the failure is after an irreversible step -> refuse + contain, never READY confirmed (`_controller_ready_confirmed` set only :987).

## 3. Count per helper start

Supervisor `_start_helper` (bootstrap.py:644-657): `check_start()` (:652) -> `_start_checkpoint` (1 _check) + `_heartbeat`; `manager.start_and_wait` (bootstrap_manager.py:1172/1201); `check_start()` after (:657) (1). => 2 supervisor-level _check.

Manager `_start_bound_audit` (:536-567) checkpoint() (:549-560) = `_check_retained_publication` + `check_start()` (1 _check) + `_check_retained_publication`. Calls to checkpoint: :562 (pre), bridge 3 phases (`_run_owned_start` :517-534 -> `_StartCheckpointBridge.run` R/bootstrap_start_bridge.py:56-77, `check_start()` at :72; phases before_observation/before_submission/after_completion, :14), :564 (post), `_capture_audit_peer_binding` (:660-685) check_start at :671 and :676 (2). => 7 checkpoints = 7 _check + 14 `retained_check` runs.

`retained_check` (mgr:848-921): each run = `local_check` x2 (guard, check_files, cgroup mount, loaded-policy load, controller identity) + one full owned-loop D-Bus observation (`_run_owned(observe)`, :~901, under `reader._bounded` 10 s: owner, profile x2, controller, start-closure x2, prerequisites x2, loaded unit inspectors x2) -> each is a whole-closure systemd walk, plausibly >=0.3-1 s each (not measured).

Per auditd start: 2 + 7 = 9 full _check (~20 s) + 14 retained_check observations. Commissiond (:605-650): checkpoint at :642, bridge x3, :644, :648 = 6 checkpoints + 2 supervisor = 8 _check, plus `_ready(AUDITD)` audit-head read in each, 12 retained_check.

Inside the single start job the bridge's 3 sync checkpoints share ONE deadline: `self._deadline` is fixed at the first `checkpoint(phase, deadline)` (bridge :34-35, passed from `BootstrapStopJobs._job`, deadline derived from `_bounded` R/bootstrap_stop.py:85-100, 10 s) and `_check_pending` (bridge :48-52) raises when `loop.time() >= deadline`. Each bridge pause costs 1 _check + 2 retained_check ~ >= 3-4 s, so 3 phases ~ 10-12 s > 10 s -> "bootstrap checkpoint expired or no longer pending". Q5 S3 shows the unit may still become active (14.21 s) after refusal, so the supervisor must (and does) contain; but the start fails deterministically on the VM.

## 4. Constraints (must hold in every option)
- Fresh evidence before each irreversible step: publication (create O_EXCL, Reload), READY notify, StartUnit submission, peer-binding capture.
- No cached success authority: no value may be accepted as "admitted" on the strength of an earlier success; no new bool/env/flag bypass; `check_*` callbacks still return None-or-raise.
- Budgets must remain bounded: absolute retained deadline (`_check` :329-336 elapsed < deadline_boottime_ns) and cancellation stay authoritative.

## 5. Options

### Option A - separate budgets (sync checkpoint time is not charged to the async transport budget)
Change: in `confirm_controller_ready`, drop the single 10 s `deadline` (:945) for the synchronous checkpoints. Keep a per-inspect async deadline (`timeout_seconds` for `BootstrapControllerInspector`, recomputed per `run_until_complete`, :971) and a separate total ceiling for the whole READY step, e.g. `min(READY_TOTAL_SECONDS, remaining of retained deadline, TimeoutStartSec - margin)` constant in bootstrap_entrypoint.py (not env/CLI). In bridge/`_job`, pause the job deadline while the loop is stopped for check_start (extend `_deadline` by the measured sync duration but never past the ceiling), or give each phase its own deadline (`checkpoint()` currently rejects a changed deadline, bridge :34-35; relax to "monotonically non-decreasing and <= ceiling").
- Pros: smallest diff; zero loss of evidence; checks still gate every step; fixes both 10 s hazards.
- Cons: does not reduce the ~24 + 9/8 _check count -> still ~53 s to READY vs TimeoutStartSec=30s, and ~20 s per helper start; moves the failure to the ceiling. Extends the window a submitted job can run between checks (acceptable: S3 already shows jobs continue; contain-on-failure unchanged).
- Risk: low-medium; a too-large ceiling weakens the bounded-sync guarantee documented in bridge docstring ("must obey its existing bounded contract").
- Tests: unit (R/tests, fake clock): 5 sync checkpoints of 2.2 s fake time inside confirm_controller_ready succeed; a checkpoint that exceeds the ceiling fails closed after the notify (assert notify called once, `_controller_ready_confirmed` False); bridge with 3 phases of 4 s passes, ceiling+1 s fails and `_observer._usable` False; async inspect still limited to its own 10 s; retained deadline expiry mid-check still raises.

### Option B - split `_check` into content-keyed immutable verification + fresh freshness items (per-process memo of the PURE signature step only)
Change: memoize only `trust.verify(...)` (S/bootstrap_approval.py:150) and the pure canonicalisation (:152-163) keyed by SHA-256 of `(trust bytes, policy bytes, payload, signature, operator, purpose)`; the time-window test (:164-166), `load_bootstrap_approval` byte re-reads and double-read stability compare (S/bootstrap_store.py:204-218), `observe()` context/clock/boot-id/closure measurements, package snapshots, installed files and generation measurement, policy/profile, deadline guard and kernel guard all still run on every `_check`. A hit still re-reads every protected file, so changed bytes => key miss => full verification; the cache holds no verdict about time, host state, or "admitted", only "these exact bytes verify under these exact trust bytes", a pure function. Also drop the second `_verify_observation` in `_verified_observation` only if the key proves identical bytes and time bounds are re-evaluated (keep the TOCTOU double-observe of context).
- Pros: attacks the dominant cost (1.8 s) if profiling shows crypto/verify dominates; every checkpoint stays full and independent; no budget changes needed to get e.g. 5 x ~0.9 s < 10 s.
- Cons: only helps if the 1.8 s is verification (must profile first: cProfile of `_verified_observation` on the VM; if time is in dpkg/context observation, B fails). Adds a cache = new security-review surface (reviewers may read it as cached success authority); key must include everything verify consumes, including `expected` context digest and `now`-independent fields; memo must be module-private, bounded, not shared across processes, never persisted.
- Risk: medium (security review burden, subtle key omissions). Doesn't cut the 24-checkpoint wall-clock unless gain is large (24 x ~1 s still ~24 s vs 30 s).
- Tests: property test that any 1-byte change in policy/payload/signature/trust/operator/context misses the memo and refuses; expired/not-yet-valid approval refused on a hit (time re-evaluated); memo not consulted across process (fresh interpreter); call-count test: second `_check` performs zero `trust.verify` calls but all reads/measurements (spy counts); mutation test: swap trust file between calls -> refusal; timing regression on VM (_check <= 1 s target).

### Option C - remove structurally redundant checkpoints (no caching)
Change (code deletions only, each justified by "no irreversible step and no await/IO between the two checks"):
- confirm_controller_ready: delete :964's neighbour so post-notify check (#2) and loop-top check (#3) are one (restructure to check at loop top only after notify; keep #1 pre-notify, one after inspect success, delete :985 duplicate of :983, drop duplicate on NotReady path :978 vs :967). 5 -> 3 minimum (pre-notify, post-notify/loop-top, post-ready), +1 per retry. Also drop supervisor `check_ready()` after (bootstrap.py:~780) vs inner :983/:985 and following `_check()`.
- helper start: drop outer :562 (immediately before bridge before_observation) and :564/:660-676 pairs adjacent to bridge after_completion; in `checkpoint()` (mgr:549-560 and :626-640) avoid two `_check_retained_publication` runs back-to-back across adjacent checkpoints (the trailing one of N and leading one of N+1): keep the leading only. Supervisor `_start_helper` :652/:657 vs manager checkpoints: keep one before submission (bridge before_submission) and one after completion.
- Target: pre-READY 24 -> ~12; per helper start 9 -> ~4.
- Pros: reduces work everywhere (also TimeoutStartSec); no new state; easiest to reason about security-wise per step.
- Cons: each deletion needs an explicit adjacency proof; wide diff over security-critical, heavily tested code (tests that count calls will break). Alone still ~12 x 2.2 = 26 s to READY (marginal vs 30 s) and 3 x 2.2 + extras ~ 7 s inside READY window (OK) but bridge 3 x (2.2 + retained) still ~10 s.
- Risk: medium-high (silent loss of a guard if an "adjacent" check actually covered a gap, e.g. `_ready(AUDITD)` audit liveness before commissiond).
- Tests: ordering tests asserting a fresh check immediately precedes: publication create, Reload, notify, StartUnit submission, peer-binding capture (fake manager recording event order vs check_* calls); negative tests: failing check at each remaining position stops the next irreversible step; call-count budget test (<= N _check before READY).

## 6. Recommendation
Do A + B-profile first, then C selectively; pick A as the committed fix with a mandatory profiling task for B.

Reasoning: A alone is the minimal, locally-reviewable change that removes the two deterministic failures (10 s READY window, shared bridge deadline) without touching what any checkpoint verifies, and its failure modes already fail closed + contain. But the numbers above show the 30 s TimeoutStartSec is the real cliff (~24 checkpoints before READY). So land in this order:
1. A (separate per-async-op budget plus one total ceiling tied to TimeoutStartSec margin and the retained deadline). Keep all checkpoints.
2. Profile `_check` on the VM (cProfile; no network). If verification (`trust.verify` x4) dominates, add B limited to the pure signature step; otherwise skip B.
3. C only for the unambiguous adjacency cases: confirm_controller_ready :964/:967 and :983/:985, supervisor outer duplicates around manager checkpoints, and the publication `checkpoint()` calls at mgr:738/750 that sit with no side effects between them; leave bridge phases and every pre-submission check intact. Measure to bring pre-READY under ~20 s.
4. If still over 30 s, raising `TimeoutStartSec` in the unit (a deployment constant, not a security property; the controller WatchdogSec=30s only starts after READY) is a legitimate lever but is a policy change for the owner to decide; flag it, don't bundle it.

No option adds an approval boolean, env/CLI input, or reuse of an earlier success as authority.
