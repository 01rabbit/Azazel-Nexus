# Selected bootstrap on the Debian 13 VM: retrospective and fail-proof procedure (2026-10-16)

Scope: Issue #93, test VM only (Debian 13 ARM64, systemd 257.13, CPython 3.13.5). Not hardware evidence.
Evidence: `docs/evidence/bootstrap-first-selected-attempt-2026-10-15.json`. Work on the VM is stopped by the owner's rule
("one more failure stops the work"); the temporary sudoers entry was removed after every run.

## 1. What happened

| Run | Build | Stop point | Cause | Safe? |
|---|---|---|---|---|
| 1 | 17d34e6 | cgroup mount admission (0.25 s) | `/proc/1/ns/cgroup` EACCES without capabilities; systemd 257 `memory.pressure` bind under `/sys/fs/cgroup` | yes: helpers masked/inactive, no deadline/audit/overlay |
| 2 | 669875c | installed-files measurement | CPython caches the executed wrapper path as a negative importer entry | yes |
| — | c943ca4 | (not started) found by pre-start replay | Cython/pyexpat spec-less modules in the loaded-module profile | n/a |
| 3 | e17ed16 | SIGKILL by `TimeoutStartSec=30s` | manifest re-validated per loaded module (verify 43.7 s, generation 11.7 s) | yes |
| 4 | 6c8edbf | `BootstrapContainmentFailed` after designed `open_pair` refusal | `_contain` always calls `withdraw_pair` for a non-closed grant; withdrawal requires an overlay journal that never exists when nothing was published | helpers masked/inactive, audit empty, no overlay; grant left `recovery_required` |

Fixed and committed locally (not pushed): 0ac892f, 669875c (owner-approved `CAP_DAC_READ_SEARCH` + `azazel-operator`), c943ca4, e17ed16, 6c8edbf.
Verified on the host: first admission end-to-end inside the real controller (deadline retained, grant intent recorded),
production `open_pair` refusal, helpers never started, audit ledger untouched.
Not verified: confirmed containment after the refusal; READY/helper start/heartbeat/stop/deadline expiry
(unreachable by design while the production manager refuses widening).

## 2. Root cause of run 4 (code-confirmed)

1. `BootstrapSupervisor.run` → `_supervise` creates the grant and advances `pair_grant_intent`; production
   `BootstrapNarrowingManager.open_pair` refuses (`bootstrap_manager.py:963-969`) before any overlay publication.
2. `_finish_transaction` advances to `closing` and runs `_contain` again (2nd daemon-reload in the journal).
3. `_contain` calls `manager.withdraw_pair` whenever the grant is a `GrantTransaction` not in `closed`
   (`bootstrap.py:408-417`).
4. `withdraw_pair` → `BootstrapWithdrawalFiles.bind` → `_bind_intent` → overlay journal `load()`
   (`bootstrap_withdrawal.py:55-58`) → `ApprovalRefused("bootstrap overlay journal unavailable")`
   (`bootstrap_overlay_journal.py:243-245`) → `UnitOperationFailed("bootstrap owned withdrawal unconfirmed")`.
5. `_contain` records `withdrawal` as a failure → `BootstrapContainmentFailed` (cause hidden by `from None`) →
   `_mark_recovery` writes `recovery_required`.

Consequence: with the production manager every selected run that creates a grant ends in
`BootstrapContainmentFailed`. Unit tests missed it because `RecordingManager` marks the pair open *before* refusing
and its `withdraw_pair` succeeds when nothing is open; no test drives the real `withdraw_pair` through `_contain`
without a journal.

## 3. Why the failures repeated (process causes)

1. **The expected end state was never traced through production code before a run.** The production manager's
   refusal was known at hand-off, yet runs were announced as able to reach READY/stop. Each run then discovered the
   next blocker on the host.
2. **Fakes diverged from the real components.** Unit tests used recording managers, synthetic mountinfo, a non-wrapper
   `__main__`, and macOS/CPython 3.10/3.12 module sets; none reproduced the real controller process.
3. **Host checks were added one stage at a time**, after each failure, instead of a complete pre-flight over every
   stage reachable without side effects.
4. **No explicit timing budget** was checked against `TimeoutStartSec`, the 10 s job budget and the watchdog.
5. **One-shot state** (controller-used marker, create-only records) made every attempt cost a snapshot revert.

## 4. Fail-proof procedure for the next attempt (proposal; nothing executed)

Gate A — design trace (desk, before any host action)
- Write the exact expected outcome for the build to be run, step by step from `run()` to process exit, citing the
  production classes actually selected by `bootstrap_entrypoint` (not prototypes or fakes). Include every exit path
  (refusal, containment, recovery). An independent reviewer must reproduce the same trace. If any step's behaviour
  on the host state is unknown, the gate fails.

Gate B — production-component integration test (macOS, offline)
- Run the real `BootstrapSupervisor` with the real `BootstrapNarrowingManager` and real stores against a fake system
  bus + temporary root that mirrors the host: installer masks as `/etc/systemd/system/<unit> -> /dev/null`, empty
  `system.control`, empty audit ledger, no overlay journal. Assert the Gate A outcome exactly (including
  "open_pair refused → containment confirmed → grant closed"). Required to pass before Gate C.

Gate C — host read-only rehearsal (sandboxed transient unit, controller-identical interpreter)
- Already built: wrapper `__main__`/importer-cache emulation, timed admission (`azn-admit-probe12`).
- Extend to every remaining read-only stage: containment inspectors on the installed masks, `withdraw_pair` bind
  preconditions, store readability, and a budget table (sum of all `_check()` calls before READY vs 30 s; any
  single check vs the 10 s job budget). Must create no files (find before/after) and leave no `.pyc`.

Gate D — run
- Snapshot first. State the Gate A outcome in writing. Run once. Any deviation from the written outcome = stop,
  record evidence, no retry in the same session.

## 5. Proposed fix for run 4 (not implemented; needs review and owner decision)
- In `_contain`, when the overlay journal is absent and the grant phase is pre-publication (`pair_grant_intent` /
  `closing` without any opened evidence), treat withdrawal as "never published" only after confirming the baseline
  masks and an empty pair (both already checked earlier in `_contain`), record that as explicit close evidence, and
  close the grant. Do not change the production `open_pair` refusal.
- Add the Gate B integration test for exactly this path; keep the underlying cause in `BootstrapContainmentFailed`.
- Reaching READY still requires a separately reviewed production-factory decision (out of scope of these fixes).

## 6. Gate status after the run-4 fix (2026-10-16, desk only; the VM was not touched)
- Fix: `BootstrapNarrowingManager.withdraw_pair` accepts a grant in prepared / pair_grant_intent / closing as
  "unpublished" only when the latest `close_starts()` fence is the unjournaled mask baseline and a fresh
  loaded-mask observation matches it (journal absent, no pair entry in the overlay, mask stamps unchanged). It
  removes nothing and grants nothing. Close evidence records `grant_withdrawal: "unpublished-baseline"`, a label only.
  The production `open_pair` refusal is unchanged.
- Gate A: an independent desk trace is in `docs/evidence/bootstrap-gate-a-trace-2026-10-16.md`. Expected outcome:
  `open_pair` refused → containment confirmed → grant `closed` → deadline released → exit 1, so the unit is `failed`.
  Open risks: total time against `TimeoutStartSec=30s` (estimated, not measured); loaded masked-stub FragmentPath
  and mask stamps after `MaskUnitFiles` (empirically fine in run 4's first `_contain`).
- Gate B: `tests/unit/test_runtime_bootstrap_unpublished_withdrawal.py` runs the real supervisor, manager, closure,
  withdrawal and journal store on a host-mirroring tree, with a fake bus and cgroup tree. It fails against the pre-fix
  behaviour (the journal-unavailable withdrawal) and passes with the fix.
- Gate C/D: not started. They need the owner to revert the VM snapshot (run-4 state: marker, recovery_required grant)
  and grant temporary sudo for the sandboxed rehearsal.

## 7. Run 5 (d93b7f2, 2026-10-16): stopped by an expired approval, an operator-procedure error
- Before the run: snapshot reverted; Phase 2g installed d93b7f2; records re-finalized and placed (installed-files
  sha256:1b639ef3…, admission sha256:d2ab65ef…); deployment, selection, generation and time initialized; approval
  (payload sha256:20ca1c47…, valid until 23:28:49Z) owner-signed, verified and placed. Gate C passed at about 23:08Z:
  admission about 2.4 s in total, no new files, no `.pyc`, helpers masked/inactive.
- The start was issued at 23:42:17Z, after the approval had expired, because the time spent waiting for the owner's go
  was not rechecked against the approval window. The controller refused at admission after about 1.4 s
  (`ApprovalRefused`, exit 1). State afterwards: only `controller-used` and `supervisor.lock` exist; no deadline record,
  no grant, an empty audit ledger, no overlay; helpers masked/inactive. The containment fix was not exercised.
- Prevention (procedure, Gate D): immediately before `systemctl start`, in the same command, read the approval
  `expires_at` and refuse to start unless at least 10 minutes remain. Ask for the owner's go before signing, not
  after, so that the signature window starts only when everything else is ready.
