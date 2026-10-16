# Q9 independent reproduction at HEAD (second reviewer, condition C1)

Scope: read-only desk review of the path that runs if `bootstrap_narrowing_manager_in_transaction` (runtime/src/azazel_nexus_runtime/bootstrap_manager.py:87) constructs `_PrototypeBootstrapManager` instead of `BootstrapNarrowingManager`. HEAD = 70f8ff6; the only change since b2f733f is the first reviewer's note itself (no code diff). Nothing was run or edited. R = runtime/src/azazel_nexus_runtime, S = src/azazel_nexus.

Order of work: inventories (section 1) were built from the sources before the first reviewer's note (bootstrap-q9-prototype-static-check-head-2026-10-16.md) was opened; section 2 compares.

`_PrototypeBootstrapManager` (R/bootstrap_manager.py:1341-1371) overrides only `open_pair`, `start_and_wait`, `is_ready`. `unmask` (mgr:785) still raises. No `__init__` override.

## 1. Independent inventories

### 1.1 (a) D-Bus members that can be sent

Emission points: `BootstrapStopJobs._call` (R/bootstrap_stop.py:131, member unchecked: safety is by literals at call sites, not an allowlist) and `SystemdBusSession._exchange` (R/systemd_bus.py:316-360; has an allowlist: Manager GetUnitFileState, GetUnit, MaskUnitFiles, UnmaskUnitFiles, EnableUnitFiles; Properties.Get with fixed shapes). No other `.call(` / `Message(` on the path (core_reserve_probe.py is not imported by anything).

| Member | Call sites | Unit names it can carry |
|---|---|---|
| bus daemon: Hello (implicit), GetNameOwner, GetConnectionUnixProcessID, GetConnectionUnixUser | stop.py:_owner; bootstrap_manager_identity.py:32-43 via systemd_bus.py:273 on every connect | none (owner is "org.freedesktop.systemd1") |
| bus daemon: AddMatch, RemoveMatch | stop.py:388, 448 | none (fixed JobRemoved rule) |
| Subscribe, Unsubscribe | stop.py:401, cleanup tuple | none |
| StartUnit, StopUnit (mode "fail") | stop.py:408-410 only | pair only (UnitKey in `_PAIR`, name from `UNIT_NAMES`; stop.py `_job`). Start only via `_run_owned_start` mgr:607 after READY confirmed |
| LoadUnit | stop.py:219 (`_load_pair_unit`, exact pair names, pinned owner); reached from loaded.py:215, start_closure.py:176 (only `load_roots` = pair), stop.py:observe_state | pair only |
| CancelJob | job_drain.py:103 | ids from ListJobs rows filtered to the two pair units (`_rows`) |
| MaskUnitFiles([unit],False,False) | units.py:232 -> systemd_bus.py:158 | pair via mgr:213; all 7 `UNIT_NAMES`/`CORE_UNITS` via `narrow()` (activated.py:461-475) and `emergency_narrow`; `_known_unit` + `_UNITS` allowlist |
| Reload | mgr:941 (publication), mgr:1283 (withdrawal fence), close.py:47, restore.py:59 | none (manager-wide) |
| GetUnitFileState | stop.py:190, systemd_bus.py:92/111 (via units.py `state`, mgr `is_masked`) | pair (7 via narrow) |
| GetUnit, Properties.Get(ActiveState), Properties.GetAll | many inspectors | fixed constants: pair, controller (`azazel-activated.service`: mgr:436/438, controller/audit/commission identity), 7 table units (systemd_bus). Graph-derived: start_closure.py:101,177 (names from Requires/Wants/BindsTo/activation properties, `_name()` restricts to the 3 roots or .target/.mount/.slice/.device; <=64 nodes, <=1024 edges); prerequisites.py:123 (names from the protected loaded policy). Read-only; never Load/Start/Stop on these |
| Manager.GetAll (Version, UnitPath), Properties.Get on Manager | masked.py:91, systemd_bus.py:185 | none |
| ListJobs | job_drain.py:91; mgr:410 | none |
| ListUnitsByPatterns(["*.device"]) | start_closure.py:69 | pattern literal |
| Signal JobRemoved (received) | stop.py `receive` | filtered to owner and job unit name |

Forbidden members (UnmaskUnitFiles, EnableUnitFiles, DisableUnitFiles, StartTransientUnit, SetUnitProperties, LinkUnitFiles, PresetUnitFiles, RestartUnit, TryRestart*, ReloadOrRestartUnit, KillUnit, ResetFailedUnit, Freeze/Thaw): none has a call site on the path. Unmask/Enable exist only in systemd_bus.py (allowlist/implementation), units.py:238-241 `unmask_and_enable`, and the ordinary activation path (activated.py `_run_once`/`ManagedUnitController`), which `main` reaches only when no selection exists (activated.py:521-530 returns first). Caveat: this is a call-site audit; `_call` would forward any member, and no test pins the member set.

Member-name set check (git grep of literals in runtime/src and src at 81d4530 vs HEAD): identical.

Methods with no non-test caller: `stop_closed_pair` (mgr:289), `drain_pending_jobs`, `inspect_masked_pair`, `inspect_loaded` (grep over runtime, src, tools, tests; only tests call them).

Non-D-Bus effects: AF_UNIX send to audit.sock and commission.sock (audit append makes auditd write the ledger); sd_notify sendto READY=1 / WATCHDOG=1 (systemd_notify.py).

### 1.2 (b) Filesystem write calls on the path

Directory fds are opened read-only (O_DIRECTORY, O_NOFOLLOW); no mkdir/symlink/link/rename-by-path/chmod-by-path/rmdir on the path.

| Target | Calls | Where |
|---|---|---|
| state/bootstrap/supervisor.lock | open O_CREAT, flock; never unlinked | S/bootstrap_lock.py:72,77 |
| /run/azazel-nexus-bootstrap/controller-used | open O_CREAT\|O_EXCL, fsync x2; never unlinked | S/bootstrap_controller_once.py:61-65 |
| state/bootstrap deadline: transaction.pending, initial.json, checkpoint.json, checkpoint.next | O_EXCL create+write+fsync, os.replace(next->checkpoint), unlink pending, dir fsync | S/bootstrap_deadline_store.py:81-104,116-158; once at retain, once per supervisor `_check()` |
| state/bootstrap grant-<boot>.json (+ .pending/.next) | O_EXCL create, fchmod, write, fsync, os.replace, unlink pending | S/bootstrap_grant_store.py:58-73,201-265; `create` bs:850, each `_advance_grant` |
| state/bootstrap-overlay/overlay-journal.json | create (S/bootstrap_overlay_journal.py:297), replace via temp + os.replace (:343-374), failed-temp unlink (:410), remove = unlink (:427,:430) | create/replace: publication, close, withdraw, restore finalize; replace(reboot-reset)+remove: `retire_prior_boot` (R/bootstrap_withdrawal.py:154,159) |
| /run/systemd/system.control/{azazel-auditd,azazel-commissiond}.service | O_EXCL create 0644 + write + fsync (R/bootstrap_overlay_files.py:212-231); close: O_RDWR open, ftruncate(0), fsync (:420,503-509); withdraw: unlink + fsync (R/bootstrap_withdraw_files.py:118-119) | pair names only, journal-owned inode |
| /etc/systemd/system, higher-priority, transient, generator-early | fds only; read/stat/readlink | no write |
| state/audit | O_RDONLY | read-only |

Not reachable: clock/deployment/selection/generation stores' writers (CLI/provisioning only; the controller uses `load_*`), AuditLedger.append, runtime_paths audit_sink, transport/serve unlinks, core_reserve_probe writes, hil_preflight write_text.
Host side effects of messages: Reload and MaskUnitFiles (persistent masks under /etc/systemd/system) are performed by systemd, not by controller file calls.

### 1.3 (c) BootstrapSupervisor.run() ordered irreversible steps and the check before each

Full check = `_check()` (bs:306: guard, fresh inputs + D1 advance, kernel timer, generation re-admission, audit head, clock), as used inside `_intent_checkpoint`/`_start_checkpoint`.

| Step | Line | Immediately preceding check |
|---|---|---|
| lock, controller-used marker | S files | none exists yet (guard only) |
| first `_contain()` (mask x7 via narrow earlier, close, stop, etc.) | bs:1051 | narrowing direction, no check required |
| retain initial deadline | bs:805 | verify, generation, prestart, `_check_transaction`, `_cancelled` |
| kernel timer armed | bs:333 inside `_check()` bs:811 | itself |
| grant create | bs:850 | `_check()` bs:811, `_cancelled` bs:843, `_transaction_matches` |
| grant pair_grant_intent | bs:854 | none besides create (durable record only) |
| retire prior-boot journal (J2 reset + J7 unlink; only if other-boot journal) | mgr:895 | `checkpoint()` mgr:894 (full, via bs:858) then read-only checks inside withdrawal.py:122-148 |
| overlay journal create | of:281 | `checkpoint()` of:280 |
| pair file create x2 | of:287 | `checkpoint()` of:283 each iteration |
| journal replace after each file | of:295 | `checkpoint()` of:294 |
| Reload | mgr:941 | `checkpoint()` mgr:914, then a bounded read-only async session (check_manager, controller inspector, check_manager) with no `_check()` |
| pair_grant_opened | bs:869 | `check_publish()` bs:867 |
| READY=1 | mgr:1114 | `checkpoint()` mgr:1112 (`check_ready` = full `_intent_checkpoint`) |
| first WATCHDOG=1 | bs:897 | `check_ready()` bs:892 |
| auditd_start_intent | bs:903 | `_check()` bs:898 |
| StartUnit auditd | stop.py:408 | bridge `check_start` at `before_submission` (retained_check + `_start_checkpoint` full check + retained_check) + owner pin |
| auditd_ready | bs:917 | final `check_start()` bs:762, `_ready`, `verify_startup` |
| ledger appends: grant_intent bs:922, controller_ready_intent bs:937, start_intent bs:940, ready bs:943 | | only `_advance_grant` (bs:933), head `observe()` and per-append peer proof; no `_check()` between bs:937, 940, 943 |
| commissiond start_intent record bs:950, intent bs:955 | | `_check()` bs:947 / bs:952 / bs:958 |
| StartUnit commissiond | bs:962 | `check_start` chain as for auditd |
| commissiond_ready, ready record | bs:965-966 | `_check()` bs:963, `_ready` bs:964 |
| steady loop WATCHDOG | bs:978 | `_check()`, `_ready`, elapsed checks |

Exit paths (run() bs:1006-1070): (i) lock/store open failure: no containment, nothing created. (ii) load_optional raises: `_contain()` (retry once), raise. (iii) existing grant for this boot: `_contain()`, `recovery_required` unless closed, raise "manual review". (iv) initial contain fails twice: raise, no grant. (v) `_supervise` raises or returns: `_finish_transaction`: grant -> `closing`, `bootstrap.stopping` if live audit, `_contain()` (close_starts, mask, stop reverse, is_inactive, confirm_empty, withdraw_pair, mask, is_inactive/is_masked, confirm_empty), then grant `closed`; journal `closed` (file persists), pair files removed; guard released; normal return exit 0 (`recorded` or proven `absent-manager-stop`), exception exit 1. (vi) `_contain` failure: `emergency_narrow` (mask x7), grant `recovery_required`, journal at whatever phase reached, exit 1. (vii) SIGKILL (deadline timer, watchdog, start timeout): no cleanup; grant/journal at last phase, files may remain; marker stays so next boot needs manual review. Terminal state for any exit that reaches `_finish_transaction` successfully: grant closed, journal closed, no pair file.

## 2. Comparison with the first reviewer's note

| Item | Result |
|---|---|
| No member added/removed since 81d4530 | Agree. Verified independently by git grep of member literals at both commits (identical sets); `git diff 81d4530 HEAD` adds only the new call sites below. |
| New call sites ListJobs mgr:410, GetUnit mgr:436, Get mgr:438 | Agree (lines exact). Fixed controller unit; all errors return False. |
| observe_inactive stop.py:246-293 newly used by `is_inactive` when a closed observation exists | Agree (mgr:480-502); members are GetNameOwner, GetUnit, GetUnitFileState, GetUnit, Properties.Get. |
| Journal remove/replace newly reachable via `retire_prior_boot` | Agree. mgr:895 -> withdrawal.py:154 (replace, reboot-reset) and :159 (remove); inside state/bootstrap-overlay. I additionally traced why the stale `published` case fails earlier (close_starts truncation needs the owned inode; /run is empty after reboot), so retirement is exercised in practice for a `closed` prior journal, matching their O1. |
| CORE_UNITS = 7 | Agree (checked by import: 7, equal to the `UNIT_NAMES` values). |
| `stop_closed_pair` no non-test caller | Agree (also `drain_pending_jobs`, `inspect_masked_pair`, `inspect_loaded`). |
| T1 deadline guard not released when `_finish_transaction` raises | Agree (bs:1061-1069). Direction is fail-closed: timer stays armed, controller SIGKILLed at the original deadline even if containment was confirmed but the close record failed. Not a widening risk. |
| O4 ledger appends bs:922-943 with no check between | Agree, with precision: bs:922 and bs:937 are separated by `observe()` and `_advance_grant` (bs:933); bs:937, 940, 943 are strictly consecutive. Unchanged from 81d4530 in order. Appends are not on the rereview's list of steps requiring an immediate full check, so not a regression. |
| Forbidden members absent; arbitrary-unit operations absent | Agree, same conclusion, same table of name sources (pair, controller, 7-table, graph/policy read-only names). |
| Write inventory | Agree on the set of locations and calls; no write found that they missed; no write they list that I could not find. |
| Gate A steps and line numbers (bs:850, 854, 863, 869, 888, 897, 903, 907, 917, 922-943, 950, 955, 962-966; mgr:894, 895, 914, 941, 1112, 1114; of:280, 283, 294) | Agree; all spot-checked lines match. |

Differences / precisions (none changes a verdict):
1. They missed (frequency, minor): their table says Reload at mgr:1283 is "called twice per withdrawal". `_observe_withdrawal_fence` is the `check_contained` callback passed to `_withdraw_candidates_at`, whose `stable()` runs it about nine times (start, before replace, three per owned unit, final), plus one before and one after withdrawal, plus the restore Reload (restore.py:59): roughly a dozen Reloads during a withdrawal. Each runs in a closed/masked state between owned-file mutations (so it narrows or confirms, not widens), but the rate matters for the 10 s stop budget (their X14) which is host-unknown anyway.
2. Precision on N1: "every widening step has a full check as its immediate predecessor" is literal for all steps except Reload, where `checkpoint()` mgr:914 is followed by a bounded read-only async session before mgr:941 (they list this in the "between" column but N1 overstates). This cannot be tightened inside the loop (synchronous admission must not run in asyncio, mgr:914 comment). Same as 81d4530; the file set is fenced by `check_manager`/`check_files` in the session.
3. I missed / they have more: their phase table (2.3) with per-phase member sets, JobRemoved filtering, and the ReadWritePaths observation (O3) are more detailed than my inventory; I did not verify the unit-file ReadWritePaths or the host-unknown list (U1-U12) and take them as stated. I also did not recompute the exit table X1-X15 row by row; spot-checked X1, X8, X10 against bs:1006-1070 and activated.py:520-529 only.
4. Disagreements with evidence: none on member names, write locations, step order or terminal states.

## 3. Verdict

C1 reproduced (with the minor corrections in section 2, items 1 and 2). At the current tree the switched path sends no forbidden member, names only the fixed pair, the fixed 7-name table, the controller unit, or read-only graph/policy-derived names, writes only to the permitted locations, and every widening step has a full supervisor check before it (Reload and the ledger appends carrying the caveats above). Nothing found blocks the factory switch on C1.

Residuals that stay open (non-blocking, as in the first note): no source-level test pins the member set (the allowlist is only call-site discipline at `BootstrapStopJobs._call`); T1; O4; host-unknown timing (watchdog margin, stop budget, cross-boot behaviour beyond Q3/Q10).
