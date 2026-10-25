# Overlay journal lifecycle: design (read-only study, HEAD 58dfde1)

*Status 2026-10-25: Option 2, including reboot-reset, is implemented (owner decision on Nexus#324). §8 records what was built and where it differs from §5. Sections 1-7 are the original study and are left as written.*

Notation: `OJ` = src/azazel_nexus/bootstrap_overlay_journal.py, `R` = runtime/src/azazel_nexus_runtime/, `BS` = R/bootstrap.py, `MG` = R/bootstrap_manager.py. All behaviour below is from static reading; nothing was executed. Items marked [infer] are chains I traced by hand and the tests below must pin them.

## 1. Confirmed lifecycle

Phases (OJ:529-545, validator for phase vs owned_files OJ:~560-566): intent -> partial -> published -> closing -> withdrawing -> closed. Transitions in `advance_overlay` (OJ:~575-615): create-file (intent/partial -> partial/published), close-starts (intent|partial|published -> closing), begin-withdrawal (closing -> withdrawing), withdraw (withdrawing -> closed, needs `OverlayStopEvidence`, all booleans True, OJ:~490-505). `closed` carries no owned_files.

Writers:
- create (O_EXCL, `_WRITE_FLAGS` OJ:32, open at OJ:297; dir fsync after read-back): only caller R/bootstrap_overlay_files.py:280 (`_publish_candidates_at`, from `_publish_verified_approval_at` <- MG:754 in `_publish_and_inspect_pair`). Second call on an existing name -> FileExistsError -> `OSError` branch, `created` False -> `ApprovalRefused("... create refused")` (OJ:~322-326).
- replace (temp + os.replace + dir fsync, OJ:330-412): create-file R/bootstrap_overlay_files.py:294; close-starts R/bootstrap_overlay_files.py:476 (`_close_candidates_at` 430-520); begin-withdrawal R/bootstrap_withdraw_files.py:107; re-affirm at :103 and bootstrap_overlay_files.py:482; withdraw -> closed R/bootstrap_restore_files.py:60-71 (`finalize`, comment at :67-68 "Never delete the journal here").
- remove (OJ:414, unlink at OJ:427, dir fsync after, durability-uncertain mapping): grep over src/ and runtime/ shows NO caller. Only tests call it (tests/unit/test_bootstrap_overlay_journal.py:437,439,798,821). Header of R/bootstrap_restore_files.py:3-6 says "No production opener, removal of journals". `advance_overlay` comment OJ:~605 says "Journal removal is a separate fsynced step" - that step does not exist. So the claim "journal removed after restore (OJ ~414-427)" is NOT reached; the code at 414-427 is dead in production.

Readers:
- `load_optional` OJ:266 (also `_check_entries` OJ:231-238: directory may contain ONLY `overlay-journal.json` or the one allowed temp name; any other entry refuses).
- R/bootstrap_close_files.py:52 (`BootstrapClosedOverlayFiles.close`): None -> initial-baseline branch (:53-59, `_check_initial` :108-124 requires no pair entry in overlay dir); non-None -> `_close_candidates_at`, which accepts only phases intent/partial/published/closing (R/bootstrap_overlay_files.py:446-448) and re-opens each owned inode via `_closing_candidate` (:410-427), which turns a missing file into `ApprovalRefused`.
- R/bootstrap_withdrawal.py:65-83 `resume_closure`: None -> False (or raises if `_intent` previously bound, :75-76); phase not in {withdrawing, closed} -> False; withdrawing/closed -> `_bind_intent(current.intent)` (:54-63) and containment uses the withdrawal-files object instead of the close-files object (MG:~210-212 `close_starts`).
- `bind(transaction)` (:43-52, used by `withdraw_pair` MG:~1005): journal intent must equal (boot_id, context, grant_id, payload digests) of the grant transaction, else "withdrawal does not own retained overlay intent".
- R/bootstrap_restore_files.py:40-43: requires withdrawing|closed.

Grant interplay:
- Grant record is per boot: `grant-<boot_id>.json` (src/azazel_nexus/bootstrap_grant_store.py:39-45, load at :161-179, boot binding check :172). `run()` (BS:~891-950) loads it with the current boot id; existing -> `_contain` then ALWAYS raises "existing bootstrap transaction requires manual review" (BS:~927-934). So a boot can never publish twice, independent of the journal. Also `controller-used` marker in /run (src/azazel_nexus/bootstrap_controller_once.py:17,61) is per boot.
- Journal intent carries boot_id/grant_id; journal is NOT per boot (single fixed name OJ:28).
- Phase coupling: grant `pair_grant_intent` is created (BS:~742-746) BEFORE the journal exists. `_UNPUBLISHED_PHASES = {prepared, pair_grant_intent, closing}` (MG:105) only allow the "unpublished baseline" withdrawal when the journal is absent (MG:~984-989). Grant -> `closed` is advanced only in `_finish_transaction` after `_contain` (BS:~528-565).

Normal single-boot lifecycle: grant prepared -> pair_grant_intent -> journal intent -> files -> published -> (supervise) -> `_contain`: close-starts (closing, truncate) -> `withdraw_pair`: begin-withdrawal (withdrawing), unlink files, restore sequence, `finalize` (closed) -> `_contain` tail (mask, inactive, `confirm_empty_pair` which calls `_containment_files.check()` at MG:~244/~254) -> grant `closed`. The journal then stays `closed` forever.

## 2. What actually happens on a later boot (static trace)

Case A: previous boot ended with journal `closed` (clean run).
1. New boot_id => `load_optional(boot_id)` None => no `existing` branch. First `_contain`: `close_starts` -> `resume_closure` True (phase closed, `check()` accepts missing files because phase != closing, R/bootstrap_withdrawal.py:100-118) -> containment succeeds [infer]. `withdraw_pair` is not called (`_grant_transaction` None, BS:~420).
2. `_supervise` creates grant `prepared`, advances `pair_grant_intent`, `open_pair` -> `_publish_and_inspect_pair` -> `journal_store.create` fails (O_EXCL, OJ:297) -> `ApprovalRefused`.
3. `run()` -> `_finish_transaction` -> `_contain` with grant at `pair_grant_intent`: `withdraw_pair` -> `files.bind(transaction)` raises because journal intent boot_id/grant_id belong to the previous boot (R/bootstrap_withdrawal.py:57-59) -> failure "withdrawal" -> `emergency_narrow`, `BootstrapContainmentFailed` -> grant `recovery_required` [infer]. Fail-closed, but the second boot leaves a spurious `recovery_required` grant and exit through the failure path, and no publication is ever possible. This is the finding.

Case B: SIGKILL/deadline/power loss left journal `published` or `closing` (Q9 E3.b, U13). After reboot /run (overlay files, marker) is gone. `resume_closure` False, so `_close_candidates_at` -> `_closing_candidate` stat of the missing file -> `ApprovalRefused` -> `close_starts` fails -> permanent refusal on every boot; manual review needed (consistent with Q3 "journal with no files").

Case C: journal `withdrawing` (crash mid-withdrawal) then reboot. `resume_closure` True and `check()` tolerates missing files; containment passes; but nothing can reach `finalize` because it needs `bind(transaction)` with the old boot's grant, which `run()` never loads (it only loads the current boot's grant). Stays `withdrawing` forever; publication still blocked as in Case A.

So: no automatic path ever reaches "journal absent" in production; the journal outlives its boot in every phase.

## 3. Constraints for any fix

- A journal removal must never occur while any in-process object still relies on it: `BootstrapWithdrawalFiles._intent`/`BootstrapRestoredOverlayFiles._journal` are re-checked via `store.load()` on every `check()` (R/bootstrap_restore_files.py:51, bootstrap_withdrawal.py:99-123), `confirm_empty_pair` calls `_containment_files.check()` (MG:~244,254), `_observe_withdrawal_fence(restored, ...)` after restore (MG:~1046) and `resume_closure` raises if `_intent` was bound and the journal vanished (:75-76). Therefore removal inside `finalize` (R/bootstrap_restore_files.py:60-71) or at the end of `withdraw_pair` makes the same `_contain` fail its own final checks [infer]. The user's first suggested shape ("as part of the existing restore sequence") hits this.
- Removal must not weaken the single-shot-per-boot rule: that rule lives in grant-<boot>.json and the /run marker, not in the journal (see section 1), so deleting a stale journal does not re-open same-boot republish.
- `_check_entries` (OJ:231-238) refuses any extra directory entry, so an archive file in the same directory needs a code change there.
- No new authority/flags: all options below only mutate the already-owned, root-0700 directory under the already-held transaction guard, use existing primitives (`remove`, `replace`), and only narrow.

## 4. Options

### Option 1: remove at end of the same boot's restore/close (user's first idea)
Add `journal_store.remove(closed)` after `_advance_grant("closed")` in `_finish_transaction` (BS:~560) via a new manager method (cannot be in `finalize` or `withdraw_pair`, section 3).
- Crash analysis: crash/error before remove -> journal `closed` persists -> same blocked state as today (not fixed). Crash after unlink, before dir fsync -> `remove` raises `OverlayJournalDurabilityUncertain` (OJ:428-436); after power loss the name may reappear (closed, harmless, same as today) or be gone (fixed). SIGKILL anywhere before this point (the E3.b/Case B/C cases) is untouched. Error after remove but before grant `closed` cannot happen if remove is after.
- Verdict: fail-closed but incomplete: leaves Cases B and C and every "removal did not complete" crash unresolved. Needs Option 2 anyway.

### Option 2: retire the stale journal at the next boot's publication (recommended)
At the one moment a new publication is about to start, under the held guard, after the first `_contain` already confirmed fence/masks/empty cgroup, delete a journal that provably belongs to a finished or abandoned earlier boot. Also add one narrowing-only transition for the reboot case.

Predicate (all must hold, else leave the journal and refuse exactly as today):
- journal.intent.boot_id != current boot id (`read_boot_id`, src/azazel_nexus/hil_preflight.py:480; the code path already has `self.boot_id_reader` BS:215,240). A same-boot journal is never removed.
- phase == `closed` (owned_files empty by validator), OR phase in {published, closing, withdrawing} AND the reboot-reset below succeeded first.
- No pair entry in the overlay dir (`_present` over `_PAIR`, same check as `_check_initial` R/bootstrap_close_files.py:120) and `_mask_paths`/`_withdraw_paths` stamps unchanged (the persistent /etc masks still intact); `confirm_empty_pair` already succeeded in this boot's `_contain`.

Reboot-reset (new `advance_overlay` action, e.g. "reboot-reset", OJ ~ line 600): allowed from published/closing/withdrawing only; returns `OverlayJournal(intent, "closed")` (same shape as the existing "withdraw" result). It requires neither OverlayStopEvidence nor any grant, but the caller (not the pure function) must have verified the predicate above, including boot_id mismatch. Persist with `journal_store.replace(current, closed)` (existing, fsyncs dir, OJ:330-412) and only then retire. Rationale: after a reboot the volatile definitions cannot exist (/run tmpfs, PID 1 rebuilt); the predicate re-proves emptiness on disk instead of trusting the inference. It is strictly narrowing (it records "nothing owned") and grants nothing.

Where: new method on `BootstrapWithdrawalFiles` (R/bootstrap_withdrawal.py), e.g. `retire_prior_boot(current_boot_id)`, because it already owns `journal_store`, `guard`, `_intent`, `_owned`. It must reset `self._intent = None; self._owned = None; self._stamps = None` after unlink so `resume_closure` does not raise "disappeared" (:75-76) in a later `_contain` of this process. Call site: `_publish_and_inspect_pair` in MG, between the `confirm_empty_pair`/`directories.check()`/`_mask_paths` block (MG:743-749) and `self._closed_observation = None` (MG:751-753), i.e. immediately before `_publish_verified_approval_at` (MG:754). This is after the grant `pair_grant_intent` exists and after every check that still needs the old journal (`confirm_empty_pair` uses `_containment_files.check()`, MG:~244), and after the unlink nothing else in the process needs the old journal. Order inside: guard(); `store.load()` equals the bound journal; predicate; [reboot-reset replace]; `store.remove(closed)`; (remove fsyncs the dir, OJ:~428); `directories.check()`.

Crash/failure analysis (state = grant / journal / overlay files / loaded units; every row ends fail closed because the pair stays masked by /etc and any later boot re-derives containment):
| Crash point | Persisted | Next `_contain` / next boot |
|---|---|---|
| before predicate or on any predicate failure | journal unchanged (closed or stale) | refusal as today; grant `pair_grant_intent` -> failure path -> `recovery_required` (same as today's Case A step 3) |
| after reboot-reset rename, before its dir fsync | journal visible `closed` or old phase after power loss | old phase: reset rerun (idempotent, boot_id still differs); `closed`: continue. `replace` maps this to `OverlayJournalDurabilityUncertain` (OJ:~400-407) and we abort publication; no files exist |
| after `closed` durable, before unlink | journal closed | rerun retire; if the process died, next boot sees closed + different boot, retires then |
| unlink done, dir fsync not done (power loss) | journal may reappear as `closed` (same boot id as the dead one => still != new boot) | harmless, retired next time; in-process `remove` raises DurabilityUncertain (OJ:428-436) and publication must abort (do not catch-and-continue) |
| after unlink+fsync, before `journal_store.create` | no journal, no files; grant `pair_grant_intent` | exactly Q9 E1.2: initial-baseline branch `_check_initial` (R/bootstrap_close_files.py:108-124) + `_confirm_unpublished_withdrawal` (MG:~1045-1085, `pair_grant_intent` in `_UNPUBLISHED_PHASES` MG:105); grant -> closed |
| `create` itself fails after O_EXCL (existing behaviour) | `OverlayJournalDurabilityUncertain` | unchanged |
| a second controller / second run in the same boot | grant-<boot>.json exists (BS `existing` branch) and /run marker | refused before any retire; journal of the current boot is never retired because boot_id equality is required |
A concurrent writer is excluded by the held `BootstrapTransactionGuard` and the 0700 root directory, same trust model as `replace`/`create`.

Archive/audit: the retired journal's identity is already preserved by `grant-<old boot>.json` (same grant_id/context) and should additionally be recorded in the audit ledger via the controller's existing `record` before unlink (log type, phase, boot_id, grant_id of the retired journal; no payload). This avoids touching `_check_entries`. If an on-disk archive is mandatory, see Option 3.

Pros: single mechanism covers clean `closed`, failed unlink, and abandoned `published/closing/withdrawing`; no change to file naming or to `_check_entries`; reuses reviewed primitives (`replace`, `remove`, initial-baseline path); keeps the journal as the cross-boot "I owned something" record until it is provably moot.
Cons: new transition + new method + one call site; needs maintainer decision that "abandoned by reboot" auto-recovers rather than demanding manual review (see section 6).

### Option 3: boot-scoped journals / archive-then-remove
(a) Boot-scoped name `overlay-journal-<boot_id>.json` (mirrors grant-<boot>.json at bootstrap_grant_store.py:39-45). Store takes boot_id; `_check_entries` (OJ:231-238) must allow older `overlay-journal-*.json`; stale files accumulate (4 KB each) unless pruned, which again needs a remove path. Prior-boot journals in any phase are ignored, so stale `published` is auto-recovered as the initial-baseline branch (safe because `_check_initial` refuses any pair entry, R/bootstrap_close_files.py:120). Widest code change (every OJ method, three runtime readers, legacy `overlay-journal.json` migration for the already-deployed VM state) and it silently drops the "journal with no files => manual review" signal.
(b) Archive-then-remove: rename `overlay-journal.json` -> `overlay-journal.<boot>.<grant>.closed.json` in the same dir (needs `_check_entries` change), dir fsync, then prune. Crash between rename and fsync leaves either name; both states must be accepted by `load_optional`, doubling the state space. More states, no more safety than Option 2 plus an audit record.

## 5. Recommendation

Option 2 (retire at the next boot's publication, with reboot-reset), implemented as:
1. OJ: add action "reboot-reset" to `advance_overlay` (published|closing|withdrawing -> closed); keep `remove` unchanged (already compare-and-unlink-and-fsync with durability mapping).
2. R/bootstrap_withdrawal.py: `retire_prior_boot(current_boot_id)` as above, resets bound intent.
3. R/bootstrap_manager.py `_publish_and_inspect_pair`: one call just before MG:754, reading boot id via the existing injectable reader; any exception aborts publication (fail closed, grant ends `recovery_required` through the existing failure path).
4. Optional hardening: Option 1's post-`closed` removal is NOT required and is not recommended (section 3 hazards), so skip it.

Why not Option 1: cannot be placed inside restore without breaking the same `_contain`'s own checks and does not cure crash cases.

## 6. Decisions for the maintainer

*Decided 2026-10-25 (Nexus#324): auto-recover with reboot-reset under the predicate of Option 2, and the retirement record is mandatory before the unlink. See §8.*

- Whether a reboot after a crash in `published/closing/withdrawing` should auto-recover (reboot-reset) or stay a manual-review event as Q9 U13 / Q3 describe. Ship the `closed`-only retire first if unsure; the reset is a separate, small step.
- Whether the audit ledger record of the retired journal is mandatory before unlink.

## 7. Tests needed (all fake-descriptor/tmp-dir unit tests, no systemd; names illustrative)

OJ unit (tests/unit/test_bootstrap_overlay_journal.py):
- reboot-reset: allowed only from published/closing/withdrawing; refused from intent/partial/closed; result has no owned_files; encode/decode round-trips.
- `remove` after `replace(..., closed)`; create succeeds afterwards; crash simulation: fsync of dir fails after unlink -> `OverlayJournalDurabilityUncertain`; after simulated reappearance the journal loads as `closed`.

Runtime (R tests, same style as test_runtime_bootstrap_withdrawal_binding.py / _unpublished_withdrawal.py / _published_pair.py):
- retire happy path: closed journal from boot X, current boot Y, overlay empty -> removed, `create` for Y succeeds, grant Y reaches `closed` end to end, `resume_closure` in a later `_contain` of the same process does not raise "disappeared".
- same boot id: never removed (second publication still refuses).
- journal closed but a pair entry present in overlay dir -> not removed, refuses.
- mask stamps changed / `_withdraw_paths` mismatch -> not removed.
- journal phases published, closing, withdrawing from boot X with files absent -> reset then retire; with files present -> refuse (no unlink of foreign files).
- Fault injection at each step of the crash table: raise at reset-replace, at unlink, at fsync; assert no publication, no overlay file created, grant ends `recovery_required` (or `closed` via unpublished baseline for the post-unlink case), pair remains masked.
- Process-level: after retire + failure before create, `_contain` takes the initial-baseline branch and `withdraw_pair` closes the grant via `_confirm_unpublished_withdrawal` (pair_grant_intent).
- Regression: `finalize` still never deletes (existing restore_files test), and no code path calls `remove` in the same boot as `finalize` (grep-style test or call spy).
- Run directory contents check: only `overlay-journal.json` (and allowed temp) after each case (`_check_entries`).
- Q9 doc updates: U13 resolved; E3.b "next boot" paragraph rewritten.

## 8. Implementation (Nexus#324, 2026-10-25)

Unit tests in a Linux container only (synthetic system bus and cgroup tree). This is not VM or hardware evidence.

What already existed: the `reboot-reset` action in `advance_overlay` (published|closing|withdrawing -> closed, no owned files), `BootstrapWithdrawalFiles.retire_prior_boot` and the call site `_retire_prior_boot_journal` in `_publish_and_inspect_pair`, between `confirm_empty_pair`/mask stamps/`checkpoint()` and `_publish_verified_approval_at`. Until now only a `closed` journal whose prior grant was `closed` could reach them, because Case B failed earlier in `close_starts`. They were extended, not duplicated.

Changes:
1. Containment fence for Case B (`R/bootstrap_withdrawal.py`). `resume_closure(boot_id_reader=...)` (the manager passes its private `_boot_id_reader`) accepts a `published`/`closing` journal as this boot's fence when all of these hold:
   - its intent boot id differs from the canonical current boot id;
   - no pair entry exists in the overlay.

   It writes nothing. `check()` for that fence requires the exact same journal, no overlay entry and unchanged `_withdraw_paths` stamps, and reports the persistent-mask fragments. The close sequence still has to see systemd's loaded state match them, and `confirm_empty_pair` still runs. When the boot id is the same or cannot be read or proved, or an entry is present, the result is False and the existing close path decides, so it still refuses on missing owned files. `withdraw()` refuses while only this fence is bound. A `withdrawing` journal already used the existing path (`check()` tolerates absent files).
2. Retirement predicate.
   - For a non-`closed` journal, `retire_prior_boot` requires that this object bound exactly that journal in this boot's containment.
   - `_retire_prior_boot_journal` additionally requires `_containment_files is` the withdrawal files and a current `MaskedBootstrapPair` observation.
   - The prior boot's grant must match grant id, context and payload digests:
     - phase `closed` for a `closed` journal (unchanged);
     - a phase in `_ABANDONED_GRANT_PHASES` (pair_grant_intent ... commissiond_ready, closing, recovery_required) for an abandoned journal. A `closed` or `prepared` prior grant is inconsistent with an abandoned journal and refuses.
   - Same boot is a no-op, and later the O_EXCL create refuses. Pair entries present, changed stamps, or a journal changed during the steps all refuse.
3. Record before unlink. az-auditd is stopped and masked at this point: the stopped-writer rule starts it only after READY. Its shared chain cannot take a record before the unlink. The record is therefore appended, through the existing `AuditLedger` of `_activation_ledger`, to the controller's own local ledger `/var/lib/azazel/state/activation.jsonl`, which is hash-chained and fsynced:
   - event `activation.overlay_journal_retiring`: phase, boot_id, grant_id, context_digest, journal_sha256, grant_phase, current_boot_id, occurred_at, actor; no payload.
   - The append runs before the reset and before the unlink. If it raises or returns anything other than a confirmed append, nothing is changed.
   - The ledger is local, neither signed nor anchored (runtime/README.md).
   - The event is not one of `FLOOR_EVENTS`, so the operator install and §7 recovery path (`activation_cli`) does not count it as a floor or history.
   - If the ledger did not exist, the append creates it. One check sees that: `require_high_water_for_pass` refuses a missing high-water file when a ledger exists ("node with history"). That only narrows the ordinary pass, and the install path is not affected.
   - The success contract is explicit: `_append_retirement_record` returns `True` only when the append returns an `AuditEntry`, and raises otherwise. The manager proceeds only on `is True`.
   - A record on the az-auditd chain would need a new bootstrap event schema, replayed after auditd starts. That was not added.
4. Order inside `retire_prior_boot` (unchanged): guard, exact journal, boot id, stamps, phase, binding, stability, record, stability, `replace(current, closed)` with read-back (only if not `closed`), stability, `remove`. In `finally`, the bound intent, owned files, stamps and prior-boot fence are cleared, so a later `_contain` in this process takes the initial-baseline path.
5. Refusal reasons in the journal (follow-up found in the VM rehearsal of #335). The static literal refusals of `R/bootstrap_withdrawal.py`, `R/bootstrap_withdraw_files.py` and `R/bootstrap_restore_files.py` (for example "prior boot overlay entry present", "prior boot journal or paths changed") are in `_STATIC_FAILURE_MESSAGES` of `R/activated.py`, so the system journal shows `ApprovalRefused: <reason>` and not only the class name. Before this, only the two messages raised in `MG` were listed. `test_static_message_allowlist_matches_reviewed_raise_literals` reads these modules too and requires the allowlist to equal their one-argument literal raises; interpolated messages and subclasses such as `OverlayWithdrawalUncertain` stay class-only.

Crash table as built (tests in `tests/unit/test_runtime_bootstrap_journal_reboot_reset.py`):
- Record fails: nothing changes, and publication is refused.
- `replace` (reset) raises: the old phase remains. The next containment re-fences, and `withdraw_pair` for this boot's grant refuses, so the supervisor ends at `recovery_required` (as in Case A).
- `remove` raises before the unlink: the journal is `closed`, and the next containment and withdrawal behave as in the `closed` Case A.
- The unlink happened but the directory fsync was uncertain: no journal remains, and the initial-baseline branch plus `_confirm_unpublished_withdrawal` close this boot's grant.
- Deviation from the §4 table: a journal that reboot-reset turned `closed`, whose unlink did not complete before a crash, is retired at a later boot only if its prior grant is `closed`. The `closed` rule was not widened beyond the owner's decision. With the usual unfinished prior grant it stays manual review (fail closed).

Mutation-checked guards: the same-boot fence, overlay entry at the fence and in `check()`, stamp and journal comparison in `check()`, binding in `retire_prior_boot`, the manager's fence and observation guard, the grant phase sets, the record confirmation, the boot id reader at `close_starts`, the `withdraw()` guard, and the reset of bound state.


Follow-up (Nexus#324, 2026-10-26): the deadline and grant records of an earlier boot use the same contract as this retirement. A confirmed append to the same activation ledger comes before any change; if it is not confirmed, nothing changes. The deadline records use `activation.bootstrap_deadline_retiring` inside the first admission's `retain`. The grant records use `activation.bootstrap_grants_archiving` after READY. Both rename the records into `/var/lib/azazel/state/bootstrap/archive/` and never delete them. The grant archive never moves the record of the boot that the retained overlay journal names, so it does not touch a record that this retirement still reads. Conditions and refusals: `docs/evidence/bootstrap-finding-reboot-rerun-2026-10-16.md` (update section) and `tests/unit/test_bootstrap_prior_boot_archive.py`.
