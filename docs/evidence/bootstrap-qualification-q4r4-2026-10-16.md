# Bootstrap qualification Q4-R4 (precursor P1, declared substitution D6) - run record

Date: 2026-10-16. Status: run complete; outcome is a finding (refusal at the loaded-unit inspector), contained.
Raw outputs (harness.out, events.log, PID 1 journal, before/after state dumps, smoke output, measurement transcripts) are retained in the operator's scratch area; this record cites them by name only.
Related: `docs/evidence/bootstrap-factory-switch-rereview-2026-10-16.md` (P1 / R-A), `docs/evidence/bootstrap-qualification-q10-q3-2026-10-16.md`, `docs/evidence/bootstrap-design-loaded-dependencies-2026-10-16.md` (finding and design options derived from this run).

## 1. Purpose

Answer P1: if the controller-root predicate (`ActiveState` in {inactive, activating, active}, `runtime/src/azazel_nexus_runtime/bootstrap_start_closure.py:204-207`) were satisfied, would the first real start get past the four inspectors that had never run against the real pair (start-closure, prerequisite, loaded-unit, retained check)? D6 is one in-memory, value-level rewrite of one D-Bus reply field (controller `GetAll(Unit)` `ActiveState` `failed` -> `activating`). It touches nothing else (pair-root states, `DefaultDependencies`, LoadState, relations, aliases are never rewritten) and writes no file.

## 2. Setup (as observed)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257.13 |
| Product build | c79291b (pre-factory-switch) |
| Boot | `b95cb30c-f168-4087-a75c-11766c539c9a`, after a reboot from state S0 (previous boot `8c3dd0e1-89fd-4abc-8427-e1d3c304277f`) |
| Boot-time controller | refused (no state) |
| `/data` | tmpfs, remounted |
| Boot-bound records | quarantined (owner-authorised test scaffolding); owner renewed the records and signed the approval payload `sha256:08d70757...` |
| Precondition detected | `boot2` (prior boot's closed journal and `grant-8c3dd0e1-...json` retained; none for this boot) |
| Controller premise | `azazel-activated.service`: ActiveState=failed, DefaultDependencies=no, NeedDaemonReload=no |
| D6 seam | `bootstrap_manager.BootstrapStartClosureInspector` rebound to a subclass whose reader rewrites only the controller path's `GetAll(Unit)` reply (`q4r4-harness.py`, D6 region) |
| Variant check | `dbus_next` Variant constructor exercised on the VM: `variant ok s activating` |
| Smoke | `smoke-ok` including `smoke-d6-selftest-ok`, `smoke-admission-verify-ok` (1.418 s); nothing written or consumed |
| START | 2026-10-16T06:45:40Z (harness `begin` epoch 1792133140) |

## 3. Result

`RESULT outcome=unexpected detail=UnitOperationFailed(loaded bootstrap observation refused) <- UnitOperationFailed(loaded bootstrap dependencies differ) process_seconds=23.134`, service exit status 10. "unexpected" is the harness label for "not the pre-registered stop-before-ready"; here it is the P1 answer.

Sequence observed:

1. Pair-grant intent, 7 publication checkpoints (journal intent -> partial -> published, both overlay files present), `open_pair` 11.848 s total; checkpoints 1.637-1.658 s each; one identity call.
2. After the manager reload, the controller stub inspector and the start-closure inspector ran. D6 substituted exactly 2 times (`d6_unit_reads=2 d6_substituted=2`, `real=failed presented=activating`, `DefaultDependencies_real_unchanged=False`, only unit `azazel-activated.service`, only field `ActiveState`). The root-policy refusal (`start closure root policy differs`) did NOT occur: the closure inspector and the prerequisite inspector were passed.
3. Refusal at the loaded-unit inspector (`BootstrapLoadedUnitInspector`, `runtime/src/azazel_nexus_runtime/bootstrap_loaded.py:123-143`, wrapper `:245`): `loaded bootstrap observation refused` <- `loaded bootstrap dependencies differ`. The outer handler collapses the cause by design; the inner message is the only discriminator. Which unit and which property differed is not logged by the product (see the design note).
4. `open_pair` returned `UnitOperationFailed`; containment ran: `close_starts`, mask both units, `stop_and_wait`, `confirm_empty_pair`, `withdraw_pair` (3.485 s, published branch), final masks, `confirm_empty_pair`. `run-selected-bootstrap-end` 22.985 s.
5. `D6-summary unit_reads=2 substituted=2 untouched=0` (the retained check was never reached, so the expected 8 never materialised).

## 4. Containment and end state (from the after-run dumps)

- Prior-boot journal retired; this boot's journal `closed`.
- This boot's grant `closed` with `grant_withdrawal=confirmed`; two grant files present (`grant-8c3dd0e1-...json` for the prior boot, `grant-b95cb30c-...json` for this boot, both 930 bytes).
- `controller-used` marker present (expected, one-shot per boot); overlay `/run/systemd/system.control` held no azazel file; both helper units back to LoadState=masked, ActiveState=inactive, Job empty, FragmentPath `/etc/systemd/system/*.service`.
- Audit ledger empty; no `Starting azazel-auditd/commissiond` line in the PID 1 journal or the full journal (0 matches); no helper started, no READY/notify.
- The real controller stayed `failed` and untouched.

## 5. Verification against the written expectation

`verify` reported exactly 3 FAILs, all being the D6-target expectations that presuppose passing the loaded-unit inspector: (a) `open_pair` completed without error, (b) `retained_check` ran, (c) `stop-before-ready` reached. All other rows PASSed (D6 armed once, substitutions limited to the named unit/field, no root-policy refusal, no start, containment complete, real controller state unchanged).

## 6. Conclusion

P1 is answered: with the controller-root predicate satisfied, the first real start would refuse at the same point, the loaded-unit dependency comparison, for reasons that are independent of D6 (see `docs/evidence/bootstrap-design-loaded-dependencies-2026-10-16.md`). D6 itself worked as designed and was contained.

## 7. Limits

- D3 (stub controller inspector) remains; the real controller inspector against an `activating` unit is unvalidated. Q4-R4 is a precursor, not a substitute for Gate D of the real factory switch.
- D6 changes what the closure fingerprint contains; this run does not show that the real pre-READY controller yields an identical fingerprint at start admission.
- The retained check, the second prerequisite/closure snapshots, and the service-settings comparison (`_SERVICE_EXPECTED`, `bootstrap_loaded.py:34`) were not reached; they remain never-run.
- The 10 s per-operation budget was not exceeded by the inspectors that ran; process time 23.1 s at RESULT (below the ~25 s finding threshold).
- One run, one VM, one systemd build (257.13); no retry in the same session per the stop rules. Irreversible state (marker, deadline records, closed grant/journal, Reload side effects) requires a snapshot revert before any next run.
