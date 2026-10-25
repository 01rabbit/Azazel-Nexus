# Finding: the supporting-only bootstrap cannot run twice on one deployment across a reboot

Date: 2026-10-16. Basis: static reading of the tree at HEAD c79291b (commit id taken from the task; no git used to re-check it). Nothing was run.

## Update 2026-10-26 (Nexus#324): deadline and grant records of an earlier boot

This finding was correct for the tree it read. The deadline row and the
grant/journal notes below have since changed. Selection, time anchor and
approval are still bound to one boot and must be renewed by the owner for each
boot, and nothing below creates or renews them.

- Deadline (`initial.json`/`checkpoint.json`). Each boot's first admission
  brings a new owner-signed approval for that boot, and that approval carries
  its own deadline. Within one boot the deadline is still never extended or
  replaced. A restart, or a soft reboot (which keeps the kernel boot id),
  still refuses with "bootstrap deadline was already initialized".
  `_retain_initial_at` (`src/azazel_nexus/bootstrap_deadline_store.py`)
  archives existing records only when all of these hold:
  - it is called from `ProtectedBootstrapInitialAdmission.retain`, after this
    boot's approval is freshly verified and prestart has passed;
  - it holds the store lock;
  - there is no `transaction.pending` or `checkpoint.next`;
  - both records are present, protected and canonical, and name the same boot
    id and approval digest;
  - that boot id differs from the current boot id, and that approval digest
    differs from the new approval's.

  Before anything changes, an `activation.bootstrap_deadline_retiring` record
  is appended to the activation ledger. If the append is not confirmed,
  nothing changes. Under a `transaction.pending` marker, the records are then
  renamed into `archive/` on the same filesystem (never deleted, never
  overwritten) and fsynced. The new records are then created create-only, as
  before. Any missing condition refuses, and the reason is on the journal's
  static allowlist.
- Grants (`grant-<boot>.json`). After READY, `GrantTransactionStore.archive_prior`
  (`src/azazel_nexus/bootstrap_grant_store.py`) moves another boot's grant
  record into the same `archive/`. It skips this boot's record, the boot the
  retained overlay journal still names, and any record with a
  `.pending`/`.next` marker or a decoded boot id that differs from its name.
  An `activation.bootstrap_grants_archiving` ledger record comes first.
- The prior-boot overlay journal retirement (b1a99d7, extended by #335) now
  appends `activation.overlay_journal_retiring` to the same ledger. It also
  handles a journal abandoned in `published`/`closing`/`withdrawing`. Owner
  decisions 1, 4 and 5 in §4 were taken that way. The archive for decision 2 is
  `/var/lib/azazel/state/bootstrap/archive/`, and the evidence is the
  controller's activation ledger.

The VM rehearsal's manual quarantine of the deadline records (§2) is therefore
no longer needed for them. Unit tests only; this is not VM or hardware
evidence.

## 1. Verified finding

After a reboot the bootstrap cannot run again on the same deployment without manual intervention. Several records are bound to the old boot or are create-only. Line numbers are as read.

| Record | Behaviour | Evidence |
|---|---|---|
| `selection.json` | Bound to a boot id. `bind_bootstrap_selection` raises `ApprovalRefused("bootstrap selection binding differs")` when `selection.boot_id != boot_id`. `load_bootstrap_selection` calls it with the current boot id and re-wraps any failure as "protected bootstrap selection refused". | `src/azazel_nexus/bootstrap_selection.py:77-86` (compare at :85); `src/azazel_nexus/bootstrap_selection_store.py:130-153` |
| `selection.json` replacement | `initialize_bootstrap_selection` refuses when `selection.json` or `selection.pending` exists ("existing selection cannot be replaced"). `recover` only completes exact pending bytes. | `src/azazel_nexus/bootstrap_selection_store.py:63-64`, :117-125 |
| `time.json` | Create-only. An existing `time.json` or `time.pending` gives "existing time state requires administrator review". The anchor is also checked against the current boot id. | `src/azazel_nexus/bootstrap_clock_store.py:68-69`; `bootstrap_clock_store.py:174`, :209, :226; `src/azazel_nexus/bootstrap_clock.py:98-99` |
| `approval.json` / `approval.sig` | The approval context carries `boot_id`. Verification compares it with the current boot id, and the window must match the context. A new boot needs a newly owner-signed approval. | `runtime/src/azazel_nexus_runtime/bootstrap_inputs.py:307-308`, :416, :432, :442 |
| Deadline records `initial.json`, `checkpoint.json` | `_retain_initial_at` refuses if either exists ("bootstrap deadline was already initialized"). Writes use `O_CREAT\|O_EXCL`. There is no overwrite path and no renewal. | `src/azazel_nexus/bootstrap_deadline_store.py:116-131` (check at :122-123); `_write_new` at :81-82 |
| Controller marker | Created with `O_EXCL` under `/run`, so it does not survive reboot (tmpfs). This is not a blocker. | `src/azazel_nexus/bootstrap_controller_once.py:61` |

Approval placement: the "placement refuses existing files" claim was not verified in this repo. The placement tooling is not in the tree.

`place-records.sh` is not in this repo. It is owner-bundle and scratch tooling and uses `mv -n`, which refuses existing destinations. It matters only as test tooling.

The repo already states this limit: "until cross-boot renewal exists a node bootstraps once -- retrying needs clean state (a VM snapshot revert), never deletion of retained records" (`docs/runtime-activation-remaining.md:5987`; the surrounding paragraph starts near :5980).

### Boot-time behaviour of the enabled controller (confirmed)

`main()` in `runtime/src/azazel_nexus_runtime/activated.py` calls `load_optional_bootstrap_selection()` at :515-518. The optional loader is `src/azazel_nexus/bootstrap_selection_optional.py`; its failure is wrapped at :49-50. The old-boot `selection.json` makes it raise. The inner `except` at :517-521 calls `narrow_invalid_selection(primary, narrow=_narrow_bootstrap_core_units)` and re-raises. The outer handler (:538-546) prints `az-activated failed before completing a safe pass: <type>` and `return 1`.

The refusal happens before any of these:
- `run_selected_bootstrap`, which is the only caller of the marker create (:522-523);
- the supervisor, grant creation, deadline `retain`, and overlay journal activity;
- any audit write.

`_run_once` (the ordinary path, :384-455) is not reached either. The only side effect on the refusal path is the narrowing call, which re-masks already-masked core units (idempotent). It takes the bootstrap lock via `src/azazel_nexus/bootstrap_lock.py` and opens an existing lock file. Conclusion: no grant, marker, deadline or audit state is created. The unit ends `failed`. Failure of the narrowing is only added as a note (`EMERGENCY_UNCONFIRMED`, printed at :539-540).

One conditional hazard: if `selection.json` were absent at boot, `load_optional_bootstrap_selection` returns None and the ordinary `_run_once` path runs (it writes `state/activation.jsonl`).

### Prior-boot journal retirement (commit b1a99d7)

`_retire_prior_boot_journal` is defined at `runtime/src/azazel_nexus_runtime/bootstrap_manager.py:798` and called at :895 inside publication (after pair emptiness and mask checks). It only retires a journal whose intent boot id differs from the current one, and it requires the prior grant to be `closed`. It can be reached only through a supervisor run on the new boot. That run needs, in this order:
1. a selection for the new boot (`selection.json`);
2. a time anchor (`time.json`) for the new boot;
3. an approval for the new boot;
4. successful `retain_initial_deadline`, i.e. no `initial.json`/`checkpoint.json`.

Without all four records renewed for the new boot, retirement is never reached across a reboot. The docstring (:808-812) says the reboot-reset branch for `published`/`closing` journals is reached only by direct calls, because those fail earlier at `close_starts`. Only the `closed` case is reachable.

## 2. Consequence

A second boot needs the owner to move aside the five records (`selection.json`, `time.json`, `approval.json`, `approval.sig`, `initial.json`/`checkpoint.json`) and then re-issue new-boot records. For the VM test the owner authorised a reversible root-only quarantine: `mv` into a root-owned 0700 directory on the same filesystem, so inodes are preserved. This is test scaffolding only. It defeats the create-only protection by design and is not a product path. The journal, `grant-<old boot>.json` and `supervisor.lock` are not touched. The plan is in the Q10 procedure (operator scratch area).

## 3. Design options for a product lifecycle

Common constraints for every option:
- No new authority, no approval boolean, no env or flag bypass.
- Anything trust-bearing (selection, approval, time anchor) is created or signed by the owner for the specific boot.
- Fail closed: any ambiguity (pending files, partial state, mismatch) refuses and leaves state as it was.
- Prior records are archived, never deleted. Retained deadline history must stay available as evidence.

### A. Per-boot namespacing (e.g. `selection-<boot>.json`, `time-<boot>.json`, `initial-<boot>.json`, `checkpoint-<boot>.json`)
Pros: grants already follow this pattern (`grant-<boot>.json`). There is no overwrite and no deletion. Create-only guarantees are kept per boot, and old records stay as an audit trail.
Cons: stores must be changed to look up by boot id, and loaders must ignore other boots' records but still detect tampering. Unbounded growth needs an owner-driven retirement. Rollback anchoring is weakened: with no cross-boot state, a deleted record looks like a fresh boot (the code already notes a local record is not an independent rollback anchor, `bootstrap_selection_store.py` docstring of `load_bootstrap_selection`). Deadline semantics must be decided: a fresh deadline per boot is a new bound on the exposure window, which needs an owner decision.

### B. Owner CLI "renew for this boot"
An owner-run, root, confirmed-digest command that (1) takes the bootstrap lock, (2) verifies the controller is not running and the journal is `closed` or absent, (3) moves the prior-boot records into an archive directory, with fsync of files and directory, (4) writes an evidence record (hashes of archived records, old and new boot id), and (5) leaves new records to the existing owner initialize/sign flows.
Pros: smallest change to stores; keeps the create-only invariant inside each store; the single audited path replaces ad-hoc quarantine.
Cons: it is a new privileged mutation path, so it must itself be owner-confirmed (digest plus explicit confirmation, like the existing `confirmed_*` parameters) and must be crash-safe (pending marker, recoverable). If it can run unattended it becomes an authority bypass. The audit chain does not exist until the first real auditd start, so evidence may initially be a file.

### C. Deadline records keyed by boot
Make `initial`/`checkpoint` per boot (a subset of A) while selection and time stay as owner-renewed files.
Pros: removes the most mechanical blocker without changing the owner trust flow. Cons: alone it does not help, since selection, time and approval still need renewal.

A and B can combine: B archives and writes evidence; A or C gives per-boot slots so nothing has to be moved.

## 4. Recommendation and owner decisions

Recommendation: B for selection/time/approval (owner-confirmed renewal with archive, fsync and evidence), plus C or A for the deadline records so the retained history is never overwritten. Do not auto-renew at boot. The enabled controller should keep refusing at selection binding, as it does now.

Owner decisions needed:
1. Is a fresh deadline per boot acceptable, or must the absolute deadline carry across boots?
2. Where does the archive live, and what evidence record is required before an audit chain exists?
3. Is a boot-time "renew" ever allowed to be non-interactive? (Recommendation: no.)
4. Should retirement (b1a99d7) remain write-free, or should it append a ledger record once the chain exists?
5. What should happen with a stale `published`/`closing` journal after reboot: stay manual review (the current behaviour)?

## 5. Limits

Static study only; nothing was run, no VM, no network, no git. File:line values come from the files as read, and not every claimed behaviour was traced (approval placement refusal and `place-records.sh` are from the Q10 procedure, not this repo). Whether a clean reboot leaves the records exactly as described depends on the VM state, which was not observed. The commit id c79291b was not re-checked against git.
