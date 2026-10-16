# Bootstrap factory qualification: Q3 and Q10, real reboot with prior-boot journal retirement (test VM, 2026-10-16)

Scope: Debian 13 ARM64 test VM; not hardware evidence. The production factory is unchanged.
Purpose: answer Q3 (reboot behaviour of the bootstrap state) and the reboot part of Q10 (see
`bootstrap-factory-switch-review-2026-10-16.md`), and exercise the prior-boot journal retirement (b1a99d7) on a real reboot.
Build: c79291b (same as `bootstrap-qualification-q4r3-2026-10-16.md`). Procedure: Q10 procedure notes with `q10-capture.sh`
(read-only capture) and `q4-run-q10.sh` / `q4-harness-q10.py` (Q4-R second-run variants).
Method: the second Q4-R run is Q4-R (D1-D5) as in the Q4-R #3 record: production `run_selected_bootstrap` in a transient unit,
a `_PrototypeBootstrapManager` subclass, five in-process substitutions (D1 cgroup constant, D2 controller identity, D3
controller-inspector stub, D4 manager class, D5 sd_notify refused). This is not real-controller evidence.
Raw outputs (`q10-out/{pre,post,quarantined,final}`, `q4-out-q10`, `q4-out-q10b`: harness.out, events.log, pid1-journal.txt,
journal-all.txt, before/after capture directories) are retained in the operator's scratch area; they are not committed.
Items marked (orchestrator-reported) were not re-derivable from the retained files.

## Sequence and results

1. **Boot A** `8c3dd0e1-89fd-4abc-8427-e1d3c304277f`, build c79291b. Q4-R #1 (= Q4-R3) left: journal `closed`, `grant-A`
   `closed`, controller-used marker, deadline records (`initial.json`, `checkpoint.json`). The owner took a VM snapshot S0.
   Stage A capture `pre` at 05:58:33Z (uptime 5264 s, boot A).
2. **Reboot #1** (boot A ended 06:00:41Z per `journalctl --list-boots`) -> **boot B**
   `e37d4e03-7c60-43fb-b288-1f94f68a87ea`. Postcheck: ALL PASS (orchestrator-reported). Confirmed in the `post` capture:
   - `azazel-activated.service`: `UnitFileState=enabled`, `ActiveState=failed`, `Result=exit-code`, `ExecMainStatus=1`,
     `NRestarts=0`. Journal line: `az-activated failed before completing a safe pass: ApprovalRefused` (06:00:55Z). The enabled
     controller therefore ran at boot and refused at selection binding (selection bound to boot A).
   - The marker was absent (tmpfs `/run`); no marker, grant, deadline record, journal change, audit write or `activation.jsonl`
     was created (orchestrator-reported postcheck; consistent with the later `before` capture of attempt 1).
   - Audit directory `state/audit`: mode 0700, owner `azaudit:root`, same inode (925703) and mtime (2026-10-15 18:48:04 +0900),
     0 entries. Pair `LoadState=masked`, `ActiveState=inactive`; masks unchanged.
3. **Owner-authorised, test-only, reversible quarantine** (`mv` to a root-only directory) of `selection.json`, `time.json`,
   `approval.json` / `approval.sig`, `initial.json`, `checkpoint.json` (capture `quarantined` at 06:01:35Z). The owner renewed
   selection, time and approval for boot B and signed (payload `sha256:69d17c37...`, synthetic test approval).
4. **Q4-R #2 attempt 1 (`q4-out-q10`), started about 06:04:12Z in boot B: REFUSED after 2.667 s** at generation admission:
   `protected bootstrap generation admission refused <- semantic admission <- policy-bound capacity <- capacity prerequisite <-
   resource observations incomplete`. Cause: the test VM's `/data` tmpfs (mounted earlier by hand, `size=512M,mode=0755,
   nosuid,nodev,noexec`, no fstab entry) did not survive the reboot, so the mission-available observation was unavailable.
   Fail-closed: no `grant-B`, no deadline records, journal untouched (still boot A), pair masked. The controller-used marker was
   created (present in `after/tree.txt`), so no second attempt was possible in boot B; the marker was deliberately not deleted.
5. **Reboot #2** -> **boot C** `f09dc5ee-d9ac-44db-ba2a-040969045166`. Postcheck ALL PASS again (orchestrator-reported); the
   `post` capture shows the same boot-time refusal (`ApprovalRefused`, 06:05:59Z; Result=exit-code, status 1, NRestarts 0) and
   the same audit directory (same inode and mtime, 0 entries). `/data` tmpfs was remounted by hand with identical options; a
   read-only `assess_resources` probe gave `unavailable=[]`, usable memory 2907 MiB, 4 CPUs, mission-available 512 MiB
   (orchestrator-reported). Quarantine again (selection, time, approval / signature of boot B). The owner renewed the records for
   boot C and signed (payload `sha256:a9da0b94...`; matches `approval_digest` in the retained `after/records.txt`).
6. **Q4-R #2 (run 2, `q4-out-q10b`) started 06:08:33Z** (uptime 158 s, boot C). `open_pair` 12.241 s with 7 publish checkpoints
   of 1.684-1.762 s (1.741, 1.714, 1.714, 1.762, 1.684, 1.685, 1.700). The same harness-artifact stop as Q4-R #3
   (`RESULT outcome=unexpected detail=UnitOperationFailed(start closure root policy differs)`, process 23.235 s); containment
   and `withdraw_pair` (3.307 s) completed. `VERIFY: ALL PASS` (orchestrator-reported), including: prior-boot journal retired
   (current journal bytes differ from the boot-A journal); journal `closed`, `owned_files=[]`, `boot_id` = this boot; prior-boot
   grant byte-identical (same size 930 and mtime in `after/tree.txt`); exactly two grant files (boot A and boot C), the boot-C
   one `closed`; close evidence recomputed (`grant_withdrawal=confirmed`); audit ledger empty; no helper started. Final diff
   against `post`: new overlay journal, new `grant-C`, new `initial.json` / `checkpoint.json`, renewed selection / time /
   approval, marker, and nothing else (journal log files excluded). `final` capture at 06:09:09Z: audit directory unchanged.
7. The temporary sudo access on the VM was removed afterwards (orchestrator-reported).

## Conclusions

**Q3 (reboot behaviour) and Q10 reboot answers**
- The `/run` marker does not survive a reboot (tmpfs). Risk 4.2 of the factory-switch review is confirmed: an enabled controller
  runs on every boot.
- With per-boot selection, that boot-time run refuses at selection binding (`ApprovalRefused`), creates no state, and leaves
  the unit `failed` (Result=exit-code, status 1, NRestarts 0). Observed in both reboots.
- `state/audit` survives the reboot and stays empty; the boot-time run does not write a genesis or any audit record.
- Prior-boot journal retirement (b1a99d7) works on a real reboot when the preserved prior grant is closed and matches the
  journal: the old journal is removed and a journal for the new boot is published. It writes no audit record (owner decision d).

**Not covered**
- Q10 genesis with a live auditd (only the fixture Q6 tmpfs genesis exists).
- A stale `published` / `closing` journal after a crash across a reboot (Q7-R is same-boot only).
- Real READY / helper start (the factory remains closed).

## Findings

- (a) Cross-boot renewal is absent. The quarantine used here is test scaffolding, not a product path; see
  `bootstrap-finding-reboot-rerun-2026-10-16.md`.
- (b) tmpfs `/data` on the test VM is non-persistent (hand-mounted, no fstab entry). It caused attempt 1 to be refused; a
  test-environment artifact, not a product defect.
- (c) The per-boot single-attempt marker is consumed even by an early admission refusal (attempt 1 refused at 2.667 s yet left
  `controller-used`), so a refused start cannot be retried in the same boot.

## Limits

Test VM only; synthetic, owner-signed test approvals (not deployment approvals); reduced harness D1-D5; the harness stop
"start closure root policy differs" is the known harness artifact, not the designed stop point. Issue #93 remains open.
Related: `bootstrap-qualification-q4r3-2026-10-16.md`, `bootstrap-finding-reboot-rerun-2026-10-16.md`,
`bootstrap-factory-switch-review-2026-10-16.md`.
