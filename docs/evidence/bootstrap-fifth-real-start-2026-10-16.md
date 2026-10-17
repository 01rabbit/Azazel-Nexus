# Bootstrap fifth real start of azazel-activated.service (build af370f3) - run record

Date: 2026-10-16. Status: refused in prestart, before any deadline or grant record. `systemctl start` was refused with `ApprovalRefused`. The product behaved correctly (fail-closed). The cause is an operator-procedure error: a first-install-genesis admission was provisioned against a non-empty (continued) audit ledger. No new product behaviour was reached.
Related: `docs/evidence/bootstrap-fourth-real-start-2026-10-16.md` (run 4, 5652d7f), `docs/evidence/bootstrap-third-real-start-2026-10-16.md` (run 3), `docs/evidence/bootstrap-second-real-start-2026-10-16.md` (run 2), `docs/evidence/bootstrap-first-real-start-2026-10-16.md` (run 1).

## 1. Scope

- VM only; not a hardware result. Approval is synthetic. Issue #93 remains open.
- Not reached: auditd start, commissiond start, loaded-bootstrap observation of the inverse edges, steady state, deadline expiry. The fix in af370f3 was therefore not exercised on a real host in this run.

## 2. Setup (orchestrator-observed)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257 |
| Product build | af370f3 (owner-approved fix: tolerates exactly `azazel-commissiond.service` in auditd's inverse `Before` / `RequiredBy` / `BoundBy`) |
| Boot | `f15d9569-6ac7-4acd-8be3-b792b55d47cb` (reboot after run 4) |
| Installed files | `sha256:13a691c4...` |
| Loaded units | unchanged, `sha256:305fc910...` |
| Approval payload | `sha256:7d717c48...` (synthetic, owner-signed) |
| Preflight | 0 failures |

Owner decisions before the run:
- Full records quarantine approved: 18 files moved, nothing deleted; re-provisioning for the new build.
- The audit ledger was deliberately KEPT (6 records from run 4, head sequence 6 = `bootstrap.stopping`, 2285 B), because audit records must not be tampered with.

## 3. Timeline (host clock)

| Time | Event |
|---|---|
| 23:01:03.7 | `systemctl start azazel-activated.service`; two daemon-reloads (initial narrowing) |
| 23:01:06.34 | refused, journal line `ApprovalRefused` (static message only; detail not logged, see section 6) |

## 4. End state

- Controller-used marker created (the claim precedes the prestart check).
- No grant, no deadline records, overlay journal absent (only `supervisor.lock`).
- Audit ledger unchanged: 6 records, 2285 B, head sequence 6.

## 5. Diagnosis (diag5)

Refusal is the stopped-writer prestart audit check, genesis branch: `inspect_first_install_audit` raised "first-install audit directory is not empty" (`runtime/src/azazel_nexus_runtime/bootstrap_audit.py` ~214-215).

- The re-provisioned `/etc/azazel/bootstrap/admission.json` was again a first-install-genesis policy (schema v5, `audit_mode` `first-install-genesis`, genesis sequence 0, head all zeros) while the ledger was non-empty (6 records, seq 1..6, chain linked, head `a6ebb5b2...a373`).
- Call path: `bootstrap_entrypoint.run_selected_bootstrap` -> supervisor `run` -> `_admit_first` (approval verified, generation required) -> `prestart` -> `inspect_bootstrap_prestart` -> `check_bootstrap_existing_audit` (`policy.first_install_genesis is not None`) -> `inspect_first_install_audit` -> raise. Wrapped successively as "first-install bootstrap audit refused", "existing bootstrap audit continuity refused", "policy-bound bootstrap audit refused", "bootstrap prestart prerequisites refused"; all `ApprovalRefused`.
- This happens before `initial_admission.retain`, so no deadline or grant records exist, matching the observed state.
- It is not a context-binding, terminal-record or chain-integrity refusal. No code compares ledger records to the deployment, approval or context; the reader checks only sequence, previous hash and event-hash recomputation.
- Run 4 used the genesis policy against an empty ledger; run 5 reused the same mode against the continued ledger. Time, approval and quarantine checks passed earlier in `_admit_first`.

Intended behaviour:
- Genesis single-use rests on the ledger being empty, not on recorded state (a wiped ledger plus a fresh signed approval would be accepted again; assurance stays `LOCAL_CONTINUITY_ONLY`).
- The designed continuation path is an existing-history (v3/v4) admission whose owner-signed policy pins `audit_sequence` and `audit_head`. The initial check requires exact head match, chain integrity and bounds. Cross-deployment continuation is supported only as "owner-signed policy pins the head".
- Not implemented: ledger archival, rotation or pruning; deployment-scoped ledgers; external anchor.

## 6. Observability follow-up

The refusal detail was not in the journal: only selected modules' static messages are allowlisted, so the wrapped `bootstrap_audit` / `bootstrap_prestart` messages were not logged and the journal shows `ApprovalRefused` only. The cause was recovered from code and on-VM state. Follow-up: consider allowlisting fixed (non-secret) refusal labels from `bootstrap_audit` and `bootstrap_prestart`.

## 7. Next step (owner decision pending)

- Re-provision `admission.json` as a v4 existing-history admission: `audit_sequence=6`, `audit_head=a6ebb5b2...a373` (owner-signed), no `audit_genesis`, `loaded_policy_digest` kept. The policy digest feeds `deployment.policy_digest`, so deployment, installed-files, selection and approval must be re-published and re-signed, with a new boot context. Head 6 is terminal (`bootstrap.stopping`); the chain continues at sequence 7. The ledger stays untouched and append-only.
- Caveat: the existing-history path has never run on a real ledger; further refusals are possible (for example the live audit head `verify_startup` with a non-zero start head).
- Alternatives (owner-authorised ledger quarantine with a fresh genesis, or signed archival) weaken or lack product support and are not recommended without a recorded owner decision.

Until the owner decides: no retry in place; the controller-used marker blocks a second start in this boot.
