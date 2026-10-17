# Bootstrap fourth real start of azazel-activated.service (build 5652d7f) - run record

Date: 2026-10-16. Status: auditd reached authenticated readiness (identity and peer proof accepted), the audit ledger was created (genesis on the real test-VM ledger, owner decision D1, irreversible; snapshot / quarantine-revert only), and the real `azazel-commissiond.service` was started for the first time. The loaded-bootstrap observation then refused with `UnitOperationFailed: loaded bootstrap observation refused: dependencies`. The controller contained the pair and exited 1. Contained. This is a product refusal (fail-closed), not a monitor artifact.
Raw outputs (realstart-out4 tar: before/after listings, `run/events.log`, `run/timeline.log`, `run/cgroups.log`, PID 1 / unit / full journals, monitor state, journal window) are retained in the operator's scratch area; this record cites them by name only.
Related: `docs/evidence/bootstrap-third-real-start-2026-10-16.md` (run 3), `docs/evidence/bootstrap-second-real-start-2026-10-16.md` (run 2, c822c9b), `docs/evidence/bootstrap-first-real-start-2026-10-16.md` (run 1, ee5cdd2).

## 1. What this is, and what it is not

Reached for the first time on a real host (test VM):
- auditd authenticated readiness (grant `auditd_ready`);
- audit ledger genesis and audit chain records 1-6 (section 4);
- a real `StartUnit` of commissiond (`active/running`, pid 4716, `commission.sock` created);
- the `bootstrap.stopping` record written during containment;
- the fixed refusal label ("dependencies") surfacing in the controller journal;
- retirement of a prior-boot journal and prior-boot grant (preflight path: prior-boot journal closed + grant closed).

Reached before (runs 1-3): real READY, real heartbeats, real `StartUnit` of auditd, auditd staying active, controller-first SIGTERM containment.

Not reached: commissiond readiness / inventory, steady both-helper loop, clean exit-0 operator stop after steady state, deadline expiry.

- Approval is synthetic (test VM only). VM only; not a hardware result. Issue #93 remains open.
- The ledger now holds real records; it cannot be rolled back by the product.

## 2. Setup (as observed)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257 |
| Product build | 5652d7f |
| Boot | `4bb32901-9b12-40d6-9eba-934476a47cfe` (rebooted from the run-3 boot `b62b58f7-...`; `after/list-boots.txt`) |
| Approval payload | `sha256:9a0acf3698f5...` (synthetic, owner-signed; matches `after/sums.txt`, `initial.json`, grant) |
| Selection / time | renewed by the owner for this boot (`selection.json`, `time.json` both bound to this boot id) |
| Preflight | 0 failures (as reported by the operator) |
| Substitutions | none: real inspector, real sd_notify, real manager, real start bridge |
| Monitor tolerances | recalibrated after run 3: S7 9..15 s from S6, S8 27..42 s from S7, S9 10..23 s from S8 |

Preparation:
- A boot-time controller start was refused at selection binding (`ApprovalRefused`, no state written; 21:57:52 journal). `/data` was remounted afterwards (tmpfs, same options before and after).
- The owner approved quarantining 5 boot-bound records (test scaffolding, not precedent), then renewed selection, time and approval and signed.
- Mask symlinks for the pair were `/dev/null` before the run.

T0 = `systemctl start --no-block azazel-activated.service`, controller pid 2565.

## 3. Timeline (seconds from T0, monitor at 4 Hz)

| T+ | Event | Stage / verdict |
|---|---|---|
| 0.006 | T0 returned (rc 0); controller `activating/start`; helpers `inactive`, `masked` | |
| 0.012 | `/proc` evidence for controller pid 2565 | R1 literal |
| 5.5 | grant `pair_grant_intent` | S1 OK (5.5 s; expected 6..9, tol 4.2..11.7) |
| 9.0 | prior-boot journal retired (`closed` -> None) | retirement path |
| 10.5 / 14.0 | journal `intent` / `partial` | |
| 12.25 / 15.5 | auditd overlay file (2106 B) / commissiond overlay file (2299 B) | |
| 17.25 | journal `published` | S2 OK |
| 19.0 | both helpers `LoadState=loaded` (Reload #2) | S3 OK |
| 20.75 | grant `pair_grant_opened` | |
| 22.5 | controller `active/running` (READY=1) | S4 OK |
| 29.26 | first heartbeat, gap 6.66 s | S5 OK (+6.8 s from S4) |
| 30.75 | grant `auditd_start_intent` | |
| 39.75 | `azazel-auditd.service` `active/running`, pid 3990; `/proc` evidence | S6 OK (+17.3 s from S4) |
| 40.76 | tree note: `/var/lib/azazel/run/audit/audit.sock` changed | helper-declared path |
| 49.0 | grant `auditd_ready`; ledger `2026-10-16.jsonl` appears (370 B) | genesis |
| 49.25 | grant `audit_intent_recorded`; ledger 1524 B | S7 OK (+9.5 s from S6; expected 9..15) |
| 51.25 | ledger 1919 B | |
| 52.75 | grant `commissiond_start_intent` | |
| 56.76 - 62.76 | heartbeats 11-14, gaps 7.81 / 2.00 / 2.08 / 2.09 s | |
| 63.0 | `azazel-commissiond.service` `active/running`, pid 4716; overlay files emptied (0 B), helpers `masked`; journal `closing`, grant `closing`; ledger 2285 B | S8 reached at S7 + 13.8 s: EARLY (expected 27..42; the monitor labels it EARLY, not a failure) |
| 63.25 | auditd and commissiond `inactive/dead` (both helpers stopped) | containment |
| 63.76 | tree note: `/var/lib/azazel/run/commission/commission.sock` added | helper-declared path |
| 64.25 / 66.5 | journal `withdrawing` / `closed` | |
| 63.1 - 67.0 | Reloads #3..#15 (total 15) | |
| 67.0 | controller `failed`, `Result=exit-code`, status 1; grant `closed` | monitor: controller left active unexpectedly |
| 67.27 | controller journal: `UnitOperationFailed: loaded bootstrap observation refused: dependencies` | |

Journal times (host clock): auditd `Started` 22:48:19.35; commissiond `Started` 22:48:42.58; commissiond and auditd `Stopped` 22:48:42.87 (both within 0.3 s of the first Reload after commissiond start); controller failure line 22:48:46.63.

After the refusal line, `az-activated` logged a traceback (`Future exception was never retrieved: BrokenPipeError(32, 'Broken pipe')`) from `bootstrap_manager.start_and_wait` -> `_start_bound_commission`. It appears after containment, did not change the outcome, and is recorded here as a cleanup-path observation for follow-up, not diagnosed.

## 4. End state

- Overlay directory empty of owned files (`overlay-journal.json`, `owned_files: []`, phase `closed`, bound to this boot).
- Grant for this boot `closed`: `close_evidence_digest` set, `recovery_evidence_digest` null, `audit_receipt_digest` set. Prior-boot grant (`b62b58f7-...`) also `closed`, `recovery_evidence_digest` null.
- Controller `failed` (`Result=exit-code`, status 1); helpers `inactive`, `LoadState=masked`.
- Audit ledger `/var/lib/azazel/state/audit/2026-10-16.jsonl`: 2285 B, 6 records (as reported by the operator; the tar holds the file listing and sizes, not the record bodies):
  1. `bootstrap.grant_intent`
  2. `bootstrap.controller_ready_intent`
  3. `bootstrap.start_intent` (auditd)
  4. `bootstrap.ready` (auditd)
  5. `bootstrap.start_intent` (commissiond)
  6. `bootstrap.stopping` (written during containment)
- Reload count 15. One-use marker `/run/azazel-nexus-bootstrap/controller-used` consumed: no second start in this boot.
- Tree changes beyond the earlier four: `audit.sock` removed, `commission.sock` added, the ledger file, and the bootstrap state files. No change in `/opt/azazel-nexus`, `/etc` units or the venv was observed.

## 5. B1 and R1 cgroup literals

| Unit | Source | `/proc/<pid>/cgroup` literal |
|---|---|---|
| azazel-activated.service | pid 2565, T+0.012 | `0::/system.slice/azazel-activated.service` |
| azazel-auditd.service | pid 3990, T+39.756 | `0::/system.slice/azazel-auditd.service` |
| azazel-commissiond.service | pid 4716, T+63.121 | captured in `run/cgroups.log` (cited by name) |

Auditd observations: uid/gid 996/985, `CapEff` zero, as in run 3. Raw observations; not an acceptance of any peer proof beyond the controller-side result in section 1.

## 6. Diagnosis (orchestrator; to be confirmed by an owner-approved fix)

- Once commissiond is loaded and active (no longer garbage-collected), systemd reports auditd's in-pair inverse edges toward commissiond: `Before`, `RequiredBy`, `BoundBy`.
- Design O1 pinned those three properties as EMPTY, because they are unobservable while the peer is inactive. The O1 review noted that any appearance fails closed. This is that case; the refusal is the designed fail-closed behaviour, and the expectation is not start-state-aware.
- Proposed direction: a start-state-aware expectation for the three auditd properties: accept empty, or exactly `{azazel-commissiond.service}`, nothing else. Not implemented or reviewed here.
- The diagnosis is the orchestrator's reading; the raw property values at refusal time are not in the tar (the refusal label names the class only).
- Monitor tolerances held for S1-S7. S8 arrived early (S7 + 13.8 s, earlier than estimated); the cause is not analysed here, and the S8 tolerance should be revisited after a run that gets past this refusal.

## 7. Next steps (owner decision pending)

1. Owner decision on the start-state-aware dependency expectation (code change plus review), then rebuild.
2. A quarantine / revert decision for the ledger (it now holds genesis and 6 records; snapshot or quarantine-revert only), then reboot, new records and approval.
3. One more real start (the one-use marker makes a second start in this boot impossible). Follow-up: the post-containment `BrokenPipeError` traceback.

Until the owner decides: no retry in place; the VM keeps the failed controller, pair masked, ledger non-empty.
