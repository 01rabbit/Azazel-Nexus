# Bootstrap third real start of azazel-activated.service (build 5652d7f) - run record

Date: 2026-10-16. Status: the real `azazel-auditd.service` was started and STAYED active (the `WatchdogUSec` fix held). The monitor then applied its own stop condition 1 (stage S7 later than tolerance) and sent the controller-first SIGTERM at T+47.5. The controller refused the start as cancelled, contained the pair and exited 1. No genesis. Contained. The stop was a monitor tolerance artifact, not a product refusal.
Raw outputs (realstart-out3 tar: before/after listings, `run/events.log`, `run/timeline.log`, `run/cgroups.log`, PID 1 / unit / full journals, monitor state, journal window, diagnosis README) are retained in the operator's scratch area; this record cites them by name only.
Related: `docs/evidence/bootstrap-second-real-start-2026-10-16.md` (run 2, c822c9b), `docs/evidence/bootstrap-first-real-start-2026-10-16.md` (run 1, ee5cdd2), `docs/evidence/bootstrap-qualification-q4r4-ee5cdd2-2026-10-16.md`.

## 1. What this is, and what it is not

Reached for the first time on a real host (test VM):
- a helper that stays active after its start (`azazel-auditd.service` `active/running`, pid 4738, no refusal after the post-start retained checks);
- an operator controller-first SIGTERM delivered during a helper start, with full containment (first real-host exercise of that path during a start).

Reached before (runs 1 and 2): real READY, real heartbeats, real `StartUnit` of auditd.

Not reached: auditd readiness / peer proof acceptance, genesis, commissiond start, steady both-helper loop, clean exit-0 stop after steady state, deadline expiry.

- The stop was triggered by the monitor's Gate A S7 tolerance (limit T+47.3 s), which underestimated the start path (section 7). The controller was healthy and on the expected path; it was not stuck and did not refuse.
- Approval is synthetic (test VM only). VM only; not a hardware result. Issue #93 remains open.

## 2. Setup (as observed)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257 |
| Product build | 5652d7f (`WatchdogUSec` fix on top of c822c9b) |
| Boot | `b62b58f7-19fb-4cda-bb0f-86cc7c51298b` |
| Loaded-units record | `sha256:305fc910...` (unchanged from runs 1 and 2; digest as reported by the operator, not re-derivable from the tar) |
| Installed-files | `sha256:3a7fdae8...` (`/etc/azazel/bootstrap/installed-files.json`, matches `before/digests.txt` and `after/digests.txt`) |
| Approval payload | `sha256:a510e67b...` (synthetic, owner-signed; matches `after/sums.txt` and the grant / initial records) |
| Preflight | 0 failures (as reported by the operator) |
| Substitutions | none: real inspector, real sd_notify, real manager, real start bridge |

Preparation: the owner approved another records-free quarantine (17 files moved, nothing deleted, test VM only; test scaffolding, not precedent) and a reboot into the boot above. Mask symlinks for all seven non-pair units point to `/dev/null` before and after. Monitor settings: heartbeat alert gap 28 s, Reload limit 40.

T0 = `systemctl start --no-block azazel-activated.service`, controller pid 3321.

## 3. Timeline (seconds from T0, monitor at 4 Hz)

| T+ | Event | Stage / verdict |
|---|---|---|
| 0.006 | T0 returned (rc 0); controller `activating/start`; helpers inactive, `masked` | |
| 0.013 | `/proc` evidence for controller pid 3321 | R1 literal |
| 5.25 | grant `pair_grant_intent` | S1 OK (5.3 s; expected 6..9, tol 4.2..11.7) |
| 10.5 / 13.75 | journal `intent` / `partial` | |
| 12.0 / 15.25 | auditd overlay file (2106 bytes) / commissiond overlay file (2299 bytes) | |
| 17.0 | journal `published` | S2 OK |
| 18.75 | both helpers `LoadState=loaded` (Reload) | S3 OK (18.8 s) |
| 20.5 | grant `pair_grant_opened` | |
| 22.25 | controller `active/running` (READY=1) | S4 OK (22.3 s, within 30 s) |
| 29.0 | first heartbeat, gap 6.64 s | S5 OK (+6.8 s from S4) |
| 30.5 | grant `auditd_start_intent` | |
| 33.76 / 35.51 / 37.51 / 39.26 | heartbeats 2-5, gaps 4.97 / 1.76 / 1.87 / 1.87 s | |
| 39.5 | `azazel-auditd.service` `active/running`, pid 4738; `/proc` evidence captured | S6 OK (+17.3 s from S4; expected 10..25) |
| 39.76 | tree note: `/var/lib/azazel/run/audit/audit.sock` changed | helper-declared path |
| 41.26 / 43.26 / 45.0 / 46.76 | heartbeats 6-9, gaps 1.93 / 1.84 / 1.84 / 1.85 s | auditd stays active |
| 47.5 | monitor: `FAIL: stop condition 1: stage S7 later than tolerance (limit T+47.3 s)` (no ledger record yet) | owner decision D4 |
| 47.509 | monitor: `systemctl kill --kill-whom=main -s TERM azazel-activated.service` (rc 0) | operator stop, controller-first |
| 48.5 | journal `closing`, grant `closing`; overlay files emptied; helpers `masked` again | containment |
| 48.75 | auditd `inactive/dead` (about 1.2 s after SIGTERM) | |
| 49.0 - 52.5 | Reloads #3..#15 (total 15, limit 40); journal `withdrawing` at 49.75; auditd overlay file unlinked at 51.0 | |
| 52.0 | journal `closed` | |
| 52.5 | controller `failed`, `Result=exit-code`, status 1; grant `closed` | |
| 52.77 | controller journal: `ApprovalRefused: bootstrap start cancelled` | |

Journal times (host clock): auditd `Started` 21:40:13.56; SIGTERM sent 21:40:21.66; auditd `Stopped` 21:40:22.83; controller exit 21:40:26.42. SIGTERM to fully closed is about 5 s. The controller consumed 48.9 s CPU over a roughly 52 s life.

## 4. End state

- Overlay directory empty of owned files (`overlay-journal.json` remains with `owned_files: []`); journal `closed`, bound to this boot; grant for this boot `closed` with close evidence present (`close_evidence_digest` set) and `recovery_evidence_digest` null; `audit_receipt_digest` null.
- Controller `failed` (`Result=exit-code`, status 1, `ApprovalRefused: bootstrap start cancelled`); helpers `inactive`, `LoadState=masked`, mask symlinks `-> /dev/null`.
- Audit ledger (`state/audit`): EMPTY (0 entries). No genesis.
- Reload count 15. The one-use marker (`/run/azazel-nexus-bootstrap/controller-used`) is consumed, so no second start in this boot.
- No refusal, retry, EACCES or peer-proof line from `az-activated` or `azazel-auditd` anywhere in the journal window; auditd logged nothing.

## 5. B1 and R1 cgroup literals

| Unit | Source | `/proc/<pid>/cgroup` literal |
|---|---|---|
| azazel-activated.service | pid 3321, T+0.013 | `0::/system.slice/azazel-activated.service` |
| azazel-auditd.service | pid 4738, T+39.506 | `0::/system.slice/azazel-auditd.service` |
| azazel-commissiond.service | never started | not captured |

Auditd observations from `run/cgroups.log`: uid/gid 996/985, `CapEff` and `CapBnd` all zero, `NoNewPrivs` 1, `Seccomp` 2, cmdline `/opt/azazel-nexus/venv/bin/python -IS /usr/libexec/azazel/az-auditd`. Raw observations; not an acceptance of the peer proof.

## 6. Tree changes outside the Gate A four

`/run/azazel` (controller RuntimeDirectory) and `/var/lib/azazel/run/audit/audit.sock` (helper-declared) were recorded as tree notes. Neither is a stop condition. The socket path should be in the declared-path list in the next Gate A revision. No change in `/opt/azazel-nexus`, `/etc`, unit directories or the venv was observed (installed-files and unit digests identical before and after).

## 7. Diagnosis

Source: diagnosis README (diag3) in the scratch area, based on the journal window, `run/timeline.log`, `run/events.log` and the after-state records. Verdict: healthy and on the expected path; slower than the Gate A estimate, not stuck, not looping.

- Heartbeats are emitted only from `check_start` and the steady loop, so one heartbeat is one completed full check (about 1.7-1.9 s of CPU: installed-files hashing and retained-publication checks). The supervisor was still inside `_start_helper(AUDITD)` running the 5 post-`StartUnit` `check_start` calls that the Gate A estimate omitted (9 checks per helper start: 4 before `StartUnit`, 5 after). The 9th-10th check was running at SIGTERM.
- Expected genesis at about S6 + 10..11 s (range S6 + 9.5..12.5), versus the Gate A assumption of S6 + 3..6 s. The abort at S6 + 8.0 s was 2-3 s before the earliest expected genesis.
- SIGTERM during a start checkpoint is the designed outcome: SIGTERM only sets an event; `_start_checkpoint` turns it into `ApprovalRefused("bootstrap start cancelled")`; the transaction closes (journal `closing`, containment, grant `closed`); `main` prints the failure line and returns 1. No `bootstrap.stopping` record is written because the live audit session does not exist yet. Exit 0 "stopped after confirmed containment" is expected only in steady state or an early-return window. Exit 1 here is not a containment failure.
- Notice latency of SIGTERM is up to one check (about 1.9 s in the start phase).

Recommended tolerances for the next Gate A revision (estimates from the same per-operation costs):

| Stage | Expected | Stop at |
|---|---|---|
| S7 (genesis record) | S6 + 9.5..12.5 s | S6 + 20 s (or absolute T+62) |
| S8 (commissiond active) | S7 + 27..38 s | S7 + 55 s |
| S9 (steady loop) | S8 + 10..16 s | S8 + 30 s |

Steady heartbeat gap is about 13.5 s (alert at 28 s stays safe; WatchdogSec 30 s). Progress-based stopping is recommended over fixed times: continue while heartbeats arrive with gaps up to about 15 s and grant phase / `checkpoint.json` advance; stop on a missing heartbeat, a failed unit, or the S limits. The total bootstrap deadline is 2530 s, so there is no code-side budget pressure. The cost lever (code, not this run) is the 9-10 full checks per helper start.

## 8. Next steps (owner decision pending)

1. Gate A revision: apply the tolerances above (or progress-based stopping), add `audit.sock` to the declared paths.
2. No product change is indicated by this run. Optional later optimisation: reduce redundant full checks per helper start.
3. Then: a records quarantine and reboot, new records and approval, and one more real start (the one-use marker makes a second start in this boot impossible).

Until the owner decides: no retry in place; the VM keeps the failed controller, pair masked, ledger empty.
