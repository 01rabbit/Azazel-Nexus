# Bootstrap factory qualification: Q4-R re-run 3, timing after decode-once and checkpoint removals (test VM, 2026-10-16)

Scope: Debian 13 ARM64 test VM; not hardware evidence. The production factory is unchanged.
Purpose: re-run Q4-R (see `bootstrap-qualification-q4r2-2026-10-16.md`) against build c79291b, which adds ca26568..c79291b:
journal retirement primitives and call site, operator-stop Option C, READY budgets and heartbeat, `controller_stop_observed`,
decode-once (bd1e9a5) and checkpoint removals C1-C8 and C10. The main question is timing and checkpoint count; the
containment path is re-checked, not changed.
Method: unchanged. The production `run_selected_bootstrap` runs in a transient unit with the controller's sandbox; a
`_PrototypeBootstrapManager` subclass publishes the pair and refuses at `confirm_controller_ready`, `start_and_wait` and
`is_ready`. The five declared in-process substitutions D1-D5 apply (D1 cgroup constant, D2 controller identity, D3
controller-inspector stub, D4 manager class, D5 sd_notify refused). This is Q4-R (D1-D5), not real-controller evidence.
Raw outputs are retained in the operator's scratch area (harness.out, events.log, pid1-journal.txt, journal-all.txt, smoke.out,
before/after capture directories); they are not committed.

## Setup
- Snapshot revert, then boot_id `8c3dd0e1-89fd-4abc-8427-e1d3c304277f` (before/after `clock.txt`). Build c79291b installed by
  Phase 2g (orchestrator-reported); installed-files digest
  `sha256:401f60a96168aaa36ab5cfb41a2ecd17268c896b895c5d0b471e2f57d48b545e` (orchestrator-reported).
- Approval: a synthetic, owner-signed TEST approval, payload
  `sha256:2d6d3ffd16d73370c76aa66d91264fa64f750fbbd268879807f5d2e245e27f07`, granted 05:46:57Z, expires 06:31:57Z. It is
  **not** a real deployment approval. At run start (05:48:00Z, `before/clock.txt`) about 2637 s of approval remained.
- Owner records script: ran once, cleanly (orchestrator-reported; the previous run's double invocation did not recur).

## Smoke (read-only rehearsal)
`smoke.out`: cgroup-mount admission ok, overlay directories ok, identity ok, admission verify ok in **1.361 s** (previous run
1.865 s, about 27% faster), `RESULT outcome=smoke-ok` (rc 0).

## Observed (one run, started 05:48:00Z, process 23.110 s)
- Publication (events.log), in order: journal `intent` -> `azazel-auditd.service` file in `/run/systemd/system.control` (2106
  bytes) -> journal `partial` -> `azazel-commissiond.service` file (2299 bytes) -> journal `published`. `open_pair` took
  12.081 s with **7** publish checkpoints of 1.678-1.726 s (1.684, 1.678, 1.693, 1.684, 1.686, 1.688, 1.726; mean 1.691 s).
- The start-closure inspector refused again ("start closure root policy differs"; `RESULT outcome=unexpected
  detail=UnitOperationFailed(...)`, harness exit 10). Same harness artifact as the previous run (the harness is not the
  controller; D3 scope), not the designed Q4Stop point.
- Containment: `close_starts` truncated both files to 0 bytes (journal `closing`, grant `closing`); all 16 `is_inactive` calls
  returned without error. Withdrawal through the published `withdraw_pair` branch (3.643 s): journal `withdrawing`, files
  unlinked commissiond first then auditd, FragmentPath back to the `/etc` masks, journal `closed` with `owned_files=[]`, grant
  `closed`.
- Final state: both units `masked`/`inactive`, FragmentPath `/etc/systemd/system/<unit>`, no owned files. The operator's `verify`
  reported the grant closed and the close evidence equal to the recomputed digest with `grant_withdrawal=confirmed`
  (orchestrator-reported).
- Reload lines: 15 "Reload requested" entries from the harness PID in `pid1-journal.txt`, same as the previous run. The
  harness's own `reload-count.txt` files read 0 and 0 (its grep pattern does not match this journal's wording).
- Journal retirement: this was the same boot as the records, so the prior-boot journal retirement path was not exercised
  (the retire path is not reached by design in this run).

## Timing comparison

| Measure | Previous (58dfde1) | This run (c79291b) | Change |
|---|---|---|---|
| Smoke admission verify | 1.865 s | 1.361 s | about -27% |
| Publish checkpoints in `open_pair` | 12 | 7 | -5 |
| Per-checkpoint time | 2.311-2.342 s (about 2.32 s) | 1.678-1.726 s (about 1.69 s) | about -27% |
| `open_pair` | 28.131 s | 12.081 s | about -57% |
| `withdraw_pair` | 3.560 s | 3.643 s | unchanged within noise |
| Process total | 41.466 s | 23.110 s | about -44% |

Reading: the per-checkpoint and admission-verify reductions of about 27% are consistent with decode-once; the drop in
checkpoint count (12 to 7) is consistent with the checkpoint removals. The two effects multiply to the `open_pair` drop
(7 x 1.69 s = 11.8 s of 12.08 s; previously 12 x 2.32 s = 27.9 s of 28.13 s). Attribution to individual commits was not
isolated; only the combined build was measured.

Pre-READY estimate (ESTIMATE ONLY, not measured): if a full path performs 12 full checks at about 1.7 s each, that is roughly
20 s, plus the earlier steps (admission, publication setup, containment-independent work). READY is never reached in Q4-R
(sd_notify is substituted by refusal, D5), so no READY-time figure exists and this number must not be quoted as one.

## Verify
All checks passed except "no systemd jobs queued". The queued job was `apt-daily.service` (job 15589, a Debian timer unrelated
to Azazel; PID 1 journal shows "Starting apt-daily.service" at 14:48:20 local, during the run). Not a product finding.

## Conclusion
On this VM, build c79291b keeps the Q4-R containment result of the previous run (refusal after real publication, inactivity
confirmed, both files withdrawn through the published `withdraw_pair` branch, masks restored, grant closed with confirmed
withdrawal) while cutting `open_pair` from 28.1 s to 12.1 s and the process from 41.5 s to 23.1 s.

## Limits (not shown by this run)
- Test VM only; not hardware. Synthetic TEST approval; not a deployment approval.
- Reduced-fidelity harness with declared substitutions D1-D5. The real `BootstrapControllerInspector` against an `activating`
  controller is not exercised.
- The stop came from the harness artifact, not the designed Q4Stop point.
- READY, helper start, heartbeat, operator stop and deadline expiry were not reached; the READY budgets, heartbeat and
  operator-stop Option C code are not exercised by this run.
- Prior-boot journal retirement was not exercised (same boot).
- The production factory remains closed. Issue #93 remains open.
