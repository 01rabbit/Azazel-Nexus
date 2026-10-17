# Bootstrap qualification Q4-R4 on build ee5cdd2 - run record (runs A and B)

Date: 2026-10-16. Status: run A refused at the loaded-unit property comparison (owner-tool defect, fixed); run B reached the READY point and stopped there by the D5 substitution, contained.
Raw outputs (harness.out, events.log, PID 1 journal, before/after state dumps, smoke output, measurement transcripts, diagnosis README) are retained in the operator's scratch area; this record cites them by name only.
Related: `docs/evidence/bootstrap-qualification-q4r4-2026-10-16.md` (earlier run on c79291b, refused at the dependency comparison), `docs/evidence/bootstrap-design-loaded-dependencies-2026-10-16.md` (option O1, implemented in this build).

## 1. Setup (as observed)

| Item | Value |
|---|---|
| Target | test VM, Debian 13, systemd 257.13 |
| Product build | ee5cdd2 (factory switch dc3e6fd + O1 ee5cdd2) |
| Substitutions | D5 (sd_notify disabled, stop at READY), D6 (in-memory `ActiveState` failed -> activating on the controller `GetAll(Unit)` reply only); D3 (stub controller inspector) status unchanged, see section 7 |
| Approvals | synthetic, VM only |

### 1.1 Records-free state (test scaffolding)

The VM had no clean snapshot. With owner approval (test VM only), all bootstrap records (17 files: `/etc/azazel/bootstrap/*`, `/etc/azazel/node.yaml`, bootstrap-generations/1, `state/bootstrap/*`, `state/bootstrap-overlay/*`) were moved with `mv -n` into a root-only quarantine, and the VM was rebooted to reach a records-free state. Nothing was deleted. This is test scaffolding, not a product path, and is in tension with the rule "never delete retained records"; it is recorded here so it is not read as precedent. It was done twice (before run A, and again before run B, each time with fresh owner approval).

Observation in the records-free state: the boot-time controller with no selection took the ordinary activation path and "completed safely: granted=0, withheld=7, reasons=no_generation", `Result=protocol`, appended `activation.jsonl` (sequence 11); all 7 product units stayed masked.

## 2. Loaded-unit measurement (design O1)

Tool: the reviewed fixture-name tool (`measure_loaded_units.sh`, builder `build_loaded_units.py` v2). First attempt failed inside the tool's host-unit query (`systemctl` needed `--` before `-.mount`); cleanup was still verified. After the fix the re-run gave `RESULT ok`, cleanup LoadState not-found for both fixtures, before/after snapshot IDENTICAL. Builder v2 output `loaded_policy_digest` `sha256:22d41742...`; the product decoder ACCEPTed it; 9 unit/property pairs differ from the old text-derived record.

## 3. Run A (build ee5cdd2, boot `c0f2c006-9528-4e69-87bd-e724eeb84610`)

Approval payload `sha256:18f02747...`. Harness `begin` epoch 1792134661; precondition `fresh`.

- Result: `RESULT outcome=unexpected detail=UnitOperationFailed(loaded bootstrap observation refused) <- UnitOperationFailed(loaded bootstrap property mismatch) process_seconds=23.102`.
- The dependency comparison (27 lists) PASSED this time; the refusal is at the property comparison (`runtime/src/azazel_nexus_runtime/bootstrap_loaded.py:70`). D6 substituted 2 times (`unit_reads=2`).
- Containment: journal closed, grant closed, both pair files withdrawn, units back to masked with `/etc/systemd/system` fragment paths (events.log).

### 3.1 Diagnosis (diag2, read-only fixture measurement)

Exactly one property differs, on both units: `WatchdogUSec`. Record value 0; systemd 257.13 reports infinity (18446744073709551615). All other compared properties matched (9 Unit props, 27 dependency lists, the Service props including TimeoutStartUSec=30000000, TimeoutStopUSec=10000000, RuntimeMaxUSec=2^64-1, and the six empty `*Ex` arrays; the `ExecStartEx` tuple passes the shape check).

Cause: the payloads declare no `WatchdogSec`; systemd 257 reports an unset watchdog as `USEC_INFINITY`. The owner tool derived `unset` as 0 from payload text (same class of error as `RuntimeMaxUSec`, which the tool already mapped to infinity). The product code is correct: `bootstrap_loaded.py:70` is a strict type and value compare, and `_service_policy` / `bootstrap_loaded_policy.py` accept any int in [0, 2^64) for `WatchdogUSec`. The controller unit's own `WatchdogUSec` (30 s) is unaffected.

Fix: owner tool only, no product change, no weakened comparison. `build_loaded_units.py:70` now maps unset to `INFINITY`. New record `sha256:305fc910...` (decoder ACCEPT); it differs from the previous one only in the two `WatchdogUSec` values. The approval, anchor and deploy inputs were regenerated.

## 4. Run B (build ee5cdd2, boot `42326adc-9164-4bf2-b736-593f5fa39f66`)

After the second full quarantine and reboot, records were re-placed; approval payload `sha256:c06e9a6c...`. START 2026-10-16T07:18:21Z (harness `begin` epoch 1792135101), harness rc 0, precondition `fresh`.

Result: `RESULT outcome=expected-stop-contained detail=Q4Stop(q4r4 harness: sd_notify is disabled) process_seconds=25.774`.

What the run shows:

1. Every real inspector accepted the really published pair: start closure (twice), publication prerequisites (twice), loaded-unit inspector for both units, and `retained_check`. D6 substituted 4 times (`unit_reads=4 substituted=4 untouched=0`), only the controller `ActiveState`.
2. The grant advanced to `pair_grant_opened` (events.log, 07:18:42Z). The run reached the READY notification and stopped there by the D5 substitution.
3. Containment withdrew the published pair (both files removed, masks restored, fragment paths back to `/etc/systemd/system`); journal `closed`; grant `closed` with confirmed withdrawal.
4. End state: `/run/systemd/system.control` empty; both helper units LoadState=masked, ActiveState=inactive; audit ledger directory empty; `controller-used` marker present (expected, one-shot per boot); 0 `Starting azazel-auditd/commissiond` lines in the journals; no helper started.

### 4.1 Timing (first measured pre-READY time)

From events.log and harness.out timestamps (epoch seconds):

| Point | Time since harness begin |
|---|---|
| last D6-substituted read (inspectors done) | 18.6 s |
| grant `pair_grant_opened` | 20.2 s (1792135122.04 - 1792135101.80) |
| containment start (`journal=closing`) | 21.9 s |
| `run-selected-bootstrap-end` / RESULT | 25.6 s / 25.8 s |

The harness-begin-to-READY time is about 20-22 s, under `TimeoutStartSec=30 s`, leaving roughly 8-10 s of margin. This is the first measured pre-READY time. The real controller adds process start-up (the harness `begin` follows interpreter start; smoke admission-verify alone took 1.42 s), so the margin in a real start is smaller than this figure suggests. Run A reached its refusal at 23.1 s total, in the same range.

### 4.2 Verify FAILs in run B (harness artifact)

The verify step reported 3 FAILs. They are a harness artifact: after the factory switch the factory builds `_PrototypeBootstrapManager` directly, so the harness's diagnostic subclass hook no longer intercepts and the open_pair-end, retained_check and stop-before-ready step lines are not printed. The behaviour is shown by the event-log grant transitions and the RESULT line (items 1-4 above), not by those step lines. The harness hook needs updating before another run relies on its verify rows.

## 5. Conclusion

With O1 and the corrected owner record, the previously never-run inspectors (start closure x2, prerequisites x2, loaded-unit for both units, retained check) accept the really published pair on the VM, and the pre-READY path completes in about 20-22 s of the 30 s budget. The only defect found in this series was in the owner measurement tool (`WatchdogUSec`), not in the product.

## 6. Cost of the findings

Run A's refusal confirms the design note's remaining risk class: a text-derived or implicit value that systemd normalises differently. `service_settings` are still derived from payload text in the tool; measuring them (and having the builder cross-check against payload text, refusing on disagreement) remains the better fix and is not done.

## 7. Limits

- VM only; synthetic approvals; D5 and D6 substitutions.
- The real controller inspector (D3 stub) is still not exercised.
- Not exercised: helper start, peer proofs against the product units, heartbeat, genesis on the real ledger, operator stop. Next step: the first real start.
- The quarantine-and-reboot scaffolding (section 1.1) is test-VM only and not a product path.
- Two runs, one VM, one systemd build (257.13). Irreversible per-boot state (marker, closed grant/journal) means another run needs a fresh boot and records-free or restored state.
