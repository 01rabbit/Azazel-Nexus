# Bootstrap factory qualification: Q4-R real publication and containment (test VM, 2026-10-16)

Scope: Debian 13 test VM, systemd 257.13; not hardware evidence. The production factory is unchanged.
Method: Q4 as specified (unmodified `open_pair` outside the real controller) is not feasible; see
`bootstrap-factory-switch-review-2026-10-16.md`. Q4-R ran the production `run_selected_bootstrap` in a transient
unit with the controller's sandbox. A `_PrototypeBootstrapManager` subclass published the pair and refused at
`confirm_controller_ready`, `start_and_wait` and `is_ready`. There were five declared in-process substitutions: D1
cgroup constant, D2 controller identity, D3 controller-inspector stub, D4 manager class, D5 sd_notify refused. Records
were the owner-signed synthetic test approval (payload sha256:83aad2e8…), not a deployment approval. The evidence is
Q4-R (D1-D5), not real-controller evidence.

## Observed (one run, 01:42Z, about 38 s)
- Admission, deadline retention, grant `pair_grant_intent` (+7 s).
- Publication, in order: journal `intent` (+19 s) → `azazel-auditd.service` file (+21 s) → journal `partial` → the
  commissiond file (+28 s) → journal `published` (+31 s). This confirms the journal-before-files ordering on the real host.
- Then the start-closure inspector refused ("start closure root policy differs"). Expected for Q4-R: the root
  controller unit was `failed` (not `activating`), because the harness is not the controller (D3 scope).
- Containment: `close_starts` truncated both owned overlay files to 0 bytes (journal `closing`, grant `closing`);
  both helpers LoadState=masked (UnitFileState `masked-runtime`, FragmentPath = the empty control file), inactive.
- **Defect found:** every `is_inactive` call failed. The generic `SystemdUnitCalls` unloaded-unit branch accepts only
  GetUnitFileState=`masked`, but a unit masked by the owned empty overlay reports `masked-runtime`. `_contain` could
  not confirm inactivity, skipped the withdrawal, raised `BootstrapContainmentFailed`, and the grant went to
  `recovery_required`. Emergency narrowing was unconfirmed.
- Never started (PID 1 journal has no "Starting azazel-auditd/commissiond"; InactiveExitTimestampMonotonic=0); audit
  ledger empty; no `.pyc`; `/etc` masks unchanged. Left behind: 0-byte overlay masks in `/run/systemd/system.control`
  (still masking), the journal in `closing`, the grant `recovery_required`, the marker. The VM needs a snapshot revert.

## Consequence and fix
With a real factory, any failure after publication would hit the same defect: containment would remain unconfirmed
even though the pair is masked and inactive. Fix (local, separately reviewed): `BootstrapNarrowingManager.is_inactive`
observes, under a confirmed fence, through `BootstrapStopJobs.observe_inactive`. That accepts an unloaded unit only
with the mask state its attested fragment implies (`/run/systemd/system.control` → `masked-runtime`, `/etc` →
`masked`) and NoSuchUnit on both reads; a loaded unit reports ActiveState. The generic unloaded rule is unchanged.

Not exercised: the published-pair `withdraw_pair` branch itself (containment stopped before it), loaded-unit and
start-closure inspectors against the published pair with an `activating` controller, peer proofs.
