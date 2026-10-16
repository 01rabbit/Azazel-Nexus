# Bootstrap factory qualification: Q1 and Q2 on the Debian 13 test VM (2026-10-16)

Scope: test VM only (Debian 13 ARM64, systemd 257.13-1~deb13u1); not hardware evidence. The production factory is
unchanged and still refuses widening. Programme: `bootstrap-factory-switch-review-2026-10-16.md` section 3.

## Q1: read-only observation set against the installer-masked state (PASS, as predicted)
- Run inside a transient unit with the controller's exact sandbox (`systemd-run`, same `-p` set as the controller,
  `python -IS`, no bytecode). Bus calls: GetNameOwner, GetConnectionUnixProcessID/User, GetUnit, GetUnitFileState,
  ListJobs, Properties.Get/GetAll only. No LoadUnit, Reload, Start/Stop, Mask/Unmask. Zero files created (find
  before/after), zero `.pyc`.
- systemd profile `systemd-257.13-deb13-path-v1`: the observed digest equals the policy's
  (`sha256:999a0724…`); the loaded-units policy verified against the declared context (`sha256:d1e17e97…`).
- Results: prerequisites OK; masked pair with `/etc/systemd/system/*` fragments OK. As expected, the controller
  inspectors refuse (the unit is `failed`, one-use condition consumed), the start closure refuses (root
  `failed`), and the loaded-unit and masked-pair inspectors without fragments refuse because the masked helpers are not
  loaded (NoSuchUnit; GetUnitFileState=`masked`).
- Controller service properties equal the inspector's required values except `ControlGroup` (empty while not
  running). The helper properties cannot be compared until a publication loads them (Q4).

## Q2: overlay precedence over the installer mask (PASS)
- Fixture names only (`azn-q2-fixture-{a,b}.service`); never started; self-cleaning.
- With `/etc/systemd/system/<a> -> /dev/null`: LoadState=masked. With a 0644 unit added in
  `/run/systemd/system.control/<a>` and a reload, LoadState=loaded and FragmentPath points to the control file; the
  mask is unchanged; UnitFileState=static. `busctl LoadUnit` agrees. After unlinking the control file and reloading,
  LoadState=masked again.
- Cleanup: both fixtures not-found; no fixture files; no difference in `/etc/systemd/system`,
  `/run/systemd/system.control`, `azazel-*` unit files or enablement.
- Meaning: the product's publication into `/run/systemd/system.control` overrides the installer masks, and
  withdrawal plus reload restores them, on this systemd.

## Remaining
Q4 (real publish and withdrawal), Q5, Q7, Q8, Q6, Q3 and Q10, plus the code issues the Q9 trace flags (READY
checkpoint budget, operator-stop recording, overlay journal never removed).
