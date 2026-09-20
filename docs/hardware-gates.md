# Hardware-unverified gates

Some claims this repository makes cannot be established by anything CI runs.
A green pipeline on a GitHub runner is evidence about Python, and about
nothing else. This file is the register of what is still owed, so that a
simulated result is never quietly read as a measured one.

The rule the register exists to keep: **a passing test is evidence for what it
executed.** A test that constructs a `systemctl` argument vector is evidence
that the argument vector is right. It is not evidence that systemd masked
anything, that a unit refused to start, that an observation interface emitted
zero frames, or that the node booted inside a time budget.

Every gate names four things: what is claimed, what CI actually executed, why
that is not the claim, and what would settle it.

| Gate | Claim | State |
| --- | --- | --- |
| `HG-01` | Operational units are masked after installation and stay masked until activation | `hardware-unverified` |
| `HG-02` | No component other than the activation controller can unmask a unit on a running host | `hardware-unverified` |
| `HG-03` | An observation-role interface transmits zero frames across link flap, resume and driver reload | `hardware-unverified` |

## `HG-01` — installation leaves nothing running

**Claimed.** After `packaging/install.sh`, `azazel-commissiond`, `azazel-auditd`
and `azazel-watchdog` are masked and disabled, and no operational network
service has started (`IMPLEMENTATION_SPEC.md` §2.3).

**What CI executed.** `tests/unit/test_packaging.py` reads the installer and
the preset as text: it checks that every governed unit is masked, that nothing
is started, that the single enabled unit is the activation controller, and
that the preset disables the rest. `SystemdUnitController`'s argument vectors
are checked against an injected runner.

**Why that is not the claim.** The installer was never run. A `systemctl mask`
that fails, a distribution preset that re-enables a unit on the next
`preset-all`, a unit file rejected by a systemd version older than the one
these files were written against — none of those are visible to a text scan.

**What would settle it.** Install on the target image, then read
`systemctl list-unit-files 'azazel-*'` and `systemctl is-active` for each
governed unit, plus a packet count on every interface across the install.
Record the systemd version with the result; the answer is version-specific.

## `HG-02` — the privilege boundary on a running host

**Claimed.** Only `azazel-activated.service` can unmask an operational unit.

**What CI executed.** `tests/unit/test_activation.py` proves the *design*
boundary in one Python process: `unmask_and_enable` refuses a call with no
controller-minted authorization, no `UnitController` subclass overrides the
guarded entry point, and no module in the package other than `activation.py`
references the widening verb or the token.

**Why that is not the claim.** In-process Python cannot withhold a privilege
from code running in the same interpreter as root. The enforcement boundary is
the operating system's: root-owned unit files, a controller that runs as root,
and daemons under their own non-login accounts (`IMPLEMENTATION_SPEC.md` §3).
None of that exists on a CI runner.

**What would settle it.** On the target image, run each daemon under its own
account and attempt `systemctl unmask` from it; record the refusal and the
account. Repeat after the accounts are created by the package, not by hand.

## `HG-03` — an observation interface transmits nothing

**Claimed.** Outside the bounded `ASSET_ACQUISITION` state, an interface in an
observation role emits zero frames (`docs/commissioning.md` §5).

**What CI executed.** Nothing. No test in this repository touches an
interface.

**What would settle it.** A span port or a second host counting frames, across
link flap, suspend/resume and a driver reload, with the counter read on the
observing host rather than on the node under test. A frame count reported by
the node that is supposed to be silent is the node grading its own silence.
