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
| `HG-04` | An operator can complete commissioning on a real host without hand-editing anything | `hardware-unverified` |

## `HG-01` — installation leaves nothing running

**Claimed.** After `packaging/install.sh`, `azazel-commissiond`, `azazel-auditd`
and `azazel-watchdog` are masked and disabled, and no operational network
service has started (`IMPLEMENTATION_SPEC.md` §2.3).

**What CI executed.** `tests/unit/test_packaging.py` reads the installer and
the preset as text: it checks that every governed unit is masked, that nothing
is started, that the single enabled unit is the activation controller, and
that the preset disables the rest. `tests/unit/test_runtime_hardening.py`
checks the unit files against the declaration they are generated from, by
value rather than by the presence of a word: the account each runs as, its
allowed address families, its writable paths against the filesystem layout,
an empty capability bounding set, `IPAddressDeny=any`, and the runtime
directory's mode against the socket directory's.

**Why that is not the claim.** The installer was never run. A `systemctl mask`
that fails, a distribution preset that re-enables a unit on the next
`preset-all`, a unit file rejected by a systemd version older than the one
these files were written against, a `RestrictAddressFamilies` the running
systemd silently ignores — none of those are visible to a text scan. What the
checks above establish is that **the distribution does not contradict
itself**, which is a different and smaller claim than that the host enforces
any of it.

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

Since #42 the accounts are separate and declared — `azcommission`, `azaudit`,
`azwatch`, and `root` for the activation controller alone — so the experiment
is now well defined. It has not been run.

## `HG-03` — an observation interface transmits nothing

**Claimed.** Outside the bounded `ASSET_ACQUISITION` state, an interface in an
observation role emits zero frames (`docs/commissioning.md` §5).

**What CI executed.** Nothing. No test in this repository touches an
interface.

**What would settle it.** A span port or a second host counting frames, across
link flap, suspend/resume and a driver reload, with the counter read on the
observing host rather than on the node under test. A frame count reported by
the node that is supposed to be silent is the node grading its own silence.

## `HG-04` — commissioning completes on a real host

**Claimed.** `azazel-nexus commission` takes an operator from an installed
node to a commissioning record without hand-editing a file (#29).

**What CI executed.** The wizard, end to end, against captured `sysfs` trees
and a scripted operator: role confirmation, the set confirmation, the
refusals, and the record it writes. Since #38, also the netlink parser,
against a real `RTM_GETLINK` dump and constructed malformed ones.

**Why that is not the claim.** An interface may carry a role only if its
permanent MAC is readable (`docs/commissioning.md` §3: a current or cloned MAC
must never resolve an assignment). Whether a given driver reports one is a
property of that driver and that NIC, and no amount of parsing establishes it.

**Status change at #38.** The route is now implemented: `az-commissiond` reads
`IFLA_PERM_ADDRESS` from an `RTM_GETLINK` dump over netlink, which needs
neither `CAP_NET_ADMIN` nor an internet address family. The gate moves from
`blocked` to open — there is a mechanism now, and it has not been run on the
target hardware.

**One observation, recorded as one observation.** The mechanism was exercised
once, on the container this repository was developed in: of four interfaces,
the virtio NIC reported a permanent address and the loopback and two ifb
devices did not. That is why
`tests/fixtures/netlink/rtm_getlink_dump.bin` contains both cases.

It is evidence that the code talks to a Linux kernel correctly. **It is not
evidence about a rugged PC**, whose NICs are different hardware with different
drivers, and it does not close this gate. One virtualised NIC answering is one
virtualised NIC answering.

**What would settle it.** `az-commissiond` running under its own account on
the target hardware, reporting a permanent address for each NIC that must
carry a role, followed by a commissioning run whose composite identities
survive a reboot that renames the adapters. Record the kernel version with the
result: `IFLA_PERM_ADDRESS` arrived in Linux 5.6, and a driver may omit it at
any version.
