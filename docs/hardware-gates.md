# Hardware-unverified gates

**No green CI run satisfies SO-01 or SO-10.** Both are hardware-only; see
[service objective records and field procedures](service-objectives.md) for the
10 cold-boot samples and 3 independent-device capture runs required at R7.

Some claims this repository makes cannot be established by anything CI runs.
A green pipeline on a GitHub runner is evidence about Python, and about
nothing else. This file is the register of what is still owed, so that a
simulated result is never quietly read as a measured one.

The rule the register exists to keep: **a passing test is evidence for what it
executed.** A test that constructs a `systemctl` argument vector is evidence
that the argument vector is right. It is not evidence that systemd masked
anything, that a unit refused to start, that an observation interface emitted
zero frames, or that the node booted inside a time budget.

The [campaign](hil-campaign.md) fixes ownership and execution order;
[HIL evidence records](hil-evidence-records.md) separates field records from CI.
No gate state changes in this preparation.

Every gate names four things: what is claimed, what CI actually executed, why
that is not the claim, and what would settle it.

## What "the target hardware" means here

Every gate below says a claim would be settled on *the target hardware*. For
Nexus that is **a generic rugged x86_64 Linux PC, at the resource class
actually deployed** — not a named model, and not any particular vendor's box.
The gates are per class, not per machine: what settles a class is a run on a
host of that class, and a run on one class says nothing about another
([`inheritance-ledger.md`](inheritance-ledger.md) §1 holds the product
boundary).

**Constrained and Raspberry-Pi-class devices are Azazel-Edge's proving
ground, not Nexus's target.** A result from one of them, or from a developer's
laptop or workstation, may be useful while building the harness. It is **not**
evidence for any gate here, and in particular it is never evidence for a
provider admission: the reserve it would measure is a different machine's.
Recording such a run as a gate result would be the exact substitution this
register exists to prevent — a simulated result read as a measured one, with
the extra hazard that it looks like hardware.

All HIL record kinds and their campaign run envelopes apply the
[virtualization negative filter](hil-evidence-records.md#tools-and-trust).
Observed virtualization (including VMware, Apple Virtualization, KVM or a
container), missing observations and unknown signals cause refusal even with
a valid operator signature. A clear filter is no physical attestation and
closes no gate. Lab schemas and lab-domain signatures are refused by production
readers; VM results remain development references only.

| Gate | Claim | State |
| --- | --- | --- |
| `HG-01` | Operational units are masked after installation and stay masked until activation | `hardware-unverified` |
| `HG-02` | No component other than the activation controller can unmask a unit on a running host | `hardware-unverified` |
| `HG-03` | An observation-role interface transmits zero frames across link flap, resume and driver reload | `hardware-unverified` |
| `HG-04` | An operator can complete commissioning on a real host without hand-editing anything | `hardware-unverified` |
| `HG-05` | A local cognition provider's memory need fits the envelope, after the Core reserve | `unmeasured` |
| `HG-06` | The decoy bridge actually refuses to forward to protected, management, control-plane and Internet zones | `hardware-unverified` |
| `HG-07` | A real Edge Core package on a real host verifies, answers its health contract and runs | `hardware-unverified` |

## `HG-01` — installation leaves nothing running

**Owner issue:** #115 pilot; #4 campaign parent. **Procedure:** [installation runbook](hil-runbooks/hg-01.md).

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
an empty capability bounding set (except the root controller, whose bounding set is exactly `CAP_DAC_READ_SEARCH` with `SupplementaryGroups=azazel-operator` and empty `AmbientCapabilities`), `IPAddressDeny=any`, and the runtime
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

**What the integration run adds (#43).** `tools/e2e.py` runs `install.sh` for
real against a prefix and checks the directories it creates against the
layout. On a host without a running systemd it reports the service-manager
stage `not_executed`, with the reason, and does not count it as a pass. See
[integration evidence](integration-evidence.md).

## `HG-02` — the privilege boundary on a running host

**Owner issue:** #115 pilot; #4 campaign parent. **Procedure:** [expected-refusal runbook](hil-runbooks/hg-02.md).

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

**What would settle it.** On the target image, use each package-created daemon
account to attempt `systemctl unmask` against a verified masked target, with
**refusal as the expected outcome**. Read back the mask after each attempt.
The linked runbook specifies noninteractive identity switching, invalid-test
conditions and root-console stop/disable/re-mask recovery if it succeeds.

Since #42 the accounts are separate and declared — `azcommission`, `azaudit`,
`azwatch`, and `root` for the activation controller alone — so the experiment
is now well defined. It has not been run.

**Since #196 P1** the governed set has two more units. The record validator
expects every non-root governed daemon exactly once, so a record captured
before P1 (no `azdecoy` attempt) no longer conforms: HG-02 is to be captured
afresh. The decoy network helper (`azazel-decoy-netd.service`) runs as root
and is not an HG-02 subject; it is kept from the service manager by its
sandbox: `RestrictAddressFamilies=AF_NETLINK` (no `AF_UNIX` socket) and
`InaccessiblePaths=` over `/run/dbus/system_bus_socket` and
`/run/systemd/private`, which the decoy-sandbox gate is to observe (its
AppArmor profile's `deny` rules for the two sockets are defence in depth
only: on Debian 13's kernel they did not refuse a path connect, G4 on a VM,
[grant design §7](deception-exposure-grant.md#7-lsm-apparmor-as-a-gate-f6))
([prerequisites §10](deception-redirect-prerequisites.md#10-p1-as-implemented)).
Since #196 option (a) the decoy namespace unit (`azazel-decoy-nsd.service`)
is a second root unit and likewise not an HG-02 subject: like the helper it
has netlink as its only address family (`RestrictAddressFamilies=AF_NETLINK`),
so no socket that could reach the service manager, and it has no file-system
sandbox at all (a mount namespace would keep its namespace handle from the
host). It adds no account, so it changes no HG-02 record; the decoy-sandbox
gate observes it with the helper.

## `HG-03` — an observation interface transmits nothing

**Owner issue:** #17 / SO-10, linked by #4. **Procedure:** [SO-10 field exercise](service-objectives.md#so-10-field-exercise--hardware-only), with driver reload added for HG-03.

**Claimed.** Outside the bounded `ASSET_ACQUISITION` state, an interface in an
observation role emits zero frames (`docs/commissioning.md` §5).

**What CI executed.** Nothing. No test in this repository touches an
interface.

**What would settle it.** A span port or a second host counting frames, across
link flap, suspend/resume and a driver reload, with the counter read on the
observing host rather than on the node under test. A frame count reported by
the node that is supposed to be silent is the node grading its own silence.

## `HG-04` — commissioning completes on a real host

**Owner issue:** #115 pilot; #4 campaign parent. **Procedure:** [commissioning runbook](hil-runbooks/hg-04.md).

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

## `HG-05` — the Core reserve

**Owner issue:** #115 8 GiB pilot; #4 campaign parent; #100 admission consumer; #68 downstream consumer. **Procedure:** [reserve procedure](core-reserve-measurement.md#5-the-procedure) and [campaign validation](hil-evidence-records.md#tools-and-trust).

**Claimed.** Nothing, yet. That is the point of this entry.

`docs/mio-runtime.md` §3 requires a local model provider to pass a *"resource
envelope sufficient for the declared memory need, **after the Core reserve**"*
gate. Deciding that needs a number. Nexus does not have one:

> Whether that class can carry a given workload is decided separately and
> remains subject to the measured Core reserve, which is not yet measured for
> Nexus. An implementation MUST NOT treat the selected profile as evidence
> that a capability fits.
> — `docs/IMPLEMENTATION_SPEC.md` §2.1

**What CI executed.** `tests/unit/test_cognition.py` runs the admission gates
in order and asserts that the resource gate **refuses**, in every envelope
including `standard`, with a reason naming this gate. That is evidence the
refusal is deliberate and reached. It is not a measurement.

Since Nexus#68 the path a measurement would travel is built and driven:
`core_reserve.py` holds the record schema, the validation and the derivation;
`az-core-reserve-probe` is the harness; `tools/e2e.py` drives the three states
(no record, a fixture record, a record shaped like a measurement) end to end.
**None of that is a measurement either** -- it is the machinery around a
number that does not exist, and `test_no_measurement_is_committed_anywhere`
offers every JSON file in the distribution to the reader and fails if one is
accepted as a measured record. [The measurement
procedure](core-reserve-measurement.md) is the run that would close this row.

**Why that is not the claim.** The Core reserve is what the node itself needs
before any optional workload: the arbiter, audit, the lease journal, evidence
capture, the operator plane, and the kernel's own working set under load. It
is measured by running the node, not by reasoning about it. A number chosen
here would be an invented measurement wearing a threshold's clothes — and
because it gates whether a model is admitted, an optimistic one would admit a
provider onto a host that then sheds the work the reserve exists to protect.

**What follows while it is open.** Every local model provider is refused at
the resource gate, so the node sits at `CORE ONLY` for a *resource* reason
with the asset, topology and trust dimensions reporting independently. That is
the required behaviour rather than a defect: the deterministic path continues
unchanged, and M.I.O. says it is unavailable rather than implying scarcity it
has not measured.

**What would settle it.** The node running on a generic rugged x86_64 Linux
PC -- see *What "the target hardware" means here* above -- under load with
audit, evidence capture and the lease journal active, and the resident set
that configuration needs measured across the 8, 16 and 32 GB classes -- since
the reserve is not a single number if it scales with retention and
concurrency, which `IMPLEMENTATION_SPEC.md` §2.1 says it does.

Three classes here, against the *four* — 8, 16, 32 and 64 GB — that
[capability model](capability-model.md) §2 and [support matrix](support-matrix.md)
name. That is not a restatement with different numbers, which those documents
forbid: they are counting different measurements. Performance and retention
targets are recorded per memory class, and 64 GB is one. The Core reserve is
keyed by the **selected profile**, and the selector has three floors -- a
64 GB host selects `standard` exactly as a 32 GB host does, so a fourth
reserve would be a second record for one profile.
[The measurement procedure](core-reserve-measurement.md) §5 is that run, step
by step: which subsystems must be active, under what load, how many runs per
class, and what makes the result admissible.

Until then this row stays `unmeasured`. That is a different word from
`hardware-unverified` on purpose -- the others have a mechanism that has not
been run on the target. **This one now has a mechanism too**, and still no
number: the harness has never been run on target hardware, and running it
here would measure a CI runner. The word stays `unmeasured` because what is
missing is the measurement, not the means of taking it.

## `HG-06` — the decoy bridge refuses to forward

**Owner issue:** #4, explicit child work (child issue number unassigned). **Procedure:** [isolation runbook](hil-runbooks/hg-06.md).

**Claimed.** Nothing, yet.

`docs/IMPLEMENTATION_SPEC.md` §9 is unusually specific about what has to
happen before a Lite decoy may be reached:

> Lite containers live only on `az-decoy0`; a host firewall and namespace
> rules deny forwarding to protected, management, control-plane, and Internet
> zones. **The isolation check MUST actively test denied paths on boot and
> before a redirect is eligible.** A failed check immediately removes all
> redirect eligibility.

*Actively test* is the load-bearing phrase. A rule that is present in a
ruleset is not a packet that failed to cross.

**What CI executed.** `tests/unit/test_decoy.py` runs the lifecycle:
`DISABLED` until an operator commissioning, a verified generation and a
**passing** isolation check are all present; `ELIGIBLE` then, and `EXPOSED`
only when an operator exposes it. It asserts that an absent check, a failing
check, a check that tested no path, and a check with no timestamp each keep
the decoy disabled — and that `redirect_eligible` is `False` in every state
the module can produce.

That is evidence the *result* of an isolation check is consumed correctly.
`IsolationCheck.passed` is supplied to it.

**Why that is not the claim.** Nothing in this repository sends a packet. The
claim is about a kernel, a bridge, a namespace and a firewall on a real host
refusing to forward — four things a unit test cannot stand in for, and the
one thing that matters if a decoy is reachable by someone hostile. A test
that constructed an nftables rule would be evidence the rule is well-formed,
which is not evidence that anything was dropped.

**What follows while it is open.** `IsolationCheck(passed=None)` is the state
of every node this repository can produce, and it keeps every decoy
`DISABLED`. **Nobody looked is not a pass**, and it reads differently from a
failure: the first needs the probe run, the second needs the bridge fixed.

**What would settle it.** `az-decoy0` on the target hardware, with a decoy
container attached, and an attempted connection to a protected, management,
control-plane and Internet destination from inside it — each one observed to
fail, from inside the namespace, with the result recorded and the probe
re-run before every exposure rather than once at install.

## `HG-07` — a real Edge Core, verified on a real host

**Owner issue:** #4, explicit child work (child issue number unassigned). **Procedure:** [real-package runbook](hil-runbooks/hg-07.md).

**Claimed.** Azazel-Nexus can verify a locally installed Edge Core package —
presence, version, digest, health and running state — and claims
`edge-baseline-ready` only when all five hold
([Edge package verification](edge-package-verification.md),
[#44](https://github.com/01rabbit/Azazel-Nexus/issues/44)).

**What CI executed.** `tests/unit/test_edge_package.py` and the
`Edge package verification` stage of `tools/e2e.py` write packages into a
temporary directory — correct, truncated, mis-versioned, digest-mismatched,
posture-enforcing, signature-claiming — and assert each of the five checks
fails on its own word. The contract those packages are written against is the
one Azazel-Edge commits, copied into `contract/azazel-edge-core/` and asserted
field by field against the constants this node reads.

**Why that is not the claim.** Every package CI inspected was written by the
test that inspected it. None of them was produced by the Azazel-Edge packager
on a real build, installed by a real deployment, or answered by a real
`azazel-edge-core --health`. `az-edge-probed` now exists and CI exercises it
end to end, but with a **fake** health command and a **fake** unit reader: no
real binary and no real systemd has answered it. A round trip through a real
artifact could differ in file layout, permissions, the installed path, in
what systemd reports for the unit, or in the health report a running binary
actually prints.

**What would settle it.** An Edge Core package built by
`packaging/nexus-core/nexus_core_package.py` on Azazel-Edge, installed at the
fixed location on the target host, `az-edge-probed` run there against the real
binary with a real D-Bus connection, and `azazel-nexus status` reading the
result it wrote. Until that has happened on hardware, the software side is
`software-complete, hardware-unverified` and nothing more.

## Lab demonstration output

[Lab demonstration](lab-demonstration.md) output never satisfies a hardware gate,
model admission, acceptance, or production activation. VM output and
`azazel-nexus-lab/` artifacts remain lab material regardless of signatures.
The persistent `/etc/azazel-lab/LAB-HOST` marker narrows the host to refusals
(`LAB_HOST_MARKER`) at HIL preflight/capture, Core reserve probing, model admission,
commission, commission review, `model-import-fetched`, and bootstrap approval publication. Removing it grants nothing.
