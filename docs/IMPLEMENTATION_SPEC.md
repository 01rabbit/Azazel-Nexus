# Azazel-Nexus Implementation Specification

## 1. Status, scope, and invariants

This specification turns the architecture documents into implementation units for a generic rugged x86_64 Linux PC. Terms **MUST**, **SHOULD**, and **MAY** describe requirements, recommendations, and allowed options.

Status: **target contract**. It carries a package (`pyproject.toml`,
`src/azazel_nexus/`) with a deliberately empty required-dependency list, a unit
suite, and an exact **Azazel-Fabric pin as an optional extra** (`v0.9.0rc5`,
ADR-0001), consumed through one boundary module. One mapping is attested by
that boundary — capability/mode publication; every other contract mapping
remains a design assertion awaiting a conformance attestation, not verified
evidence. Nothing below is implemented or
verified here, and no statement in this document may be cited as implementation
evidence. Outstanding bootstrap work is
listed in
[contract ownership](contract-ownership.md) §6.

The baseline is a self-contained node. It MUST keep collecting evidence, evaluating signed policy, presenting deterministic explanations, auditing, and applying already supported bounded controls without cloud connectivity or external modules. AZ-04 and AZ-06 increase depth; they never provide the prerequisite for baseline operation.

The following authority rule is non-negotiable:

```text
Evidence -> evaluators -> Action Arbiter -> enforcement adapter
                    \-> M.I.O. / Knowledge / Deception (advisory or bounded capability)
```

Only `azazel-arbiterd` can create an enforcement intent. M.I.O., either Knowledge service, either Deception service, the UI, and remote services MUST use requests or advisories that the arbiter independently validates. No service may hold the arbiter signing key and an enforcement-adapter privilege at the same time.

This single-issuer rule is a **condition Nexus places on the Edge package it admits**, not a property already demonstrated upstream: Azazel-Edge currently contains two independent decision/enforcement paths and has not declared which is authoritative for the x86_64 profile. Nexus MUST NOT admit an Edge package that does not declare a single authoritative decision and enforcement boundary. See [inheritance ledger](inheritance-ledger.md) §4.2.

Shared contracts are owned by Azazel-Fabric. Nexus owns only what it performs
on the host: product admission, installation, commissioning, activation,
rendering, service confinement, storage layout, audit chain enforcement,
update, and recovery. Nexus MUST NOT define a local canonical form for a record
that crosses a product boundary. [Contract ownership](contract-ownership.md)
maps every record in this specification to Fabric or to Nexus, and marks which
Fabric contracts do not exist yet.

Edge, Knowledge, and Deception are consumed as released, signed packages behind
explicit adapters. Nexus MUST NOT vendor a product source tree, and MUST NOT
invoke or inherit Azazel-Edge's device-specific network installer, its NIC
fixed values, or its unit defaults; see
[commissioning](commissioning.md) §1.

Out of scope: any device-vendor-specific implementation and a cloud dependency for local protection.

## 2. Target platform, resource envelopes, commissioning, and admission

The reference OS is **Debian 13 / amd64**, fixed as the program's initial platform baseline ([program plan §15 OF-07](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md); adopted in [ADR-0002](adr/0002-debian-13-baseline.md)). systemd, nftables, `tc`, cgroup v2, TPM 2.0 tools and LUKS2 come from it, and no other distribution is a co-equal v1 support target. The implementation MUST support a headless console; a touchscreen is an optional presentation device.

### 2.1 Resource profile selection

The resource profile records measured capacity only. It MUST NOT enable any
capability by itself. One product-local selector reads usable RAM in **MiB
after firmware reservation** and produces exactly one value. That reading is the
selector's only input: the measured Core reserve MUST NOT be subtracted before
selection.

| Usable RAM (MiB, after firmware reservation) | Resource profile | Resource envelope permitted |
| --- | --- | --- |
| `< 7168` | `diagnostic` | diagnostics and inventory only; no policy activation |
| `7168` – `15359` | `core` | evidence, evaluators, arbiter, audit, UI/API, deterministic voice |
| `15360` – `31743` | `lite` | `core` envelope plus Knowledge Lite, Deception Lite, and local M.I.O. **capacity** |
| `>= 31744` | `standard` | `lite` envelope plus concurrent analysis, wider local models, and module-link capacity |

Each threshold is the nominal module size it is meant to admit **minus a
1024 MiB firmware-reservation allowance**: 8192 − 1024 = 7168,
16384 − 1024 = 15360, 32768 − 1024 = 31744. Thresholds set at the nominal size
itself are wrong, because usable RAM is always below nominal: on x86_64 the
firmware reserves memory for UEFI runtime services, ACPI tables,
kernel-reserved regions, and — the large and variable term — integrated-GPU
stolen memory (the UMA aperture), commonly 512 MiB and BIOS-configurable. A
measured nominal 16 GB Linux host reported `MemTotal: 16481980 kB` = 16,095 MiB
usable, 289 MiB short of 16384. The 1024 MiB allowance covers that measured case
with room for a 512 MiB aperture and margin. **Residual risk:** a host reserving
more than 1024 MiB, such as one with a 2 GiB iGPU aperture, still selects one
tier low; the remedy is measurement on real hardware, not a larger allowance.

The selected profile names a **hardware class**. Whether that class can carry a
given workload is decided separately and remains subject to the measured Core
reserve, which is not yet measured for Nexus. An implementation MUST NOT treat
the selected profile as evidence that a capability fits.

Retention and concurrency limits are recorded against the resource profile:
`core` retains metadata only; `lite` permits a 7-day tactical cache, up to
three Lite decoys, and one concurrent local request; `standard` permits a
30-day tactical cache, up to three Lite decoys, and two concurrent local
requests. Audit and lease-journal reserves are protected in every profile.
Performance targets are measured separately for the 8, 16, 32, and 64 GB
classes; a 64 GB host selects `standard`.

CPU cores and storage are recorded and MAY independently reduce the envelope.
They MUST NOT raise it above the RAM-selected value.

**Implemented in `azazel_nexus.resource_profile`** (Nexus#26). Three points
about the implementation are load-bearing rather than incidental:

- **The reading is used as reported.** `MemTotal` is usable RAM after firmware
  has taken its share, which is the quantity these floors are written against.
  Subtracting the 1024 MiB allowance from the reading as well applies it twice
  and selects one tier low — on the host measured above, 16,095 MiB becomes
  `core` instead of `lite`, undoing the allowance's whole purpose.
  `test_the_firmware_allowance_is_not_applied_to_the_reading_as_well` pins the
  four readings where the second subtraction changes the answer; a reading in
  the middle of a band absorbs it silently.
- **A failed reading refuses.** An unreadable `/proc/meminfo`, a missing
  `MemTotal`, or a non-positive count raises rather than returning a small
  number, because a small number selects `diagnostic` and that would be a
  hardware class asserted on no measurement.
- **The module cannot express a capability.** It does not import the
  capability vocabulary, so no edit to it can return a capability set. §2.2 is
  a sentence; this is what keeps it true.

**Residual risk, unchanged:** a host reserving more than 1024 MiB — a 2 GiB
iGPU aperture, for instance — still selects one tier low. The remedy is
measurement on real hardware (Nexus#4), not a larger allowance, and no
simulated result establishes it.

### 2.2 The resource profile is not a capability

A resource profile states that the host has **room** for a capability, not that
the capability is permitted. Effective capability is the intersection of the
resource profile, the topology profile, the verified asset set, and the current
trust/health state, evaluated independently:

```text
effective capability = resource ∩ topology ∩ verified assets ∩ trust/health
```

A `standard` host with one usable NIC and no independent management path is
observe-only: it runs Core and local cognition, and capture, enforcement, and
Deception are all unavailable. [Capability model](capability-model.md) defines
each dimension and works this example through in §6.1.

Separate protected, observation, management, decoy, and egress/module zones are
a **topology** requirement for the functions that need them. They are assigned
only by [commissioning](commissioning.md), and an interface is identified by a
composite identity — never by kernel device numbering, and never by MAC address
alone.

### 2.3 Commissioning and activation preconditions

Installation MUST NOT start an operational network service. Every operational
unit is installed **preset disabled** and stays masked until the activation
controller validates a verified generation. Until then the node transmits
nothing on any interface outside the bounded `ASSET_ACQUISITION` state.

The following are normative and are specified in
[commissioning](commissioning.md):

- interfaces are identified by composite identity; zero or multiple matches
  fail closed to `COMMISSIONING_REQUIRED` (§3);
- logical roles are assigned only by explicit operator confirmation, never
  inferred from interface name, link state, or default route (§4);
- an observation-role interface transmits zero frames, verified across link
  flap, resume, and driver reload (§5);
- asset acquisition runs in a bounded outbound-only state on one
  operator-selected interface and grants no capability (§6);
- the activation controller is the only component that may unmask operational
  services or issue generation-scoped credentials, and it revalidates every
  digest on every boot (§7);
- Suricata and all other generated configuration render from commissioned
  logical roles with no physical-name or default-route fallback (§8);
- a high-impact network change requires an independent management path or
  physical console and a two-stage commit (§9);
- commissioning closes after activation; re-entry requires a physical local
  action, strong administrator authentication, maintenance state, and explicit
  handling of active leases (§10).

**Implementation note (#28).** `azazel_nexus.activation` holds the controller,
`azazel_nexus.layout` holds the §3 directory table, and `packaging/` holds the
unit files, the preset and the installer. Two things about that implementation
are worth stating here rather than leaving to the reader:

*The privilege boundary CI proves is the design one.* No component other than
the controller can reach the widening verb, because the token is unmintable
outside `activation.py` and a static scan keeps every other module away from
it. That is provable in one Python process. It is not the claim that a daemon
running under `azobs` on a real host cannot `systemctl unmask` -- that
boundary is the operating system's, and it is recorded open as `HG-02` in
[hardware gates](hardware-gates.md).

*This slice ships no daemon executables.* The package imports nothing that can
spawn a process, so `SystemdUnitController` takes the runner from its caller
and the unit files name binaries the repository does not yet build. The
installer refuses rather than enabling a unit whose `ExecStart` is absent. The
controller's decisions are implemented and tested; the daemons that would
carry them out are not, and no green pipeline says otherwise.

**Tiers (#39).** Activation preconditions differ by unit tier, and treating
them alike is the failure the split prevents. `SUPPORTING` (commissioning, the
ledger, the watchdog) needs a verified generation, health and a valid lease.
`EDGE_BASELINE` needs a verified local Edge Core on top. `ENFORCEMENT` needs a
complete commissioning record on top of that.

**Supporting-only bootstrap (owner-adopted implementation contract,
2026-10-14).** Before normal commissioning, the activation controller MAY use
the separate [two-helper bootstrap contract](runtime-activation-remaining.md#proposed-supporting-only-bootstrap-contract)
for exactly `azazel-auditd.service` and `azazel-commissiond.service`.
This is not an ordinary `SUPPORTING` tier grant or `ActivationLease`. It MUST
bind an independently admitted bootstrap generation, protected current context,
purpose-specific operator approval, health and immutable per-boot deadline.
It MUST supervise audit-first readiness and stop/remask both helpers on loss
of any prerequisite, cancellation, expiry or commissioning phase transition.
Both notify helpers bind to the activation controller with `After`, `Requires`
and `BindsTo`; commissiond additionally declares those dependencies on auditd.
Following the owner's option-1 decision (2026-10-15), bootstrap consumes one
controller execution attempt per boot. Before constructing the selected
Supervisor or publishing a grant, the controller MUST exclusively create and
retain `/run/azazel-nexus-bootstrap/controller-used`. The private directory is
prepared by tmpfiles without any age/removal rule. No normal exit, failed
attempt, cleanup or same-boot retry removes the marker. PID 1's controller unit
declares `ConditionPathExists=!/run/azazel-nexus-bootstrap/controller-used`;
the loaded controller inspector MUST confirm that exact non-triggering,
negated condition and its historical successful evaluation. Marker identity
checks are composed with the existing transaction guard for the full selected
lifetime. Ordinary activation without bootstrap selection does not claim it.
This retains the execution-time `BindsTo+After` check while preventing a fresh
controller execution through a dependency start after the attempt is consumed,
assuming normal PID 1 condition evaluation and a shared stable marker path.
The marker is refusal state, not approval or a deadline; it creates no new
authority. Mount-view agreement and crash/queued-job behavior require Linux
system-manager verification. Other implicit/transitive service-start closure,
executable/import coverage and suspend-inclusive expiry remain separate gates.
Installer checks, profile helpers and staging execute Python with `-IS`.
Generated runtime wrappers use the same site-disabled mode and explicit initial
import paths as staging's import validation. The selected conventional venv's
lexical prefix determines its package roots without processing `.pth` or site
customization; missing installed dependencies refuse rather than inherit other
site paths. This restricts startup path construction, not complete executable
integrity: observed paths remain installation candidates, and unsupported aliases,
directory membership, bytecode and native loader dependencies remain separate
admission requirements. No bootstrap start gate is opened by staging.
The protected bootstrap installed-file reader MUST decode the independently
pinned manifest and require the fixed controller, auditd and commissiond
executables from the declared service profiles, each with mode 0755, before
measurement. A manifest selecting only unrelated files is insufficient. The
same manifest bytes are measured and reread afterward; changes refuse. These
mandatory entrypoints are a coverage floor, not proof of their interpreter,
imports or the rest of the process closure.
The same independently pinned installed-file document MAY use the explicit v2
schema to declare exact directory membership. V2 directories have protected
no-follow identities and exact 0755 mode; expected immediate children derive
from the files/directories union. Descendant intermediate directories must be
declared, empty directories remain empty, and extra entries refuse. Bounded
enumeration and named identity checks bracket file hashing in both repeated
observations. V1 semantics remain unchanged. Neither a v2 version tag nor a
candidate emitted from explicit operator paths establishes that all import
roots were selected; completeness and later filesystem drift remain separate
admission requirements. No independent approval or start grant is created.
Bootstrap admission also reads and verifies the three fixed wrapper files
against their entries in that same pinned manifest. A pure shared renderer and
parser require the exact canonical `-IS` wrapper and compiled target for each
unit, without executing wrapper content. All three wrappers MUST agree on the
interpreter and ordered import paths. The interpreter requires an exact 0755
regular-file entry or an explicitly pinned v3 leaf-link chain to one; each
initial import path requires an exact declared directory
record or a pinned regular `.zip` entry. Ancestor-only directory coverage is
insufficient. Full manifest measurement and the protected manifest reread follow
these checks. The fixed content reader is limited to three 64-KiB files, with
protected metadata, hash and repeated named-identity checks before returning any
bytes. This binds canonical startup paths to approved coverage, not interpreter
startup semantics, native-loader closure, arbitrary import mutation or functional
module resolution. Unlisted interpreter links remain refused, not silently
resolved. V3 adds sorted unique `links` records with exact `path` and `target`.
Targets are canonical absolute /usr or /opt paths, or single basename siblings;
directory aliases and relative paths containing slashes are unsupported. Every
declared chain, used or unused, MUST terminate in a listed regular file within
eight links. Collisions, cycles, missing targets and file/link ancestors refuse.
Link identity/text checks use protected no-follow parents, lstat/readlink and
named identity rereads before and after file hashing in both observations.
Links themselves are never opened/followed. The same manifest pin covers all
link text and terminal file bytes; bootstrap additionally requires terminal
mode 0755. At most 1024 links are accepted. This does not admit pyvenv config,
initial interpreter/native loading, directory aliases or later filesystem drift.
Repeated protected generation admission MUST also recheck policy-bound capacity
without replaying the stopped-writer audit preflight after auditd is running.
The selected supervisor requires a controller-owned kernel deadline guard,
armed once from the freshly verified retained absolute BOOTTIME deadline before
blocking generation admission/publication/READY/start. The Linux native backend
uses a one-shot absolute self-SIGKILL timer, never a caller PID or extra service.
Every refresh checks the same guard; no extension is supported. Only successful
confirmed transaction cleanup permits explicit release. GC, context exit and
failed cleanup do not disarm it. Exec deletes POSIX timers, so selected
supervision must not exec. This does not wake a suspended host or establish
instantaneous helper containment; native lifetime qualification remains required.
Runtime wheels require the compiled Linux backend for their target Python ABI;
no backendless portable-wheel fallback is supported. Installer staging imports
and checks the native loader but never arms a timer. Missing/unsupported backend
fails closed. Public pair opening/start remains unavailable until the remaining
execution-admission and native qualification obligations are satisfied.
The matching ARM64 CPython3.13.5 backend has now passed isolated compiled-source
smoke tests for self expiry, retained/GC-dropped handles, invalid input, active
rearm refusal, idempotent/final release (including survival past the cancelled
deadline), and fork-owner refusal. Child tests bind the exact extension loader
and source-package origin, use `-IS`, and require operation markers before fatal
termination. Fork descendants explicitly default/unblock a short fatal alarm.
This does not qualify a production wheel, systemd sandbox, exec, suspend or
manager/controller-to-helper containment. See
[native qualification](evidence/bootstrap-native-qualification-2026-10-15.json).
Before exec, the three selected-bootstrap units MUST disable login environment
construction, have no PAM stack, and remove the exact compiled loader/Python
environment-name set. Loaded helper and controller inspection MUST require
empty Environment, EnvironmentFiles and PassEnvironment, the exact removal
set, SetLoginEnvironment=false and empty PAMName. Retained start checks bracket
helper/graph inspection with fresh full controller observations in the current
pre-READY or READY phase; a READY transition or observed drift refuses. Mutable
reply lists are copied before any subsequent await. Installer Python children
receive only fixed PATH/LANG/LC_ALL; only the staging child additionally receives
explicit DESTDIR when selected. These constraints do not undo code already
loaded by the installer shell or establish whole-OS native-loader integrity.
See [launch environment evidence](evidence/bootstrap-launch-environment-2026-10-15.json).
The selected bootstrap additionally supports only conventional protected
`/opt/.../bin/python`, `python3` or `python3.13` venv paths. Its lexical parent
venv's `pyvenv.cfg` MUST be a pinned 0644 regular file of 1–4096 bytes, read
through the existing protected content reader, not reopened by pathname. The
fixed metadata profile requires home `/usr/bin`, no system site packages,
canonical `3.13.micro` creation version and executable `/usr/bin/python3.13`.
Only unique standard venv keys are accepted; optional command/prompt are inert
metadata and never executed. The pinned 0755 base interpreter and resolved
wrapper interpreter terminal MUST have identical size/hash, followed by full
measurement of both. This permits a pinned regular copy without equating its
startup semantics with a symlink. Version/executable metadata does not prove
the running interpreter's version, ABI or kernel executable identity. Separate
current-interpreter observation below is required; startup-override and native
qualification remain open.
These profile mechanics impose no CPU-architecture restriction and do not
change the runtime package's general Python floor. See
[venv binding evidence](evidence/bootstrap-python-venv-binding-2026-10-15.json).
Before and after full installed-file measurement, the fixed current-Python
observer MUST inspect only its own kernel procfs executable. It verifies procfs
directories, bounds the protected root-owned 0755 single-link executable to
64MiB, hashes twice through the same descriptor with rewind/metadata checks,
and brackets named kernel-executable identity, PID and Python state. Both
observations MUST match the independently pinned terminal bytes and each other.
The fixed state is Linux CPython3.13 final/GIL-enabled, empty ABI flags, matching
cfg microversion, base executable `/usr/bin/python3.13`, `/usr` prefixes,
`-IS` flags, little-endian 64-bit state, exact wrapper executable/import paths
and bytecode-write suppression. No alias fallback is inferred. The existing
procfs statfs adapter supports Linux LP64 amd64/arm64; this is not qualification
for other native ABIs. An accepted fingerprint reads at most128MiB, twice per
measurement admission. This binds current executable content and observed
state, not historical mapped pages, selected-path inode equality, native
libraries, arbitrary in-process mutation resistance or a filesystem freeze.
See [current Python evidence](evidence/bootstrap-running-python-2026-10-15.json).
Selected bootstrap also MUST check a fixed bounded startup-override absence set:
the lexical wrapper interpreter's `._pth`, `/usr/bin/python3.13._pth`,
`/usr/bin/pybuilddir.txt`, `/usr/bin/Modules/Setup.local` and
`/usr/lib/python313.zip`. Any existing object, including empty files and dangling
links, refuses. The fixed-root reader traverses protected root-owned directories
without following links. Only ENOENT establishes a missing component; other
lookup errors refuse. Named/fd ancestry, missing-component location and shared
ancestor stamps are bracketed and repeated, then compared before/after full
installed-file measurement. Missing intermediate components are recorded rather
than silently ignored. No negative-input manifest, selector or approval is added.
This is repeated current absence of those five candidates, not historical
startup proof, every prefix fallback, stdlib/import closure or a filesystem
freeze. See [startup absence evidence](evidence/bootstrap-python-startup-2026-10-15.json).
Protected measurement also checks current import routing before and after file
measurement. Only the standard builtin/frozen/path meta finders and standard
ZIP/FileFinder path hooks are supported; configured callbacks are not invoked.
Initial roots require exact declared directories or pinned ZIP files. Cached
FileFinders require exact declared subdirectories beneath those roots, standard
loader/suffix order, no instance method overrides and plain bounded cache data.
ZIP finders require explicit pinned archives and a bounded detached directory
table; CPython3.13's module-level cache is checked, not an older `_files` layout.
Cache identity/data must remain unchanged. The implicit negative
`/usr/lib/python313.zip` cache entry is allowed only with the surrounding startup
absence checks. At most2048 finders and16384 aggregate cached names are observed;
each ZIP table is limited to4096 plain records. This is routing metadata
qualification, not loaded-module/bytecode coverage, ZIP table correspondence to
archive bytes, future imports, hostile in-process defense or full import closure.
See [import routing evidence](evidence/bootstrap-import-routing-2026-10-15.json).
The first operational source-prototype profile is explicitly **unpacked
directories and ordinary packages**, not ZIP execution. ZIP entries/wrappers
remain valid generic candidates, but do not pass this selected bootstrap
profile. Namespace and sourceless-only modules are unsupported. The profile
requires current module metadata to bind the fixed controller `__main__`,
standard source/native loader name/path pairs, exact pinned origins (including
declared v3 leaf chains), and ordinary package search directories beneath the
approved import roots. Builtin/frozen labels must name modules known to the
running interpreter; aliases retain canonical registry identities. In-flight
initialization, optimization other than exact zero and pycache redirection
refuse. Source bytecode cache names must be canonical: cache bytes must be
independently pinned or their derived paths must be observed absent through the
protected fixed-root reader. The reader also requires `/etc/ld.so.preload`
absent. Snapshots bracket full measurement, with at most2048 modules and65536
metadata attributes. This binds current metadata to measured candidates, not
historical executed bytes or source/bytecode equivalence. The existing trusted
Debian kernel/glibc/native-loader substrate is explicit; no universal ELF/OS
hermeticity or hostile privileged/in-process defense is claimed. See
[loaded-module profile evidence](evidence/bootstrap-loaded-modules-2026-10-15.json).
The three bootstrap-related units explicitly disable `DefaultDependencies` to
avoid pulling `sysinit.target` into their START transactions. Ordering after
`sysinit.target`/`basic.target` and before shutdown is declared explicitly;
`Conflicts=shutdown.target` preserves shutdown behavior. Controller and loaded
helper inspection require the effective boolean value to be false.
After Reload and around pair inspection, and again at retained start checks,
a bounded inspector traverses effective `Requires`/`Wants`/`BindsTo` from all
three roots. It rejects any external service, socket, timer, path, automount,
swap or scope, and rejects asynchronous activation channels throughout the
visited graph. Device followers are discovered using fixed read-only
`ListUnitsByPatterns([], ["*.device"])` and separate Device `SysFSPath`
properties. All units sharing a nonempty canonical sysfs path join the graph;
following links must resolve to a same-group anchor. Both the inventory and
the graph are remeasured. Inventories exceeding 512 entries, missing/malformed
required identities, changed membership and non-idle reached devices are refused.
Only active, idle target/mount/slice/device infrastructure is traversed, bounded to
64 units and 1024 dependency entries. Complete detached graph observations
must match, both within each inspection and across the bracketing observations.
This detects disallowed paths; it does not authorize mount executables, model
stop-propagation effects or establish atomic graph stability during submission.
The protected loaded policy additionally requires every positive `Requires`,
`Wants` and `BindsTo` edge to appear in `After`. External positive prerequisites
(including `Requisite`) must be observed active and idle; pinned `Conflicts`
and inverse `ConflictedBy` peers must be loaded, inactive and idle. Positive
and conflict sets must not overlap across the pair, and conflicts with either
helper or the controller refuse. These bounded repeated observations do not
establish atomic exclusion of subsequent external state/job changes.
These native ordering/lifetime declarations do not replace audited readiness,
deadline checks or a start-job revocation fence. Cleanup must deny new starts
and contain pending/late starts before stopping the pair and withdrawing its
owned grant; a persistent mask alone is not proof against a higher-priority
volatile override. The production grant path remains refusing until that
mechanism is implemented and reviewed.
The controller uses PID 1's fixed 30-second service watchdog, with SIGKILL
on watchdog failure, rather than launching another Nexus watchdog service.
The main supervision path renews it only after READY confirmation and fresh
admission/progress checks. Notifications and synchronous guards are charged
to the retained BOOTTIME deadline; steady waits are capped at 10 seconds and
the freshly recomputed approval remainder. Cleanup never feeds the watchdog.
This is a running-system hang backstop, not independent suspend-inclusive
expiry enforcement or proof of bounded startup/stop completion.
After fresh prerequisite checks, the supervisor durably records a per-boot
grant-transaction intent before asking the manager to open the exact pair. Once
that manager operation is confirmed, the controller sends systemd READY so
the `After=`-ordered auditd helper can start. It then confirms both audit-chain
continuity and an append receipt before requesting commissioning. The
protected transaction record is a crash-recovery write-ahead record, **not**
an audit event or replacement for the audit chain. Because the audit socket
does not exist until auditd starts, the supervisor MUST NOT require an
audit-chain append before starting auditd. Once auditd is ready, it appends the
previously journaled controller/grant intent and returns a receipt whose
digest is retained in the transaction record; only then may the commissioning
start intent be appended and its start requested. The ordering and receipt
binding MUST be covered by crash-boundary tests. An interrupted or
durability-uncertain transaction MUST remain
non-replayable and refuse a new grant; it is not automatically repaired or
reinitialized. The transaction record is boot-bound and a new boot requires a
new independently approved context. Grant withdrawal is permitted only after
confirmed start fencing and stopped/inactive helpers; it must not remove
another lifecycle's grant. Partial grant/withdrawal failures remain
containment failures. These are backend obligations, not authorization to
deploy the current refusing adapter.
Historical intent events MUST be appended in occurrence order: the grant
intent and its verified receipt precede the later controller-ready intent.
An append into a day preceding an already existing ledger segment MUST be
refused before writing; daily segmentation must not reorder the hash chain.
After persisting commissioning start intent, admission/deadline, auditd
readiness and cancellation MUST be checked again before requesting its start.
Each manager start handoff MUST carry the captured durable per-unit start
intent and a fresh synchronous checkpoint: `auditd_start_intent` for auditd,
`commissiond_start_intent` with its retained audit receipt for commissiond.
The supervisor checks before and after the handoff; the backend must also
invoke the checkpoint at its start boundaries. A changed intent, expiry,
cancellation or unconfirmed return prevents subsequent readiness-phase
advancement and enters containment. This callback does not replace the
backend's owner/job/lifetime fences and must not be run inside an event loop
that it would re-enter through synchronous admission checks.
No fetch, provider, watchdog, Edge baseline, capture or enforcement authority
is included. Normal generation readers MUST reject bootstrap metadata.
Bootstrap-only trees use the separate root-owned private namespace
`/var/lib/azazel/bootstrap-generations/`. They MUST NOT be published into
`/var/lib/azazel/generations/`, whose numeric entries determine the latest
operational generation. This separates storage selection as well as metadata
types; no automatic migration or deletion of existing generations is permitted.
The durable grant transaction is stored per boot under the existing
root-private `/var/lib/azazel/state/bootstrap/` directory, beside—but distinct
from—the retained deadline and shared lock. A transaction filename is derived
only from the validated current boot UUID. Files are create-once/CAS-updated;
unfinished markers and ambiguous fsync outcomes require explicit recovery and
must never be reset by an installer. Closed history is retained, not silently
garbage-collected.
Deployment MUST remain refusing until protected producers, bounded service jobs,
controller-lifetime binding and reboot/persistent-mask fencing are implemented
and independently reviewed. Adopting this contract authorizes implementation,
not installation, service startup, key enrollment or a hardware-success claim.

**Administrator-managed provisioning (owner-selected, 2026-10-14).** Implement
the explicit administrator-managed bootstrap setup first on the development VM,
using a common versioned contract that also supports later physical Debian
installations. VM address, SSH credentials, architecture and hypervisor identity
MUST NOT become trust defaults or be embedded in that contract. Separate
persistent administrator declarations from fresh boot/time/device/health
observations and from purpose-specific activation approval. Moving or cloning
a deployment requires target identity review, fresh measurements and boot-bound
approval; do not copy live grants or retained deadlines. Platform adapters may
vary how evidence is collected, but MUST NOT bypass admission or silently fall
back to weaker evidence. A local administrator-managed record is not an
independent rollback anchor. Existing Debian 13 / amd64 support baseline and
hardware gates remain unchanged; ARM64 VM tests are software evidence only.

A node whose ledger and watchdog are running can account for itself. It has
said nothing about an Edge Core and must not be read as having:
`edge_baseline_ready` is derived from what was established about Edge, **not**
from whether the Edge tier's units were granted — over an empty tier the
latter is vacuously true, which would make a node with no Edge Core at all the
most confident node on the network.

**Leases.** Activation requires a time-bounded authorization naming the
generation digest it was granted against. An authorization with no expiry
cannot be withdrawn by doing nothing, and every other way of withdrawing it
needs the thing that went wrong to still be working. The clock is passed in;
nothing in the decision reads one.

**Residual risk.** A verified generation establishes that the tree on disk is
the tree that was promoted. It does not establish that what was promoted is
safe: admission (§2.4) is what judges content, and it is not built yet. Until
it is, "verified" here means unchanged since promotion and nothing more.

### 2.4 Product admission

A signature is one input to admission, not admission itself. Assets pass
`authenticity -> exact tested compatibility tuple -> semantic content policy ->
resource/topology admission -> approval -> staged activation`, in that order,
with any gate able to reject. The tuple fields, delegated trust roles, and the
monotonic-reduction rule for deployment overlays are specified in
[contract ownership](contract-ownership.md) §4 and §5. A correctly signed but
obsolete, cross-role, or policy-incompatible artifact is rejected.

## 3. Filesystem layout and identities

`/etc/azazel/` is configuration; `/var/lib/azazel/` is small mutable state; `/data/` is the encrypted mission volume mounted only after successful boot integrity checks. Permissions below are mandatory defaults.

```text
/etc/azazel/
  node.yaml                    # node identity, resource profile, declared logical roles
  commissioning/active.record   # operator-signed role/identity bindings (read-only to daemons)
  commissioning/inventory.json  # read-only hardware and interface inventory + digest
  admission/policy.yaml         # delegated trust roles, tested tuples, security epoch
  admission/roots.d/*.pem       # separately provisioned offline roots per asset class
  policy/active.bundle          # signed policy bundle (read-only to daemons)
  policy/trust.d/*.pem          # policy and module trust anchors
  mio/sanitizer.yaml            # remote privacy classes and allowlists
  mio/providers.d/*.yaml        # endpoint metadata, no secrets
  knowledge-lite.yaml
  deception-lite.yaml
  modules.yaml                  # expected AZ-04/AZ-06 peers and pinning rules
  voice.yaml
  retention.yaml
  resource-governor.yaml
  systemd/*.conf                # unit drop-ins installed by packages
/var/lib/azazel/
  run/                          # socket tree (0711 traversal parents; per-daemon 2710 leaves)
  state/                        # traversal-only parent; daemon-owned private leaves
  state/audit/                  # azaudit's segmented hash chain
  state/auditd/                 # azaudit refusal log, outside chain segments
  state/commission/             # azcommission's refusal log
  state/watchdog/               # azwatch's fence, ledger and refusal log
  generations/<n>/              # private versioned staging tree; promoted, never edited in place
  bootstrap-generations/<n>/    # separate root-private bootstrap-only namespace; not operational latest
  secrets/                      # root-only credential material, preferably tmpfs-backed
/data/azazel/
  evidence/objects/             # content-addressed encrypted artifacts
  evidence/index.sqlite         # metadata index; WAL enabled
  audit/ledger/                 # daily append-only segments and signed checkpoints
  knowledge-lite/               # cache database and verified bundles
  deception-lite/               # decoy persistent state; no protected-network data
  models/                       # signed local model assets
  capture/                      # bounded capture spool, lowest retention priority
  exports/                      # operator-approved encrypted exports
  recovery/                     # sealed recovery manifests, never live secrets
```

Each daemon MUST use a dedicated, non-login system account: `azobs`, `azevidence`, `azeval`, `azarbiter`, `azenforce`, `azmio`, `azknowledge`, `azdecoy`, `azmodule`, `azvoice`, and `azui`. A service reads only its stated configuration. Secrets are supplied through systemd credentials or a root-owned secret broker; they MUST NOT appear in YAML, command lines, process environments, journal fields, or audit payloads.

## 4. Runtime units

All local APIs use Unix domain sockets under `/var/lib/azazel/run/` unless an explicit loopback TCP port is specified. Root-owned parent directories permit traversal but not listing; each daemon-owned setgid leaf supplies the operator group to its socket. Daemon accounts are not members of the operator group. The runtime verifies socket mode, owner and expected operator GID before accepting requests, then derives operator membership from kernel peer credentials and supplementary groups. Socket ACLs are the first authorization boundary; every request also carries a workload identity and trace ID.

| Unit / executable | Account | Listens or consumes | Owns | Required behavior |
| --- | --- | --- | --- | --- |
| `azazel-observed.service` / `az-observed` | `azobs` | capture sockets, Suricata EVE input, interface telemetry | normalized observations | never drops a valid source event silently; records source loss |
| `azazel-evidenced.service` / `az-evidenced` | `azevidence` | `evidence.sock` | object store, evidence index, hashes | assigns immutable evidence IDs and stores provenance |
| `azazel-evaluatord.service` / `az-evaluatord` | `azeval` | evidence subscription | NOC/SOC assessments | rules only; outputs cited assessments, not actions |
| `azazel-arbiterd.service` / `az-arbiterd` | `azarbiter` | `arbiter.sock`, operator approvals | decision and lease store | sole intent issuer; validates policy, scope, expiry, prerequisites |
| `azazel-enforced.service` / `az-enforced` | `azenforce` | `enforcement.sock` | nftables/tc/route state | applies one approved intent, verifies it, then emits a receipt |
| `azazel-auditd.service` / `az-auditd` | `root` plus append-only group | `audit.sock` | hash-chain ledger, checkpoints | accepts canonical events only and refuses chain discontinuity |
| `azazel-knowledge-lite.service` | `azknowledge` | `knowledge.sock` | tactical cache | returns cited, freshness-labeled context; advisory only |
| `azazel-deception-lite.service` | `azdecoy` | `deception.sock` | decoy bridge and containers | manages only approved Lite decoys; no protected route |
| `azazel-module-manager.service` | `azmodule` | `modules.sock`, mTLS links | module inventory and bundle staging | discovers, verifies, quarantines, and reports modules |
| `azazel-mio-router.service` | `azmio` | `mio.sock` | route state and request budget | local-first selection and deadline management |
| `azazel-mio-local.service` | `azmio` | `mio-local.sock` | local inference worker | strict advisory output; resource-capped |
| `azazel-mio-sanitizer.service` | `azmio` | `mio-sanitize.sock` | redaction decision records | default deny; emits only `MioRemoteFrame` |
| `azazel-mio-remote.service` | `azmio` | loopback `127.0.0.1:9444` | remote request state | egress-only mTLS client; treats response as untrusted |
| `azazel-mio-merger.service` | `azmio` | `mio-merge.sock` | merged advisory cache | retains per-claim provenance and disagreement |
| `azazel-voiced.service` | `azvoice` | `voice.sock` | priority queue and acknowledgement state | deterministic alerts precede explanatory speech |
| `azazel-uid.service` | `azui` | loopback `127.0.0.1:8443` | operator sessions/read model | authenticated UI; no privileged direct controls |
| `azazel-commissiond.service` | `root` | local console / authenticated UI session | inventory, proposed role map, signed commissioning record | read-only inventory; assigns a role only on explicit operator confirmation; closes after activation and refuses remote re-entry |
| `azazel-activated.service` | `root` | commissioning record, admitted assets | generation counter, staging trees, generated-file digests | sole component permitted to unmask operational units and issue generation-scoped credentials; may install but not read the arbiter intent-signing credential |
| `azazel-watchdog.service` | `root` | systemd watchdog notifications, health sockets | degradation coordinator | fences failed capabilities; never restarts into a broader authority state |

`azazel-enforced` and the one-shot Deception Lite network helper `azazel-decoy-netd.service` ([#196](deception-redirect-prerequisites.md) §5, §10) are the only units granted narrowly constrained `CAP_NET_ADMIN`; no other unit may hold it, and the helper may hold nothing else (as a bounding set, never ambient, with `AF_NETLINK` as its only address family). The enforcement service MUST use `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `PrivateDevices=yes` except explicit NIC access, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, and a systemd `SystemCallFilter` appropriate to netlink operations. The audit daemon writes through a root-owned append-only helper rather than granting write access to other daemons.

## 5. API and port contract

All request and response bodies are versioned JSON or protobuf messages using `schema_version: "v1"`. Network APIs are mutually authenticated TLS 1.3. Local service APIs reject unknown fields unless the schema marks them as extensions. The UI port is bound to management loopback by default and is reverse-proxied only on a designated management interface.

| Boundary | Transport | Authentication | API operations |
| --- | --- | --- | --- |
| operator -> UI | HTTPS `8443` | WebAuthn or client certificate; local break-glass profile | read status, view evidence, acknowledge, submit approval/decline |
| observer -> evidence | `evidence.sock` | `azobs` socket ACL | `PutObservation`, `PutArtifactReference`, `ReportSourceHealth` |
| evidence -> evaluator | `events.sock` | `azeval` ACL | ordered `EvidenceCreated` subscription |
| evaluator -> arbiter | `arbiter.sock` | `azeval` ACL | `ProposeAssessment`; cannot call `IssueIntent` |
| UI -> arbiter | `arbiter.sock` | `azui` plus operator authorization | `ApproveProposal`, `DeclineProposal`, `AcknowledgeReceipt` |
| arbiter -> enforcement | `enforcement.sock` | `azarbiter` ACL plus signed intent | `ApplyIntent`, `InspectScope`, `RollbackLease` |
| all components -> audit | `audit.sock` | component ACL + signed canonical envelope | `AppendAuditEvent` |
| Edge -> Knowledge Lite | `knowledge.sock` | `azeval`, `azmio` ACL | `LookupContext`, `ImportVerifiedBundle` |
| arbiter -> Lite Deception | `deception.sock` | `azarbiter` ACL plus intent | `PrepareDestination`, `ActivateRedirect`, `DeactivateRedirect` |
| M.I.O. internal | Unix sockets | `azmio` subservice ACL | `Route`, `Sanitize`, `Analyze`, `Merge` |
| Nexus <-> AZ-04/AZ-06 | HTTPS `9443` | mTLS, signed manifest, peer identity pin | `GetManifest`, `GetBundle`, `GetHealth`, bounded Deception control |
| remote M.I.O. egress | HTTPS `443` | mTLS client identity / approved provider credential | one-way `Analyze(MioRemoteFrame)` only |

No API exposes shell command execution, arbitrary policy upload, arbitrary container start, packet capture retrieval, or a general network-control primitive. The external AZ-06 control API receives a signed `DeceptionLease`, not an Edge enforcement intent.

## 6. Data contracts and record ownership

**Azazel-Fabric owns the canonical form of every record that crosses a product
boundary.** This section does not define one. The JSON below is illustrative —
it shows which fields Nexus depends on and how it uses them. Where a record is
Fabric-owned, the canonical serialization, digest rules, validation, and golden
fixtures live in Fabric, and Nexus consumes them behind an exact release pin.
Where a Fabric contract does not exist yet, the record is a **target contract**
and Nexus MUST NOT publish a local canonical form in its place.

[Contract ownership](contract-ownership.md) §3 is the authoritative map. A
summary for this section:

| Subsection | Owner | Fabric artifact |
| --- | --- | --- |
| 6.1 evidence citation, decision explanation | Fabric (available) | `schema.evidence.EvidenceRef`, `schema.decision.DecisionExplanation` |
| 6.1 observation and assessment envelopes | **Nexus-local** | product-local ingest records; only the citation and explanation projections cross a boundary |
| 6.2 enforcement intent and action plan | Fabric (available) | `schema.action.ActionIntent` and its plan variants |
| 6.2 receipt, lease timer, rollback state | **Nexus-local** | product-local durable state |
| 6.3 `MioSituationFrame`, `MioRemoteFrame`, advisory result, merge output | Fabric (**target, R1**) | `mio_contracts` — published in the pinned Fabric; **not adopted here** |
| 6.3 sanitizer policy, alias keys, redaction records | **Nexus-local** | only the redaction record *reference* is carried in the Fabric frame |
| 6.4 audit event envelope and canonical bytes | Fabric (available) | `schema.audit.AuditEvent`, `audit.jsonl` |
| 6.4 hash chain, checkpoints, ledger genesis | **Nexus-local** | chain enforcement is a product-local trust decision |

Every record carries `schema_version`, a ULID `id`, RFC 3339 UTC `occurred_at`, `trace_id`, `producer`, `classification`, and `integrity` fields. Timestamps include a `time_confidence` value: `trusted`, `degraded`, or `untrusted`.

### 6.1 Evidence and assessment

Owner: the observation and assessment envelopes are Nexus-local ingest records. Evidence citations and operator-facing decision explanations use the Fabric models named above, and MUST NOT be re-declared here.

```json
{
  "schema_version": "v1",
  "id": "01J...",
  "trace_id": "AZ-2026-00142",
  "kind": "observation",
  "source": {"id": "suricata:wan0", "sequence": 4812},
  "occurred_at": "2026-09-18T02:30:00Z",
  "classification": "mission-confidential",
  "payload": {"event_class": "authentication_anomaly", "fields": {}},
  "artifact_refs": ["sha256:..."],
  "integrity": {"payload_sha256": "...", "previous_id": "01J..."}
}
```

```json
{
  "schema_version": "v1",
  "id": "01J...",
  "kind": "assessment",
  "risk": 84,
  "risk_state": "high",
  "assessment_type": "soc",
  "rule": {"id": "SOC-CRD-004", "policy_version": "2026.09.1"},
  "evidence_ids": ["01J...", "01J..."],
  "recommended_actions": ["throttle", "isolate"],
  "confidence": 0.91
}
```

### 6.2 Intent, lease, receipt, and rollback

Owner: Fabric defines the intent and its action plans; Nexus persists the receipt, lease timer, and rollback state. The example below is the Nexus view of a Fabric-owned intent, not a competing definition.

An intent is immutable and has exactly one lifecycle. An action lease bounds any non-permanent control; expiration is enforced independently by `azazel-enforced` even if the arbiter disappears.

```json
{
  "schema_version": "v1",
  "id": "01J...",
  "kind": "enforcement_intent",
  "decision_id": "01J...",
  "policy": {"id": "EDGE-ISO-002", "version": "2026.09.1", "hash": "sha256:..."},
  "action": "isolate_segment",
  "scope": {"zone": "guest", "interfaces": ["lan-guest"], "selectors": ["segment:guest"]},
  "evidence_ids": ["01J..."],
  "approval": {"required": true, "operator_id": "op-17", "approved_at": "..."},
  "lease": {"id": "01J...", "issued_at": "...", "expires_at": "...", "rollback": "restore_previous_ruleset"},
  "signature": {"key_id": "arbiter-2026-01", "ed25519": "..."}
}
```

`receipt` records `intent_id`, adapter, pre-state hash, post-state hash, verification probes, effective time, result (`applied`, `failed`, `rolled_back`, `expired`), and failure reason. A rollback MUST use the receipt's captured pre-state or a policy-declared safe baseline; it MUST NOT reconstruct a ruleset from an untrusted current state.

### 6.3 M.I.O. and privacy classes

Owner: **Fabric `mio_contracts` — published in the pinned Fabric, not adopted here.** The frames and result shape below describe what Nexus needs from that module; they are a local sketch and nothing has been reconciled against Fabric's actual records. Nexus MUST NOT treat the shapes below as an interoperable canonical form, and adopting the module means reading it, not assuming these shapes were it. Privacy classes, sanitizer policy, and alias key material are Nexus-local.

`MioSituationFrame` is local-only and may cite evidence IDs. `MioRemoteFrame` is separately built, carries `sanitizer_policy_version`, `redaction_record_id`, `remote_privacy_class`, and contains no raw artifacts or internal addressing.

| Privacy class | Remote eligibility | Examples |
| --- | --- | --- |
| `P0-public` | allowed | product version, generic technique name |
| `P1-sanitized` | allowed after sanitizer | stable aliases, role categories, counts and time buckets |
| `P2-mission` | local only unless explicit policy transformation exists | internal topology, named assets, detailed timelines |
| `P3-restricted` | never remote | credentials, keys, raw capture, operator identity, exact location |

`MioResult` has `summary`, `claims[]`, `confidence`, `evidence_ids[]`, `next_checks[]`, `limitations[]`, and `source` (`local`, `remote`, `merged`). Each claim includes `provenance` and can be shown as untrusted remote content. It contains no executable action field.

### 6.4 Audit ledger

Owner: Fabric defines the audit event envelope and its canonical bytes. Nexus owns chain enforcement — whether a chain is continuous, anchored, or broken is a product-local trust decision that Fabric MUST NOT make. Audit assurance is reported as `ROLLBACK_ANCHORED` or `LOCAL_CONTINUITY_ONLY`; see [capability model](capability-model.md) §5.

The audit event is a canonical serialized envelope with `event_type`, actor, target IDs, outcome, and redacted details. Each segment stores:

```text
sequence | event_hash = SHA-256(previous_hash || canonical_event_bytes) | previous_hash
```

At rotation (at least daily and on shutdown), `azazel-auditd` writes a signed checkpoint containing the final hash, segment root, policy hash, boot ID, and TPM measurement reference where available. The next segment includes the prior signed checkpoint hash. Audit records are write-only for workloads and are exported as a signed manifest plus encrypted artifacts. A chain gap, failed checkpoint signature, or backwards trusted clock enters `INTEGRITY_RECOVERY`.

## 7. State machines and degradation

The node exposes one computed capability state and individual service states. State changes are appended to audit before being published to the UI.

```text
BOOTSTRAP -> INVENTORY -> COMMISSIONING_REQUIRED -> ACTIVATING -> VERIFYING
                                |                                     |
                        (ASSET_ACQUISITION, bounded)                  v
                                                          CORE -> LITE -> FULL
                                                           ^       |       |
                                                           |       +-------+ external or embedded capability loss
                                                           +--------------- resource shed / local capability loss
VERIFYING -> INTEGRITY_RECOVERY -> RECOVERY -> CORE
any state -> COMMISSIONING_REQUIRED   (interface identity changed or ambiguous)
```

| State | Preconditions | Permitted operation |
| --- | --- | --- |
| `BOOTSTRAP` | encrypted data unavailable | diagnostics only; no policy activation |
| `INVENTORY` | node powered, no roles assigned | read-only hardware and interface inventory; zero transmitted frames |
| `COMMISSIONING_REQUIRED` | a role is unassigned, ambiguous, or its interface identity changed | operator confirmation of roles; the affected capability is unavailable; operational units stay masked |
| `ASSET_ACQUISITION` | operator selected one interface for asset fetch | bounded outbound-only fetch with endpoint allowlists; no forwarding, listening, capture, enforcement, or role assignment |
| `ACTIVATING` | signed commissioning record and admitted assets present | activation controller renders to staging, preflights, establishes the management failsafe, and switches policy-owned objects in the fixed order |
| `VERIFYING` | data mounted | verify boot, policy, audit checkpoint, generation digests, interfaces, clock |
| `CORE` | Edge health and signed policy valid | evidence, evaluation, deterministic enforcement, UI, audit, deterministic voice |
| `LITE` | `CORE` plus both embedded Lite services healthy | standalone Knowledge/Deception and local M.I.O. if provisioned |
| `FULL` | `LITE` plus verified fresh AZ-04 and AZ-06 links | external capacity under signed leases |
| `CONSTRAINED` overlay | resource or partial service threshold | preserve Core; shed priority-defined optional work |
| `INTEGRITY_RECOVERY` | integrity check fails | read-only diagnostics and protected evidence access; no remote egress, policy activation, or module change |

The expected normal degradation is `FULL -> LITE -> CORE`. AZ-04 loss removes only extended knowledge, and AZ-06 loss stops new full-host redirects then selects an eligible Lite destination. Loss of either Lite service is source-specific: the other remains available; the state is `CORE` plus a visible impairment. Loss of local cognition does not reduce Edge authority or deterministic voice alerts.

Automatic restoration above `CORE` requires a passing health window, signature/segmentation revalidation, and an audited state transition. Restoring a module route or a failed enforcement adapter requires operator acknowledgement.

## 8. Health checks, watchdog, and failure handling

Every daemon MUST expose `GET /healthz` on its Unix socket, returning `ready`, `degraded`, or `failed`, dependency summaries, build ID, last successful work timestamp, and backlog. A `GET /readyz` returns success only when safe to accept new work. systemd `WatchdogSec=30s` is required for core units; the watchdog uses a 10-second polling cadence.

| Component | Health evidence | Failure response |
| --- | --- | --- |
| observer | source sequence advancing; interface carrier and capture counters | mark source impaired; evaluators enforce corroboration prerequisites |
| evidence | encrypted volume writable; index transaction and object hash verification | stop low-priority capture; preserve audit and decisions; if persistent failure, no new automatic action needing missing evidence |
| arbiter | policy signature valid; lease timer alive; decision store transaction | reject new intents; existing enforcement leases continue to expiry |
| enforcement | ruleset/queue inspection equals desired state; rollback baseline present | lock new intents for adapter scope; execute only verified rollback; critical alert |
| audit | chain continuity, free protected space, checkpoint signature | enter `INTEGRITY_RECOVERY` on chain error; halt nonessential mutations |
| Knowledge Lite | query integrity and bundle signature/freshness | return `unavailable` rather than stale as current; evaluators continue without it |
| Deception Lite | container/process, bridge isolation, route-deny probes | remove redirect eligibility, detach unsafe bridge, preserve telemetry |
| module manager | mTLS, peer pin, manifest signature, compatibility, freshness | quarantine peer and degrade to Lite; never retry with trust relaxed |
| M.I.O. sanitizer | policy loaded, negative test, tokenization key available | deny remote route; local or Core path only |
| local M.I.O. | bounded test inference and cgroup headroom | shed to `CORE`; do not starve capture/evidence |
| voice | audio device write and queue serviceability | visual-only alert plus audit; no enforcement impact |

`azazel-watchdog` MUST order remediation as: (1) cancel optional remote work, (2) reduce M.I.O. concurrency/context, (3) stop local model, (4) pause low-priority capture, (5) request controlled shutdown for persistent power or storage risk. It MUST NOT kill the arbiter or audit daemon as a resource-reclamation action. Every fence, restart, and state transition emits an audit event and UI status.

## 9. Enforcement, leases, and network isolation

Policy actions are allowlisted: `observe`, `alert`, `throttle`, `block_selector`, `isolate_segment`, `redirect_to_lite`, `redirect_to_az06`, `revoke_temporary_route`, and `rollback`. A policy binds every action to permitted zones, selector grammar, approval requirement, maximum lease duration, corroboration prerequisites, verification probes, and rollback method.

The enforcement adapter MUST:

1. Verify the arbiter signature, active policy hash, intent expiry, action allowlist, and local scope map.
2. Capture and hash the policy-owned pre-state.
3. Apply a transactionally generated nftables/`tc`/routing change with an intent-specific tag.
4. Run policy-declared verification probes and inspect the effective kernel state.
5. Emit the signed receipt, schedule lease expiration, and publish the result.
6. Roll back tagged changes on expiry or verified failure; fail closed for the affected control if rollback cannot be verified.

Deception uses an equivalent but separate `DeceptionLease`. Lite containers live only on `az-decoy0`; a host firewall and namespace rules deny forwarding to protected, management, control-plane, and Internet zones. The isolation check MUST actively test denied paths on boot and before a redirect is eligible. A failed check immediately removes all redirect eligibility.

## 10. M.I.O. route selection and voice queue

Provider admission, confinement, request budgets, deterministic sanitizer
requirements, the full fallback table, and the per-dimension reasons published
with each capability state are specified in
[M.I.O. runtime control plane](mio-runtime.md).

The router selects `local`, `remote`, `local_then_remote`, or `parallel` from mission policy, privacy class, remote health, latency budget, local resource headroom, and incident severity. `remote` is eligible only for P0/P1 frames with a valid sanitizer decision. The default is `local_then_remote`. A remote deadline expiration returns the local result unchanged and records only the sanitized request fingerprint; it never queues P2/P3 data for later submission.

The merger compares claims by cited evidence and outcome. It labels material conflict `ANALYSIS_DISAGREEMENT`; this label never changes an arbiter decision. Remote text is rendered as inert text, with no tool calls, links automatically followed, or instructions treated as commands.

`azazel-voiced` maintains a durable, bounded priority queue:

| Priority | Source | Interrupt rule | Default expiry |
| --- | --- | --- | --- |
| `P0` | integrity, enforcement verification failure | interrupts all speech | 10 min, repeat on escalation |
| `P1` | arbiter action/outcome | interrupts P2/P3 | 5 min, repeat until acknowledgement by policy |
| `P2` | source/module health | waits for P0/P1 | 15 min |
| `P3` | M.I.O. explanation | never interrupts deterministic speech | 2 min |

Queue items include correlation key, severity, scope, immutable source event IDs, suppression window, and acknowledgement state. Deduplicate by correlation key; escalate only if severity or scope changes. The deterministic alert is generated from a template, not model text. Audio failure switches to visual state and audit without blocking the source action.

## 11. Module discovery and signed links

`azazel-module-manager` discovers only peers declared in `/etc/azazel/modules.yaml` or physically provisioned through an operator-approved inventory update. Discovery never grants trust. A candidate presents a TLS client certificate and signed manifest:

```json
{
  "module_id": "az04-field-02",
  "role": "az04-knowledge",
  "api_version": "v1",
  "software_version": "1.0.0",
  "capabilities": ["context.bundle.get"],
  "issued_at": "...",
  "expires_at": "...",
  "nonce": "...",
  "signature": "ed25519:..."
}
```

Acceptance requires certificate chain and pin validation, manifest signature, allowed role/capability, compatible API version, freshness, non-revocation, and zone reachability. AZ-04 content is content-addressed and signed; it is staged, verified, and atomically promoted. AZ-06 receives a lease that names only its assigned decoy zone and bounded action; it cannot query arbitrary evidence or reach protected networks. A changed peer identity, invalid signature, or failed segmentation probe causes quarantine and `FULL -> LITE` degradation.

## 12. Security, boot, update, and recovery

The boot path is UEFI, with Secure Boot enabled by default on machines that support it. **LUKS2-encrypted system and data volumes are required**, and a host that cannot provide LUKS2 is refused for operational deployment. TPM 2.0 measured boot is assumed where a TPM exists. The LUKS data key SHOULD be TPM-sealed to approved PCR measurements with a recovery passphrase held under mission custody. If a TPM is unavailable, require a boot-time operator secret and label measured-boot evidence unavailable; do not silently claim hardware attestation.

The activation controller is the only component permitted to unmask operational services and issue generation-scoped systemd credentials. On every boot it validates the operator/site signature, hardware inventory digest, policy digest, security epoch, generation counter, expiry, renderer digest, and every generated-file digest. Any mismatch leaves operational units masked. An old-generation replay, a replaced renderer, a substituted path, a parallel boot race, and a service-default fallback MUST each produce zero operational packets and zero actions. Activation failure withdraws exposure, expires affected leases, stops or quarantines Deception, restores only owned last-known-good resources, and reports `ROLLBACK_INCOMPLETE` until observed state matches. Software rollback never restores obsolete trust state, policy, or hardware bindings. The controller MAY install the arbiter's intent-signing credential but MUST NOT be able to read or reuse it.

Security boundaries are: untrusted ingress -> observation; operator -> authenticated management; arbiter -> privileged enforcement; decoy -> isolated execution; module -> mTLS/signed contract; remote cognition -> sanitizer-controlled egress. Default host firewall policy is deny, with explicit rules for these paths only. Management services bind only to the management zone. Decoys use rootless containers or dedicated namespaces, read-only images, dropped capabilities, and no host socket mounts.

Updates use an A/B or transactional OS deployment with signed repository metadata and pinned package versions. An update bundle includes software SBOM, unit/config migration, schema compatibility, policy compatibility, and rollback manifest. Apply only in maintenance state after: audit checkpoint, encrypted backup of configuration and indexes, and free-space check. Boot the candidate slot, run health and segmentation tests, and promote only after an operator-approved soak window. Failure returns to the prior slot without deleting evidence. Schema migrations MUST be forward-compatible or include a tested reverse migration.

Recovery media is encrypted, signed, and versioned. It can boot diagnostics, verify signatures and audit segments, unlock data through controlled custody, export evidence, and restore a known software slot. It MUST NOT bypass audit verification, silently reset policy, or erase mission data. A repair that breaks audit continuity creates a new ledger genesis explicitly linked to the last valid checkpoint and requires an operator custody record.

## 13. Required configuration examples

The following example is deliberately generic and belongs in a deployed node as `/etc/azazel/node.yaml`.

`node.yaml` declares **logical roles only**. It does not name an interface. The
binding from a logical role to a physical interface exists solely in the signed
commissioning record, which is produced by operator confirmation and validated
on every boot. A role with no commissioning entry renders nothing and enables
nothing; there is no physical-name, kernel-index, or default-route fallback.
See [commissioning](commissioning.md) §3, §4, and §8.

```yaml
node_id: nexus-field-01
resource_profile: standard          # selected from measured usable MiB; capacity only
commissioning:
  record: /etc/azazel/commissioning/active.record
  require_signed: true
roles:                              # declared intent; eligibility comes from the record
  protected:   {required: true}
  observation: {required: true, zero_transmit: required}
  management:  {required: true, independent_of_enforced_path: required}
  decoy:       {required: false, isolation_attestation: continuous}
  egress:      {required: false}
policy:
  active_bundle: /etc/azazel/policy/active.bundle
  require_signed: true
audit:
  checkpoint_interval: 24h
  minimum_free_gib: 8
  assurance: rollback_anchored      # else LOCAL_CONTINUITY_ONLY with its restrictions
```

The commissioning record holds the composite identity for each confirmed role.
It is operator-signed, digest-bound to the hardware inventory, and is the only
input the renderer accepts for an interface:

```yaml
# /etc/azazel/commissioning/active.record  (illustrative; Fabric CommissioningRecord is a target contract)
generation: 7
inventory_digest: sha256:...
assignments:
  - role: observation
    identity:
      bus_path: pci-0000:05:00.0
      permanent_mac: "..."          # ethtool -P, not the current MAC
      pci_id: "8086:1572"
      serial: "..."
      driver: "i40e"
      driver_version: "..."
      physical_label: "NIC-2 (tap)"
    confirmed_by: op-17
    confirmed_at: "..."
signature: {key_id: site-2026-01, ed25519: "..."}
```

Zero matches or more than one match for a composite identity is not resolved by
preference order: the affected capability returns to `COMMISSIONING_REQUIRED`
and the competing candidates are reported to the operator.

```yaml
# /etc/azazel/mio/sanitizer.yaml
version: v1
remote_default: deny
classes:
  P0-public: {remote: allow}
  P1-sanitized: {remote: allow, fields: [event_class, role, count, time_bucket]}
  P2-mission: {remote: deny}
  P3-restricted: {remote: deny}
redactions: [ip_address, hostname, account, credential, secret, payload, location]
limits: {max_bytes: 16384, requests_per_hour: 20, remote_deadline_seconds: 20}
```

```yaml
# /etc/azazel/modules.yaml
modules:
  - id: az04-field-02
    role: az04-knowledge
    endpoint: https://az04.module.local:9443
    certificate_pin: sha256:REPLACE_AT_PROVISIONING
    required_capabilities: [context.bundle.get]
  - id: az06-field-02
    role: az06-deception
    endpoint: https://az06.module.local:9443
    certificate_pin: sha256:REPLACE_AT_PROVISIONING
    required_capabilities: [deception.lease.apply]
```

## 14. Acceptance tests and release gates

A release MUST demonstrate the following in an isolated lab before a production profile is signed:

- A cold standalone boot reaches `LITE` (or documented `CORE` profile) with no AZ-04/AZ-06/remote route; an action, receipt, evidence chain, and deterministic alert are visible.
- Loss, expiry, bad signature, and identity change for each external module produces `FULL -> LITE`, retains embedded capability, and creates no extra enforcement privilege.
- A P2/P3 M.I.O. frame, invalid sanitizer policy, and malformed remote response produce no egress or control-plane change.
- An attempted direct UI, M.I.O., Knowledge, or Deception call to enforcement is rejected and audited.
- Intent replay, expired lease, scope widening, failed verification, and adapter restart each result in the specified receipt and safe rollback/fence behavior.
- A decoy compromise simulation cannot reach protected, management, control-plane, or Internet zones; failed isolation makes redirect unavailable.
- Audit tampering, checkpoint mismatch, and trusted-clock rollback enter `INTEGRITY_RECOVERY`.
- CPU, memory, disk, thermal, and battery pressure exercises prove shedding order preserves evidence, audit, arbiter, and lease expiry.
- Candidate update rollback and encrypted recovery media preserve the latest valid audit checkpoint and evidence index.
- A clean installation starts no operational network service: before a verified generation exists, capture, forwarding, wireless association, module links, and remote cognition are all absent, and every operational unit is masked.
- An interface whose composite identity is ambiguous or changed returns its capability to `COMMISSIONING_REQUIRED`; the node does not rebind by kernel name, index, or default route.
- An observation-role interface records zero transmitted frames across a link flap, suspend/resume, and driver reload interval.
- Old-generation replay, renderer or generated-file digest mismatch, path substitution, a parallel boot race, and service-default fallback each produce zero operational packets and zero actions.
- A deployment overlay attempting to change Edge action policy, approval requirements, lease ceilings, trust roots, routes, firewall rules, services, container capabilities, or any authority field is rejected as a non-monotonic reduction.
- A correctly signed artifact that matches no tested compatibility tuple, carries the wrong delegated role, or falls below the minimum security epoch is rejected.
- A `standard`-resource host with one usable NIC and no independent management path reaches Core and local cognition and reports capture, enforcement, and Deception as unavailable.
- A high-impact network change that is not acknowledged over an independent management path within its lease window is rolled back automatically.
- Loss of the independent audit anchor moves audit assurance to `LOCAL_CONTINUITY_ONLY`, fences live Deception and new disruptive actions, and labels exports as not rollback verified.

## 15. Implementation order

Implement in dependency order:

1. **Repository bootstrap** — the license, security policy, and contribution
   guide are published; the package layout, dependency manifest, and an
   explicit Fabric pin are not. Until they exist nothing below can be released
   or attested; see [contract ownership](contract-ownership.md) §6.
2. **Fabric adapters against the pinned release** — consume the Fabric-owned
   records that already exist rather than declaring local equivalents.
3. **Inventory, commissioning, and the activation controller** — composite
   identity, operator role confirmation, verified generations, preset-disabled
   units, and rendering from logical roles. This precedes every operational
   capability because no capability may run before a verified generation.
4. **Product admission policy** — delegated trust roles, tested compatibility
   tuples, security epoch, and the bounded extractor.
5. **Identity and audit** — service accounts, socket ACLs, hash-chain ledger,
   checkpoints, and the independent anchor.
6. **Evidence and evaluators.**
7. **Arbiter and one verified enforcement adapter**, with leases, verification,
   rollback, and the two-stage management commit.
8. **UI and deterministic voice.**
9. **Lite services and their continuous isolation attestation.**
10. **Module manager** for optional AZ-04/AZ-06 peers.
11. **Local M.I.O.**, then sanitizer, remote adapter, and merger — the last two
    blocked on the Fabric `mio_contracts` release.
12. **Update and recovery automation.**

No later capability may bypass or revise the authority, commissioning, or audit
contracts established by the earlier stages.
