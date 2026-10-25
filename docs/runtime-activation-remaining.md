# Remaining runtime activation connections

Status: implementation handoff, 2026-10-13. This is not admission evidence,
an accepted new cross-product wire format, or authorization to start services.
Existing [commissioning](commissioning.md) and
[package boundaries](contract-ownership.md#5-released-package-boundary) apply.

## Milestone 1 integration (2026-10-18)

The M.I.O. entry and Knowledge Lite daemons now exist, with console scripts,
fixed socket/state leaves, installer accounts and hardened SUPPORTING units.
`az-mio-entryd` composes MioRouter with locald (`mio`) and remoted (`remote`)
socket clients and records deterministic handoff when providers are unavailable
or unadmitted. Its route ledger is daily segments in `/var/lib/azazel/state/mio/route/`.
No persisted M.I.O. profile reader exists yet, so production selects CORE.
HG-05 remains unmeasured and provider admission remains fail-closed.

`az-knowledge-lited` serves only `knowledge.status` from
`/var/lib/azazel/knowledge`, with read-only commissioned `lite-trust`.
Entry routing does not depend on Knowledge status. Both units are governed by
the activation allowlist; their existence does not establish installed systemd
lifecycle success. The read-only `azazel-nexus setup` command guides the operator
through current state, next commands and reasons. Issues #93 and #5 remain open
for the remaining flow/lifecycle evidence; see [M.I.O. runtime](mio-runtime.md)
and [Knowledge Lite consumer](knowledge-lite-consumer.md).

## Current selected-bootstrap gate snapshot (2026-10-15)

The adopted two-helper implementation is not operationally complete. The actual
selected entrypoint reaches the supervisor, but the production manager still
refuses pair opening and starts; its readiness remains false. Owner approval
of option 1 is already recorded and is not a missing design decision.

| Remaining gate | Current evidence / next action |
| --- | --- |
| Independent elapsed expiry | ARM64 CPython3.13.5 backend compiled with authenticated disposable matching tools; five native smoke tests pass. Operator's corrected real systemd retry now passes expiry and release under the configured controller sandbox subset. Notify/helper lifetime and suspend qualification remain open; a production wheel is not a source-prototype prerequisite. |
| Continuing preconditions | Capacity now rechecked during repeated generation admission without replaying stopped-writer audit; local causal tests pass. |
| Execution admission | First unpacked source profile now connects wrapper/directory/leaf pins, interpreter/venv, startup/routing, loaded module/package origins and pinned-or-absent caches. ZIP/namespace/sourceless execution unsupported in this subset. Historical executed bytes and universal native/OS closure are not claimed; actual deployment qualification remains separate. |
| Native lifecycle | Marker/mount-view agreement, queued/late starts, controller death-to-helper containment and reboot recovery need actual system-manager evidence. |
| Independent deployment state | Operator enrollment, reviewed pins, policy/time/epoch/approval/generation records must be genuinely provisioned; test fixtures do not supply production authority. |

Latest Linux source-snapshot unit result: **6872 passed / 25 failed / 7 skipped**.
Within that same run, the related bootstrap/runtime selection is **2975 passed /
4 skipped**; the four native-backend tests were skipped, not passed. The full
suite is not green: 25 model-import/view failures hit the VM's sub-2-GiB free
space against the existing 2-GiB reserve. No systemd unit was installed or started.

Subsequent launch-environment hardening: isolated macOS related selection
**3016 passed /6 skipped**; fresh Debian ARM64 focused selection **471 passed /
5 skipped**. These overlap earlier runs and are not added to their counts.
The Debian full suite above was not repeated or made green. Fixed pre-exec
environment constraints and retained controller-Service checks are implemented;
interpreter/pyvenv/native-loading semantics and actual system-manager behavior
remain unqualified. See the [launch evidence](evidence/bootstrap-launch-environment-2026-10-15.json).

Latest venv-binding related selection: **3078 passed /6 skipped** on macOS;
**107 passed** in a fresh Debian ARM64 snapshot. These overlap previous results,
are not additive and do not rerun or repair the previous red full suite. See
[venv binding evidence](evidence/bootstrap-python-venv-binding-2026-10-15.json).

Current-Python binding selection: **3136 passed /6 skipped** on macOS;
**165 passed** in a Debian ARM64 snapshot. Actual read-only `-IS` procfs
observation matched the named Debian Python3.13.5 base bytes; this is not a
service deployment or independently approved installed-manifest admission.
Linux exposed a same-stamp mutation gap; the observer now checks two bounded
content hashes, with a causal fixed-stat regression. See
[current Python evidence](evidence/bootstrap-running-python-2026-10-15.json).

The bounded startup-absence increment has macOS related **3165 passed /6
skipped**, then **25 passed** for a final test-only review amendment; final
Debian ARM64 focused **195 passed**. Overlapping counts are not added. The
actual Linux read-only reader also observed the five candidates absent, without
admitting or installing an `/opt` runtime. See
[startup absence evidence](evidence/bootstrap-python-startup-2026-10-15.json).

Native deadline qualification: Debian ARM64 **133 passed**, including **five
actual compiled-backend tests**; macOS **128 passed /5 skipped**. These are
overlapping related selections, not new full-suite totals. The previous
unbuilt-native limitation is superseded for this matching ARM64/Python build,
not for every ABI or deployment. See
[native qualification evidence](evidence/bootstrap-native-qualification-2026-10-15.json)
and its [authenticated toolchain inputs](evidence/bootstrap-native-toolchain-inputs-2026-10-15.json).

Import-routing increment: final macOS related **3190 passed /7 skipped** and
Debian ARM64 focused **219 passed**. The additional macOS skip reflects the
fifth native case added in native qualification, not a new regression. These
overlap earlier runs and are not added. Actual CPython3.13 routing mechanics
also accepted standard finders and refused an instance method override in a
disposable child with synthetic root declarations—not installed-file admission.
See [import routing evidence](evidence/bootstrap-import-routing-2026-10-15.json).

The first unpacked loaded-module profile has macOS related **3216 passed /7
skipped**, then **21 passed** after a type-test-only amendment; final Debian
ARM64 focused **245 passed**. An actual selected-stdlib metadata probe accepted
83 module records with synthetic controller/file declarations and refused a
redirected cache; the previous native extension was reused for metadata only,
not rebuilt or rearmed. None of this is protected runtime admission. See
[loaded-module evidence](evidence/bootstrap-loaded-modules-2026-10-15.json).

### Finite source-prototype work boundary

Private manager composition now has **3239 passed /7 skipped** in the macOS
related selection and **89 passed** in the Debian ARM64 focused selection.
These overlap earlier results and are not full-suite or native-manager passes.
Sol's independent source review found a readiness reinspection gap: the private
adapter now brackets authenticated readiness with the existing retained
publication check. A real ordinary-file mutation during the synthetic peer
exchange is refused. Selected entrypoint plus actual supervisor also exercise
the private adapter, with explicit synthetic publication/OS/cleanup seams.
See [prototype manager evidence](evidence/bootstrap-prototype-manager-2026-10-15.json).

Do not turn production wheel selection or universal OS hermeticity into new
source-prototype prerequisites. The bounded ordinary unpacked profile above is
the first supported subset; unsupported ZIP execution is not a reason to keep
adding general verifiers before composition work.

The private `_PrototypeBootstrapManager` now delegates the supervisor protocol
to retained pair publication, bound audit/commission starts and authenticated
readiness without duplicating transaction state. Its public pair operation is
tested through actual ordinary-file publication/journaling and fake loaded-unit
observations; helper protocol calls also exercise actual job/identity/peer-client
code through the supervisor with synthetic publication/cleanup dependencies.
Individual unmask still refuses. This is software composition evidence, not
native system-manager qualification. Under the currently adopted qualification
contract the fixed production factory remains narrowing-only until authorized native
system-manager qualification. The final switch must be reviewed, not enabled
by another approval boolean or self-produced record. Actual sandbox/lifetime,
mount-view/queued-job/reboot evidence and genuine deployment provisioning remain
distinct operator qualification, not another unfinished verifier project.

After those gates, a reviewed production factory change can select the already
implemented delegation. Do not replace the
remaining obligations with an approval boolean, status result, synthetic test
success or another owner-design question. Individual unmask remains refusing.

Read-only VM recheck on 2026-10-15: the manager reports
`257.13-1~deb13u1` with the reviewed 12 unit paths; controller, auditd and
commissiond all report `LoadState=not-found`, `ActiveState=inactive` and
`SubState=dead`. This is not installed lifecycle evidence. The existing
installer enables the controller for the next boot, so it must not be run as
a harmless preflight. Actual service installation/start now requires explicit
operator authority; the current no-service-operation constraint is retained.
See [read-only preflight](evidence/bootstrap-native-preflight-2026-10-15.json).

The owner subsequently authorized VM trial service installation/start/stop,
excluding provider/fetch/Edge activation. That authority is no longer missing.
However, `sudo -n true` requires interactive authentication in the current SSH
session. No password is saved or passed by the qualification tool.

`tools/qualify_bootstrap_deadline_sandbox.py` is the next bounded native check,
not an activation gate. Default execution prints a plan without reading the
artifact or touching systemd. Explicit root `--execute` operates two uniquely
named transient fixtures, tests the pinned ARM64 native deadline under the
controller's sandbox subset, distinguishes native SIGKILL from manager timeout,
and confirms fixture stop before deleting temporary resources. Cleanup failure
preserves collected results and names retained resources. It does not install,
enable or start any product unit. Type=exec, fixture deadlines and journal
settings intentionally differ from the notify controller; no READY, dependency
containment, mount-view, reboot or suspend qualification follows from this test.

Reviewed tool and native artifact are staged on the VM at
`/tmp/azn-sandbox-handoff.SNurJL`. The operator can run the following from their
terminal; sudo's password prompt stays in that terminal, not a saved file:

```sh
ssh -t -i ~/.ssh/id_ed25519 rabbit@192.168.40.100 '
  cd /tmp/azn-sandbox-handoff.SNurJL &&
  printf "%s  %s\n" 187cc81d348b4c68ce7dff65cc3b97bf0c1930ebb8905156c15b325a5b1a0721 qualify_bootstrap_deadline_sandbox.py | sha256sum -c - &&
  sudo /usr/bin/python3.13 qualify_bootstrap_deadline_sandbox.py --execute --native ./_bootstrap_deadline.cpython-313-aarch64-linux-gnu.so
'
```

Record the returned JSON, including both case outcomes and cleanup status.
If stop or deletion is unconfirmed, use the exact reported fixture names and
directory to inspect/recover; do not treat either individual test result as
overall success. The native artifact's fixed digest is verified again by the
root runner before staging/loading. This is a reviewed operator utility, not
a privileged broker for hostile callers or proof against a hostile root/user.
Initial macOS and Debian synthetic selections each had **47 passed**, before
the actual attempts and correction described below. See
[sandbox tool evidence](evidence/bootstrap-deadline-sandbox-tool-2026-10-15.json).

The operator's first real attempt failed before native arm: `/run` on this VM
is mounted `noexec` and the extension could not map an executable segment.
No `ARMED` marker was emitted; that attempt qualified neither expiry nor release. The
failed unit remained `failed` with zero main/control PIDs and an empty cgroup
property after stop, exposing a separate tool bug: it demanded inactive before
resetting failure state. The updated command above stages beneath a protected,
executable `/var/lib` parent, never remounts `/run` or relaxes sandbox settings,
and resets the exact fixture before fresh inactive/dead/zero-PID checks.
It accepts a garbage-collected unit only with the same inactive/dead/zero-PID
observation. Original failure results are captured before any reset and cannot
become test passes through cleanup. The old root-owned fixture directory
`/run/azazel-nexus-qualification-0zq6m4y8` is intentionally still retained;
the updated tool does not discover or delete previous trials. The previous
command's source hash is superseded; the native artifact is unchanged.
Final correction selections are **53 passed on macOS** and **53 passed on
Debian ARM64**, with target Ruff/docs/diff checks passing. They are synthetic
regression/hardening tests, not native timer passes. The actual first failure,
read-only observations, changed input hash and retest limits are recorded in
[first sandbox attempt](evidence/bootstrap-deadline-sandbox-attempt1-2026-10-15.json).

The operator's second actual run passed **both native sandbox fixtures**:
expiry emitted only `ARMED` and ended with `Result=signal`, `ExecMainCode=2`,
`ExecMainStatus=9`; the separate release process emitted `ARMED` and
`RELEASE_SURVIVED` and exited successfully. The report confirms cleanup, no
unconfirmed units and no retained directory for this retry. Its release
`active/exited` snapshot is from before cleanup, not evidence of a remaining
running service. Coordinator matched the exact reported properties, probe hash,
and local/VM runner/native hashes. This is operator-supplied privileged evidence,
not an independent root journal capture. Read-only unit inventory lists only
the retained first-attempt failure; product units remain not-found/inactive/dead.
See [successful sandbox retry](evidence/bootstrap-deadline-sandbox-attempt2-2026-10-15.json).

Do not repeat these two cases without changed inputs or a concrete regression.
The next native check is notify/READY ordering and helper containment when the
controller dies, using the existing two-helper dependency contract. The
successful Type=exec timer fixtures do not qualify that lifecycle, authenticated
product endpoints, marker/mount views, late jobs, reboot or suspend, and do not
authorize a production-factory switch or manufacture deployment approvals.

Sol's bounded next-trial review selects one unique three-unit notify family:
hold controller before READY and queue the helpers nonblocking; verify through
PID 1 that neither helper has executed; release READY from the controller's
main process and observe active/running before audit then commission readiness.
After both are running, kill only the retained fixture controller main process
and observe helper termination, empty cgroups and drained jobs **before runner
cleanup**, so cleanup cannot masquerade as dependency containment. A consumed
fixture-local marker must also prevent a late helper request from executing
either controller or helper again; a skipped controller condition alone is not
proof of helper refusal. Never touch the product marker. Death while a helper
job is still queued, audit-death propagation, and reboot/suspend remain separate
cases. Reuse the current tool's staging/report/cleanup machinery rather than
adding another admission verifier or repeating timer qualification.

## Renderer consumer gap

The current Nexus runtime contains no operational capture/configuration
consumer. `GenerationStore` can publish complete trees but does not judge their
meaning. A JSON role list alone would not provide the missing consumer.

The reviewed Edge prototype worktree at base
`2a3e42d653f6be148fd010bc18e2afc77aaa78d7` has two distinct contracts:

- `docs/nexus-core-package.md` and `packaging/nexus-core/nexus_core_package.py`
  implement an unsigned, observe-only Core package and fixed CLI health check.
  Package verification is not operational capture admission.
- `docs/X86_64_INTEGRATION_BOUNDARY.md` is an R0 **target**. It calls for
  services consuming rendered configuration and a disabled Suricata template.
  Its illustrative role vocabulary is not a replacement for the pinned Fabric
  vocabulary, nor an implemented wire-format guarantee.

The appliance `systemd/azazel-edge-suricata.service` contains fixed interface
fallbacks and protected subnets; it must not be imported into Nexus. A read-only
tool lookup in the Debian ARM64 review VM did not find `suricata` or `nft` on
PATH. No package was installed and no capture or firewall operation was run.

Before connecting an operational renderer, identify the supported package
consumer/template and its exact configuration schema. Then implement the
Nexus adapter against that consumer using Fabric composite identities and
operator-confirmed roles, with explicit protected-segment policy rather than
appliance subnet defaults. Carry unknown capture/zero-transmit, management
and isolation evidence as unknown; do not convert profile presence to approval.
Inspect the generated configuration without starting capture first. Only after
semantic/resource/topology admission may it enter the activation transaction.
No Edge or Boot repository changes are authorized by this handoff.

## Activation approval storage versus independent context

The library verifier already checks signed approvals against an explicit
`ActivationContext`, operator, current time and maximum lease duration. The
bounded input reader is now implemented in `activation_store.py`, using fixed protected files
`/etc/azazel/activation/approval.json` and `approval.sig`, with current enrolled
operator trust. It reads only; it must not create files or keys, import a
caller-supplied path, or derive expected context from the approval being checked.
Files must be owner-only regular single-link files, ancestry protected and
root-owned, and the containing directory private. Concurrent modification or
trust change before return must refuse. Detached signatures use the existing
activation purpose transcript, not raw JSON signing.

That reader is not yet wired into production: it does **not** fill these independent producer gaps:

| Expected input | Required source / unresolved condition |
| --- | --- |
| Node identity binding | Independently enrolled/declared identity policy; no hostname or machine-ID fallback |
| Boot identity | Current boot readout, not a value imported from the approval |
| Generation and tree digest | Reverified published generation; publication is not semantic admission |
| Commissioning digest / full evidence binding | Authoritatively admitted record plus fresh full signed evidence; not flattened profile names |
| Inventory digest | Independently validated present inventory under the agreed privacy binding |
| Policy, renderer digest | Protected admitted policy and measured deployed renderer; no placeholder digests |
| Security epoch / high-water | Required independent anti-rollback state; directory numbering is not an anchor |
| Time and maximum lease duration | Established clock trust and local policy; no duration learned from the candidate |
| Health / Edge evidence | Actual admitted producers; unsigned package/probe integrity alone is insufficient |

Until the complete independently sourced context exists, the production
entrypoint must continue supplying no lease. Do not add a fallback context or
make diagnostic status an authorization producer just to call the reader.
Authoritative commissioning promotion and the fresh-install supporting-service
bootstrap remain required work, not satisfied by storage or signature success.

## Verification boundaries

Ordinary-file tests with ephemeral keys can prove bounded reading, signature
purpose/context matching, permission/refusal behavior and change detection.
They do not prove production key enrollment, independent rollback state,
installed systemd sandbox execution, Debian Live/HIL or package authenticity.
Keep those results distinct and keep #93 open until its full flow is evidenced.

## Fresh-install bootstrap decision boundary (reviewed 2026-10-13)

Read-only reinspection of the dirty implementation and a separate agent review
confirmed the concrete dependency cycle; this is not a hardware prerequisite
for the software prototype:

- `activation.UnitTier.SUPPORTING` explicitly permits commissioning helpers
  before commissioning is complete.
- `ActivationController.activate` nevertheless requires a verified published
  generation. `_withholding_reason` checks wiring, established health and a
  valid lease before returning the SUPPORTING grant.
- The production `_run_once` deliberately supplies `lease=None` and
  `healthy=False`. The fixed approval reader cannot supply independently
  expected context or establish health. (Superseded for the five
  SUPPORTING loop units by #206 P4, which composes the observe-baseline
  inputs: [§8](activation-observe-baseline.md#8-p4-supporting-wired-into-the-pass),
  and for `azazel-edge-core.service` by P5:
  [§8.1](activation-observe-baseline.md#81-p5-edge-core-in-the-pass).)
- `ActivationContext` currently requires commissioning/inventory/policy/
  renderer digests and epoch information. No accepted bootstrap representation
  of these inputs is specified. Empty or fabricated digests are not a solution.
- Edge package evidence is an additional EDGE_BASELINE requirement, and
  commissioning evidence/record binding is an ENFORCEMENT requirement. Neither
  should be incorrectly demanded as an additional SUPPORTING-tier condition.

Before implementation, a reviewed bootstrap contract must identify who admits
the initial generation and policy, which independent identity/time/epoch/health
sources are accepted, and how a narrowly scoped supporting-only approval is
represented without pretending commissioning is complete. It must name the
exact service allowlist; current SUPPORTING membership alone is insufficient
as a proposed bootstrap allowlist because it also describes fetch/model hosts.
No provider, remote transport, capture or enforcement permission may follow
from starting the commissioning/audit helpers.

The recommended next design step is an explicit supporting-only bootstrap
proposal with refusal/revocation/reboot cases, reviewed against IMPLEMENTATION_SPEC
before changing the entrypoint. An alternative is to retain the unprivileged
prototype runner while leaving production host installation blocked at this
boundary. Neither option authorizes guessed health, self-issued approval,
implicit key enrollment or bypassing the existing generation/lease checks.
The completed prototype HTTP/browser tests do not decide this policy.

## Proposed supporting-only bootstrap contract

Status: **two-helper contract adopted for implementation by owner direction
on 2026-10-14; not deployment authorization or completed implementation**.
This supersedes the earlier design/review-only approval. The owner approved
continuing after an explicit question about adopting the audit/commissioning
contract and implementing runtime wiring. No grant, key provisioning, actual
unit unmask/start, provider admission or enforcement follows from this approval.
IMPLEMENTATION_SPEC now names the separate bootstrap path; its ordinary
activation lease and tier rules remain unchanged. Concrete protected producers
and installed lifetime/mask/boot fencing still require implementation and review.

### Scope and types

The proposed exact grant set is `azazel-commissiond.service` and
`azazel-auditd.service`. No glob, caller-selected unit, dependency expansion,
or `UnitTier.SUPPORTING` shorthand is accepted. Watchdog, Edge probe, fetch,
local/remote M.I.O., capture, Edge baseline and enforcement are excluded.
The activation controller remains the only widening authority; these two
services retain their current unprivileged accounts and local socket boundaries.

Introduce a distinct bootstrap context and verified bootstrap authorization,
not an `ActivationLease` with invented commissioning digests. There must be no
implicit conversion to the general activation lease, and no ordinary
`activate()` path may accept the bootstrap type. A future dedicated controller
pass must reject every unit outside the compiled exact set, even when a newly
installed build wires additional SUPPORTING capabilities.

Use an independently enrolled operator approved for the new, domain-separated
`supporting-bootstrap` purpose by protected local policy. Existing activation
or commissioning signatures must not verify for it, or vice versa. The new
purpose is now represented in `ApprovalPurpose` for pure verifier tests; it does
not enroll an operator or add a production admission path.
The installer neither enrolls a signer nor creates an approval.

### Signed inputs and independent sources

The signed bounded canonical proposal must bind: schema/purpose; approval ID;
operator; exact sorted unit set; independently declared node identity; current
boot ID; bootstrap generation number and tree digest; installed package and
unit-hardening measurements; admitted bootstrap policy digest; security epoch
and revocation/high-water binding; grant/expiry times. Unknown/extra fields,
duplicate keys/units, noncanonical encodings and malformed types refuse.

Expected values come from protected deployment state and fresh measurements,
never from the candidate approval. Signatures establish attribution only:
authenticity, tested compatibility, semantic content, resource/storage checks
and local approval remain distinct admission gates. The runtime must measure
the approved code/unit closure, including systemd drop-ins, dependencies,
ExecStartPre/Post and socket activation; checking only two filenames is not
enough to establish the allowed process set.
The newly started service closure must be a subset of the exact two-unit set.
Independently admitted, already-running OS infrastructure (PID 1/system bus)
is a prerequisite, not permission to start another dependency. Any other new
service, socket/timer-triggered activation or unapproved executable hook refuses.

An explicit `bootstrap/uncommissioned` generation variant is proposed. Its
content contains only the fixed supporting configuration and measured service
closure. It contains no logical network roles, capture configuration, provider
registry, active commissioning record or normal renderer claim. Do not hash an
empty commissioning document into a field meaning approved commissioning.
`GenerationStore` publication remains transactional, but a distinct semantic
admission step is required before this variant can be promoted. Normal
commissioning/generation readers must reject it as a normal operational tree.
Implementation update: the pure variant verifier and protected reader now
implement this metadata/compatibility boundary in the existing numbered
`generation.json` / `tree/bootstrap.json` layout. Normal readers reject it.
This does not provide a publisher or semantic admission; deployment adoption
and provisioning remain distinct. Existing generations must not be rewritten.

### Break the readiness cycle without inventing health

Pre-start health is a controller-owned bounded local check: protected input
ownership and modes; verified bootstrap tree and service closure; writable
private state with policy-defined reserve; verifiable existing audit chain;
available local service-manager transport; and fresh trust/time/epoch state.
It is not a check that the not-yet-started services already respond.
Measurements and policy thresholds must be separate; absent thresholds or
measurements refuse, rather than defaulting to `healthy=True`.

A first empty audit store is allowed only when an independently admitted fresh
provisioning record binds that fact. Missing state on a previously provisioned
node is a refusal, not a new genesis. An unsigned checkpoint or local hash chain
is not an independent rollback anchor. If the deployment requires an external
epoch/anchor and none is provisioned, bootstrap remains refused; this must not
be described as an additional HIL requirement for the unprivileged prototype.

After all gates pass, recheck identities and expiry under a single controller
transaction lock. Durably record the boot-bound grant intent before opening the
exact pair, then send controller READY so the `After=`-ordered auditd service
can start. Verify the live audit writer head against stopped-writer evidence;
append the controller/grant intent and durably bind its receipt before
commissiond can start. Readiness validates the expected service identity,
local socket ACLs and audit continuity. Timeout/failure stops and remasks the
entire bootstrap set. A missing/failed audit record prevents further widening,
but must never prevent narrowing. A service's own `healthy` string is not
admission.

### Expiry, revocation and transition

The existing boot-time oneshot is insufficient to enforce expiry. A proposed
controller-owned bounded supervisor must revalidate trust, revocation, boot,
generation, policy, health and wall-clock trust while helpers are running;
it must not rely on granting the excluded watchdog. Bind an immutable monotonic
deadline at admission as well as signed UTC expiry. Use a same-boot elapsed
clock including suspend (Linux `CLOCK_BOOTTIME`), not uptime excluding suspend;
unavailability refuses rather than silently weakening expiry. Backward clock movement,
clock uncertainty, expiry, trust loss or changed inputs stops/remasks both
helpers. No renewal or reboot fallback is automatic. Exact local duration and
supervision bounds are deployment policy, not measurements invented here.
Before the first start, atomically retain the boot ID, approval ID, immutable
monotonic deadline and protected revocation binding. A same-boot controller
restart reuses that deadline; it never computes a fresh duration from restart
time. Missing, changed or unverifiable retained deadline state refuses and
narrows. A new boot invalidates the grant, even if the signed UTC expiry remains
in the future. Local retained state is not an independent anti-rollback anchor.

Controller death must cause both helpers to stop through a reviewed supervisor
lifetime binding; a bootstrap grant must not survive reboot. Both the
controller-crash path and restart race require service-manager tests before
deployment. Failure to stop/mask is an explicit containment failure: request
the existing broader narrowing mechanism and report it; never claim fencing
succeeded without confirmation. No shell/unit/path supplied by the caller is
executed. The supervisor may narrow but cannot mint an extension.

Proposed lifetime mechanism: the existing activation controller would run a
bounded, non-restarting supervision mode rather than its current oneshot pass.
Both helpers would bind to its lifetime with `BindsTo=` plus `After=`; neither
helper may auto-restart or be persistently enabled by bootstrap. Readiness
ordering must let the supervisor become active before it waits on helpers,
avoiding a systemd ordering deadlock. A helper stop also triggers narrowing of
the pair. These are proposed unit changes, not properties of current units.
See the upstream [unit dependency documentation](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
for lifetime binding semantics. Debian 13's installed systemd must still be
tested, including suspend and kill/crash cases; documentation is not evidence.

The current installer uses persistent masks. A runtime grant must not silently
remove them or leave an unmasked service after reboot. The exact transactional
mask/disable and boot-time fence arrangement, with power-loss recovery, remains
an explicit deployment design gate. No `enable` call or global unmask fallback
is permitted as a shortcut. Until that arrangement is reviewed and tested,
only pure verification and fake-manager composition are eligible for work.

Completed commissioning does not upgrade a bootstrap grant. Stop/remask the
helpers at the phase boundary, retain audit history, and require separately
admitted normal generation/context/approval for any later activation. A
revoked/expired approval cannot be revived by replay, rollback or a new boot;
the independent epoch/revocation state, not directory numbering, determines
that outcome. Repeated valid requests within one bound session are idempotent,
never extend the deadline, and cannot start additional instances.

### Review and implementation sequence

1. Review the proposed purpose, two-unit scope and generation variant against
   IMPLEMENTATION_SPEC and ownership boundaries. Specify policy provisioning
   and the concrete identity/time/epoch/health producers; no hidden fallback.
2. Implement pure context/signature/scope verification using ephemeral test
   keys only. Wrong purpose/key/node/boot/tree/policy/epoch/unit set, revoked
   signer, malformed input, expiry and missing producer must all refuse.
3. Implement protected bounded readers and bootstrap semantic admission with
   regular-file fixtures. Test replacement races, audit genesis versus missing
   history, replay, concurrent passes and refusal of bootstrap metadata by
   normal activation readers.
4. Implement controller composition against a fake service manager: only the
   two named services may widen; audit-first ordering, readiness failure,
   expiry/revocation, clock changes, partial start, audit failure, controller
   death, reboot and commissioning transition must stop/remask without granting
   fetch, provider, baseline or enforcement. Test actual installed systemd
   dependency/lifetime behavior separately before enabling a real deployment.
5. Keep production `_run_once` refusing until the reviewed contract, protected
   deployment inputs and confinement/lifetime tests exist. No current unit or
   activation behavior is changed by this proposal.

### Design review record

2026-10-13: a separate read-only agent reviewed the draft against the current
controller, unit declarations and specification. It identified three material
questions: transitive activation scope, deadline rebasing on controller restart,
and the missing concrete lifetime/reboot mechanism. The revision forbids extra
activation closure, retains a same-boot immutable deadline, proposes explicit
lifetime binding and preserves persistent-mask/reboot handling as an unresolved
deployment gate. Follow-up review found no additional material issue in this
design-only handoff; that is not approval of an implementation or OS boundary.
Main integration additionally specifies suspend-inclusive elapsed time.

Additional integration finding (before the containment-observation fix): `DbusUnitManager.mask()` in
`runtime/src/azazel_nexus_runtime/units.py` calls `MaskUnitFiles` and verifies
unit-file state only. `ActivationDaemon._remask_all()` does not check process
inactivity. The recording manager derives activity from enablement state,
so its successful remask is not evidence that a running service was stopped.
Do not use these existing operations as proof of runtime containment.
The bootstrap adapter needs separately observable unit-file and process/job
states, an explicitly reviewed fixed-unit stop operation, and confirmation
that both helpers are inactive as well as masked. A stop timeout, failed job,
or unknown activity must report containment failure rather than success.
Tests must include a service that remains active after successful masking.
The D-Bus allowlist does not authorize start/stop operations; adding
those operations is a separate reviewed implementation step, not implicit
permission granted by this design. No privileged operation was added here.

2026-10-13 implementation follow-up: all activation narrowing paths now
require a separate positive `is_inactive()` observation after masking. The
read-only `GetInactiveState` semantic operation reads systemd `ActiveState`
and accepts only `inactive`; transitional, failed, unknown and malformed
states cannot be mistaken for stopped by negating the readiness boolean.
A masked but still running unit is reported as a containment failure. This
does not stop it, authorize a new D-Bus mutation, prove an empty cgroup, or
prevent a later start. The reviewed stop/job/supervision boundary remains
unimplemented; production bootstrap remains refusing.

Synthetic regression coverage independently models process and unit-file
state for policy narrowing, preflight remasking, rollback, broader narrowing
and the unexpected-grant emergency path. A separate read-only reviewer found
that last bypass after the initial patch; it was corrected and given its own
regression test. This is source review, not deployment approval.

Final macOS targeted run: 92 passed, including 29 new containment cases;
targeted Ruff passed. Commands:

```sh
./.venv/bin/python -m pytest tests/unit/test_runtime_containment.py tests/unit/test_runtime_activated.py tests/unit/test_runtime_systemd_bus.py tests/unit/test_runtime_activated_entrypoint.py -q
ruff check runtime/src/azazel_nexus_runtime/activated.py runtime/src/azazel_nexus_runtime/units.py runtime/src/azazel_nexus_runtime/systemd_bus.py tests/unit/test_runtime_containment.py tests/unit/test_runtime_activated.py tests/unit/test_runtime_systemd_bus.py
```

The broader macOS run initially produced 574 passed / 4 failed / 26 errors
with overlong Unix socket paths. A short `mktemp` directory resolved that
issue but exposed Linux-only `SO_PEERCRED` requirements: 581 passed / 23
failed. These runs were not successes and product authentication was not
weakened to accommodate macOS.

The final source was then tested in a separate ordinary-user directory on
the existing Debian ARM64 VM, `/tmp/nexus-containment.gsGoAi`, using its
existing Python 3.13.5 rc2 conformance environment. Command:

```sh
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_runtime_*.py tests/unit/test_activation*.py --basetemp=/tmp/nexus-containment.gsGoAi/final-test-tmp -q
```

Result: **605 passed in 1.82 seconds**. The prior 604-pass VM run preceded
the emergency-path correction; only the 605-pass run covers the final patch.

No installed source or running service was replaced. These are local unit
tests (including real Unix sockets for transport), not systemd lifecycle,
provider activation, hardware, or GitHub Actions evidence.

### Bootstrap approval verifier implementation

`src/azazel_nexus/bootstrap_approval.py` implements bounded signature and
canonical-context verification of the proposal. It returns
`VerifiedBootstrapApproval`, not `ActivationLease` or a service-manager token.
Normal activation explicitly refuses non-`ActivationLease` input and masks
its governed units rather than relying on accidental attribute errors.

The payload fixes the two service names and binds the approval ID, boot/node,
bootstrap generation/tree, package, unit closure, admission policy, security
epoch and revocation digest. An independently supplied
`BootstrapApprovalPolicy` separately selects authorized operator identifiers
and maximum duration; enrollment alone is insufficient. Its canonical digest
is also signed, so changing that approval policy invalidates prior evidence.
This approval-policy digest is distinct from the admission policy digest:
health, service closure, fresh provisioning and storage semantics still need
independent admission. Neither policy nor expected context may be constructed
from the candidate document.

No protected bootstrap reader, initial-generation publisher, retained replay
state/deadline, lifetime supervisor, CLI approval import, or actual helper
startup is implemented by this verifier. It deliberately cannot establish
those facts from a signature. Production `_run_once` remains refusing.

Review/validation on 2026-10-13:

- A separate read-only source reviewer found no material issue in the pure
  verifier, purpose separation and normal-lease type guard. This is not
  adoption of the proposed bootstrap protocol or approval to deploy it.
- A separate bounded test worker added `tests/unit/test_bootstrap_approval.py`:
  48 passed using in-memory ephemeral Ed25519 keys. Coverage includes every
  context binding, malformed types/JSON, duplicate/reordered/expanded units,
  wrong/revoked key, cross-purpose signatures, enrollment without bootstrap
  role, changed policy, time bounds and normal activation refusal.
- Main integration ran existing local boundary/operator/activation tests:
  184 passed. Targeted Ruff, `git diff --check`, and document links passed.
- Debian ARM64 Python 3.13.5 broader integration: **782 passed in 2.61s** with
  the command below, using the existing rc2 environment and a separate source
  copy under `/tmp/nexus-containment.gsGoAi`. The first run on tmpfs was
  **780 passed / 2 failed**: model import correctly refused approximately
  1.5 GiB free against its existing 2 GiB reserve. Moving only test scratch
  storage to the approximately 11 GiB-free home filesystem resolved it;
  no product reserve, device, service or installed source was changed.

```sh
task_test_dir=$(mktemp -d /home/rabbit/nxb.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_approval.py tests/unit/test_operator_*.py tests/unit/test_activation*.py tests/unit/test_runtime_*.py tests/unit/test_boundary_static.py --basetemp="$task_test_dir" -q
ruff check src/azazel_nexus/bootstrap_approval.py src/azazel_nexus/operator_trust.py src/azazel_nexus/activation.py tests/unit/test_bootstrap_approval.py
```

These counts overlap and must not be summed as distinct coverage. No production
key, approval sidecar, service activation, provider admission, CI or hardware
validation was performed. Issue #93 remains open; its broader operator-flow
acceptance conditions are not satisfied by pure approval evidence.

### Protected reader and deadline-transition follow-up

`bootstrap_store.load_bootstrap_approval()` reads only the proposed fixed
`/etc/azazel/bootstrap` input directory: canonical `policy.json`, bounded
`approval.json` and a 64-byte `approval.sig`. It uses root-owned no-follow
descriptor traversal and private directory/files, rejects hard-linked files,
and checks the directory identity, all input bytes and fresh operator trust
again after verification. Public callers cannot override the path or owner;
errors are redacted. No directory, key, policy or approval is provisioned by
the reader. Tests replace only private seams with ordinary temporary files.

`bootstrap_deadline.py` supplies pure initial/advance transitions and a
`CLOCK_BOOTTIME`-only read operation, with no monotonic fallback. Same-boot
revalidation never changes the original deadline. It refuses UTC or elapsed
clock rollback, signed expiry, elapsed expiry, unknown clock trust, missing
retained state, a new boot or a changed freshly verified approval. The elapsed
deadline therefore still expires in simulated suspend/stalled-wall-clock
tests. Full approval equality binds context, operator and revocation inputs.

These transitions are **not durable retention yet**. A future protected
transaction must distinguish initial admission from resumption, persist the
initial deadline before start, persist advanced high-water observations before
continued use, and refuse missing/corrupt state without invoking initial
admission again. The local high-water cannot prove its own rollback resistance
or clock trust. No actual helper start or lifetime supervision is implemented.

Environment incident: the reader-test worker exceeded its file-only scope and
recreated the local `.venv` via
`uv run --extra dev --python 3.11 pytest -q tests/unit/test_bootstrap_store.py`.
Current interpreter is Python 3.11.15;
the earlier evidence records macOS Python 3.12.13. No backup of the previous
environment has been found, so exact environment restoration is not claimed.
The existing source diffs remain; the Debian VM environment was not changed.
Further environment writes were stopped. Subsequent local results must be
identified as the new 3.11 environment, not continuation of the old baseline.
`uv.lock` and `pyproject.toml` have no diff. Main review corrected two test
false positives before accepting the reader results: a mistaken trust
attribute masked by generic refusal, and an error-redaction test that had
refused its context before reaching the simulated failing directory reader.

Final verification for this follow-up:

- Separate read-only review found no material correctness issue in the reader
  or pure deadline transitions; it explicitly did not approve persistence or
  service lifetime boundaries.
- macOS Python 3.11.15: **147 passed in 0.64s**, including 22 protected-reader
  and 24 deadline cases; target Ruff passed. Main review corrected clock tests
  to force the BOOTTIME seam on macOS rather than accidentally passing on its
  absence, and added exact expiry and in-interval UTC rollback coverage.
- Existing Debian ARM64 Python 3.13.5 environment: **828 passed in 2.73s**.
  Source transfer stayed in `/tmp/nexus-containment.gsGoAi`; test scratch used
  a new `/home/rabbit/nxb.XXXXXX` directory with sufficient disk headroom.
  No VM packages or installed services changed. Counts overlap, not additive.

```sh
./.venv/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_activation_store.py tests/unit/test_operator_store.py tests/unit/test_boundary_static.py -q
ruff check src/azazel_nexus/bootstrap_store.py src/azazel_nexus/bootstrap_deadline.py tests/unit/test_bootstrap_store.py tests/unit/test_bootstrap_deadline.py
# In the isolated Debian source copy, using its existing environment:
task_test_dir=$(mktemp -d /home/rabbit/nxb.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_operator_*.py tests/unit/test_activation*.py tests/unit/test_runtime_*.py tests/unit/test_boundary_static.py --basetemp="$task_test_dir" -q
```

Remaining implementation: protected durable state publication/resumption,
independent trusted-time/epoch producers, initial-generation semantic admission
and reviewed stop/lifetime/reboot fencing. No production bootstrap admission,
systemd lifecycle success, CI result or completed #93 is claimed.

### Retained deadline storage follow-up

`bootstrap_deadline_store.py` adds fixed-path protected persistence at the
proposed `/var/lib/azazel/state/bootstrap` directory; it does not provision the
directory or wire an installer/runtime grant. The separate initial and advance
APIs have no public path/owner override. A private directory-descriptor seam
supports ordinary-file tests with the current user's ownership.

Initialization refuses any preexisting initial/checkpoint record or unfinished
transaction. It writes a durable pending marker before creating an exclusive
immutable `initial.json` and the first `checkpoint.json`. Advancing requires
both records, revalidates the freshly verified approval and clock observations,
and checks immutable admission fields against the original record. A private
`checkpoint.next` is written and synced, rechecked, renamed atomically and
directory-synced before removing the pending marker. An exclusive nonblocking
directory lock serializes cooperating writers. Missing/corrupt input or leftover
transaction state is never turned into a new deadline.

An I/O error returns no successful state. If it occurs before marker removal,
the unfinished state refuses further normal operations. If final directory
sync fails after marker removal, the checkpoint may already be advanced; a
subsequent accepted operation still uses the same immutable original deadline.
Durability across power loss is not claimed when fsync fails. Power-loss storage
semantics and operator-mediated recovery still require deployment validation.
No automatic cleanup/reset, arbitrary-path writer or service start is added.
Deleting/rolling back the entire store as trusted root remains outside the
local-file guarantee; independent provisioning/replay/epoch/clock trust is
still required before production admission.

Verification on 2026-10-13:

- Independent read-only review found no transaction-ordering flaw under the
  stated local-filesystem/non-hostile-root assumptions. Main integration
  reviewed and corrected fault-injection positions, then added stale-marker,
  rebased-checkpoint and public API regression cases.
- New storage tests: **32 passed**; abrupt worker-exit tests: **2 passed**.
  The latter use real forked processes exiting after synced initial/next-file
  writes. Both leave a refusing store. These are process-crash observations,
  not power-cut or running-service evidence.
- Final macOS Python 3.11.15 related set: **181 passed in 0.84s**.
- Final existing Debian ARM64 Python 3.13.5 related set: **862 passed in 2.99s**.
  The source copy and test-directory pattern are the same isolated locations
  as above. No environment/package replacement occurred in this follow-up.
- Target Ruff, `git diff --check`, and links across 54 Markdown files passed.
  Read-only VM sampling found `CLOCK_BOOTTIME` available and nondecreasing;
  that does not establish wall-clock trust or measure suspend behavior.

Commands:

```sh
./.venv/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_activation_store.py tests/unit/test_operator_store.py tests/unit/test_boundary_static.py -q
ruff check src/azazel_nexus/bootstrap_deadline_store.py tests/unit/test_bootstrap_deadline_store.py tests/unit/test_bootstrap_deadline_crash.py
# Existing Debian environment, inside the isolated source copy:
task_test_dir=$(mktemp -d /home/rabbit/nxb.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_operator_*.py tests/unit/test_activation*.py tests/unit/test_runtime_*.py tests/unit/test_boundary_static.py --basetemp="$task_test_dir" -q
```

Local/VM SHA-256 equality was checked for:

| File | SHA-256 |
| --- | --- |
| `src/azazel_nexus/bootstrap_deadline_store.py` | `7f0576fbd57dab9db3c84dc1cbf471aa8e354dee3e50d9da1f263e861ebc2e29` |
| `tests/unit/test_bootstrap_deadline_store.py` | `21aa7a4549ba0d6d6d69f4d9a22692f30d78fdb5f31a516ca33825038dba3fdb` |
| `tests/unit/test_bootstrap_deadline_crash.py` | `2bc914995b8235f4f51be32a7f5fecf1d10127ec9c36f33b2c5ead3785104ff3` |

Still open: independently admitted initial generation/provisioning and clock/
epoch producers, actual stop/job/lifetime/reboot fencing, and production
controller wiring. Protected persistence is not itself any of these gates.

### Bootstrap-generation format separation

Read-only compatibility review recommended a distinct Nexus-local proposal
format, not an optional commissioning digest on ordinary `Generation`.
`bootstrap_generation.verify_bootstrap_generation()` now checks the proposed
`bootstrap/uncommissioned` variant in memory. Its tree contains exactly one
bounded declarative `bootstrap.json`: the fixed two-unit set and independently
expected policy/package/unit-closure digests. No executable, provider, capture
configuration or fabricated commissioning record is accepted in this tree.
Metadata uses a separate schema and is matched canonically against the expected
number/tree digest; the return type is `VerifiedBootstrapGeneration`, not
ordinary `Generation`. This proves shape/integrity only. Declaring a package
or closure digest does not measure the installed package or service graph.

Ordinary metadata without a variant stays in the legacy format. Ordinary
`GenerationStore.read/verify/current` reject any schema/purpose/variant marker,
malformed/duplicate metadata, directory-number mismatch and absent/invalid
commissioning digest. Bootstrap publication or automatic migration is not
added. `ActivationController` now converts a current-generation domain refusal
into an explicit all-unit withholding/masking decision; unexpected programming
errors still reach the daemon's broader fail-closed handling.

This proposed local format is not an adopted ADR, Fabric descriptor, production
bootstrap admission or rendering contract. Review of its publisher, protected
context producers and installed service closure remains required before any
bootstrap generation can start services. Existing operational generations are
not rewritten and rollback cannot treat bootstrap metadata as operational.

Review found malformed rollback attribution could reach `.strip()` before
becoming a domain refusal; explicit type checks now reject it. Ancestry must
also name positive earlier generations. Regression tests distinguish expected
metadata refusal from unexpected reader defects, which still trigger broader
narrowing. Final local focused tests: **160 passed in 0.64s**, including 27
new variant/compatibility cases. Target Ruff and diff checks passed.
An additional local subset was 124 passed / 1 skipped: the skipped evidence
module requires optional Fabric, absent from the recreated Mac environment;
the existing Debian rc2 environment is used for complete coverage instead.

The first full Debian unit run in the older non-Git scratch source copy was
**4079 passed / 4 failed / 1 skipped** (41.30s). Two harness safety checks
required a real Git checkout, one mutation check required HEAD/worktree
machinery, and a source-tree artifact check saw prior nested test output.
This was not recorded as a successful full suite. No product check was relaxed.

For the corrected setup, a bundle of the actual local HEAD
`778d61bab79805288e136b2f6d0502146e4f3910` was cloned without checkout into
`/home/rabbit/nexus-generation-review.q6DBZI/source`, its index was populated
from that HEAD, and current source/test/documentation files were overlaid.
This is an explicitly dirty review copy, not a new commit or clean build.
Scratch output lives outside that source tree under `/home/rabbit/nxf.XXXXXX`.
No local branch or existing VM deployment was modified by this setup.

```sh
# Within the isolated Git-backed Debian source copy:
task_test_dir=$(mktemp -d /home/rabbit/nxf.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit --basetemp="$task_test_dir" -q
```

Local/VM code/test SHA-256 equality:

| File | SHA-256 |
| --- | --- |
| `src/azazel_nexus/generation.py` | `74f5c8052ca4b55c50f27bbd91a3e59b87ee8d75d697d314971f8edfa8834bb3` |
| `src/azazel_nexus/activation.py` | `0a47bcf1389df67f858364d9a4f04ca74afd639e194a9224e44ec40bd74af3cf` |
| `src/azazel_nexus/bootstrap_generation.py` | `69d524c3cbab0b9cd7648f3e55f1812aa9711c0ecf674b33ccdb9fc55159a9e1` |
| `tests/unit/test_bootstrap_generation.py` | `633978cf6dd3ca21c737b7baa76b55697385900944af4f0e4c07a121a1070ea3` |
| `tests/unit/test_runtime_activated.py` | `0e92842e050ccd1ee1c8752b35bed104ee30e5138f19bb21ca388811996c3095` |

Full-run completion (2026-10-14 JST): **4083 passed / 1 skipped / 2 warnings
in 41.10s** on the Git-backed Debian ARM64 copy. The two warnings concern
forking the crash-test worker from a multithreaded Python 3.13 test process;
both bounded crash tests passed, but this is not a claim of warning-free
validation. CI and actual service-manager lifecycle remain untested.
The VM has `/run/systemd/system` and ran as uid 1000; the installer test for
absence of systemd is explicitly skipped under that condition. This is not a
successful observation of the missing-systemd refusal on this VM.

Validation: internal document links passed across 54 Markdown files;
`git diff --check` passed. No Nexus source, unit, lease, trust store or installer
was changed in this design step, so no runtime test or live activation result
is claimed. At that earlier checkpoint, owner design/review approval had not
adopted the contract; the later implementation approval above supersedes that
status without authorizing deployment.

### Adopted-contract supervisor increment (2026-10-14)

The owner approved proceeding after the explicit adoption question. The target
spec now distinguishes this exact two-helper contract from normal SUPPORTING
leases. Existing dirty changes, the Mac venv and VM installed environments were
preserved. No production entrypoint, service-manager allowlist, systemd unit,
operator trust or running host service was enabled by this increment.

Added runtime `bootstrap.BootstrapSupervisor`: an activation-owned transaction
with required admission/refresh/locking/audit/manager dependencies. It starts
audit before commissioning, checks readiness and refreshes independently
verified retained inputs around widening, uses an immutable suspend-inclusive
deadline and bounded polling, and never requests enable or an extra unit.
Startup, partial start, cancellation, failure and expiry all attempt masking,
reverse-order stopping and positive inactive **and** masked observations for
both helpers. Unconfirmed containment requests broader narrowing and raises;
audit failure cannot bypass cleanup. A consumed supervisor cannot restart.
Exception cleanup is not SIGKILL, power-loss or installed lifetime fencing.

Added `bootstrap_inputs.ProtectedBootstrapInputs`: connects fixed protected
approval verification to advancing existing retained deadline storage, checks
independently supplied observation/context/operator/time stability and current
boot identity around the reads. It has no initialization fallback or signer.
The independent producer remains mandatory; the signature candidate is not its
source. Runtime uses the library public validated `parse_bootstrap_time` API.

Independent read-only review found cancellation bypassed the final stopped
audit event despite performing cleanup. This was fixed by routing cancellation
through the common post-cleanup record, with before-start/audit-ready/poll
regressions. Main review strengthened partial-start, running-session change,
scope and actual cross-operation audit ordering tests. The new 46 cases are
synthetic-manager/reader tests, not actual systemd jobs or protected deployment.

Validation results (overlapping subsets must not be added):

- Initial Mac runtime subset: 78 passed / 1 failed because existing local venv
  lacks `dbus-next`. No installation or environment replacement followed.
- Initial Debian related run: 662 passed / 1 failed: the runtime boundary test
  detected a private library `_utc` import. The test was not weakened; a public
  validated time boundary and malformed-time tests replaced that import.
- Final Mac new-controller/input/boundary subset: **59 passed in 0.27s**.
- Final Debian ARM64 bootstrap/runtime subset: **668 passed in 2.09s**.
- Target Ruff and `git diff --check` passed. Full unit suite, repository-wide
  lint, CI and installed-service lifecycle were not rerun for this increment.

Commands:

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap.py tests/unit/test_runtime_bootstrap_inputs.py tests/unit/test_runtime_boundary.py -q
# Existing isolated Git-backed Debian review copy and existing rc2 environment:
task_test_dir=$(mktemp -d /home/rabbit/nbs.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Five code/test hashes agree between the Mac source and VM review copy:

| File | SHA-256 |
| --- | --- |
| `src/azazel_nexus/bootstrap_approval.py` | `2588f3fba0fdeca1b713c6de7c68f6ec030fc89146bf07cc7add270c98124d02` |
| `runtime/src/azazel_nexus_runtime/bootstrap.py` | `7de63212ee2a474a30fdb681f44789a7b4e7fd8b05860392d004c7bceb1cd87e` |
| `runtime/src/azazel_nexus_runtime/bootstrap_inputs.py` | `290c815d2f271df251bc182d9c874766ed198b2131c47aa681d6aee7bdfa4cbd` |
| `tests/unit/test_runtime_bootstrap.py` | `c6ab52b76bcfa2e5f142f893c9f105da4e9b956f921c663f2b3094d7a1366032` |
| `tests/unit/test_runtime_bootstrap_inputs.py` | `98a22d81587dc405525444f282ee9475e3a41aac5f7f50c367bce59936c89b6a` |

Next implementation boundary: supply reviewed independent protected observation
and semantic-admission producers, a lifetime transaction lock and a bounded
two-helper service-manager backend with the persistent-mask/reboot fence.
Then connect this supervisor to `az-activated` instead of its refusing oneshot
path and test the installed lifecycle separately. The new supervisor and input
adapter are **not yet called by that production entrypoint**. No assertion of
completed runtime wiring follows from these tests. The implementation direction
is approved; no repeat adoption question is required for those remaining steps.

### Lifetime transaction lock connected (2026-10-14)

The supervisor now defaults to the real library `bootstrap_transaction()`
instead of requiring an otherwise unimplemented lock callback. This locks
`/var/lib/azazel/state/bootstrap/supervisor.lock` with nonblocking exclusive
`flock` for the entire supervised transaction, including narrowing and final
audit. The private root-owned directory must preexist; no provisioning or
deadline initialization is inferred from creating the empty 0600 lock file.
The file is no-follow, regular, single-link, owner-private and empty, and is
never unlinked after use. Existing protected ancestry traversal is reused.

The yielded validator is required by the runtime and runs before and after
each admission/refresh check. It compares both held descriptors with freshly
opened fixed-path directory/file identities. Replacements, owner/mode changes,
missing state and released or foreign-process validators refuse. Narrowing is
still attempted after validator failure. A failed acquisition does not affect
another supervisor. Exception-path checks preserve an already-raised containment
failure or interrupt rather than replacing it with a secondary lock failure.

Independent review checked the implementation and final integration. Tests
exercise ordinary-file locks across separate descriptors and an actual spawned
contender process, acquisition races, inode retention, directory/file replacement,
and a retained validator after release/reacquisition. Recording-manager tests
confirm the lock stays held across start, wait and cleanup, and that replacement
after audit readiness prevents commissioning start but not cleanup.

Final Mac subset: **79 passed in 0.40s**. Final Debian ARM64 bootstrap/runtime
subset: **688 passed in 2.21s**. Four code/test hashes match across local and VM
copies. Target Ruff and diff checks pass; existing environments were not changed.
Commands and hashes: [machine-readable lock evidence](evidence/bootstrap-lifetime-lock-2026-10-14.json).
These subsets overlap earlier runs and are not new full-suite/CI results.

The lock serializes cooperating controllers. It cannot stop orphaned helpers,
prevent hostile-root replacement, or make an unmask reboot-safe. Protected
observation/semantic-admission producers and the bounded service-manager plus
lifetime/reboot-fence backend remain the next integration work. Production
`az-activated` still does not run the supervisor; no live activation is claimed.

### Stop-job transport increment (2026-10-14)

Added `runtime/bootstrap_stop.py` with a dedicated stop-only D-Bus adapter.
It accepts only audit/commissioning `UnitKey` values, not unit names or method
arguments from a caller. No Start, Enable, Unmask, Restart or CancelJob operation
is exposed. It requires an already-owned dedicated bus connection; it does not
connect or change the ordinary production adapter allowlist.

The adapter subscribes and installs its signal handler before StopUnit, queues
early notifications, and correlates exact job ID/path, unit, signal envelope and
systemd unique owner. Manager/property calls are addressed to that pinned unique
owner, not a potentially replaced well-known owner. A successful job notification
must be followed by an exact unit-object and `ActiveState=inactive` observation
and another owner check. Unknown, skipped, cancelled or failed jobs do not count
as success. This follows the upstream
[systemd v257 D-Bus job contract](https://raw.githubusercontent.com/systemd/systemd/v257/man/org.freedesktop.systemd1.xml),
not an observation of installed systemd behavior.

Independent review caught `replace` potentially replacing conflicting jobs;
the adapter now uses mode `fail`. A conflict remains explicit containment
uncertainty; no broad job cancellation is attempted. Unit dependencies and
failure handlers still need installed closure admission: constraining the
requested name is not proof of all resulting process effects.

Review also caught that `asyncio.wait_for` may exceed its timeout while waiting
for cancellation. This new adapter uses separate finite operation/cleanup waits,
poisons the client on failure, and rejects late replies before further calls.
Tests include cancellation-resistant Subscribe and Unsubscribe coroutines: after
their budget ends, releasing the delayed response cannot issue StopUnit or a
late RemoveMatch. Failed clients must be discarded; cancellation is not a claim
that systemd undid an already accepted stop. Queue overflow refuses. Blocking
the Python event loop itself is outside this asynchronous-wait guarantee.

The existing `SystemdBusSession` now bounds connect and exchange using a
10-second **cooperative** wait. Connect failure disconnects and restores/closes
the owned event-loop context; a disconnect error cannot leak past the redacted
connection refusal. This older path does not have the new stop adapter's
cancellation-resistant timing guarantee. A missing mask reply never triggers a
success state read or a successful narrowing claim.

Final local new-code/boundary subset: **57 passed in 0.25s**. Final Debian
ARM64 bootstrap/runtime subset: **732 passed in 2.32s**. All bus responses are
synthetic; no actual systemd operation was performed. The 44 new tests are not
hardware evidence. Target Ruff, diff check and document links passed. No full
unit-suite, repository-wide lint or CI run is claimed. Counts overlap prior runs.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap_stop.py tests/unit/test_runtime_bus_timeouts.py tests/unit/test_runtime_boundary.py -q
# Existing Debian review copy and rc2 venv; fresh ordinary-file scratch directory:
task_test_dir=$(mktemp -d /home/rabbit/nbj.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Local/VM SHA-256 matches:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/bootstrap_stop.py` | `2605939d6966822661add334be6b125c4d78192c1931e162ac5e6018291f83f9` |
| `runtime/src/azazel_nexus_runtime/systemd_bus.py` | `4cb33c8ed0453307468c12815d692c8e661cdad43b2ebfaf9d5ade1a6954375a` |
| `tests/unit/test_runtime_bootstrap_stop.py` | `cafcab3b6efa6978a164a0d53bd43ae61fe465c08fff8d548c91292ec44f15d6` |
| `tests/unit/test_runtime_bus_timeouts.py` | `859946b54059f2541cd485b71b6fb35338f23ead2372f3759608af7fcf1769d5` |

Still open: composing this asynchronous stop observer into the synchronous
supervisor backend; start/readiness, persistent-mask and controller-lifetime/
reboot fencing; independent protected producers and semantic admission; final
production entrypoint wiring and installed lifecycle verification. This is not
a completed start/stop backend or permission to execute Stop on the VM.

### Supervisor-to-stop-manager connection

`BootstrapNarrowingManager` now implements the supervisor's synchronous
narrowing interface using the existing fixed system-bus session and the new
asynchronous stop-job observer. Mask/state observations each own a fresh session;
stop runs on that dedicated session's bus/event loop. Cleanup disconnects before
bounded cancellation/draining of pending tasks, then closes the session. It does
not reuse an uncertain observer or inherit another caller's subscription.
Operational failures remain failures even if subsequent cleanup also fails;
cleanup failure after an otherwise successful operation is a redacted refusal.

Exact audit/commissioning enum keys are required before any connection. Raw unit
names and all other unit keys refuse. `unmask` and `start_and_wait` deliberately
refuse without opening a session, and `is_ready` remains false: active-state
inspection alone cannot establish authenticated helper readiness. This adapter
is usable for the narrowing portion of supervisor composition, not as evidence
that the missing widening/lifetime/reboot backend is complete.

An independent read-only source review found no additional actionable issue in
the session ownership/cleanup implementation. Actual D-Bus/systemd operations
remain unexecuted; production `az-activated` still uses its refusing path.

Final verification for this increment (2026-10-14): Mac targeted manager,
stop, supervisor and runtime-boundary tests **127 passed in 0.39s**; existing
Debian ARM64 review copy bootstrap/runtime subset **773 passed in 2.31s**.
The manager test file has 41 cases, including actual supervisor-to-adapter
composition with a fake bus, cleanup error precedence/redaction and invalid
timeouts. These are synthetic transport tests, not installed systemd lifecycle
evidence. Counts overlap earlier checkpoints and are not additive. Targeted
Ruff passed, `git diff --check` passed; no CI or full-suite rerun is claimed.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap_manager.py tests/unit/test_runtime_bootstrap_stop.py tests/unit/test_runtime_bootstrap.py tests/unit/test_runtime_boundary.py -q
ruff check runtime/src/azazel_nexus_runtime/bootstrap_manager.py tests/unit/test_runtime_bootstrap_manager.py
# Existing Debian review copy, existing rc2 venv, ordinary-file scratch only:
task_test_dir=$(mktemp -d /home/rabbit/nbm.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Matching final local/VM SHA-256:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/bootstrap_manager.py` | `eb3b66396abdbaf39ab1249dfb7b0fcd6357a9b200a14d3596835ec12e9713e2` |
| `tests/unit/test_runtime_bootstrap_manager.py` | `17e3032cad39fa0dc35b792f711513372ed58b8daa4c8ed57485e41eb6db1e02` |

### Packaged controller-lifetime dependency increment (2026-10-14)

The generated controller unit now uses `Type=notify`, without `RemainAfterExit`.
Its current production entrypoint still performs a refusing pass and exits;
that exit no longer leaves a logically active supervisor. It emits no readiness
notification, so systemd startup is unsuccessful even when the refusal ledger
was written with exit status zero. The eventual long-running supervisor must
notify only after mandatory containment and admission, but **before** waiting
for helper readiness (helpers wait for controller startup through `After`).
No such readiness signal is emitted by the current production entrypoint.
Independent review caught a preflight race in the initial `Type=exec` draft:
it would release dependent starts as soon as exec succeeded. That draft was
withdrawn before deployment, and tests now require explicit main-process
readiness for the controller as well as the helpers.

The exact audit/commissioning pair now declares `BindsTo=azazel-activated.service`
alongside its existing `After`/`Requires`. All three explicitly disable automatic
restart and use control-group termination; notify helpers explicitly restrict
notification to their main process. The generated source and packaged files are
checked byte-for-byte. No other unit acquires these dependencies, and no
installer mask, enable list, D-Bus permission or production grant path changed.

These declarations implement part of controller-lifetime binding, not proof of
OS enforcement. Their intended semantics follow upstream
[unit dependency documentation](https://github.com/systemd/systemd/blob/v257/man/systemd.unit.xml)
and [service type documentation](https://github.com/systemd/systemd/blob/v257/man/systemd.service.xml).
Persistent-mask/reboot grant recovery is still unresolved: a runtime unmask
does not override an existing persistent mask, while simply removing the latter
would leave a crash/reboot gap. This change does neither. Controller kill,
bounded stop/cgroup termination, reboot and installed dependency behavior still
require separate lifecycle verification before deployment. The manager still
refuses start/unmask. No real service was started, stopped or reconfigured.

Scope incident during delegation: the test-only worker briefly edited the
hardening declaration. The coordinator stopped it before integration, the worker
removed its own additions while preserving the prior dirty diff, and the
coordinator then applied the reviewed-scope declaration patch. No generated
unit, installed service or environment was changed by that worker. Final tests
and source review below cover the coordinator's resulting tree, not the
withdrawn worker patch.

The independent revision review found no new widening path in the final notify
declaration, and confirmed the intentional unsuccessful startup while the
entrypoint emits no `READY=1`. This is source review, not OS lifecycle approval.
Other governed services still have their prior lifetime relationships; the
two-helper mechanism is not a fence for provider/fetch/Edge/watchdog units.

Final local targeted validation: **54 passed in 0.19s**. Existing Debian ARM64
review-copy bootstrap/runtime subset: **776 passed in 2.31s**. These tests cover
packaged declaration values and code behavior with synthetic transports, not
installed systemd jobs. The earlier exec-draft runs are superseded by this final
notify-tree result. No full suite, CI, installation or actual service lifecycle
was run. Document links: 54 Markdown files passed; diff whitespace check passed.
New test Ruff passed. Unfiltered hardening Ruff reports three pre-existing F401
imports (`field`, `Mapping`, `Sequence`), confirmed in HEAD; excluding F401
passes. Those unrelated imports were not changed and unfiltered lint is not
claimed clean.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap_lifetime.py tests/unit/test_runtime_hardening.py tests/unit/test_runtime_boundary.py tests/unit/test_runtime_activated_entrypoint.py -q
ruff check tests/unit/test_runtime_bootstrap_lifetime.py
ruff check runtime/src/azazel_nexus_runtime/hardening.py --ignore F401
# Existing Debian review copy and rc2 venv; fresh ordinary-file scratch:
task_test_dir=$(mktemp -d /home/rabbit/nblf.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Matching final local/VM SHA-256:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/hardening.py` | `f557320e9d0024ed96c4cbf7b75724f5d25e6a3277f4deb813df8b721725c8a6` |
| `packaging/systemd/azazel-activated.service` | `bc4f3ed27125cf69f13938a858d36d9fafd2fda3d7dd06a7cfb487d7a4d6fc42` |
| `packaging/systemd/azazel-auditd.service` | `913069d222c4c9dfa83132a9352c27baeb7b3e4bc1ebfe89a700d05480d84d1f` |
| `packaging/systemd/azazel-commissiond.service` | `3b67a424569b82a72ef349a1dfd09aa12a6a13c0970625a69deeeabf67ca7b93` |
| `tests/unit/test_runtime_bootstrap_lifetime.py` | `f222e08a6b8c3ee85d9fdb1af664cef8622d98039fb5b499d6e57ea06ba8d92a` |

Next concrete wiring gap confirmed in source: `auditd.main` and
`commissiond.main` pass their optional `ready` callback (default `None`) to
`serve_forever`; it calls the callback after binding/listening but has no default
systemd notification. Therefore even the existing notify helper declarations
are not proof of an installed readiness handshake. Implement the fixed runtime
notification boundary and controller handoff ordering, test with ordinary Unix
socket fixtures, then independently verify installed notify/job behavior before
claiming that a service start completes. Do not supply success from ActiveState
or an injected callback alone.

### Main-process notification and supervisor handoff (2026-10-14)

`systemd_notify.notify_ready()` now sends only `READY=1` over a one-second
bounded Unix datagram operation to the fixed `/run/systemd/notify` address.
It has no public address/message/PID parameters, requires the host-root runtime,
the system-manager marker and the expected invocation/environment shape, and
redacts failures. These context checks are not authentication: the receiver's
`NotifyAccess=main` sender attribution is the systemd boundary. Alternate systemd
socket layouts refuse rather than fall back. A completed send is not a manager
acknowledgement or a proven service start. The protocol basis is upstream
[sd_notify documentation](https://github.com/systemd/systemd/blob/v257/man/sd_notify.xml).

Audit and commissioning production entrypoints now select this default callback;
existing explicit harness callbacks are preserved. Relocated `AZAZEL_ROOT`
user-process harnesses select no systemd notification and cannot use this as
installed-service readiness evidence. Audit checks its chain before serving.
The shared accept loop invokes readiness after binding and engine construction;
timeout setup, engine construction and notification are now inside its cleanup
region, so those startup failures close the listener and remove its socket.

`BootstrapSupervisor` requires a `controller_ready` composition dependency.
It completes initial containment and independent admission, persists a readiness
intent, rechecks time/inputs/cancellation, then notifies before helper start.
It rechecks after notification and before each unmask/start. This releases the
controller's `Type=notify` barrier before waiting for its `After`-ordered helpers
without declaring readiness before admission. Notification failure, cancellation
or expiry follows the common containment path. Independent source review found
no additional ordering defect. Production `activated.main` is deliberately not
wired to this supervisor yet and still emits no readiness notification: missing
protected producers, start backend and persistent-mask/reboot fence must not be
replaced with a successful signal.

The first targeted run had **82 passed / 6 failed** because the newly delegated
test used the wrong import-time ROOT monkeypatch seam and its fake socket lacked
the real socket context-manager protocol. Tests were corrected to exercise the
actual interface; refusal behavior was not relaxed. Final Mac related run:
**119 passed in 0.37s**. Debian ARM64 bootstrap/runtime subset:
**809 passed in 2.35s**. This includes a temporary Unix datagram socket test, not
the real systemd socket. New cleanup tests' two E731 findings were fixed.
Target Ruff passes except two pre-existing F401 imports in `auditd.py` (`json`,
`field`, confirmed in HEAD); that file passes with F401 excluded. No actual
systemd notification, service operation, key enrollment or CI was performed.

Because production helper entrypoints changed, the full unit suite was also
rerun on the existing Git-backed Debian ARM64 review copy using its unchanged
rc2 venv: **4270 passed / 1 skipped / 2 warnings in 40.31s**. The skip remains
the installer missing-systemd case on a systemd host; warnings are the two
existing Python 3.13 multithreaded-fork crash tests. This is a local dirty-tree
review run, not CI or a deployment. Results overlap the subsets above.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_systemd_notify.py tests/unit/test_runtime_ready_cleanup.py tests/unit/test_runtime_bootstrap.py tests/unit/test_runtime_bootstrap_manager.py tests/unit/test_runtime_boundary.py -q
# Existing Debian source copy and venv, scratch outside the source tree:
task_test_dir=$(mktemp -d /home/rabbit/nbfull.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit --basetemp="$task_test_dir" -q
```

Final code/test bytes were compared locally and on the VM; all nine match:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/systemd_notify.py` | `29b6a26379ceb2240bc9a3f43cd8ea1240d3ce1d95bfcc9dd9e6281a3c69d143` |
| `runtime/src/azazel_nexus_runtime/serve.py` | `933eccc8345e539898888741bd91a0aa3ecf8f5a069104165299c771daff06fd` |
| `runtime/src/azazel_nexus_runtime/bootstrap.py` | `b132a197dde7e8f66425f3bd5eb937cf804205aacc5a7523984234abe9e32c42` |
| `runtime/src/azazel_nexus_runtime/auditd.py` | `f14ee7d008e3b7c1f26fcadc15a5b05a3e8512f8ddc89d09281d6034a4cd5ddd` |
| `runtime/src/azazel_nexus_runtime/commissiond.py` | `9f81f955cffeb660519becac4148434e503fd4a5155def58bbbe536c59df5c05` |
| `tests/unit/test_runtime_systemd_notify.py` | `9f6eca1df55da86ce5a24203e91ce2b2eed877136d83702a62e7fe4d4a4fb617` |
| `tests/unit/test_runtime_ready_cleanup.py` | `ac47979fbd2a39c25f74aa740e6adaa0659767dfc0b3b5b9b536ca5bc065b6bd` |
| `tests/unit/test_runtime_bootstrap.py` | `b1a948c4b8fbfc654cd313c82bee0a595f8f7a67680bf88c8afd03063c11397c` |
| `tests/unit/test_runtime_bootstrap_manager.py` | `3e2eed5290a07d15dbee3cebea22011080ebf73710e0a9afdaad750397bc0f88` |

Remaining gates are unchanged by a notification send: independently admitted
protected context/generation/health producers, retained initial provisioning,
the widening job backend and persistent-mask/reboot recovery, final activation
entrypoint wiring, and separately authorized installed lifecycle verification.

### Guarded start-job observation (2026-10-14)

Added private `BootstrapStartJobs`, sharing the bounded subscription/job observer
with the stop adapter instead of duplicating its protocol. The public stop
method remains stop-only. Start requires the exact audit/commissioning enum pair
and an explicit synchronous `check_start` dependency; no RPC, CLI or production
factory supplies that dependency. The guard must revalidate retained deadline,
independent admission, installed notify/dependency closure and lifetime/reboot
fencing, return exactly None or raise. It is not synthesized from approval alone.

The adapter checks before bus contact, observes the target as inactive, subscribes
before `StartUnit` with fixed mode `fail`, checks again immediately before start,
correlates owner/unit/job ID/path/result, positively observes active state, and
rechecks admission. Late replies/failed jobs/cancellation/timeouts poison the
observer; cleanup remains bounded and no retry is performed. A submitted start
can still take effect after timeout: the caller must contain the pair on every
failure and discard the dedicated connection. No cancel/enable/unmask operation
is added, and ActiveState/job completion alone is not authenticated readiness.

The shared observer now checks its operation budget before non-cleanup bus calls
and rejects a completion delivered after the budget. A synchronous guard that
eventually returns late cannot issue a late Start. It cannot preempt a guard
that never returns; bounded trusted input readers remain a composition obligation.
Independent source review confirmed the implemented ordering and called out that
limitation. `BootstrapNarrowingManager.start_and_wait` still deliberately refuses;
the incomplete deployment fence is not bypassed to exercise this adapter live.

Added 37 fake-bus cases covering the exact pair, three admission checks, rejected
preflight/late checks, malformed or unrelated signals, owner change, failed job,
post-state mismatch, cleanup, timeout/cancellation, no retry and an over-budget
synchronous guard. The main integration fixed 12 style findings in the new
test file; no production checks were relaxed. Final targeted Mac run:
**132 passed in 0.35s**; target Ruff and whitespace checks passed.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap_start.py tests/unit/test_runtime_bootstrap_stop.py tests/unit/test_runtime_bootstrap_manager.py tests/unit/test_runtime_boundary.py -q
ruff check runtime/src/azazel_nexus_runtime/bootstrap_start.py runtime/src/azazel_nexus_runtime/bootstrap_stop.py tests/unit/test_runtime_bootstrap_start.py
# Existing Debian copy/venv, ordinary-file scratch only:
task_test_dir=$(mktemp -d /home/rabbit/nbsj.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

No real StartUnit, installed service change, CI or full-suite rerun was performed
for this increment; the preceding 4270-case full run is historical, not this
new start adapter's full-suite result.

Final Debian ARM64 bootstrap/runtime subset: **846 passed in 2.45s** after
syncing the final test formatting. Local/VM code/test hashes match:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/bootstrap_start.py` | `b48a78b34b8a7091fc5938ab853108a690d08b900e0df51aa8a299475cf6969e` |
| `runtime/src/azazel_nexus_runtime/bootstrap_stop.py` | `fe9c5c5caf6cb0d63249460888c81c82f77f441c0e296a3cb93f8fd406d9f88c` |
| `tests/unit/test_runtime_bootstrap_start.py` | `591a6780ca448e05f353e03f222b85ce387806a563078cedbdeca74e08ec46e1` |

Next fence design candidate (not adopted or implemented): preserve the exact
`/etc/systemd/system/<helper>.service -> /dev/null` persistent masks while
placing independently admitted copies in the higher-priority volatile
`/run/systemd/system.control` load path. A separate read-only design review
recommended only a guarded prototype, based on upstream systemd v257's
[load-path/drop-in rules](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.unit.xml).
It requires rejecting higher-priority entries, aliases and unexpected drop-ins,
checking effective execution/security/dependency properties and FragmentPath
after reload, proving `/run` volatility and absence of boot-time re-creation,
and confirming stop/process containment separately from remasking. Reload reruns
generators and does not stop existing processes. This manager-owned load path is
a deployment-sensitive choice, not a selected production mechanism or proof of
reboot fencing. First implement/inspect a regular-file-only prototype and review
the exact loaded-unit verification contract; do not copy files into a live
systemd directory or issue daemon-reload on the VM under this software-only work.

### Isolated mask-overlay prototype and native offline observation (2026-10-14)

Implemented `tools/inspect_bootstrap_mask_overlay.py`, not a production backend.
It accepts no destination/unit/payload: each instance creates a new private
temporary tree, renders the current three packaged declarations, and inspects
fixed helper mask symlinks without opening their `/dev/null` target. The exact
closed fixture tree is verified with no-follow descriptor-relative traversal;
unexpected overrides/drop-ins, mutated bytes, hardlinks, replaced identities or
unsafe permissions refuse. Grant publishes only the exact two candidate copies;
withdraw removes only verified owned copies. Partial publication/withdrawal is
reported as incomplete, never atomic success or confirmed containment. Fixture
cleanup removes its own scratch tree. No protection against hostile same-user
concurrent mutation, durable production rollback or OS enforcement is claimed.

`--verify-offline` runs the fixed `/usr/bin/systemd-analyze` against that fresh
root by unit name, with generators and man-page execution disabled and a minimal
environment. On the existing Debian ARM64 VM, systemd **257.13-1~deb13u1**
reported for both helpers:

1. Persistent-mask-only fixture: the unit is masked.
2. Candidate present: `Fragment Path` is the candidate under
   `run/systemd/system.control`, while the persistent symlink is unchanged.
3. Candidate withdrawn: the unit is masked again.

All six analyzer calls exited **1**, not success. The masked phases explicitly
refuse masked units; the candidate phases select the intended fragment but lack
fixture OS dependencies (including `sysinit.target`) and executable entrypoints.
Architecture-specific syscall-name warnings and VM metadata read diagnostics are
also retained. No stubs or relaxed unit settings were added to turn this into a
green verification result. The evidence establishes observed offline load
precedence only, not a valid complete rootfs, live reload/start, process death,
reboot behavior or a production fence. The analyzer created an offline manager
and read VM cgroup/EFI metadata; it did not operate the running service manager
or change firmware. Raw output, nonzero exit codes, version, candidate digests
and runner hash are preserved in
[machine-readable evidence](evidence/bootstrap-mask-overlay-2026-10-14.json).

Corrections and unsuccessful runs:

- Initial VM fixture construction refused vendor files under its group-writable
  umask. Files now receive explicit 0600 permissions. Its one leaked scratch
  directory was individually inspected and removed; subsequent runs clean up.
- Independent source review found root-fd-open failure could leak a newly empty
  scratch directory. It now removes only that new empty directory and has a
  regression test.
- The first expanded VM subset had **859 passed / 1 failed**: the hardlink test
  attempted to cross `/home` and `/tmp` filesystems. Its external fixture is now
  on the same filesystem; hardlink rejection remains unchanged.
- The test worker also exceeded its focused validation assignment by running
  `.venv/bin/pytest -q` on macOS: **3919 passed / 16 skipped / 62 failed / 26
  errors**, including known dependency/socket-path environment failures. This
  is not a successful full-suite run; it was not repeated, and no environment
  installation or product weakening followed.

Final Mac fixture/declaration subset: **47 passed in 0.14s**, including 14 new
fixture cases. Target Ruff passes. These are file/model tests, supplemented by
the separately scoped native analyzer observations above; neither is installed
lifecycle evidence. Production startup remains refusing. Next work is the
reviewed effective-loaded-unit/property verification and recovery transaction,
not installing this prototype or treating its grant method as authorization.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_bootstrap_mask_overlay_fixture.py tests/unit/test_runtime_bootstrap_lifetime.py tests/unit/test_runtime_hardening.py -q
ruff check tools/inspect_bootstrap_mask_overlay.py tests/unit/test_bootstrap_mask_overlay_fixture.py
# Existing Debian review copy, ordinary user, no service operations:
/home/rabbit/nexus-rc2-conformance-20261013/bin/python tools/inspect_bootstrap_mask_overlay.py --verify-offline
task_test_dir=$(mktemp -d /home/rabbit/nbov.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Final Debian ARM64 subset: **860 passed in 2.51s**. Final local/VM tool and
test hashes match. Documentation links and diff whitespace checks pass. No CI
or successful full-suite result is claimed for this increment.

| Artifact | SHA-256 |
| --- | --- |
| `tools/inspect_bootstrap_mask_overlay.py` | `b1f796115a83896683fd56f91b0f294282a2c6a312165d82ba5c91eededbb435` |
| `tests/unit/test_bootstrap_mask_overlay_fixture.py` | `6176c411d8dd7301b0f931b512e3e32a6650c0f35c86ba6eade29a51e06d10ee` |
| `docs/evidence/bootstrap-mask-overlay-2026-10-14.json` | `ee7863a20c036a8e315ce529c758aff36bb0d8ec9ffdbf2a7cbd46445a09c3b6` |

### Loaded-unit projection and reply-origin validation (2026-10-14)

Added `BootstrapLoadedUnitInspector`, a single-use bounded read-only observer
over an already-owned system-bus connection. Only owner lookup, GetUnit and
Properties.GetAll are issued for the exact bootstrap helper pair. It requires
the canonical identity, candidate FragmentPath, no aliases/following/source
redirect or drop-ins, and no pending daemon reload. It checks lifecycle and
execution fields, all Exec*Ex hooks/flags/arguments, account/group/environment
settings, and direct forward/reverse dependency relationships against independent
expectations. Expected implicit OS dependencies are mandatory inputs, never
guessed from `After=controller` or copied from the observation. Other Azazel
units cannot be admitted through that expectation argument.

Review identified missing environment/group and timer projections. The final
implementation also checks UnsetEnvironment and SupplementaryGroups and requires
independent expected SetLoginEnvironment and uint64 start/stop/runtime/watchdog
timings at construction. The controller projection additionally requires, exactly, SupplementaryGroups=[azazel-operator], CapabilityBoundingSet=0x4 (CAP_DAC_READ_SEARCH only) and AmbientCapabilities=0 (owner-approved so the root controller can read the 0700 audit state and reach the operator-group sockets). Those values are copied before any await. No local
policy duration or implicit systemd default was invented. Matching a zero or
infinite timer is only an observation, not proof of a finite lifetime deadline.

Two serialized projected snapshots must agree under the same pinned systemd
owner and exact object path. The result is `LoadedBootstrapUnit`, deliberately
not admission or a start token. This does not recursively admit dependency
closure, measure package/unit bytes, verify all sandbox/resource properties,
authenticate node health, make the reads atomic with Start, prove cgroup
emptiness or establish a reboot fence. Those remain separate requirements of
the start guard. Production composition remains refusing.

The review also found the shared bootstrap D-Bus helper checked reply shape but
not reply origin. It now requires METHOD_RETURN.sender to equal the pinned
unique systemd destination, or `org.freedesktop.DBus` for bus-daemon calls.
This strengthens start, stop and read-only inspection. The library's
[dbus-next 0.2.3 reply dispatch](https://github.com/altdesktop/python-dbus-next/blob/v0.2.3/dbus_next/message_bus.py)
matches reply serials; this is not itself an origin check. Tests now model the
two sender identities and explicitly reject missing/wrong senders. No exploit
against the VM's bus policy or hostile-root protection is claimed.

Test integration initially had **47 passed / 1 failed**, but the nominally
successful negative cases shared an invalid preflight fixture (missing newly
required dependency keys). They were not accepted as coverage. The baseline was
corrected against the actual implementation, both helper success cases were
added, and property-negative cases now assert the relevant GetAll was reached.
This was a test correction, not relaxation of production validation.

Final source review found no further concrete issue in the added timing and
environment expectation checks or reply-sender validation. Final Mac focused
run: **216 passed in 0.39s**; existing Debian ARM64 bootstrap/runtime subset:
**944 passed in 2.48s**. The new inspector file contains 70 cases and the
start/stop files add 14 sender regressions; subset counts overlap earlier runs.
All six targeted source/test files pass Ruff. Diff whitespace and 54-document
link checks pass. No full suite, live D-Bus inspection, service operation or CI
was run for this increment. The earlier 4270-case full-suite result predates
these changes and is not evidence for this final tree.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap_loaded.py tests/unit/test_runtime_bootstrap_start.py tests/unit/test_runtime_bootstrap_stop.py tests/unit/test_runtime_bootstrap_manager.py tests/unit/test_runtime_boundary.py -q
ruff check runtime/src/azazel_nexus_runtime/bootstrap_loaded.py runtime/src/azazel_nexus_runtime/bootstrap_stop.py tests/unit/test_runtime_bootstrap_loaded.py tests/unit/test_runtime_bootstrap_start.py tests/unit/test_runtime_bootstrap_stop.py tests/unit/test_runtime_bootstrap_manager.py
# Existing Debian review copy/venv, ordinary-file scratch outside the tree:
task_test_dir=$(mktemp -d /home/rabbit/nblu.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Final local/VM bytes agree:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/bootstrap_loaded.py` | `a27b353ca7d2b0c8c33553dae9eeead09f2a28e32677df2f6d5426a014e83ddf` |
| `runtime/src/azazel_nexus_runtime/bootstrap_stop.py` | `963dae869596094ed9c53e2326dbef57aeec61d1822673f464bacb6a8c732fd7` |
| `tests/unit/test_runtime_bootstrap_loaded.py` | `4e3512e656d43bc111690ede472fe7a3924386efd9112169a6be0ad1ed089a00` |
| `tests/unit/test_runtime_bootstrap_start.py` | `27e5e8b93e40973522f7470cea6cc3bdbab287952c129997c73a4efbd53f1fa2` |
| `tests/unit/test_runtime_bootstrap_stop.py` | `83061cb4da523c28ca61539ff83bf93670556d489ab83ac9d79b6f5a399170b5` |
| `tests/unit/test_runtime_bootstrap_manager.py` | `5e1a499b8f46b724a33f0abea5fbfc3fbe467e85c1547e9980603953d4cccd4c` |

Next: implement and review recovery of partially published/withdrawn runtime
overrides without modifying persistent masks; connect file measurement, loaded
projection and independently admitted transitive expectations to that transaction.
The file-only prototype must not be promoted into a live writer by adding an
arbitrary destination option. Protected producers, complete hardening/lifetime
admission and installed lifecycle testing remain necessary before startup wiring.

### 2026-10-14: same-process fixture recovery checkpoint

`MaskOverlayFixture.recover()` now narrows only its newly created scratch tree.
It retains the inode and acknowledged written prefix for each candidate, checks
the complete tree before deletion, and refuses foreign entries, changed bytes,
or replaced candidates. Persistent masks are not modified. Missing owned files
need no deletion. A partial publication, withdrawal, or directory-fsync failure
can be retried; interruptions inside mutation mark the phase incomplete and
propagate rather than reporting success. No live systemd paths are writable
through this interface.

A test-only worker added 10 regression cases. Coordinator review corrected the
replacement-inode test to create the replacement before removing the original,
avoiding accidental inode reuse. This is not an independent deployment review.
Final Mac fixture/recovery run: **24 passed in 0.19s**. Existing Debian ARM64
review-copy bootstrap/runtime subset: **954 passed in 2.48s**. These counts
overlap; they are not additional full-suite results. Targeted Ruff passes;
54-document link inspection and `git diff --check` pass. The worker additionally
reported 72 repository-wide Ruff findings outside its new test file; that is
not a clean repository-wide lint result and was not addressed in this increment.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_bootstrap_mask_overlay_fixture.py tests/unit/test_bootstrap_mask_overlay_recovery.py -q
ruff check tools/inspect_bootstrap_mask_overlay.py tests/unit/test_bootstrap_mask_overlay_recovery.py
# Existing Debian review copy and unchanged existing venv; ordinary-file scratch:
task_test_dir=$(mktemp -d /home/rabbit/nbrec.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Local and VM file hashes agree:

| File | SHA-256 |
| --- | --- |
| `tools/inspect_bootstrap_mask_overlay.py` | `a82411a84282e206c1515abbfb8d4bf718b4347cf4123edc6aa3f27fc8d907ab` |
| `tests/unit/test_bootstrap_mask_overlay_recovery.py` | `b712101d04d1ef4c9b133e477eb392392752dd587aea79369904702aaf35b7d6` |

Ownership remains in memory: this does **not** implement durable restart or
reboot recovery. An interruption between an OS write and its in-memory
acknowledgement can leave uncertain bytes; recovery then refuses rather than
guessing ownership. Same-user concurrent hostile mutation is outside this
fixture's assurance. Removing an override does not prove that a running service
stopped. The earlier offline systemd-analyze evidence retains its historical
runner hash and was not rerun or relabelled for this change. No full suite,
live D-Bus inspection, service operation, deployment, CI, or hardware operation
was performed. Production activation remains refusing. Next integration work
must provide durable transaction ownership and loaded-configuration admission
before connecting this experiment to a production manager.

### 2026-10-14: loaded-unit inspector connected to owned manager sessions

`BootstrapNarrowingManager.inspect_loaded` now composes the real read-only
inspector with a dedicated system-bus session and owned idle event loop. It
requires explicit independently supplied dependency/service expectations and
the exact helper enum. Connection shutdown and bounded pending-task drainage
are shared with the existing stop operation; primary failures remain failures.
No public CLI/RPC, reload, grant, start or unmask path was added. A successful
inspection remains a projection, not semantic admission or readiness. The
production entrypoint is still not wired to the bootstrap supervisor.

A test-only worker supplied 12 cases using the actual inspector and simulated
transport. Coordinator review strengthened the widening regression to inspect
successfully first, then verify start/unmask still refuse without another bus
connection. Both helpers, the exact read call sequence, invalid inputs,
timeout/error cleanup and fresh sessions are covered. This is code/test review,
not independent deployment approval or live systemd verification.

Final local focused run: **136 passed in 0.23s**. Existing Debian ARM64 review
copy subset: **966 passed in 2.48s**. Counts overlap and are not a full-suite
result. Targeted Ruff, `git diff --check`, and 54-document link checks pass.
The existing VM venv was unchanged; only the two changed Python files were
copied into the existing review tree. No live D-Bus calls, service operations,
CI, push, hardware actions, or credential provisioning were performed.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap_manager_loaded.py tests/unit/test_runtime_bootstrap_manager.py tests/unit/test_runtime_bootstrap_loaded.py tests/unit/test_runtime_boundary.py -q
ruff check runtime/src/azazel_nexus_runtime/bootstrap_manager.py tests/unit/test_runtime_bootstrap_manager_loaded.py
# Existing Debian review copy / existing venv:
task_test_dir=$(mktemp -d /home/rabbit/nbmgr.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Local/VM SHA-256 matches:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/bootstrap_manager.py` | `1c464d2030a858506b25d1f88d3c56eb53bc0dcbb786f04dfe27747dff94084e` |
| `tests/unit/test_runtime_bootstrap_manager_loaded.py` | `774c7161dc9f01c5f98d9244d942e5e77bb542a588ee90aee7cb18bbc37f7c91` |

Remaining integration prerequisites are unchanged: protected independent input
producers and semantic closure admission, durable deployment ownership/recovery
and lifetime/reboot fencing, authenticated readiness, and installed lifecycle
tests. Neither this connection adapter nor fixture recovery satisfies them.

### 2026-10-14: existing-history audit pre-start producer

Added `runtime/bootstrap_audit.py` (under `runtime/src/azazel_nexus_runtime`)
to read the actual auditd location `/var/lib/azazel/state/audit`, without using
the directory-creating/relocatable runtime helper. The fixed traversal checks
root ancestry and the installer-defined `azaudit` ownership of state/audit.
No missing file/directory is created. The caller supplies an independently
authenticated positive sequence/hash and explicit byte/segment limits; the
producer never adopts an observed head as its expected head. The independently
supplied expectation may come from protected local provisioning; it does not
by itself establish an independent rollback anchor. This existing-history
reader refuses sequence zero; admitted fresh genesis needs its own path.

Existing UTF-8 daily segments are read with no-follow descriptors and bounded
enumeration, checked for protection/single-link regular files, record types,
duplicate JSON keys, sequence/hash continuity and stable identity/content over
two snapshots. Nonfinite values and unfinished records refuse. Empty history
and genesis expectations refuse; this is not fresh-provisioning admission.
The writer must be independently stopped for this pre-start observation.
Matching a supplied head is not authentication of that head, hostile-root
resistance, audit anti-rollback, or complete bootstrap health.

A read-only source reviewer caught a compatibility mismatch with AuditLedger's
blank-line handling; valid records with interspersed blank lines now work.
An empty/whitespace-only segment still refuses. Coordinator review aligned
UTF-8/text splitting with the existing reader and added fixed-path traversal,
same-byte inode replacement, and non-UTF-8 regressions. The test worker's
mutation tests initially computed expectations after modifying history; those
were corrected to retain the original head before mutation.

Integration exposed a real package-boundary violation: runtime imported library
private helpers. These were removed in favor of runtime-local checks without
weakening the boundary test. The first VM subset had **980 passed / 8 failed**:
the boundary failure plus valid-fixture failures caused by VM umask 002 producing
group-writable files/directories. Test fixtures now explicitly set protected
modes; production refusal checks were not relaxed. The subsequent 988-case
run passed, followed by three additional coordinator regression cases.

Final Mac focused run: **38 passed in 0.24s**. Final Debian ARM64 subset:
**991 passed in 2.57s**. These are overlapping subsets, not full-suite results.
Targeted Ruff, diff whitespace, and 54-document link checks pass. Only ordinary
temporary files and simulated account/path seams were exercised. Actual host
audit storage, account resolution, live service state and genesis provisioning
were not verified. No service operations, deployment, CI, keys, push or hardware
operations occurred; production activation remains refusing.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap_audit.py tests/unit/test_runtime_bootstrap_audit_paths.py tests/unit/test_runtime_boundary.py -q
ruff check runtime/src/azazel_nexus_runtime/bootstrap_audit.py tests/unit/test_runtime_bootstrap_audit.py tests/unit/test_runtime_bootstrap_audit_paths.py
# Existing Debian review copy / unchanged venv:
task_test_dir=$(mktemp -d /home/rabbit/nbaudit.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Local/VM SHA-256 matches:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/bootstrap_audit.py` | `f01d18ef26493024cf5ca7702dcf6887472222969dcbe447dee96abcdc2fbe26` |
| `tests/unit/test_runtime_bootstrap_audit.py` | `bfbe6112bcff8cae850b28c73ff2f8590221cdc08c57fd7515982549280aabf1` |
| `tests/unit/test_runtime_bootstrap_audit_paths.py` | `af62914c59fec7c49f1af88b5cc26edcbd389079a5d9ab189c992122fb48a5a6` |

Next: compose independently admitted anchor/provisioning inputs and the other
pre-start observations into generation admission. This reader is not yet that
composition. Durable overlay ownership/recovery, deployment fencing and real
installed lifecycle validation remain separately open.

### 2026-10-14: pinned generation storage and admission adapter connected

Rechecked #93 (still open; latest owner-adoption comment remains
`issuecomment-6156459128`) and the adopted contract. Added the read-only
`bootstrap_generation_store.load_bootstrap_generation` for the existing
`/var/lib/azazel/generations/<expected-number>/generation.json` and
`tree/bootstrap.json` layout. It accepts only the exact independently pinned
number, private protected directories/files and closed content set, invokes
the existing pure verifier and rechecks snapshots/path identities. It neither
publishes nor infers the latest admissible generation. Normal readers continue
to refuse this bootstrap variant.

`ProtectedBootstrapGenerationAdmission` now wires that actual reader around a
mandatory semantic checker for the supervisor's admission interface. The
checker must raise on uncertainty and return exactly None; boolean permission
flags refuse. Number/digest are checked, and the full verified result must be
unchanged after semantic checking. There is no default semantic approval and
the production entrypoint is not changed. Ordinary-file integration tests
exercise the real reader through this adapter, including mutation during the
semantic check.

The admission adapter additionally compares `BootstrapContext.package_digest`
with a fresh, fixed-query Debian package snapshot before and after semantic
checking. `debian_packages.py` preserves multiarch rows and canonicalizes native
architecture plus installed binary package/version/architecture records. The
snapshot is explicitly not package authenticity, selected-file bytes, Python or
unit closure, health, or a trust anchor. Static review found that a constructed
`PackageSnapshot` could previously carry an unchecked schema/record set with a
matching digest string; the boundary now recomputes and validates its structure
and digest. It rejects qualified `dpkg` as a native-architecture source and
rejects package qualifier/architecture disagreement.

On 2026-10-14, a read-only query on the Debian 13 ARM64 VM passed the stricter
parser/validator: native architecture `arm64`, 1,672 installed records, digest
`sha256:397e686b07d53c19f80e9fb0ddc61616121c1d3eee8ea4aeebcdc0973776b04c`.
Only the aggregate was displayed; package names/versions were not retained.
This does not show Nexus is installed or active and is not an authenticated
baseline. It demonstrates the observation format on this one ARM64 VM only.

Verification after this integration: selected runtime/bootstrap suite **1,412
passed, 1 deselected**; targeted Ruff passed; `git diff --check` passed; the
repository documentation-link checker passed for 54 Markdown files. Synthetic
package parser/admission tests include canonical tamper rejection, ambiguous
native architecture and multiarch qualifier mismatch. GitHub Actions, systemd
activation, installation and Debian Live end-to-end flow were not run. The
production runtime composition and independently reviewed semantic admission
provider remain open work.

### 2026-10-14: architecture observation CLI and activation unit lifecycle

Added `az-nexus-bootstrap observe-packages`, a read-only digest-only
observation for administrators measuring each target installation. It reports
schema, native architecture, row count and digest, never package names or
versions; output explicitly disclaims authenticity and admission. Synthetic
tests verify both normal output and redacted refusal.

Reviewed the tempting change of converting `azazel-activated.service` to a
successful one-shot unit. It was rejected and not retained: the owner-adopted
bootstrap lifetime contract and `test_runtime_bootstrap_lifetime.py` require a
long-lived `Type=notify` controller with `NotifyAccess=main`, no
`RemainAfterExit`, and an explicit readiness barrier. The production
`az-activated` entrypoint still performs one activation pass and exits without
READY, and it does not wire `BootstrapSupervisor`; that concrete composition
gap remains. A successful one-shot would conflict with the contract rather
than solve it. The first-audit-event versus auditd-start ordering cycle and
non-executable pair grant backend also remain unresolved.

The local Debian ARM64 VM again passed the strict package snapshot parser with
the same 1,672-record digest; no package names were emitted and no VM files or
services were changed. After reverting the experimental unit change, the final
selected runtime/bootstrap suite passed **1,415 tests, 1 deselected**. Targeted
Ruff, `git diff --check`, and the 54-file documentation-link check passed. No
CI, service-manager operation, installation, provider admission, fetch or Edge
activation was performed.

A test-only worker supplied 22 store cases; coordinator review corrected a
symlink case to point at an existing file (rather than a nonexistent relative
target). Main added 14 adapter cases including real-reader integration.
Read-only source review of both implementations found no further concrete
flaw; it did not certify deployment or run tests. The earlier review-only
wording about metadata implementation was updated without adopting a publisher
or rewriting any generation.

Final Mac generation/input/boundary subset: **92 passed in 0.26s**. Existing
Debian ARM64 bootstrap/runtime subset: **1027 passed in 2.70s**. Counts overlap;
neither is a full-suite result. Four targeted Python files pass Ruff; whitespace
and 54-document links pass. Existing dirty branch/HEAD remain
`work/debian-live-installer-readiness-20260928` / `778d61b`. No live store,
systemd operation, key provisioning, deployment, CI or hardware test was run.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_bootstrap_generation_store.py tests/unit/test_bootstrap_generation.py tests/unit/test_runtime_bootstrap_generation_admission.py tests/unit/test_runtime_bootstrap_inputs.py tests/unit/test_runtime_boundary.py -q
ruff check src/azazel_nexus/bootstrap_generation_store.py runtime/src/azazel_nexus_runtime/bootstrap_inputs.py tests/unit/test_bootstrap_generation_store.py tests/unit/test_runtime_bootstrap_generation_admission.py
# Existing Debian review copy / unchanged venv:
task_test_dir=$(mktemp -d /home/rabbit/nbgen.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_bootstrap_*.py tests/unit/test_runtime_*.py --basetemp="$task_test_dir" -q
```

Local/VM SHA-256 matches:

| File | SHA-256 |
| --- | --- |
| `src/azazel_nexus/bootstrap_generation_store.py` | `97a14231f2af23926baf7783dd137e2789f39605ee36568e68eff79e027c0942` |
| `runtime/src/azazel_nexus_runtime/bootstrap_inputs.py` | `914078abf327d315de37220aa71abe2eba89d60942a22b6ff7581242f5dd1b73` |
| `tests/unit/test_bootstrap_generation_store.py` | `b282975afd61465fa811963889e4393346c86409ed20c0e74a48535c44e2033b` |
| `tests/unit/test_runtime_bootstrap_generation_admission.py` | `78f88223282e392558953902ce029a38cf102c403e9189558f450cee92065d1f` |

Integration review separated deployment inputs from software work: trusted time,
node/epoch/revocation provisioning, purpose/duration policy and independently
authenticated audit anchor/genesis cannot be inferred from signed candidates
or local measurements. Remaining software work is semantic policy/installed
closure/health composition, durable grant recovery/fencing, authenticated
readiness and final entrypoint wiring. Installed lifecycle evidence follows;
it must not be replaced by these ordinary-file tests. Next design work should
specify the concrete input/provisioning contract rather than add more unconnected
readers or treat callbacks as implemented producers.

### Concrete provisioning inputs: integration decision record (2026-10-14)

This section separates requirements already adopted from unresolved deployment
choices. It does not adopt a new signature purpose, trust root, wire format,
key enrollment or live bootstrap permission. The existing two-helper scope is
already approved; that approval does not need to be repeated.

**Do not add an unconditional external-anchor or TPM prerequisite.**
[Capability model §5](capability-model.md#5-trust-and-health-state) permits
`LOCAL_CONTINUITY_ONLY` with its stated restrictions. Independent audit receipts
are necessary to claim `ROLLBACK_ANCHORED`, not automatically to start the exact
audit/commission helper pair. The adopted bootstrap contract makes an external
epoch/anchor prerequisite conditional on deployment policy. A protected local
provisioning record can supply an independent expected audit head (independent
of the ledger being tested) without becoming an independent rollback anchor.
The existing audit reader therefore labels its observation
`LOCAL_CONTINUITY_ONLY`; accepting an expected head does not validate a receipt.
No live Deception, disruptive action or rollback-verified export follows.

The following bindings must be supplied independently of the candidate approval:

| Input | Existing implementation / canonical location | Concrete missing step |
| --- | --- | --- |
| Declared node identity | `load_declared_node`, `/etc/azazel/node.yaml` | Define the admitted identity binding and digest transcript; do not substitute hostname or machine ID. |
| Operator and purpose/duration policy | `/etc/azazel/operator-trust/operators.json`, `/etc/azazel/bootstrap/policy.json` | Explicit administrator enrollment/policy provisioning using independently checked public-key fingerprint; no installer-generated keys or default duration. |
| Current boot and elapsed time | `read_boot_id`, `read_boottime_ns` | Already readable; these establish neither trusted UTC nor operator approval. |
| Trusted UTC | `BootstrapObservation.now/clock_trusted` are required, but no producer exists | Select an authenticated existing source or a reviewed explicit administrator observation procedure with boot/elapsed binding, expiry and loss-of-trust handling. OS wall time, a synchronization flag, and candidate grant time alone are not proof. |
| Epoch and revocation/high-water | Required context values; spec names `/etc/azazel/admission/policy.yaml` | Specify protected ownership, update/rollback policy and the independent measurement transcript. A directory number or mutable retained deadline is not the source. External anchoring is conditional, not silently presumed. |
| Admitted policy and installed package/unit closure | Candidate verifier and loaded-unit projection exist | Identify the reviewed package/policy authority and measure the installed transitive closure against it; do not promote a file hash or loaded properties into admission. |
| Initial audit state | Existing-history reader accepts an independent positive head | Provision either an existing-head expectation or a separately admitted first-install record. Missing ledger does not imply a new node. Local provisioning remains local-continuity assurance unless a receipt is separately verified. |
| Storage reserve and lifecycle bounds | Required pre-start checks, explicit timing parameters | Supply policy thresholds separately from measurements; do not invent hardware values or durations. |

Implementation order from here:

1. Reuse an existing deployment source if the operator identifies one. Otherwise
   review an explicit administrator-provisioning procedure, including how stale
   records are invalidated and how a new boot obtains fresh input. Do not create
   production records or a signing mechanism merely to satisfy current tests.
2. Implement that selected producer contract and one semantic admission
   composition using the existing generation, audit and loaded-unit readers.
   A callback seam is not a completed producer. Test absent/stale/mismatched
   records, explicit genesis versus lost history, and state transitions.
3. Complete durable grant ownership/recovery and lifetime fencing, integrate
   start plus authenticated readiness, then wire the supervisor into the real
   entrypoint. Keep normal activation/Edge authority unchanged.
4. Separately authorize and run installed systemd lifecycle tests. Synthetic
   tests are not systemd/firmware/hardware evidence. Current permission does
   not authorize service installation/start or credential provisioning.

An asynchronous operator question requests whether trusted deployment inputs
already exist or an explicit VM administrator-provisioning design is needed.
Pending that answer, requirements clarification and non-deploying software work
can continue; unavailable trust inputs must not be replaced with passing flags.

Review/verification for this decision record: a separate read-only reviewer
confirmed the conditional external-anchor requirement against capability model
§5 and the adopted bootstrap contract. The existing-history checkpoint wording
was corrected from "expected anchor" to "expected head" without enabling empty
history. `AuditObservation.assurance` now always reports
`LOCAL_CONTINUITY_ONLY`; its constructor accepts no caller-supplied assurance
flag. This change does not authenticate provisioning records or select a clock.

Mac targeted audit/path/boundary tests: **39 passed in 0.23s**. Same tests on
the existing Debian ARM64 review copy: **39 passed in 0.17s**. Target Ruff,
diff whitespace and 54-document link checks pass. Only the affected subset was
rerun; the earlier 1027-case result predates this assurance-property change.
No real audit store, systemd action, CI, credentials or hardware were touched.

```sh
PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest tests/unit/test_runtime_bootstrap_audit.py tests/unit/test_runtime_bootstrap_audit_paths.py tests/unit/test_runtime_boundary.py -q
ruff check runtime/src/azazel_nexus_runtime/bootstrap_audit.py tests/unit/test_runtime_bootstrap_audit.py
# Existing Debian review copy / unchanged venv:
task_test_dir=$(mktemp -d /home/rabbit/nbassure.XXXXXX)
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit/test_runtime_bootstrap_audit.py tests/unit/test_runtime_bootstrap_audit_paths.py tests/unit/test_runtime_boundary.py --basetemp="$task_test_dir" -q
```

Local/VM matching SHA-256:

| File | SHA-256 |
| --- | --- |
| `runtime/src/azazel_nexus_runtime/bootstrap_audit.py` | `4854d389c2f35106440772627a9f6ae42f83932fc7687ba069b92459c4c441d0` |
| `tests/unit/test_runtime_bootstrap_audit.py` | `a0d4977e93ebe456aae52438c8ffad3e882be731b14debe4953069c57e0e99ee` |

### 2026-10-14: current-tree full-suite checkpoint

The earlier narrow checkpoints did not establish full-suite integration. A new
full run on the existing Debian ARM64 review copy now reports **4489 passed,
1 skipped, 2 warnings in 41.08s**, exit 0. Python is 3.13.5; pytest is 9.1.1.
No venv was recreated or package installed. The skip is the installer refusal
case for a host without systemd (`test_e2e_harness.py:289`); systemd exists on
this VM. The two warnings concern Python's multithreaded-fork deprecation in
ordinary-file deadline crash tests, not a failed assertion or live unit test.

Before/after verification, 303 selected source/runtime/test/tool/packaging/config
files agree byte-for-byte between local and VM. The sorted SHA-256 listing's
digest is `499822aea26858e6047767bf473063a47ec59c4c499908fe00e4cb1977f26c4e`.
`runtime/README.md` was synchronized before testing. A VM-only AppleDouble file,
`src/._azazel_nexus.egg-info`, was explicitly excluded from this comparison and
left intact. This is not a clean-checkout build or a claim that all repository
documentation was synchronized. Both trees have base HEAD `778d61b`; the tested
code includes the preserved uncommitted changes.

Repository-wide Ruff was also rerun: **72 findings, exit 1**, matching the
previous count but not asserting every finding has an identical history.
Repository-wide lint is not successful; no unrelated cleanup was attempted.
Diff whitespace and the 54-document link check pass.

Machine-readable commands, scope, versions and results are recorded in
[the full-suite evidence](evidence/bootstrap-current-tree-tests-2026-10-14.json).
This advances software integration evidence only. Production activation,
installed systemd lifetime/startup, credentials, external trust inputs and
hardware remain unverified. The unresolved provisioning-source question does
not invalidate the tests and is not answered by them.

Shared this checkpoint on [Issue #93](https://github.com/01rabbit/Azazel-Nexus/issues/93#issuecomment-6157530147),
explicitly retaining its open status and distinguishing local dirty-tree evidence
from remote source/release artifacts. No source push or PR action was taken.

### VM provisioning handoff: observed state and draft sequence (2026-10-14)

Read-only SSH inspection as the existing unprivileged VM account found
`/etc/azazel` and `/var/lib/azazel` absent with their parent directories readable
and searchable. No credential or configuration contents were opened. Therefore
the fixed production stores used by the readers above are not installed at
their canonical locations on this VM. This does not prove the VM is a newly
provisioned node, that no old audit history exists elsewhere, or that no external
management source exists. It does explain why source-copy tests cannot complete
production startup by themselves.

The systemd-timesync synchronization marker exists as an empty regular file and
`timedatectl` is on PATH. The latter was not executed (avoiding implicit service
activation); neither chronyc nor ntpq was found on PATH. None of these facts
establishes authenticated time, a trusted source, freshness, or bootstrap clock
policy. No NTP/clock configuration was changed. No elevated access was used.

The following is a **reviewable procedure draft, not executed provisioning and
not an adopted new record/signature protocol**. It gives the operator one
bounded decision about using an existing managed source versus defining an
explicit administrator-managed VM procedure, rather than repeatedly adding
unconnected readers while that source is unspecified.

| Order | Responsible action and required evidence | Existing software / remaining implementation |
| --- | --- | --- |
| 1 | Name the approved source for node identity, policy, current epoch/revocation, trusted UTC and audit initial/head state. Specify whether deployment policy requires an external rollback anchor. No candidate approval may be its own expected context. | Protected readers and context types exist; no concrete producer/provisioning contract has yet been selected. `LOCAL_CONTINUITY_ONLY` remains permitted only within its restrictions. |
| 2 | Review the exact installed package and transitive unit/executable closure, with tested compatibility and explicit health/storage/time limits. | Source hashes and loaded projections are measurements, not admission. The complete semantic checker and policy threshold provisioning remain absent. |
| 3 | Explicitly provision operator public-key trust and purpose policy after independent fingerprint confirmation. The installer must not create keys, enroll itself, or infer a duration. | Existing `operator_enrollment` supports explicit enroll/revoke using a supplied public key and fingerprint; protected directory provisioning and permission review are separate. No command is run by this handoff. |
| 4 | Establish an independent audit expectation: verified existing history, or a specifically approved first-install record binding empty genesis to this node and provisioning event. | `inspect_existing_audit` handles only the former. Missing canonical directories must not trigger genesis. A separately admitted genesis publisher/consumer is not implemented. |
| 5 | Stage and inspect the exact bootstrap generation plus protected policy/context inputs. A failed stage must remain distinguishable from an admitted/published generation. | `load_bootstrap_generation` and the pure verifier exist. No bootstrap publisher exists; do not use ordinary `GenerationStore.create` with a fake commissioning digest or manually rename a tree to imply admission. |
| 6 | After the actual boot/context, generation, policy/closure and time are established, obtain the purpose-specific approval binding them. Confirm its signer is currently enrolled and permitted for bootstrap. | `verify_bootstrap_approval` and `load_bootstrap_approval` verify the adopted transcript. This procedure neither creates a signing key nor invents a signing CLI/sidecar. A new boot invalidates that approval. |
| 7 | Under the controller transaction, after pre-start admission and before any widening, initialize and durably retain the immutable deadline exactly once. Record the admitted context, intent and provisioning state coherently. | `begin_deadline` / `retain_initial_deadline` are available building blocks, not a completed provisioning transaction. A restart uses `advance_deadline`; absent or pending state never reinitializes. Recheck trust/time after persistence before starting. |
| 8 | Review and deploy the complete persistent-mask/volatile-grant, controller lifetime, readiness and restart/reboot recovery implementation, then verify loaded effective settings. | File-only experiments and bounded adapters exist. Durable production grant recovery and the final manager/entrypoint connection remain unfinished. No global unmask, service enable or status-CLI substitution is acceptable. |
| 9 | With separate deployment/test authority, exercise real audit-first startup, helper readiness, expiry/revocation, controller death, same-boot restart and reboot, recording each result. | Not performed. Unit/ordinary-file tests do not supply this evidence or hardware claims. No provider/fetch/capture/Edge activation is included. |

Any administrator-provisioning design must explicitly define storage ownership,
transaction/recovery behavior and the following bindings before code treats its
records as evidence: provenance/issuer, node identity, applicable boot or boot
transition rule, epoch/revocation reference, reviewed policy/package/closure,
time-observation method and validity, audit existing-head versus fresh-genesis
status, and applicable assurance level. These are required semantics, not a
newly accepted JSON schema or default values. No record may mint another
operator authority, silently reset a consumed deadline or make local state
rollback-proof by naming it an anchor.

This turn changed the handoff only; it did not rerun the completed full suite,
change software behavior, install anything or create production records. The
4489-pass evidence above remains a historical full-suite result for its recorded
303-file manifest, not a new count for this diagnostic inspection.

Independent read-only review agreed with the source-first and explicit-genesis
sequence and emphasized two ordering constraints: approval must be verified
before deadline initialization, and every reboot invalidates its boot binding.
The reviewer confirmed existing enrollment is an explicit mutating administrator
operation, whereas bootstrap policy/approval provisioning and generation
publication have no completed production command. Do not present the table as
an executable installer or supply invented commands for those gaps. No review
finding authorized running enrollment, installing services or making a local
record independently rollback-anchored. Diff whitespace and all 54 Markdown
document links passed after this handoff update.

### Owner choice resolved: portable administrator provisioning (2026-10-14)

The owner selected option 1 (explicit administrator-managed VM provisioning),
with the additional requirement that later physical installations remain
flexible. The earlier supply-source selection question is **answered**; do not
ask it again or retain it as the reason to block implementation. This is
permission to design and implement the administrator workflow, not to create
production keys/credentials, install services, or start them without their
separate authorization and safety gates. Goal-tool status is separate from this
decision: its status cannot be resumed by the agent's update API.

The VM is the first test target, not a distinct product or trust mode. Implement
one shared policy/validation path with platform observation adapters, not
`vm=True` bypasses or separate VM/physical activation implementations.

| Layer | Persisted or supplied information | Portability rule |
| --- | --- | --- |
| Administrator intent/policy | Explicit node identity binding, operator public-key references, purpose and duration policy, epoch/revocation source, audit genesis/head intent, storage/health limits | Versioned declarative records; no secrets, executable hooks, environment-selected imports or caller-selected trust-store paths. Bind all activation-affecting settings into independently admitted policy/context. |
| Fresh local observation | Actual boot ID, suspend-inclusive clock, trusted-time observation, installed package/unit closure, capacity and health | Common typed observations; adapters report unsupported/unknown rather than fabricating values. Architecture-specific artifacts still require their actual compatibility checks. |
| Approval and retained transaction state | Exact two-helper approval, current generation and boot, immutable deadline, transaction ownership | Same existing verifier/supervisor rules everywhere. Do not transfer these records between VM and physical host or silently renew them after reboot. |
| Deployment execution | Protected publication, service-manager binding, readiness and containment | Fixed trusted runtime entrypoints, not SSH command strings or VM-specific paths. Installer transports files but does not become a decision/enforcement authority. |

Migration rules:

- Reuse the reviewed procedure, schema and suitable non-secret policy template;
  do not clone machine identity, writable audit state, genesis approval or live
  authorization as if the destination were the same node.
- Reinspect the destination's installed package and unit graph, boot identity,
  storage and relevant hardware capability. Require a separately confirmed node
  binding and new boot-bound approval. Existing-history migration needs explicit
  custody/continuity handling; absence must not be interpreted as fresh genesis.
- Keep observation method and assurance explicit. TPM or external anchoring may
  be required by a deployment's policy but are not universally mandatory. Losing
  a required producer refuses; optional adapters cannot trigger a weaker fallback.
- Keep the default source local administrator-managed and offline-capable. A
  future managed-source adapter must implement the same validation contract and
  be explicitly selected/reviewed; arbitrary plugins or new remote trust are not
  implicitly authorized by extensibility.

Implementation sequence now selected: define canonical administrator records
and their policy binding; implement validation/preview without writes; then
explicit protected publication with separate confirmation and recovery; compose
fresh observations and semantic admission; integrate the existing supervisor
and validate real lifecycle under separate deployment authority. Reuse the
existing node declaration, operator enrollment, approval-policy and generation
readers instead of inventing parallel stores for the same authority. A schema
version change must be explicit; missing/unknown fields and unsupported versions
must fail closed rather than acquire new default permissions.

This decision does not adopt a guessed clock value, epoch, duration, disk
threshold or identity. Those are explicit administrator inputs to the workflow
being implemented, not questions that require stopping implementation again.

Read-only design review confirmed the declaration/observation split and exact
two-helper boundary. Incorporate its digest recommendation: admission
`policy_digest` and `BootstrapApprovalPolicy.digest()` remain distinct; a
record's own digest must not appear inside the bytes it hashes. Define the
declared-node digest transcript explicitly before implementing the producer.
The reviewer suggested identity portability; interpret that as portability of
the schema and an explicitly reviewed logical-node continuity operation, not
automatic copying of a VM identity onto a second host. This turn changed only
the implementation contract/handoff; no provisioning record, key, service or
source module was created. Diff check and all 54 Markdown links pass; tests were
not rerun for these documentation-only changes.

### Portable administrator declaration implementation (2026-10-14)

The selected administrator-managed source now has a common typed declaration,
not a VM-only configuration or a start permission. `bootstrap_deployment.py`
implements exact canonical `azazel-nexus/bootstrap-deployment/v1` JSON with
`node_digest`, `security_epoch`, `revocation_digest`, `policy_digest`,
`approval_policy_digest`, and `operator`. Unknown fields, duplicate keys,
noncanonical bytes, unsupported versions and malformed values refuse.
The node digest is `sha256:` plus the SHA-256 of UTF-8 compact sorted JSON
`{"node_id":<explicit declared label>,"schema":"azazel-nexus/declared-node/v1"}`.
This is an identity binding, not proof of enrollment or anonymization.

`bootstrap_deployment_store.py` reads only the protected fixed
`/etc/azazel/bootstrap/deployment.json`, rechecking directory identity and bytes.
It neither publishes the record nor reads expected values from `approval.json`.
`AdministratorBootstrapObservation` binds that declaration and the separately
protected node declaration to a required fresh observation producer, then
rechecks both declarations. It does not supply trusted time, synthesize health,
prove epoch rollback resistance, or replace generation semantic admission.
VM IP, architecture, boot ID, secrets and executable hooks are not schema fields.
The same schema/validation can therefore be reused on a physical installation;
fresh observation and separately authorized provisioning remain necessary there.

Read-only delegated review of the two new library modules and observation
adapter found no concrete defect within that scope; it is not installed-runtime
approval. A separate worker supplied pure schema/binding regression tests;
the coordinator additionally checked single-defect mutations of valid records.

This increment's commands/results (not the earlier full-suite baseline):

- Mac: `PYTHONPATH=src:runtime/src ./.venv/bin/python -m pytest
  tests/unit/test_bootstrap_deployment.py tests/unit/test_bootstrap_deployment_store.py
  tests/unit/test_runtime_bootstrap_administrator.py tests/unit/test_runtime_bootstrap_inputs.py
  tests/unit/test_runtime_boundary.py -q` — **90 passed**.
- Debian 13 ARM64 existing review copy: `PYTHONPATH=src:runtime/src
  /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest
  tests/unit/test_bootstrap*.py tests/unit/test_runtime_bootstrap*.py
  tests/unit/test_runtime_boundary.py --basetemp=<new private regular-directory scratch> -q`
  — **607 passed**. The six changed Python files were copied into the existing
  review source; the existing virtual environment was not modified.
- Targeted Ruff on those six files and `git diff --check`: pass.

All tests used synthetic inputs/ordinary files. No production declaration,
key, service installation/start, CI, provider/fetch/Edge activation or hardware
operation occurred. Earlier full-suite evidence predates these additions and
is not a full-suite result for this tree. Next: administrator validation/preview
and separately confirmed protected publication/recovery, followed by independent
fresh producers, complete semantic admission and installed lifecycle wiring.

### Administrator preview CLI (2026-10-14)

`azazel-nexus bootstrap-deployment-preview < deployment.json` now reaches the
common strict decoder before any host report collection. It accepts bounded
binary stdin, refuses an interactive terminal, never publishes or activates,
redacts input failures and prints only the declaration hash with explicit
NOT installed/admitted/authorized wording. A successful exit is syntax-only;
protected publication, independent expected-context binding and semantic
admission remain outstanding. This does not generate a production declaration.

New tests: `tests/unit/test_bootstrap_deployment_cli.py`. Existing dirty CLI
changes were preserved. On both Mac and the existing Debian ARM64 review copy,
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_bootstrap_deployment_cli.py tests/unit/test_wizard_and_cli.py
tests/unit/test_boundary_static.py -q` passed **71 tests** per environment.
VM used a new ordinary-file `--basetemp`; no venv modification or live service
operation. Targeted Ruff reports one existing `cli.py` F401 for `tpm_present`
outside this increment; no unrelated cleanup was performed. These are local
tests, not CI or installed-runtime verification.

Separate read-only review found no concrete defect in the CLI branch and
suggested testing valid canonical input followed by excess bytes; that regression
was added before the final 71-test runs. New-test Ruff, diff check and all 54
Markdown link checks pass. The existing CLI import warning remains separate.

### Initial protected declaration publication (2026-10-14)

`bootstrap_deployment_store.initialize_bootstrap_deployment` now implements
first publication to the existing protected fixed directory. Exact canonical
bytes, their separately confirmed SHA-256 and exact `True` initialization
confirmation are required before writes. It upgrades to a nonblocking exclusive
cooperative lock, refuses any existing declaration/pending entry (including
dangling symlinks), creates private files exclusively, fsyncs, reads back exact
bytes, then removes the pending marker and fsyncs the directory. No path/owner
override exists on the public API. It does not create directories or overwrite
state. The reader now refuses pending publication.

Failure is not evidence that nothing was written. Partial/pending state remains
for review and blocks readers/retry. In particular, a final directory fsync
failure after marker removal leaves uncertain durability and possibly a
readable declaration; callers must not automatically retry. Reading/publication
still does not confer admission. Recovery and an interactive publication UI
remain unimplemented; the current CLI continues to expose preview only.

A separate read-only review found no concrete correctness defect and highlighted
the final-fsync ambiguity above. A worker added initial publication regressions;
the coordinator added each of the five fsync failure positions and an active
reader-lock conflict. Tests use only private ordinary temporary files.

Mac and Debian ARM64 existing review copy each ran:
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_bootstrap_deployment*.py
tests/unit/test_runtime_bootstrap_administrator.py -q` — **83 passed** each.
VM additionally used a fresh ordinary-directory `--basetemp`; only source/test
copies changed, not the venv. Targeted Ruff on the store and new publication
test passes. No production declaration, directory, key, installed service,
provider/fetch/Edge activation, CI or hardware change was performed.

### Interactive publication and bounded recovery (2026-10-14)

The real operator CLI now dispatches `bootstrap-deployment-initialize` and
`bootstrap-deployment-recover` before host report collection. Both require
interactive stdin, bounded canonical JSON on one line, a separately retyped
reviewed digest, and the exact distinct `INITIALIZE`/`RECOVER` operation word.
No default consent, piping mode, privilege escalation or selectable store path
was added. The existing fixed protected store remains the publication boundary.

Recovery completes only an exact complete retained declaration plus the known
protected pending marker. It fsyncs existing content and directory, rechecks,
then removes only that marker. It never rewrites declaration bytes, recreates
missing bytes, removes unknown state, or interprets missing history as genesis.
All existing semantic admission requirements remain independent.

Read-only delegated review highlighted ambiguous final-fsync reporting. The
coordinator added `DeploymentDurabilityUncertain`, preserved through both public
store APIs: CLI exit **2** explicitly reports possible publication with uncertain
durability and forbids automatic retry. Exit **1** is refusal/error (possibly
partial retained state), while **0** is publication only, never activation.
Tests cover each fsync failure, retained inode preservation, mismatches,
truncation, unsafe links, terminal refusals and actual CLI dispatch with mocked
publication calls. No live protected-store write was executed.

Final local commands on Mac and existing Debian ARM64 review copy:
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_bootstrap_deployment*.py
tests/unit/test_runtime_bootstrap_administrator.py tests/unit/test_wizard_and_cli.py
tests/unit/test_boundary_static.py -q` — **168 passed** per environment.
VM used a fresh ordinary-directory `--basetemp`, unchanged existing venv.
Targeted Ruff on the store, new interactive module and three changed tests
passes; the earlier unrelated CLI F401 remains. Diff check and Markdown link
checks pass. No CI, installed service, key, provider/fetch/Edge activation or
hardware operation occurred. Complete fresh observation producers, generation
semantic admission and production lifecycle composition remain unfinished.

### Deployment flow integration and full regression (2026-10-14)

`test_bootstrap_deployment_flow.py` now exercises actual CLI → public store API
→ publication → protected read algorithms, and interrupted publication → reader
refusal → explicit recovery. Only directory/owner boundaries are redirected to
private ordinary temporary files; publication is not mocked. This remains a
synthetic integration test, not an installed store or systemd lifecycle test.

Full Debian ARM64 `pytest tests -q` initially found a real documentation
integration regression: the root README subcommand table omitted the three new
commands (**1 failed, 4592 passed, 1 skipped, 2 warnings**). The README was fixed
without weakening the consistency test. After copying the fix and two new flow
tests into the existing review source, the full rerun completed:
**4595 passed, 1 skipped, 2 warnings in 41.11s**. Command:
`PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python
-m pytest tests --basetemp=<new private ordinary directory> -q`.
Warnings are the two existing multiprocessing/fork deprecations in deadline
crash tests on Python 3.13. The environment-specific e2e skip remains; no CI or
real lifecycle success is implied. Mac README + flow subset: **20 passed**.
New-flow Ruff, diff check and all 54 Markdown link checks pass.

An integration review confirms the next vertical slice must replace observation
and semantic-admission callbacks with concrete independently sourced inputs,
not another status-only connection or permissive manager. Existing readers can
be reused, but the following still need concrete implementation:

- An explicit expected approval/generation selection independent of the signed
  candidate, with observed package and transitive unit closure.
- Administrator-managed bounded trusted-time observation with boot/elapsed
  binding, expiry and loss-of-trust handling; OS wall time alone is insufficient.
- Admitted policy with explicit resource/lifecycle limits and epoch/revocation
  update rules, plus expected audit head or explicitly authorized first genesis.
- One semantic admission composition using those producers, then the real
  controller entrypoint and separately reviewed readiness/lifetime fencing.

The administrator-managed source choice is already resolved. These are software
contracts to implement with explicit operator inputs, not a renewed request to
choose a source or grounds to declare the overall goal complete. Production
observation/admission and installed lifecycle remain unproven. No credentials,
live stores/services, CI, provider/fetch/Edge activation or hardware were changed.

### Fresh resource floor prerequisite (2026-10-14)

`runtime/bootstrap_resources.py` reuses the actual `assess_resources()` producer
with explicit positive exact-integer floors for kernel usable RAM, online logical
CPUs and available mission filesystem MiB. Missing/invalid/unavailable or
below-floor values refuse; every call remeasures. No floor defaults or cached
success exist. `MemTotal` is not free RAM or cgroup allocation. The observation
timestamp is not trusted UTC and architecture is not a release-support grant.

Read-only delegated review found no concrete defect in the bounded capacity
check, but emphasized two remaining composition requirements: bind the exact
floors to independently admitted policy bytes/digest, and inspect state-volume
capacity separately where required. `/data` capacity says nothing about
`/var/lib/azazel` audit/deadline storage. This helper is therefore NOT yet wired
as production semantic admission or sufficient health; no service-start gate
was weakened. Policy binding, state storage, time and full closure remain open.

Current VM read-only observation via the existing assessor, at its untrusted OS
timestamp `2026-10-14T08:43:01Z`: ARM64, kernel usable RAM **2907 MiB**, online
logical CPUs **4**, mission available space **null/unavailable**. No root-volume
fallback was used. The assessor does not distinguish every underlying refusal
cause in public output; this does not prove `/data` is absent, encrypted or
correctly mounted. No mount, directory creation, service or device operation was
performed. Actual deployment needs an explicitly prepared valid storage layout;
software development can continue without treating it as present.

Mac and existing Debian ARM64 review copy each ran
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_runtime_bootstrap_resources.py
tests/unit/test_runtime_resource_assessment.py
tests/unit/test_runtime_bootstrap_generation_admission.py
tests/unit/test_runtime_boundary.py -q`: **88 passed** each (VM with fresh ordinary
`--basetemp`). Targeted Ruff passes. The earlier 4595-case full-suite run predates
this helper and is not a full-suite result for this increment. No CI, credentials,
installed-runtime operations or activation occurred.

### Actual state-volume capacity and audit ancestry correction (2026-10-14)

`bootstrap_state_capacity.py` now reads filesystem availability at the actual
fixed bootstrap deadline and audit directories, using no-follow descriptor
traversal and a canonical-path inode recheck. Explicit positive byte and inode
floors are required. When both paths share a filesystem, the sum of both floors
must fit the smaller observed availability; space is not counted twice. Missing,
unsafe, readonly, invalid-stat or insufficient paths refuse without creating
directories or opening devices. Availability is not a reservation, service-UID
quota/access test, encryption proof or full health. Threshold policy binding
and production semantic composition remain unfinished.

Review of the real installer/layout exposed a pre-existing traversal bug in
`bootstrap_audit._open_ledger`: before opening `audit`, it checked the parent
`state/` against UID azaudit. The installer and `PathSpec` instead define that
parent as **root:azaudit** (owner:group). The loop now checks every ancestor as
root and only the final `audit/` as UID azaudit. The regression assertion was
corrected to `[0, 0, 0, 0, 0, audit_uid]`; new capacity traversal tests verify
the same parent-versus-leaf distinction. A separate reviewer confirmed against
both `layout.py` and `packaging/install.sh`. No installed ownership was changed;
the audit leaf's actual provisioning is still a separate deployment requirement.

Mac and the existing Debian ARM64 review copy each ran
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_runtime_bootstrap_state_capacity.py
tests/unit/test_runtime_bootstrap_audit*.py tests/unit/test_runtime_boundary.py -q`
— **76 passed** each. Tests use synthetic stats and private ordinary directories;
VM uses fresh `--basetemp` without venv changes. Ruff on the two source and two
test files passes. No production capacity floor was invented or used, and no
live provisioning, services, CI, keys or hardware operations were performed.

### Policy-pinned capacity composition (2026-10-14)

The new library `bootstrap_prestart_policy.py` defines exact canonical
`azazel-nexus/bootstrap-prestart-policy/v1` bytes for the exact two-helper,
existing-history/local-continuity profile. Explicit fields cover package/unit
closure expectations, all resource/state floors, expected audit sequence/head,
and bounded audit scan sizes. There are no numeric defaults, unknown fields,
implicit genesis or external-anchor claims. This is a Nexus-local prototype
contract; no live policy or new signing authority was provisioned.

`bootstrap_prestart_store.py` reads only protected
`/etc/azazel/bootstrap/admission.json`. Its full bytes must hash to independently
supplied `BootstrapContext.policy_digest`, with package and closure expectations
also matching context. This is not the separate signer/duration
`approval_policy_digest`. Stable directory/byte reinspection remains required.

`runtime/bootstrap_prestart.py:check_bootstrap_capacity` now consumes those
protected policy values, runs both actual capacity-check algorithms, and reads
the pinned policy again. This connects the former standalone checks to a real
policy source. It remains capacity-only and has no production entrypoint caller
yet: expected audit bindings are not audit inspection, and declared package
digests are not installed closure measurements. Never substitute this function
for complete semantic admission or use `None` as a general start grant.

Separate review found no concrete defect in the three new modules and confirmed
the scope limits. Worker pure-policy tests and coordinator integration tests
exercise canonical/version/scope/type/hash refusal, protected ordinary-file
reads, both actual capacity algorithms with synthetic measurements, and policy
mutation during measurement. Mac and Debian ARM64 review copy each ran
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_bootstrap_prestart_policy.py tests/unit/test_runtime_bootstrap_prestart.py
tests/unit/test_runtime_bootstrap_resources.py tests/unit/test_runtime_bootstrap_state_capacity.py
tests/unit/test_runtime_boundary.py -q` — **127 passed** each; VM used a fresh
ordinary `--basetemp` with unchanged venv. Targeted Ruff, diff and Markdown links
pass. No live store/service, credentials, CI or activation was changed.

### Policy-bound audit and supervisor prestart wiring (2026-10-14)

`check_bootstrap_existing_audit` consumes the policy's expected sequence/head
and scan bounds through the actual existing-history reader. Both helpers must
report exactly `True` for masked and inactive before and after inspection;
the returned exact `AuditObservation` must match the policy head, and policy is
reloaded. No manager mutation is called. `inspect_bootstrap_prestart` combines
this with capacity checks and further policy/state reinspection. These snapshots
are not a continuous writer lock, hostile-root defense or rollback anchor.

The supervisor's default prestart now invokes this real composition under its
lifetime transaction, after containment and the first input/generation check,
before the first controller audit record, READY notification or helper unmask.
Only an exact audit observation is accepted. Trusted test overrides remain
explicit; no permissive production default was added. The production daemon
entrypoint and manager widening are still unavailable.

Lifecycle review identified an important distinction: the initial stopped-writer
head must be checked **once**, not by every repeated `admit_generation` call
after the audit writer starts or controller records advance. Supervisor and
generation-adapter contracts now state that separation. Continuing audit
verification needs a separate mechanism accounting for subsequent records; it
has not been implemented or claimed by this change. Installed closure, trusted
time and the remaining lifetime/boot gates are still outstanding.

Worker composition tests include an actual ordinary-file audit chain with only
the fixed opener redirected, policy-change/refusal cases and exact boolean
manager checks. Coordinator tests verify default prestart placement, lock
ownership, once-only invocation across periodic checks, and refusal before
READY/unmask on an invalid result. No installed service was queried or mutated.

Mac and existing Debian ARM64 review copy each ran
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_runtime_bootstrap.py tests/unit/test_runtime_bootstrap_manager.py
tests/unit/test_runtime_bootstrap_lifetime.py tests/unit/test_runtime_bootstrap_prestart*.py
tests/unit/test_runtime_bootstrap_audit*.py tests/unit/test_runtime_boundary.py -q`
— **148 passed** each, with fresh ordinary VM `--basetemp`. Targeted Ruff,
diff check and Markdown links pass. No live stores, credentials, CI, hardware or
provider/fetch/Edge activation changed; overall runtime goal remains incomplete.

### Verified audit extension during supervision (2026-10-14)

`inspect_audit_extension` preserves the fixed protected ledger reader and its
bounded full-chain integrity verification. Unlike initial exact-head inspection,
extension mode requires the previously verified positive sequence/hash to occur
in the valid chain, then accepts unchanged history or a valid successor. A
truncated or rewritten prefix, unstable second snapshot, unsafe path or exceeded
scan bound refuses. Initial `inspect_existing_audit` still requires the exact
head; genesis/pruning/rollback anchoring were not silently added.

`check_bootstrap_audit_extension` binds the previous in-session head and scan
limits to the protected policy, rechecking policy after the read. Supervisor
`audit_continuation` defaults to that real implementation after prestart. Its
head advances only after inspection, clock checks and transaction revalidation
succeed. Refusal leaves the head unchanged and enters normal containment.
No stopped-writer check is repeated against an active audit service, and no
service mutation is performed by the inspector itself.

Separate review found no concrete defect and requested a policy-bridge test;
the added tests verify exact previous-head/limit forwarding and refusal when
policy changes during inspection. Ordinary-file tests cover valid append,
unchanged chain, truncation, rewritten prefix and mutation. Supervisor tests
verify head advancement and containment after post-start inspection failure
using recording managers. These do not prove live-writer usability: concurrent
writes can cause conservative stable-snapshot refusal; no retry/cached success
or external rollback proof is claimed.

Final Mac and existing Debian ARM64 review-copy command:
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_runtime_bootstrap.py tests/unit/test_runtime_bootstrap_manager.py
tests/unit/test_runtime_bootstrap_lifetime.py tests/unit/test_runtime_bootstrap_prestart*.py
tests/unit/test_runtime_bootstrap_audit*.py tests/unit/test_runtime_boundary.py -q`
— **159 passed** per environment; VM used fresh ordinary `--basetemp` and no
venv changes. Targeted Ruff, diff and Markdown link checks pass. No live store,
credential, installed service, CI or hardware was touched. Trusted UTC,
installed closure admission and actual production lifecycle remain unfinished.

### Bounded administrator time arithmetic and verifier bridge (2026-10-14)

`bootstrap_clock.py` adds pure projection of an explicitly admitted UTC interval
bound to node, policy and boot, with a nonrenewable elapsed-clock validity end.
Fractional elapsed seconds round the lower UTC bound down and upper bound up.
The result preserves the observation's boot-time sample and validity end rather
than dropping those metadata. Missing/mismatched/reversed/expired inputs refuse;
construction alone is not trust, and no wall-clock or synchronization-flag
fallback exists. No protected anchor store or live time-source provisioning was
created in this increment.

`BootstrapObservation` now optionally carries a lower UTC bound; existing
explicit exact-time observations retain their behavior. Protected input loading
verifies both interval ends against the signature/current trust and requires
equal evidence. Both bounds must fit the grant. Upper UTC is retained for
conservative expiry; either bound moving backwards within the refresh refuses.
Tests include real signature verification using ephemeral synthetic keys, not
only mocked verifier results.

Independent review confirmed outward rounding and endpoint-verifier arithmetic,
and identified producer integration requirements that remain OPEN:

- The admitted initial interval must cover worst-case oscillator drift over its
  entire allowed lifetime, or an explicit policy-bound drift rate must widen it.
- The numeric integer ceiling is not a deployment lifetime policy. A separate
  explicit maximum lifetime/uncertainty must be policy-bound.
- Protected production observation must consume preserved sampling/expiry
  metadata, recheck anchor freshness through signature verification/retention,
  and reproject/reverify where needed. The current generic interval consumer
  does not supply that producer and must not discard metadata to pretend it does.

Final Mac and Debian ARM64 review-copy subset:
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_bootstrap_clock.py tests/unit/test_runtime_bootstrap_time_interval.py
tests/unit/test_runtime_bootstrap_inputs.py tests/unit/test_runtime_bootstrap_administrator.py
tests/unit/test_runtime_boundary.py -q` — **73 passed** each; VM with fresh
ordinary `--basetemp`, unchanged venv. Targeted Ruff, diff and Markdown links
pass. No OS clock changes, production keys/anchors, service operations, CI or
hardware operations occurred. Trusted-time production composition remains open.

### Explicit clock limits and drift policy v2 (2026-10-14)

The prestart policy format is explicitly advanced to
`azazel-nexus/bootstrap-prestart-policy/v2`, adding mandatory
`max_anchor_lifetime_ns`, `max_uncertainty_ns` and `drift_ppb`. V1 and missing
clock fields refuse; no legacy record receives guessed defaults. These fields
are included in the already independently pinned full policy digest. Tests use
explicit synthetic values only; no production policy or anchor exists from this
work. `clock_limits()` returns the exact validated policy values.

`project_administrator_time` now requires those explicit typed limits, rejects
an overlong full anchor lifetime, widens both UTC bounds by
`ceil(elapsed_ns * drift_ppb / 1e9)`, and checks maximum uncertainty after outward
whole-second rounding. All arithmetic is integer-based. The rate bounds UTC
error per measured BOOTTIME elapsed interval, with `0 <= drift_ppb < 1e9`;
calibrating/authorizing that bound remains a producer obligation. Explicit zero
is not a measured zero-drift claim. No implicit clock source or fallback exists.

Independent review found no concrete arithmetic/type/schema defect and confirmed
nondecreasing lower bounds. It reiterated the remaining freshness connection:
the eventual protected producer must preserve and enforce projected BOOTTIME
sample/expiry metadata through signature verification and retention, rather
than discarding them into UTC-only observations. That connection and protected
anchor publication are still unfinished; time-source trust is not claimed.

Final Mac and existing Debian ARM64 review-copy subset:
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_bootstrap_clock.py tests/unit/test_bootstrap_prestart_policy.py
tests/unit/test_runtime_bootstrap_prestart*.py tests/unit/test_runtime_bootstrap_time_interval.py
tests/unit/test_runtime_bootstrap_inputs.py tests/unit/test_runtime_boundary.py -q`
— **135 passed** each. The version-rejection test was updated to reject old v1
after the intentional v2 schema change; missing-value refusal was also added.
VM used fresh ordinary `--basetemp`, with no venv changes. Targeted Ruff, diff
and Markdown links pass. No live stores, keys, OS clock changes, services, CI,
provider/fetch/Edge activation or hardware operations occurred.

### Clock validity window through retention (2026-10-14)

`AdministratorTimeWindow` is distinct from a point projection: its UTC interval
covers every BOOTTIME nanosecond in `[observed, valid_until)`. Window projection
fixes the earliest bound at the sample, searches a monotonic upper envelope,
and uses policy uncertainty/anchor expiry to bound validity. The bounded integer
search adds no guessed latency defaults. A point projection cannot masquerade
as a validity window.

`BootstrapObservation.time_window` preserves the metadata and requires exact
node/policy/boot and UTC endpoint agreement. Protected input refresh refuses
metadata disappearance, checks validity before retention, and checks it again
after retention with no elapsed rollback. Expiry detected after retention may
leave advanced local state, but returns no usable result and does not reset or
retry state. No source authority is established by constructing these values.

Read-only review confirmed the monotonic search and exclusive endpoint arithmetic.
Its requested test coverage is present in the concurrently added
`test_bootstrap_clock_window.py` and `test_runtime_bootstrap_time_window.py`:
sample/final-included/exclusive-end boundaries, zero/nonzero/high drift,
one-nanosecond windows, bounded search, point-versus-window distinction, UTC
binding, expiry before/after retention, elapsed rollback, and metadata loss.
All are synthetic; protected anchor provisioning and actual source authority
remain unimplemented, so this is not production clock verification.

Mac and existing Debian ARM64 review copy each ran
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_bootstrap_clock*.py tests/unit/test_runtime_bootstrap_time*.py
tests/unit/test_runtime_bootstrap_inputs.py tests/unit/test_runtime_bootstrap_administrator.py
tests/unit/test_runtime_boundary.py -q` — **106 passed** each. VM used fresh
ordinary `--basetemp`, without venv changes. Targeted Ruff, diff and Markdown
links pass. No live time records, clock settings, services, CI or hardware were
modified. Full runtime completion remains unproven.

### Protected administrator time reader and runtime adapter (2026-10-14)

Canonical encoding/decoding of `administrator-clock-anchor/v1` now requires the
explicit `administrator-confirmed` source label. The fixed protected reader
loads `/etc/azazel/bootstrap/time.json`, validates the independent current boot,
loads hash-pinned v2 policy, projects a policy-bounded validity window, and
rechecks directory identity, exact record bytes, policy, boot and final BOOTTIME.
No path override, creation, wall-clock or sync-marker fallback exists.

`ProtectedAdministratorClockObservation` connects the reader to administrator
declaration/node binding and preserves the exact window in `BootstrapObservation`.
It rechecks the required independent context producer around time inspection.
The selected authority is explicit local root administrator confirmation, not
authenticated external time, hardware attestation or root-resistant rollback
protection. No production record was created. Operator publication/confirmation
and actual independent installed-context production remain unfinished.

Separate read-only review found no concrete correctness defect and confirmed
those authority limits. Ordinary-file tests cover malformed/unsafe/missing
records, canonical source, boot mismatch/change, record and policy mutation,
elapsed expiry/rollback and metadata preservation. They do not establish that
an administrator's supplied time/calibration is correct.

Mac and existing Debian ARM64 review copy each ran
`PYTHONPATH=src:runtime/src <existing-venv-python> -m pytest
tests/unit/test_bootstrap_clock*.py tests/unit/test_runtime_administrator_clock_source.py
tests/unit/test_runtime_bootstrap_time*.py tests/unit/test_runtime_bootstrap_inputs.py
tests/unit/test_runtime_bootstrap_administrator.py tests/unit/test_runtime_boundary.py -q`
— **122 passed** each; VM with fresh ordinary `--basetemp`, unchanged venv.
Targeted Ruff, diff and Markdown links pass. No live records, keys, clock settings,
services, CI or hardware were changed. The goal is not complete.

### Clock/audit full integration regression and next closure boundary (2026-10-14)

The full Debian ARM64 review-copy run first returned **4818 passed, 6 failed,
1 skipped, 2 warnings**. All six failures were harness temp-root length checks:
the chosen `nb-integrated-clock-audit.*` prefix made test roots 77 bytes, beyond
the 72-byte Unix-socket budget. No code or safety check was weakened. Rerunning
with `mktemp -d /home/rabbit/nx.XXXXXX` yielded **4824 passed, 1 skipped,
2 warnings in 40.93s**. Same existing venv and source; this was an environment
path correction, not a build or service deployment. Warnings remain the two
Python 3.13 multiprocessing/fork deprecations.

A read-only delegated comparison matched 301 selected files between local and
VM source; the coordinator recomputed the local aggregate. Selection: 288 Python
files under src/runtime-src/tests/tools, 10 tracked regular packaging files,
both pyproject files and root README. SHA-256 over sorted
`<hash><two spaces><relative path><newline>` records:
`e94bad28006b41458228a9854b7a21726b79f62c35d361c9ad2df74df020bd4e`.
This is selected-source identity, not installed-environment/production evidence.
Machine-readable results are in
[the integration checkpoint](evidence/bootstrap-clock-audit-full-regression-2026-10-14.json).

Independent installed-closure investigation confirmed that `install.sh` assumes
both Python distributions already exist; it installs units/presets/accounts and
stages wrappers, but does not build the environment. `build_offline_bundle.py`
is a source bundle, not an installed dependency/closure manifest. The loaded-unit
observer is only a property projection, not that missing byte-level manifest.
The `/opt/azazel-nexus/venv` path in the installation guide is an example of a
stable environment, not evidence that a particular environment is admitted.

A concrete prerequisite surfaced: stager import checks and generated wrappers
currently use Python `-c` without isolated mode, so inherited `PYTHONPATH` can
supply modules that are not installed in the selected environment. Read-only
`python -I` import checking failed for the Mac test venv's runtime module and
succeeded for the VM venv; neither result measures installed closure or proves
the VM's isolated imports resolve to this dirty source. Do not change/recreate
the existing venv merely to get green tests. Next implementation should separate
isolated installed-environment validation from synthetic staging tests, then
bind an explicit artifact/environment manifest and actual installed measurements.
No live installation, service, key, clock, CI or hardware operation occurred.

### Isolated runtime staging follow-up (2026-10-14)

The inherited-PYTHONPATH prerequisite above is now corrected: the installer
invokes its Python version check and stager with `-I`, and both the stager import
check and generated unit-backed wrappers use `-I`. The publication-only test
mocks import admission; three separate actual-subprocess tests create temporary
stdlib venvs without pip and use harmless synthetic modules. They prove that
PYTHONPATH-only modules are refused, installed synthetic modules take precedence
over poisoned PYTHONPATH, and wrappers preserve arguments while ignoring that
poisoned path. No existing Python environment was modified.

Focused command, with `PYTHONPATH=src:runtime/src` for the test runner only:
`python -m pytest tests/unit/test_stage_runtime_entrypoints.py tests/unit/test_stage_runtime_isolation.py tests/unit/test_packaging.py -q`.
Mac: **32 passed in 1.61s**; Debian 13 ARM64 review source copy using the existing
review venv: **32 passed in 0.13s**. Targeted Ruff, shell syntax checking of
`packaging/install.sh`, and `git diff --check` passed. These are synthetic/local
tests, not CI, installed Nexus closure verification, or live service validation.
The previous full-suite source aggregate predates this follow-up and must not
be attributed to the new tree.

Isolated Python still processes normal site-packages/site configuration; it is
not an immutable environment guarantee. Actual installed-byte measurement,
administrator time publication, production context composition, and lifecycle
fencing remain open. Administrator-managed provisioning remains portable:
deployment-specific identities, policies and capacities are explicit inputs,
not defaults inferred from this VM. No Boot files, services, keys, clocks,
hardware, CI or remote Git state were changed by this follow-up.

### Administrator time initial publication (2026-10-14)

`initialize_administrator_time` now provides a fixed-path initial publication
boundary for explicit canonical UTC-anchor bytes. It requires independent
BootstrapContext, the protected policy, matching byte digest and a separate
exact-True initialization confirmation. It checks current boot, policy, bounded
time projection, nonregressing BOOTTIME and directory identity before completion.
It neither derives UTC from the OS clock nor changes that clock or grants start.

Existing `time.json` or any `time.pending` entry refuses without replacement.
Exclusive creation, private files, read-back and fsync preserve the supplied
bytes; a pending marker blocks readers across incomplete publication. Independent
review found a nested flock conflict in the first implementation. Revalidation
now uses shared locking while the pending marker remains, then reacquires
exclusive locking and rechecks exact retained bytes before marker removal.
Regression tests use real shared/exclusive file locks in ordinary temporary
directories. A final directory fsync failure after marker removal raises
`TimeDurabilityUncertain`: current-boot readers may see the record, but durable
publication is unconfirmed. Do not retry automatically or claim fail-blocked
readability for this particular failure.

Focused tests: `python -m pytest tests/unit/test_bootstrap_clock_store.py tests/unit/test_bootstrap_clock_publication.py tests/unit/test_bootstrap_clock.py tests/unit/test_runtime_administrator_clock_source.py -q`
with source PYTHONPATH, on Mac and the existing Debian ARM64 review environment.
Final results: Mac **70 passed in 0.10s**; Debian ARM64 **70 passed in 0.07s**.
Targeted Ruff, `git diff --check` and the 54-file documentation link check passed.
The 14 new publication cases cover confirmation, existing/pending refusal,
real-lock publication, boot/expiry/regression refusal, retained-byte mutation
and final fsync uncertainty. This is synthetic ordinary-file evidence, not
production provisioning, trusted UTC calibration, systemd lifecycle or CI.

Remaining: interactive input/confirmation wiring to an independently produced
context, explicit renewal/reboot replacement and interrupted-state recovery
procedures. No real time record was created. The initialize-only API intentionally
does not provide an overwrite or delete fallback; the full administrator workflow
is not yet complete. Installed closure measurement and runtime lifetime fencing
also remain open. VM-specific identity or time defaults were not introduced.

### Interrupted administrator time publication recovery (2026-10-14)

`recover_administrator_time` completes only an existing exact, complete
`time.json` plus the known private `time.pending` marker. The administrator must
confirm the canonical bytes' SHA-256 and separately confirm recovery. The same
independent context, protected policy, current boot and nonregressing bounded
BOOTTIME projection used by initialization are rechecked. Recovery fsyncs the
retained record, allows protected shared-lock reinspection while pending blocks
readers, reacquires exclusive locking and compares the retained bytes again
before removing the marker. It never repairs/truncates/overwrites the record or
resets an approval deadline. Final directory fsync failure remains explicitly
durability-uncertain, not guaranteed reader refusal after marker removal.

Operational decision order: inspect retained state; if it is complete, reviewed
and still valid in the current boot, explicitly recover those same bytes. If
expired, from another boot, incomplete or unknown, leave it unchanged and retain
the refusal. A replacement/renewal procedure is still separate unimplemented
work; deleting the marker or retrying initialization is not a recovery shortcut.
The library boundary is not yet exposed as an operator CLI because its expected
context must come from independent production measurements, not candidate JSON.

Validation: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_bootstrap_clock_store.py tests/unit/test_bootstrap_clock_publication.py tests/unit/test_bootstrap_clock_recovery.py tests/unit/test_bootstrap_clock.py tests/unit/test_runtime_administrator_clock_source.py -q`
gave **84 passed in 0.12s** on Mac and **84 passed in 0.08s** in the existing
Debian ARM64 review environment. Targeted Ruff, diff check and the 54-document
link check passed. Recovery adds 14 cases, including real shared-lock public
recovery, unchanged retained state on refusal and final durability uncertainty.
Independent code review found no concrete new defect; tests remain synthetic
and ordinary-file-only. No live time record, service, system clock, hardware,
CI, production key or remote Git state was changed.

Follow-up review added failure injection at both pre-unlink recovery fsyncs:
each failure preserves record and marker and the reader refuses. Recovery now
has 16 cases. Final focused result: **86 passed in 0.14s** on Mac and
**86 passed in 0.08s** on Debian ARM64; targeted Ruff and diff check passed.
The reviewer rechecked and confirmed the imported fixture uses real shared
flocks (an earlier claim of an unlocked fixture was stale and withdrawn).

Debian ARM64 full unit suite was also run this turn, before the final two
test-only cases: **4855 passed, 1 skipped, 2 warnings in 40.94s** with
`PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit --basetemp="$task_test_dir" -q --tb=short`,
where `task_test_dir` was created with `mktemp -d /home/rabbit/nx.XXXXXX`.
The two warnings were existing multiprocessing/fork deprecations in deadline
crash tests. This is the existing VM review source copy/venv, not CI or a clean
installed production closure. The final two added cases ran in the focused
86-test result above; do not add them to the full-suite execution count.

### Selected installed-file measurement diagnostic (2026-10-14)

`installed_manifest.py` defines a bounded canonical selected-file manifest with
an independently supplied `sha256:` pin. `installed_files.py` reads actual
regular files under canonical `/usr` and `/opt` paths using descriptor-relative
no-follow traversal, protected ancestor checks, exact ownership/mode/size/hash,
single-link checks and two identity-stable observations. The new
`installed-files-check --manifest-digest sha256:...` operator command accepts
bounded manifest stdin and reports selection counts/digest only. It never
generates its own expected pin, installs files, imports measured modules,
executes a service or modifies the selected tree.

This diagnostic is not a completed package/unit-closure producer. Unlisted
files, symlinks, Python resolution and dependencies, interpreter/system files,
systemd aliases/drop-ins/transitive dependencies, and compatibility admission
remain outside its scope. A canonical regular target's match cannot establish
its symlink execution path. Separate package/unit manifest definitions and
protected production binding are still needed; no single selection digest is
assigned to both context fields. Independent review identified that distinction
and a bare-hex/prefixed-hash integration mismatch; the latter was corrected to
the existing `sha256:<hex>` pin format, with bare-hex refusal regression coverage.

Command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_installed_manifest.py tests/unit/test_installed_files.py tests/unit/test_installed_files_cli.py tests/unit/test_boundary_static.py tests/unit/test_wizard_and_cli.py -q`.
Mac: **119 passed in 0.59s**; Debian ARM64 source review copy: **119 passed in
0.39s**. All tree tests use ordinary synthetic temporary files. CLI tests mock
the public measurement boundary; they are not a claim that the current VM's
installed Nexus files match a reviewed deployment manifest. No production
manifest/pin was created and no installed tree was inspected this turn.

Ruff passed for the five new implementation/test files. Checking the touched
CLI also reports the existing F401 `tpm_present` import, present at HEAD; it was
not changed as unrelated cleanup. No full-suite result is claimed for this
new tree. Earlier full-suite checkpoints predate these changes. No Boot files,
existing venv, service, clock, credentials, hardware, CI or remote Git state
were changed.

### Integration-path audit and bootstrap generation publication (2026-10-14)

Fresh read-only integration audits confirm that `activated._run_once` still
does not compose the bootstrap supervisor and `BootstrapNarrowingManager`
still refuses widening. The remaining context source must independently select
approval ID and generation and bind protected package/unit measurements; the
selected-file diagnostic cannot supply full closure admission by itself.

The next lifecycle connection is a pair-scoped prepare/grant/withdraw operation
owned by the manager under the existing supervisor transaction, audited-helper
start before commission-helper start, and stop/inactive confirmation before
withdrawal. Start jobs must reuse `BootstrapStartJobs` with the supervisor's
actual checks, not a truthy bypass. `/run/systemd/system.control` remains a
candidate mechanism pending its production mutation/reload/reboot contract; it
was not silently adopted by this audit and no live writer was enabled.

For the separately well-defined provisioning step 5, a real fixed-path
`publish_bootstrap_generation` now writes the existing bootstrap-only layout.
It consumes independently selected context and canonical metadata/config,
requires exact publication-transcript digest plus separate exact-True consent,
creates only a new numbered directory with private exclusive-created files,
fsyncs and reads back the tree, and compares stable snapshots before completion.
A per-number `.bootstrap-N.pending` marker blocks the existing bootstrap reader
at both ends of its verification until publication completes. Existing numbered
paths (even empty directories) and pending state are never overwritten. Failures
retain private state for review; no automatic repair, cleanup or number selection
occurs. Final fsync failure after marker removal reports durability uncertainty;
readers may see the generation, so it is not falsely described as still blocked.

The result remains `VerifiedBootstrapGeneration` (shape/byte integrity), not
semantic admission or a start grant. Ordinary commissioned-generation readers
must still refuse this variant. The API does not manufacture a context from
the candidate, generate approval/signing material, install services or expose
an unrestricted path. Production context composition and interactive publication
remain incomplete, and no live generation was published.

Validation command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_bootstrap_generation.py tests/unit/test_bootstrap_generation_store.py tests/unit/test_bootstrap_generation_publish.py tests/unit/test_runtime_bootstrap_generation_admission.py -q`.
Mac: **77 passed in 0.15s**; existing Debian ARM64 review copy/venv: **77 passed
in 0.08s**. The 14 new publication cases include actual publisher→reader
roundtrip on ordinary temporary storage, normal-reader refusal, existing-target
preservation, final-recheck mutation, late/dangling pending marker refusal,
other-generation isolation and fsync uncertainty. Targeted Ruff and diff check
passed. Independent source review found no concrete publication/reader defect;
these results do not establish production invocation or admission. No CI or
full-suite run is claimed for this increment.

### Independent administrator selection → generation provisioning (2026-10-14)

Added a canonical per-boot administrator selection (`bootstrap_selection.py`)
and protected fixed `/etc/azazel/bootstrap/selection.json` reader. The record
contains full deployment digest, boot ID, approval ID, generation number and
generation digest. Unknown fields, noncanonical bytes, pending state, wrong boot,
changed deployment, unsafe files and observed source replacement refuse. No
defaults, candidate approval reads, UUID generation or latest-number selection
are used. A selection is intent, not approval. Its initialization/replacement
workflow is not yet implemented; no production record was created.

`load_declared_bootstrap_context` builds a distinct `DeclaredBootstrapContext`
from the protected deployment, separately declared node, selection, current boot
and independently hash-pinned prestart policy. The policy decoder now separates
full-byte pin verification from complete context binding, avoiding a circular
dependency on a candidate-supplied context. Final rereads check all input sources.
This result intentionally is NOT `BootstrapObservation`: declared epoch,
revocation, package and unit expectations are not fresh measurements or semantic
admission. The actual runtime producer/closure and lifecycle checks remain open.

`publish_selected_bootstrap_generation` connects those independently selected
inputs to the actual generation publisher and accepts no caller-supplied context
or generation number. Its versioned confirmation transcript binds the exact
metadata/config digest AND the complete selected context/operator. Thus old
confirmation cannot be reused after an approval-ID/operator change even if
payload bytes are identical. It rechecks selection before writing and before
completion; changed selection leaves pending state rather than success.

Independent review found a prior integration defect: the old bootstrap publisher
shared the ordinary numeric generation root, so a higher bootstrap number could
be selected by ordinary `GenerationStore.current()` and make it refuse. The
bootstrap reader/publisher now use **`/var/lib/azazel/bootstrap-generations/`**,
with root-private 0700 directory declaration in both `layout.py` and installer.
The implementation spec and installation guide explicitly record this namespace
separation. The first packaging run caught the missing layout declaration
(181 passed, 1 failed); the declaration was then corrected. No existing files
were moved or deleted and there is no automatic migration/fallback to the old
namespace. Existing records, if any, require explicit review, not silent import.

Final focused command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_bootstrap_selection.py tests/unit/test_bootstrap_selection_store.py tests/unit/test_bootstrap_declared_policy.py tests/unit/test_runtime_bootstrap_provisioning.py tests/unit/test_bootstrap_prestart_policy.py tests/unit/test_runtime_bootstrap_prestart.py tests/unit/test_bootstrap_generation.py tests/unit/test_bootstrap_generation_store.py tests/unit/test_bootstrap_generation_publish.py tests/unit/test_bootstrap_generation_namespace.py tests/unit/test_packaging.py -q`.
Mac: **184 passed in 0.28s**; Debian ARM64 review copy: **184 passed in 0.15s**.
Tests include actual fixed descriptor traversal redirected into a temporary root,
publisher→reader, and preservation of an existing ordinary generation while a
higher-numbered bootstrap generation is published in its separate namespace.
Targeted Ruff, shell syntax and diff checks passed. All record/file operations
were synthetic/ordinary temporary files, not live installation or provisioning.

The first full VM unit run produced **4981 passed, 2 failed, 1 skipped,
2 warnings in 41.23s**. Failures were actionable integration findings:
the VM README was stale, and the local new command row also needed the exact
command-name-only table format; runtime provisioning imported private library
helpers, violating the existing runtime/library boundary. The README row was
corrected and synced. Runtime now calls only public `publish_bootstrap_generation`,
whose trusted `revalidate_selection` callback rechecks independently selected
inputs under its publication transaction. The callback must be callable and
return exactly None; no candidate/RPC callback, permissive boolean, path override
or boundary-test allowlist was added. Two refusal regressions cover that API.
Post-fix local publication/runtime-boundary/README subset: **59 passed in 0.45s**;
targeted Ruff, diff and 54-file documentation link checks passed.

Final Debian ARM64 full unit rerun: **4985 passed, 1 skipped, 2 warnings in
41.53s**, using the unchanged existing review venv, a fresh ordinary temporary
`mktemp -d /home/rabbit/nx.XXXXXX` basetemp, and
`PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit --basetemp="$task_test_dir" -q --tb=short`.
Warnings remain the two Python 3.13 multiprocessing/fork deprecations in deadline
crash tests. Independent review of the public callback integration found no
concrete new defect. This is local VM test evidence, not GitHub Actions, actual
administrator provisioning or installed systemd lifecycle evidence. No service,
live record, firmware, physical device or remote Git state was changed.

### Interactive administrator selection publication/recovery (2026-10-14)

`bootstrap-selection-initialize` and `bootstrap-selection-recover` now connect
TTY-only bounded input to the protected selection store. Canonical record bytes,
digest re-entry and separate operation-word confirmation are required. No raw
identities/parser exceptions are echoed, no UUID/generation is selected, and no
approval, signature, deadline, service or runtime grant is created. Existing
records are not overwritten; recovery requires exact complete retained bytes and
the known marker, with current boot/deployment and directory identity checked
again. Protected readers refuse any pending marker, including a dangling link.

File transactions use real shared/exclusive flock phases, exclusive private
creation, readback and fsync. Shared-lock source reinspection occurs while the
pending marker blocks consumption, followed by exclusive retained-byte checks.
Failure before marker removal retains refusing state; a final directory fsync
failure after removal is a distinct `SelectionDurabilityUncertain`, surfaced as
CLI exit 2, not successful durable publication or guaranteed reader refusal.
Unknown/incomplete/stale-boot state is left untouched. Cross-boot replacement,
renewal and actual live provisioning are still not implemented/performed.

Command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_bootstrap_selection.py tests/unit/test_bootstrap_selection_store.py tests/unit/test_bootstrap_selection_publication.py tests/unit/test_bootstrap_selection_cli.py tests/unit/test_runtime_bootstrap_provisioning.py tests/unit/test_runtime_boundary.py tests/unit/test_readme_status.py tests/unit/test_boundary_static.py -q`.
Mac: **108 passed in 0.47s**; Debian ARM64 review copy/unchanged venv:
**108 passed in 0.37s**. The 16 publication tests and 9 CLI cases include actual
CLI→public store→protected reader initialization/recovery on private ordinary
temporary files, not only mocked backend assertions. Source-change refusal
restores a valid deployment reader before checking pending-state refusal, so an
exhausted mock iterator does not stand in for marker coverage.

Targeted new/changed selection-file Ruff passed. The touched central CLI still
reports the pre-existing F401 `tpm_present` import; unrelated cleanup was not
performed. No full-suite rerun/CI is claimed for this increment; the prior 4985
result predates these changes. Production records, installed services, existing
venv, hardware and remote Git state were not modified.

Final independent review found no concrete defect but identified two coverage
gaps. Added contention tests where a separately opened shared-lock holder blocks
the nonblocking exclusive upgrade for both initialization and recovery, plus
recovery-specific final-fsync uncertainty. Retained files remain unchanged on
contention. Publication coverage is now 19 cases. The same focused command above
finished **111 passed in 0.46s** on Mac and **111 passed in 0.34s** on Debian ARM64;
targeted test Ruff and diff check passed. No production behavior was enabled.

### Runtime-owned bootstrap generation operator command (2026-10-14)

The runtime distribution now declares `az-nexus-bootstrap`, with only
`generation-preview` and `generation-publish`. This is an operator tool, not a
daemon or systemd unit. Preview requires redirected input containing exactly
two bounded canonical JSON lines (metadata, config) and rejects trailing bytes.
It runs the actual generation verifier against independently loaded declared
context, rereads that context, and prints only the selected publication digest
and explicit non-admission status. It publishes nothing.

Publication requires a terminal, the same exact two records, digest re-entry
including the `sha256:` prefix, and a separate `PUBLISH` confirmation. It calls
the existing selected publisher, which reloads/rechecks context rather than
accepting expected context from the candidate or command line. Existing/pending
targets remain refusing. Durability uncertainty is exit 2, not successful
publication. No root, generation-number or expected-context override is accepted;
no signatures, deadline reset, admission, systemd mutation or activation occur.

The first packaging/boundary selection produced 66 passed and 1 failed because
the exact operator-tool declaration list had not yet named the new command.
Added this one explicit operator tool (not a general exemption), with tests
that it has no governed unit and that target overrides refuse before any input
or provisioning call. The unit-backed wrapper set remains unchanged. The
existing review venv was not reinstalled; source tests do not prove that its
console-script installation contains this new command.

Focused command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_runtime_bootstrap_cli.py tests/unit/test_runtime_bootstrap_provisioning.py tests/unit/test_runtime_boundary.py tests/unit/test_stage_runtime_entrypoints.py tests/unit/test_readme_status.py tests/unit/test_packaging.py tests/unit/test_offline_bundle.py -q`.
Mac: **96 passed in 1.45s**; Debian ARM64 source review copy: **96 passed in
0.28s**. Sixteen CLI cases include actual `main`→selected publisher→public store
→reader through private ordinary temporary files. Negative framing/confirmation
cases explicitly forbid publisher invocation so a default backend refusal cannot
make them pass accidentally. Targeted Ruff, diff and documentation checks pass.
No full suite or CI is claimed for this increment. No live generation, service,
existing venv, firmware, physical device or remote Git state was modified.

### Selected administrator time operator flow (2026-10-14)

`az-nexus-bootstrap time-initialize` / `time-recover` now connect terminal input
to the selected-context wrapper and the actual protected clock store. The
versioned confirmation digest binds exact canonical anchor bytes, complete
selected context/operator and operation; an initialize confirmation cannot be
used for recovery. The caller cannot supply expected context, target path or
clock-policy defaults. The store rechecks independently selected context via a
trusted callback before/after writing, alongside existing boot/policy/BOOTTIME,
expiry, drift, uncertainty and directory checks. Callback return must be exactly
None; changed selection leaves pending state. Runtime imports only public
library APIs, and the generation path is unchanged.

This is explicit administrator assertion of UTC bounds, not OS wall-clock trust
or external time-source calibration. There is no clock-setting call, automatic
renewal/replacement, deadline reset, service start or authority expansion.
Terminal digest re-entry and separate `INITIALIZE`/`RECOVER` confirmation remain
mandatory. Final persistence uncertainty is surfaced as exit 2. Actual provisioned
UTC and cross-boot replacement remain unverified/unimplemented respectively.

Command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_bootstrap_clock*.py tests/unit/test_runtime_administrator_clock_source.py tests/unit/test_runtime_bootstrap_cli.py tests/unit/test_runtime_bootstrap_provisioning.py tests/unit/test_runtime_bootstrap_time_provisioning.py tests/unit/test_runtime_boundary.py -q`.
Mac: **152 passed in 0.33s**; Debian ARM64 review copy/unchanged venv:
**152 passed in 0.24s**. Fifteen new cases include actual `main`→selected wrapper
→clock store→protected window reader for initialization and recovery on private
ordinary files with shared/exclusive locks. The coordinator corrected the negative
test's monkeypatch target to the actual CLI import, bound mock iterators separately,
and added oversize/truncated and cross-operation refusal cases. Independent final
review found no concrete defect. Targeted Ruff, diff and documentation link checks
passed. No full-suite result or CI is claimed for this increment, and no live
record, clock, service, hardware, existing venv or remote Git state was changed.

### Audit-first native dependency increment (2026-10-14)

The commissiond profile and rendered unit now declare `After`, `Requires` and
`BindsTo` on auditd as well as the activation controller. The read-only loaded
unit inspector requires those forward edges for commissiond and expects
auditd's in-pair inverse edges (`Before`, `RequiredBy`, `BoundBy`) to be empty
(option O1, see `docs/evidence/bootstrap-design-loaded-dependencies-2026-10-16.md`;
systemd cannot report them for a freshly loaded single unit). Expected dependencies still come from independent admission, not
the observed graph. This is portable systemd configuration, not a VM hostname,
IP address or architecture trust default.

The semantics follow the [systemd v257 unit contract](https://github.com/systemd/systemd/blob/v257/man/systemd.unit.xml).
Declaration and mocked D-Bus inspection are not installed lifecycle evidence.
Review of the prospective pair grant identified a prerequisite: close new starts
and fence/cancel pending or late jobs before reverse-order stop, withdrawal of
the owned grant and final inactive/masked verification. A persistent mask may
be shadowed by a higher-priority volatile override. No pair-grant API or
production overlay writer is adopted by this increment; the actual manager's
unmask/start refusal remains intact. No service reload or startup is performed.

Independent review found no pair-edge direction defect and noted the existing
activated entrypoint still exits refusing without `READY=1`; a long-running
ready controller remains a deployment prerequisite. Review-requested reverse
edge omission tests were added. The lifetime tests assert all rendered forward
edges for both units; the hardening round-trip verifies packaged bytes.

Final command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_runtime_hardening.py tests/unit/test_runtime_bootstrap_lifetime.py tests/unit/test_runtime_bootstrap_loaded.py tests/unit/test_runtime_bootstrap_manager_loaded.py tests/unit/test_runtime_bootstrap_manager.py -q`.
Mac: **174 passed in 0.17s**; Debian ARM64 source review copy, unchanged venv:
**174 passed in 0.14s**. These are synthetic/source tests, not live systemd
integration. Targeted inspector/test Ruff and `git diff --check` pass; 54
Markdown files pass link checking. Including the existing hardening module in
Ruff reports its three pre-existing F401 imports (`field`, `Mapping`, `Sequence`),
which are unchanged. No full-suite rerun, CI, installation, activation or remote
Git update is claimed for this increment.

### Start-fence prerequisite wired into containment (2026-10-14)

`BootstrapSupervisor._contain` now invokes the trusted manager's exact-pair
`close_starts()` before mask, reverse-order stop and remask. Only exact `None`
means completion; missing method, exception or any other result is retained as
a containment failure even when all inactive/masked observations succeed.
Cleanup is still attempted for both helpers and emergency narrowing is invoked.
This applies to initial and terminal containment; a future reviewed grant must
explicitly reopen admission rather than inferring permission from `unmask`.

`BootstrapNarrowingManager.close_starts` deliberately refuses without opening
a bus session. No deployment fence exists yet: process-local start refusal is
not evidence that old/external start jobs are fenced. Its supervisor integration
test now proves cleanup is attempted but refresh/admission is never reached and
no successful containment is reported. There is no new widening operation.
Independent design review confirmed the requirement and the explicit initial
containment/reopen lifecycle caveat; production activation remains unavailable.

Command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_runtime_bootstrap*.py -q --tb=short`.
Mac **517 passed in 0.83s**; Debian ARM64 source review copy, unchanged venv,
**517 passed in 0.65s**. These use injected dependencies/ordinary files, not
installed service jobs. Targeted Ruff and diff checks pass. Changed source:
`runtime/.../bootstrap.py`, `runtime/.../bootstrap_manager.py`; tests:
`test_runtime_bootstrap.py`, `test_runtime_bootstrap_manager.py`; documentation:
this handoff and runtime README. No CI, service action, provisioned record,
physical operation or remote Git update was performed.

### Bootstrap lifecycle events use auditd's single writer (2026-10-14)

The supervisor record shape is now aligned with the declared schemas: top-level
events omit `unit_key`; helper intent/readiness events carry only `auditd` or
`commissiond`. `BootstrapAuditClient` sends through the fixed local audit socket
and accepts only a bounded, exact append receipt. It does not write the ledger
file. Auditd's ordinary service-writable `audit.append` enum excludes bootstrap
types; `audit.bootstrap.append` admits root only, and AuditService enforces that
the selected verb and event family match. The event remains a claim from the
root supervisor, whose package and composition are part of the trusted computing
base; the schema alone is not a signature or independent attestation.

Independent review caught both the unitless-field mismatch and the broad service
principal issue before integration. Both were corrected. Targeted runtime set
including auditd, audit client, job drain, manager, all bootstrap tests and
runtime boundary: Mac **604 passed in 1.16s**, Debian ARM64 review copy **604
passed in 0.89s**. Ruff on touched production/test files, diff check and 54-file
link check pass. Tests use ordinary files and synthetic Unix socket pairs.
No actual audit socket, D-Bus, mask or service was used. Full suite/CI remain
unclaimed for this increment.

The client/socket test was then tightened against `SocketServer.read_frame`'s
one-request EOF check. The client now half-closes its write side before waiting
for the receipt; fake-socket tests assert the server observes EOF first. The
same targeted 604-test set passes again on Mac (**1.18s**) and the Debian ARM64
review copy (**0.85s**). This is protocol-pair evidence over socketpair only.

### Overlay transaction journal state machine (2026-10-14)

Independent review confirmed the supervisor's process lock does not fence
other systemd clients and cannot make the two-file publication atomic. Direct
files in `/run/systemd/system.control` also need a supported-version check,
effective loaded-property inspection, and reboot/crash handling before
production use. Accordingly, no path writes or daemon reload were added.

Added `src/azazel_nexus/bootstrap_overlay_journal.py`, a strict pure state
machine for a root-protected journal: immutable boot/context/grant identity,
fixed two-unit payload digests, per-file device/inode ownership, intent →
partial → published → closing → closed transitions, canonical bounded encoding,
and strict decoding that refuses unknown fields, duplicate keys, reordered
identities and inconsistent phase/ownership. Withdrawal evidence requires
start-fence, both stops/inactive observations, both owned-file withdrawals, and
restored persistent/effective masks. The record describes file transaction
progress only; it cannot grant starts or prove these observations. The
pre-create intent must be durable before exclusive file creation, followed by
an ownership-record fsync; a crash in that gap stays ambiguous and requires
manual recovery rather than adopting matching bytes.

Next, use regular-file tests to verify every transition, serialization and
crash ambiguity. A persistent lock/journal file store, fixed-path writer,
systemd reload integration, boot reconciliation and live effective-mask
verification remain separate work. No backend is wired into the supervisor.

Final read-only independent code review found no concrete defect in this
increment. Debian ARM64 review-copy full regression was then run with the
existing venv and a new short ordinary-file pytest scratch directory:
`PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit --basetemp="$task_test_dir" -q --tb=short`.
Result: **5069 passed, 1 skipped, 2 warnings in 41.62s**. The warnings are the
existing Python 3.13 multi-threaded `fork()` deprecations in the two abrupt
deadline-worker exit tests. This result describes the source review copy, not
an installed distribution, live systemd integration, clean build or CI run.
Documentation link check also passes (54 Markdown files).

### Pair-scoped grant lifecycle integration (2026-10-14)

The supervisor no longer sequences independent per-helper `unmask` calls.
It durably records pair-grant intent, revalidates admission/cancellation,
requests a single transaction-bound `open_pair()` and revalidates again. It
then sends controller READY before auditd, since the notify helper is ordered
`After=` the controller. The stopped-writer/live-writer comparison and the
grant-intent append receipt are required before commissioning can be requested.
Grant completion must return exact `None`; uncertain/partial grant creation
enters cleanup.

Cleanup now separates close-starts, initial masks, reverse-order stops and
inactive observations from owned `withdraw_pair()`, followed by remask and final
observations. Withdrawal is skipped if the start fence or stop/initial mask
operations or inactive observations are unconfirmed. Ownership must remain
recoverable; failure is never promoted to a successful stopped result.
Initial containment does not claim or withdraw an unowned grant. Withdrawal is
attempted only when this run has a durable transaction identity; a process-local
empty variable cannot establish ownership or prove another grant absent.

The narrowing adapter refuses both pair-grant methods without D-Bus access.
This integrates the required lifecycle into the real supervisor code but does
not implement or select a production overlay writer. Durable ownership,
reload/late-job fencing, reboot recovery and a reviewed production composition
remain required. No systemd reload/start, real provisioning, CI or GitHub write
is authorized or performed by this increment.

Verification command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_runtime_bootstrap*.py -q --tb=short`.
Mac **526 passed in 0.82s**; Debian ARM64 review source copy with unchanged venv
**526 passed in 0.67s**. Targeted Ruff, diff and 54-file documentation link checks
pass. Independent review found no source-ordering defect and caught incorrect
test failure timing; tests were corrected to inject stop/inactivity failures
after pair opening, to propagate non-None stop results, and to distinguish
initial idempotent withdrawal from final withdrawal. These are synthetic tests,
not an installed grant/revocation demonstration. The preceding 5069-test full
suite result predates this increment and is not presented as its full result.

### Exact-pair systemd job-drain component (2026-10-14)

`bootstrap_job_drain.BootstrapJobDrain` and the trusted manager's owned-session
`drain_pending_jobs` implement a bounded queue-cancellation component. An async
independent revalidator must prove an already effective loaded-mask/reload and
new-start fence before and between observations/cancellations. The adapter
pins the systemd unique owner, validates bounded ListJobs identities and paths,
and cancels only IDs belonging to the exact auditd/commissiond pair. Unrelated
jobs are never cancelled and `ClearJobs` is never used. At most eight list
rounds and a finite transaction deadline apply; two pair-empty observations
are required. Owner changes, missing guard, malformed/oversized responses,
timeouts and ambiguous cancellation cannot produce success.

The [systemd v257 D-Bus contract](https://github.com/systemd/systemd/blob/v257/man/org.freedesktop.systemd1.xml)
states that job IDs are unique within a manager instance, and cancellation does
not generally abort already executing operations. Therefore this component
does not establish the start fence, inactive services, empty cgroups, completed
stops or safe grant withdrawal. The supervisor must still perform the existing
stop/observation sequence after a deployed fence is established. The current
production `close_starts`, `open_pair` and `withdraw_pair` remain refusing;
the component is tested on fake transports, not connected to live systemd.

### Overlay transaction journal state machine (2026-10-14)

Independent review confirmed the supervisor's process lock does not fence
other systemd clients and cannot make the two-file publication atomic. Direct
files in `/run/systemd/system.control` also need a supported-version check,
effective loaded-property inspection, and reboot/crash handling before
production use. Accordingly, no path writes or daemon reload were added.

Added `src/azazel_nexus/bootstrap_overlay_journal.py`, a strict pure state
machine for a root-protected journal: immutable boot/context/grant identity,
fixed two-unit payload digests, per-file device/inode ownership, intent →
partial → published → closing → closed transitions, canonical bounded encoding,
and strict decoding that refuses unknown fields, duplicate keys, reordered
identities and inconsistent phase/ownership. Withdrawal evidence requires
start-fence, both stops/inactive observations, both owned-file withdrawals, and
restored persistent/effective masks. The record describes file-transaction
progress only; it cannot grant starts or prove these observations. The
pre-create intent must be durable before exclusive file creation, followed by
an ownership-record fsync; a crash in that gap stays ambiguous and requires
manual recovery rather than adopting matching bytes.

The state machine and strict canonical codec were implemented and tested with
synthetic values and ordinary temporary files; it does not persist a journal to
disk yet. Command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_bootstrap_overlay_journal.py -q`.
Mac: **42 passed in 0.03s**; Debian ARM64 review copy with unchanged venv:
**42 passed in 0.03s**. Ruff, `git diff --check` and 54-file doc-link check pass.
The test fixture also proves that a filesystem stat identity is merely recorded;
no unit file is created or removed by the state-machine API. Independent review
found that two unit names could initially claim one `(st_dev, st_ino)` pair and
that stat integers were unbounded. Both are now rejected; new tests cover a
crafted canonical duplicate identity and out-of-range inode.

Next, implement the journal file store and recovery proof, then a fixed-path
writer and systemd reload/effective mask integration. Live manager calls remain
unverified and the manager still refuses the grant.

Independent read-only review found no concrete defect in the component scope,
noting that cancellation of a stop job still requires a new observed stop.
Coordinator additions check pinned routing, wrong reply sender, fence loss
between cancellations and a disappeared job returning D-Bus error. Together
with the delegated tests, 24 new cases cover scope, malformed/oversized lists,
owner changes, persistent/running jobs, timeouts, single-use behavior and actual
sync-manager-to-async-drain cleanup over a fake transport.

Final command: `PYTHONPATH=src:runtime/src python -m pytest tests/unit/test_runtime_bootstrap*.py tests/unit/test_runtime_boundary.py -q --tb=short`.
Mac **566 passed in 1.03s**; Debian ARM64 source review copy and unchanged venv
**566 passed in 0.79s**. Targeted Ruff, diff check and documentation link checks
pass. No full-suite rerun or CI is claimed for this increment. Changed files:
`runtime/src/azazel_nexus_runtime/bootstrap_job_drain.py`,
`runtime/src/azazel_nexus_runtime/bootstrap_manager.py`,
`tests/unit/test_runtime_bootstrap_job_drain.py`, runtime README and this handoff.
No actual job was enumerated/cancelled and no installed service was changed.

### Descriptor-pinned overlay journal file store (2026-10-14)

Extended the pure overlay transaction state machine with an internal
`OverlayJournalStore` that receives a directory descriptor plus a trusted
reopen callback; it has no public pathname or filename parameter. It pins and
rechecks the private `0700` directory identity, accepts only the fixed
`0600` single-link regular journal and a single internally generated temporary
name, bounds and canonically decodes contents, and provides O_EXCL creation,
expected-value compare-and-swap replacement, and expected-value removal.
Replacement fsyncs the temporary before rename and the directory after rename.
Removal checks the exact record inode and bytes before unlinking and fsyncing
the directory. Post-create, post-rename, post-unlink, or durability failures
that leave persistence uncertain raise a distinct refusal subtype; no failure
is reported as a successful transition. Temporary cleanup is limited to the
exact inode created by this call. Crash leftovers and unexpected directory
entries fail closed and are not adopted.

Declared `/var/lib/azazel/state/bootstrap-overlay` as a separate root-owned
`0700` directory in the layout and installer. This isolation is necessary
because `/var/lib/azazel/state/bootstrap` contains the permanent shared
`supervisor.lock`; the journal store intentionally refuses every unrecognized
directory entry. The existing bootstrap state directory remains the home of
the retained deadline and transaction lock. A normal install prepares both
boundaries; it does not yet install or wire the journal into the supervisor.

The accompanying tests use ordinary temporary directories/files only. They
cover CAS conflicts, wrong ownership/modes, symlink/hardlink/noncanonical or
unexpected entries, injected write/fsync errors, and uncertain outcomes after
filesystem mutations. Added a fixed production traversal from `/` to the
dedicated directory (rejecting symlink components, writable ancestors, wrong
owner/mode), plus `overlay_journal_store_in_transaction(guard)` for a lock
already held by the supervisor and `overlay_journal_transaction()` for a
standalone caller that must acquire it exactly once. `BootstrapTransactionGuard`
is yielded by the shared lock and revalidated before/after store use, avoiding
the nonblocking flock self-conflict a nested lock would cause. The lock remains
cooperative and is not an external-systemd start fence. Commands:
`PYTHONPATH=src:runtime/src .venv/bin/python -m pytest -q tests/unit/test_packaging.py tests/unit/test_bootstrap*.py tests/unit/test_runtime_bootstrap*.py tests/unit/test_runtime_boundary.py`
and `uv tool run --from ruff ruff check src/azazel_nexus/bootstrap_lock.py src/azazel_nexus/bootstrap_overlay_journal.py tests/unit/test_bootstrap_overlay_journal.py`.
Mac local: **67 focused journal tests**; the bootstrap, packaging and runtime
boundary selection passed **1,196 tests**. Ruff, `git diff --check`, and the
54-file documentation link check pass. Debian ARM64 VM review copy: **67
focused tests** and **1,196 broad tests** passed on the unchanged venv.
Independent code review identified and prompted fixes for uncertain-state
classification after mutations, a temporary-FD close failure, journal/lock
directory collision, and nested-lock reacquisition. Final review confirms the
lock lifecycle and expiry tests; the guard is an internal trusted-code aid,
not an isolation boundary against arbitrary Python code. This is still not
integrated into supervisor startup/containment, and there is no systemd overlay
writer, reload, start
fence, or recovery orchestration. Read-only Debian ARM64 VM inspection
reported systemd 257.13, but the installed Nexus overlay directory and systemd
control directories were absent; no package was installed and no live service
was operated. No CI or device was accessed.

### Fixed-pair journaled overlay file publisher (2026-10-14)

Added `runtime/src/azazel_nexus_runtime/bootstrap_overlay_files.py` as a
descriptor-only, non-entrypoint writer primitive. It obtains only the auditd
and commissiond rendered bytes from `hardening.PROFILES`; no caller chooses a
unit name, payload or path. Its intent derives the boot identity and canonical
context digest from a `VerifiedBootstrapApproval` object, generates a random
transaction id, and binds the exact two rendered payload hashes. The function
does not itself authenticate that approval, admit the generation, close the
systemd start fence, reload systemd or grant either unit.

Before publishing, the writer checks the exact persistent `/dev/null` mask
symlinks, refuses relevant higher-priority entries and drop-ins, and validates
any journal-owned file against its recorded inode, mode, link count and full
bytes. It durably creates the intent before the first O_EXCL/no-follow file;
for each candidate it writes exact mode-0644 bytes, fsyncs, reopens and
read-verifies the same inode, fsyncs the overlay directory, then advances the
journal with that inode and digest. `published` means only that both candidate
files are durably recorded. It is not a loaded-unit, start permission or grant
claim. A partial second-file failure remains journaled. If a candidate is
durable but its journal update is not, the unrecorded file and prior journal
are retained; retry refuses instead of inferring ownership or cleaning up.

Independent review confirmed the low-level primitive is not imported by the
supervisor, CLI or systemd bus, and has no production path opener/caller. It
must remain disconnected until an independently reviewed start fence,
effective-unit/load-path verification and recovery flow exist. The writer
does not validate the full effective systemd load path or establish approval
authority; those are explicit future adapter gates. No daemon-reload, unit
start, service stop, firmware or `/dev` operation is performed by this code.

Tests use temporary regular-file directories and synthetic persistent-mask
symlinks only. They cover exact payload binding, higher-priority/drop-in and
mask conflicts, second create/update failure, the durable-file/unrecorded-inode
crash gap, refusal to retry stale state, and replaced inode rejection.
Verification command:
`PYTHONPATH=src:runtime/src .venv/bin/python -m pytest -q tests/unit/test_packaging.py tests/unit/test_bootstrap*.py tests/unit/test_runtime_bootstrap*.py tests/unit/test_runtime_boundary.py tests/unit/test_runtime_bootstrap_overlay_files.py tests/unit/test_stage_runtime_entrypoints.py tests/unit/test_runtime_hardening.py`
Mac: **1,246 passed**, including **12 focused writer tests**; Debian ARM64
review copy: **1,246 passed**, including **12 focused writer tests**. The new
writer and test Ruff checks pass. Independent review of this last delta is
pending; no CI or live systemd verification is claimed.

### Physical-install portability boundary (2026-10-14)

The administrator-managed bootstrap remains one workflow for the Debian VM and
later physical nodes. Flexibility belongs at measured platform adapters, not in
the authority-bearing core: the administrator's declarative policy, approval
semantics, exact auditd/commissiond scope, fail-closed behavior and transaction
ownership remain common. A destination adapter may report observed architecture,
systemd version/features, package/unit closure, filesystem capacity and
available hardware evidence. Unknown or unsupported observations refuse the
affected operation; they do not select weaker defaults or a `vm=True` path.

For installation, keep package-owned state paths and permissions declared by
`src/azazel_nexus/layout.py`; do not make privileged paths or D-Bus addresses
operator-selectable. Adapt only through an explicitly supported installer or
systemd capability profile that is derived from the destination and reviewed
against its actual load paths. The low-level publisher therefore requires
separate descriptors for the controlled overlay, persistent masks and
higher-priority unit directory. It must refuse if the profile cannot prove the
effective precedence/load path for that systemd build. Architecture is an
artifact compatibility observation, not authorization. Node identity, keys,
audit history, boot-bound approvals and mutable state are freshly provisioned
per physical node; none is copied from the VM.

This is a portability contract, not evidence of physical installation support.
Before wiring the production supervisor, implement and review the target
capability probe and systemd start fence, then exercise the same workflow under
synthetic tests and an explicitly authorized Debian Live lifecycle test. The
current file publisher still has no production caller, performs no systemd
reload/start and establishes no live start fence.

Independent read-only review agrees with this boundary. Existing deployment
and selection records already separate administrator intent from per-boot
selection; package/state paths and the auditd/commissiond unit pair remain
deliberately fixed. The current product support baseline remains Debian 13 /
amd64. ARM64 VM execution of synthetic tests is useful cross-architecture
software evidence only; it does not widen that support matrix. In particular,
`BootstrapSupervisor` is not yet composed into the installed `az-activated`
entrypoint, and `BootstrapNarrowingManager` still refuses grant/start/withdraw.

Follow-up verification after adding direct tests for the approval-to-publisher
composition: the targeted local selection
`PYTHONPATH=src:runtime/src .venv/bin/python -m pytest -q tests/unit/test_packaging.py tests/unit/test_bootstrap*.py tests/unit/test_runtime_bootstrap*.py tests/unit/test_runtime_boundary.py tests/unit/test_stage_runtime_entrypoints.py tests/unit/test_runtime_hardening.py`
passed **1,248 tests**, including **14 overlay publisher tests**. Targeted Ruff,
`git diff --check`, and the 54-file documentation-link check passed. These are
local software checks only: no CI, installed systemd lifecycle, hardware
installation, or service operation was run.

### Read-only systemd compatibility observation (2026-10-14)

To make later machine variation explicit without accepting arbitrary systemd
layouts, added `bootstrap_systemd_profile.py` and a read-only Manager property
reader on `SystemdBusSession`. The first reviewed profile is deliberately
`systemd-257.13-deb13-path-v1`: it accepts the observed systemd version string
`257.13-<Debian revision>~deb13u<revision>` only when the complete ordered
`UnitPath` matches the current Debian 13 VM layout. This is a match on
systemd-reported values, not authentication of the host OS or package
provenance. Other upstream versions, suffixes, extra/higher-priority paths,
missing paths, duplicates or reordered paths refuse. Supporting another
version/layout therefore requires an explicit reviewed profile with its own
evidence and tests, not an environment-variable override.

The existing ARM64 Debian VM was queried read-only through the system bus and
reported Manager `Version=257.13-1~deb13u1` and the exact 12-entry profile now
pinned in the tests. `uname -m` reported `aarch64`; `/etc/os-release` reported
Debian 13. A repeat read-only SSH check on 2026-10-14 also successfully ran
`systemd --version`, `systemd-analyze unit-paths`, and `systemctl
is-system-running`: version `257.13-1~deb13u1`, exact reviewed 12 paths, and
`running`. This supersedes the earlier note that the `systemd` executable was
not on PATH. This is VM compatibility evidence, not physical hardware support
or an installed Nexus lifecycle result.

The current `SystemdBusSession.bootstrap_profile()` and profile reader were
then copied alone to a unique temporary VM directory and invoked with the
existing Debian review venv. Through the real system bus they returned
`systemd-257.13-deb13-path-v1`, version `257.13-1~deb13u1`, 12 paths. This
exercises the actual read-only D-Bus property calls, beyond the earlier
`systemctl` observations. The temporary source/bytecode files were removed;
no manager mutation, Nexus unit operation, install or source-tree change on the
VM occurred. It remains compatibility evidence only.

The reader has no production caller yet and is not a start fence or permission
to write `/run/systemd/system.control`. Upstream systemd v257 documents that
`RefuseManualStart=yes` still permits dependency starts, while `UnitPath` and
`Version` are observable Manager properties; direct overlay publication still
needs a supported manager-coordination mechanism, reload and effective-mask
proof. The exact v257 contract is documented in upstream
[`systemd.unit(5)`](https://github.com/systemd/systemd/blob/v257/man/systemd.unit.xml)
and the pinned [systemd D-Bus API](https://github.com/systemd/systemd/blob/v257/man/org.freedesktop.systemd1.xml).

An independent review caught that accepting arbitrary v257 package revisions
would have exceeded the observed compatibility evidence, and that the profile
name must not imply host-OS authentication. The gate is now limited to the
observed `257.13-<revision>~deb13u<revision>` Manager string plus the exact
ordered path list, and is named for that observation. It still does not prove
Debian identity or package provenance. Manager property names are type-checked
before allowlist membership. Final local selection
`PYTHONPATH=src:runtime/src .venv/bin/python -m pytest -q tests/unit/test_packaging.py tests/unit/test_bootstrap*.py tests/unit/test_runtime_bootstrap*.py tests/unit/test_runtime_boundary.py tests/unit/test_runtime_systemd_bus.py tests/unit/test_stage_runtime_entrypoints.py tests/unit/test_runtime_hardening.py -k 'not test_connect_constructs_and_runs_dbus_next_on_the_same_loop'`
passed **1,285 tests**, with **one test deselected** because the existing local
venv lacks `dbus-next`. New profile code/tests pass Ruff; import sorting for the
modified D-Bus module/tests passes. No CI or live systemd operation was run.

### Fence-failure containment correction (2026-10-14)

Independent runtime review found a mismatch between the `BootstrapManager`
contract and `BootstrapSupervisor._contain()`: when `close_starts()` failed,
the supervisor still issued `StopUnit`, despite the contract requiring an
effective start fence before any stop. The supervisor now attempts the exact
pair masks, but skips both stops and grant withdrawal unless the fence returned
confirmed success. It still requires positive inactive/masked observations and
raises `BootstrapContainmentFailed` with emergency narrowing on uncertainty.
Thus a running helper may remain running when fencing is unavailable; runtime
reports failure rather than racing a stop against unblocked start jobs.

Regression tests cover missing/raising/non-confirming fence results, an active
helper under fence failure, no stop/withdraw calls and the fake-bus operation
trace. `PYTHONPATH=src:runtime/src .venv/bin/python -m pytest -q tests/unit/test_runtime_bootstrap.py tests/unit/test_runtime_bootstrap_manager.py`
passed **101 tests**. `git diff --check` passed. Full Ruff on these large,
already-dirty files still reports existing formatting/import findings; no
unrelated cleanup was applied. CI and live systemd remain untested.

### Fixed supervisor process-lifetime callbacks (2026-10-14)

Added `BootstrapProcessLifetime` as a single-use context-managed adapter for
the supervisor's `stopped()` and `wait(timeout)` callbacks. It registers only
SIGTERM/SIGINT on the main thread, restores previous handlers on exit, and
uses a `threading.Event` so bounded waits wake promptly. It accepts no signal,
callback, environment or command input; reusing an object is rejected to avoid
carrying a stale stop event into a later run. Tests invoke captured handlers
directly and do not deliver real signals. The adapter is not yet wired to a
production service.

The current combined local selection (including the fence-failure regression,
systemd profile, and lifetime adapter) passed **1,299 tests**, with one
`dbus-next`-dependent test deselected. Ruff passed on new lifecycle/profile
modules and tests, import sorting passed for the modified D-Bus source/tests,
and E/F syntax checks (excluding existing E501 lines) passed on the touched
supervisor/test files. `git diff --check` and the 54-file document-link check
passed. No CI, service operation, device or hardware test was run.

### Audit startup-order review and platform-observation boundary (2026-10-14)

Independent read-only review confirmed a runtime blocker: `BootstrapSupervisor`
requires auditd masked/inactive for its prestart file inspection, then tries to
append `bootstrap.controller_ready_intent` through auditd's Unix socket before
starting auditd. The socket is created only by auditd's running server; there
is no socket-activation or queued-listener path. Consequently this first append
cannot succeed in the current composition. Retrying, direct supervisor writes
to the ledger, or a second writer are not safe workarounds and were not added.

The clean architectural direction is to treat auditd as infrastructure rather
than a bootstrap-granted helper, but that entails coordinated changes to the
controller's long-lived `Type=notify` lifecycle, generated unit dependencies,
`CORE_UNITS` masking, bootstrap pair ownership, audit head observation, and
event semantics. The current controller is one-shot, does not send `READY=1`,
and broadens its writable state path over audit storage. Because those changes
cross the trusted audit/activation boundary, no partial wiring was attempted.
Required design and tests are enumerated in the reviewer report: readiness
ordering, socket availability/loss, anchored head observation, append
acknowledgement ambiguity, and proof bootstrap containment never owns auditd.

The independent context review also confirmed that the current adapter seams
are installation-neutral, but no producer measures a complete installed
package/unit closure or authenticated health. The Debian 13/systemd 257.13
profile is a narrow compatibility observation, not an architecture allowlist
or OS authentication. Future hardware support should add explicit platform
observation adapters and separately reviewed profiles, while keeping policy
and authority platform-neutral; unknown measurements must remain unsupported,
not pass through a generic fallback. Selected-file measurement, Manager
properties and loaded-unit projections must not be described as complete
closure or admission.

No changes to production wiring, event schemas, unit ownership or audit storage
were made from these reviews. Their conclusions are static code review only;
no tests, CI, live systemd, VM, device or hardware operations were performed
for this review.

### Root-only audit writer-head query (2026-10-14)

Added the fixed, payload-free `audit.bootstrap.observe` verb for the root
bootstrap client. It returns only auditd's in-memory head established by its
startup verification and advanced by its serialized append handler. It does
not scan the live files, authenticate an external rollback anchor, or protect
against another privileged writer; the auditd single-writer/trusted-root
assumption remains. The client rejects an unverified flag, genesis/invalid
sequence, malformed digest, extra fields and transport/refusal errors. This
query can reconcile the last accepted head after auditd is available, but it
does not resolve how auditd becomes available before the controller's first
pre-READY audit event, nor replace the bounded stopped-writer prestart scan.

Synthetic tests cover root-only authorization, chain-not-verified refusal,
head movement after serialized appends, exact request vocabulary and malformed
responses. The focused run
`PYTHONPATH=src:runtime/src .venv/bin/python -m pytest -q tests/unit/test_runtime_auditd.py tests/unit/test_runtime_bootstrap_audit_client.py tests/unit/test_runtime_bootstrap.py tests/unit/test_runtime_bootstrap_prestart_audit.py`
passed **117 tests**. This is a protocol/read-boundary increment only; no
production service composition was enabled.

Added `BootstrapLiveAuditHead` as a typed comparison primitive: the first live
writer-head must exactly match the stopped-writer `AuditObservation`, and later
heads must be monotonic with digest stability at equal sequence. This avoids
pretending a live writer head is the same evidence type as a filesystem scan.
Its tests use synthetic tuples only and passed **17 tests**. The adapter is not
yet consumed by `BootstrapSupervisor`; it must not be reported as an integrated
runtime path while the service-start contract remains unresolved.

### Debian VM deployment preflight (2026-10-14)

Read-only SSH confirmation reported Debian 13 and `aarch64`. The `azazel-*`
unit-file listing was empty, `systemctl show` returned `LoadState=not-found` for
activated/auditd/commissiond, and `dpkg-query` found no installed
`azazel-nexus-runtime` package. No files were staged or changed on that VM.
Thus the ARM64 VM is available but is not yet an installed Nexus test target;
the next VM evidence requires a reviewed local package/install artifact and an
isolated install plan. No service behavior is inferred from its OS identity.

A second read-only query using the exact proposed fixed TSV fields
(`binary:Package`, `Version`, `Architecture`, `db:Status-Abbrev`) counted 1,672
installed records across two package architectures, with zero malformed rows.
Only aggregate counts were returned; package names and versions were not
exposed. This is format/host observation, not an independently pinned package
closure, package authenticity, or admission evidence.

The owner selected keeping auditd inside the exact two-helper grant, so moving
auditd outside that pair is not an option. Review then confirmed the current
pre-grant auditd append order is impossible with auditd masked and the auditd
socket absent. The existing overlay journal is explicitly not an audit event
ledger and cannot be treated as one.

A separate crash-recovery journal binds the exact boot/context/approval/
generation/grant identity before any widening. The typed model, protected
boot-keyed CAS store, and `BootstrapSupervisor` consumer are now connected;
they do not grant services and the journal is not an audit event ledger. The
supervisor enforces auditd's chain append receipt before commissiond becomes
startable. The store retains one record per boot and has no automatic garbage
collection. A fenced D-Bus backend, crash/restart reconciliation, independent
readiness/context producers and production entrypoint composition remain
absent. Therefore production `BootstrapSupervisor` remains unwired to a real
service-manager grant path. The lifecycle order is documented in
`IMPLEMENTATION_SPEC.md` §2.3; it must not be changed implicitly.

The final selected local runtime/bootstrap/hardening suite including this pure
model passed **1,427 tests, 1 deselected**. Target Ruff for the new model,
package observer, CLI and related tests passed; `git diff --check` and the
54-file documentation link check passed. Installer staging was attempted in a
temporary `DESTDIR` without service-manager/accounts; it correctly refused
because the existing Mac venv lacks pinned `dbus-next==0.2.3` (and the Debian
VM's system Python also lacks `dbus-next`). No dependency was installed and the
VM was not modified. Consequently there is no claim that runtime entrypoints
were staged or that Debian Live installation succeeded.

### Debian systemd parser verification (2026-10-14)

Copied the eight current generated service unit files to a unique temporary
alternate root on the Debian 13 ARM64 VM and supplied empty executable stubs
there for their fixed `ExecStart` paths. On systemd `257.13-1~deb13u1`,
`systemd-analyze verify --root=<temp-root> --recursive-errors=no --man=no`
passed for `azazel-activated.service`, `azazel-auditd.service`, and
`azazel-commissiond.service`. The wider eight-unit check returned successfully
but emitted missing external-system-unit notices because the alternate root
contained only the Azazel units; it is not counted as a clean pass. The focused
three-unit check covered the lifecycle dependency set. All temporary unit and
stub files were removed. No unit was installed, reloaded, enabled, started or
stopped. This is parser/declared-dependency evidence only, not service runtime
or installed closure evidence.

### Installation compatibility profiles (2026-10-14)

The read-only loaded-unit inspection path now requires a recognized systemd
compatibility profile before it inspects either bootstrap helper. The initial
profile is the measured Debian 13/systemd 257.13 ordered `UnitPath`; it is not
an OS identity claim or authorization to change units. Profiles are additive:
a future installation target can be supported by measuring its exact Manager
`Version` and ordered `UnitPath`, reviewing how its unit search precedence
affects the trust boundary, then adding a narrowly matched profile and
refusal tests. There is intentionally no wildcard, path-subset, architecture,
or distro-name fallback. Unknown hosts fail closed without preventing future
reviewed targets from being added.

This keeps machine/architecture-specific observations out of the authorization
contract while avoiding assumptions that all systemd installations share the
same unit lookup behavior. Compatibility-profile evidence remains separate
from package provenance, installed file closure, service health, or bootstrap
admission. Current local tests exercise the known profile and prove an
unsupported or malformed profile refuses before unit inspection; other real
machines remain unverified until their measurements are captured and reviewed.

Local verification for this connection (2026-10-14):
`pytest -q tests/unit/test_runtime_bootstrap_manager.py
tests/unit/test_runtime_bootstrap_manager_loaded.py
tests/unit/test_runtime_bootstrap_systemd_profile.py` passed **79 tests**.
Including `tests/unit/test_runtime_systemd_bus.py` passed **97 tests**, with
the single real `dbus-next` connection-construction test deselected because the
local venv does not contain the runtime dependency. Target Ruff, `git diff
--check`, and the 54-file docs-link check passed. The earlier broader local
suite attempt was not green (**4,903 passed, 61 failed, 16 skipped, 26 errors,
1 deselected**);
observed transport setup errors include macOS temporary socket paths exceeding
the 107-byte AF_UNIX limit. The remaining broad-suite failures were not
classified here and are not attributed to this compatibility-gate change.
No CI or Debian Live installation was run in this verification pass.

### Durable grant transaction storage (2026-10-14)

Added `src/azazel_nexus/bootstrap_grant_store.py`, a fixed-root descriptor-based
store under the existing `/var/lib/azazel/state/bootstrap/` directory. It uses
boot-UUID-derived names, exact canonical transaction bytes, private regular
single-link files, create-once publication, compare-and-swap advancement,
directory fsyncs, and a pending marker that forces fail-closed behavior after
an interrupted or durability-uncertain write. It performs no systemd operation
and is not an audit ledger. Tests exercise ordinary temporary directories only:
`tests/unit/test_bootstrap_grant_store.py` plus the state model tests passed
**19 tests**; target Ruff and `git diff --check` passed.

### Supervisor write-ahead integration (2026-10-14)

`BootstrapSupervisor` now consumes this store under its existing lifetime
lock. The default factory binds boot/context/approval/generation identity and
the fixed auditd/commissiond payload digests. It persists each transition
before the corresponding manager side effect: pair-grant intent before
`open_pair`, auditd start intent before its start job, audit receipt before
commissiond becomes startable, commissiond start intent before its job, and a
close intent before shutdown. The audit client now returns a typed append
receipt, and the supervisor verifies that auditd's live writer head exactly
matches the stopped-writer prestart evidence before using the writer. A
`bootstrap.stopping` audit event is an intent emitted while auditd is still
available; durable close evidence is committed only after containment
observations complete. On entry, it loads this boot's existing record under the
same lock. Any prior transaction is fenced/stopped/remasked and withdrawn only
by its durable grant identity, marked `recovery_required` unless already
terminal, then refused; it is never replayed or reset. An unreadable or
unfinished store marker also causes containment and refusal without inventing
an owner ID. Manual recovery remains required.

Synthetic supervisor tests use both an in-memory transaction store and the
real CAS file store in an ordinary private temporary directory. They cover
write-ahead ordering, receipt/live-head equality, fixed pair scope, failure
containment, terminal close state, and fresh-supervisor refusal for every
persisted transaction phase. They do not exercise a real D-Bus manager,
readiness producer, or Debian service process. The deployed
`BootstrapNarrowingManager` still hard-refuses pair opening, withdrawal, and
starts, and the production entrypoint does not compose a permissive adapter.
Accordingly, this is lifecycle/restart wiring, not runtime activation: the
writer/grant path remains disabled. Per-boot history is retained without
automatic garbage collection; bounded retention/export, independently reviewed
fencing, readiness, and production entrypoint composition remain open before
any deployment.

The admission adapter now also reads the fixed
`/etc/azazel/bootstrap/installed-files.json`, verifies its bytes against the
independently selected `unit_closure_digest`, and measures each selected
regular file before and after semantic admission. Missing, changed or
unmeasurable manifests refuse; no manifest is generated or trusted from the
installation itself. This is selected-file integrity only—not complete Python
import closure, unlisted-file absence, package authenticity, live loaded-unit
state, health, or a start grant. The operator must still provision a reviewed
manifest independently.

Local verification on this development host:

```text
PYTHONPATH=src:runtime/src .venv/bin/python -m pytest -q tests/unit/test_runtime_bootstrap.py tests/unit/test_bootstrap_grant_transaction.py tests/unit/test_bootstrap_grant_store.py tests/unit/test_runtime_auditd.py tests/unit/test_runtime_bootstrap_audit_client.py tests/unit/test_runtime_bootstrap_manager.py tests/unit/test_runtime_bootstrap_manager_loaded.py tests/unit/test_runtime_bootstrap_systemd_profile.py tests/unit/test_runtime_bootstrap_generation_admission.py tests/unit/test_runtime_bootstrap_installed_files.py tests/unit/test_packaging.py
265 passed
ruff check runtime/src/azazel_nexus_runtime/bootstrap.py runtime/src/azazel_nexus_runtime/bootstrap_manager.py runtime/src/azazel_nexus_runtime/bootstrap_audit_client.py runtime/src/azazel_nexus_runtime/auditd.py src/azazel_nexus/bootstrap_grant_transaction.py src/azazel_nexus/bootstrap_grant_store.py tests/unit/test_runtime_bootstrap.py tests/unit/test_bootstrap_grant_transaction.py tests/unit/test_bootstrap_grant_store.py tests/unit/test_runtime_auditd.py tests/unit/test_runtime_bootstrap_manager.py
All checks passed
git diff --check
passed
python3 tools/check_docs_links.py
54 Markdown files checked; internal links OK
```

The Ruff invocation covered `bootstrap.py`, `bootstrap_manager.py`,
`bootstrap_audit_client.py`, `auditd.py`, the grant transaction/store modules,
and their changed focused tests. No GitHub Actions, VM install, systemd/D-Bus
service start, or Debian Live verification was run.

Crash-boundary coverage also includes a simulated supervisor process loss
after a partial pair grant, followed by a fresh supervisor that contains and
withdraws only the recorded grant without replaying starts. Store tests inject
directory-fsync failures around transaction creation and all three advance
boundaries, then reopen the ordinary temporary directory and require either a
refusal marker or the durably published state. This is fault-injection evidence,
not power-loss or target-filesystem durability evidence. The installed-file
manifest wiring adds three fixed-path/no-fallback/reinspection tests and the
admission adapter tests now require the selected-file measurement on both
sides of semantic checking. Target Ruff, `git diff --check`, and the
54-Markdown link check passed after this increment. No CI, VM, service-manager,
or Debian Live test was run.

The same increment declares and installs the previously missing
`/etc/azazel/bootstrap` directory as `0700 root:root`, which the protected
deployment, approval and policy readers already require. The installer creates
only the empty directory; it does not create trust records, enroll keys, or
publish the selected-file manifest.

### Concrete refresh-input observation (2026-10-14)

`bootstrap_inputs.py` now has a fixed production refresh factory which composes
the protected declared-context reader, two matching dpkg package observations,
the pinned selected-file manifest measurement, an explicitly reviewed systemd
Manager profile, and the existing locally confirmed administrator time window.
Each source is re-read and compared before returning a context; no path, bus,
package adapter, environment override, key enrollment, or trust fallback is
accepted by this factory. Missing deployment/selection/policy, package pin,
manifest, reviewed profile, clock window, or approval still refuses.

This improves future-install portability through explicit adapter/profile
additions, not automatic OS discovery: a new Debian/systemd combination needs
a separately measured and reviewed package/systemd profile, and unsupported
systems remain refused. Package digests are identity measurements, not package
provenance. A follow-up change now binds the exact systemd profile digest
(profile name, version and ordered UnitPath) into required pre-start policy v3.
The deployment pins the policy digest, and the signed bootstrap context pins
the same digest; live profile mismatch therefore refuses, and merely adding a
profile cannot validate an older policy. Policy v2 is rejected, not migrated.
Changing the target profile therefore requires an explicitly measured new
profile digest, a newly approved v3 policy/deployment pin, and regenerated
selection/context/approval-bound bootstrap generation values; there is no
runtime auto-enrollment or legacy-policy upgrade path.
Manifest enrollment remains a separate provisioning action. Selected-file
checks and repeated reads do not establish complete executable closure or
eliminate changes after observation.

The factory is not wired to a production entrypoint and does not change the
manager's hard refusal for opening, withdrawing or starting the service pair.
It therefore cannot activate services. Local synthetic tests cover stable and
changing sources, package-pin mismatch, malformed values, and factory wiring;
no Debian VM, real systemd/D-Bus manager, service process, CI, or hardware test
was run for this increment.

The profile binding is covered by synthetic policy-version/digest tests and a
runtime observation test that rejects an otherwise reviewed systemd version
when it differs from the profile pinned by the protected policy. An operator
must explicitly measure the target's exact version and ordered UnitPath before
creating/pinning a v3 policy; runtime observation never enrolls the profile.

The fixed `protected_bootstrap_generation_admission()` factory now supplies
the supervisor's previously injection-only generation checker. On each
admission it checks the policy-pinned fixed bootstrap variant, re-reads the
systemd profile against the v3 policy, and requires the generation to remain
identical. Its wrapper independently measures the dpkg snapshot and every
manifest-selected file before and after that semantic check. This establishes
only the exact minimal uncommissioned tree/config contract plus those selected
measurements; it does not establish package provenance, full executable or
loaded-unit closure, helper readiness, audit continuity, safe systemd start
fencing, hostile-root resistance, or a start grant. The supervisor's separate
prestart/readiness checks and reviewed lifecycle backend remain mandatory.
An ordinary-file integration test now drives the real v3 policy decoder,
fixed-layout reader (redirected to a private temporary directory), generation
store verifier, selected-file manifest decoder/measurement, and admission
factory together. Its roots are synthetic temp trees; it does not exercise
root-owned `/etc` or `/var` deployment, D-Bus, or actual loaded unit bytes.

The combined policy/profile/context/provisioning/prestart/admission and
ordinary-file store integration regression set (including changed profile,
policy and generation refusals) passed **220 tests** on the macOS host. Target Ruff,
`git diff --check`, and the 54-file docs-link check passed. No real protected
host records, system bus, service operations, VM, or CI were used.

Verification on the macOS development host: the focused bootstrap-input,
installed-file, generation-admission, administrator-clock and packaging set
passed **85 tests** before the policy profile-binding increment. The expanded
policy/profile/context/provisioning/prestart set then passed **146 tests**.
Target Ruff passed, `git diff --check` passed, and the internal
documentation-link check passed for 54 Markdown files. A broader
`PYTHONPATH=src:runtime/src .venv/bin/python -m pytest -q tests/unit` run
reported **4,961 passed, 16 skipped, 63 failed, 26 errors**; it is not a clean
suite result. Reproduced environment causes include unavailable `dbus_next`
and YAML parsing dependencies, plus macOS temporary socket paths exceeding the
platform AF_UNIX address limit. This is unchanged from the pre-profile-binding
full run's 63 failures and 26 errors. No claim is made that the known causes
explain every failure; Linux CI or a Linux VM is still required to classify the
remainder. No CI was started.

Read-only inspection of the available Debian VM confirmed Debian's systemd
package `257.13-1~deb13u1` on `arm64` and `systemd-analyze unit-paths` matching
the reviewed 12-entry profile. The VM's four Nexus copies are clean at
`778d61b`, not the current dirty source tree; no pytest/Ruff executable or
project venv was found in the inspected paths, and `dbus_next` is unavailable
in system Python. No VM files or packages were changed, and the VM output is
not system-bus Manager-property evidence or test evidence for this source tree.

### Debian VM follow-up and boundary correction (2026-10-14)

For a Linux run without altering the VM's existing checkouts, the current
working tree was copied to `/tmp/nexus-bootstrap-review.3cmnP4`; a private
venv and pinned Ruff were created only inside that scratch copy. This did
modify temporary VM files, but no existing checkout, system package, device,
unit, or service. Read-only `SystemdBusSession` observation against the real
system bus returned `systemd-257.13-deb13-path-v1`, package version
`257.13-1~deb13u1`, and profile digest
`sha256:999a07245eb55a402ae0b74870a459764d410680d297019a464ad76fc22daf37`.
This is a live manager-property observation only; no unit was started or
changed.

The first full Linux run on the copied source reported **5,019 passed, 17
skipped, 30 failed, 2 warnings**. After the fixes below, a second run reported
**5,020 passed, 17 skipped, 29 failed, 2 warnings**. Neither run is a clean
suite or CI evidence. A focused rerun identified that the available `/tmp`
tmpfs had only 1,302,668 KiB available, below `model_import.py`'s fixed 2 GiB
headroom; 23 model import/acquisition tests and two operator-view tests
dependent on promoted models therefore correctly stopped before staging.
The first run also exposed two actionable source/test mismatches: the runtime
imported private `_bootstrap_directory` and `_read_file_at` library helpers,
and the payload-verb test omitted the implemented `audit.bootstrap.append`
contract. These were corrected without weakening the boundary: the library
now owns a fixed-path public `read_bootstrap_installed_manifest()` reader
which repeats protected-directory and exact-byte checks, while the runtime
uses only that public API. The test expectation now includes the bootstrap
audit verb.

After those corrections, the Linux focused regression command covering
prestart policy, generation store, runtime inputs/prestart, time provisioning,
systemd profile/context, installed-file measurement, provisioning, CLI,
protected admission, generation admission, systemd bus, and the public-name
boundary passed **210 tests**. Ruff 0.9.4 passed on the five Python files
changed in this correction; local `git diff --check` passed. The full Linux
suite still was not clean. The other four failures are attributable to the
scratch setup: two E2E harness tests and the mutation test require Git checkout
metadata, which was intentionally omitted; one reserve scan sees the
synthetic `measured.json` generated by the preceding E2E test in the disposable
scratch tree. Those fixture side-effects remained inside `/tmp` and did not
touch a repository checkout. No GitHub Actions, device, service operation,
installation, firmware, or hardware test was run.

### Physical-install extensibility and socket ACL correction (2026-10-14)

The existing systemd profile remains deliberately additive: the only measured
profile is Debian 13/systemd 257.13 with the exact ordered UnitPath observed on
the ARM64 VM. A future physical target can be supported by collecting and
reviewing its own OS/architecture, manager properties, package/selected-file
measurements, account and path ownership, filesystem behavior, and chosen
persistence arrangement. The generic Python/installer path is not an
architecture allowlist, but the HIL baseline remains independently governed;
no physical model or alternate distro is claimed supported by this change.

The first local socket ACL correction did not match `runtime_paths.socket_path()`
and added all daemon accounts to the shared operator group. An independent
review correctly rejected that implementation: daemons would still bind in
the wrong directory, and the group membership would broaden socket reachability.
Its **180 passing macOS tests and first Linux snapshot run are superseded and
must not be cited as validation of the corrected design**.

The follow-up correction routes each fixed daemon name to its installer-owned
leaf (`audit`, `commission`, `watchdog`) and no longer creates a missing socket
directory at runtime. The shared parent directories are root-owned `0711`
(traverse, no list/write); each daemon-owned leaf is `2710`, setgid, and grouped
to `azazel-operator`. Service accounts are not added to that group. A Linux
socket inherits the leaf's group; `serve_forever` requires that exact operator
GID and the existing `0660` mode/daemon owner before accepting. `SO_PEERGROUPS`
is used to identify ordinary operator users whose operator membership is
supplementary rather than primary. Known service UIDs are never classified as
operators, even if group data unexpectedly contains the operator GID. Platforms
without `SO_PEERGROUPS` fail closed for supplementary-group operator requests;
root and primary-GID classification remain available. The independent review
found these exact missing path and supplementary-identity cases; the corrected
version now has regression tests for both plus service isolation declarations.

Before this correction, a read-only Debian ARM64 VM probe created a unique
temporary setgid directory in an existing supplementary group, bound one Unix
socket, observed the socket inheriting the directory GID (`100`), and removed
the exact temporary paths in a `finally` block. This is useful kernel behavior
evidence only. The VM has no `azazel-operator` group or `/var/lib/azazel` tree;
the `systemd` executable is absent from PATH. The earlier 224-test Linux run
used the pre-review snapshot and did not test runtime path-to-leaf wiring or
supplementary operator identity; it is **not** evidence for the corrected
tree. No installation, unit operation, device, firmware change or HIL was
performed. The corrected Linux regression suite and the read-only VM service
flow remain outstanding.

The follow-up independent review found a second concrete write-permission
defect: watchdog used `ledger_dir()/watchdog.jsonl` and the shared state root,
while installer made that tree audit-owned/read-only to watchdog. The fix
creates root-owned traversal-only `/var/lib/azazel/state/` with private
service-owned leaves for the audit chain, auditd refusals, commissiond
refusals, and watchdog ledger/fences/refusals. The auditd refusal log is
separate from `state/audit/*.jsonl`, which `SegmentedLedger` treats as chain
segments. `azwatch` is no longer added to the `azaudit` group. Runtime paths
are fixed and do not create missing directories; installer/layout declarations
are tested against each other. Generated auditd, commissiond and watchdog
units now receive write access only to their own state leaves, and
commissiond's write scope includes its refusal directory.

The watchdog composition regression constructs the real handler with injected
filesystem paths and proves its ledger/fence paths and refusal sink all bind to
the watchdog leaf. `test_runtime_paths.py` verifies the service-specific refusal
directories and rejects undeclared names. The Linux service account/installer
integration itself has not run: the VM still has no Nexus account or state
tree, and no unit was installed or activated.

Final verification for this corrected socket and state-path implementation:

- On the Debian 13 ARM64 VM, a disposable source snapshot was tested with
  `PYTHONPATH=src:runtime/src <temporary-venv>/bin/python -m pytest` over
  `tests/unit/test_runtime_auditd.py`, `test_runtime_ready_cleanup.py`,
  `test_runtime_commissiond.py`, `test_runtime_watchdog.py`,
  `test_runtime_bootstrap_systemd_profile.py`,
  `test_runtime_bootstrap_manager.py`,
  `test_runtime_bootstrap_manager_loaded.py`, `test_packaging.py`,
  `test_runtime_hardening.py`, `test_runtime_transport.py`, and
  `test_runtime_paths.py`: **277 passed, 2 skipped**. Ruff 0.9.4 passed on
  the corresponding changed runtime/test files. The two skips are reported
  without inferring a cause.
- The focused macOS regression run for the affected transport, runtime-path,
  audit, watchdog, and installer tests reported **132 passed**. Target Ruff,
  the 54-file Markdown-link check, and `git diff --check` passed.
- A fresh attempt to rerun that mixed suite on macOS after recording the Linux
  result produced **134 passed, 2 skipped, 6 failed, 26 errors**. The failures
  are platform-specific test assumptions: macOS pytest temp paths exceeded
  Linux `sockaddr_un`'s 107-byte limit, and the installer mode assertion
  intentionally masks Linux setgid semantics on non-Linux. This is not a
  passing macOS suite and is not evidence against Linux behavior. Ruff,
  `tools/check_docs_links.py` (54 Markdown files), and `git diff --check`
  passed on the current tree.
- These are local checks, not GitHub Actions or Debian service-installation
  evidence. No Nexus accounts/state tree were installed in the VM; no unit was
  installed, started, or changed. No systemd sandbox execution, physical
  install, device, firmware, or HIL test was performed.

For future physical installations, add a platform profile only after measuring
that target's OS release, architecture, systemd version and ordered UnitPath,
package/file hashes, account and directory ownership, filesystem behavior,
and persistence layout. Keep shared Python policy/platform-neutral where
possible, and put OS-specific package/service integration behind explicit
profiles. An unmeasured target must remain unsupported/unknown rather than
falling through to a guessed default. The current profile remains only the
measured Debian 13/systemd 257.13 ARM64 VM; this does not establish physical
hardware or other-distribution support.

### Offline distribution and loaded-mask observation (2026-10-14)

The new install-profile helper was initially absent from the offline source
bundle's fixed input list. The builder now requires and includes it. A regression
builds the actual source bundle, extracts it into a temporary directory and runs
its profile resolver with `python -I -S` and synthetic Debian release data.
This checks the shipped import/data closure without installed project packages
or the checkout on Python's search path. It does not run the installer.

`BootstrapNarrowingManager.inspect_masked_pair()` now connects the read-only
`BootstrapMaskedPairInspector` through the existing owned system-bus session and
reviewed systemd-profile check. It inspects exactly auditd and commissiond, pins
the manager owner, rechecks Version/UnitPath against that same owner before and
after the pair snapshots, and requires two matching pair observations. Wrong identity,
aliases, unmasked state, pending daemon reload, malformed properties, owner
change and timeout refuse. Fragment paths are recorded rather than guessed from
the candidate grant. A masked but active helper is deliberately accepted as a
mask observation; this result proves neither stopping nor cgroup emptiness.

This observation is one prerequisite for the proposed closing transaction:
retain persistent masks, durably record ownership before replacing owned
volatile grant files with same-priority masks, reload and inspect the loaded
masks, drain exact-pair jobs while rechecking the fence, then stop and confirm
containment before withdrawing only owned volatile masks. This proposal still
requires journal transitions for partial replacement/withdrawal and uncertain
durability, a cgroup observation, and version-specific lifecycle validation.
The [systemd v257 unit documentation](https://github.com/systemd/systemd/blob/v257/man/systemd.unit.xml)
documents mask/load-path behavior; the [D-Bus API](https://github.com/systemd/systemd/blob/v257/man/org.freedesktop.systemd1.xml)
documents reload and observed properties. These references do not prove the
complete concurrent close/reload/drain sequence on the VM.

Current verification: the Mac runtime/manager/supervisor/bundle selection passed
**171 tests**. The same runtime selection, excluding the nine bundle tests,
passed **162 tests** on the existing Debian ARM64 VM interpreter. The four
new/modified runtime and integration-test file hashes matched across machines.
Target Ruff, diff check and internal document links passed. The VM test copy
was temporary and removed; no packages or host services were changed. Exact
commands and source hashes are in the
[local evidence record](evidence/bootstrap-mask-observation-2026-10-14.json).
These overlapping counts must not be added. Full suite and CI were not rerun.

Production `close_starts`, `open_pair` and `withdraw_pair` still refuse. No
deployment fence, installed bootstrap lifecycle, production activation or
hardware result is established by this increment. Issue #93 remains open.

### Owned empty-file close and recovery (2026-10-14)

`bootstrap_overlay_files._close_candidates_at()` now implements the file side
of closing an owned grant. It persists `closing` intent before writable opens,
then truncates only the same journal-owned, single-link, mode-0644 regular
inodes after checking their original digests. The persistent symlink masks are
left unchanged. Empty unit files are documented mask syntax in
[systemd v257](https://github.com/systemd/systemd/blob/v257/man/systemd.unit.xml).
This replaces the preceding proposed inode-replacing symlink step for the
current file experiment, avoiding a new-inode ownership handoff.

Recovery accepts original bytes or an empty file only on the retained inode
while the journal is `closing`. It does not adopt a replacement by digest or
emptiness. A visible closing record is durably re-published before recovery
mutates anything, because an earlier journal rename may have succeeded while
its directory fsync failed. Rechecking an already-empty candidate does not
truncate again or change its timestamps. Failures retain ownership and report
uncertainty; they never mark the journal `closed` or claim a loaded fence.

The journal can now retain closing intent after zero or one recorded file as
well as complete publication. The file adapter requires every unowned pair
path to be absent, so interruption between file creation and its ownership
record remains ambiguous and refuses. Protected descriptors and the held
controller lock are prerequisites; arbitrary privileged mutation and malicious
inode reuse are outside this local file-transaction threat model.

Tests cover partial publication, durable ordering, mixed original/empty
recovery after truncate/fsync failures, uncertain journal visibility,
idempotence, wrong/replaced/hardlinked/symlinked files, changed persistent
masks and higher-priority/drop-in conflicts introduced after closing intent.
Independent review's suspected missing repeated conflict check was retracted
after source inspection; dynamic injection tests confirm that check occurs.

The final related journal/publisher/close/supervisor/manager/mask selection
passed **250 tests with one Linux-only skip on macOS**, and **251 tests on
Debian ARM64**. The latter includes `systemd-analyze 257.13-1~deb13u1` offline
inspection of the actual emptied files beneath a temporary root, with
generators disabled and `SYSTEMD_UNIT_PATH=/system.control`; the existing
persistent masks are deliberately excluded from the analyzer search path.
Both fixed units produced a masked diagnostic. This is offline parsing evidence,
not a live reload, job-fence, stop, cgroup, reboot or installed-lifecycle result.
Four code/test hashes matched the VM copy; target Ruff, diff and 54-document
links passed. Commands and hashes are in the
[local closing evidence](evidence/bootstrap-overlay-close-2026-10-14.json).

Next integration is the same-owner reload/effective-mask/job-drain sequence,
then positive process/cgroup containment and journaled withdrawal. This file
primitive has no production path opener; production manager widening and the
full entrypoint connection remain incomplete. No live manager operation,
installation, provider/fetch/Edge activation, CI or hardware work occurred.

### Cross-operation systemd owner binding (2026-10-14)

Read-only independent review found that masked inspection and job draining
each pinned their own manager, but did not carry an enclosing transaction's
identity between operations. Both adapters and their narrowing-manager entry
points now accept a trusted `expected_owner` pin. Invalid pins are refused
before connection; a different observed owner is refused before unit inspection
or job listing/cancellation. Omitting the pin preserves standalone observations,
not permission to treat them as a connected fence. This is not authorization,
file provenance, or protection against arbitrary privileged process mutation.

The new owner-binding test module contains 61 synthetic tests. Main-agent
verification of it plus masked, drain, stop, manager and manager-mask tests:

```sh
PYTHONPATH=.:src:runtime/src .venv/bin/python -m pytest -q \
  tests/unit/test_runtime_bootstrap_owner_binding.py \
  tests/unit/test_runtime_bootstrap_masked.py \
  tests/unit/test_runtime_bootstrap_job_drain.py \
  tests/unit/test_runtime_bootstrap_stop.py \
  tests/unit/test_runtime_bootstrap_manager.py \
  tests/unit/test_runtime_bootstrap_manager_masked.py
```

Result: **209 passed** on macOS. Target Ruff for these four runtime modules
(`bootstrap_stop`, `bootstrap_masked`, `bootstrap_job_drain`,
`bootstrap_manager`) and the new test module passed; `git diff --check` passed.

A broader diagnostic run of `PYTHONPATH=.:src:runtime/src .venv/bin/python
-m pytest -q tests/unit` was **5078 passed, 75 failed, 19 skipped, 26 errors**.
One confirmed cause was the long default macOS temporary path exceeding UNIX
socket limits. Repeating with `TMPDIR=/tmp` after the new tests were complete
yielded **5153 passed, 62 failed, 19 skipped, 23 warnings**. These counts overlap
and are not additive. Remaining failures include Linux-only `/proc`,
`SO_PEERCRED`, `/etc/os-release` and device-number assumptions, and missing
`yaml` / `dbus_next` modules in this local venv (both dependencies are already
declared in `runtime/pyproject.toml`). This is not a green full-suite result,
nor proof that every failure is environmental; Linux validation and individual
failure resolution remain required. No dependencies were installed.

The review also confirmed unresolved composition: journal-owned file identity
must be bound to loaded fragments, and close/reload/mask/drain must form one
same-owner operation before stopping, checking cgroups and withdrawing grants.
Production `close_starts` still refuses. No live systemd operation, VM test,
CI, hardware operation, commit or push was performed in this increment.

### Connected close/reload/drain increment (2026-10-14)

`BootstrapCloseSequence` now connects owned-file closure to a pinned-owner
Manager.Reload, repeated loaded-mask checks and exact-pair job draining on one
owned bus session. `BootstrapClosedOverlayFiles` binds independently supplied
directory paths to retained descriptors and rechecks the held controller lock,
journal, empty owned inodes, unowned-path absence and persistent masks. Loaded
fragment paths must match this independently observed closure. It does not learn
expected paths from D-Bus. Profile/owner drift, reload error, wrong fragments,
file changes, timeout or a non-quiescing queue refuse without withdrawing the
retained closing journal. Widening remains refused.

`BootstrapNarrowingManager.close_starts()` uses this sequence only when trusted
composition supplies the exact file-backend type; the default still refuses.
There is no production directory opener or production entrypoint connection.
Tests now exercise that manager method with the real journal/file backend and
a synthetic systemd bus, rather than replacing the refusal with an unconditional
success. No stopped-helper or empty-cgroup guarantee is inferred.

The systemd v257 [Reload implementation](https://github.com/systemd/systemd/blob/v257/src/core/dbus-manager.c)
defers its method reply until reload completes. The adapter additionally checks
loaded masks and `NeedDaemonReload`, and does not treat the reply alone as a
fence. Installed lifecycle behavior, including fragment spelling for persistent
symlink masks and partial publication recovery, remains to be measured.

Independent review identified a remaining deployment limitation: synchronous
filesystem operations such as fsync cannot be preempted by the async bus
deadline. The deadline rejects overdue results and a regression test confirms
that slow closure does not proceed to Reload, but wall-clock return latency is
not bounded. No abandoned worker thread was introduced that could mutate files
after timeout. An independently supervised controller lifetime remains required
before production admission; the existing signal-event adapter alone is not
that guarantee. This limitation is unresolved, not a completed safety gate.

Local related tests (close sequence/files, overlay close/publication, masked
observer, manager/manager-mask, job drain, owner binding, stop, supervisor and
overlay journal) passed **407 tests with one Linux-only skip**. Target Ruff,
diff check and document links are recorded separately from full Linux testing.
No hardware, provider/fetch/Edge activation, CI, commit or push is implied.

Final Debian ARM64 full-unit validation completed on 2026-10-15:
**5552 passed, 3 skipped, 2 warnings** (Python 3.13 fork warnings in the
deadline-crash tests). Eight changed source/test hashes matched the local tree.
This used the existing interpreter, a disposable source copy with a synthetic
Git snapshot for Git-dependent tests, and a separate test root on the home
filesystem with sufficient free space. No upstream commit was made; both
temporary trees were removed. The first diagnostic run was interrupted after
observing a FIFO wait with test fixtures nested in the source tree. A second
run exposed absent Git metadata, tmpfs below the model-import headroom, and a
real harness comparison bug. The latter now uses `stat.S_IMODE` so declared
setgid directory bits are checked rather than discarded; installer modes were
not relaxed. Earlier failed/partial runs remain recorded and are not counted
as successful runs.

Target Ruff passed except the separately inspected `tools/e2e_stages.py`,
which retains one pre-existing F401 unused local `_Path` import already in
HEAD. No unrelated lint cleanup was made. Full repository lint was not rerun.
Commands, hashes, diagnostic outcomes and unresolved gates are in the
[close-sequence evidence](evidence/bootstrap-close-sequence-2026-10-15.json).
Synthetic unit success does not establish installed systemd lifecycle; #93
remains open.

### Connected stopped-pair observation (2026-10-15)

`BootstrapNarrowingManager.stop_closed_pair()` now connects the owned-file
close/reload/drain sequence, reverse-order stop jobs, and repeated inactive,
zero-MainPID/ControlPID and cgroup observations on one dedicated connection.
The stop client carries the enclosing unique-owner pin; an owner mismatch is
refused before subscription or StopUnit. The fence and owned files are
revalidated around stops and observations. No grant is withdrawn here.

The supported cgroup paths are fixed to the two helpers under `system.slice`;
observed D-Bus values never select arbitrary filesystem paths. The reader
walks a trusted descriptor with no-follow directory opens, bounded nonblocking
event reads, regular-file/ownership checks and repeated identity checks. It
accepts `populated 0` only, or absence of the final leaf beneath an existing
protected parent. An absent intermediate directory is not success. A cleared
systemd ControlGroup is accepted only with an absent expected leaf. Parent
identity is retained for absence and cgroup inode identity for emptiness, so
the repeated snapshots reject identity changes. The Linux
[cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#un-populated-notification)
defines populated as covering the subtree, not just its immediate processes.

An independent review found that invalid root descriptors/UIDs were detected
too late. They are now checked before opening the bus or closing files, and
the manager holds a validated duplicate through teardown. Tests verify that
invalid input leaves the original owned unit files unchanged and opens no bus.

The root descriptor's host cgroup-v2 mount identity and no-process-escape unit
hardening must still be independently admitted by production composition.
Ordinary-file tests do not establish those properties; absence is not evidence
that a process could never have migrated elsewhere. Filesystem IO remains
non-preemptible by the bus budget. No production cgroup opener is installed.
The supervisor's existing containment evidence/withdrawal path has not yet
been upgraded to consume this richer observation; that integration and owned
withdrawal remain required before claiming completed containment.

The related Mac selection passed **451 tests with one Linux-only skip**;
the same selection on the existing Debian ARM64 VM passed **452 tests**.
Eight source/test hashes matched. Target Ruff and diff check passed. These
overlapping results are not additive; the preceding 5552-test full-suite result
belongs to the preceding source snapshot and was not rerun for this increment.
No live systemd/cgroup operation, installation, CI, hardware, commit or push
occurred. The VM copy and fixture trees were disposable and removed.
Commands, file hashes and remaining gates are recorded in the
[stopped-pair evidence](evidence/bootstrap-stopped-pair-2026-10-15.json).

### Supervisor empty-pair gate (2026-10-15)

The supervisor now requires `confirm_empty_pair()` after stop/inactive checks
and before owned withdrawal, and repeats the check before returning successful
containment. Exceptions, absent implementations and non-None returns refuse.
A pre-withdrawal failure retains the owned grant; a final failure cannot return
a successful containment digest. The private containment record is explicitly
versioned to `azazel-nexus/bootstrap-containment-evidence/v2` and adds the fixed
`cgroup_empty_pair` field. An exact canonical-digest regression covers it.

The narrowing manager implements that gate using fresh stopped/PID/cgroup and
loaded-mask observations, not a previous success flag. A close result carries
only the expected owner/fragment identity; the current manager and owned files
are re-observed. Stops following a close also carry its unique-owner pin.
The optional cgroup root descriptor is explicitly borrowed for the manager's
lifetime: composition must keep it open/unreused, while each confirmation
validates its pinned identity and owns a duplicate through session teardown.
The manager never closes or automatically reopens the borrowed original.
Independent review's missing descriptor-lifetime contract was resolved by this
explicit contract and an early-close refusal regression.

The selected supervisor, gate, manager, stopped/cgroup, stop, close and grant
store/transaction tests passed **265 on Mac and 265 on Debian ARM64**. Four
source/test hashes matched; target Ruff and diff check passed. The Linux run
used the existing interpreter, private source/fixture trees and synthetic bus
and regular-file data only. No full-suite or CI rerun is claimed. Prior full
suite evidence remains tied to its earlier source hashes.

This supersedes the pending supervisor-gate item above, not the entire pending
containment integration: actual owned withdrawal, post-withdrawal restored-mask
revalidation, production root/mount admission, controller lifetime and the
production composition root remain incomplete. `withdraw_pair()` and widening
still refuse; no production source was substituted with a permissive default.

### Recoverable owned-mask withdrawal file phase (2026-10-15)

The private overlay journal now distinguishes `closing` from `withdrawing`.
`begin-withdrawal` retains all original ownership records and must be durably
published before any unlink. Final `withdraw` requires `withdrawing` plus the
existing typed final evidence; direct closing-to-closed transition refuses.
The canonical private journal codec retains the new phase with zero, one or two
owned files. This phase is intent, not evidence of restored loaded masks.

`bootstrap_withdraw_files._withdraw_candidates_at()` removes only recorded,
same-inode empty masks. Before intent, missing owned files refuse; after durable
intent, recovery permits recorded files already absent while verifying every
remaining inode. Recovery re-publishes/fsyncs the retained intent before any
further unlink, including when an earlier publication was visible but its
durability uncertain. Directory fsync and fresh containment/path checks surround
removal. All owned identities remain recorded until independent finalization.
Unowned, replaced, nonempty or ambiguous entries are not deleted.

The file primitive checks the persistent `/dev/null` masks and the reviewed
pre-persistent-mask precedence directories: etc system.control, the owned run
system.control overlay, transient and generator.early. Competing exact units
and checked unit drop-ins refuse, and aliased directory descriptors refuse.
These are injected protected descriptors, not a production path opener: their
canonical installed locations and the absence of optional directories still
need binding in composition. The required `check_contained` callback has no
permissive default; it is a trusted, synchronous, phase-aware revalidator, not
a cached success boolean. The existing closing-only observer cannot simply be
reused after an unlink. A file-phase success returns `withdrawing`, not `closed`.

Independent review's proposed lower-priority/prefix drop-in mask bypass was
retracted after checking pinned systemd v257
[fragment loading](https://github.com/systemd/systemd/blob/v257/src/core/load-fragment.c)
and [drop-in loading](https://github.com/systemd/systemd/blob/v257/src/core/unit.c):
parsing drop-ins does not turn a selected null/empty masked unit into a loaded
unit. Admission of drop-ins for a published nonempty unit remains a separate
closure requirement; this was not treated as proof of that admission.

Tests include a second-unlink failure with one file gone and one retained,
directory fsync failure, uncertain visible journal publication and failed
reaffirmation, descriptor aliasing, containment refusal, replacement inode,
missing-before-intent refusal and a competitor appearing after durable intent.
The related selection passed **309 on Mac with one Linux-only skip**, and
**310 on Debian ARM64**. Four source/test hashes matched, target Ruff and diff
check passed. No full-suite/CI or live manager operation occurred. The remaining
integration must re-observe the pinned manager and stopped/cgroup state,
reload and verify restored effective masks, then finalize the owned journal;
`BootstrapNarrowingManager.withdraw_pair()` still refuses until that exists.

### Post-unlink restoration integration (2026-10-15, local worktree)

`BootstrapRestoredOverlayFiles` separately observes the post-unlink phase:
retained withdrawing/closed journal, held guard, descriptor/path bindings,
persistent masks, precedence-directory exclusion and absent overlay entries.
It never infers loaded systemd state from file absence. Finalization persists
the closed journal only with typed restoration evidence; a visible closed
record is re-published to reaffirm durability during recovery, not deleted.

`BootstrapRestoreSequence` connects those observations to a single pinned
systemd owner: reload, repeated exact persistent-fragment mask observation,
guarded job drain, reverse-order stops, inactive/PID/cgroup-empty observations,
journal completion, and fresh final observations. A changed owner, fragment,
profile or populated cgroup refuses. The private component does not authorize
grant removal, open production directories, unlink files or start services.
Dedicated-session cleanup and borrowed descriptor lifetimes remain caller
obligations; synchronous filesystem IO still needs external supervision.

This does not yet make `withdraw_pair()` operational. Grant-to-journal intent
binding, phase-aware pre-unlink containment, production directory/mount
admission, post-withdraw manager state replacement and the installed runtime
composition root remain required. Supporting helpers were not installed in the
last read-only VM observation (both units were `not-found`); observing an
existing distro mask's FragmentPath does not validate this service lifecycle.

The selected six test files passed **138 on Mac and 138 on Debian ARM64**,
including 18 new restoration tests. Five source/test hashes matched. Target
Ruff, diff check and 54-document link check passed. One initial integration
fixture omitted inactive state and correctly refused; the fixture was fixed,
not the runtime refusal. Evidence and exact commands are in
[the restoration record](evidence/bootstrap-restore-2026-10-15.json).
The temporary VM source/fixture directories were removed. No full-suite, CI or
live service lifecycle result is claimed. Astra's bounded static sequence review
and Luna's file-contract review found no blocking issue under the stated
injected-component assumptions; neither establishes production readiness.

### Manager-owned withdrawal connection (2026-10-15, local worktree)

The explicitly injected `BootstrapWithdrawalFiles` binds retained overlay
ownership to the exact grant transaction's boot ID, context digest, grant ID,
and ordered unit payload digests before mutation or a withdrawal bus operation.
Approval/generation authorization remains the supervisor's obligation; this
selector cannot create a grant. Unknown, changed or missing ownership refuses.

`BootstrapNarrowingManager.withdraw_pair()` now connects this backend to fresh
phase-aware observations before and after each owned removal. Each checkpoint
owns and tears down its dedicated bus session, reloads against the original
owner, checks the supported manager profile and the current mixed overlay/
persistent fragment paths, drains pair jobs, and observes inactive/PID/cgroup
emptiness. Final restoration uses the connected restoration sequence and then
replaces the manager's containment observer with the persistent-mask backend.
The supervisor's final `confirm_empty_pair()` therefore rechecks restored masks,
not stale pre-unlink files. No grant record or overlay journal is deleted here.

Static review found and prompted correction of a recovery integration gap:
ordinary close refused withdrawing/closed records, so the manager could not
recover after partial unlink or finalization. `close_starts()` can now observe
that retained narrowing state without unlinking or adopting unknown files.
Actual removal still requires explicit matching `bind(transaction)`; merely
resuming the closed fence never selects a grant for removal. Early binding and
descriptor errors invalidate cached observation and normalize refusal, too.

This supersedes the earlier unconditional-withdrawal-refusal statements only
for explicitly composed, held-descriptor backends. Default construction still
refuses; production path/cgroup admission, externally supervised lifetime,
grant publication/start wiring and installed runtime composition remain open.
No live service, provider, fetch, Edge activation or hardware operation is
authorized by these private testable seams.

Validation on this source snapshot: Mac selected tests **280 passed**;
Debian ARM64 full `tests/unit` **5674 passed / 3 skipped / 2 warnings** in
45.08 seconds. The warnings are multiprocessing fork DeprecationWarnings in
the crash tests, not service lifecycle observations. Four changed source/test
hashes matched. Target Ruff, diff and 54-document link checks passed. Tests
include first-unlink owner drift, fresh-manager recovery, closed-journal repeat
containment, mismatched grants, missing backend and explicit-selection refusal.
Exact commands and hashes are recorded in
[manager withdrawal evidence](evidence/bootstrap-manager-withdrawal-2026-10-15.json).
The VM used only synthetic bus data and ordinary-file fixtures; its temporary
source snapshot (including a test-only Git identity) and fixtures were removed.
No source-branch commit/push, CI or live systemd service operation occurred.

### Fixed cgroup mount admission (2026-10-15, local worktree)

`open_bootstrap_cgroup_mount()` is a read-only, fixed-path context owner. It
traverses `/sys/fs/cgroup` without following directory symlinks, verifies root
ownership/modes and cgroup2 filesystem type, then correlates kernel procfs
mountinfo with the held descriptor's mount ID, inode and device. It rejects
subtree roots, ambiguous fixed-path mounts, and nested mounts under that root.
Read-only mount options are accepted: the controller's filesystem protections
must not be relaxed just to read cgroup state. The small libc fstatfs boundary
is gated to Linux LP64 amd64/arm64; other ABIs refuse rather than guessing.

Namespace comparison opens kernel-provided namespace descriptors through procfs
directories and requires nsfs targets; matching ordinary symlink text is not
accepted. It compares the current process and PID 1 cgroup namespace identities.
This is not authentication of PID 1 as the selected D-Bus manager, nor proof of
unit no-escape hardening, host identity outside a container, or hardware state.
Kernel interface references: [mountinfo and fdinfo](https://www.kernel.org/doc/html/latest/filesystems/proc.html),
[Linux statfs leading field](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/statfs.h).

The narrowing manager can borrow the context-owned `cgroup_mount` instead of
raw descriptors, rechecking it around awaited containment observations and
during restoration. An explicit standalone stop duplicates the admitted
descriptor, not an alternate same-inode mount alias supplied by a caller.
Context closure or identity drift refuses. Synthetic descriptor seams remain
available for ordinary-file tests; production composition must select the
admitted context and cannot treat those fixtures as mount admission.

The unprivileged SSH probe opened the real cgroup2 root and read mountinfo and
fdinfo successfully, but access to PID 1's namespace failed with EACCES. Full
opener success is therefore **unverified** in the target service context.
Passwordless sudo was unavailable; no password was supplied and no privilege,
mount, namespace or service configuration was changed. This denial was not
converted into a skipped check or a permissive fallback.

Final selected tests passed **234 on Mac and 234 on Debian ARM64**. Six changed
source/test hashes matched; target Ruff, diff check and 54-document links
passed. Tests include namespace-source spoof rejection, context cleanup,
post-close use refusal, malformed/ambiguous mount metadata and mount drift
during the final D-Bus reply. Astra identified three issues (mount alias
traversal, missing closing rechecks, and namespace symlink-text trust); all were
fixed and re-reviewed. A preliminary agent report incorrectly treated one
namespace-link output as two matching outputs; that report is retracted, and
the main agent's direct EACCES observation is authoritative.

The final VM read-only probe additionally confirmed genuine procfs/fdinfo
binding and the self namespace's nsfs type. PID 1 namespace comparison and
full admission still refuse under the SSH account. No full-suite rerun for
this increment is claimed; the previous 5674-test result belongs to its earlier
source snapshot. Commands, hashes and these limits are recorded in
[cgroup mount evidence](evidence/bootstrap-cgroup-mount-2026-10-15.json).

### Fixed system-bus manager identity (2026-10-15, local worktree)

Production `SystemdBusSession.connect()` now uses the explicit local address
`unix:path=/run/dbus/system_bus_socket`, not an environment-selected system bus.
Before returning a usable session it resolves the fixed systemd name and asks
the bus daemon for that unique connection's Unix PID and UID. Exact PID 1 and
UID 0, typed replies from the daemon, and owner continuity are required. See
the primary [D-Bus credential API specification](https://dbus.freedesktop.org/doc/dbus-specification.html#bus-messages-get-connection-unix-process-id).
No credentials are accepted from the service itself; unavailable credentials
or timeouts refuse and tear down the owned connection/loop.

The admitted unique owner is retained on the production transport. Every
bootstrap inspector's shared owner reader checks that pin, including readers
which formerly learned their initial owner independently. Generic fixed
manager calls target the admitted unique name and reject replies from another
sender. Private synthetic construction remains a test seam, not production
bus admission. These checks do not authenticate the OS/systemd binary or prove
host identity outside a container; cross-PID-namespace deployments require
separate admission before correlating PID numbers with namespace observations.

The existing Debian ARM64 VM accepted the new read-only connection path and
returned UID 0/PID 1 plus the reviewed `systemd-257.13-deb13-path-v1` profile.
No Mask/Unmask/Start/Stop/Reload call was made. This does not resolve the SSH
account's PID 1 namespace EACCES, validate the installed hardened service
context, or make runtime composition complete.

Review found that pinned dbus-next 0.2.3 performs a synchronous Unix connect
inside its constructor, before the asynchronous connection timeout begins.
The private `FixedSystemBusSocket` mixin now applies a per-socket timeout before
that call, admits only the fixed filesystem socket, then switches it to
nonblocking mode for dbus-next. Partial constructor failures close stream/socket
resources. It does not change process-global socket defaults or use a worker
thread. The exact dependency version is checked before construction because
the override uses that pinned library's private socket-setup seam. Reference:
[pinned dbus-next socket setup](https://github.com/altdesktop/python-dbus-next/blob/v0.2.3/dbus_next/message_bus.py).
The final adapter also passed the read-only VM identity/profile probe. Overall
controller lifetime and non-preemptible filesystem operations remain separate
deployment obligations; per-operation timeouts are not a whole-lifecycle proof.

The pinned library's disconnect initiates shutdown rather than closing both
Python socket/file references synchronously. The owned session now explicitly
closes those references after loop teardown, including admission failures;
the final read-only VM probe confirmed stream, socket and loop closed without
waiting for garbage collection. This is relevant to repeated withdrawal fence
observations, each of which owns a separate short-lived bus session.

Final verification: Mac selected tests **305 passed**; Debian ARM64 full
`tests/unit` **5764 passed / 3 skipped / 2 warnings** (existing fork
DeprecationWarnings). Eight changed source/test hashes matched. Target Ruff,
diff and 54-document links passed. The first full run had one test failure
because Linux returned EAGAIN on a full temporary Unix listen queue; the test
now covers that immediate refusal as well as timeout/connection refusal, and
checks the configured timeout and closed descriptor. No permissive connection
fallback was added. The real bus was not stopped or filled; only temporary
test sockets were used for saturation. Commands, failed-run context, final
hashes and read-only probe code are in
[manager identity evidence](evidence/bootstrap-manager-identity-2026-10-15.json).
No CI or installed lifecycle success is claimed; the namespace access and
remaining production-composition conditions above are still open.

### Current startup order and cross-session start identity (2026-10-15)

The historical "Audit startup-order review" section above describes an older
supervisor. It is not a current instruction to move auditd outside the approved
pair. The present `_supervise()` persists the grant intent, opens the pair,
persists `pair_grant_opened`, releases controller READY, persists
`auditd_start_intent`, and only then starts auditd. After checking its live head
against the stopped-writer head, it appends the historical controller/grant
events through auditd. Commissiond remains gated on the grant append receipt.
The crash-recovery journal is not an audit ledger. This ordering already exists;
it must not be redesigned as if the old socket-availability cycle still existed.

The private `BootstrapStartJobs` adapter now requires the enclosing grant's
systemd unique-owner pin. A fresh bus connection's PID/UID admission alone
does not transfer a previous manager's grant observations to a new owner.
The existing job observer checks the supplied pin before subscribing or sending
StartUnit; mismatch poisons that observer and refuses retry. The fixed start
guard, pair scope, deadlines and cleanup requirements remain unchanged.
No production factory or permissive start guard was added. `open_pair`, actual
readiness admission, overlay directory lifecycle/hardening, and the installed
entrypoint composition are still required before this can start services.

Initial local verification command:
`PYTHONPATH=.:src:runtime/src .venv/bin/python -m pytest -q tests/unit/test_runtime_bootstrap_start.py tests/unit/test_runtime_bootstrap_stop.py tests/unit/test_runtime_bootstrap_owner_binding.py`
passed **161 tests** using fake buses. Target Ruff and `git diff --check` passed.
This is not a Linux/systemd lifecycle or CI result; no VM service was operated.

Luna added supervisor boundary tests; coordinator review also extended the
ordinary-file journal reload to the commissiond start boundary. Failed
`pair_grant_opened` and `auditd_start_intent` advances prevent the respective
notification/start and contain the pair. The final six-file test selection
passed **265 tests**, with target Ruff and diff checks passing. Exact commands,
source hashes and unverified scopes are in
[start-owner evidence](evidence/bootstrap-start-owner-2026-10-15.json).
These ordinary-file tests demonstrate the observed store ordering, not
power-loss durability or installed service operation.

Astra's independent bounded review confirmed the old audit/socket cycle is
resolved, but found two distinct defects. Both are now corrected: the historical
grant event and its receipt are recorded before the later controller-ready
event (preserving chronological daily segments), and commissioning rechecks
admission/deadline, auditd readiness and cancellation after its durable start
intent write. Luna added backward-day refusal in `SegmentedLedger.append`
before any write; coordinator reviewed the integration. Same-day earlier
timestamps remain allowed. Midnight-crossing supervisor events are exercised
against a real ordinary-file ledger and verified with `ledger.verify()`;
restart/backward-day refusal leaves files and heads unchanged. Four synthetic
fault cases cover expiry, cancellation, lost readiness and withdrawn admission
during the commissioning intent write. Final expanded local selection:
**335 passed**, target Ruff and diff checks passed. This supersedes the
265-test intermediate result and updates the evidence hashes above. No live
services or CI were exercised, and production composition remains incomplete.

### Fixed overlay directory ownership and narrowing composition (2026-10-15)

`open_bootstrap_overlay_directories()` now owns no-follow, root-owned fixed-path
handles for the reviewed five systemd search locations. Overlay and persistent
mask directories remain mandatory; only the final leaves of the higher-priority
control, transient and generator.early directories may be absent. Absence is
represented by a retained parent-chain/path witness, not an invented fd or an
empty substitute directory. Any observed appearance, unsafe mode/owner, symlink,
or named-chain replacement refuses. No directories are created.

Present handles validate all five retained observations when used as a dir-fd
or `fileno()` (including fsync). Thus the checks also run inside existing file
mutation checkpoints rather than only at adapter entry. The three higher-priority
locations reject pair files/drop-ins even when partial close falls back to
persistent masks. Withdrawal and restoration retain the original observations;
they do not reopen and accept a new baseline. Shared absent parents are allowed;
existing present-leaf alias rejection remains in withdrawal, not the opener.
Repeated checks do not prove exclusion of arbitrary privileged concurrent
changes or an appearance/disappearance between observations.

`bootstrap_narrowing_manager_in_transaction()` composes fixed directory handles,
the protected overlay journal and admitted cgroup mount under the existing
supervisor lock. It owns their lifetimes through cleanup, without a second lock,
service control call, directory creation or start authority. Earlier primitive
module comments saying there is no production opener describe the original
descriptor-only stage; this context is now the fixed narrowing opener. It is
not yet installed into `activated.main` and does not enable widening.

Astra reviewed the bounded directory design/implementation; Luna added traversal
tests; coordinator added all eight presence combinations and real ordinary-file
publication/close/withdraw/restore observations. Appearance after a journal intent
refuses before the next file mutation. Synthetic context tests cover cleanup
after store/mount/manager/body failure. Final results: **Mac 212 passed / 1
skipped; Debian ARM64 213 passed**. Nine source/test hashes matched. Target Ruff
and diff checks passed. The first Linux run (194 passed / 19 failed) exposed
group-writable intermediate fixture directories under its umask; fixtures now
set protected modes explicitly, without weakening runtime checks. An initial
local integration failure exposed fsync's need for `fileno()`; the validated
method was added and retested. Commands and hashes are in
[directory-path evidence](evidence/bootstrap-directory-paths-2026-10-15.json).
Temporary VM source and fixture trees were removed. No real systemd directory,
service, device or firmware was mutated; this is not installed-lifecycle proof.

Remaining composition work: provision the mandatory volatile overlay with
explicit installation/lifetime responsibility and service write permissions;
define initial protected overlay-journal state without inventing ownership;
complete no-escape/lifetime admission, publication/start/readiness backend and
the actual activated entrypoint. The PID1 namespace/service-context gate remains
unverified. No provider/fetch/Edge activation or CI was performed.

### Initial persistent-mask baseline without invented ownership (2026-10-15)

`OverlayJournalStore.load_optional()` now returns None only for confirmed
absence of the fixed journal filename in the validated protected store. It
does not catch generic refusal as absence: malformed bytes, symlinks, FIFO,
unsafe metadata, permission/IO failures, unexpected entries and a closed store
still refuse. Strict `load()` is unchanged. No file is created by observation.

`BootstrapClosedOverlayFiles` has an explicit initial observational mode:
journal remains absent, persistent exact masks retain their stamps, overlay pair
entries/drop-ins remain absent, and the held guard/path bindings are rechecked.
Production grouped wrappers retain all five path/competitor checks. The mode
returns persistent fragment paths to the existing close/reload/loaded-mask/drain
sequence, without claiming ownership or writing a journal. An existing owned
closure cannot fall back when its journal disappears. `resume_closure()` skips
journal recovery only for genuine absence before any selected withdrawal
intent; binding and actual withdrawal still require retained ownership.

This resolves the initial narrowing dependency without manufacturing a grant.
Astra reviewed this explicit-mode variant and found no concrete safety defect
within the existing directory/lock assumptions; a separate closure class was
not needed. Luna implemented store refusal regressions and coordinator added
real ordinary-file initial closure plus fake-systemd manager integration.
Final local selection: **165 passed**, target Ruff and diff checks passed.
Commands, five hashes and limitations are in
[initial-baseline evidence](evidence/bootstrap-initial-baseline-2026-10-15.json).
No Linux rerun/full suite, CI or installed-service operation occurred in this
increment. The supervisor's separate stop/cgroup-empty requirements remain;
absence is not proof of no historical journal and cannot authorize widening.

Deployment research located a possible next provisioning mechanism: a narrowly
scoped vendor tmpfiles rule for the mandatory volatile overlay, with explicit
controller write permissions. A plain `d` rule with ordinary mode/owner fields
would also adjust an existing directory. The systemd v257 documentation permits
colon-prefixed mode/user/group to apply those attributes only on creation,
and an omitted cleanup age avoids automatic cleanup. This distinction must be
preserved in a reviewed deployment implementation; it is not yet implemented
or installed. Source: [systemd v257 tmpfiles.d](https://raw.githubusercontent.com/systemd/systemd/v257/man/tmpfiles.d.xml).
Existing unsafe directories must continue to fail runtime admission, not be
silently repaired. Production grant publication/start/readiness and actual
activated entrypoint composition remain open.

### Volatile overlay packaging and scoped write policy (2026-10-15)

The vendor rule `packaging/tmpfiles.d/azazel-nexus-bootstrap.conf` now declares
the mandatory volatile directory with create-only mode/UID/GID attributes and
no cleanup age or removal operation. Installer staging copies the rule without
invoking tmpfiles; the real service-manager stage invokes its fixed basename
after masking all governed units and before enabling the controller. The
basename respects same-name administrator overrides rather than bypassing
them with an absolute configuration path. The install profile declares
systemd-tmpfiles as a service-manager tool, not a staging prerequisite. The
offline source bundle includes the required rule and its measured bytes.

The hardening declaration and generated activated unit now permit precisely
`/run/systemd/system.control`, not its parent paths. Other service profiles
cannot declare this exception. Activated orders after tmpfiles setup while
retaining default dependencies. No helper starts or new admission authority
are introduced. Existing directory mode/ownership are preserved; this does
not promise no security-label repair by tmpfiles. These semantics follow
[systemd v257 tmpfiles.d](https://raw.githubusercontent.com/systemd/systemd/v257/man/tmpfiles.d.xml).

Astra reviewed the bounded deployment change; Luna supplied staging tests;
coordinator corrected comment-sensitive assertions and integrated bundle/profile
coverage. Final **Mac 201 passed / 1 skipped; Debian ARM64 202 passed**. The
staged install confirms identical rule bytes and that the fake tmpfiles marker
is not invoked. No host rule was executed. An earlier expanded Linux run failed
one real-bundle test because the copied source had no Git metadata; the disposable
source fixture received a synthetic commit, then passed. The actual source
branch was not committed/pushed. All temporary copies were removed.

Changed-file Ruff passes except three existing hardening.py F401 imports already
present at HEAD (`field`, `Mapping`, `Sequence`); a check excluding F401 passes.
They were not cleaned up as unrelated work. Shell syntax and diff checks pass.
Commands, ten hashes and limits: [tmpfiles evidence](evidence/bootstrap-tmpfiles-2026-10-15.json).

This is packaging support, not reboot evidence. Same-name overrides may suppress
the vendor rule; differently named rules targeting the directory can affect
boot even when not included in the install invocation. Effective target config
must be inspected before deployment claims. `After=` is not success dependency;
if the directory is absent, namespace setup for ReadWritePaths can fail before
Nexus executes or records a refusal. Actual hardened write access, controller
lifetime/no-escape admission and publication/start/readiness/entrypoint wiring
remain unverified or incomplete. Changed deployment bytes require fresh
installed-file/closure measurements and independent approval, not reuse of old
pins. No CI or live service/hardware operation was run.

### Publication binds the already-retained grant identity (2026-10-15)

The prior approval publication helper allocated a new random grant ID even
though the supervisor had already persisted its own grant transaction. Those
two records could not subsequently bind for withdrawal. Publication now
requires the pre-existing `pair_grant_intent` transaction, preserves its grant
ID, and verifies boot/context/approval/generation/payload bindings before any
write. The transaction still precedes publication; it must not be reconstructed
from the resulting overlay journal after mutation.

The verified helper now requires an explicit publication checkpoint returning
exactly None, and the file primitive invokes it at the existing lock checkpoints
through intent/file publication. This is a trusted private composition seam,
not a permissive production default or evidence that the passed object is
currently persisted. The eventual producer must re-read the protected grant
record and revalidate independent approval/generation/deadline, cancellation,
same-owner manager and phase-aware lifetime/fence conditions. The initial
absent-overlay baseline cannot be reused unchanged once publication begins.

Astra reviewed the bounded fix and clarified those remaining gates. Luna added
binding tests; coordinator corrected the invalid closed-phase fixture, exercised
an actual ordinary-file retained grant with publication/close/withdrawal, and
added partial-publication refusals. **175 local tests passed**, target Ruff and
diff checks passed. Evidence: [publication binding](evidence/bootstrap-publication-binding-2026-10-15.json).
If admission is lost after inode creation but before its ownership record is
persisted, the retained intent and unrecorded file remain an uncertain recovery
case, not authority to adopt or delete that file. Tests assert this distinction.
No Linux/full-suite rerun, CI, service operation, source commit or push occurred.

Next concrete composition dependency: independently selected exact dependency
and service-setting expectations for loaded auditd/commissiond (not learned
from observed properties), then phase-aware same-owner publication/reload/pair
inspection. Existing package/selected-file/profile measurements alone do not
provide that policy. The protected approval/generation/deadline readers already
exist and should be reused. Start guarding, authenticated readiness and actual
activated entrypoint follow; `open_pair` remains refusing until those gates
are connected. No additional generic deployment declaration is needed.

### Independently pinned loaded-unit expectations (2026-10-15)

Pre-start v4 adds `loaded_policy_digest`; v3 retains its prior canonical bytes
and remains usable by nonwidening readers. The new loaded-policy reader refuses
v3 rather than inventing defaults. Protected `loaded-units.json` contains exactly
auditd/commissiond, all 27 dependency projections and five timing/environment
settings. The complete canonical bytes and systemd-profile digest are pinned by
the independently selected pre-start policy. Nexus forward edges are
checked against source profiles and auditd's in-pair inverse edges are expected
empty (O1, see `docs/evidence/bootstrap-design-loaded-dependencies-2026-10-16.md`); OS/mount dependencies and inherited settings
remain explicit administrator expectations, never copied from observed D-Bus
properties. Returned mappings are fresh views of immutable tuple storage.

Manager loaded inspection now requires the enclosing unique systemd owner.
A different newly authenticated owner cannot inherit an earlier transaction;
it is rejected before GetUnit, with session cleanup preserved.

Luna implemented the policy reader and tests; coordinator added explicit v3
wire-byte compatibility and v3/v4 protected-reader coverage after Astra review.
The broader test run also exposed a stale lifetime test that prohibited the
already-declared tmpfiles ordering. Its correction permits exactly that edge,
not arbitrary dependencies. Astra also found private core imports in the new
runtime module; these were replaced by a public fixed core-store reader and
a local duplicate-key hook. Final bootstrap and boundary selection: **1815 passed,
2 skipped**, changed-file Ruff and diff check pass. See
[loaded-policy evidence](evidence/bootstrap-loaded-policy-2026-10-15.json).
Final review corrected the positive mount-policy test to actually supply and
preserve `var.mount` edges, without claiming observed mount topology. Its
19-test subset and Ruff passed after that test-only change; this count overlaps
the broader run and is not an additional unique-test count.

This supplies expectations, not permission to start. Production publication,
same-owner reload/pair inspection, phase-aware start guards, authenticated
readiness and activated entrypoint composition still need integration. The
manager remains refusing. No Linux VM/service/CI/hardware run or source
commit/push was performed in this increment.

### Publication checkpoint is supplied by the supervisor (2026-10-15)

The supervisor's existing `open_pair` call now passes the fresh verified
approval and a concrete `check_publish` callback. Each invocation revalidates
admission/generation/deadline, cancellation, exact `pair_grant_intent`, and
equality with the protected retained grant. Cancellation and monotonic elapsed
time are checked again after the synchronous store read. A final checkpoint
after the manager returns precedes `pair_grant_opened`; failure enters existing
containment rather than claiming a completed grant.

This callback deliberately does not rerun the initial absent-overlay check.
The backend must enforce phase-specific file/manager checks. It must also call
the synchronous callback outside an active owned event loop, since admission
can itself open synchronous D-Bus sessions.

`_check_published_pair_at` supplies the separate file-only check: a captured
fully published journal, exact owned inode/bytes, and persistent-mask stamps
retained before publication. Later journal contents never become a replacement
baseline. This helper is not yet connected to a manager reload sequence and is
not proof of atomic systemd/disk state or controller lifetime.

Remaining integration is the manager-owned publish→reload→pair-inspection
sequence, with this file check around/between observations and owner/profile/
loaded-policy rechecks, followed by guarded start/readiness and entrypoint.
The real manager still refuses publication/start; no services were operated.

Validation: **226 local tests passed**, six changed source/test files pass Ruff,
and diff check passes. Astra reviewed the checkpoint and published-state helper;
Luna supplied synthetic/ordinary-file tests. A missing published file initially
surfaced a raw filesystem exception; it now produces a redacted refusal.
Commands and source hashes: [publication checkpoint evidence](evidence/bootstrap-publication-checkpoint-2026-10-15.json).
No full-suite, Linux VM or CI rerun was performed for this increment.

### Integrated publication and loaded-pair preparation (2026-10-15)

The transaction factory now retains its directory handles, overlay store and
guard for a private manager preparation path. `_publish_and_inspect_pair`
loads the independently pinned policy, freshly confirms the stopped/empty
pair, retains mask stamps, and runs the supervisor checkpoint before publishing
the exact grant. It invalidates the old closed observation before any possible
publication mutation. The returned journal remains the expected ownership
record throughout subsequent checks.

One owned bounded system-bus session verifies the retained owner and policy's
systemd profile before Reload, then checks both loaded helpers using the same
owner and independently supplied expectations. Directory/file checks surround
Reload and both inspections. After session cleanup, the policy is reread and
compared, files are checked again, and the synchronous admission callback runs
last. That callback never runs inside the session's active event loop.

This is the integrated preparation algorithm, not full bootstrap admission.
Publishing and reloading are widening mutations even without StartUnit; there
is no production caller to this private method. `open_pair` remains refusing
because complete loaded-closure/controller-lifetime admission and guarded
start/readiness/entrypoint wiring remain incomplete. Failures retain journal
and files for containment; no new grant token or successful grant phase is
created here. File reads remain byte-bounded, not wall-clock bounded.

Local validation: **1844 passed / 2 skipped** across bootstrap and runtime
boundary tests. A final test-only strengthening of before-Reload/no-start
assertions passed the 13-test integration subset (overlapping, not additive).
Target Ruff and diff checks pass. These tests run the real ordinary-file
publisher/checker and real loaded inspectors against a fake bus; initial empty
pair confirmation and protected policy loading are fixture seams, not live
Linux admission evidence. Directory binding checks and the admission callback
are synthetic in this integration fixture as well. Final review corrected the
second-inspector fault to target commissiond, with an explicit auditd→commissiond
GetUnit sequence assertion; the 13-test subset passed again.
Astra reviewed the source; Luna supplied tests;
coordinator integrated and verified. [Manager publication evidence](evidence/bootstrap-manager-publication-2026-10-15.json)
records commands, hashes and limitations. No CI, Linux VM, live service,
hardware operation or source commit/push occurred.

### Audit exchange uses one monotonic I/O deadline (2026-10-15)

Readiness-path inspection found that the default BootstrapAuditClient connected
before setting any timeout, and reset the full timeout for individual reads.
Both append and observe now share one deadline across connect, send, shutdown,
header/body reads, trailing EOF and response decoding. Expired results refuse
even when an operation returns successfully after its budget. Nonfinite
configuration is rejected. The fixed production connector sets timeout before
connect and closes failures; injected factories remain trusted test seams and
cannot be interrupted if they themselves block indefinitely.

Local audit/supervisor/boundary selection: **188 passed**; target Ruff and diff
check pass. Socketpair tests preserve framing/receipt behavior; deterministic
fake sockets exercise slow-drip, send, EOF, decode and late-factory expiry.
[Audit deadline evidence](evidence/bootstrap-audit-deadline-2026-10-15.json)
records commands and hashes. This is not peer authentication, readiness
admission, a real service test or hard real-time preemption. Server identity
and same-owner start/readiness wiring remain incomplete. No CI, Linux VM,
service operation, commit or push was performed.

### Remaining start semantics: observation is not transaction enforcement

Astra's source review identified a concrete distinction for the next increment:
the current StartUnit job mode `fail` rejects conflicting pending jobs; it is
not a ban on starting dependency units. The coordinator confirmed this against
[systemd v257 job-mode documentation](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemctl.xml).
Changing to `ignore-requirements` would change requirement semantics while
retaining ordering; it is not an implicit fix and has not been implemented.

Next implementable read-only component: observe the protected policy's external
prerequisites and the fixed controller identity/phase, with the retained owner
and repeated bounded observations. Before controller READY, its expected
activating phase must be distinguished from active/running after READY. Such
observations remain prerequisite evidence, not an atomic guarantee that no
external unit can start after the observation. Full start enforcement still
requires an explicit reviewed transaction design. Do not silently rename this
remaining requirement as satisfied by ActiveState checks.

Controller hang bounds and actual wrapper/interpreter/import inputs are finite
remaining implementation questions. They do not justify a new whole-host
registry or unrelated hardening expansion. The audit deadline change received
Astra review with no concrete defect; server peer identity remains separate.

### Policy semantics and prerequisite observation (2026-10-15)

The protected loaded policy now rejects nonempty Upholds/UpheldBy,
OnFailure/OnSuccess and their inverses, and Triggers/TriggeredBy on either
helper, even with a matching independently pinned digest. This excludes those
additional activation channels on the pair, not all activation elsewhere.
No new registry or policy schema was introduced.

The new read-only prerequisite inspector derives a distinct, bounded set
(maximum 64) from Requires/Wants/BindsTo/Requisite, excluding the pair and the
controller. It checks canonical identity, bounded stable aliases, loaded/active
state, no pending job and no reload requirement in two complete rounds under
the retained owner/profile. Aliases never become additional requested units.
The job tuple follows [systemd's Unit interface](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/dbus-unit.c).
Manager preparation runs this inspector before and after its loaded-pair
observations and compares the results. Inactive or changed prerequisites refuse
while leaving publication ownership intact for containment.

Astra's review found that the shared D-Bus label encoder mishandled underscores
and leading digits. It now follows the byte-wise
[systemd encoding](https://raw.githubusercontent.com/systemd/systemd/v257/src/basic/bus-label.c),
with independent literal vectors and actual prerequisite-path regression tests.
Luna implemented the observer; coordinator integrated and added external-unit
and between-observer alias-drift tests. Final **1925 passed / 2 skipped**;
nine changed-file Ruff and diff checks pass. Commands, hashes and limits:
[prerequisite evidence](evidence/bootstrap-prerequisites-2026-10-15.json).

These observations do not solve atomic no-external-start enforcement, complete
process closure or controller lifetime. Controller PID/invocation and its
pre-READY/post-READY phase still need a separate observation. Production
open_pair/start remain refusing; no Linux VM, CI, service or physical operation,
commit or push occurred. Existing unrelated dirty changes remain preserved.

### Controller identity and phase binding (2026-10-15)

The private manager preparation now captures the controller's local PID,
INVOCATION_ID and fixed unified cgroup before publication. The local reader
requires the installed root context, checks the existing self/PID1 cgroup
namespace admission and rereads the kernel-backed proc identity. Environment
values are not authentication: independently owner/profile-pinned D-Bus
observations must match those captured inputs.

Controller Unit and Service properties are observed twice before Reload and
again after the loaded helper/prerequisite checks. Preparation requires the
pre-READY activating/start phase, fixed notify/main settings and a correlated
outstanding job. The job's type is not inspected. The two complete controller
observations must match, and local identity is reread after session cleanup.
The observer also supports active/running with no pending job, but that ready
phase is not yet wired into production startup. READY notification alone is
not an acknowledgement that the ready phase has been reached.

The first controller D-Bus check remains after file publication, not before it.
This is a private preparation path with no production open_pair caller. The
new checks do not establish a controller hang bound, atomic external dependency
start exclusion, authenticated audit peer readiness or complete process closure.
Production open_pair/start continue to refuse. No live service, Linux VM, CI,
physical operation, commit or push is implied by this increment.

Astra identified retained mutable D-Bus reply data across awaits. The observer
now validates and detaches each projection immediately, including nested
execution metadata; mutation and invalid-state-laundering regressions cover
the correction. Manager fault tests assert that their intended injection was
reached. Final bootstrap/system-bus/boundary selection: **1989 passed / 2
skipped**, with six-file Ruff, diff check and 54-document link check passing.
[Controller evidence](evidence/bootstrap-controller-2026-10-15.json) records
commands, complete-file hashes and the synthetic test limits.

### Phase-bound supervisor start handoff (2026-10-15)

Both supervisor start calls now capture the exact per-unit durable intent and
pass it with a fresh synchronous checkpoint to the manager. auditd requires
auditd_start_intent; commissiond requires commissiond_start_intent with its
retained audit receipt. Each checkpoint rechecks admission, cancellation,
generation, captured/in-memory/protected-store equality and the elapsed
deadline/lock after the store read. Commissioning additionally rechecks auditd
readiness. A non-None manager return or a failed post-return checkpoint prevents
readiness advancement and enters the existing containment path.

This supplies the previously missing supervisor-to-manager contract, not a
working production start backend. BootstrapNarrowingManager still refuses
without opening a session or calling the supplied checkpoint. The full
checkpoint may itself perform synchronous D-Bus admission; it must not be
passed directly to BootstrapStartJobs callbacks inside its running event loop.
Actual start composition must preserve one owner/subscription/operation deadline
while yielding to synchronous checkpoint boundaries outside that loop.
The exact activation/process scope, controller hang/lifetime guarantees and
authenticated helper readiness remain necessary before deployment.

Astra confirmed that pre-live callbacks use the existing strict audit extension
reader, not stopped-writer initial preflight. That reader permits a concurrent
writer but refuses inconsistent repeated snapshots. No pending-state bypass
or fake observation was introduced. Live startup must still match the original
stopped head exactly; an extension seen during handoff does not replace it.

Final local bootstrap/system-bus/boundary selection: **2008 passed / 2
skipped**. Six-file Ruff, diff and 54-document link checks pass. An earlier
run exposed one old-signature refusal fixture, corrected before the final run.
The 19 new handoff regressions use an in-memory manager/store, not systemd.
[Start-binding evidence](evidence/bootstrap-start-binding-2026-10-15.json)
records commands, current complete-file hashes and remaining deployment gates.
No CI, VM/service operation, commit or push occurred.

Next reviewed implementation unit: a private three-checkpoint bridge around
the existing start job (before observation, before submission, after
completion). It must retain one session/task/subscription and original deadline,
pause through an awaited future and execute the supervisor checkpoint only
with the loop stopped. Recheck elapsed time before releasing the future and
the retained owner before submission. Failed/stale releases must never resume
submission; disconnect and bounded task draining remain mandatory. This bridge
must not become a public start capability or a substitute for the remaining
deployment gates. Astra supplied this source-grounded design; it is not yet
implemented or tested.

### Owned-loop synchronous checkpoint bridge (2026-10-15)

The private manager start runner now keeps a single job task and session while
the fixed before-observation, before-submission and after-completion checkpoints
pause on a future. The synchronous admission callback executes with that loop
stopped. The driver checks the original operation deadline before and after
the callback, and only then releases that exact pause. The job rechecks the
retained systemd owner immediately before StartUnit; no replacement owner is
adopted. Subscriptions and the fast-job signal queue survive the pauses.

On failure the bridge poisons the observer and cancels the pending release and
task before owned-session teardown disconnects and drains pending tasks. A
submitted job may still have taken effect: cleanup is not proof of job
cancellation or containment. Synchronous callbacks still require a bounded
implementation; this bridge cannot preempt arbitrary blocking Python calls.
The regular stop path retains its previous semantics. The asynchronous start
adapter's existing synchronous test seam remains distinct from the new bridge.

This is private job composition, not complete start admission. Public
start_and_wait remains refusing and has no call to the private runner; no real
service is started by constructing it. Exact activation/process scope,
controller lifetime, authenticated readiness and entrypoint composition remain
unfinished. Existing dirty changes are preserved.

Astra identified a pre-existing single-snapshot teardown gap exposed by this
integration. Shared owned-loop teardown now rescans cancellation descendants
within one fixed budget, cancels each newly seen task and checks expiry even
when the final task set is empty. Non-quiescence cannot become success; if the
operation already failed its original exception is preserved. Closing a loop
is not itself evidence that all cleanup tasks quiesced.

Final local bootstrap/system-bus/boundary selection: **2038 passed / 2
skipped**. Seven-file Ruff, diff and 54-document link checks pass. The 30 new
bridge tests use fake D-Bus and real local asyncio loops: fixed phase/deadline,
independent nested synchronous work, pre-submit owner drift, late cancelled
reply, primary-error preservation, child/grandchild cleanup and non-quiescence
failure. Test-only cleanup records residual tasks before removing stragglers;
it is not reported as production quiescence. [Bridge evidence](evidence/bootstrap-start-bridge-2026-10-15.json)
records commands and current full-file hashes. No CI, VM/service operation,
commit or push occurred.

### Audit server binding in the real exchange (2026-10-15)

BootstrapAuditClient now requires a retained audit server binding for its fixed
production connector. Missing binding refuses before connection. Explicitly
injected socket factories remain trusted test seams, not production admission.
The private manager can capture the fixed auditd PID/invocation after start
under retained systemd owner/profile pins and a fresh checkpoint. Later reads
must match that captured identity rather than adopt a replacement. The identity
observer checks two detached active/running Unit/Service projections; it is not
a replacement for loaded hardening or full readiness.

The client retains a descriptor-relative, no-symlink path chain to the fixed
audit socket, validates declared ownership/modes, compares kernel peer PID,
UID and primary GID, and checks the fixed process cgroup/namespace context.
Socket GID is the operator group; peer GID is the service's primary group.
Connected socket FD inode is not compared with the filesystem socket inode.
Local checks run both before and after manager identity revalidation, before
sending bytes and again before accepting a response. Path replacement or
invocation drift refuses. The same client supplies append receipts and head
reads; the supervisor defaults its head reader to that exact client when it
is supplied for recording. Original stopped-head startup equality is unchanged.

All checks are charged against the existing monotonic exchange deadline;
late completion refuses. This is not a hard wall-time ceiling: synchronous
identity/path/account reads cannot be preempted and manager sessions still
use their own connection/observation/cleanup budgets. No verified host peer is
claimed by mocked credentials or synthetic Linux ownership/SGID metadata on
macOS. Descriptor traversal tests use ordinary temporary directories and Unix
sockets only.

Private capture is not yet called by production startup; public start remains
refusing. Commission readiness, controller-ready confirmation, exact process
closure/lifetime and entrypoint composition remain incomplete. No live service,
Linux VM, CI, physical operation, source commit or push occurred.

Final local bootstrap/system-bus/boundary selection: **2117 passed / 2
skipped**, ten-file Ruff, diff and 54-document link checks pass.
[Audit peer evidence](evidence/bootstrap-audit-peer-2026-10-15.json) records
commands, complete-file hashes and synthetic limits. Astra found and confirmed
the check-order correction; Luna workers supplied identity and exchange tests;
coordinator integrated descriptor-path and manager tests. No success in the
synthetic suite substitutes for a Linux peer/namespace or live service test.

### Controller READY acknowledgement barrier (2026-10-15)

The supervisor now calls the real manager READY barrier between the durable
`pair_grant_opened` checkpoint and `auditd_start_intent`. Successful private
publication retains the controller identity, systemd owner/profile and exact
grant transaction. The barrier requires its exact opened successor, consumes
notification before sending, and polls under one deadline. Pending state is
retryable only after full repeated identity/configuration checks; success
requires stable `active/running` with an idle job, owned-session cleanup and a
final admission checkpoint. Cancellation, expiry or changed identity refuses.
Closing starts invalidates this context. The private start bridge additionally
requires confirmed READY; this ordering guard is not full start authorization.

Synthetic integration tests now run the supervisor through the real barrier
and first audit start bridge, with publication/admission/containment explicitly
modelled. Pending or owner drift cannot advance the audit start intent. Other
regressions cover uncertain notification without retry, pending jobs and failed
cleanup. Astra reviewed the barrier; Luna supplied focused regressions and the
coordinator checked coverage and integrated the supervisor test.

This supersedes the earlier missing controller-ready confirmation item, not
the other startup gates. Public pair opening/start still refuse. Audit binding
capture, authenticated commission readiness, executable/import closure,
start dependency/conflict semantics, lifetime containment and production
entrypoint composition remain unfinished. There is no live systemd, Linux VM,
CI, deployment or hardware evidence from these tests. Existing dirty changes
are retained; no commit or push was performed.

Final local bootstrap/system-bus/boundary selection: **2133 passed / 2
skipped**, seven-file Ruff and diff checks pass. The 54-document link check
passes. [READY barrier evidence](evidence/bootstrap-controller-ready-2026-10-15.json)
records the final command and full-file hashes; this is not a full repository
suite or real systemd readiness result.

### Bound audit start composition (2026-10-15)

The private manager audit-start composition now requires the exact
`auditd_start_intent` successor of its retained publication transaction and
confirmed controller READY. It derives owner/profile pins from that context,
runs the owned start bridge through cleanup, rechecks admission, then captures
audit identity. Capture failure cannot return successful start completion.
Existing bindings cannot be replaced. Closure entry invalidates the audit
binding even if subsequent fencing fails. The supervisor records stopping
before containment; there is no post-containment audit append to preserve.

A synthetic integration test connects the supervisor, real READY barrier,
owned audit job, real identity capture and real authenticated audit client
observe/append. The same client supplies head observations and receipts.
Capture failure or wrong kernel peer PID prevents commissioning; the latter
also sends no request bytes. The original stopped-head equality and grant
receipt checks remain. D-Bus, kernel/path evidence and ledger are synthetic;
publication, commissioning and containment are modelled. This is not a live
service/transport or host authentication result.

Astra identified the closure binding lifetime gap; the coordinator fixed it
and added an existing-client refusal regression. Luna added six focused bound
start regressions. Public widening remains disabled pending the remaining
entrypoint, process closure, dependency/conflict and lifetime requirements.
Commission identity/inventory readiness remains to be implemented. No CI,
Linux VM, deployment, physical operation, source commit or push occurred.

Final local bootstrap/system-bus/boundary selection: **2143 passed / 2
skipped**. Four-file Ruff, diff and 54-document link checks pass.
[Bound audit evidence](evidence/bootstrap-bound-audit-2026-10-15.json) records
the command, synthetic limits and complete-file hashes.

### Authenticated commission inventory composition (2026-10-15)

The fixed commission identity observer and peer binding now retain the
systemd owner/profile, PID and invocation for `azazel-commissiond.service`.
The fixed `azcommission` account, descriptor-guarded commission socket path,
kernel peer credentials and process cgroup/namespace are checked before
sending and after receiving. Audit identities cannot substitute for commission
identities. Closing starts invalidates both retained client bindings.

The new client sends only `commission.inventory` with empty arguments. It
requires the retained binding, bounds framing and elapsed budget, rejects
duplicate JSON fields/trailing data, and validates the exact successful
response and producer row vocabulary. The snapshot digest is an opaque
producer reference: it is not recomputed from redacted inventory and does not
prove role selection, provider admission or inventory truth.

Private second-helper composition matches the receipt-bearing transaction to
the retained publication, runs the existing owned job bridge, and captures
commission identity only after completion and cleanup. The trusted supervisor
checkpoint, not a caller-supplied digest, supplies durable-intent and receipt
provenance checks plus fresh authenticated audit readiness. Private readiness
now observes audit head or commission inventory through the corresponding
retained client. No replacement identity is adopted during polling.

The supervisor integration test now traverses both helper jobs, both identity
captures and both authenticated clients. Wrong commission peer or malformed
inventory prevents `commissiond_ready`. Host/D-Bus evidence, admission,
publication, ledger and containment remain synthetic. Public production
widening still refuses; process/import closure, dependency/conflict semantics,
lifetime containment and production entrypoint remain unfinished. No live
service, VM, CI, deployment, hardware operation, commit or push was performed.

Astra reviewed the fixed client and supervisor-owned receipt provenance. The
trusted adapter must forward the exact transaction with its matching captured
checkpoint closure. Coordinator tests reject a valid-format receipt-only
protected-store substitution before commission `StartUnit`, and assert exact
audit-then-commission job submission plus the successful ready transition.
Final local selection: **2196 passed / 2 skipped**; eleven-file Ruff, diff and
54-document links pass. [Commission readiness evidence](evidence/bootstrap-commission-ready-2026-10-15.json)
records commands, current full-file hashes and the remaining limits.

### Ordered positive dependencies and observed conflict quiescence (2026-10-15)

The shared loaded dependency validator now requires `Requires | Wants |
BindsTo` to be a subset of `After`, retaining exact controller/audit lifetime
edges. Both protected policy decoding and loaded inspection use that validator.
Existing successful synthetic fixtures now declare and return the same ordered
edges; no installed policy is rewritten automatically.

The existing prerequisite observer also checks the union of `Conflicts` and
`ConflictedBy` from both helpers. Positive/conflict overlap is refused before
excluding pair/controller, and any conflict with those fixed services refuses.
The combined external set is bounded at 64. Positive units must be active;
conflict units must be loaded, canonical, inactive and idle. Repeated snapshots,
aliases, state and owner/profile checks enter the compared observation. Missing
conflict units refuse; the observer does not call LoadUnit. A pinned inactive
shutdown target is not blanket-rejected, but a pending shutdown job refuses.

The [systemd v257 dependency atom mapping](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/unit-dependency-atom.c)
assigns retroactive stop behavior to both conflict directions. The
[unit implementation](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/unit.c)
also distinguishes ordered from unordered retroactive positive dependencies.
This motivates stronger observations, not a claim of atomic no-external-job
behavior: dependency expansion, concurrent state changes and queued conflict
semantics remain a separate admission obligation. StartUnit mode remains
`fail`, public widening remains refusing, and no live systemd/VM/CI operation
or policy migration was performed.

Astra reviewed both conflict directions, cross-helper overlap and the combined
bound. Luna regressions cover literal inactive `shutdown.target`, pending jobs,
inverse-only conflicts, drift, exact-64 acceptance and over-bound refusal.
Final local selection: **2215 passed / 2 skipped**; six-file Ruff, diff and
54-document links pass. [Dependency evidence](evidence/bootstrap-dependency-order-2026-10-15.json)
records the command, complete-file hashes and observational limits.

### Main-progress controller watchdog (2026-10-15)

The packaged controller now declares `WatchdogSec=30s` and
`WatchdogSignal=SIGKILL`, retaining `Restart=no`, `NotifyAccess=main` and
`KillMode=control-group`. Controller inspection verifies the effective timeout
and signal before and after READY. A fixed `WATCHDOG=1` notifier uses the same
fixed system-manager socket/context boundary as READY; it accepts no public
payload/path/PID and creates no background feeder.

The supervisor renews only after confirmed READY and successful start
checkpoints or steady-state admission/readiness. BOOTTIME, cancellation and
transaction guards are sampled before and after notification; a guard itself
is bracketed by fresh samples. Cleanup disables renewal first. Steady waits
are capped at 10 seconds and the post-notification approval remainder.
Astra review identified stale wait/guard sampling risks; both are corrected
and covered by slow-notifier and guard-time expiry/cancellation tests.

Update (Nexus#324, 2026-10-25): between auditd's last start checkpoint and
commissiond's first, the supervisor used to run 4 full `_check()`, 3
grant-journal fsync writes and 5 audit appends (plus readiness and live audit
head reads) with no renewal, an estimated 15-20 s on a healthy disk; a VM run
was killed by the watchdog there during a ~30 s virtual-disk stall. In the
post-READY sequence of `_supervise`, from the READY renewal up to the first
steady wait, the supervisor now renews (`_renew_after_step`,
`_record_and_renew`) after each successful counted step: a full `_check()`,
a supervisor helper readiness read (`_ready`), a live audit head read outside
`_check()` (`verify_startup`, the grant-intent `observe`), a grant advance
(fsync) or an audit append with a confirmed receipt. At most one counted step
lies between two pings there, including the commissiond start checkpoint,
which renews between its `_check()` and its auditd readiness read. A renewal
runs only after the step returned: never before a check, from another
thread, after a refusal, for an unconfirmed receipt or once cancellation is
seen. WatchdogSec, TimeoutStartSec and every check and its order are
unchanged.

Not counted and not split: work nested inside a counted step (for example
the grant-store reads and audit continuation inside `_check()`), the
retained-intent store read and clock samples inside a start checkpoint, and
everything `start_and_wait` does between two `check_start` callbacks
(retained-publication checks, D-Bus start/observe, peer binding). The
stop/teardown path is not renewed by design, after cancellation or failure.
A cancelled session skips renewal and continues to its next cancellation
check, so it may finish a few steps without a ping (at most, after auditd
starts: its readiness and live head reads, two grant advances and the four
replayed intent appends); returning earlier would drop intent records from
the ledger, so that is not changed. A single step stalling for 30 s is still
killed. `tests/unit/test_runtime_bootstrap_watchdog.py` counts the steps
between pings with synthetic callbacks; this is not PID 1 or hardware
evidence.

This wires a running-system hang backstop, not complete lifetime admission.
Startup and helper stop bounds, actual system-manager failure behavior,
suspend-inclusive expiry enforcement and executable/import closure remain
open. The existing immutable BOOTTIME approval deadline is not replaced by
RuntimeMaxSec or watchdog timing. See the
[v257 service documentation](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.service.xml)
and [service implementation](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/service.c).
Public widening remains refusing. No VM/service operation, CI, source commit
or push occurred; synthetic notifications are not PID 1 watchdog evidence.

Final local selection including notifier, hardening and packaging tests:
**2319 passed / 2 skipped**. Seven-file Ruff, diff and 54-document links pass.
The separately checked `hardening.py` retains three baseline F401 unused
imports (`field`, `Mapping`, `Sequence`), confirmed in HEAD and not cleaned up.
[Watchdog evidence](evidence/bootstrap-watchdog-2026-10-15.json) records the
expanded command, current full-file hashes and limits.

### Read-only installed-file candidate preparation (2026-10-15)

`azazel-nexus installed-files-candidate` prepares the existing selected-file
manifest format from an explicit sorted selection, without executing selected
files, discovering a directory tree, installing a manifest or updating a pin.
Input is bounded JSON on stdin with exactly `paths`; each path is a canonical
relative `usr/` or `opt/` regular file. The reader refuses symlinks, hard links,
unprotected ownership/modes, devices and ambiguous changes. It records bytes
and descriptor/path identities, then uses the existing snapshot reader to
repeat the measurement before returning canonical manifest bytes.

For example, an operator-reviewed selection can be passed as follows:

```sh
azazel-nexus installed-files-candidate < reviewed-selection.json > candidate-installed-files.json
```

The stdout is only the canonical manifest; candidate status is reported on
stderr. On refusal stdout remains empty; scripts must check the nonzero exit
status before using a redirected candidate. Generation does not make its own
digest trusted. After independent
review and pin admission, the separate comparison remains:

```sh
azazel-nexus installed-files-check --manifest-digest 'sha256:<independently-reviewed-pin>' < candidate-installed-files.json
```

This does not close executable/import coverage. In particular the current
`#!/bin/sh` wrapper and typical venv interpreter symlinks cannot be silently
represented by regular-file v1. Interpreter/library/link semantics and the
completeness of the selected package/import set still need explicit coverage.
The generator does not resolve links or manufacture successful closure evidence.
No VM selection was generated, no protected deployment input was changed, and
public widening remains closed.

Candidate/manifest/CLI, protected admission and staging regression selection:
**120 passed**, no skips. Candidate module/two test-file Ruff and diff checks
pass; `cli.py` retains its baseline F401 `tpm_present` import. Astra reviewed
the generator and identified stdout pollution on refusal; it is corrected and
tested through the default output stream. Luna supplied CLI and focused tests;
coordinator added growth/truncation and descriptor cleanup regressions.
[Candidate evidence](evidence/installed-candidate-2026-10-15.json) records this
turn's actual selection and hashes, not prior full-bootstrap test counts.

### 2026-10-15 — selected bootstrap entrypoint composition

`az-activated` now reads the protected optional bootstrap selection before
ordinary activation. Only rechecked absence follows the ordinary path;
malformed, pending, stale, replaced or insufficiently protected selection
refuses. A missing protected parent also refuses. Invalid selection attempts
fixed broad narrowing under the transaction lock, never ordinary fallback.

Selected intent enters `run_selected_bootstrap`: one retained transaction lock,
selection rechecks around initial narrowing, manager resources and process
lifetime retained through Supervisor cleanup. Construction/run/teardown failure
attempts emergency narrowing without replacing the primary failure; an
unconfirmed emergency attempt is separately reported. Lock contention does not
narrow another cooperating session. Selection is not approval or admission.

Public manager opening/start gates still refuse. This connects the operational
attempt, not successful startup; executable/import closure, transaction/lifetime
obligations and live validation remain open. No private successful method was
substituted for the public refusal gates.

Astra performed the read-only boundary review; Luna implemented the optional
reader and composition regressions in separate file scopes, then ran integration
and lint in parallel. Local synthetic regression selection: **2323 passed,
2 skipped**. Seven source/test files passed Ruff; diff check passed. No CI, VM,
deployment or physical operation was performed.
[Entrypoint evidence](evidence/bootstrap-entrypoint-2026-10-15.json) records
the exact selection and current-file hashes.

### 2026-10-15 — native startup/stop configuration admission

The controller and supporting pair now declare a 30-second startup timeout and
10-second stop timeout, with normal SIGTERM and timeout escalation via
`TimeoutStartFailureMode=kill`, `TimeoutStopFailureMode=kill`,
`FinalKillSignal=SIGKILL`, `SendSIGKILL=yes`, `KillMode=control-group`.
The controller inspector requires those exact loaded properties. Helper
inspection retains independently pinned timer values, but requires positive
start/stop values no larger than 30/10 seconds and exact observed equality;
pinning zero, infinity or a larger value no longer admits it. Helper failure
modes and kill signals are also checked, not inferred from rendered files.
Overlay publication uses the same hardening renderer as packaged units.

This is configuration admission, not proof of native termination. Normal stop
still begins with SIGTERM; timeout failure mode selects escalation only when
the timeout expires. The existing 10-second job observer can expire before a
30-second startup completes, or at the stop escalation boundary. Such a result
remains refusal, not cancellation or successful cleanup. Existing exact job,
inactive-state and empty-cgroup checks are not weakened. Notify timeout
extension, suspension, kernel kill completion and actual manager behavior are
not established by these properties. Public widening remains closed.

Semantics and property signatures were checked against systemd v257's
[service documentation](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.service.xml),
[service D-Bus table](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/dbus-service.c)
and Astra's independent boundary review. This adds neither deployment nor
permission to start services in the VM.

Final local synthetic regression selection: **2398 passed / 2 skipped**.
The first run overlapped incomplete shared test-fixture updates (19 failures);
the final run above was executed after worker completion. Five source/test
files passed Ruff. `hardening.py` retains only its three baseline F401 imports,
confirmed against HEAD; diff check passes. Astra reviewed admission separately
from Luna's packaging/test implementation. See
[native timeout evidence](evidence/bootstrap-native-timeouts-2026-10-15.json).

### 2026-10-15 — direct Python entrypoints and concrete remaining wiring

Staged wrappers now invoke the selected interpreter directly with `-I`, removing
the intermediate `/bin/sh` dependency. Canonical absolute ASCII paths without
whitespace/control characters and a 127-byte shebang ceiling are validated
before import checks or writes. Module/function identifiers and keywords are
validated. Existing venv interpreter links remain installable, not admitted:
v1 selected-file measurement still refuses links, and interpreter/native-library
and import-set completeness remain separate obligations. This does not claim
closure merely because the synthetic wrapper imports successfully.

Local synthetic tests additionally cover a native start/stop job path returned
without a subsequent JobRemoved. Observer expiry refuses, cleans subscriptions
and handlers, does not call CancelJob and does not imply native job completion.
Focused staging/isolation/start/stop/packaging selection: **160 passed**.
The final run follows correction of Path-subclass handling and shorter synthetic
interpreter paths within the explicit shebang limit; earlier runs had failures.
No CI, VM deployment or service operation was performed.

Independent review identified the next concrete runtime omission: publication
checks retain neither the published journal/mask stamps nor loaded policy and
fingerprints for reuse by start checkpoints. Retain that checking context in
the manager, revalidate it immediately before StartUnit, and clear it on closure.
Acceptance: changed bytes/journal/policy/dependencies/owner prevents submission;
unchanged retained context passes. This is revalidation wiring, not atomic
transaction exclusion. External targets can transitively pull services, so
filtering only direct external `.service` names or assuming an already-active
target stays active does not satisfy the adopted newly-started-service closure.
Public widening stays closed until that graph/transaction obligation and the
remaining executable/lifetime obligations are met.

### 2026-10-15 — retained publication checks in bound starts

The manager now retains the successful publication's file/journal/mask checks,
held transaction guard, controller identity, manager owner and independently
loaded policy. Both bound helper start paths invoke this retained check around
their current phase-specific admission callback, including the owned bridge's
before-submission checkpoint. Each retained observation checks published bytes
and journal, policy equality, manager/profile identity, both loaded helpers
against the same expected settings and dependencies, and external prerequisites
before/after. It never performs another Reload or creates a replacement pin.

The old publication callback is not reused: its transaction phase is stale once
the grant advances. Nor is the pre-start full fingerprint compared after a
helper starts, since ExecStartEx runtime metadata legitimately changes. Fresh
loaded inspection validates fixed policy fields and internally stable snapshots.
`close_starts` invalidates retained admission before attempting containment,
including when containment fails; a failed new publication leaves no checker.

Focused final regression: **47 passed**. Expanded bootstrap/boundary/system-bus/
activation-entrypoint selection: **2396 passed / 2 skipped** before the final
additional owner check following profile observation; the final focused run
covers that check. Coverage includes
file, policy, owner and loaded dependency drift, absent/refusing retained checks
for both helpers, no additional Reload, closure invalidation, and late drift
after Subscribe that prevents StartUnit. Existing public widening still refuses.
These observations do not atomically constrain systemd's dependency expansion,
establish complete executable/import coverage or prove actual service lifetime.
No CI, VM or physical operations were run. Astra found no blocking defect and
identified an end-of-observation owner-check ordering question; an explicit
final owner read now follows the final profile read. Fresh D-Bus controller
READY confirmation and uninterrupted prerequisite continuity are not established
by this increment. Targeted Ruff, diff and document-link checks pass.

### 2026-10-15 — transaction feasibility decision, not another snapshot gate

The strict newly-started-service set is exactly auditd/commissiond, while the
adopted lifetime mechanism mandates Requires and BindsTo on the controller.
Both map to PULL_IN_START in systemd v257. If a previously submitted helper
request is processed after the controller becomes inactive, its dependency
START is no longer redundant. `fail` rejects conflicts with queued jobs; it
does not prohibit dependency starts. This is a conditional source-level
counterexample, not a reproduced PID 1/caller-death event trace.

See upstream [dependency atoms](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/unit-dependency-atom.c)
and [transaction construction and application](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/transaction.c).
Further recursion over external target dependencies cannot remove the mandatory
controller edge. `ignore-requirements` is not an equivalent replacement: the
transaction early-return also bypasses verification and conflict dependencies.
Neither job mode nor the adopted lifetime edges were changed here.

The new synthetic start-observer regression records an injected dependency
effect while the requested helper job completes successfully. It establishes
only that per-unit observation does not prove transaction closure; it is not
systemd execution evidence or acceptable production policy. Public start/grant
APIs continue refusing. Local start/manager tests: **95 passed**.

Owner decision required before changing this contract: (A) retain strict
two-service closure and authorize redesign/review of controller dependency and
start semantics, or (B) retain those semantics and explicitly revise the closure
guarantee and its allowed effects. No assumption that prerequisites/controller
cannot change, no job-mode switch, and no detection-after-start substitute has
been adopted. Executable/import coverage remains independent unfinished work.

### 2026-10-15 — option 1 approved; controller execution consumed once

The owner selected option 1: preserve the exact two-service start scope and
authorize dependency/start redesign. That decision supersedes the preceding
decision-wait state. Review rejected replacing BindsTo with Requisite and
PropagatesStopTo: an inactive queued helper could escape the execution-time
prerequisite check. Existing BindsTo/After declarations therefore remain.

The new implementation instead consumes a controller execution attempt before
any selected Supervisor construction, grant, READY or helper request. A fixed
root-private `/run/azazel-nexus-bootstrap/controller-used` marker is exclusively
created, fsynced with its directory and retained on success and failure.
The transaction guard also checks the marker and directory identity. Public
composition offers no path override, reset or removal operation. Tmpfiles
prepares the directory with no cleanup age; it is outside RuntimeDirectory.
The controller declares a negative ConditionPathExists for the same path, and
its loaded-unit inspection checks the exact typed condition and historical
successful evaluation. A selected retry refuses before Supervisor construction.
Ordinary activation without a selection does not consume the marker.

Under normal PID 1 condition evaluation and a shared stable pathname, a fresh
dependency start of the controller is skipped once the marker exists. A skipped
condition may finish its job successfully; the retained BindsTo/After execution
check still refuses a helper whose controller is inactive. This follows the
[v257 unit execution code](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/unit.c)
and [condition property encoding](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/dbus-unit.c).
This source review does not reproduce the PID 1 scheduling trace. The known
condition-evaluation environment/OOM error path, shared mount-view agreement,
reload, and actual caller-death/queued-request interleavings remain explicit
review/deployment limits. Persistent `/run` would cause continued refusal.
Implicit/transitive dependencies, import closure and BOOTTIME enforcement are
still unfinished; public widening remains refusing.

Local synthetic bootstrap/hardening/packaging/activation-entrypoint selection:
**2450 passed / 2 skipped** (8.86s). Nine changed source/test files passed Ruff;
hardening.py retains its previously recorded baseline imports. Diff check
passes. Coverage includes retained claim/refusal, marker/directory tampering,
fsync failures, loaded-condition drift, exact packaged declarations and an
ordinary-file composition test proving retry never constructs a second
Supervisor. Sol independently reviewed the causal argument and source; Luna
implemented disjoint marker and packaging tests. No CI, VM, service deployment,
physical operation, commit or push occurred.

### 2026-10-15 — effective transitive START graph checks

Controller/auditd/commissiond now declare `DefaultDependencies=no`. Explicit
ordering after sysinit/basic and before shutdown, together with the shutdown
conflict, preserves those ordering/stop declarations without pulling sysinit
through a new Requires edge. Both controller and helper loaded-unit inspectors
require effective `DefaultDependencies=false`. Systemd v257's
[service defaults](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/service.c)
and [exec/mount/slice dependencies](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/unit.c)
show why this does not remove all implicit edges.

`BootstrapStartClosureInspector` traverses effective Requires/Wants/BindsTo
from the fixed three roots, regardless of observed activity. It rejects
external services and socket/timer/path/automount/swap/scope units, and rejects
the existing activation-channel set on every visited node. Target/mount/slice
infrastructure must be active, idle, canonical and loaded without pending
reload. Devices refuse because systemd's following-set expansion can include
sibling device Wants not visible in the canonical unit's forward arrays.

The reader compares complete detached graph snapshots with retained manager
owner/profile checks, a 64-node bound, at most 256 names per relation and 1024
total dependency entries. Publication invokes it after Reload and around pair
inspection; retained admission invokes it again at bound start checkpoints.
The bracketing observations must also agree. The result is rejection evidence,
never a newly learned policy pin or permission to start.

This does not prove continuous/atomic graph stability, inspect stop-propagation
effects, or approve executable mount effects. Device follower support and real
PID 1 traces remain unfinished; public widening continues refusing. In v257,
active START jobs are expanded before pruning, but pruning can remove their
exclusive descendants: expansion alone is not evidence those descendants
execute. Sol reviewed the implementation under these stated limits; Luna
supplied disjoint declaration, projection and transitive-graph tests.

Final local related selection after installing the already pinned
`PyYAML==6.0.3` from the offline cache: **2583 passed / 2 skipped** (9.99s).
Ten changed source/test files pass Ruff; hardening.py retains its recorded
baseline unused imports. Diff and 54-document link checks pass. The full
unit suite was also exercised: default macOS temporary paths produced
6257 passed / 64 failed / 20 skipped / 26 errors. A short dedicated temporary
root reduced that to **6286 passed / 61 failed / 20 skipped**; its bootstrap
subset is **2448 passed / 2 skipped**, with no failures. Full-suite failures
include missing Linux `/proc`, `SO_PEERCRED`, `/etc/os-release`, Darwin device
number behavior, missing local YAML dependency (now corrected and tested in
the final related selection), and a setgid directory-mode expectation on this
filesystem. This is not a Linux/CI success claim; the full suite remains red.
The full run also exposed a prior installed-files-candidate README omission
and stale lifetime ordering expectations; both are corrected. No unrelated
platform behavior was changed. Source hashes, exact commands and the local
JUnit digest are recorded in
[start-closure evidence](evidence/bootstrap-start-closure-2026-10-15.json).

### 2026-10-15 — device follower inventory in the retained start path

The transitive inspector now handles the device follower-group gap. A fixed
read-only ListUnitsByPatterns request enumerates at most 512 device units;
separate Device-interface SysFSPath reads group units sharing the same path.
Every group member enters the same bounded dependency walk, including members
not named by a root dependency. Nonempty Following must point to a same-group
anchor with empty Following; a unique path-derived leader is not assumed.
Reached devices must match listed identity/state/job values, be loaded, active
and idle, and expose a nonempty canonical sysfs path. Unrelated inventory units
with empty sysfs paths are not inferred to belong to any group.

Rows and accepted Unit values are detached before further awaits. Full
inventory rereads bracket each graph observation; changed membership, paths,
following, identity or state refuses. Inventory values contribute to the
transient comparison/hash, while raw sysfs paths are not returned by the
observation. This opens no filesystem device and issues no start, load, mount,
probe or other mutation request. Existing root admission, owner/profile,
graph-node and dependency-entry bounds remain in force.

The native relation is grounded in v257's
[same-sysfs following set](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/device.c),
[Device property](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/dbus-device.c)
and [fixed list method](https://raw.githubusercontent.com/systemd/systemd/v257/src/core/dbus-manager.c).
Sol reviewed source and causal coverage; Luna supplied follower/inventory and
retained-start integration tests. Synthetic success is not a native enumeration
or PID 1 scheduling trace. Atomic graph stability, udev changes after inspection,
mount executable effects, stop propagation, import closure and BOOTTIME remain
open; public widening remains refusing.

Related local selection: **2609 passed / 2 skipped** (10.42s). After
strengthening the manager regression, the final device/publication selection
is **57 passed**. The regression first publishes a graph whose independent
loaded policy already pins the audit-to-device edge, then changes only the
same-sysfs sibling's Wants to an external service. The real retained bound
audit path refuses before StartUnit, retaining the published journal and
closing its owned sessions. Four changed source/test files pass Ruff; diff
and 54-document link checks pass. The prior macOS full-suite audit remains
red as recorded above; it was not repeated for this bounded change. No CI,
VM, service deployment, device-file operation, commit or push occurred.

[Device follower evidence](evidence/bootstrap-device-followers-2026-10-15.json)
records current full-file hashes and exact test selections.

### 2026-10-15 — site-disabled startup and explicit initial import paths

The actual installer preflight, profile helper and stager now run with `-IS`.
Staging probes the selected interpreter without site initialization, derives
conventional venv package paths from the executable's lexical prefix using the
explicit sysconfig venv scheme, and shares one literal initial-path bootstrap
between dependency validation and generated direct-Python wrappers. Existing
paths are bounded, normalized and deduplicated; malformed probe output refuses.
There is no inherited system-site or editable `.pth` fallback. Bytecode writes
are disabled before application imports. The operator installation command is
unchanged; no architecture or Python minor is hardcoded.

Luna implemented disjoint regression files; Sol reviewed the source. Coordinator
review caught vacuous old dependency mocks and test-runner path mutation, which
were repaired before final validation. Real harmless temporary venv wrappers
skip executable `.pth` and sitecustomize, reject CWD/PYTHONPATH decoys and missing
modules, and preserve arguments. The final related local selection is **2693
passed / 2 skipped** (14.96s); overlapping earlier runs are not added. Three
Python files pass Ruff, shell syntax and diff checks pass, and 54-document
link inspection passes. This is not the full unit suite or Linux/CI success.

This is **site-disabled startup with explicit initial import paths**, not full
executable closure. The probe supplies installation candidates, not independent
integrity approval. Initial interpreter startup still precedes wrapper path
replacement; links, directory membership, existing bytecode, native libraries
and later import mutation remain separate admission work. Probe JSON size is
checked after capture, not a bounded-output process sandbox. Public widening
remains refusing. No VM/service deployment, CI, device operation, commit or push
occurred. Native system-manager behavior and suspend-inclusive expiry remain
open; the earlier recorded macOS full-suite failures remain outstanding.

[Site-disabled startup evidence](evidence/bootstrap-site-disabled-startup-2026-10-15.json)
records commands, counts, current dirty-tree file hashes and scope limitations.

### 2026-10-15 — mandatory bootstrap entrypoint coverage

The production protected installed-file reader previously measured whatever
regular files the independently pinned manifest selected, even if none were
bootstrap executables. It now decodes the exact pinned manifest first and
requires the controller, auditd and commissiond executable paths derived from
the declared service profiles, each with mode 0755. It measures the same raw
bytes through the existing protected regular-file verifier, then rereads the
protected manifest and refuses changed bytes. Both production context
observation and generation admission already call this reader; this is not a
standalone diagnostic or a new approval source.

Sol reviewed the bounded source change without a blocking finding. Luna updated
the direct and real protected-factory fixtures. Coordinator review preserved the
protected-read replacement regression with valid canonical input and added a
wrong-independent-pin case. Each missing/wrong-mode entrypoint and an unrelated
manifest refuse before measurement; changed bytes during measurement refuse
after the actual measurement seam was reached. A synthetic installed tree with
all three wrappers passes the real protected-admission composition.

Final related local selection: **2717 passed / 2 skipped** in 13.25s. This is
one overlapping selection, not an addition to prior counts or the full suite.
The three source/test files pass Ruff; diff and 54-document link checks pass.
No CI, Linux service deployment, device operation, commit or push occurred.
The earlier full macOS suite remains red as recorded separately.

This is a mandatory-entrypoint coverage floor, **not** complete executable or
import closure. Interpreter links, directory membership, unlisted imports,
bytecode and native loader dependencies remain separate admission work. No
public opening/start gate was enabled. Native scheduling, mount-view and
suspend-inclusive expiry qualification remain outstanding.

[Entrypoint coverage evidence](evidence/bootstrap-entrypoint-coverage-2026-10-15.json)
records the current dirty-tree hashes, commands, scope and remaining gates.

### 2026-10-15 — explicit selected-directory membership

The existing pinned manifest/verifier now supports v2 directory records while
preserving v1 bytes and selected-file behavior. Expected immediate children
derive from the files/directories union; intermediate directories below declared
roots are explicit and empty directories must remain empty. Selected directories
are protected no-follow exact-0755 paths. Bounded enumeration refuses unknown or
duplicate names, named/descriptor identities are compared, and membership scans
bracket file hashing in both complete observations. V2 schema identity is
preserved even with an empty directory array.

The real production context/generation reader uses this verifier; its existing
fixed-entrypoint coverage floor still applies. Candidate preparation accepts
explicit sorted `--directory` arguments with the existing JSON file selection.
There is no automatic discovery, independent approval or installation. The same
independently supplied digest pins the entire document. The CLI reports declared
directory count where nonzero and retains canonical stdout/candidate-only stderr.

Luna implemented disjoint schema and candidate/CLI changes. Coordinator added
the verifier, causal directory tests and protected-factory v1/v2 integration;
review corrected an initially overbroad parent rule so ancestors outside selected
roots need not be enumerated. Sol's scoped design and final implementation review
found no blocking defect. The final related local selection is **2798 passed /
2 skipped** (13.87s); a post-documentation README check is 18 passed, overlapping
that selection. Neither count is the full suite. Eight changed source/test files
pass Ruff. `cli.py` retains its pre-existing F401 for `tpm_present`, independently
reproduced from HEAD; no unrelated cleanup was performed. Diff and 54-document
link checks pass. No Linux/VM service deployment, CI, physical/block/loop device
operation, commit or push occurred.

Exact membership covers only declared directories. It does not establish that
all import roots were selected, handle interpreter symlinks/native libraries, or
freeze state against later changes/hostile root. Public bootstrap opening/start
remains refusing; native scheduling and suspend-inclusive expiry remain open.
The prior macOS full-suite failures remain separately recorded.

[Directory membership evidence](evidence/bootstrap-directory-membership-2026-10-15.json)
records commands, full-file dirty-tree hashes and these limitations.

### 2026-10-15 — canonical wrapper to pinned initial-path binding

Bootstrap measurement now reads all three fixed wrappers through a protected
content reader: at most three sorted unique listed files, each at most 64 KiB
(192 KiB aggregate), with pinned hashes, no-follow metadata and repeated
named-identity checks. Returned bytes are not obtained by an unchecked reopen.
A pure renderer/parser shared with staging accepts only the exact canonical
`-IS` wrapper for each compiled target, without executing the wrapper. All three
must agree on the interpreter and ordered initial import paths. The interpreter
requires its exact 0755 regular-file entry; import roots require exact v2
directory records or listed regular `.zip` files, not merely an ancestor record.
Full existing measurement and protected raw-manifest reread follow. No new
schema, approval source or grant was added.

Luna implemented disjoint shared-wrapper and content/admission tests. Coordinator
added actual private bound-audit start regressions: an initially valid synthetic
installed tree passes publication, then wrapper drift or an import-directory
addition causes fresh admission to refuse before any StartUnit. No interpreter
or helper is executed by that fixture. Sol found a stager/admission file-root
mismatch; the stager now also accepts only directories or `.zip` files, and Sol
confirmed the correction. Coordinator review retained the original protected
read-race causality and the render/parser 64-KiB bound symmetry.

Final related local selection: **2902 passed / 2 skipped**, 15.34s. Overlapping
file/subagent runs are not added, and this is not the full suite. Ten changed
source/test files pass Ruff; diff and 54-document links pass. Prior unrelated
lint findings and full macOS suite failures remain separately recorded. No CI,
Linux/VM service deployment, device operation, commit or push occurred.

This binds approved wrapper bytes to approved initial-path coverage; it is not
proof of complete import resolution, initial interpreter semantics, pyvenv
configuration or native-loader closure. Staging supports interpreter links, but
bootstrap still refuses them instead of treating target hashes as link proof.
V1 generic diagnostics remain valid, including a pinned zip-only initial path
set; ordinary directory import paths require v2 records. Observations do not
freeze later filesystem state or defend against hostile root. Public opening
and start remain refusing; native behavior and suspend-inclusive expiry remain
open.

[Startup-path binding evidence](evidence/bootstrap-startup-path-binding-2026-10-15.json)
records the final dirty-tree hashes, exact selection and remaining limitations.

### 2026-10-15 — pinned interpreter leaf-link chains

V3 extends the same independently pinned installed manifest with explicit leaf
link records; v1/v2 bytes and behavior remain unchanged. Targets are canonical
absolute /usr or /opt paths, or one sibling basename. Every declared chain,
including unused records, must terminate at a listed regular file within eight
links. Cycles, missing targets, collisions and links used as ancestors refuse;
at most 1024 links are accepted. No directory alias or slash-relative fallback
is added. This supersedes the blanket interpreter-link refusal in the earlier
startup-binding slice only for these explicitly admitted chains.

The verifier never opens/follows a link: protected no-follow parents, lstat,
exact readlink text and named identity checks bracket regular-file hashing in
both observations. Directory membership includes link names. Bootstrap resolves
only manifest data and requires the terminal regular-file entry to be 0755,
then measures all actual link text and terminal bytes. Fixed wrapper content
reads remain regular-file-only. Candidate `--link` selection is explicit; every
chain member and terminal file must already be selected. No targets are added,
pins approved or service grants created automatically.

Luna implemented disjoint schema/resolver and candidate/CLI changes; coordinator
implemented measurement/runtime wiring, causal tests and avoided repeated large
set unions during ancestry validation. Sol reviewed all scopes without a
blocking finding; a stale candidate docstring was corrected afterward, with
lint rechecked. Synthetic bound-audit tests first pass real file/chain admission
and publication, then change link text or terminal bytes and refuse before any
StartUnit. Targets/interpreters are never executed in these fixtures.

Final related local selection: **2949 passed / 2 skipped**, 15.85s. Overlapping
subruns are not summed; this is not the full unit suite. Eight changed source/test
files pass Ruff. `cli.py` retains the previously baseline-confirmed F401 for
`tpm_present`; no unrelated cleanup was performed. Diff and 54-document links
pass. No Linux/VM service deployment, CI, physical/block/loop operation, commit
or push occurred. Earlier macOS full-suite failures remain separately recorded.

Only the explicitly pinned leaf-link gap is addressed. Initial interpreter and
pyvenv configuration, native startup, complete import resolution, mount-view
agreement, queued-job qualification and suspend-inclusive expiry remain open.
Observations do not freeze later state or defend hostile root. Public bootstrap
opening and start remain refusing.

[Interpreter leaf-link evidence](evidence/bootstrap-interpreter-leaf-links-2026-10-15.json)
records current dirty-tree hashes, commands, results and limitations.

### 2026-10-15 — independent kernel deadline and continuing capacity

The end-state audit found two real software gaps. Repeated protected generation
admission now calls the existing policy-bound capacity checker and rereads policy
afterward, without rerunning stopped-writer audit preflight after auditd starts.

The supervisor now requires a kernel deadline guard, bound from the first freshly
verified retained absolute deadline before blocking semantic admission or any
publication/READY/start. Production lifetime composition supplies the fixed
Linux C backend: CLOCK_BOOTTIME, SIGEV_SIGNAL/SIGKILL, TIMER_ABSTIME, one shot to
the creating process only. No additional service, thread, caller-selected PID,
signal, clock, wake capability or runtime opt-in is added. Every refresh checks
the same immutable guard. Only successful confirmed transaction cleanup permits
explicit release; failed cleanup, GC and context exit do not disarm it.

The native backend checks integer/time_t bounds, ownership after fork and armed
state. It deliberately retains an armed kernel timer if a capsule is abandoned.
POSIX timers do not survive exec, so selected supervision must not exec. BOOTTIME
counts suspend but does not wake the host; self-SIGKILL does not prove immediate
helper stopping. The upstream [timer API](https://man7.org/linux/man-pages/man2/timer_create.2.html)
and [absolute arming semantics](https://man7.org/linux/man-pages/man2/timer_settime.2.html)
ground the design, not native qualification.

Runtime builds always declare the native extension, preventing a backendless
portable wheel. The source distribution manifest and offline source bundle
include setup/C sources. Default loading requires the native extension loader;
installer staging imports/checks it but never arms a timer. Missing backend
refuses before entrypoint import/publication. No Linux wheel was built here.

Sol reviewed the actual remaining gates, native source/lifetime and final
packaging/staging wiring. Review fixed a portable-wheel fallback and an ignored
non-None guard result. Luna implemented disjoint supervisor wiring and continuing
capacity tests; coordinator integrated the C/backend/lifetime/build boundary and
causal guard/staging tests. Final local related selection: **2973 passed / 6
skipped**, 16.85s. Four skips are the explicitly unavailable compiled-Linux timer
tests: **zero native timer passes**. Overlapping subruns are not summed. Eighteen
changed Python source/test files pass Ruff; C was not compiled or Ruff-checked.
Diff and 54-document links pass. Prior full macOS-suite failures and unrelated
lint findings remain separately recorded.

No CI, VM/service deployment, native timer, physical/block/loop device operation,
commit or push occurred. Initial interpreter/pyvenv/native-loading admission,
syscall-filter compatibility and actual system-manager lifetime/reboot/suspend
qualification remain open. Public manager opening/start/unmask and readiness
remain refusing; no provider or Edge activation was enabled.

[Kernel deadline/capacity evidence](evidence/bootstrap-kernel-deadline-capacity-2026-10-15.json)
records exact commands, hashes, skipped native scope and review limitations.

### 2026-10-15 — actual Debian ARM64 unit validation

The existing Debian13 ARM64 VM was inspected using the supplied SSH identity,
without sudo, package installation or service/VM configuration changes. Its
existing Python3.13.5 test venv contains pytest/PyNaCl/PyYAML/dbus-next, but no C
compiler, Python.h, setuptools or Ruff. No cached compiler was available. Native
compilation therefore was not attempted or treated as successful.

Only ordinary temporary source trees were copied. Local per-member hashes and
the transferred archive hash were checked; all 598 final source members matched
again after tests. A first incomplete snapshot omitted contract fixtures and
workflow source metadata, producing 6793 passed /92 failed /12 errors /7 skipped.
Those omissions were corrected, not explained away as product failures. Test
Git histories existed only inside disposable copies to support worktree/tool
tests; the real development branch/HEAD and installed sources were unchanged.

The actual Linux run exposed two umask-sensitive bootstrap fixtures and two
installer tests that incorrectly relied on PYTHONPATH as installed-runtime
substitution. Luna corrected explicit file/ancestor modes under umask0002 with
safe restoration. Installer layout fixtures now copy real installer/profile
inputs and replace wrapper staging only within that temporary checkout. These
tests establish synthetic layout/tmpfiles behavior, not native runtime readiness.
Production metadata checks, isolated import requirements and native loader gates
were not relaxed. Sol independently reviewed the four test changes.

Final full unit command in the isolated Linux snapshot: **6872 passed /25 failed /
7 skipped**, 47.72s, no collection errors. The related selection extracted from
that same JUnit is **2975 passed /4 skipped**; it is not an additional run/count.
Four native timer tests remain skipped: zero native timer passes. Other skips
cover unavailable supplementary-group setup and an inapplicable no-systemd case.
Remaining failures are model acquisition(1), model import(22), operator view(2):
the VM has roughly1.3GiB available during tests, below the unchanged 2GiB model
reserve. No model admission/threshold change or unrelated cleanup was made.
The repository-wide suite is explicitly not green.

Four changed tests pass host Ruff; Ruff was not installed in the VM. Diff and
54-document link checks pass. Both XML reports and source archives are retained
locally with hashes in the evidence record. Generated remote test data was
removed after verification: initial156MiB, final162MiB and43MiB source/report
trees. This removed no user/Boot archive or installed environment. Local raw
reports are temporary artifacts, not remotely published evidence.

No CI, systemd/D-Bus service deployment, physical/block/loop operation, firmware
change or development-repository commit/push occurred. Native backend validation
requires a matching Linux compiler/Python headers or a reviewed arm64-cp313 wheel.
Execution-profile admission and native lifecycle qualification remain open;
public widening still refuses.

[Linux unit validation evidence](evidence/bootstrap-linux-unit-validation-2026-10-15.json)
records actual commands, input digests, non-additive counts, failures and cleanup.

### 2026-10-15 — pre-exec environment and retained controller inspection

Exactly the controller/auditd/commissiond units now disable login environment
construction and remove 31 fixed loader/Python names. Loaded policy requires
empty Environment/EnvironmentFiles/PassEnvironment/PAMName, the exact removal
set and SetLoginEnvironment=false. It cannot be relaxed by an owner policy pin.
Installer Python children receive fixed PATH/LANG/LC_ALL through absolute
`/usr/bin/env`; only the stager additionally receives explicit DESTDIR. Both
stager probes receive the fresh minimal environment. Notification/watchdog
variables are not globally removed from services. This does not establish
whole-OS integrity or undo native code already loaded in the installer shell.

A causal bound-start test exposed missing controller Service reinspection in
retained publication checks. Those checks now bracket graph/helper inspection
with full controller observations bound to the current pre-READY or READY
phase, original controller/grant binding and stable ready flag. The READY
transition remains owned by its existing confirmation path. Validated Service
reply lists are copied before subsequent awaits; four causal mutation tests
ensure later reply mutation cannot alter an earlier accepted fingerprint.
Sol reviewed the resulting source and found no remaining scoped issue.

Isolated macOS related tests: **3016 passed /6 skipped**. Fresh Debian ARM64
focused tests: **471 passed /5 skipped**, including four unbuilt-native skips.
The initial Linux copy lacked the `.git` sentinel used by two checkout-refusal
tests: 469 passed /2 failed /5 skipped. Adding that fixture only to the temporary
copy resolved those failures; product code was not relaxed. All 601 archive
members matched current local input and remote source after tests. Counts
overlap prior runs; the previous full Linux suite remains red and was not rerun.
Fourteen selected Python files pass Ruff; hardening.py retains three F401
findings independently reproduced from HEAD. Shell syntax and diff checks pass.

Tooling incident: an agent's project-scoped `uv run` replaced local `.venv`
Python3.11.15 with Python3.12.13 and left pytest absent. This was our operation,
not a user edit. The user was informed. Original dependency inventory is unknown,
so it has not been guessed/restored; all subsequent tests use a cached
`--no-project --isolated` environment. Source changes were preserved. The local
project venv remains altered and must not be described as restored.

No CI, native compilation, real service deployment/start, physical device
operation or development-repository commit/push occurred. Execution-profile
admission and native lifecycle qualification still block public opening; no
provider/Edge activation was added. Exact commands, source/archive/XML hashes
and limits are in [launch evidence](evidence/bootstrap-launch-environment-2026-10-15.json).

### 2026-10-15 — READY-order / bind-stop fixture tool (prepared, not yet run)

The native timer sandbox evidence explicitly left "Type=notify/READY protocol"
and "controller-to-helper BindsTo/After containment and queued/late jobs"
*not qualified*. A new operator-only tool, `tools.qualify_ready_order_sandbox`,
is the fixture that will close exactly those, separately from product admission.
It reuses the native timer tool's `_stage_parent` and `_stop_fixture` for staging
and fixture stop/cleanup, and operates only uniquely named transient
`azazel-nexus-readyorder-<32hex>-{controller,audit,commission,recheck}.service`
units; its `UNIT_PATTERN` refuses every product unit name. Default is plan-only:
no subprocess, no systemd, no artifact read. `--execute` refuses unless already
root and never attempts sudo.

On a real host the three Type=notify fixtures reproduce the product edges
(`After`/`Requires`/`BindsTo`). It proves, by system-wide CLOCK_MONOTONIC event
timestamps, that the controller readies before either helper starts and that the
order is controller → audit → commission; that the helpers are held during the
controller's pre-READY gate (no helper event then, helper start jobs waiting);
that each unit is observed populated in its own cgroup *before* the kill, so a
later absence or emptiness counts as drain rather than an unobserved path; that
killing the controller's main process follow-stops both helpers, drains their
cgroups (retried) and their systemd jobs; and that the consumed
`ConditionPathExists=!/run/azazel-nexus-bootstrap/controller-used` once-marker
refuses a fresh controller re-run. Stop and containment are confirmed before any
runner cleanup, and staging is removed only when every attempted unit's stop is
confirmed.

Synthetic regression starts no systemd: `tests/unit/test_ready_order_sandbox_tool.py`
is **24 passed**, **44 passed** with the sibling deadline-tool suite. The happy-path
fake models the real hold, and a dedicated test fails the run when a helper starts
before READY, so that gate cannot silently regress. One `real_process` test runs
the actual probe text with a throwaway notify socket and asserts its argv-role +
`__file__`-directory + stamp + READY contract. The two changed files pass the
project's effective Ruff ruleset (`E4,E7,E9,F`, ruff 0.17.0) — the same bar the
sibling tool meets; ruff 0.17.0's expanded compiled default additionally flags the
shared, accepted broad-except cleanup pattern on both tools and is recorded, not
chased. Diff is two added files only; the 54-document link check passes. An
independent fresh-context review found no hard-constraint violation and three
non-critical findings (cgroup baseline/retry, held-before-READY gating, re-run
await condition), all addressed.

Two privileged real-host attempts have run. Attempt 1 **failed**: the controller
held the helpers correctly but wrote no events and went to failed, from a
command()/probe argument-contract bug — the probe read its staging directory from
an argv the tool never passed and raised before stamping; the monkeypatched tests
do not execute the probe text, so they missed it. The probe now self-locates via
`__file__`, covered by the new `real_process` test. Attempt 2 then **passed every
qualification check on the real host** — ordered READY timeline
(preready < ready < audit < commission), helpers held and both waiting,
all cgroups populated before the kill, controller death follow-stopping both
helpers with cgroup and job drain, and the once-marker refusing the re-run — but
reported `passed=false` on a cleanup artifact: `systemctl stop` returned "not
loaded" for the BindsTo-followed helpers and the condition-skipped recheck unit,
which systemd had already garbage-collected (the terminal stopped state the
containment checks had confirmed). A `_confirm_or_stop` wrapper now treats an
already not-found unit as confirmed stopped and only stops a still-loaded one,
reusing the unchanged sibling `_stop_fixture`; four tests cover it. Attempt 3 then
**passed cleanly on the real host**: `passed=true`, `error=null`,
`cleanup_confirmed=true`, no retained directory, exit 0 — every ready-order,
containment (cgroup + job drain) and re-run-refusal check true. A separate
read-only cross-read (no sudo) confirmed no leftover fixture units, no leftover
staging directories, and that the product `azazel-activated`/`auditd`/`commissiond`
units stayed `not-found`/inactive — the fixture never touched them.

No product unit operation, native rebuild, CI, provider/Edge activation,
physical/firmware operation or commit/push occurred. The privileged actions were
the three fixture attempts above, which operated only their own uniquely named
transient units under an operator root session (the tool never attempts sudo); the
two earlier failures left root-owned staging directories the operator removed.
This qualifies systemd fixture mechanics, not product admission/deployment, and
fabricates no enrollment/pins/approval/time/epoch/generation input. Issue #93 stays
open and is not closed beyond this evidence.
[Ready-order fixture evidence](evidence/bootstrap-ready-order-sandbox-2026-10-15.json)
records the tool/source hashes, the synthetic result, the Ruff scope, the review
disposition, all three real-host attempts and the operator's passing report.

### 2026-10-15 — composition status, containment fixtures, installer staging

Three independent read-only investigations (acceptance conditions, provisioning
inputs, composition/factory) were integrated into a finite status record. The
production factory `bootstrap_narrowing_manager_in_transaction` builds the base
`BootstrapNarrowingManager`, whose `open_pair`, `start_and_wait`, `unmask` and
`is_ready` refuse unconditionally; no runtime input makes them succeed, and the
implemented delegations live only on the private `_PrototypeBootstrapManager`.
The refusal is kept: the inputs and native evidence a reviewed selection change
would need are not all present. Every provisioning input has a protected reader,
but enrollment, the purpose policy, reviewed pins, the per-boot selection, time
anchor and signed approval are owner inputs, and the initial-deadline genesis
remains the provisioning design gate in the 2026-10-14 table (rows 1, 4 and 7):
it was deliberately not implemented, because approval verification and the
owner's source/genesis decisions must precede it. An initial claim that the
deployment and selection publishers were unexposed was checked and corrected:
they are `azazel-nexus bootstrap-deployment-*` / `bootstrap-selection-*`.

`tools/qualify_lifecycle_containment_sandbox.py` adds three operator-only fixture
cases on the READY-order primitives: controller death while helper starts are
still queued (late-start containment, with positive proof the kill preceded
READY: controller events are only `preready` and no marker exists), audit death
follow-stopping commission while the controller survives, and a sandboxed
controller writing its once-marker under the per-boot `/run` tmpfs, whose
re-run is refused by the manager on a blocking start. Its 30 synthetic tests
pass; an independent review found no hard-constraint violation and its findings
(kill-before-READY proof, controller cgroup baseline, evaluated-condition
recheck, interrupt-safe cleanup, tmpfs check, per-case isolation) are addressed.
The privileged VM run is pending the operator.

On the Debian ARM64 VM the installer's read-only Phase 0 and non-root Phase 1
(`DESTDIR` staging with `--without-service-manager --without-accounts`) ran
against a verified archive of commit `9d9f7bd`, using a throwaway ordinary
unpacked venv with the previously reviewed native backend (the existing
conformance venv holds an editable install of older source that the stager
correctly ignores; it was not modified). Exit 0; all eight units, the preset and
the tmpfiles rule were byte-identical to source; wrappers carry the `-IS`
shebang and fixed import path; a host-state snapshot was identical before and
after; the scratch root was removed. The persistent phases — system accounts,
masks, `systemctl enable azazel-activated` for the next boot, controller start
and reboot — were not run and need explicit owner approval.

Following the selected sequence (validation/preview without writes before any
protected publication), two read-only previews were added:
`azazel-nexus bootstrap-admission-preview` validates canonical prestart admission
JSON with the same decoder the protected reader uses and prints the
`sha256:` digest the deployment `policy_digest` must carry (plus the v4
loaded-units pin); `azazel-nexus bootstrap-approval-policy-preview` validates the
purpose policy with the store's own decoder and prints the
`approval_policy_digest`, without echoing operator labels or duration. Both
refuse a tty, bound input to the reader limits, write nothing and print one
fixed refusal line. An independent review found that deeply nested JSON escaped
the approval preview as an uncaught `RecursionError`; both previews now fail
closed on it, pinned by tests. `az-nexus-bootstrap loaded-units-preview` reads
two canonical lines (a v4 admission policy, then loaded-units JSON) and checks
the loaded-units policy against that admission with the runtime's own decoder,
printing digests of the supplied bytes only — package, closure, live units and
the systemd profile are still checked at admission; its independent review
found no escape path and its wording findings are addressed. The existing
`installed-files-candidate` already produces context-free manifest candidates.
The previews confer no admission, enrollment or authorization.

The owner then decided the three provisioning gates of the 2026-10-14 table:
first-install audit genesis (row 4), declared-constant epoch/revocation (row 1,
with no anti-rollback claim) and in-controller first admission of the deadline
(row 7, option 1). Independent designs were written and reviewed before code.

First-install genesis rides in admission.json: a v5 prestart policy with
`audit_mode: "first-install-genesis"` and a closed `audit_genesis` object
(sequence 0, the genesis hash, the node digest, a provisioning id that only makes
the digest distinct). The operator's signed supporting-bootstrap approval already
binds admission.json through `BootstrapContext.policy_digest`, so no new
authority, purpose or approval flag exists. `inspect_first_install_audit` accepts
only an existing, correctly owned, mode-0700, empty ledger directory, stable
across two scans; it takes no expected head, so nothing observed is adopted.
`inspect_existing_audit` still refuses genesis, v3/v4 bytes and behaviour are
unchanged, and the live-head guards accept exactly `(0, genesis)` at sequence 0.
Once the first `bootstrap.grant_intent` lands the policy refuses; nothing else
enforces single use, so a wiped ledger plus a fresh signed approval would be
accepted again (assurance stays `LOCAL_CONTINUITY_ONLY`).

First admission of the deadline happens inside the controller run:
`ProtectedBootstrapInitialAdmission` (the only caller of `begin_deadline` and
`retain_initial_deadline`, composed by a fixed no-argument factory) is used by
`BootstrapSupervisor._admit_first` in the order fresh verify, generation
admission, stopped-writer prestart, re-verify and create-only retain, then the
normal refresh/advance check that arms the kernel guard from the retained
absolute deadline before any grant, publication, READY or start. Refresh still
never initializes, a refused retain never falls back to advance, and the legacy
order is kept when no initializer is supplied. Two consequences are stated
rather than hidden: prestart and generation admission now run before the kernel
guard is armed (still pre-READY, so the controller unit's `TimeoutStartSec=30s`
with `TimeoutStartFailureMode=kill` bounds them), and a deadline is never
extended within one boot: a second first admission on the same kernel boot id
(a restart, or a soft reboot, which keeps the boot id) refuses with "bootstrap
deadline was already initialized". Across a reboot (Nexus#324) each boot's
first admission carries its own owner-signed approval for that boot, and that
approval brings its own deadline. Only inside `ProtectedBootstrapInitialAdmission.retain`,
after this boot's approval is freshly verified, the generation is admitted and
prestart has passed, does the create-only store accept existing records. It
archives them, and only when all of these hold under the store lock: no
`transaction.pending` or `checkpoint.next`; both `initial.json` and
`checkpoint.json` present, protected and canonical; the two records name the
same boot id and approval digest; that boot id differs from the current one;
and that digest differs from the new approval's. Before anything changes, an
`activation.bootstrap_deadline_retiring` record (old boot id, approval digest,
both record hashes, current boot id) is appended to the controller's activation
ledger, the same path the prior-boot overlay journal retirement uses. If the
append is not confirmed, nothing changes. Inside a `transaction.pending`
marker, both records are then renamed into `archive/` (same directory tree and
filesystem, never deleted, never overwritten) and fsynced, and the new boot's
records are created as before. Any missing condition refuses as before, and the
refusal reason is on the static allowlist, so it appears in the journal. An
interrupted archive leaves the marker, and the marker refuses until reviewed.
After READY, the controller also moves earlier boots' `grant-<boot>.json`
records into the same `archive/`. It skips this boot's record, the boot the
retained overlay journal still names, any record with a `.pending`/`.next`
marker, and any record whose decoded boot id differs from its name. It first
appends `activation.bootstrap_grants_archiving` to the same ledger. Selection,
time anchor and approval remain owner-renewed per boot; none of this creates or
renews them.

No tool produced the canonical approval payload the owner must sign: only the
verifier called `bootstrap_payload`. `az-nexus-bootstrap approval-request` now
prints, read-only, the exact payload bytes for the protected declared context
and operator plus the owner-chosen `granted_at`/`expires_at`, and the SHA-256 of
the domain-separated message to sign off-host with the enrolled operator key. It
mirrors the verifier's policy, operator and duration checks through a new public
`read_bootstrap_approval_policy` reader, signs nothing, holds no key, writes
nothing, and states that drift, enrollment/revocation, the trusted time window or
a reboot can still make admission refuse a correctly signed approval. This is
consistent with the documented separation: signing stays in the operator's own
tool, never in Nexus. An independent review found no critical or high issue; its
wording and private-import findings are addressed.

Re-running bootstrap on a later boot (#324) needed the owner to move the
previous boot's selection, time record and approval aside by hand and to place
the signed pair by hand. `az-nexus-bootstrap boot-initialize` now runs the
selection, time and approval-request steps in one terminal session with each
step's own confirmations, skips steps already valid for this boot and reports
where it stopped; `approval-install` verifies a signed pair with the same
`verify_bootstrap_approval` over both bounds of the boot's administrator time
window, against the declared context (the entrypoint's live package, closure
and systemd observations are not taken; it verifies the placed pair again),
before placing it. Inside these confirmed operations only, a canonical
record of another boot with no pending marker is recorded in the activation
ledger (`activation.bootstrap_prior_boot_record_retiring`) and renamed to
`retired-<boot id>-<name>`; a record of the current boot still refuses, and the
boot-time controller never moves anything (procedure:
[Debian Live install](debian-live-install.md#per-boot-records-after-a-reboot)).
This is software-only (unit tests); `initial.json`, `checkpoint.json` and an
outdated admission audit pin still need the owner.

Building a real installed-files candidate on the Debian ARM64 VM exposed a gap
that synthetic declarations had hidden: Debian's `libpython3.13-minimal` ships
`/usr/lib/python3.13/sitecustomize.py -> /etc/python3.13/sitecustomize.py` and
`config-3.13-*/libpython3.13.so -> ../../aarch64-linux-gnu/libpython3.13.so.1`,
which the v3 manifest refuses, so the stdlib directory the wrappers put on
`sys.path` could not be pinned at all. Manifest schema v4 (v1-v3 bytes and
behaviour unchanged) adds only `etc/` as a pinnable root and relative link
targets of the form `(../)* name(/name)*`, normalized against the link's parent
and kept inside an allowed root. That adds sha-checked pins, never trust: every
link must still resolve to a pinned file, module origins stay under `/usr` or
`/opt`, and a v4 manifest may not pin `etc/ld.so.preload` in any form. The
generator emits v4 only when a selection needs it. An independent review found
no critical or high issue; its lexical-normalization, pinned-read version and
preload-placement findings are fixed. On the VM, as an unprivileged user and
with no product entrypoint executed, the v4 generator produced a complete
candidate (1494 files, 113 directories, 6 links) whose pure layout self-checks
and real-filesystem measurement pass; the installed runtime must first be
updated to decode v4, after which the owner-review candidate is regenerated.

Installer phases 2, 2b and 3 then ran on the VM (owner-approved): a root-owned
runtime venv, accounts, files, seven masked units and `azazel-activated` enabled
for the next boot. Starting the controller (phase 4) failed closed with
`RollbackFailed`: every unit stayed masked and inactive, but the pass could never
complete because Manager.GetUnit returns `org.freedesktop.systemd1.NoSuchUnit`
for masked units systemd has not loaded, and the adapter treated every bus error
as failure, so inactivity could never be confirmed. Synthetic tests had always
modelled loaded units. The fix accepts exactly that error name, only for GetUnit
inside the active/inactive query, only with fresh `masked` file state and a
re-read that the unit is still not loaded, and reads it as "inactive" (the same
claim the loaded path makes from ActiveState, not proof of no processes); every
other error still refuses and the activation adapter never uses LoadUnit. An
independent review found no critical or high issue.

The bootstrap inspectors had the same real-host gap in two places. In the
masked/closed phases (masked-pair, stopped-pair and post-stop observations) an
unloaded helper is now accepted only as an explicit "not loaded" value: exact
`NoSuchUnit` from the pinned manager, fresh file state derived from the
file-attested fragment (`/run/systemd/system.control` -> `masked-runtime`,
`/etc/systemd/system` -> `masked`), a re-read still not loaded, and for the
stopped pair an absent cgroup. Cross-observation closed checks compare owner and
fragments, not the loaded flag, so a StopUnit or garbage collection between
observations does not spuriously refuse; within one inspection the two
snapshots stay strict. After publication and Reload, nothing references the
unmasked helpers, so systemd does not load them and the start-closure,
loaded-unit and pre-start inactivity checks could never see them. Those checks
now use Manager.LoadUnit as the lookup for exactly `azazel-auditd.service` and
`azazel-commissiond.service`, with the manager owner pinned and the object path
fixed, never in masked/closed phases and never for the controller or external
units (the prerequisite observer above still never loads). LoadUnit creates no
job and starts nothing; a still-masked result reports LoadState `masked` and is
refused. An independent review found no critical or high issue. Two real-host
properties remain to be observed on the VM: the `masked-runtime` report for the
owned overlay file, and whether systemd collects a just-loaded idle helper
between lookups (that would refuse, fail-closed, but could make the flow flaky).

The bootstrap resource floor could never pass inside the real controller either:
the prestart measures `/data` from within the service, where `ProtectSystem=strict`
makes `/data` a read-only bind, so `statvfs` reports `ST_RDONLY` and the mission
measurement refused. A probe in a transient `ProtectSystem=strict` unit on the VM
confirmed it (`ST_RDONLY`, mount `ro`, superblock `rw`, same `0:49` device). The
measurement now ignores that per-mount flag only when exactly one
`/proc/self/mountinfo` entry for `/data` on the opened descriptor's device shows a
writable superblock; a read-only superblock, missing or duplicate entry, or a
malformed `/data` line still refuses, and unrelated exotic mounts no longer can.
The figure is free space on a writable filesystem, not proof that the controller
may write there; no write access was granted. Because the goal forbids block
device work, the test VM's `/data` is a 512 MiB tmpfs mounted for the boot, which
is separate from root and writable but not durable storage. An independent review
found no critical or high issue, and the real VM mountinfo parses as expected.

Both changes were independently reviewed with no critical or high finding; the
genesis review also mutation-tested the change. Follow-ups addressed: wording
that overstated single use, stamp-change and exact-int tests, a real-factory and
real-store first-admission test, and a supervisor test that runs first admission
through a genesis prestart to the first audit receipt.

This session's related tests: 74 passed across the three fixture-tool suites;
104 passed for the preview suite with the deployment-preview, boundary and CLI
companions; after the genesis and first-admission changes, the combined related
selection (bootstrap runtime and store suites, auditd, hardening, boundary/CLI
and fixture tools) is 3019 passed / 7 skipped;
the changed files pass the project Ruff ruleset and the 54-document link check.
No product unit, enable, reboot, provider/fetch/Edge activation, CI, push or
Issue closure occurred. [Composition status](evidence/bootstrap-composition-status-2026-10-15.json)
and [installer staging](evidence/bootstrap-installer-staging-2026-10-15.json)
evidence record the classification, gates, owner-input procedure, commands and
hashes.
