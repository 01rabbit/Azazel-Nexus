# Nexus packages in a user-prepared Debian Live environment

Status: **installation contract and path inventory; not hardware-qualified**.
This describes how the current source tree expects its Python packages and
systemd files to be laid out. It does not claim that a particular Debian Live
image, persistence mode, machine, or release has been tested.

## What the installer is

`packaging/install.sh` is the privileged host-integration step, not a
self-contained installer. The project has two Python distributions:

- `azazel-nexus` provides the `azazel-nexus` operator CLI;
- `azazel-nexus-runtime` provides the ten service entrypoints named by the
  packaged systemd units, plus the `az-mio-identity` pre-start helper of
  `azazel-mio-locald`, and depends on `azazel-nexus`.

Both must already be installed in a Python environment. The systemd units
execute fixed wrappers under `/usr/libexec/azazel`; ordinary Python installs
put console scripts in the environment's `bin/` directory instead. The
`tools/stage_runtime_entrypoints.py` command creates the unit-backed wrappers
from the runtime distribution declarations. It stages no operator-only tools
and accepts no caller-supplied executable or unit names.

Before writing, `install.sh` resolves the exact `ID` and `VERSION_ID` from
`/etc/os-release` through `runtime/src/azazel_nexus_runtime/install_platform.py`
and `tools/install_profile_fields.py`. The current registry contains only
`debian-13-systemd-installer-v1`; the generated plan supplies the unit,
preset, and libexec destinations, tool prerequisites, and the declared
mask/enable intent. The plan is data only: the shell remains the executor,
the installer does not start a service, and the profile does not bypass the
existing account, file-layout, or unit-declaration checks. Unknown or
ambiguous OS profiles refuse before file/account/service-manager changes.
Preflight tool checks follow the selected mode: account-management tools are
required only when account creation is enabled, and `systemctl` only when the
service-manager stage is enabled. The always-required file/runtime tools remain
checked in both modes.

This is a seam for adding a measured installation environment, not a claim
that Debian 13 on every machine has been physically tested or that another
distribution is supported. A future profile must reconcile its package and
account tools, paths, systemd behavior and runtime package observations with
the plan; if unit executable paths change, the rendered unit declarations and
wrapper staging path must change together and pass the same consistency tests.
Architecture-neutral Python behavior is kept separate from ADR-0002's
Debian 13/amd64 hardware campaign baseline: an install profile does not
qualify a CPU, firmware, persistence layout, or HIL target.

## Preconditions and invocation

For a real host installation, all of the following must hold:

- CPython 3.11 or newer, with the `azazel-nexus` and `azazel-nexus-runtime`
  distributions installed in the same environment; the runtime distribution
  pins its system-bus client dependency to `dbus-next==0.2.3`;
- the exact package inputs have been obtained and verified by the operator;
- a verified Nexus source checkout or source bundle is available for the
  wrapper-staging tool and `packaging/install.sh`;
- the Python environment path is stable across reboot. The example below uses
  `/opt/azazel-nexus/venv`;
- root privileges, `useradd`, `groupadd`, `install`, and a running systemd
  manager at `/run/systemd/system`;
- the runtime distribution and all eleven module entrypoints (ten services and
  the locald identity pre-start) are importable
  from that Python environment (the staging tool checks this before writing).

The runtime distribution now includes a small Linux C extension for its fixed
kernel deadline. Build its wheel on Linux for the target Python/architecture,
with the matching Python development headers and a C toolchain, or supply a
reviewed matching wheel offline. This changes neither the pure library's CPU
independence nor the supported OS profile. Runtime source distributions and the
offline source bundle include `runtime/setup.py`, `runtime/MANIFEST.in` and the
native C source. Runtime wheel builds always declare the extension; non-Linux
compilation refuses rather than generating a backendless `py3-none-any` wheel.
No Linux wheel was compiled by the local macOS tests reported here.

Staging checks that the compiled backend imports through its native extension
loader before importing the activation entrypoint. It does not arm a timer,
start a service, verify kernel syscall-filter compatibility, or qualify Linux
deadline/lifetime behavior. Synthetic tests use explicit fake guards; a Python
stub is not accepted by the production backend loader.

The installer invokes Python checks and the stager with `-IS`; the stager's
import check and generated service wrappers also disable site startup.
The stager probes the selected interpreter without importing `site`, and embeds
the same explicit initial import paths in validation and wrappers. Conventional
venvs use their lexical prefix and the interpreter's `venv` sysconfig scheme,
not the interpreter symlink's destination. `.pth`, `sitecustomize`, user-site
and `include-system-site-packages` do not add package directories. Install
regular distributions into the selected environment; editable `.pth` installs
and dependencies available only through inherited site paths are not supported.
Adding checkout paths to `PYTHONPATH` therefore cannot substitute for installing
the runtime. This applies equally to a VM and a physical host. Isolated mode
does not attest installed bytes or make site-packages hermetic: dependency and
unit closure admission still require independent measurement and verification.

For a reviewed selection of regular installed files, the read-only command
`azazel-nexus installed-files-check --manifest-digest sha256:<reviewed-hex> < selected-files.json`
compares canonical manifest bytes and the actual selected files. The manifest
pin must be obtained independently of the target installation. Its schema is
`azazel-nexus/selected-installed-files/v1`, with a sorted nonempty `files` array
of `path`, integer `mode` (0644 or 0755 expressed as decimal JSON), `size`, and
bare hexadecimal `sha256`. JSON is compact and key-sorted, with no trailing
newline. Paths are relative to `/`, restricted to `usr/` and `opt/`; ancestors
must be root-owned and not group/world writable. Files must be root-owned,
single-link regular files with exact mode, size and content. Inspection performs
two stable observations and neither installs nor executes the selected files.

Bootstrap admission adds a mandatory coverage floor to this general diagnostic:
its independently pinned manifest must include all three fixed executable paths
`usr/libexec/azazel/az-activated`, `usr/libexec/azazel/az-auditd` and
`usr/libexec/azazel/az-commissiond`, each with mode 0755 (decimal 493). A manifest
of unrelated files cannot substitute. Admission measures those same pinned
bytes and rereads the protected manifest afterward; any byte change refuses.
Including these wrappers alone still does not establish interpreter/import
closure or authorize a service start.

Admission now verifies those three wrappers' pinned contents and accepts only
the stager's exact canonical `-IS` format with each compiled target. The same
pure renderer is used for staging and parser comparison. All three must have
the same interpreter and ordered initial import paths. The exact interpreter
path must be a selected regular executable (0755), or an explicitly pinned v3
leaf-link chain to one; every initial import path must be an exact declared
directory or a selected regular `.zip` file.
An ancestor directory record alone is insufficient. The content reader returns
at most three 64-KiB entries after protected no-follow hash/identity checks; it
does not execute them. The whole manifest is then measured and reread. V1
remains valid for general diagnostics and can cover a zip-only initial path
set, but ordinary directory import paths need declared-directory records.

Staging supports conventional interpreter links. Bootstrap admission accepts
only explicitly pinned v3 leaf-link chains with independently pinned regular
terminal bytes. Unlisted links still refuse rather than silently using a target.
Do not replace symlinks or select a new interpreter merely to obtain a passing
diagnostic; review the deployment's actual execution layout. Even a matching
canonical wrapper and selected path set is not full import/native-loader or
initial-interpreter-startup verification.

Selected supervision requires an immutable kernel self-deadline from the first
verified retained BOOTTIME record, before blocking generation admission and any
grant/READY/start. Refreshes cannot rearm or extend it. Successful confirmed
cleanup explicitly releases it; failed cleanup, context exit and GC leave it
armed. It uses no extra service, thread, caller PID, wake-alarm capability or
runtime opt-in. POSIX timers are deleted on exec, so this selected path must not
exec another program. It is not proof of immediate helper stopping or host wake
from suspend. Native Linux compilation, expiry, fork/GC behavior, service sandbox
compatibility and systemd death-to-helper containment still need separate tests.
The current public opening/start gates remain refusing.

Once a matching Linux wheel is installed in a disposable test environment, the
four native-only tests in `tests/unit/test_runtime_bootstrap_native_deadline.py`
exercise fatal timers only in isolated subprocesses. They never target the
test runner, a service or another PID. Run these deliberately as ordinary local
tests, not a deployment operation. The current macOS run skipped all four due
to the missing compiled Linux backend; that is not native success. Full runtime
and Debian Live validation remain separate from those tests.

The v2 schema `azazel-nexus/selected-installed-files/v2` keeps the same `files`
records and adds a sorted, unique `directories` array of `{path, mode}` records
with mode 0755 (decimal 493). The whole canonical document is independently
pinned through the same digest, not a second approval source. Expected immediate
children are derived from the files/directories union. Every intermediate
directory beneath a declared root must have a directory record; empty declared
directories must remain empty. Extra files, directories and symlinks refuse.
Filesystem reads use no-follow protected descriptors, bounded enumeration and
named identity checks. Membership checks bracket file hashing in both repeated
snapshots. V1 remains unchanged; a v2 document retains its version even if its
directory array is empty. At most 4096 files and 1024 directories are accepted,
subject to the existing raw-manifest and byte bounds.

For a candidate only, supply the existing sorted JSON `{"paths":[...]}` on
stdin to `installed-files-candidate` and add one `--directory <relative-path>`
per explicitly selected directory, in sorted unique order. No directory tree
is automatically discovered, and omitted children cause refusal rather than
being added to the candidate. Without directory or link options, output remains
v1. Canonical
candidate bytes go to stdout; the candidate-only warning goes to stderr. The
read-only `installed-files-check` accepts these versions and reports the number
of declared directories when nonzero. The production bootstrap reader uses the
same verifier, so v2 membership checks also apply to context/generation admission.

V3 (`azazel-nexus/selected-installed-files/v3`) adds a sorted unique `links`
array of `{path, target}` records to the v2 document. A target is either a
canonical absolute path under `/usr` or `/opt`, or one sibling basename. Relative
paths with slashes, `.`/`..`, directory aliases and implicit targets refuse.
All chains, including unused records, must terminate at an explicitly listed
regular file within eight links; cycles, missing targets, collisions and links
used as ancestors refuse. At most 1024 links are accepted. Declared directory
membership includes link names. The reader uses protected parents, no-follow
metadata, exact `readlink` text and named identity checks before/after hashing;
it never opens a link or follows one to read its target. Terminal bytes are
measured separately through their canonical regular-file entries. Symlink
permission bits are not regular-file permission claims; ownership and single
link count are checked instead.

Candidate preparation accepts repeatable sorted unique `--link <relative-path>`
arguments. Select every chain member and terminal file explicitly; none is
automatically added or approved. Link arguments produce v3, directory-only
arguments v2, and no such arguments v1. CLI inspection reports nonzero link
counts separately from regular files/directories. V1/v2 canonical bytes and
behavior remain unchanged, and explicit v3 identity is preserved even if its
link array is empty. Link coverage alone does not cover pyvenv configuration,
initial interpreter behavior or native library loading.

This is **selected-file/directory/link comparison**, not complete installed closure
or a grant. Unlisted files outside declared roots remain outside its scope;
the verifier does not prove that the chosen roots cover all imports. Repeated
observations are not a filesystem freeze against later changes or hostile root.
Unlisted links and directory aliases are refused, not silently resolved:
merged-/usr aliases, unsupported venv paths, Python import/dependency closure,
and systemd dependency/load semantics still need separate measurement and review.
Use canonical regular-file paths for this diagnostic; do not claim it validates
an alias or execution path merely because its target bytes match.

`package_digest` has a separate Debian-specific observation format:
`azazel-nexus.debian-installed-packages.v1`. The runtime's read-only adapter runs
the fixed `dpkg-query` binary-package query, retains installed package rows with
their architecture and version (including foreign-architecture rows), sorts and
canonicalizes them, and hashes that record together with the native architecture
reported by the installed `dpkg` row. This allows an administrator to establish
separate, explicit observations for different target architectures without
assuming that an amd64 package set applies to arm64. It is an observation/pin,
not package authenticity, repository provenance, a portability claim, or an
allowlist. Changes to the installed package set require a newly reviewed
context; the adapter does not silently accept drift. It does not measure pip,
venv or other non-dpkg files. Do not reuse this digest as
`unit_closure_digest`: complete Python/runtime and systemd unit closure has a
separate scope and remains unfinished, as does production admission wiring.

On a target installation, `az-nexus-bootstrap observe-packages` prints only
the schema, native architecture, record count and digest; it does not print
package names or versions. The output supports an administrator's independent
review and provisioning process; it is not something to copy into an
authorization record without review. Refusal emits no inventory.

Administrator per-boot selection has separate interactive commands:
`azazel-nexus bootstrap-selection-initialize` and
`azazel-nexus bootstrap-selection-recover`. They require an already protected
bootstrap directory and deployment declaration; they do not create parents or
choose identifiers. Enter the reviewed canonical `azazel-nexus/bootstrap-selection/v1` JSON,
re-enter its SHA-256, then separately type `INITIALIZE` or `RECOVER`. Do not put
secrets in this record. It binds the exact deployment, current boot, chosen
approval ID and generation; it is not a signed approval or runtime admission.
This library command never overwrites existing or pending state. Recovery completes
only exact complete pending bytes valid for the same current deployment/boot;
it never repairs bytes or resets a deadline. Exit 2 means publication may be
visible but final durability is unconfirmed—inspect before retrying. To replace
a selection left by a previous boot, use `az-nexus-bootstrap boot-initialize`
(below) instead of moving files by hand; renewal within the same boot remains
unfinished, so do not delete a marker or reuse an old selection as a shortcut.
No live record has been created by the software-only tests documented here.

Once the protected declaration, selection and pinned admission policy exist,
`az-nexus-bootstrap generation-preview` reads exactly two newline-terminated
canonical JSON lines from redirected stdin: generation metadata, then bootstrap
config. It compares them with independently selected context and prints the
context-bound publication digest without writing. For publication, run
`az-nexus-bootstrap generation-publish` in a terminal, enter the same two lines,
re-enter the reviewed digest including its `sha256:` prefix, then separately type
`PUBLISH`. The target path/number/context cannot be overridden by CLI flags.
The publisher reloads the selection, refuses existing/pending targets and never
activates services. Exit 2 reports unconfirmed durability after possible
publication; inspect retained state instead of retrying automatically. These
commands are declared in the runtime Python package, not deployed into the
existing review VM venv by the tests. Preview is integrity/binding validation,
not proof of admission, signature, installed closure or live runtime readiness.

For an already reviewed explicit administrator time observation,
`az-nexus-bootstrap time-initialize` and `time-recover` accept one canonical
`azazel-nexus/administrator-clock-anchor/v1` JSON line in a terminal. The UTC
interval, boot/BOOTTIME observation and uncertainty/drift assumptions must be
established by the administrator procedure, not copied from a candidate approval
or inferred from the OS clock/synchronization flag. Re-enter the displayed
selected-time digest (`sha256:...`) and separately type `INITIALIZE` or `RECOVER`.
That digest binds the exact bytes, protected selected context/operator and the
specific operation. Selection is reread during publication; policy, boot and
time-window checks remain enforced. The commands do not change the system clock,
renew an existing anchor, reset an approval deadline or start a service. Exit 2
is uncertainty about final persistence, not success. No live anchor or trusted
UTC calibration was created by the tests.

### Per-boot records after a reboot

Selection, time record and approval are bound to one boot. After a reboot
(a new boot id), prepare them for the new boot with two commands instead of
moving the previous boot's files aside and placing the approval by hand:

```sh
sudo az-nexus-bootstrap boot-initialize
# sign the printed message off-host with the enrolled operator key
sudo az-nexus-bootstrap approval-install --payload approval.json --signature approval.sig --confirm-sha256 PAYLOAD_SHA256
```

`boot-initialize` runs in a terminal and goes through three steps in order:
the selection (enter the JSON, re-enter its SHA-256, type `INITIALIZE`), the
administrator time record (enter the anchor, re-enter the selected time digest,
type `INITIALIZE`), and the approval request (enter the
`{"expires_at":...,"granted_at":...}` validity line; the payload, its SHA-256
and the exact `approval-install` line are printed, as `approval-request` does).
No confirmation is skipped and nothing is signed. A step whose record is
already valid for this boot is detected through the protected readers and
skipped, so after a refusal the output names the step that stopped and the
steps already completed, and running `boot-initialize` again continues from
there. Exit 2 means durability is unconfirmed: inspect, do not retry
automatically.

Only inside these confirmed operations (`boot-initialize`, `time-initialize`
and `approval-install`), an existing `selection.json`, `time.json` or
`approval.json`/`approval.sig` pair is moved aside when **all** of these hold:
its boot id differs from the current boot, no `*.pending` marker (or
interrupted `.approval.*.partial` file) is present, and it decodes in its
canonical form. The move is recorded first as
`activation.bootstrap_prior_boot_record_retiring` in `/var/lib/azazel/state/activation.jsonl`
(record kind, both boot ids, SHA-256 of each file and its new name); if the
record cannot be confirmed nothing is moved. The file is then renamed in place
to `retired-<boot id>-<name>` (same owner and mode). A record of the current
boot, expired or not, is never replaced and still refuses. The controller at
boot time never moves a selection, time record or approval: a stale selection
still makes the boot-time run narrow and fail as before. Review and remove
`retired-*` files yourself. Records moved aside by Nexus are in one of two
places. These commands leave them under `/etc/azazel/bootstrap/retired-*`.
The bootstrap controller (#337) puts them in
`/var/lib/azazel/state/bootstrap/archive/`, never deleting them, in two cases:

- In the first admission of a boot, after this boot's approval is verified and
  prestart has passed, it moves an earlier boot's `initial.json`/`checkpoint.json`
  there as `initial-<boot id>.json`/`checkpoint-<boot id>.json`. It records
  `activation.bootstrap_deadline_retiring` first. It does this only when both
  records name another boot and another approval, and no transaction is
  unfinished. Otherwise it refuses as before.
- After READY, as best effort, it moves earlier boots' `grant-<boot id>.json`
  records there. It records `activation.bootstrap_grants_archiving` first. It
  never moves the record of the boot that the retained overlay journal still
  names. A failure is reported, noted as
  `activation.bootstrap_grants_archive_failed`, and retried at the next boot.

Review the archive yourself as well.

A READY bootstrap controller stopped by an ordinary `systemctl reboot` or
shutdown closes its grant and overlay journal over the system bus, so
`azazel-activated.service` is ordered after `dbus.socket` and `dbus.service`
(ordering only; #324). Without that ordering the shutdown stopped the bus in
parallel and the close ended in `emergency narrowing unconfirmed` or a
`TimeoutStopSec` SIGKILL. A close that still cannot be confirmed is not
reported as closed: the grant and journal stay `recovery_required`/`closing`,
and the next boot's controller handles that journal as an earlier boot's
(#335) before it admits again.

One shutdown race remains (#339): systemd stops `azazel-commissiond` and
`azazel-auditd` before it signals the controller, and if the controller's
supervision wakes in that window its helper check fails (`loaded unit changed
during inspection`, or the audit head is unavailable) instead of seeing the
stop. The controller still contains the pair and closes the overlay journal,
but the grant stays `recovery_required`; it is never reported as closed in
that boot. Only when all of the following held does the controller label the
grant's recovery evidence as a manager stop with an unrecorded close: the
close intent was recorded, `bootstrap.stopping` was refused only because
auditd was gone, systemd was observed stopping the controller, containment
was confirmed and the stopped-writer audit chain was intact. The next boot
retires that boot's closed journal only for that exact label, bound to the
journal's grant id, context digest and payload digests, and appends
`activation.overlay_journal_retiring` with `grant_phase` `recovery_required`,
`recovery_reason` `manager-stop-close-unrecorded` and the supervision failure
type. Any other `recovery_required` grant behind a closed journal (generic
recovery evidence, another grant's label, a containment or chain failure, a
failure of another type, or no observed stop) still refuses every boot until
you recover it by hand. The label is not an approval: the next boot still
needs this boot's records, a fresh signed approval and the full admission.

Both boots leave a trace in `/var/lib/azazel/state/activation.jsonl`. The
failing boot appends `activation.bootstrap_recovery_labelled` (boot id, grant
id, `recovery_reason`, supervision failure type and the recovery evidence
digest) right after the grant takes the label. That is the controller's own
local ledger, not az-auditd's chain, so it is normally writable even though
auditd has already stopped; if the append fails, the controller prints
`az-activated could not record the recovery label in the activation ledger`
and the outcome is unchanged. The next boot's
`activation.overlay_journal_retiring` repeats `recovery_reason`, the failure
type and the same `recovery_evidence_digest`. Search the ledger for
`recovery_reason` to see every automatic recovery and why it happened.

The stop observation is not specific to reboot: any stop job on
`azazel-activated.service`, including a manual `systemctl stop`, counts. A
root attacker who changes a helper unit at runtime and then stops the
controller can therefore get the label and an automatic retirement on the
next boot. A change that persists on disk is still refused by the next
boot's admission (the loaded-unit check against the declared policy), and a
new signed approval and the full admission are still required; what the
runtime change leaves behind is the ledger's `recovery_reason` and digest.

Ordering with observe-baseline activation: these events (like the bootstrap
controller's own records) create `/var/lib/azazel/state/activation.jsonl`. On a
node with that ledger and no `high-water.json`, every activation pass refuses
(`high-water absent on a node with an activation ledger`). They are not floor
events, so `az-activation install` still initializes the floor; on a node that
also uses observe-baseline activation, run `az-activation install` (§3.1 of
[activation-observe-baseline](activation-observe-baseline.md)) before relying on
the activation pass, ideally before the first bootstrap command here.

`approval-install` (root) reads the payload and the 64-byte signature
(regular, single-link, not followed links), requires `--confirm-sha256` to
equal the payload SHA-256, and verifies the pair with the same
`verify_bootstrap_approval` the bootstrap admission uses, with the protected
*declared* context and operator, the approval policy, the enrolled operator
trust, and both bounds of this boot's administrator time window. It does not
take the live package, installed-closure or systemd observations; the bootstrap
entrypoint takes them and verifies the placed pair again on every attempt.
A refusal by this first verification (or any earlier input check) changes
nothing. The command then verifies once more, refuses if a pair for this boot is
already installed, moves a prior boot's pair aside as above, writes private
`0600` temporary files, verifies again, renames them into place, reads them back
and records `activation.bootstrap_approval_installed`. A refusal after the prior
pair was moved aside (writing the temporary files, or the last verification)
removes the temporary files but leaves the prior pair under `retired-*` with no
new pair placed; the output says so and exits 2. Exit 2 always means a step
after the first change did not complete; inspect `/etc/azazel/bootstrap` before
retrying. Placement is not admission.
`initial.json` and `checkpoint.json` from a previous run are not handled by
these commands. The controller's first admission archives them, as described
above. These commands do not handle admission pins that a longer audit ledger
has outdated.

The installer does **not** create the Python environment, install packages,
download inputs, or configure Live persistence. Provision the venv separately
with a Python 3.11+ interpreter and its venv/pip support, then install both
verified distributions and their dependencies into it. On an offline target,
carry the [offline install bundle](#offline-install-bundle) to the Live system;
its installer creates the venv and confirms imports before you run this
installer. For example, create the environment with
`python3 -m venv /opt/azazel-nexus/venv` only if that interpreter's venv module
is available; Debian Live images may differ in which Python support packages
they include.

After installing both distributions into the venv, run the host integration
step. It validates imports and generates the fixed wrappers before changing
account records, Nexus state directories, or systemd state:

```sh
cd /path/to/verified/Azazel-Nexus-source
sudo env PYTHON=/opt/azazel-nexus/venv/bin/python sh packaging/install.sh
```

After installation, inspect the ordered read-only guide:

```sh
/opt/azazel-nexus/venv/bin/azazel-nexus setup
/opt/azazel-nexus/venv/bin/azazel-nexus setup --next --json
```

The guide prints each step's current status, reason and next command. It does
not run the installer, create a commissioning record, publish bootstrap state,
import a model, or contact the service manager. Run it from the reviewed source
directory if following its relative `packaging/install.sh` command, and ensure
`azazel-nexus` is on PATH when following its other commands. The installed-file
step requires `--installed-manifest` and `--manifest-digest` together for the
existing independently pinned reader to complete. `--operator` enables the
existing read-only signed draft review; presence alone is never a review.
The Knowledge Lite store is `/var/lib/azazel/knowledge`; the separate daemon
trust pin is `/var/lib/azazel/lite-trust`. Fetch commissioning checks presence
only, model candidates require a separate root import, and unit masks/files do
not prove a running service. **HG-05 remains unmeasured and provider admission
blocked.** No enforcement readiness is asserted. Exit 0 means guidance was
produced, not that commissioning or activation completed. See the
[setup guide](operations.md#0-read-only-operator-setup-guide) for statuses,
verification scope, and JSON fields.

The generated wrappers keep the absolute interpreter path in their invocation.
They invoke Python directly with a site-disabled (`-IS`) shebang, without an
intermediate `/bin/sh`. The interpreter path must be canonical absolute ASCII
without whitespace/control characters; the complete shebang is limited to 127
bytes. Choose a short stable installation path such as the example above.
Staging continues to support a venv interpreter link, but does not attest its
target or import dependencies: the selected-file v1 measurement still refuses
links and does not establish a complete executable/import closure.
The observed paths are installation candidates, not independent integrity
approval. Replacing `sys.path` drops nonexistent default zip entries from later
wrapper imports, but does not prevent CPython consulting its initial paths
before wrapper code runs. Native loader dependencies, existing bytecode,
directory membership and modules that subsequently alter import behavior still
need separate closure admission. Bytecode writes are disabled, not bytecode reads.
Do not move or remove the venv after installation. `DESTDIR=/path/to/staging-root`
is staging only, not a Live-system installation mode: it must be combined with
`--without-service-manager`, because systemctl operations are never redirected
by DESTDIR. `useradd` and `groupadd` are also host operations; combine staging
with `--without-accounts` unless deliberately running the account-stage test in
a disposable test host. These flags make the result incomplete and are not a
substitute for the real Live installation.
The operator CLI is invoked from `/opt/azazel-nexus/venv/bin/azazel-nexus`;
for example, append `--help` to inspect the commands available in the installed
version.

The installer refuses when `DESTDIR` is set without explicitly disabling
systemd changes (exit 2), when systemd is not running (exit 3), when account
creation is not permitted (exit 4), when Python is below 3.11, or when a
required runtime entrypoint is missing. `--without-service-manager` and
`--without-accounts` are explicitly incomplete packaging/integration modes;
their messages do not establish a complete installation and they are not
substitutes for missing Debian Live prerequisites.

### Offline install bundle

Status: **implemented** (code and focused tests), **container-rehearsed** on
emulated x86_64; **not verified** on x86_64 hardware and **not signed**. Two
artifacts come out of the offline path, both unsigned:

- the **source bundle** (`tools/build_offline_bundle.py --output X`): the two
  distributions' declared source, README/license build metadata, installer,
  wrapper-staging tool and the offline verifier. It is not a wheelhouse.
- the **install bundle** (`tools/build_offline_bundle.py --output X
  --wheelhouse W`): one `.tar.gz` whose first member is `MANIFEST.json`. The
  manifest lists every other member with its sha256, size, kind and source:
  the same source files, the hash-pinned wheelhouse, and four optional slots
  (Edge package, Debian `.deb` set, model, Knowledge).

The build runs **online on a build host**; the install runs **offline** on the
target:

```sh
# Build host: Debian 13, x86_64, Debian's CPython 3.13, python3-dev and a C
# compiler, from a clean checkout. Refuses any other architecture or Python,
# because the runtime's native extension is compiled for the build host's ABI.
python3 tools/build_wheelhouse.py --output /path/to/wheelhouse
python3 tools/build_offline_bundle.py --output /path/to/azazel-nexus-offline.tar.gz \
  --wheelhouse /path/to/wheelhouse \
  [--edge-package DIR --edge-source TEXT] [--deb DIR --deb-source TEXT] \
  [--model FILE] [--knowledge FILE] [--assets-source TEXT]

# Target, no network. Run the verifier from a reviewed checkout, not from the
# bundle it verifies.
python3 -I /path/to/reviewed/Azazel-Nexus/tools/offline_bundle.py install \
  --bundle /path/to/azazel-nexus-offline.tar.gz \
  --into /var/lib/azazel-offline/bundle \
  --venv /opt/azazel-nexus/venv --python /usr/bin/python3
# Immediately before the privileged step, re-hash the extracted tree.
python3 -I /path/to/reviewed/Azazel-Nexus/tools/offline_bundle.py recheck \
  --tree /var/lib/azazel-offline/bundle
sudo env PYTHON=/opt/azazel-nexus/venv/bin/python \
  sh /var/lib/azazel-offline/bundle/source/packaging/install.sh
```

`build_wheelhouse.py` installs the build backend from
`packaging/offline/build-backend.lock` (`setuptools==84.0.0`, by file hash),
downloads the third-party wheels named in
`packaging/offline/requirements-x86_64-cp313.lock` with `--require-hashes
--only-binary=:all: --no-deps`, and builds both Nexus wheels from the source
bundle with `--no-build-isolation --no-index`. The lock's names and versions
are tested against `runtime/pyproject.toml`; `uv.lock` is not used because it
does not cover the runtime distribution. The two Nexus wheels are recorded by
the hash this build produced; reproducibility across builders is not measured.

`offline_bundle.py install` extracts into a private staging directory beside
`--into` and renames it into place only after every check passed. It refuses:

- absolute paths, `..`, links of any kind, device files, FIFOs, GNU sparse
  members and directory members; paths that differ only in case, and a path
  that is both a file and another path's directory;
- a PAX or GNU long-name header above 64 KiB, before `tarfile` reads it into
  memory; a manifest above 8 MiB or nested deeper than 16 levels;
- member counts or byte totals above the caps, a declared total more than 200
  times the archive size, and a filesystem without the declared total plus a
  64 MiB margin free;
- a member the manifest does not declare or a declared one that is missing,
  and any size or sha256 mismatch (writing stops at the declared size);
- a destination whose parent directory is group- or other-writable or owned
  by another user.

A staging directory that a killed earlier run left behind (same destination,
owned by this user) is removed on the next run. Every third-party wheel must
match the reviewed checkout's `packaging/offline/requirements-x86_64-cp313.lock`
by name, version and sha256; a wheel the lock does not pin, such as an extra
`evil==1.0` with a self-consistent manifest hash, is refused. The two Nexus
wheels must carry the reviewed `pyproject.toml` versions; their content is
built per bundle and is covered only by a future bundle signature. The Edge
slot then goes through the existing `edge_package` checks (package present,
version, digest, bound components), and each `.deb`'s control fields are
re-read against the manifest. Only then does it create a **fresh** venv with
the given interpreter and install with `pip --no-index --find-links
--require-hashes --only-binary=:all:` from a requirements file generated from
the manifest hashes. On any refusal after extraction the extracted tree and
the venv it created are removed, so nothing half-verified is left in place.

It does not run `install.sh`. The extracted tree is not authenticated, and
`sudo install.sh` runs code from it, so run `offline_bundle.py recheck` right
before that step: it re-hashes the tree against its `MANIFEST.json` and
refuses changed, extra or missing files, links, and anything owned by another
user or writable by group/others.

Every report carries `bundle_authenticated: false`. The integration point for
the issuer/operator bundle signature is `verify_bundle_signature` in
`tools/offline_bundle.py`, which receives the exact `MANIFEST.json` bytes and
an optional `MANIFEST.sig` member; no verifier is wired in, so a present
signature is carried and not checked. A sha256 match against an unsigned
manifest is integrity against accidental change, not authenticity: whoever
can rewrite the bundle can rewrite the manifest with it. Carrying an Edge
package, a `.deb`, a model or a Knowledge bundle admits none of them; their
own admission paths are unchanged, and `.deb` files are verified and carried
but never installed by this tool.

| Item | Status | Evidence / what is missing |
| --- | --- | --- |
| Hash-pinned wheelhouse build (backend, `dbus-next`, `PyYAML`, both Nexus wheels incl. native `_bootstrap_deadline`) | implemented; container-rehearsed | [container evidence](evidence/offline-install-container-2026-10-28.json); x86_64 under Rosetta emulation, not hardware |
| Single bundle manifest (source, wheels, slots; sha256/size/kind/source) | implemented | `tests/unit/test_offline_install_bundle.py` |
| Safe atomic extraction and refusal cases | implemented | same tests; one tampered bundle refused in the container |
| Offline install with `--no-index --find-links --require-hashes` | implemented; container-rehearsed | `--network none` container at the commit the evidence names; lock check, `pip check`, imports, `recheck` and `install.sh --without-service-manager` passed. The e2e harness needs PyNaCl for its fixtures; with a separate harness-only PyNaCl set (not in the bundle or the lock) 21 of 22 stages passed, the systemd stage not run |
| Edge package slot | implemented; container-rehearsed with an Edge packager build | `edge_package` checks only; health/running stay `not-checked`; not admitted |
| Debian `.deb` slot | implemented (slot and control-field check only) | no pinned package set or source exists; no `.deb` was carried |
| Model / Knowledge slots | implemented (carry and hash only) | not admitted; admission paths unchanged |
| Bundle signing | **not implemented** — hook only | needs the issuer/operator signing work and a key |
| Bundle encryption ([update channel](update-channel.md) §2) | **not implemented** | format and key distribution open |
| Python interpreter on the target | **not provided by the bundle** | the target must already have Debian's `python3` and `python3-venv` |
| x86_64 hardware install | **not done** | requires an owner-run install on target hardware |

Still needed from the owner or hardware:

- a bundle signing key and the issuer/operator signature format (the hook is
  `verify_bundle_signature`);
- the Debian package set to carry (for example `suricata`, `iproute2`) and its
  pinned source, such as a dated `snapshot.debian.org` archive;
- provisioning of the Python interpreter and `python3-venv` on the target,
  which this bundle assumes and does not carry;
- Edge-side sensor packaging (Suricata rules/config and their owner), which
  belongs to Azazel-Edge;
- an install of a bundle on x86_64 hardware, which is the only confirmation
  of the target ABI; the container rehearsal ran under Rosetta emulation.

The [2026-10-13 prototype](#fresh-offline-installation-check-2026-10-13)
predates this path: it downloaded dependency wheels online and used an
unpinned, host-resolved build backend. It is kept as history;
[its evidence](evidence/offline-install-2026-10-13.json) still applies only to
what it recorded.

## Paths created or required

| Path | Role | Persistence consideration |
| --- | --- | --- |
| `/opt/azazel-nexus/venv` | Example location for the two installed Python distributions | Must survive reboot if used by staged wrappers |
| `/usr/libexec/azazel/` | Fixed wrappers invoked by systemd units | Must survive reboot |
| `/lib/systemd/system/` | Eight runtime unit files, including `azazel-activated.service` | Must survive reboot; Debian may expose this through merged `/usr` |
| `/lib/systemd/system-preset/99-azazel-nexus.preset` | Nexus unit preset | Must survive reboot |
| `/etc/systemd/system/` | `systemctl mask` links and the enabled-controller link | Must survive reboot; these links encode the installer's safe unit state |
| `/etc/azazel/` | Base configuration and systemd drop-in directories | Persist configuration needed after reboot; `/etc/azazel/commissioning/commissioning.json` contains raw identity and must be on LUKS-backed storage before it is written |
| `/etc/azazel/bootstrap/` | Root-private administrator declarations, signed bootstrap approvals, and the independently pinned selected-installed-files manifest | Installer creates only the empty `0700 root:root` directory; it does not enroll keys, publish approvals, or create manifests |
| `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | Account databases changed by `useradd`/`groupadd` | Must survive reboot while installed services rely on the declared system accounts |
| `/var/lib/azazel/state/` | Traversal-only parent for durable state | Root-owned; individual service leaves below are private to their writer |
| `/var/lib/azazel/state/audit/` | Auditd segmented chain | Owned by `azaudit` mode `0700`; persist if audit history must survive reboot |
| `/var/lib/azazel/state/auditd/` | Auditd refusal log, separate from chain segments | Owned by `azaudit` mode `0700`; private diagnostic state |
| `/var/lib/azazel/state/commission/` | Commissiond refusal log | Owned by `azcommission` mode `0700`; per-service diagnostic state |
| `/var/lib/azazel/state/watchdog/` | Watchdog fence file, ledger and refusal log | Owned by `azwatch` mode `0700`; persist if fences must survive reboot |
| `/var/lib/azazel/generations/` | Verified generation trees | Persist if generations are to remain available after reboot |
| `/var/lib/azazel/bootstrap-generations/` | Private bootstrap-only trees; separate numbering from operational generations | Byte integrity does not establish admission; the selected approval remains boot-bound |
| `/var/lib/azazel/secrets/commissioning.key` | Root-only HIL-preflight protection key | The installer does not create it; preflight requires it and independently refuses to write the commissioning record unless `/etc/azazel/commissioning` is LUKS-backed |
| `/var/lib/azazel/fetch/`, `/var/lib/azazel/mio/`, `/var/lib/azazel/remote/` | Optional fetch staging, local model, and remote registry state | Needed only when those later workflows are configured; they are not populated by this installer |
| `/var/lib/azazel/run/` | Runtime sockets and short-lived probe/measurement records | Treat as runtime data, not durable state; stale records have TTLs and sockets are recreated. Every unprivileged unit may write only its own leaf; no unprivileged unit holds the run root. `azazel-edge-probed` writes `run/edge-probe/edge-probe.json` (leaf `azprobe:azazel-operator 2750`, result `0644`, readable by `azazel-nexus status`) |
| `/run/azazel/mio/`, `/run/azazel/remote/`, `/run/azazel/fetch/` and other service-specific runtime directories | systemd-created volatile runtime directories, one leaf per unit; no unit declares the parent `/run/azazel/` itself, which systemd creates root-owned `0755` and never removes | Recreated by systemd; do not require persistence |

The persistent socket parents `/var/lib/azazel` and `run/` are root-owned
`0711` traversal-only directories; operators and daemons cannot list or create
entries there. Each daemon owns only its private `2710` setgid socket leaf,
whose group is `azazel-operator`. Daemon accounts are not members of that
operator group, so they do not gain filesystem access to each other's sockets.
Linux `SO_PEERCRED` identifies the peer's primary credentials, while
`SO_PEERGROUPS` supplies its kernel-reported supplementary groups; operator
membership is accepted from either, but a known service UID is never promoted
to operator based on group membership. No Nexus daemon account
(`principal.DAEMON_ACCOUNTS`, which includes every installer-created account)
is ever an operator either: entryd's unit grants `azazel-operator` only so that
it can reach provider sockets, and that group must not make it an operator at
commissiond, auditd, watchdog or the fetcher. CPython does not export
`socket.SO_PEERGROUPS` and caps `getsockopt` buffers at 1024 bytes, so the
runtime uses the Linux generic value (59) on architectures that use it and reads
at most 256 groups; a peer with more is classified without its supplementary
groups. The runtime verifies socket group,
owner and mode before accepting requests. If the target filesystem does not
preserve setgid socket-group inheritance, startup fails closed. Non-Linux
systems without `SO_PEERGROUPS` can still classify root/primary-group peers,
but supplementary-group operator access is denied; this is not a claim that
those systems are otherwise supported.

### Commissioning storage at boot

The installer does not create, open or mount the commissioning LUKS volume and
writes nothing to `crypttab` or `fstab`. For the boot-time activation pass to
read the commissioning evidence, the operator adds both entries
([commissioning storage at boot](commissioning-storage-at-boot.md), #242).
The passphrase is typed at boot; a key file and `systemd-creds` with the host
key are not supported:

```text
# /etc/crypttab -- "none": no key file
azn-commissioning  <device>  none  nofail,timeout=300
```

```text
# /etc/fstab
/dev/mapper/azn-commissioning  /etc/azazel/commissioning  ext4  nodev,nosuid,noexec,nofail,x-systemd.device-timeout=300s  0  0
```

On Debian 13 the `crypttab` generator ships in the separate `systemd-cryptsetup`
package (`apt-get install systemd-cryptsetup`); with `cryptsetup-bin` alone
`/etc/crypttab` is ignored and the mount only waits for a device that never
appears (VM-confirmed, mechanics only;
[activation rehearsal](hil-runbooks/activation-rehearsal.md)).

`x-systemd.device-timeout=300s` matches the crypttab `timeout=300`: without it
the mount job waits for the mapped device only for the default start timeout
(90 s), and could fail before the prompt ends and not be retried after a later
unlock.

`azazel-activated.service` is ordered `After=etc-azazel-commissioning.mount`
and `After=var-lib-azazel-secrets.mount` and has no `Requires=`, `Wants=`,
`BindsTo=` or `RequiresMountsFor=` on either. A volume left locked, absent or
failed therefore does not stop the controller: it still remasks, and its pass
refuses because `/etc/azazel/commissioning` is not LUKS-backed. While a mount
job is still pending, the controller waits for it, up to that 300 s timeout,
before it starts. `After=` on a mount that does not exist has no effect. That
an untyped passphrase leaves the volume locked after 300 s and the boot
continues is the intended behaviour and is **not yet verified**; the P1 VM
rehearsal checks it. When `/var/lib/azazel/secrets` shares the device, its
`fstab` line also carries `nofail` and the same device timeout. The volume
must be plain LUKS (not LVM on LUKS): `luks_backed` in
`src/azazel_nexus/hil_preflight.py` reads `dm/uuid` of the directory's own
device (`st_dev`) and accepts only a `CRYPT-LUKS` prefix, which an LVM volume
on top of LUKS does not carry.

The controller is also ordered `After=data.mount`, under the same
ordering-only rule (#251 M-7): its pass measures the free space of `/data`
against the policy's `min_mission_available_mib`, and a `/data` mounted after
the pass would refuse that boot. A `/data` that is absent, still locked or
failed does not stop the controller; the pass refuses the resources floor
([observe-baseline activation §10](activation-observe-baseline.md#10-review-251-ordering-and-residual-risks)).
How an encrypted `/data` is opened at boot is not decided here.

## Adding a future physical-install target

Hardware installation is not limited by the Python implementation to amd64;
the installer does not select an architecture-specific artifact. That is not
the same as claiming every CPU, distribution, init system, filesystem, or
Live-persistence setup is supported. The current measured runtime compatibility
profile is Debian 13 with systemd 257.13 and its exact ordered `UnitPath` on an
ARM64 Debian VM. The HIL/preflight baseline remains separately defined by its
own ADR and must not be widened just because the generic software installs on
another architecture.

To add a physical target safely, collect its exact OS and architecture,
systemd Manager `Version` and ordered `UnitPath`, package and selected-file
measurements, account/group resolution, effective directory/socket
ownership/modes, filesystem behavior (including setgid socket-group
inheritance), and the operator-selected persistence/encryption arrangement.
Review the unit lookup precedence and trust-boundary effects, then add a
narrow compatibility profile and positive/negative synthetic tests. Unknown
observations remain refused; do not use distro-name matching, architecture
wildcards, environment overrides, or automatic fallback. Installation must
not configure persistence, encrypt a volume, enroll trust, or activate a
service on the operator's behalf. Each physical model and chosen storage
layout still requires its own HIL evidence.

The table describes declared paths, not a recommended `persistence.conf`.
The user selects persistence for the exact Live image. A selective setup must
account for package code, service policy, account records, configuration, and
the state the operator actually intends to keep. Persisting only `/home` is
not enough for a system-wide Nexus installation. In particular, do not persist
or use a commissioning record on an unencrypted backing store: the record
contains raw identity, the preflight checks the backing device for a LUKS
device-mapper UUID, and the installer itself neither encrypts the path nor
creates the protection key. Boot and Nexus do not provide a tested Live
persistence allowlist or guarantee that host storage is quarantined.

## Runtime-composition boundary and remaining gates

The `az-activated` entrypoint now has a production composition root: it
requires its root systemd service context, connects to the system bus, invokes
the existing one-pass `ActivationDaemon`, and uses only the fixed governed-unit
table. A completed pass withholds all units until the implementation has
authenticated producers for generation health, an activation lease, a
commissioning record, and Edge baseline evidence. A zero exit status means
that this safe decision was recorded; it does not mean a service was admitted.
The installer still masks every operational unit and enables only this
controller for the next boot. Its packaged `Type=notify` service no longer remains
logically active after the current refusing pass exits. That pass emits no
readiness notification, so systemd startup remains unsuccessful even if the
refusal was recorded with exit status zero. Audit and commissioning
carry `BindsTo` plus `After` dependencies on the controller; this is not yet a
deployed bootstrap supervisor or verified reboot fence.

The activation controller compares a supplied lease's generation digest with
the digest re-derived by `GenerationStore.verify()` on that pass. A valid time
window alone cannot authorize another configuration; a mismatch follows the
existing mask-and-audit refusal path before any grant. This check does not
authenticate a lease or supply the missing issuer/trust contract.

An enforcement unit also requires the supplied complete commissioning record's
digest to match the generation's `commissioning_digest`. A different record
re-masks enforcement and records `commissioning_generation_mismatch`; supporting
and Edge-baseline tiers retain their existing requirements. This is a binding
check, not authentication of the record or its author, and does not make the
unsigned generation metadata an admission authority.

This branch's tests can establish the composition wiring and simulated D-Bus
method contracts, but no real systemd/D-Bus operation or Debian Live boot has
been performed. In particular, no authenticated lease/commissioning loader
exists, so a fresh install cannot advance from the masked state into the
commissioning service through activation. That bootstrap path and the remaining
operator-flow stages stay open under Issue #93; provider admission, online
acquisition, Edge activation, actual systemd enforcement, and Debian Live
verification are not established here. This guide must not be read as a claim
that Nexus is ready for field operation on Debian Live.

### Operator approval ownership (2026-10-13)

The operator selected **pre-enrolled per-operator keys**, not a central site
signer. Enrollment is a separate administrator action after verifying the
operator's public-key fingerprint through an independent channel. The installer
must not create a signing key, enroll a key supplied in an approval, or grant
its own approval. Private keys stay with the operator and are never installed
in a Nexus daemon, logged, or committed. Existing provider/catalog/Lite trust
roles do not implicitly gain this role.

`operator_trust.py` implements the initial, Nexus-local verification boundary:
an immutable supplied public-key snapshot, explicit revocation, bounded opaque
payloads and distinct commissioning/activation signature domains. It reuses
the existing Ed25519 verifier, whose independent cryptographic review gate
remains open; see [signature review](signature-review.md). It returns no
activation authorization and defines no replacement Fabric commissioning
schema. Tests use ephemeral in-memory keys only.

Remaining implementation sequence:

1. Connect the explicit enrollment/revocation tooling and protected trust
   store reader described below; load the current key set on every activation pass. Keep
   operator identity and fingerprint confirmation separate from installation.
2. Bind signed approval inputs to validated commissioning/generation content,
   node identity, policy/renderer digests, security epoch and freshness. Define
   bounded UTC lease timing and replay state; a valid signature alone does not
   satisfy these checks. Do not reuse a provider-registry envelope.
3. Extend the existing local `azazel-nexus commission` wizard with explicit
   unsigned-draft export and signed-input verification; do not create a second
   wizard. It already prepares role choices without unmasking services. Signing is
   performed by the operator's separate tool, not a Nexus daemon. Bootstrap
   must not fabricate health or bypass the activation controller.
4. Wire verified inputs and actual health/Edge evidence into `_run_once`, then
   validate installer-to-service flow on Debian. Until that wiring and its
   remaining checks exist, the production composition keeps withholding all
   units. This primitive alone is not authenticated runtime startup.

Verification of this initial boundary (2026-10-13, uncommitted worktree):
`python -m pytest tests/unit/test_operator_trust.py tests/unit/test_activation.py
tests/unit/test_runtime_activated.py tests/unit/test_runtime_activated_entrypoint.py
tests/unit/test_boundary_static.py -q` passed **109 cases locally and 109 in the
dedicated Debian ARM64 review worktree**. The latter used the existing rc2
conformance environment; it did not install services. The new trust tests plus
existing Lite signature/static-boundary tests separately passed 61 cases locally
(overlapping coverage, not an additional distinct total). Targeted Ruff and
diff checks passed. Read-only subagent review found no material flaw in this
attribution-only primitive; this does not satisfy external cryptographic review.
Each enrolled key currently verifies either purpose. Operator labels are not
in the signed transcript; signed identity/content binding and scoped enrollment
policy remain part of the subsequent input-validation layer. No GitHub Actions,
production keys, enrollment, or privileged activation was performed.

The subsequent `operator_store.py` reader fixes the production location to
`/etc/azazel/operator-trust/operators.json`. It traverses from `/` using
directory descriptors, requires root ownership with no group/other writes at
every level, refuses symlinks, and requires a single-link regular file. Reads
are limited to 64 KiB and reject concurrent size/mtime/ctime changes. The JSON
has exactly `schema` (`azazel-nexus/operator-trust/v1`), `keys` (operator label
to lowercase Ed25519 public-key hex), and `revoked` (unique operator labels).
Duplicate JSON fields and malformed trust material refuse. No path or owner
override is public, and no file is created or modified by this reader.

Reader validation: the same related command above, with
`tests/unit/test_operator_store.py` added, passed **136 cases locally and 136
on Debian ARM64**. The initial VM run had 135 passes and one failure because
the synthetic fixture inherited a group-writable parent directory from its
umask; explicit private fixture directory modes corrected the test, without
relaxing production checks. Root ownership is simulated only in the synthetic
traversal test; this is not a root-owned host deployment verification. Targeted
Ruff/diff checks passed, and read-only review found no material security error.
The reader remains a point-in-time snapshot. It is now connected to diagnostic
collection after narrowing in the production activation pass, as described
below; it is not yet consumed as an authorization input. The input/health/bootstrap work above
is still required.

#### Explicit administrator enrollment

The separate command `python -m azazel_nexus.operator_enrollment enroll LABEL`
requires root and an interactive terminal. It requests the lowercase Ed25519
**public** key, its independently obtained SHA-256 fingerprint over the raw
32-byte public key (not an SPKI fingerprint), then the exact confirmation
`ENROLL LABEL`. The command does not display a fingerprint for the operator to
blindly copy. The administrator must verify it with the operator through a
separate channel. No private key is requested or generated. The installer does
not invoke this command. Administrators must first provision the fixed trust
directory with root ownership and no group/other write permission; the command
does not create or repair directory ancestry silently.

`python -m azazel_nexus.operator_enrollment revoke LABEL` requires the matching
public key/fingerprint and the separate `REVOKE LABEL` confirmation. Revoked
identities and public keys are retained: enrollment refuses silent replacement,
revoked-name reuse and a second label for the same key. Rotation requires a new
key/label and explicit revocation of the old one. Removing/re-enabling revoked
keys is not supported by this command.

Updates use a nonblocking exclusive lock on the protected directory, a new
ordinary file, file fsync, atomic replacement, directory fsync and protected
read-back. The new file is 0600 unless the `azmission-read` group exists; then,
before any content is written, the descriptor is set root:azmission-read 0640
and the locked directory descriptor root:azmission-read 0750 (fchown/fchmod,
no path-based chmod). The store holds only public keys and revocations;
azazel-mio-locald (azmio with supplementary `azmission-read`) needs read access
for local model admission. Nothing becomes group/other-writable and the reader
checks are unchanged. The installer migrates an existing root-owned
0700/0600 store to the same modes and otherwise refuses without changes; see
[local model admission](local-model-admission.md#protected-read-only-storage). All application writers must use this lock. A failure after rename
can leave the new state installed even though success was not confirmed; the
command reports failure and requires inspection before retry, never rollback
to an older unrevoked trust state. A crash before rename can leave a protected
temporary file; it is not an active trust store. This does not defend against
a malicious root administrator or filesystem rollback.

Revocation persistence is not immediate withdrawal of an already running
service. Fresh trust loading, authenticated input validation and the runtime
narrowing path must still be integrated and tested before making that claim.
After `revoke`, run `sudo systemctl restart azazel-mio-entryd.service`:
entryd verifies the M.I.O. profile against a start-time credential copy of this
store, so until it restarts a LITE/FULL selection signed by the revoked
operator still applies (see [M.I.O. runtime](mio-runtime.md)).
No real keys were registered and no host services were changed during tests.

Enrollment validation (2026-10-13): local enrollment/store/trust/activation/
runtime/entrypoint/static-boundary/Lite-signature selection passed **194 tests**.
The dedicated Debian ARM64 review worktree ran `PYTHONPATH=src:runtime/src
/home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit -q
--basetemp=/home/rabbit/nxoperator-enrollment --tb=short`: **3378 passed, 3 failed,
1 skipped** (37.67 seconds). The three failures remain the existing
`test_hil_preflight.py` amd64 ready-path cases on ARM64. This is not a green
suite, CI execution, privileged enrollment or product hardware evidence.
Targeted enrollment/store Ruff, documentation links and diff checks passed.

Review follow-up: enrollment originally bounded only the immediate document,
which could leave no capacity to persist a later revocation. Enrollment now
reserves the encoded space for revoking **all** retained keys before accepting
a new key. A 400-byte synthetic-capacity regression demonstrates a candidate
that fits before revocation but would exceed capacity afterwards is refused,
then successfully revokes every accepted key. Local and Debian ARM64 related
tests both passed **195 cases** after this fix; the full-suite result above
predates this fix and was not rerun for this localized change. The production
store limit remains 64 KiB. This does not guarantee free filesystem capacity;
I/O failures still report unsuccessful/uncertain completion and require
inspection, rather than claiming a key was revoked.

#### Signed activation binding

`activation_approval.py` adds the Nexus-local
`azazel-nexus/activation-approval/v1` document. It is authorization input, not
a Fabric commissioning record. Its exact canonical payload contains `schema`,
`operator`, `context`, `granted_at` and `expires_at`. Context names the node
digest, current boot UUID, generation number/tree digest, commissioning,
inventory, policy and renderer digests, and security epoch. The external
operator signs `approval_message(ApprovalPurpose.ACTIVATION, payload)`; Nexus
does not gain a signing implementation.

The verifier requires an independently established expected context and a
local-policy maximum lease duration. It compares the entire signed canonical
payload to the expected values, including the operator label; signature
validity alone cannot substitute different context, extra authorization fields,
or ambiguous JSON representations. Times must be real UTC whole-second values
(`YYYY-MM-DDTHH:MM:SSZ`); grant time is inclusive and expiry exclusive. The
maximum lease duration has no permissive default and is never taken from the
approval document.

This verifier returns the existing `ActivationLease`, not a controller-minted
authorization. Runtime integration must verify and consume the approval in the
same serialized activation pass with a fresh trusted context. A retained lease
object does not retain the additional boot/epoch/policy bindings. Production
context collection, rollback-resistant generation/epoch state, clock trust,
health checks and commissioning input verification remain incomplete. This
does not claim durable replay protection or protection against clock rollback,
and `_run_once` is not changed to grant services by this patch.

The activation-approval/trust/activation/runtime/entrypoint/static-boundary
test selection passed **137 tests locally and 137 on Debian ARM64**. It covers
each context binding, expired/future/invalid times, local duration limits,
cross-purpose signatures, duplicate/extra JSON fields and changed signed
operator labels. Targeted Ruff and diff checks pass; this is synthetic software
evidence, not an installed systemd activation or hardware result.

The signed verifier now also carries generation number and commissioning
digest in the returned lease. The controller checks that pair against the
generation it actually re-verifies, before any unit decision. A new generation
with identical tree bytes cannot inherit an old approval, and a changed
commissioning metadata binding is refused even if the tree digest is unchanged.
Legacy injected/library leases may omit both fields; the signed verifier never
does. This compatibility path is not a production authenticated-input loader.

Regression tests exercise ephemeral signature verification followed by the
actual `ActivationController` with a recording unit adapter, then replacement
with a same-tree/new-number generation or changed same-number metadata. Both
paths remask previously granted units and emit no subsequent grant. Local
approval/enrollment/store/trust/activation/runtime/entrypoint/static-boundary/
Lite-signature selection passed **230 tests**. Targeted source/approval-test
Ruff and diff checks passed. Full root composition and filesystem transaction
serialization remain separate unfinished work; this does not claim to prevent
arbitrary concurrent administrator edits after verification.

The matching Debian ARM64 full unit run used the dedicated review worktree and
`--basetemp=/home/rabbit/nxapproval-binding --tb=short`: **3414 passed / 3 failed /
1 skipped**, 37.80 seconds. The three failures are the same existing amd64
HIL-preflight ready-path cases; this is not CI or a green product suite.
Read-only review found no material invariant regression in the binding change.

The bound-lease path now also revalidates canonical whole-second UTC when the
controller calls `valid_at`; offset notation, fractional seconds, lowercase
zone markers, invalid calendar dates and non-string instants refuse rather
than being compared lexicographically. Bound-lease construction rejects
noncanonical grant/expiry values. Legacy injected leases retain their previous
behavior; production signed approvals always produce bound leases. This is
format/calendar validation, not proof of trustworthy wall time or clock
rollback resistance. Local and Debian ARM64 approval/activation/runtime/
entrypoint/static-boundary tests each passed **136 cases** after this change;
targeted Ruff and diff checks passed. The full-suite count above is from the
preceding generation-binding run, not a rerun of this time-validation change.

#### Production input collection, still withholding

`activated._run_once` now calls the protected operator trust reader and the
existing kernel boot-ID reader, **after** its mandatory daemon narrowing pass
and unexpected-grant guard. It appends `activation.inputs_incomplete` with fixed
status values and names of missing producers. Raw operator labels, public keys,
boot identifiers and reader exception details are not written to the event.
Staged roots skip host reads. Failure to append this diagnostic event propagates
after the governed units have been masked; reader failures never skip masking.

The diagnostic status is not a partial `ActivationContext`, health result or
permission. Independent node identity, inventory delivery, policy/renderer
measurement, protected epoch/high-water state, clock trust, signed commissioning
and approval loaders, and health/Edge inputs still need implementation. The
activated service's AF_UNIX sandbox is unchanged; no netlink privilege was added.

A read-only call to the collector as the existing ordinary VM user observed
`operator_trust=unavailable_or_refused` and `boot=observed`. No raw identity was
printed. This is an unprivileged host-read observation, not a real root systemd
service run or confirmation that a protected trust store has been enrolled.

Local and Debian ARM64 runtime-input/runtime/entrypoint/static-boundary tests
each passed **63 cases**. Tests cover both absent and verified generations with
previously enabled recording-manager units, unavailable/revoked/active trust,
invalid boot data, audit failure after masking, and staged-root isolation.
Read-only review found no material safety issue; its request for previously
enabled-unit/verified-generation coverage was incorporated. Targeted Ruff,
documentation links and diff checks passed. No service activation, enrollment,
GitHub Actions or physical hardware operation was performed.

#### Existing commissioning bootstrap, not a second wizard

`cli._cmd_commission` already invokes `wizard.commission`, which returns a
local `CommissioningRecord` after per-interface choices and whole-set
confirmation. The default command displays its digest but does not sign or
persist that object. Its old `commissioning recorded` wording has therefore
been corrected to `commissioning draft prepared`, with explicit unsigned,
unpersisted and non-activation status. `--profiles` supplies operator assertions,
not hardware/resource/topology measurement evidence. Assigning no roles also
does not prove an observation service is running.

The missing bootstrap work is validating this existing draft
through the operator-signature path, not inventing another prompt flow or
unmasking commissiond first. Runtime `commissiond.build_snapshot().digest`
binds ordered interface observations plus permanent addresses; it is distinct
from Fabric's sorted composite-identity inventory digest. Neither is complete
hardware/resource/topology evidence. No digest substitution or extra activated
netlink capability was introduced during this investigation.

The commissioning/wizard/CLI/runtime-commissiond/static-boundary selection
passed **124 tests locally and 124 on Debian ARM64**, including confirmed-role and all-skip drafts.
Ruff reports six unchanged baseline findings across `cli.py` (one F401) and
`test_wizard_and_cli.py` (one F401, four E741), reproduced against HEAD; no
unrelated cleanup was performed. Diff checks passed.
Read-only review found the revised output truthful; its remaining wizard
docstring inconsistency was corrected to describe a returned, unsigned draft.

Explicit `commission --draft-output
/etc/azazel/commissioning/commissioning-draft.json` now exports the confirmed
wizard result only to that fixed file, never replacing an existing name. The
parent must already be caller-owned/private and pass the existing LUKS-backed
device check, evaluated against the opened directory descriptor. The existing
commissioning protection key must also be available. Missing protection or an
arbitrary output directory refuses before file creation. No host directory,
encryption mapping or key is created automatically.

The bounded Nexus-local draft reuses the existing record representation but
does not invent a generation number. It labels itself unsigned and its profile
names as assertions, not measurements. It remains within the node's encrypted
commissioning-record storage, not an externally shareable report or a Fabric
record. It must not be copied to issues, logs or ordinary storage. The initial
private-file-only implementation was rejected in read-only review because
0600 alone did not satisfy inventory confidentiality; no actual identity was
exported, and the protection checks above replace that implementation.

File creation is exclusive and 0600, refuses final symlinks, and fsyncs the
file/directory. A write failure can leave an incomplete private file and reports
failure requiring inspection before retry. Operator cancellation creates no
file. These changes do not sign/import a commissioning approval or activate
services; CLI review now uses the parser described below, while measured-profile
validation and operational admission remain incomplete.

Final draft-export validation: **173 related tests passed locally and 173 on
Debian ARM64**, including inventory-confidentiality checks. The filesystem tests
use ordinary temporary files and injected protection observations; they do not
prove real LUKS provisioning or key protection. Re-review confirmed the storage
finding is closed. Tests were corrected to reach the permission and symlink
checks rather than stopping early at the fixed-path check. New module/test
Ruff, documentation links and diff checks passed; the six pre-existing CLI/test
Ruff findings described above remain. No real draft, key or host storage was
created or changed.

`commissioning_draft.verify_draft_review` now verifies a detached operator
signature over the commissioning-purpose transcript, strictly decodes the local
draft and compares each selected composite identity against a supplied fresh
proposal. It reuses `confirm_roles`, refuses missing/ambiguous matches and
checks that each confirmation names the signing operator and record time.
Canonical re-encoding rejects altered digests, unknown fields, duplicate JSON
fields and wrong schema/status values. Signature validity does not make an
invalid draft valid.

This is draft-review verification only: success returns no commissioning record
or activation authorization. Claimed profile names remain assertions, and
node/boot/policy/freshness binding and actual measurements are still required
for runtime admission. No signing key is created or stored in production code.
The verifier is connected to the read-only CLI review described below, not
to CLI import or production startup; a file
with a detached signature is not automatically accepted by a service.

Draft review/export/wizard/commissioning/runtime-commissiond/confidentiality/
static-boundary tests passed **189 cases locally and 189 on Debian ARM64**.
Signatures use ephemeral in-memory test keys, inventory is synthetic and tests
do not establish encrypted host storage or operational activation. Tests include
correctly re-digested/re-signed documents with a substituted confirmation author
or time, not merely malformed signatures.
Read-only review found no material parser/authority bypass. Review clarifies
that only assigned bindings are compared: added/skipped interfaces are not
covered, and an all-skip draft can review successfully against a different
proposal. A regression documents this limit. Success must not be described as
proof that the entire inventory is unchanged; full-inventory binding belongs
to the separate activation-context validation.

#### Read-only signed draft review command

`azazel-nexus commission-review --operator ENROLLED_LABEL` reads only
`/etc/azazel/commissioning/commissioning-draft.json` and
`commissioning-draft.sig`. The latter is exactly 64 raw Ed25519 signature bytes
over `approval_message(ApprovalPurpose.COMMISSIONING, payload)` generated by
the operator's separate signing tool. The private key never enters Nexus.
Both files must be private caller-owned single-link regular files in the
protected encrypted commissioning directory. Reads are bounded, nofollow, and
refuse changed size/mtime/ctime. The same encryption/protection prerequisites
as export are checked before reading payload bytes. No arbitrary input paths
or inline signature/key material are accepted by this subcommand.

The command loads the current enrolled-key store, recollects the available
interface observations, and verifies the signed draft's assigned bindings.
It reports exactly that limited result; it does not import/promote the record,
prove unassigned inventory unchanged, establish measured profiles, or activate
anything. Failed reads, signatures and bindings produce a generic refusal
without printing raw identities or document/exception contents. Inventory
completeness still depends on the existing read-only collector boundary.

The local related selection passed **202 tests**, including a synthetic CLI
wizard export -> ephemeral signing -> protected-file read -> CLI review flow
and refusal for tampering, wrong signature purpose, revoked keys and changed
assigned identities. Storage protection and trust enrollment are test seams;
this does not verify a real encrypted host deployment. New reader tests also
cover missing/short/oversized/public/symlink/hardlinked signature files and
refusal before reading on unencrypted storage. New module/test Ruff and diff
checks passed; existing CLI/test Ruff findings remain separately recorded.

Follow-up validation: the Debian ARM64 full unit run recorded **3478 passed /
4 failed / 1 skipped** (38.33 seconds, `--basetemp=/home/rabbit/nxdraft-review-cli`).
Three failures were the existing amd64 HIL-preflight cases; the fourth exposed
the missing `commission-review` README table entry. The table was corrected.
The final related selection, including README conformance and additional
stable-read/missing-key/nonregular-metadata tests, passed **223 locally and 223
on Debian ARM64**. The full suite was not rerun after the documentation/test
corrections, so these runs are not presented as a green full suite.

Read-only review found no material security bypass. It identified an important
execution limit: the library CLI defaults to `no_permanent_mac`. The synthetic
CLI E2E injects a permanent-MAC reader and synthetic sysfs as well as protected
storage/trust seams. This is not evidence that an installed CLI can acquire
complete inventory. Connecting the existing runtime netlink reader through a
runtime-owned entrypoint is still required; do not add runtime imports to the
library or duplicate the wizard. Special-file rejection is tested by simulated
FIFO metadata on an ordinary temporary file, not by operating a real FIFO or
block device. No host enrollment, signed real draft or activation occurred.

The controller's local decision chain lives at
`/var/lib/azazel/state/activation.jsonl`. It is deliberately separate from the
`az-auditd` shared segmented chain and is not signed or anchored; no central
audit-integration claim is made by this composition.

### Operator runtime adapter follow-up (2026-10-13)

The permanent-address connection noted above is now implemented by
`azazel_nexus_runtime.commission_cli` / `az-nexus-commission`. It reuses the
existing wizard rather than introducing another commissioning workflow.
Only `inventory`, `commission`, and `commission-review` are exposed; global
path overrides are refused. Inventory and role selection require a terminal.
Rows/prompts use the existing physical-label/bus-path screen allowlist;
raw device identity and the unkeyed commissioning digest are not displayed.
The review success message is buffered until a fresh read-only netlink
name/index/permanent-address snapshot matches. This is not an atomic check
of all sysfs/composite fields, measured profiles, or complete inventory.

A first local run found an import cycle while reusing the screen-policy
helper; deferred helper lookup corrected it. Regression coverage includes
malformed initial/final kernel reads, suppressed premature success, private
exception redaction and raw-identity exclusion from prompts. A separate
read-only agent reviewed the corrections without finding a material issue;
this is not a complete production cryptographic/security review.

The final related selection passed **256 locally and 256 on Debian ARM64**:

```sh
python -m pytest tests/unit/test_runtime_commission_cli.py tests/unit/test_runtime_commissiond.py tests/unit/test_runtime_boundary.py tests/unit/test_stage_runtime_entrypoints.py tests/unit/test_boundary_static.py tests/unit/test_wizard_and_cli.py tests/unit/test_operator_trust.py tests/unit/test_operator_store.py tests/unit/test_operator_enrollment.py tests/unit/test_activation_approval.py tests/unit/test_commissioning_draft.py tests/unit/test_commissioning_draft_review.py -q
```

The VM run used `PYTHONPATH=src:runtime/src` in the dedicated
`/home/rabbit/nexus-lease-review-20261013` tree and the existing rc2 conformance
environment. These are test-seam results, not installed service admission.
New adapter/trust/draft modules and the wizard passed targeted Ruff.
`test_runtime_boundary.py` has an existing F401 (`pytest`) also reproduced
from HEAD; it was not cleaned up. Other previously recorded CLI/test lint
findings remain separate. `git diff --check` passed. No full-suite rerun or
CI success is claimed for this follow-up.

Earlier read-only VM collection observed two links, one available permanent
address, one commissionable and one refused interface, with a stable link
snapshot. Only counts were reported. No operator roles, production keys,
enrollment, real signed draft, encrypted export or activation were created.
Trusted context/health producers and signed-record promotion remain required
before an authenticated production activation pass can be wired.

### Resource measurement prerequisite (2026-10-13)

Review of signed-draft promotion found that the HIL persistence helper is not
a safe promotion transaction: it overwrites through a path, lacks protected
atomic persistence, and does not retain the signed wrapper. More importantly,
the local record's profile names are assertions while enforcement readiness
uses their presence. Copying a signed draft into that slot would erase the
distinction between assertions and measurements. No promotion was added.
Fabric resource/topology profile inputs and a provenance-preserving protected
transaction remain prerequisites; `commission-review` stays read-only.

The runtime now exposes `az-nexus-commission resources` to acquire missing
resource observations without changing admission. It reuses the RAM reader,
counts online logical CPUs from sysfs, and reads caller-available filesystem
space from an opened nofollow `/data` directory. Root-backed or read-only
mission storage is refused. This does not prove encryption or a separate
physical disk. Unknown architecture and failed observations remain null and
make the command exit 1. There is no GPU/cgroup/throughput/thermal benchmark,
no manufactured zero, no role inference and no Fabric ResourceProfile claim.

At `2026-10-13T06:45:21Z`, the existing Debian ARM64 VM reported 4 online
logical CPUs and 2907 MiB kernel-usable RAM. Mission storage was unavailable;
the command returned 1 with `mission_available_mib: null`. No mount, directory,
partition, device or network configuration was changed. This is VM software
evidence, not product hardware admission or Debian Live evidence.

Final related tests passed **84 locally and 84 on Debian ARM64** (resource
assessment, operator adapter, runtime/library boundaries and resource-profile
tests). Targeted Ruff, documentation links (53 files) and diff checks passed.
Read-only review caught unknown architecture missing from the unavailable
list; the correction and regression test are included in that final selection.

The VM full-unit run before that small correction recorded **3492 passed /
28 failed / 1 skipped**, 37.64 seconds. Of the failures, 25 model import/view
cases ran on the default `/tmp` tmpfs with only 1439 MiB available and were
correctly refused by the existing storage gate. Re-running only those failed
cases on the existing home filesystem (10883 MiB available) passed **25**, using
`--lf --basetemp=/home/rabbit/nxresource-spacecheck-20261013` with
`test_model_import.py`, `test_model_acquisition.py`, and `test_operator_view.py`.
No gate was relaxed. The remaining three failures are the previously recorded
amd64 HIL-preflight ready-path expectations on this ARM64 VM. No green full
suite or CI result is claimed; the full suite was not rerun after the final
unknown-architecture correction.

### Fabric resource projection (2026-10-13)

`fabric_boundary.project_resource_profile()` now maps the runtime resource
observation to the pinned Fabric `ResourceProfile` (v0.9.0rc5). It requires an
actual Fabric `HardwareInventory`, revalidates the complete model and verifies
its content digest with Fabric's helper. The interface-only composite digest
is explicitly not accepted as the full hardware snapshot digest. This is
internal consistency checking, not inventory authentication or freshness.

Measurements must be available and exact integers; a missing mission-space
measurement cannot become zero. A measured zero remains zero. RAM is not
reduced a second time. The profile records caller-available filesystem space
and online logical CPUs with explicit limitations, no capability or admission.
The known limitation set is exact: an independent read-only review identified
acceptance of arbitrary extension strings, which was corrected and covered by
unknown/duplicate limitation regressions. No production signing occurred.

Final validation command:

```sh
python -m pytest tests/unit/test_resource_projection.py tests/unit/test_commissioning.py tests/unit/test_fabric_boundary.py tests/unit/test_boundary_static.py tests/unit/test_runtime_resource_assessment.py -q
```

Results: **98 passed locally and 98 on the dedicated Debian ARM64 review
tree**, including real pinned Fabric model validation with synthetic inventory
and resource observations. Targeted Ruff, documentation link checks (53 files)
and diff check passed. This follow-up did not rerun the full suite or CI.
No real complete hardware inventory was generated: node/platform/storage
identity collection, topology projection, protected signed-record persistence
and authenticated activation context/health remain unfinished. The VM's
unavailable mission storage is not replaced with a synthetic successful value.

### Reviewed topology projection (2026-10-13)

`fabric_boundary.project_reviewed_topology()` verifies the original local
draft signature against enrolled operator trust and a supplied current
proposal. It revalidates the full Fabric hardware snapshot and its content
digest, then compares the entire projected interface set, including unassigned
interfaces, before constructing assignments. Enumeration order is ignored;
observed name/version changes require a refreshed snapshot rather than silent
rebinding. Roles still bind by composite identity, never by kernel name.

Assignments retain the actual signer and signed confirmation time, use Fabric's
`signed_site_approval` method, and cite the full hardware snapshot digest. They
resolve uniquely against that snapshot. Remaining keys stay unassigned;
all-skip produces no assignment. Management reachability is unknown, capture
and isolation evidence absent. The original signature covers the draft only,
not the new topology/node/snapshot fields. The returned profile contains raw
identities and is not terminal output, an authenticated profile, or admission.
Platform/storage freshness, production inventory collection and protected
signed-record persistence remain unfinished.

Separate read-only review found no concrete implementation bug and requested
a genuine added-interface regression in addition to duplicate-composite
coverage; both are now tested. Final test command:

```sh
python -m pytest tests/unit/test_topology_projection.py tests/unit/test_resource_projection.py tests/unit/test_commissioning.py tests/unit/test_inventory.py tests/unit/test_commissioning_draft_review.py tests/unit/test_fabric_boundary.py tests/unit/test_boundary_static.py -q
```

**136 passed locally and 136 on Debian ARM64**, using ephemeral keys and
synthetic snapshots with pinned Fabric rc2. Targeted Ruff, docs links and diff
checks passed. No full-suite/CI success, real signed topology, production
activation, provider admission or hardware verification is claimed.

### Hardware observation and in-memory projection (2026-10-13)

The runtime `hardware_inventory` collector reads fixed sysfs sources only;
there is no device open, probe, mount or persistence. Class symlinks are
resolved within `/sys/devices`, metadata reads are bounded, required storage
fields have strict numeric/boolean interpretation, and optional platform/
model/serial gaps remain explicit. Whole-device observations exclude virtual
block devices and partitions with a fixed limitation; capacities are not
summed across these layers. Collection is repeated to detect changes, but is
not claimed atomic. `hardware-assess` additionally refreshes netlink and
outputs aggregate counts/limitations only, never raw identity or bare digests.

`collect_hardware_inventory()` connects those observations to the pinned
Fabric model constructor. It requires independently supplied node/inventory
IDs, rejects refused/ambiguous interfaces, and computes the normalized full
record digest. Callers must refresh a cached permanent-address reader before
using the result as a current snapshot. No node ID/key was generated: the
existing protection-key reader is not yet a bounded, ownership-checked trust
reader, and machine-ID-derived node binding has not been adopted implicitly.

Independent read-only review identified two issues fixed before handoff:
failed NIC enumeration could appear empty, and callers could omit applicable
missing-field limitations. The collector now opts into strict enumeration;
missing/disappearing entries raise, while successfully enumerated empty trees
remain distinguishable. Projection refuses suppressed platform/storage
omission markers. Regressions exercise both fixes.

Final command:

```sh
python -m pytest tests/unit/test_hardware_projection.py tests/unit/test_runtime_hardware_inventory.py tests/unit/test_resource_projection.py tests/unit/test_topology_projection.py tests/unit/test_runtime_boundary.py tests/unit/test_boundary_static.py tests/unit/test_inventory.py tests/unit/test_runtime_commission_cli.py -q
```

**127 passed locally and 127 on Debian ARM64**. Targeted source/test Ruff,
documentation links and diff checks passed. The real VM read-only CLI returned
2 observed interfaces, 1 refused interface, 2 observed whole storage devices,
and missing optional platform/storage identity limitations. These counts are
not a complete commissioned snapshot: no real Fabric record was persisted or
authenticated. No full-suite/CI, encrypted-store deployment, signed profile,
activation, provider or hardware-admission success is claimed. Remaining work
includes protected node binding, snapshot completeness for intended roles,
authenticated profile linkage, protected signed persistence and runtime health.

### Protected declared-node reader (2026-10-13)

The implementation specification explicitly declares `node_id` in
`/etc/azazel/node.yaml`; there is no automatic machine-ID identity contract.
The runtime reader now preserves that explicit string and ignores other fields
as authority/evidence. It traverses root-owned non-writable directory ancestors
using descriptors and nofollow, then reads a bounded stable regular single-link
file. It rejects ambiguous YAML, aliases, tags, multiple documents, excessive
depth and implicit non-string node IDs without exposing parser diagnostics.
No node file, key, pseudonym or node digest is generated.

Runtime-only `PyYAML==6.0.3` is pinned, and the wrapper stager checks for its
presence. Review caught an eager-import path that could prevent mandatory
masking if the parser was missing; parsing is now deferred into the guarded
post-mask diagnostic. A regression proves previously enabled recording units
are masked even when importing the parser fails. A protected declaration is
reported only as `protected_declaration_only`; authenticated node identity
remains an absent activation producer, and raw labels never enter audit.

Final tests: **109 locally and 109 on Debian ARM64**, from
`test_runtime_node_config.py`, `test_runtime_activation_inputs.py`,
`test_runtime_boundary.py`, `test_runtime_activated.py`,
`test_runtime_activated_entrypoint.py`, and `test_stage_runtime_entrypoints.py`.
Targeted Ruff, docs links and diff checks passed. Parser packages were installed
only into the existing local/VM test virtual environments. No production
configuration, key, enrollment, service activation, CI or hardware operation
occurred. Full-suite success is not claimed.

Operator classification remains open: whether the declared node label is
restricted to a non-sensitive administrative alias or may contain sensitive
asset identity. Until settled, it is not published. A domain-separated mapping
to activation's node digest and authenticated profile linkage remain required;
the reader does not silently choose them.

### Fresh offline installation check (2026-10-13)

The selected dirty source was bundled, built into both wheels, and installed
with `--no-index` into a fresh Debian ARM64 Python 3.13 virtual environment.
Dependency preparation downloaded wheels online; this is not an air-gapped
preparation claim. A dedicated builder was needed because the earlier test
environment lacked setuptools. `pip check` passed. The real packaging installer
then staged eight wrappers under a temporary `DESTDIR`, explicitly using
`--without-service-manager --without-accounts`. No host services/accounts were
changed. Hashes, exact backend versions, paths and limitations are recorded in
[machine-readable evidence](evidence/offline-install-2026-10-13.json).

Integration review found two corrected mismatches: staging now actually imports
PyYAML/dbus-next and checks the pinned distribution versions rather than merely
finding a module, and the draft reader/exporter accepts the declared `0750`
commissioning directory. That directory remains owner-controlled and rejects
group write/all other-user permissions; payload/signature files still require
owner-only `0600`, nofollow, single links and encrypted-storage/key checks.
Directory group members may observe fixed filenames, sizes and timestamps;
metadata secrecy is not claimed. Installer/ADR directory defaults were not
changed. The final source/wheel run includes both fixes.

Related tests (`test_commissioning_draft.py`, `test_commissioning_draft_review.py`,
`test_stage_runtime_entrypoints.py`, `test_offline_bundle.py`,
`test_packaging.py`) passed **81 locally and 81 on Debian ARM64**; targeted Ruff
passed. No full-suite, CI, account ownership, systemd activation, authenticated
release or hardware verification success follows from this staged install.

### Explicit kernel-loopback collection scope (2026-10-13)

Read-only VM diagnosis found one commissionable ARPHRD type 1 interface and
one uncommissionable type 772 interface. The latter was kernel loopback, not
an incomplete physical adapter. The runtime collector now excludes only an
entry with both exact type 772 and validated virtual/net sysfs placement.
Unknown/missing type or inconsistent location refuses; non-loopback virtual
interfaces remain included. Excluded names are compared across both collection
passes internally, while only their count and fixed limitation may be shown.
The general library inventory is unchanged. The collection-scope clarification
is explicit in commissioning.md, not an implicit relaxation of matching.

The scoped observation supplies `commissioning_proposal()` so topology review
can use exactly the same interface set. This does not wire complete production
commissioning or authenticate a snapshot. Final related selection:

```sh
python -m pytest tests/unit/test_runtime_hardware_inventory.py tests/unit/test_hardware_projection.py tests/unit/test_topology_projection.py tests/unit/test_inventory.py tests/unit/test_runtime_commission_cli.py -q
```

**92 passed locally and 92 on Debian ARM64**. The real VM read-only command now
reports 1 included NIC, 0 refused NICs, 1 excluded loopback and 2 observed whole
storage devices. Missing optional platform/storage fields remain explicit.
Targeted Ruff, docs links and diff checks passed. No interface, key, signed
record or service state changed. The preceding wheel evidence remains bound
to its recorded source snapshot and does not include this later source change;
no wheel rebuild or full-suite/CI success is claimed for this follow-up.

Review found no material exclusion regression and requested the added mixed
loopback/incomplete-NIC test. It also confirmed a remaining integration gap:
the existing CLI draft review still collects the general interface scope.
The scoped-proposal helper is not yet its production input; end-to-end topology
scope alignment remains unfinished and must be wired explicitly.

### Runtime wizard/review scope wiring (2026-10-13)

The preceding callback gap is now connected: library `main()` accepts a
commissioning-proposal reader for commission/review only, and the runtime
operator entrypoint supplies the scoped HardwareObservation proposal. General
library inventory remains unchanged. Before confirmation can export a draft,
and before buffered review success is printed, runtime recollects the hardware
snapshot and compares interfaces, platform, storage and exclusion metadata.
Review identified that cached permanent addresses required a second netlink
check after recollection; checks now bracket recollection. This detects the
tested replacement race, not arbitrary atomicity across kernel subsystems.

The actual runtime-to-library CLI flow is tested with ephemeral signatures,
synthetic protected-input/trust seams and synthetic hardware. Changed platform,
storage, interface fields or loopback exclusion refuse export/success. A link
replacement during recollection is also refused. No real signed draft,
encrypted storage deployment or activation was performed. Related selection:

```sh
python -m pytest tests/unit/test_runtime_commission_flow.py tests/unit/test_runtime_commission_cli.py tests/unit/test_wizard_and_cli.py tests/unit/test_runtime_hardware_inventory.py tests/unit/test_boundary_static.py tests/unit/test_topology_projection.py -q
```

**126 passed locally and 126 on Debian ARM64**. New/changed runtime flow Ruff
passed; existing CLI/test findings remain separate. A VM full-unit run at this
point was **3643 passed / 3 failed / 1 skipped**, with the three known synthetic
HIL-preflight tests leaking the runner's real ARM64 architecture. The test-only
helper now supplies explicit synthetic x86_64 facts, alongside its already
synthetic OS/RAM/TPM/storage facts. A new explicit ARM64 case still refuses at
`A-2` and writes no commissioning record. No production architecture check was
changed. The HIL-preflight module passed **126 locally**. Its existing unused
`argparse` import Ruff warning was reproduced from HEAD and left untouched.

Final VM full-unit verification after the synthetic-platform fixture correction:
**3647 passed / 1 skipped**, 37.99 seconds. Command:

```sh
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit -q --tb=short --basetemp=/home/rabbit/nxsf2
```

An intermediate run returned 3641 passed / 6 failed / 1 skipped because the
chosen longer temporary root exceeded the harness's Unix-socket path limit.
Using the fresh shorter root resolved those six environment-path failures
without product changes. This is local VM unit-suite evidence, not CI, native
amd64 HIL, deployed systemd/D-Bus service success, or production admission.
The explicit ARM64 campaign-refusal regression passes in the same suite.

### Linked full-proposal export (2026-10-13)

The assembler now validates all three Fabric inputs, their inventory/node
bindings, assignment coverage, nested capture/isolation references and times,
and produces a complete **unsigned** proposal. A separate
`commissioning-proposal` signature purpose covers its canonical full bytes;
role-draft and activation signatures cannot substitute. Expected snapshots
are independent arguments, never extracted from an imported candidate to
justify that same candidate. Assembly/signature checks grant no activation.

An explicit `az-nexus-commission proposal-export --operator LABEL` now connects
the real runtime entrypoint to the protected role-draft reader, node/trust
loaders, hardware/resource collection, Fabric projection and fixed encrypted
proposal storage. It requires an interactive `EXPORT` confirmation and
rechecks node/trust/draft and hardware/netlink before writing. UUIDs identify
proposal components, not nodes. Resources keep their actual observation time;
the local assembly clock is not treated as trusted evidence. The CLI emits
only redacted status. Storage uses bounded bytes, owner-only ordinary files,
exclusive creation and fsync. Partial-write/no-progress/fsync failures may
leave a private file; retries refuse overwrite rather than hide that state.

Independent code review found no material flaw in this bounded export path;
it specifically noted that resource observations are historical, not refreshed
after operator confirmation. Regression tests cover changed node, revoked
trust, altered draft, hardware and netlink replacement, missing measurements,
missing protected inputs, storage prerequisites, noninteractive use and
existing destination preservation. A CLI-to-real-temporary-file test exercises
the actual writer; encrypted storage, hardware and enrolled trust are synthetic
seams with ephemeral test keys, not real host provisioning.

Final related local command (**117 passed**):

```sh
PYTHONPATH=src:runtime/src .venv/bin/python -m pytest tests/unit/test_commissioning_approval.py tests/unit/test_commissioning_proposal_storage.py tests/unit/test_commissioning_draft.py tests/unit/test_runtime_proposal_export.py tests/unit/test_runtime_commission_cli.py tests/unit/test_runtime_commission_flow.py tests/unit/test_boundary_static.py tests/unit/test_stage_runtime_entrypoints.py -q
```

Before adding the runtime export, the full linked-proposal selection was 113
passed on Mac and Debian ARM64, and the VM full suite was 3669 passed / 1 skipped
(38.49s, `/home/rabbit/nxsf3`). These counts precede the additional export tests.
After adding the export and storage regressions, final Debian ARM64 full unit
suite: **3702 passed / 1 skipped**, 38.61 seconds:

```sh
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit -q --tb=short --basetemp=/home/rabbit/nxsf4
```

Targeted Ruff, documentation links (53 Markdown files) and `git diff --check`
passed. Pre-existing repository-wide lint findings were not changed. The
following selected-source digest was independently reproduced on Mac and the
VM review tree; this is source synchronization, not installed package evidence.
Selected source/test digest for the final export implementation:
`52e425f96eefafe767d64e2065a0fc56330955eca875564386be04e14af43b16`.
It is SHA-256 of the ordered `shasum -a 256` listing of
`src/azazel_nexus/{commissioning_approval,commissioning_draft,fabric_boundary,operator_trust}.py`,
`runtime/src/azazel_nexus_runtime/{proposal_export,commission_cli}.py`, and
`tests/unit/{test_commissioning_approval,test_commissioning_proposal_storage,test_runtime_proposal_export}.py`.

No real proposal, enrolled key or signature was created. Production signature
import needs independently retained expected context; freshness/clock/epoch/
policy/health and activation composition remain incomplete. Prior wheels do
not contain this code. No CI, physical media, production activation or provider
admission was run; #93 remains open.

### Retained expectations and detached proposal review (2026-10-13)

The runtime export now calls the public `retain_proposal_context` API with
locally collected, typed model inputs. The API rebuilds canonical bytes; it
accepts no imported payload. Under a nonblocking directory lock it exclusively
creates a 0600 `commissioning-proposal.expected.json` followed by the signing
view `commissioning-proposal.json`. Any existing expected/proposal/signature
state refuses without modification. Partial transactions remain for inspection;
no repair, migration, overwrite or deletion is attempted. Legacy one-file
exports cannot acquire retained provenance automatically.

`proposal-review --operator LABEL` reads those two bounded, protected, equal
files and the fixed 64-byte detached signature. It reconstructs expected models
through the Fabric boundary, revalidates canonical bytes and linkage, matches
the configured node and operator, and verifies the full-proposal signature
against current enrollment. It rereads node/trust and the complete file set
before reporting historical approval. No authoritative record is promoted.

Independent read-only review accepted this bounded provenance model: protected
local ownership is trusted, not protected against its privileged owner or
rollback. Validation cannot prove where arbitrary in-process model objects
originated; the actual runtime caller supplies its own collected observations.
Present hardware/resource freshness, trusted time, health, policy/epoch and
activation still need separate evidence and composition.

The first VM full suite caught a genuine layering violation: runtime imported
the private `_retain_proposal_context`. Result: **3755 passed / 1 failed /
1 skipped**, 38.93s (`nxsf5`). The existing runtime-boundary test was not
weakened. The product API was made public with explicit required model arguments,
and regressions reject candidate bytes substituted for any model. Independent
review confirmed this preserves the storage and validation refusals.

Final related local selection: **203 passed**, 1.26s:

```sh
PYTHONPATH=src:runtime/src .venv/bin/python -m pytest tests/unit/test_commissioning_approval.py tests/unit/test_commissioning_retained_review.py tests/unit/test_commissioning_retained_storage.py tests/unit/test_commissioning_proposal_storage.py tests/unit/test_commissioning_draft.py tests/unit/test_commissioning_draft_review.py tests/unit/test_runtime_proposal_export.py tests/unit/test_runtime_proposal_review.py tests/unit/test_runtime_commission_cli.py tests/unit/test_runtime_commission_flow.py tests/unit/test_boundary_static.py tests/unit/test_runtime_boundary.py tests/unit/test_stage_runtime_entrypoints.py -q
```

The integration test exercises actual CLI export → ordinary temporary retained
files → ephemeral detached signature → actual CLI historical review. Only
hardware/node/trust/protection inputs are synthetic. Tests explicitly refuse
missing/partial/changed inputs, wrong purpose/key/node, revoked keys, insecure
files, lock contention, noncanonical data and incorrect cross-record bindings.
Coordinator review corrected two initially weak test setups: signing-transcript
validation had preceded the intended invalid-expected-input check, and missing
file cases had all left only the signature absent. Final cases exercise the
intended verifier and each independently missing file.

Targeted Ruff passed; repository-wide historical findings are not repaired by
this work. Mac/VM selected-source digests match:
`f951b7e5397f644010b6f42e039e9ca10d1f46de8b28937649e77d380d6d4018`.
The ordered listing uses SHA-256 for
`src/azazel_nexus/{commissioning_approval,commissioning_draft,fabric_boundary}.py`,
`runtime/src/azazel_nexus_runtime/{proposal_export,proposal_review,commission_cli}.py`,
and `tests/unit/{test_commissioning_retained_review,test_commissioning_retained_storage,test_runtime_proposal_export,test_runtime_proposal_review}.py`,
then SHA-256 of that listing. The detailed result is recorded in
[retained review evidence](evidence/commissioning-review-2026-10-13.json).

Final Debian ARM64 full unit suite: **3759 passed / 1 skipped**, 38.67s:

```sh
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit -q --tb=short --basetemp=/home/rabbit/nxsf6
```

No production enrollment, private key, real signed record, activation, CI,
physical media or firmware operation occurred. Earlier built wheels remain
historical; this result concerns current source in the dedicated VM review tree.

### Current hardware comparison and activation bridge audit (2026-10-13)

Read-only reviews found no lossless conversion from the full signed Fabric
proposal into the legacy local commissioning record alone: that record binds
roles and profile names, not all signed node/inventory/profile contents and
limitations. No flattened authoritative record was created. No production
renderer, independent epoch/generation high-water store or trusted-clock source
was found. HIL `commissioning.json` is not the production promotion path, and
Edge's existing unsigned-manifest probe was not substituted for authenticated
package admission. These are concrete integration gaps, not hardware results.

The implementable prerequisite now runs through the existing CLI:

```sh
az-nexus-commission proposal-review --operator LABEL --check-current-hardware
```

After retained-signature verification it collects a current full inventory and
validates both Fabric models/self-digests. It compares every content field
except snapshot ID, collection time and digest; neither input is rewritten.
The current time must not precede the retained time, but neither timestamp is
claimed trusted. Strict collection/order comparison conservatively refuses
reordered equivalent data. Hardware/netlink recollection and protected-state
rereads precede success. Default proposal review remains historical; the new
option does not establish resource/capture/isolation readiness or activation.

The complete test flow performs real CLI export, protected temporary-file
retention, ephemeral full-proposal signing and current-hardware review with
synthetic observations. Platform, storage, interface, inventory-scope,
limitation and clock changes refuse, as do hardware/netlink changes during
the second collection. No actual node enrollment or encrypted storage was used.

An assignment-inventory regression also confirms that pinned Fabric already
refuses inconsistent nested assignment digests. No redundant product check was
added. Its agent's initial ambient Python lacked `nacl`; the repository test
environment passed the case. Current-inventory comparison tests normalize and
validate synthetic models, then independently assert their new self-digests
before testing differing content. This avoids falsely crediting content checks
for a malformed-model or stale-digest refusal.

Final Mac related command: **125 passed**, 1.00s:

```sh
PYTHONPATH=src:runtime/src .venv/bin/python -m pytest tests/unit/test_current_inventory_binding.py tests/unit/test_commissioning_approval.py tests/unit/test_commissioning_retained_review.py tests/unit/test_hardware_projection.py tests/unit/test_runtime_proposal_export.py tests/unit/test_runtime_proposal_review.py tests/unit/test_runtime_boundary.py tests/unit/test_boundary_static.py -q
```

Independent read-only review found no material issue with this bounded
comparison; source-order strictness and lack of trusted time remain explicit.
Targeted Ruff, 53-file documentation-link scan and diff check pass. Previous
wheel and full-suite counts remain historical rather than evidence of this
later source. CI, production activation, provider admission, physical media and
firmware operations were not run. The broader activation goal remains open.

Final Debian ARM64 full unit suite: **3781 passed / 1 skipped**, 38.96s:

```sh
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit -q --tb=short --basetemp=/home/rabbit/nxsf7
```

Mac and VM selected-source listing digests match:
`ffb11499a0be547e5628e44056971f260c093e33d1bcce3f62d2e3f3732c6c19`.
The ordered source list and current results are in
[current inventory review evidence](evidence/current-inventory-review-2026-10-13.json).
The digest is SHA-256 of the ordered SHA-256/file-name listing, not a whole
repository or installed-wheel digest.

### Full commissioning evidence → generation/controller binding (2026-10-13)

The retained full signed payload, detached signature and current inventory now
remain separate controller evidence. A private domain-separated HMAC binding
must agree across evidence, generation and signed approval for enforcement;
the legacy local record must match the signed roles, identities and confirmation
provenance as well. Its existing digest meaning is unchanged. Missing optional
binding fields do not alter legacy signed bytes. A bound rollback refuses until
a new forward render and approval can be validated.

The actual activation entrypoint attempts all masks before loading the fixed
protected inputs, follows existing retry/escalation on masking failure, verifies
signature/current hardware and rereads node/trust/key/files before passing the
evidence to the controller. No authoritative record, lease or health is fabricated.
The generated service adds only AF_NETLINK alongside AF_UNIX, retaining empty
capabilities and IPAddressDeny=any. Independent review caught and resolved a
lease-only binding bypass, unintended baseline-tier gating, the initial sandbox
family mismatch, and a mask-retry bypass. Regression tests cover these cases.

Final Mac related tests: **241 passed**, 1.61s. Final Debian ARM64 full unit:
**3857 passed / 1 skipped**, 39.67s, using the existing review environment:

```sh
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit -q --tb=short --basetemp=/home/rabbit/nxsfa
```

The preceding full run had 3853 passed / 1 failed / 1 skipped: its D-Bus test
still expected one masking sweep instead of preflight plus decision. The test
now verifies both ordered sweeps and the preflight audit event. An earlier
pre-transfer run was interrupted after discovering rsync was unavailable on
the VM; it is not current-source evidence. Ordinary-file transfer and matching
source hashes preceded both subsequent complete runs.

Targeted Ruff passes except hardening.py's three pre-existing F401 imports,
confirmed against HEAD and left unchanged. Repository-wide lint was not rerun.
Documentation links (53 files) and diff check pass. Selected source-list digest
matches Mac and VM:
`e5375a6d8fbbe0c403d65d4bd0265c5ea2f183944b3ea8cdae9cf3effa61a7ac`.
Commands, ordered file list, review findings and limitations are recorded in
[commissioning binding evidence](evidence/commissioning-binding-2026-10-13.json).

`systemd-analyze verify` returned 1 because
`/usr/libexec/azazel/az-activated` is not installed in this review VM. No actual
service/sandbox execution is claimed. Tests use synthetic input seams,
ephemeral signing keys and fake D-Bus/recording managers. Earlier installed
wheels do not contain these changes. Production approval/admission, renderer,
policy/epoch/high-water, trusted clock, health and authenticated Edge producers
remain incomplete. No production keys, CI, provider admission, physical media,
firmware operations or production activation occurred; #93 remains open.

### Generation publication transaction (2026-10-13)

Inspection before renderer integration found that `GenerationStore.create()`
previously wrote directly into its numbered, discoverable generation directory.
A mid-write failure could leave that unfinished directory as `current()`.
Creation now snapshots immutable input bytes, serializes cooperating writers
with a nonblocking directory lock, writes private hidden staging, reads it all
back, syncs files/directories and publishes with one rename. New root directory
entries are synced in their parents. Numeric aliases, symlinks and numeric
non-directory generation entries refuse inspection/allocation. A concurrent
advance also refuses a stale rollback publication.

Before publication, failures leave hidden private staging and preserve existing
generations. After publication, a failed parent sync raises
`GenerationCommitUncertain(number)` rather than implying nothing was published.
No automatic retry, cleanup, activation or authoritative record promotion is
performed. This is a storage prerequisite for the missing role renderer, not
that renderer or semantic product admission. Edge's device-specific installer,
fixed names, network values and defaults were not imported.

Independent read-only review caught the new-root parent-sync and numeric-alias
issues; both were corrected and regression-tested. The new file has 18 test
cases using only ordinary temporary files and injected failures, not physical
power-loss testing. Final Mac related run: **84 passed**, 0.69s. Final Debian
ARM64 full unit run: **3875 passed / 1 skipped**, 39.61s:

```sh
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit -q --tb=short --basetemp=/home/rabbit/nxsfb
```

Targeted Ruff, 53-file docs link checks and diff check pass; repository-wide
lint was not rerun. The two-file ordered source-list digest agrees Mac/VM:
`fdf497c3247636bd489b70410529349efe99e7e8f481d59aaee2c8510af9bba0`.
See [generation transaction evidence](evidence/generation-transaction-2026-10-13.json)
for commands and limits. Previous evidence retains its original source scope.
The operational renderer, authoritative commissioning admission/promotion and
production activation producers remain unfinished. No CI, provider admission,
service activation, keys, physical media or firmware operation was performed.

### Protected activation approval reader (2026-10-13)

`activation_store.load_activation_approval` reads fixed private
`/etc/azazel/activation/approval.json` and `approval.sig` using enrolled trust.
Context, operator, time and the local lease ceiling are independent required
inputs, never values copied from the approval. The bounded single-link regular
file reader refuses symlinks, unsafe permissions, bad signatures/purpose/context,
expired/overlong approval and concurrent changes. Shared nonblocking directory
locking is followed by fixed-path reopening, directory identity comparison,
byte rechecks and trust rereading before return. Nothing is created or signed.

Main review caught the stale held-directory descriptor case; reopening the
fixed path and a same-content directory replacement regression address it.
Independent read-only review found no additional material issue and corrected
documentation that still described the reader as upcoming. Synthetic-root
tests exercise the real fixed-component traversal and lock behavior, without
writing host `/etc` or creating production keys.

There are **23 new reader cases**. Final Mac related tests: **109 passed**,
0.56s. Final Debian ARM64 full unit suite: **3898 passed / 1 skipped**, 39.70s:

```sh
PYTHONPATH=src:runtime/src /home/rabbit/nexus-rc2-conformance-20261013/bin/python -m pytest tests/unit -q --tb=short --basetemp=/home/rabbit/nxsfc
```

Targeted Ruff, 54-file docs link checks and diff check pass; unrelated
repository-wide lint was not rerun. The ordered two-file listing SHA-256
matches Mac and VM:
`0ea43723179ef0dde24e289dffb70da9ddd310dbd83d5c43d572a7b7203279c9`.
Commands and scope are in
[approval store evidence](evidence/activation-approval-store-2026-10-13.json).

The [remaining runtime connections](runtime-activation-remaining.md) distinguish
this reader from the still-missing independent context producer and production
wiring. `_run_once` continues supplying no lease. Inspection also established
that the current unsigned observe-only Edge Core package is not the future
rendered-configuration/capture runtime; a descriptive role JSON is not that
missing consumer. No appliance defaults or unsupported wire format were added.
The VM tool lookup did not find Suricata/nft on PATH; no package installation
or capture followed. No CI, production enrollment/keys, provider admission,
service activation, physical media or firmware operation occurred. #93 is open.
# Bootstrap overlay deployment note (2026-10-15)

The installer now ships `/usr/lib/tmpfiles.d/azazel-nexus-bootstrap.conf` for
the volatile `/run/systemd/system.control` directory. Its vendor rule preserves
existing mode/ownership and has no cleanup/removal operation. Only the activation
controller receives the exact writable-path exception; staging does not execute
tmpfiles, and installation does not start helpers. An administrator override or
another tmpfiles rule may change the effective boot result. Inspect the target's
effective configuration and actual directory metadata before bootstrap use.
Successful installation is not proof of reboot creation or hardened runtime
write access. Missing directory setup fails closed and may prevent the controller
from reaching Python. Source/installed-file/closure pins must be refreshed after
this deployment change; old approvals do not authorize newly measured bytes.
See [current composition status](runtime-activation-remaining.md) for the still
incomplete publication/start/readiness and entrypoint wiring.

The selected-bootstrap controller/auditd/commissiond profiles additionally require
fixed pre-exec environment constraints: no login/PAM environment, no environment
files or inherited manager-name list, and the compiled loader/Python removal set.
Installer Python probes use only fixed PATH/LANG/LC_ALL (plus explicit DESTDIR
for staging). Refresh independent unit/installed-file pins after these changes;
old pins are not authorization for new bytes. The protected loaded-unit readers
enforce these constraints; installation success does not prove PID1 behavior.
See [launch evidence](evidence/bootstrap-launch-environment-2026-10-15.json).

Selected-bootstrap installed-file measurement also requires the conventional
Debian CPython3.13 venv metadata/base binding described in the
[implementation contract](IMPLEMENTATION_SPEC.md). Include the lexical venv's
`pyvenv.cfg` as a 0644 pinned regular file (1–4096 bytes) and the 0755
`/usr/bin/python3.13` base file. A copied wrapper interpreter must match the
base file's pinned hash and size. Missing/unsupported metadata refuses without
fallback. Candidate generation is not approval: refresh reviewed independent
manifest/context pins through the existing deployment procedure. This does not
admit the current interpreter/ABI, startup overrides or native loading, and is
not a claim the existing VM test venv is an admitted deployment.

The subsequent current-interpreter guard now checks procfs executable bytes and
observed CPython state before/after full measurement. The selected wrapper must
actually run with `-IS`, exact compiled import paths and bytecode writes off;
the observed final3.13 microversion must match pinned cfg metadata. It requires
the exact `/usr/bin/python3.13` base-executable spelling, with no unpinned alias
fallback; some copied-venv layouts remain intentionally unsupported. The guard
does not qualify native libraries, initial startup overrides or helper lifecycle.
See [current Python evidence](evidence/bootstrap-running-python-2026-10-15.json).

The fixed startup-absence reader now rejects the five compiled override/build/zip
candidates in the [implementation contract](IMPLEMENTATION_SPEC.md), even when
empty or symlinked. Do not delete unexpected files automatically or turn lookup
errors into absence. Diagnose the unsupported deployment and refresh independent
reviewed inputs as needed. This read-only check does not prove historical startup
safety or qualify native libraries, imported modules or systemd helper lifecycle.

An actual ARM64 CPython3.13.5 source backend was compiled/tested using a
disposable user-owned Debian toolchain without package/venv installation.
That build is not an installed runtime or reviewed production wheel: do not
copy the test extension into deployment as admission. Five native smoke tests
now pass; real sandbox/lifecycle/suspend checks remain open. Exact input lock,
build flags, artifact digest and limits are in
[native qualification evidence](evidence/bootstrap-native-qualification-2026-10-15.json).

Selected bootstrap now also requires standard import finders/hooks and bounded
cache metadata over exact approved roots. A parent-directory pin is not a pin
for a cache subdirectory. Unexpected hooks, instance method overrides, mutable
custom cache objects or drift refuse; do not clear/replace them automatically
to manufacture readiness. ZIP routing metadata checks do not establish that
cached tables match archive bytes or that loaded bytecode/module origins are
covered. Those remain separate gates, as recorded in
[import routing evidence](evidence/bootstrap-import-routing-2026-10-15.json).

The first source-prototype admission subset now requires unpacked directories
and ordinary source/native packages. ZIP files may remain candidate inputs,
but ZIP/namespace/sourceless execution is not operationally admitted. Existing
`.pyc` files need their own independent pins; disabling writes does not disable
reads. Otherwise the derived cache location must be absent through protected
ancestry. Module/package metadata and fixed controller main are checked around
full file measurement. `/etc/ld.so.preload` is unsupported and must be absent;
do not delete it automatically to pass. Debian kernel/glibc/native-loader trust
is explicit, not a whole-OS hash claim. See
[loaded-module evidence](evidence/bootstrap-loaded-modules-2026-10-15.json).
