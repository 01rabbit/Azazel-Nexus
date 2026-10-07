# Nexus packages in a user-prepared Debian Live environment

Status: **installation contract and path inventory; not hardware-qualified**.
This describes how the current source tree expects its Python packages and
systemd files to be laid out. It does not claim that a particular Debian Live
image, persistence mode, machine, or release has been tested.

## What the installer is

`packaging/install.sh` is the privileged host-integration step, not a
self-contained installer. The project has two Python distributions:

- `azazel-nexus` provides the `azazel-nexus` operator CLI;
- `azazel-nexus-runtime` provides the eight service entrypoints named by the
  packaged systemd units and depends on `azazel-nexus`.

Both must already be installed in a Python environment. The systemd units
execute fixed wrappers under `/usr/libexec/azazel`; ordinary Python installs
put console scripts in the environment's `bin/` directory instead. The
`tools/stage_runtime_entrypoints.py` command creates the unit-backed wrappers
from the runtime distribution declarations. It stages no operator-only tools
and accepts no caller-supplied executable or unit names.

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
- the runtime distribution and all eight module entrypoints are importable
  from that Python environment (the staging tool checks this before writing).

The installer does **not** create the Python environment, install packages,
download inputs, or configure Live persistence. Provision the venv separately
with a Python 3.11+ interpreter and its venv/pip support, then install both
verified distributions and their dependencies into it. On an offline target,
carry the verified wheelhouse to the Live system and confirm imports before
running the installer. For example, create the environment with
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

The generated wrappers keep the absolute interpreter path in their invocation.
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

The offline source bundle built by `tools/build_offline_bundle.py` contains
both distributions' declared source, README/license build metadata, installer,
and wrapper-staging tool. It is **not** a wheelhouse and does not contain built
distributions or the setuptools build backend (`setuptools>=68`). This
repository currently has no published, signed Nexus wheel set. To install from
source offline, the operator must independently provide and verify a compatible
build backend and the pinned `dbus-next==0.2.3` wheel; the bundle itself does
not establish authenticity or provenance for generated wheels. Do not infer a
ready-to-install package from the source bundle.

For a **local, unreleased prototype only**, this source bundle was successfully
built on the preparation host with `uv build` and its isolated PEP 517 backend:

```sh
cd /path/to/extracted/Azazel-Nexus-source
uv build --wheel --out-dir /path/to/wheelhouse .
uv build --wheel --out-dir /path/to/wheelhouse ./runtime
```

The target's Python installer can then be pointed only at those local files:

```sh
/opt/azazel-nexus/venv/bin/python -m pip install \
  --no-index --find-links /path/to/wheelhouse \
  azazel-nexus==0.0.1.dev0 azazel-nexus-runtime==0.0.1.dev0
```

This demonstrates a prototype source-to-wheel route, not reproducible or
authenticated publication: `setuptools>=68` is not pinned, the temporary
build selected a host-resolved backend, and `uv` is not a production builder
selection. Record and independently verify the source bundle, build backend,
and wheel hashes for each preparation; do not treat local hashes as a
signature or product release approval.

## Paths created or required

| Path | Role | Persistence consideration |
| --- | --- | --- |
| `/opt/azazel-nexus/venv` | Example location for the two installed Python distributions | Must survive reboot if used by staged wrappers |
| `/usr/libexec/azazel/` | Fixed wrappers invoked by systemd units | Must survive reboot |
| `/lib/systemd/system/` | Eight runtime unit files, including `azazel-activated.service` | Must survive reboot; Debian may expose this through merged `/usr` |
| `/lib/systemd/system-preset/99-azazel-nexus.preset` | Nexus unit preset | Must survive reboot |
| `/etc/systemd/system/` | `systemctl mask` links and the enabled-controller link | Must survive reboot; these links encode the installer's safe unit state |
| `/etc/azazel/` | Base configuration and systemd drop-in directories | Persist configuration needed after reboot; `/etc/azazel/commissioning/commissioning.json` contains raw identity and must be on LUKS-backed storage before it is written |
| `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` | Account databases changed by `useradd`/`groupadd` | Must survive reboot while installed services rely on the declared system accounts |
| `/var/lib/azazel/state/` | Audit and other durable state | Persist if the operator requires that state to survive reboot |
| `/var/lib/azazel/generations/` | Verified generation trees | Persist if generations are to remain available after reboot |
| `/var/lib/azazel/secrets/commissioning.key` | Root-only HIL-preflight protection key | The installer does not create it; preflight requires it and independently refuses to write the commissioning record unless `/etc/azazel/commissioning` is LUKS-backed |
| `/var/lib/azazel/fetch/`, `/var/lib/azazel/mio/`, `/var/lib/azazel/remote/` | Optional fetch staging, local model, and remote registry state | Needed only when those later workflows are configured; they are not populated by this installer |
| `/var/lib/azazel/run/` | Runtime sockets and short-lived probe/measurement records | Treat as runtime data, not durable state; stale records have TTLs and sockets are recreated |
| `/run/azazel/` and service-specific runtime directories | systemd-created volatile runtime directories | Recreated by systemd; do not require persistence |

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
oneshot for the next boot.

This branch's tests can establish the composition wiring and simulated D-Bus
method contracts, but no real systemd/D-Bus operation or Debian Live boot has
been performed. In particular, no authenticated lease/commissioning loader
exists, so a fresh install cannot advance from the masked state into the
commissioning service through activation. That bootstrap path and the remaining
operator-flow stages stay open under Issue #93; provider admission, online
acquisition, Edge activation, actual systemd enforcement, and Debian Live
verification are not established here. This guide must not be read as a claim
that Nexus is ready for field operation on Debian Live.

The controller's local decision chain lives at
`/var/lib/azazel/state/activation.jsonl`. It is deliberately separate from the
`az-auditd` shared segmented chain and is not signed or anchored; no central
audit-integration claim is made by this composition.
