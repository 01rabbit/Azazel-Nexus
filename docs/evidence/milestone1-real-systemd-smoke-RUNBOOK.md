# Milestone 1 real systemd smoke — Debian 13 test VM

Run manually as root on a disposable Debian 13 VM with systemd as PID 1.
Never run this in CI. This checks the installed service sandbox and bounded
socket exchange; it does not close HG-05 or grant provider admission.

Install the reviewed build and its Python environment using the
[Debian installation procedure](../debian-live-install.md). Record the build
commit, package/artifact digest, OS release, kernel version and systemd version.
Use the same build's checkout for the tool and installed daemon wrappers.
Installation must have created the declared accounts, operator group and
writable state/socket leaves. Keep the governed units masked and disabled;
do not activate them for this smoke. If either target is already running,
use a fresh VM. Investigate any pre-existing socket rather than deleting it.

From the reviewed checkout, with the installed Python environment available:

```sh
sudo env -u AZAZEL_ROOT -u CI PYTHONPATH=src:runtime/src \
  /opt/azazel-nexus/venv/bin/python tools/systemd_unit_smoke.py \
  azazel-mio-entryd > mio-entry-smoke.json
sudo env -u AZAZEL_ROOT -u CI PYTHONPATH=src:runtime/src \
  /opt/azazel-nexus/venv/bin/python tools/systemd_unit_smoke.py \
  azazel-knowledge-lited > knowledge-smoke.json
```

The tool reads `/etc/systemd/system` first, skipping `/dev/null` masks, then
`/usr/lib/systemd/system` and `/lib/systemd/system`. It refuses drop-ins because
a base file alone cannot reproduce their overrides. Every `[Service]` directive
is parsed and passed to `systemd-run`; unsupported transient properties fail
the run. `[Unit]` dependencies and `[Install]` activation are deliberately not
applied. The transient names are `azazel-smoke-azazel-mio-entryd.service` and
`azazel-smoke-azazel-knowledge-lited.service`.

The client retains UID 0 and temporarily uses `azazel-operator` as its effective
GID for the exchange, then restores it. The verbs admit OPERATOR; ROOT alone
is insufficient. No account database membership is changed.

The only added property is `RuntimeDirectoryPreserve=yes`: the installed
services share `/run/azazel`, which smoke cleanup must retain. Record this
exception with the evidence. The smoke uses real installed state/store paths,
so M.I.O. appends its normal metadata-only route ledger. It sends no prompt,
provider request body, key or endpoint. It does not enable, unmask or change
activation state for the governed units.

Record exit status and each JSON summary. Successful evidence includes the
source unit digest, parsed directive names, bounded reply, active transient
state, main PID's UID from `/proc`, effective sandbox properties from
`systemctl show`, and a successful stop. Compare the effective properties to
the installed service declarations; retain empty capability sets, AF_UNIX,
path restrictions and the explicit runtime directory preservation exception.
Knowledge may validly report unavailable with a reason when no store/trust is
commissioned. To test available status, prepare the store and separate trust
using the [Knowledge trust procedure](../knowledge-lite-trust.md), then repeat.
Use fixture public trust only on the disposable VM.

A failure emits only its exception type to avoid leaking configuration.
Inspect the transient's journal locally and retain a redacted diagnostic;
do not attach raw environment, trust documents or credentials. The tool always
attempts `systemctl stop` after starting. If interrupted externally, stop only
the named transient smoke unit. Confirm the real units' masks and disabled
state are unchanged, and attach those observations to the evidence record.
