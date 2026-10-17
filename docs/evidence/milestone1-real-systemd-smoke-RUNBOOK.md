# Milestone 1 isolated systemd smoke — Debian 13 test VM

Run manually as root on a disposable Debian 13 VM with systemd as PID 1.
Never run this in CI. This checks a **relocated transient**, not production
activation, commissioned data, or HG-05 provider admission. No VM run has been
performed by the unit tests.

Install the reviewed build and its Python environment using the
[Debian installation procedure](../debian-live-install.md). Record the build
commit, package/artifact digest, OS release, kernel and systemd versions.
Use the same build's checkout and canonical installed daemon wrappers.
Installation must have created the service accounts and operator group.

The installed units declare `ProtectSystem=strict` and `ProtectHome=yes`.
The tool requires `ProtectSystem=strict` before starting; `full` does not make
`/var` read-only and is refused. Isolation relies on systemd's enforced mount
protection and effective write exceptions, so dormant absolute path constants
in imported dependencies no longer prevent this smoke.

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
`/usr/lib/systemd/system` and `/lib/systemd/system`. Drop-ins are refused.
Repeated `[Service]` assignments become separate, ordered `--property`
arguments, including empty resets. Exec hooks other than the single
`ExecStart` are refused. Percent specifiers in all values are refused.
Unreviewed environment, bind mounts and other path directives are refused.
Unsupported transient properties or an unrecognised show representation fail
closed. `[Unit]` dependencies and `[Install]` activation are not applied:
this scratch experiment does not claim to exercise `azazel-activated`.

Before starting, the tool parses the canonical installed wrapper to obtain its
interpreter and import roots for the bounded client. There is no static
import-closure source gate. Isolation works as follows:

- A fresh `/run/azsm-*` scratch root receives only the unit's declared leaves
  and layout ancestors. Owners, groups and modes come from the installer's
  `LAYOUT`, including setgid socket leaves. Real state is never copied.
- `Environment=AZAZEL_ROOT=<scratch>` relocates daemon sockets, route/refusal
  ledgers, Knowledge store and public trust. Local/remote M.I.O. probes target
  absent scratch sockets, so they cannot reach real providers. The bounded
  client uses the installed wrapper's interpreter/import roots and the same
  scratch environment in a fresh process.
- Every `ReadWritePaths`/`ReadOnlyPaths` occurrence is rewritten under scratch,
  retaining reset assignments and path flags. Unknown layout paths refuse.
- After start, `systemctl show` must report `ProtectSystem=strict`, the exact
  private `RuntimeDirectory`, and effective `ReadWritePaths` contained only
  within scratch or equal to that private `/run/azazel-smoke-<name>` directory.
  Missing properties, real state paths, parent paths, relative paths and
  symlink escapes fail. This assertion supplements full property comparison.
  `RuntimeDirectory` is an implicit writable exception under strict protection;
  it need not appear explicitly in `ReadWritePaths`.
- `RuntimeDirectory` becomes `azazel-smoke-<name>`, never shared `azazel`.
  Its mode and all other sandbox directives are retained verbatim. The scratch
  root is outside `/tmp` and `/var/tmp`, which `PrivateTmp` can hide.
- `Type=notify` becomes `Type=exec`: `AZAZEL_ROOT` deliberately suppresses
  READY notification. This explicit startup-protocol exception is recorded;
  it does not validate production notification. No hardening property is
  weakened. User/Group, SupplementaryGroups, capability sets, address families,
  protections, private namespaces, IP denial, syscall filter and UMask remain.

The client retains UID 0 and sets its child process's effective GID to
`azazel-operator`; no account membership changes. Knowledge normally reports
unavailable because scratch has no commissioned store or trust. This smoke
cannot validate a real store's available status; use the separate
[Knowledge trust procedure](../knowledge-lite-trust.md) for that workflow.

Record the exit status and JSON, including failures. Evidence includes original
and relocated directives, the unit file digest, the relocation reason, effective
properties, property mismatch keys, bounded reply and daemon UID from `/proc`.
Every passed Service property except ExecStart is compared automatically with
`systemctl show`, including unknown future hardening keys. Normalisation
retains inverse lists and path flags, and handles set order, boolean encodings,
empty capability sets, octal modes and IP-denial representations. Mixed
positive/inverse repeated lists refuse rather than guess systemd's algebra.
Any missing property or mismatch means FAIL.

The two real daemons and `azazel-activated.service` may already be active:
there is no shared socket or data use. Their `ActiveState` is recorded before
and after and must be unchanged. Before start and after stop, recursive snapshots
cover `/var/lib/azazel/state/mio`, `/var/lib/azazel/state/knowledge`,
`/var/lib/azazel/run`, `/var/lib/azazel/knowledge`, `/var/lib/azazel/lite-trust`
and `/run/azazel`, including absent roots. Each entry records path, inode, mode,
UID, GID, size and nanosecond mtime. Regular files up to 8 MiB also receive
SHA-256; larger files are compared by metadata only. Symlinks are recorded with
their targets and never followed; special files, including sockets, are never
read. Atime is excluded because hashing can update it. Concurrent traversal or
hashing mutations fail closed. Run on a quiescent test VM: any observed change
fails even if caused by another operator or active real daemon.

JSON includes `real_paths_before`, `real_paths_after`, `snapshot_hash_limit`,
`real_path_differences` (paths and changed fields) and
`write_isolation_verified`. Any snapshot difference means FAIL, including on
an otherwise successful daemon/client run. Snapshot read failures also fail.
These bounded observations supplement the enforced write isolation; they do
not detect transient writes reverted between snapshots or same-metadata
content changes in files above the hash bound. No unit is enabled, unmasked or
activated.

`systemd-run --collect` is mandatory. Finally, even after start/client failure,
the tool attempts both stop and reset-failed on only its named transient,
then checks collection and leftovers. Cleanup errors never replace the primary
error. A stopped-but-not-yet-collected unit is given a bounded collection wait.
Scratch is removed after collection is confirmed (or if no start was attempted);
an uncollected unit's tree is retained to avoid removing a running daemon's files. The JSON reports
leftover unit, runtime directory, socket and scratch root, plus cleanup errors;
a leftover or cleanup failure fails the run. A socket left by SIGTERM is
recorded before scratch removal and is removed with scratch. Inspect failures
locally and retain redacted diagnostics, never raw credentials. If interrupted
externally, stop/reset-failed only `azazel-smoke-<name>.service`, verify it has
been collected, and remove only the exact reported scratch root.
