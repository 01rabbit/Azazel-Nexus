# Milestone 1 real-systemd smoke — 2026-10-18

Host: Debian GNU/Linux 13 (trixie) test VM, Linux 6.12.111+deb13-arm64 aarch64,
systemd 257 (257.13-1~deb13u1). Build: `01f0909` (plus the SystemCallFilter
comparison fix committed with this record). Procedure:
[milestone1-real-systemd-smoke-RUNBOOK.md](milestone1-real-systemd-smoke-RUNBOOK.md).
Raw evidence: [`milestone1-smoke-2026-10-18/`](milestone1-smoke-2026-10-18/).

**This is a test VM, not hardware evidence.**

## How the VM was prepared (additive only)

The VM's existing installation is pinned by earlier bootstrap approvals, so it
was not upgraded. Instead, and recorded in `setup.log`:

- a separate venv `/opt/azazel-nexus-m1smoke/venv` with this build's two
  distributions (the unchanged `_bootstrap_deadline` extension was reused from
  the existing venv; its C source is unchanged since `5bb1a62`);
- the accounts `azmioentry` and `azknowledge`;
- the two new wrappers `/usr/libexec/azazel/az-mio-entryd` and
  `az-knowledge-lited`, staged by `tools/stage_runtime_entrypoints.py`;
- the two new unit files in `/etc/systemd/system` (never enabled or started).

All of these were removed after the run (see "Cleanup").

## Results

| unit | ok | verb reply | hardening | real state |
| --- | --- | --- | --- | --- |
| azazel-mio-entryd | yes | `mio.route` → `deterministic handoff`, outcome `refused`, reason "no candidate is permitted besides it", recorded at ledger seq 4 | every declared property matched; SystemCallFilter 389 observed ⊆ 394 declared, none undeclared | unchanged; real units unchanged (`azazel-activated` stayed `failed` from an earlier deadline test) |
| azazel-knowledge-lited | yes | `knowledge.status` → `unavailable` / `trust_unreadable` (no trust in scratch: fail-closed) | same | unchanged |

Both ran as their own accounts (uid 984 / 983) with `AF_UNIX` only, no
capabilities, `NoNewPrivileges`, `ProtectSystem=strict`, `IPAddressDeny=any`,
and write access confined to scratch (`write_isolation_verified`). No
transient unit, socket, runtime directory or scratch tree was left behind.
`@system-service` itself includes `@chown`/`@setuid` members (18 names); they
are reported as `declared_dangerous`, and with no capabilities and
`NoNewPrivileges` they cannot change identity.

## What this does not establish

- The real `/var/lib/azazel/...` directories and their owners: the run used a
  scratch tree built from the installer layout.
- `Type=notify` readiness: `AZAZEL_ROOT` suppresses READY, so the transient
  used `Type=exec` and readiness was inferred from the socket.
- Activation gating (`Requires=azazel-activated.service`), commissioned trust,
  a real Knowledge bundle, or any provider admission (HG-05 unmeasured).
