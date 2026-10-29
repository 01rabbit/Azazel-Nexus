# ADR-0005 — The offline install bundle has an Arm lab target, not a second baseline

Status: **proposed (2026-10-29)**, with defaults adopted by the implementing
change; the owner may change any of them · Supersedes nothing · Leaves
[ADR-0002](0002-debian-13-baseline.md) unchanged · Extends
[ADR-0003](0003-arm-software-verification-profile.md) and amends
[ADR-0004](0004-fabric-in-offline-wheelhouse.md) decision 6 for a lab target
only

## Context

[ADR-0003](0003-arm-software-verification-profile.md) names Arm as the
`lab-software-verification` platform profile `debian-13-arm64-cp313-lab` and
leaves "the arm64 offline-bundle target and lock" as a follow-up.
[ADR-0004](0004-fabric-in-offline-wheelhouse.md) decision 6 declared one
bundle target, `debian-13-x86_64-cp313`, and said an aarch64 lock "belongs
with an aarch64 target".

Without that target, an Arm VM could only be installed from the network (the
`pip` of the VM rehearsals), so the offline path — extraction, the lock
check, the no-index install, `recheck`, `install.sh` — was never exercised on
the CPU the lab actually has. Two wheels in the closure are native
(`pydantic-core`, `PyYAML`), and the runtime's `_bootstrap_deadline` is a C
extension, so the x86_64 wheelhouse cannot stand in.

## Decision

**D1. The deployment baseline does not move.** ADR-0002 D1, D4 and D6 and
ADR-0003 D1 stand as written. The default target of
`tools/build_wheelhouse.py` and `tools/build_offline_bundle.py` stays
`debian-13-x86_64-cp313`, its lock stays
`packaging/offline/requirements-x86_64-cp313.lock`, and the
[HIL offline-install runbook](../hil-runbooks/offline-install.md) uses that
target only.

**D2. One more declared target, `debian-13-aarch64-cp313`, with purpose
`lab-software-verification`.** `tools/offline_bundle.py` `TARGETS` gives each
target its `lock`, its `platform_profile_id` and its `purpose`. The aarch64
target names `debian-13-arm64-cp313-lab`; tests hold every target's purpose,
CPU spellings (kernel, Debian), OS and Python tag equal to its reviewed
profile in `platform_profile`, and to what the `install.sh` platform
evaluation (ADR-0003 R6) selects for the same host. A target is still
defined in code and never read from a manifest. The aarch64 target refuses a
filled Edge slot at build and at verify, because the only reviewed Edge pin
is an x86_64 artifact.

**D3. The lock is per target.** `packaging/offline/requirements-aarch64-cp313.lock`
pins the same names and versions as the x86_64 lock (tested against the
pyproject files and the `fabric` extra's `uv.lock` closure). The pure wheels
carry the same hash; `pydantic-core` and `PyYAML` carry the manylinux aarch64
cp313 file that PyPI publishes (checked against PyPI's JSON API on
2026-10-29; `pydantic-core`'s also equals `uv.lock`'s). `azazel-fabric` is
built from the pinned commit exactly as in ADR-0004 and must reproduce the
same sha256. `verify`, `recheck` and `install` check a bundle against the
lock of **its manifest's target** only, so an aarch64 wheel never satisfies
the baseline lock and the other way round, and a bundle relabelled to the
other target is refused by its native wheels' tags.

**D4. A lab target is chosen by name and says what it is.** The builders take
`--target`; without it they build the baseline, and a lab wheelhouse given to
the baseline bundle builder (or a baseline wheelhouse to the lab one) is
refused. `wheelhouse.json`, the `verify` / `install` report and the `recheck`
report carry `platform_profile_id`, `purpose` and, for a lab target, a
`purpose_note` saying it is VM software-integration evidence at most.

**D5. The installed purpose is the host's, not the manifest's.** After the
no-index install, `install` runs the installed runtime's
`platform_observation.select(observe())` and refuses unless the observed
profile and purpose equal the target's. The report records the observation
(`install.observed_platform`). `install.sh` then evaluates the CPU again and
prints its lab notice, as it already did.

**D6. No production reader accepts an Arm bundle, wheelhouse or install
record.** None exists for any target today — no module under `src/` or
`runtime/src/` reads a bundle report, `wheelhouse.json` or an install
evidence record, and a test holds that. Every production use (model
admission, product admission, HIL preflight, a hardware-gate record, a
core-reserve record) still requires a `DeploymentBaseline`, which refuses the
lab profile (ADR-0003 D4). This change adds no switch, environment variable
or setting that would accept Arm in production.

## What was observed

[A container record](../evidence/offline-install-aarch64-lab-container-2026-10-29.json)
(2026-10-29): the wheelhouse and bundle were built in a `debian:trixie`
linux/arm64 container running natively on the aarch64 colima VM of a macOS
host (Debian CPython 3.13.5, pip 25.1.1, uid 1001, umask 022); the Fabric
wheel reproduced the locked hash. The bundle then installed with
`--network none` in a `debian:trixie` arm64 container holding only `python3`
and `python3-venv`: lock check, `pip --no-index --require-hashes`,
`pip check`, imports (including the aarch64 `_bootstrap_deadline`,
`pydantic_core` and Fabric's contracts), the observed profile
`debian-13-arm64-cp313-lab`, `recheck`, and `install.sh
--without-service-manager` all passed, and on that host every production use
refused the profile with `LAB_PROFILE_NOT_FOR_PRODUCTION`.

That is a **container** result. It is not Arm hardware, not an Arm VM with
systemd (no unit, service or activation was exercised), and not evidence for
any hardware gate.

## Alternatives considered

**Use the x86_64 lock with extra aarch64 hashes.** A lock is the reviewed
statement of what one target installs; mixing CPUs would let an x86_64
bundle carry an aarch64 wheel the lock check accepts, and would make the
baseline lock change whenever the lab does.

**Name the target `debian-13-aarch64-cp313-lab`.** The profile id already
ends in `-lab` (ADR-0003 D3), and every report carries the purpose; the
target keeps the `debian-13-<uname -m>-<python tag>` form of the existing
target. The owner may prefer the suffix on the target as well (see below).

## Open for the owner

- Whether the target identifier should also end in `-lab`.
- An arm64 Edge Core pin (ADR-0003 R4). Until it exists, a filled Edge slot
  on the aarch64 target is refused by `build_offline_bundle.py` and by
  `verify` / `recheck` / `install` (`TARGETS[...]["edge_slot"]` is false), so
  the x86_64 Edge artifact cannot ride in an Arm bundle.
- Repeating the offline install on a real Arm VM with systemd, which would
  make it VM software-integration evidence (ADR-0003 D5) — still not a
  hardware gate.

## What this ADR does not establish

- That anything is installed on Arm hardware or on an Arm VM by this path.
- That Arm is a deployment target. It is not.
- That the two Nexus wheels are reproducible on aarch64. They are recorded by
  the hash the build produced, as on x86_64.
