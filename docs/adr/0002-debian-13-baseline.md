# ADR-0002 — Nexus adopts the Debian 13 / amd64 platform baseline

Status: **accepted (2026-09-22)** · Supersedes nothing · Revises
[`IMPLEMENTATION_SPEC.md`](../IMPLEMENTATION_SPEC.md) §2 and §12,
[`support-matrix.md`](../support-matrix.md) §3 and §7

## Context

The platform was undeclared. `IMPLEMENTATION_SPEC.md` §2 said "a supported
long-term-support Linux distribution", and
[`support-matrix.md`](../support-matrix.md) §7 carried "OS distribution and
release" and "Kernel series" as **undeclared** rows, to be resolved "by an
owner decision or a measurement, not by a contributor choosing a plausible
value".

Two products were about to answer the question separately: Nexus was writing
an installer preflight and Boot was describing its media, and neither had a
distribution to write down.

The owner decided the frame at program level on 2026-09-22, as
[program plan §15, finding OF-07](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/nexus-boot-program-plan.md).

## Decision

**D1. Nexus adopts the OF-07 frame unchanged.** The baseline is **Debian 13 /
amd64**, installed from a signed netinst or a verified offline install bundle,
with `main` plus `non-free-firmware`; UEFI with Secure Boot enabled by default
where supported; LUKS2 required, a TPM2 key protector optional and a recovery
passphrase required; updates as signed bundles against a pinned apt snapshot
with no automatic update.

This ADR **records** that decision. It does not re-decide it, restate it more
strongly, or extend it. Where a Nexus document describes the platform, it
cites program plan §15 OF-07 and this ADR rather than a Nexus-local
restatement — the rule
[`test_repository_status_claims.py`](../../tests/unit/test_repository_status_claims.py)
already applies to another product's pin: *cite the record; do not copy it.*

**D2. The undeclared rows move rather than being guessed.** "OS distribution
and release" leaves §7 for §3, citing OF-07. "Firmware/boot path requirements"
leaves §7, resolved by OF-03 and OF-07 together. This follows the CPython
precedent in §3.3: a row is moved out of §7 by an owner decision, never by a
contributor choosing a plausible value.

**D3. The kernel series stays undeclared, and is now bounded.** Debian 13
ships a kernel series; this ADR does not name it, because a point release
changes it without changing the baseline, and a series written here would be
a number nobody measured. It is recorded per entry, as the `os_abi` of the
first tested compatibility tuple.

**D4. The preflight refuses a host that is not on the baseline.** `A-2` when
the architecture is not `x86_64`, `A-3` when `os-release` does not report
`ID=debian` and `VERSION_ID=13`. The match is on those identifiers and never
on `PRETTY_NAME`, which is prose a vendor may rewrite between point releases.

**D5. A host that cannot provide LUKS2 is refused, and nothing is written to
it.** No raw identity reaches a commissioning record, hardware-in-the-loop
measurement and operational deployment are both refused, and the host may be
used for diagnostics only. This is the existing `A-7` refusal, named here as
the disposition it produces.

**D6. The 8 GiB pilot is a Debian 13 / amd64 campaign.** `HG-05` measures a
reserve under one kernel, one allocator and one service manager, and those
belong to the distribution. A record taken on another distribution is a record
of another platform, and nothing in this build can say by how much they
differ.

## Alternatives considered

**Leave the rows undeclared until the first machine is tested.** This is what
§7 prescribes in general, and it is why the rows sat there for as long as they
did. It fails here for a specific reason: the preflight has to answer
`HIL_PREFLIGHT_READY` or `HIL_PREFLIGHT_BLOCKED` on a host, and a preflight
with no baseline accepts whatever it finds — which would make the first
campaign's evidence describe a platform chosen by whoever installed the
machine.

**Declare a family rather than a release** ("a Debian-derived distribution").
A family is not a measurement target: the reserve differs between members, and
the preflight would have to accept a set whose members it cannot compare.

**Declare several co-equal distributions.** A campaign run across two produces
evidence for neither. The alternatives are kept, as a
[future evaluation profile](https://github.com/01rabbit/Azazel/blob/main/docs/roadmaps/future-platform-profiles.md),
and they move only by a campaign with a recorded result.

## Consequences

- `IMPLEMENTATION_SPEC.md` §2 and §12, `support-matrix.md` §3 and §7,
  [`hil-preflight.md`](../hil-preflight.md),
  [`deployment-candidates.md`](../deployment-candidates.md) and
  [`core-reserve-measurement.md`](../core-reserve-measurement.md) are revised
  in the same change as this ADR.
- `hil_preflight.py` carries the baseline as three constants, and
  `tests/unit/test_hil_preflight.py` drives a host off the baseline on each
  of them.
- The Fabric pin does not move. The baseline is recorded per entry in the
  `os_abi` of a tested compatibility tuple, a field that exists at
  `v0.9.0rc2`; no Fabric change and no re-pin follows from this ADR.

## What this ADR does not establish

- That Debian 13 has been installed on anything. No image has been built, no
  host installed, and no measurement taken.
- That the baseline is correct for the machine that will eventually be
  chosen. It is the platform the campaign will measure, not a claim about a
  machine.
- That any other distribution has been evaluated. None has.
