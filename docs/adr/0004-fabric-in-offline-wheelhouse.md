# ADR-0004 — Fabric is optional for CORE, required for commissioned activation, and carried in the offline wheelhouse

Status: **accepted (2026-10-28)** · Successor to [ADR-0001](0001-fabric-pin.md)
(amends its packaging consequences; its decisions 1–5 stand) · Revises
[`debian-live-install.md`](../debian-live-install.md) §Offline install bundle

## Context

ADR-0001 declared Fabric an optional extra so that `CORE` keeps working with
nothing installed. That remains true of `CORE`. It is not true of activation:

- every production activation pass calls `daemon.activate(...,
  require_commissioning_evidence=True)` with evidence from
  `azazel_nexus_runtime.commissioning_input.load_commissioning_evidence`
  (`runtime/src/azazel_nexus_runtime/activated.py`);
- that loader projects the current hardware through
  `fabric_boundary.project_hardware_inventory`, which raises
  `CommissioningRecordUnavailable("pinned Fabric is required")` unless
  `azazel_fabric` at the pinned version imports;
- the offline wheelhouse lock (`packaging/offline/requirements-x86_64-cp313.lock`)
  pinned only `dbus-next` and `PyYAML`.

So a node installed the supported offline way could never pass a commissioned
activation. This was reproduced on 2026-10-28 in an emulated x86_64 Debian 13
container: a bundle built from `ee52a38` installed with `--network none`,
and the projection refused with "pinned Fabric is required".

ADR-0001 §Consequences anticipated this: making Fabric present at runtime
needs "a Nexus release artifact that vendors its dependencies", and a
successor ADR. The offline bundle is that artifact.

## Decision

1. **`CORE` stays Fabric-free.** `pyproject.toml` keeps `dependencies = []`
   and Fabric as the optional `fabric` extra; the "CORE imports with nothing
   installed" CI job and
   `test_the_fabric_pin_is_an_optional_extra_and_not_a_required_dependency`
   are unchanged. Nothing here moves Fabric into either distribution's
   `dependencies`, so a development install without the extra still runs CORE.

2. **Commissioned activation requires pinned Fabric.** This is not new
   behaviour; this ADR records it as intended. Without Fabric the activation
   pass refuses (fail-closed) rather than granting anything; that is kept.

3. **The offline wheelhouse carries Fabric and its closure.** The lock pins
   `azazel-fabric==0.9.0rc5` plus `pydantic`, `pydantic-core`,
   `annotated-types`, `typing-extensions` and `typing-inspection` at the
   versions and wheel hashes `uv.lock` already records for the extra.
   `tools/build_wheelhouse.py` derives the expected set from the `fabric`
   extra and `uv.lock` (`BUNDLED_EXTRAS`, `bundled_extra_closure`) and refuses
   any drift; `tools/offline_bundle.py install` refuses a bundle that lacks
   any locked wheel and imports `azazel_fabric.provisioning_contracts` and
   `pydantic_core` after installing.

4. **How the Fabric wheel is made and pinned.** Fabric publishes no wheel (not
   on PyPI, no release asset), and pip cannot hash a VCS requirement under
   `--require-hashes`. The builder therefore follows the pattern it already
   uses for the Nexus wheels — build from a fixed source tree with the
   hash-pinned backend, `--no-build-isolation --no-index` — and adds what the
   Nexus wheels lack, a content pin:
   - a bare `git clone` of the repository; `refs/tags/v0.9.0rc5^{commit}` must
     equal the pinned commit (`SOURCE_BUILDS`, which the tests tie to
     `uv.lock` and `fabric_boundary.FABRIC_PIN`);
   - `git archive` of that commit with `tar.umask=0022`, extracted with the
     archive's modes, so the tree does not depend on the builder's umask;
   - the resulting wheel must equal the sha256 in the lock, or the build is
     refused. Pinning the build output turns the commit pin into a content
     pin and makes any builder or backend drift visible at build time.

   The pinned hash was reproduced bit-for-bit on Debian 13 CPython 3.13.5,
   pip 25.1.1, setuptools 84.0.0 in an x86_64 (Rosetta-emulated) container
   and an aarch64 container. Reproducibility on other pip versions is not
   claimed; a mismatch is a refusal, not a silent rebuild.

5. **Fabric's release signature is not verified by Nexus.** Fabric signs a
   content digest of each release (`release/v0.9.0rc5.digest.json(.sig)`,
   checked by Fabric's `tools/rc_signature.py` against
   `release/signing-keys.json`). That key is **not** a trust anchor Nexus
   holds, and reading it from the same repository the build fetches would be
   self-vouching. The pin is therefore the tag-to-commit check plus the wheel
   hash only. Adopting Fabric's release key as a Nexus anchor (and verifying
   the digest signature in the builder) is an owner decision left open.

6. **x86_64 only, for now.** The bundle format declares one target,
   `debian-13-x86_64-cp313`. An aarch64 lock (with the aarch64
   `pydantic-core` wheel) belongs with an aarch64 target and is not added
   here.

## Alternatives considered

**Move Fabric into `runtime/pyproject.toml` `dependencies`.** Rejected: every
development and CI install of the runtime would then need GitHub access and
pydantic, and the optional/required line would move from "what a deployment
carries" to "what any install of the service layer needs", which ADR-0001
rejected for good reasons that still hold.

**Commit a prebuilt Fabric wheel into this repository.** Rejected: a binary
nobody can rebuild from a reviewed checkout is weaker than a hash any builder
must reproduce from the pinned commit.

**Make commissioning evidence optional when Fabric is absent.** Rejected: it
would let an install lacking a contract library narrow the activation gate.
Absence must refuse, not widen.

## Consequences

- The offline build host needs `git` and HTTPS access to GitHub as well as
  PyPI (it is already the online half of the path).
- The bundle grows by six wheels; `pydantic-core` is native, so its wheel is
  architecture-specific and the lock is per target.
- Moving the Fabric pin (rc6, `v0.9.0`) now means updating, together:
  `pyproject.toml`'s extra, `uv.lock`, `fabric_boundary.FABRIC_PIN`,
  `SOURCE_BUILDS` and the lock's Fabric hash. The tests refuse any one of
  them moving alone.
- Azazel-Edge's deterministic arbiter remains the only decision and
  enforcement authority. Fabric present or absent changes no grant by itself.
