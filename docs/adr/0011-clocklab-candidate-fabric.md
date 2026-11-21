# ADR-0011 — The clocklab candidate Fabric is installed by hand and is not the pin

Status: **accepted for the current PR candidate (2026-11-21)**; does not approve a
Nexus release, merge, trust-root change, or deployment. Amends nothing in
[ADR-0001](0001-fabric-pin.md) or [ADR-0009](0009-fabric-pin-v0-10-0.md).

## Context

The explicit lab clock contract (Knowledge Context v2, commissioning proposal v4)
needs `azazel_fabric.knowledge_context_clocklab`. It exists only in Azazel-Fabric
`a4fa5535d3d0a0c9ed2694ea15b4b474ed587aa1` (`0.10.1.dev0`), an unpublished
development build with no tag or release digest. Against `v0.10.0` that commit
adds the clocklab module and changes `version.py`; no existing contract changes.

An earlier revision of this candidate moved the `fabric` extra, `uv.lock`,
`FABRIC_PIN`, the wheelhouse builder and both target locks to that commit.
ADR-0001 requires an exact tag, "never a branch or a development commit", and
ADR-0009 records `v0.10.0` as the published pin. Azazel-Knowledge keeps the same
split: its stable `api` extra stays on `v0.10.0` and the clocklab profile is the
separate `api-context-candidate`, "not to be combined".

## Decision

1. `FABRIC_PIN`, the `fabric` extra, `uv.lock`, the wheelhouse builder and both
   target locks stay on `v0.10.0` (`397fcce`).
2. The candidate is identified by its wheel hash, not by its version string. Its
   own file, `packaging/offline/lab/requirements-clocklab-candidate.lock`,
   pins `azazel-fabric==0.10.1.dev0` (commit `a4fa553`) at
   `sha256:9f9926bcb03ec50ae6feac2185041c07cb4b83a1cb28df7e68ff5fb102317e6e`.
   `packaging/offline/lab/install-clocklab-candidate.sh <wheel dir>` compares
   the wheel to that hash and refuses a mismatch, then installs with
   `pip --require-hashes --no-deps`. It is installed instead of the `fabric`
   extra, never together with it. No extra, stable lock, `uv.lock` or the
   default wheelhouse path carries it
   (`tests/unit/test_clocklab_candidate_lock.py`). The wheel is reproduced with
   the pinned backend of `tools/build_wheelhouse.py` (`SOURCE_DATE_EPOCH=315532800`).
   After `pip install` the installer compares every file of the wheel's RECORD
   with the installed file, so an older build of the same version that was kept
   fails the install. `fabric_boundary` still only recognises the version string; the hash
   check is the install-time gate, so a wheel that claims `0.10.1.dev0` without
   passing it is outside this decision.
3. `fabric_boundary` recognises the candidate by the exact version string
   `0.10.1.dev0` (`CLOCKLAB_CANDIDATE_FABRIC_VERSION`), and only in the
   commissioning projections a v4 proposal passes through. Every v2 entry
   (`clock_contract*`, `validate_clocklab_*`, `canonical_clocklab_request`,
   `clocklab_response_*`) requires that exact version even when the module can be
   imported, and otherwise raises `ClocklabUnavailable` (a
   `KnowledgeContextUnavailable` and an `ImportError`). The runtime reaches
   Fabric only through these functions (`tests/unit/test_runtime_fabric_boundary_static.py`).
   Every other
   projection, the explanation ledger and the tested-tuple check still require
   the pin and report "pinned Fabric is required" otherwise.
4. Without the candidate there is no v2 and no fallback to v1: the clocklab
   modules are not importable, v4 export and v2 requests refuse, and a v2
   technique record is shown as not usable.
5. Tests that need the clocklab module skip against the pinned tag. They are
   run, and must pass, in a second environment with the candidate installed.

## Consequences

Evidence for the lab candidate comes from the candidate environment only; the
pinned-tag run does not count for it, and the candidate run does not count for
the pin. The wheelhouse and offline target do not yet carry the candidate.
