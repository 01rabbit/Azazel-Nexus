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
2. The candidate is installed by hand in a lab environment, instead of the
   `fabric` extra, never together with it:
   `pip install "azazel-fabric @ git+https://github.com/01rabbit/Azazel-Fabric.git@a4fa5535d3d0a0c9ed2694ea15b4b474ed587aa1"`.
   No extra, lock or offline bundle carries it. An offline lab bundle for the
   candidate is a separate, reviewed build and is not part of this change.
3. `fabric_boundary` recognises the candidate by the exact version string
   `0.10.1.dev0` (`CLOCKLAB_CANDIDATE_FABRIC_VERSION`), and only in the
   commissioning projections a v4 proposal passes through. Every other
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
