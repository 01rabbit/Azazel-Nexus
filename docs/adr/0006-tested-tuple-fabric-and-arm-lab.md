# ADR-0006 — The tested tuple reads its CPU from the platform profile, maps to Fabric's `TestedCompatibilityTuple`, and an Arm tuple is lab-only

Status: **proposed (2026-10-29)**, with defaults adopted by the implementing
change; the owner may change any of them · Extends
[ADR-0003](0003-arm-software-verification-profile.md) · Leaves
[ADR-0002](0002-debian-13-baseline.md) unchanged

## Context

[`compatibility.TestedTuple`](../../src/azazel_nexus/compatibility.py) is the
deny-by-default admission tuple of
[contract ownership §4.1](../contract-ownership.md#41-tested-compatibility-tuple).
It held its own constant, `ADMITTED_ARCHITECTURE = "x86_64"`, and refused any
other CPU when a tuple was built. ADR-0003 D1 kept that value and added
[`platform_profile`](../../src/azazel_nexus/platform_profile.py), whose
`REVIEWED_PROFILES` name the deployment baseline (`debian-13-amd64-cp313`)
and the Arm lab profile (`debian-13-arm64-cp313-lab`). The two statements of
"which CPU is the baseline" were held equal only by a test.

Fabric `v0.9.0rc5` publishes the same concept as
`provisioning_contracts.TestedCompatibilityTuple`: a descriptive claim
("recording that a tuple was tested is not admitting it") whose
`architecture` is Fabric's `Literal["amd64", "arm64"]`. Nexus could neither
describe its tuple in that shape nor read an `arm64` claim at all.

## Decision

**D1. The admitted CPU is the deployment-baseline profile's CPU.**
`ADMITTED_ARCHITECTURE` is now computed as the kernel spelling of the one
profile in `REVIEWED_PROFILES` whose purpose is `deployment-baseline`
(`platform_profile.deployment_baseline_profile()`, which refuses a table with
none or two). Its value is still `x86_64`; HIL preflight, model admission and
product admission refuse exactly what they refused before.

**D2. Tuple records keep the kernel spelling.** `TestedTuple.architecture`
stays `x86_64` / `aarch64`, the spelling the mission-pack configuration, the
model-admission evidence (compared with `uname`), HIL records and the Edge pin
already use. Translation to Fabric's `amd64` / `arm64` happens only at the
Fabric boundary, through `platform_profile`. No existing record, pin or
mission-pack `compatibility` object changes; `as_record()` of a baseline
tuple is byte-identical to before.

**D3. A tuple has a purpose, and it is the CPU's profile purpose.**
`TestedTuple.purpose` defaults to `deployment-baseline`. The only other
accepted value is `lab-software-verification`, and only together with the lab
profile's CPU (`aarch64`); a baseline tuple still accepts `x86_64` only. The
purpose is checked against `platform_profile.purpose_for_architecture`, so a
record cannot claim a purpose its CPU does not have. A lab tuple's audit
record carries `"purpose"`; a baseline tuple's does not.

**D4. A lab tuple never backs a production admission.** `refusal_for`
refuses a lab tuple for every host, as its first check, so
`TestedTupleSet.admits` (model admission, cognition, mission packs) and the
mission-pack import never select one -- not even for an `aarch64` host that
matches every field. Arm stays a software-verification profile (ADR-0003 D5):
an Arm tuple records a lab software run and is never evidence for a hardware
gate. There is no flag, field, environment variable or setting that lets a
lab tuple admit.

**D5. Fabric's tuple is mapped, compared and projected; never imported as an
admission.** [`fabric_boundary`](../../src/azazel_nexus/fabric_boundary.py)
(the only Fabric import site) adds:

- `project_tested_tuple(tested, *, tuple_id, product_version, evidence_ref,
  deployment_profile)` — a Fabric `TestedCompatibilityTuple` describing a
  Nexus tuple, with `product = "azazel-nexus"`.
- `check_tested_tuple(tested, claim)` — validates `claim` with Fabric's own
  model and reports whether the shared fields agree, naming the first one that
  does not, plus the purpose the reviewed table gives the claim's CPU.

Neither builds a `TestedTuple` from a Fabric record: what Nexus admits is
still only the commissioned tuple set. Both are unavailable, with a reason,
when Fabric is absent or not the pin, so CORE is unaffected.

The vocabulary, in one place each:

| Nexus `TestedTuple` | Fabric `TestedCompatibilityTuple` | Rule |
| --- | --- | --- |
| `component_digest` | `artifact_digest` | exact |
| `adapter_digest` | `adapter_digest` | exact |
| `fabric_version` (`v0.9.0rc5`, the tag) | `fabric_version` (`0.9.0rc5`, `__version__`) | exactly one leading `v` removed; anything else refused |
| `os_abi` | `os_abi` | exact; no table relates the two spellings (see below) |
| `architecture` `x86_64` / `aarch64` | `architecture` `amd64` / `arm64` | `platform_profile` kernel ↔ Fabric names |
| `cpu_features` (set) | `cpu_features` (list) | same set; a repeated entry in the claim is refused |
| `schema_features` (set) | `schema_features` (list) | same set; a repeated entry is refused |
| `overlay_schema` | `overlay_schema_version` | exact; a claim without one does not conform |
| `purpose` | — | read from `architecture` through `REVIEWED_PROFILES`: `arm64` is lab |
| `renderer_digest`, `toolchain_digest`, `fabric_features`, `profile`, `security_epoch`, `max_rollback_version`, `model_role` | — | Nexus-only; not exported, never inferred |
| — | `tuple_id`, `product`, `product_version`, `deployment_profile`, `evidence_ref`, `schema_version` | claim identity; supplied when projecting, ignored when comparing (`product` must be `azazel-nexus`) |

A test reads both models' field lists and fails if either side gains a field
the table does not place.

## What this does not establish

- That Arm is a deployment target. ADR-0002 and ADR-0003 D1 stand.
- That any Fabric `TestedCompatibilityTuple` is published for Nexus, or that
  Nexus consumes one in a production path. The adapter has no production
  caller; it is tested against the pinned Fabric and its golden fixture.
- A shared `os_abi` vocabulary. Nexus's examples use `debian-13/linux-6.12`
  and Fabric's golden fixture uses `linux-gnu-x86_64`; they are compared
  byte for byte and a difference is reported, not translated.
- That Fabric's free-text `deployment_profile` is Nexus's resource envelope.
  It is not read as one.

## Alternatives considered

**Canonical (`amd64`/`arm64`) spelling inside `TestedTuple`.** Every existing
mission-pack configuration, `as_record()` digest and the `uname` comparison in
model admission would change; the translation belongs at the Fabric boundary.

**Refuse `arm64` claims outright.** Then a Fabric `arm64` claim has no Nexus
reading and the lab software runs ADR-0003 asks for cannot be described in
the shared shape. Recording them with a purpose that never admits is the
narrower change.

**Build `TestedTuple`s from Fabric claims.** That would turn a descriptive
claim into an admission input, which is what both Fabric and §4.1 forbid.
