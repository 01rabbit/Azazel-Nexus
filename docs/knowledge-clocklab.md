# Clocklab contract candidate (not production acceptance)

The existing v1 request, envelope signature domain, zero clock tolerance and
empty activation grant markers remain available. Nonzero clocklab is an explicit
separate v2 commissioning mode, with a 5000 microsecond laboratory hypothesis.
This is not a synchronization accuracy or availability guarantee.

A full operator-signed commissioning proposal v4 contains `clock_policy` (the
Fabric ClockContract canonical body and contract_id). The proposal requires the
FULL profile. Its complete bytes retain the existing commissioning digest and
activation generation/approval binding. `build_commissioning_bundle.py
--clock-proposal <protected-body>` checks that body against the independently
supplied commissioning digest and produces a commissioning manifest v2. The
normal builder invocation still produces manifest v1. The builder does not
claim to authenticate the external approval; the existing commissioning evidence
loader and activation pass verify the signature and retained expectations.

The activation publisher and pass compare the manifest policy and registry
commissioning digest against the verified full proposal. A successful formal
activation writes boot_id, contract_id and commissioning_digest into the
contextd grant marker only for this v2 mode. The broker refuses a new v2
manifest under an old empty marker. The protected marker's identity is checked
again immediately before adoption, preserving revocation and replacement
refusal. Marker reset removes the binding with the marker. The trusted root
model is unchanged.

V2 calls the existing `/v1/knowledge-context` transport URL with the immutable contract ID. Both Fabric
consumers use the explicit v2 correlation validator. The signed envelope uses
`azazel-nexus/knowledge-context-envelope/2` and domain
`azazel-nexus/knowledge-context-envelope/v2\0`; the semantic payload signs the
contract ID. There is no fallback to v1, timestamp clamp, signature bypass or
extension of the request's monotonic deadline.

Only generated/request correlation and future bounds use B. Signature and
semantic expiration must both exceed now+B. At final adoption, the broker
checks clock health, effective expiration, the monotonic request deadline and
the original grant marker. The local `VerifiedContext` and socket validity
wrapper retain original signed and semantic expiry, effective expiry, contract
ID and adopted_at. These local facts are not added to or substituted for the
provider's signed payload. Technique projection v2 retains this validity.

The lab health file is `/run/azazel/knowledge-clock-health.json`, protected by
root ownership, non-writable ancestors, regular-file mode and bounded atomic
snapshot reads. Its exact `azazel-clocklab-health/1` keys are:

- contract_id, n_boot_id, k_boot_id, generation, step_counter;
- observed_boottime_ns, valid_until_boottime_ns (N-local BOOTTIME);
- n_error_us, k_error_us (each at most 1000);
- k_age_at_receipt_us and mapping_bound_us (conservative K-to-N freshness mapping);
- wall_minus_boottime_ns (N sample).

Age is strictly below five seconds at adoption. The guard includes both node
ages at 100ppm, ceiling rounding, mapping bound and a 2000us sampling margin in
the 5000us budget. It never directly subtracts K and N BOOTTIME values. Missing,
unsafe, stale, over-budget, changed-boot/step/generation or stepped-wall evidence
refuses; a broker guard latches closed until restart. A privileged external
observer supplies evidence; this does not claim autonomous NTP monitoring.

API and handoff retain raw/effective expiry separately. The UI shows the last
server validity decision and as_of; browser Date.now does not extend v2
freshness. Failed polling changes the display to update-stopped/unknown.
Saved artifacts remain observations at generation time, not a reusable grant.
A past reference remains not_adoptable, regardless of its freshness.

Tests exercise signed v2 positive/negative B boundaries, policy/nonce replay
binding, effective expiry equality, expiry crossing after client validation,
health loss/unsafe files, server-time projection and v2 grant binding. Formal
fresh-VM acceptance and human visual acceptance are separate and unperformed.

## Explicit full-proposal CLI input

`az-nexus-commission proposal-export --operator LABEL --clock-policy /absolute/policy.json`
opts into v4 through the normal interactive protected export. The file must be
root-owned, a single-link regular file of 1–4096 bytes, with root-owned real
directory ancestors and no group/other write permission on any component.
Symlinks, duplicate JSON keys, unknown fields, non-finite values and ambiguous
paths are refused. Its complete `ClockContract.as_dict()` must name the 5000us
lab budget, 5000ms observation age and matching contract ID. The selected M.I.O.
ceiling must be FULL. This is an explicit lab configuration, not a production
clock guarantee. There is no fallback to zero or an older peer.

The consent screen identifies the policy digest. Export reopens the entire
input path after consent and compares exact bytes, file metadata/identity and
ancestor identities before retaining the ordinary protected proposal and
separate expected bytes. The policy is inside those full-proposal signature
bytes and the commissioning digest; no manual proposal/expected-context editing
or separate policy signature substitutes for the formal path. Omitting the flag
preserves the existing proposal format and behavior. This command signs nothing
and activates nothing. Older candidate wheels predating this CLI input do not
establish that the formal v4 export can run; rebuild the candidate artifacts.
