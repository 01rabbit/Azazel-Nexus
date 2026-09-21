# M.I.O. route policy — policy-first / fastest-permitted

Status: **implementation specification. Not implemented.**

This document specifies how Nexus selects a cognition route once route
selection stops being fixed local-first. It replaces the routing clause of
[Nexus #5](https://github.com/01rabbit/Azazel-Nexus/issues/5) and is tracked by
[#81](https://github.com/01rabbit/Azazel-Nexus/issues/81)–[#84](https://github.com/01rabbit/Azazel-Nexus/issues/84).

Related: [M.I.O. runtime control plane](mio-runtime.md) ·
[M.I.O. dual cognition](mio-dual-cognition.md) (Edge-owned) ·
[the sanitizer](mio-sanitizer.md) · [hardware gates](hardware-gates.md)

## 0. What does not change

Stated first, because a routing change is exactly where an authority boundary
gets moved by accident.

- **M.I.O. advises.** It summarises, explains and prioritises. It holds no
  share of the Azazel-Edge arbiter's decision, no action lease, and no
  enforcement authority. No route changes that.
- **The deterministic no-model handoff is always available and is never
  removed.** Policy-first does not give it a competitor; it is the answer when
  the permitted set is empty, which is every node today.
- **Knowledge Lite being `functional` grants nothing.** It is not a reason for
  M.I.O. or Edge to hold more.
- **M.I.O. is not displayed `functional` until `HG-05` is measured** and the
  reserve needed for provider admission is verified. The
  `CORE imports with nothing installed` tripwire enforces this mechanically.
- **Nexus alone runs safely in CORE/LITE** with no external API, no remote
  provider and no AZ-04 peer.

## 1. The Edge-owned doctrine, and the reading this spec proceeds under

`mio-dual-cognition.md` is **Edge-owned** and says:

> Remote-only operation is not the preferred field posture. **The normal route
> is local-first** so that a loss of connectivity cannot remove immediate
> operational cognition.

Its mode table also lists `Local + remote parallel` — speculative dual-send —
as a legitimate mode "where policy permits".

**This spec proceeds under the following reading, stated as an assumption
because it has not been confirmed:**

| layer | reading |
| --- | --- |
| the selection **algorithm** | policy-first: permit, then predict, then choose |
| `fastest-permitted` | an **operator-selected profile**, not the default |
| the default profile | `core` — no provider is admitted |

Under this reading local-first remains the **default posture**, which is what
the Edge doctrine asserts, and `fastest-permitted` sits where that same
doctrine already says "where policy permits". Speculative dual-send being
forbidden by default is consistent for the same reason.

**Making `fastest-permitted` the default would contradict the Edge-owned
doctrine and needs an Edge-side revision first.** Nexus does not change a
document it does not own, and does not ship an implementation that contradicts
one it vendors. #81 tracks that decision.

## 2. Profiles

Selected at install and recorded at commissioning ([#82](https://github.com/01rabbit/Azazel-Nexus/issues/82)).

| profile | meaning |
| --- | --- |
| `core` | no M.I.O. provider is admitted; explanation and status only |
| `local-only` | approved on-premises models only |
| `fastest-permitted` | the fastest of the permitted candidates, local or remote |
| `remote-disabled` | the remote route is disabled in configuration **and** at runtime |

**A profile is a ceiling, not a grant.** Selecting `fastest-permitted` admits
nothing; every admission gate still runs. A node on `fastest-permitted` with
no admitted provider answers deterministically, exactly as `core` does — and
says so for a different reason.

`local-only` and `remote-disabled` are **not the same word**. The first is a
configuration that prefers local; the second is the absence of a remote route.
An operator's next action differs, which is the same discipline that keeps
`disabled` and `unavailable` apart in the status vocabulary.

An uncommissioned node behaves as `core`. "It is written in the config" is not
a grant.

## 3. Stage one — permit

The first stage answers one question per candidate: **may this route carry
this request at all?** A candidate that fails any condition is excluded *even
if it is the fastest*.

| condition | today |
| --- | --- |
| privacy class | implemented, doubly (`routing._REMOTE_ELIGIBLE` and `sanitizer.NEVER_REMOTE`) |
| operator setting | **absent** — arrives with the profile (#82) |
| mission policy | **absent** |
| trust state | **absent** — [#84](https://github.com/01rabbit/Azazel-Nexus/issues/84) |
| provider health | **absent** as an input; the three-valued reading exists |
| available resources | partial; the reserve is unmeasured (`HG-05`) |
| comms state | **absent** |

### The output is two sets, not one

The stage returns the permitted candidates **and the excluded ones with the
condition each failed**. An exclusion with no reason is an exclusion an
operator cannot act on, and the audit record in §8 needs it.

### Privacy class stays a separate refusal

P2 and P3 are never remote. `routing` refuses them and `sanitizer` refuses
them again at the egress boundary. **The trust-state check of #84 is a third
independent refusal, not a replacement for either.** Three refusals exist so
that editing one does not silently open the others.

### Speed never overrides

A remote route that is reachable, healthy and fastest is still excluded if the
operator has not opted in, if mTLS/identity/allowlist/health are not
`passed`, or if the class is P2/P3. **This is the whole content of
"policy-first".**

## 4. Stage two — predict

Only permitted candidates are compared, on: observed p95 latency, success
rate, queue depth, local-model cold-start, input/output size, and the request
deadline.

**None of this is measured today.** `grep -rn "latency\|p95\|success_rate" src/`
returns nothing. [#83](https://github.com/01rabbit/Azazel-Nexus/issues/83)
builds the record schema, the collection and the validation — and, following
`HG-05`, **invents no values**.

### No observation, no prediction

A candidate with too few samples is **not predictable**, and a candidate that
is not predictable cannot be called fastest. This is the correct state, not a
defect.

- "not yet measured" and "measured and slow" are **different words**
- observations expire; a stale observation is not evidence of current speed
- a prediction from no evidence is a permanent setting wearing a
  measurement's clothes, which is precisely what the policy forbids

On every node today the permitted set contains only the deterministic handoff,
so no prediction is made at all.

### Determinism

The same observation set, the same deadline and the same candidate set produce
the same prediction. The clock stays an argument, as it already is in
`routing.select_route`, so a decision replays.

## 5. Stage three — choose

The candidate predicted to answer **soonest within the deadline**. A candidate
predicted to miss the deadline is not chosen, however fast it is relative to
the others.

If no permitted candidate is predicted to make the deadline, the deterministic
handoff answers.

## 6. Fallback — once

On failure, deadline overrun, or health degradation, fall back **once** to a
remaining permitted candidate.

| rule | reason |
| --- | --- |
| the fallback target comes from the **original** permitted set | re-running the permit stage on a failure is how a failure becomes a reason to widen |
| **one** fallback per request | a second failure is not a third chance; it is evidence |
| a second failure falls to the deterministic handoff | the floor of the ladder, which is never removed |

The existing invariant — *a fallback never escalates* — is re-expressed as
**a fallback never leaves the permitted set**. That is the stronger statement,
because the permitted set is computed from policy rather than from an ordering.

All eight existing `FallbackTrigger` values keep their meanings.

## 7. Speculative dual-send — forbidden by default

No request is sent to two routes concurrently.

An exception requires an explicit mission policy **and** a privacy class that
permits it, both at once. Absent that, **no code path exists** to send twice —
checked as the absence of a path, not as a configuration flag set to off.

## 8. Audit — why "online is faster" is a claim and not a setting

Every route decision records:

| field | so that |
| --- | --- |
| the measured evidence: which observations, how many samples, how old | "faster" can be checked rather than believed |
| the permitted set, and every exclusion with its failed condition | an operator can see what was not considered, and why |
| the privacy class | the class that constrained the decision is visible |
| the selection reason | why this candidate was predicted soonest |
| the profile in force | the ceiling the decision was made under |

`RouteDecision.as_event` today carries route, reason and inputs. It carries
neither the evidence nor the exclusions; both are added.

**A display that says remote is faster without these is a permanent setting.**

## 9. Status and degradation

New status facts, each in its own word:

- the profile in force
- the route actually selected for the most recent decision, and why
- per candidate: permitted / excluded, with the condition
- whether any candidate is predictable at all

Degradation gains rows for: profile narrowed, remote excluded by trust state,
remote excluded by comms state, and no candidate predictable. Every row states
**what continues** — the deterministic path, always.

`remote M.I.O. disabled` and `remote M.I.O. unavailable` stay distinct, and a
third fact — *permitted but not predictable* — is neither of them.

## 10. What stays refused until `HG-05`

Nothing in this document admits a provider. The resource gate refuses every
local model provider while the Core reserve is unmeasured, so:

- the permitted set contains only the deterministic handoff
- no prediction is made
- no fallback occurs
- M.I.O. is **not** `functional`, and the CI tripwire enforces it

This spec describes what happens **after** that gate opens, and changes
nothing about when it opens.

## 11. Test matrix

| area | what must be shown |
| --- | --- |
| permit | each of the 7 conditions excludes independently, with its own reason |
| permit | a faster-but-not-permitted candidate is excluded |
| permit | P2/P3 stay remote-ineligible with every trust condition `passed` |
| predict | no samples ⇒ not predictable ⇒ no `fastest` claim |
| predict | stale observations are not used as current |
| predict | the same inputs produce the same prediction |
| choose | a candidate predicted to miss the deadline is not chosen |
| choose | an empty permitted set answers deterministically |
| fallback | exactly one fallback; the second failure reaches the handoff |
| fallback | the fallback target is inside the original permitted set, over all 8 triggers |
| dual-send | no path sends twice, by static scan |
| audit | the event carries evidence, exclusions, class, reason and profile |
| profile | `core` default; uncommissioned behaves as `core` |
| profile | `remote-disabled` is unreachable at runtime, not merely unconfigured |
| boundary | no Knowledge/M.I.O. state changes Edge readiness, authority, lease or enforcement |
| boundary | M.I.O. does not report `functional` |
| CORE | every module here imports with nothing installed |

## 12. Order of work

`#82` profile → `#84` trust plane → `#83` evidence → `#81` selection.

The profile and the permit conditions decide the shape of the selection. Built
the other way round, the selection decides what the configuration is allowed
to say — which is how a ceiling becomes a grant.
