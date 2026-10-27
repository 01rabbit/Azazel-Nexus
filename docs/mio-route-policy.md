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

## 1. The Edge-owned doctrine, quoted exactly

`mio-dual-cognition.md` marks its **Cognitive Router** section Edge-owned, and
that section *is* about M.I.O. cognition routing rather than about Edge's
decision path — line 92: *"It selects a cognition route from explicit mission
conditions"*. So the text below is on point and is quoted rather than
paraphrased.

**Line 109:**

> Remote-only operation is not the preferred field posture. The normal route is
> local-first so that a loss of connectivity cannot remove immediate
> operational cognition.

**Line 106, the mode table's "normal connected operation" row:**

> | **Local → remote** | Normal connected operation. | Local gives the operator an immediate grounded answer; remote adds analysis when ready. |

### Does `fastest-permitted` require an Edge revision? **No.**

Taking the two sentences of line 109 separately:

| assertion | under `fastest-permitted` |
| --- | --- |
| "Remote-only operation is not the preferred field posture" | `fastest-permitted` is **not remote-only**. Local is always among the candidates; remote is one more candidate that must first be permitted |
| "The normal route is local-first **so that** a loss of connectivity cannot remove immediate operational cognition" | the stated purpose is **preserved**: comms state is a permit condition (§3), so losing connectivity removes remote from the candidate set and local answers |

And the same section's own list of routing inputs already sanctions
latency-driven selection under operator policy — lines 96 and 99:

> - urgency and latency budget;
> - operator-selected mission policy; and

The mode table likewise already contemplates modes other than local-first
"where policy permits" (lines 105, 107).

### The one real gap, and it is a documentation gap

`fastest-permitted` is **a fifth mode that the table does not name**. Line 106
describes normal connected operation as local-answers-first-and-remote-adds;
under `fastest-permitted` a permitted remote predicted to be sooner may answer
**instead of** local rather than in addition to it.

That is a completeness matter for the Edge-owned table, not a contradiction of
the doctrine's normative content, and **it does not block this implementation**.
Tracked in [#81](https://github.com/01rabbit/Azazel-Nexus/issues/81) as a
suggested Edge-side amendment: add `fastest-permitted` to the mode table.

### What is genuinely unchanged

M.I.O. remains an **advisory plane**. The Azazel-Edge arbiter is the sole
decider, and no route selection here touches a decision, an action lease,
enforcement, or activation. Every stage below is tested for exactly that.

## 2. Profiles and the operator's path through them

Selected at install and recorded at commissioning ([#82](https://github.com/01rabbit/Azazel-Nexus/issues/82)).

| profile | meaning |
| --- | --- |
| `core` | no M.I.O. provider is admitted; explanation and status only |
| `local-only` | approved on-premises models only |
| `fastest-permitted` | the earliest-answering of the permitted candidates, local or remote |
| `remote-disabled` | the remote route is disabled in configuration **and** at runtime |

### The path

1. **Immediately after install, uncommissioned: `core`.** Remote is disabled
   and no provider is admitted. "It is written in the config" is not a grant.
2. **At commissioning, when the operator explicitly configures remote use, the
   privacy policy, the provider and the comms permission, the recommended
   profile is `fastest-permitted`.** This is the standard path for a normal
   commissioned deployment, not an advanced option buried behind a flag.
3. **Otherwise — remote not opted into, or policy / health / sanitizer / trust
   incomplete, or `HG-05` unmet — remote is excluded from the candidate set**
   and the node degrades to `local-only` or `CORE`.

### `fastest-permitted` is not "prefer online"

It selects the candidate that, **on observed evidence**, is predicted to answer
soonest **within the deadline**. When local is sooner, local is chosen. A
profile that preferred remote would be a permanent setting, which §8 exists to
prevent.

What it does deliver is the thing an operator reasonably expects: **when a
permitted online provider really is faster, that is used automatically**, and
the record says why.

### Speed never overrides policy

Even when remote is predicted soonest it is **not selectable** if any of these
holds:

- the class is P2 or P3
- the class is P1 and the frame is **not sanitised**
- mTLS, provider identity, the endpoint allowlist, or health is not `passed`

### Opt-in is revocable

The operator can withdraw the remote opt-in at any time. On withdrawal:

- the remote provider leaves the candidate set **immediately** — not at the
  next commissioning, not at the next restart
- an in-flight task either **falls back safely to local** or is **refused**; it
  is never completed by the route the operator just withdrew
- the withdrawal is an audit event carrying who, when and why

**Runtime recheck** (implemented; mock evidence only). The router
(`runtime/src/azazel_nexus_runtime/mio_router.py`) re-reads the remote
admission through the caller's `remote_recheck` before every remote attempt
and at every fallback, and only for a remote route the selection already
permitted, so a recheck can narrow the permitted set and never widen it. A
recheck that refuses, raises or returns anything but a permitting
`RemoteAdmission` removes remote (fail-closed): nothing is sent,
`OPT_IN_WITHDRAWN` is recorded with a fixed reason
(`remote_opt_in_withdrawn` / `remote_recheck_failed`), and
`mio_profile.disposition_on_withdrawal` decides between one local fallback and
refusal. Entry passes a recheck that re-evaluates `remote_admission` with the
same inputs as the selection; this build has no opt-in reader (always
`NO_OPT_IN`), so remote is never selected and production behaviour is
unchanged. Evidence: `tests/unit/test_mio_router.py`,
`tests/unit/test_mio_router_deadline.py` and `tests/unit/test_mio_entryd.py`,
all with mock providers. Cancelling a remote request **already in flight** is
not implemented: there is no remote transport in this build.

### A profile is a ceiling, not a grant

Selecting `fastest-permitted` admits nothing; every admission gate still runs.
A node on `fastest-permitted` with no admitted provider answers
deterministically, exactly as `core` does — and says so for a different reason.

`local-only` and `remote-disabled` are **not the same word**. The first prefers
local; the second is the absence of a remote route. An operator's next action
differs, which is the discipline that keeps `disabled` and `unavailable` apart
in the status vocabulary.

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

Implementation status (2026-10-28, software evidence only): the runtime router
(`runtime/src/azazel_nexus_runtime/mio_router.py`) makes at most two AI attempts,
measures one deadline per request on the monotonic clock, gives each attempt only
what is left of it, starts no attempt without room for one, discards a reply that
arrives after the deadline, and ends every unanswered request — including a
second failure — in the deterministic handoff, which calls no AI. See
[M.I.O. runtime](mio-runtime.md) §9 and `tests/unit/test_mio_router_deadline.py`.
Before this, the router ended a second failure as `refused` on the failed AI
route without reaching the handoff.

The existing invariant — *a fallback never escalates* — is re-expressed as
**a fallback never leaves the permitted set**. That is the stronger statement,
because the permitted set is computed from policy rather than from an ordering.

All eight existing `FallbackTrigger` values keep their meanings.

**A withdrawn remote opt-in is not a fallback trigger; it is a permit change.**
It removes the candidate rather than failing it, so an in-flight task on that
route falls back to local once, or is refused. A withdrawal must never be
served by the route it withdrew.

In the runtime router this holds for a withdrawal seen before the remote
attempt starts or when a fallback is chosen: every fallback passes the
rechecked set to `fallback_once(still_permitted=...)`, which is always a subset
of the selection's permitted set (see "Runtime recheck" above; mock evidence).

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

`Selection.as_event` carries the route, reason, profile, privacy class,
permitted set, and every candidate's evidence or exclusion. The execution
boundary in `route_audit` appends that event before returning the decision;
it also records the failed origin and selected destination of a fallback and
the distinct terminal outcome. A ledger failure therefore withholds the
decision from execution rather than leaving an unaudited route choice.

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
| profile | commissioning with remote opted in, policy, provider and comms set recommends `fastest-permitted` |
| profile | any one of those four missing does **not** recommend it, and degrades to `local-only` or `CORE` |
| opt-in | withdrawal removes remote from candidates immediately, not at restart |
| opt-in | an in-flight task on the withdrawn route falls back to local once, or is refused — never completed remotely |
| opt-in | withdrawal is an audit event carrying who, when and why |
| selection | local is chosen when local is predicted sooner (`fastest-permitted` is not "prefer remote") |
| selection | remote predicted sooner is still unselectable for P2/P3, unsanitised P1, or any trust condition not `passed` |
| boundary | no Knowledge/M.I.O. state changes Edge readiness, authority, lease or enforcement |
| boundary | M.I.O. does not report `functional` |
| CORE | every module here imports with nothing installed |

## 12. Order of work

`#82` profile → `#84` trust plane → `#83` evidence → `#81` selection.

The profile and the permit conditions decide the shape of the selection. Built
the other way round, the selection decides what the configuration is allowed
to say — which is how a ceiling becomes a grant.
