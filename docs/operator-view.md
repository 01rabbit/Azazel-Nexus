# The Operator Screen

Status: **implemented** (`src/azazel_nexus/operator_view.py`, Nexus#99).
What an operator sees after installation, and what they may safely do next.

Related: [the model catalog contract](model-catalog.md) ·
[offline model import](model-import.md) ·
[M.I.O. runtime control plane](mio-runtime.md) ·
[the route policy](mio-route-policy.md) ·
[Capability model](capability-model.md) ·
[Hardware gates](hardware-gates.md) ·
[Commissioning](commissioning.md)

## 1. One screen, two concerns

Installer and commissioning UX — what to ask, what not to ask, how to keep
confirmations apart — and the state of the catalog and its artifacts are
separate concerns. They land on the same page. Building them apart would
build two pages, and an operator would have to hold both in their head to
answer one question.

So this module joins them, and draws the boundary elsewhere: it **displays**
provider admission, model import and network acquisition as distinct
operations; it **performs** none of them.

| shown here | performed by |
| --- | --- |
| profile, remote consent | `mio_profile` (#82, #84) |
| catalog and artifact state | `model_catalog` (#94) |
| inbox, staging, quarantine, promotion, rollback | `model_import` (#95) |
| provider admission | nothing, in this build — [`HG-05`](hardware-gates.md), then [#97](https://github.com/01rabbit/Azazel-Nexus/issues/97) |
| network acquisition | nothing, in this build — [#96](https://github.com/01rabbit/Azazel-Nexus/issues/96) |

## 2. Answers that are mechanical are not questions

RAM, disk and the selected profile are read and **shown**, never asked. A
question whose answer is already determined teaches an operator that their
answers do not matter, and the next question — one that really is theirs —
gets the same reflex.

The memory classes 8, 16 and 32 GiB appear as **possibilities**: what a host
of that class selects, with this node's class marked. A possibility is a
statement about hardware. Nothing is chosen, fetched or started because a
class appears, and a class is never evidence that a capability fits
([capability model](capability-model.md) §2).

The floors those possibilities are derived from are the selector's own,
imported rather than restated. [Support matrix](support-matrix.md) forbids
these numbers appearing with different values anywhere, and a screen carrying
its own copy is where they would first diverge.

## 3. An option that cannot be chosen is shown with its reason

Never removed. A screen where options quietly vanish is a screen where an
operator spends an hour looking for one that was never there.

Every operation carries `available` and a `reason`, and the reason is present
either way. "Why yes" is as useful as "why no" when the next step is a
confirmation somebody has to stand behind.

## 4. Five confirmations stay five

| confirmation | what it consents to | audit transition |
| --- | --- | --- |
| `profile` | what route selection may consider | `mio.profile.commissioned` |
| `remote opt-in` | requests may leave this node | `mio.remote.opt_in` |
| `license acknowledgement` | the model's terms | `mio.model.license_acknowledged` |
| `model import` | an artifact is brought in | `mio.model.import.promoted` |
| `provider admission` | something starts and uses resources | `mio.provider.admitted` |

Collapsed into one "yes", an operator consents to five things believing they
consented to one. `Confirmation` has exactly five members and each maps to a
**distinct** transition, so "these are five separate consents" is checkable
rather than asserted: five confirmations that wrote one event would be one
confirmation with five labels.

Naming a transition is not writing one. Reading this screen writes none.

## 5. Three vocabularies that must not merge

`CatalogState` — what the node was told and what it holds:
`absent` / `empty` / `declared` / `present`.

`ProviderState` — whether anything may run:
`unavailable` / `not admitted` / `not activated`.

`MioProfile` — the ceiling on what route selection may consider.

They answer different questions, and a `present` artifact is routinely
`not admitted`. The two state enums share **no word**, so a value of one can
never appear in the other's row and be read as an answer to the other's
question. A test asserts the disjointness rather than the discipline.

## 6. `fastest-permitted` does not admit anything

This is the case an operator is most likely to misread. A node may be on
`fastest-permitted`, have every remote prerequisite set, hold a verified
artifact, and **still admit no provider**, because the resource gate refuses
for want of a measured Core reserve ([`HG-05`](hardware-gates.md)).

The screen says so in the admission row, on every profile. And the sentence
below does not move — not for a profile, not for an imported artifact, not
for a node with every prerequisite met:

> M.I.O. routing and commissioning control plane implemented; provider
> execution unavailable pending hardware evidence and provider integration

What is missing is hardware evidence and a provider integration. A screen
cannot supply either.

## 7. Reading this screen does nothing

Not by a guard that could be edited. `operator_view` performs **no I/O at
all**: it imports no `os`, no `pathlib`, no `hashlib`, no socket or HTTP
module, and calls no `open`. It therefore cannot import, hash, download,
admit, start anything, or write an audit event — there is nothing in it that
could.

`gather_facts` is the single function that touches a service, and it may call
only the read verbs in `READ_ONLY_VERBS`. That is checked against the
module's syntax tree rather than trusted because the function is called
`gather_facts`: a name is not an enforcement.

End to end, building and rendering the screen three times over a real node
leaves the tree byte-identical and the audit recorder empty.

A screen that changes something when looked at is a screen an operator stops
looking at — and this is the screen they are meant to consult before every
irreversible step.

## 8. No authority

No state of this screen moves Edge authority, the action lease, enforcement
or activation. Only the Edge-owned deterministic arbiter decides and
enforces; `FULL → LITE → CORE` is a capability state, not an authority state.
The Edge answer is held fixed across every profile × catalog state × reserve
× consent combination the screen can show.
