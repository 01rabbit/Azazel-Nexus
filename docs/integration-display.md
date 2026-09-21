# The six axes, and the words that must stay apart

Status: **implemented** (`src/azazel_nexus/integration.py`), unit tested and
mutation checked. **Not yet reachable from `azazel-nexus status`** — that
wiring is E4's second half and is named in §6 rather than left implicit.
This is E4 of [#53](https://github.com/01rabbit/Azazel-Nexus/issues/53) /
[#55](https://github.com/01rabbit/Azazel-Nexus/issues/55).

Related: [capability model](capability-model.md) ·
[degradation matrix](degradation-matrix.md) ·
[the Knowledge Lite trust chain](knowledge-lite-trust.md) ·
[M.I.O. runtime](mio-runtime.md) · [Deception Lite](deception-lite.md)

## 1. Why this is data and not a renderer

A distinction is lost in the data long before it is lost on a screen. This
module produces rows; what prints them is somebody else's problem. That split
is what lets the rules below be tested as rules rather than as strings.

## 2. Six axes, reported independently

| axis | values |
| --- | --- |
| `capability` | `CORE` / `LITE` / `FULL` |
| `freshness` | `available` / `stale` / `unavailable` / `quarantined` / `missing` |
| `cognition_route` | `CORE ONLY` / `LOCAL` / `HYBRID`, with remote `disabled` / `unavailable` |
| `knowledge_supplier` | `Knowledge Lite` / `AZ-04 peer` / `none` |
| `deception_supplier` | `Deception Lite` / `AZ-06 peer` / `none` |
| `edge` | `absent` / `unknown` / `verified-ready` |

**Independent** means an input that moves one axis moves only that one.
`tests/unit/test_integration.py` varies each input on its own and asserts the
other five do not follow — a test that built one view and read six values
would prove nothing.

Two inputs move two axes, and the tests say so explicitly rather than
treating it as an exception to discover: a Knowledge Lite that becomes
`available` is also a *supplier*, and a decoy that becomes `exposed` is too.

## 3. Five words that are not four

| word | means | what the operator does |
| --- | --- | --- |
| `disabled` | somebody decided not to connect | change the decision, if that is wanted |
| `unavailable` | an attempt that did not arrive, or nothing admitted | connect it, or install content |
| `stale` | having something too old to serve | refresh it |
| `quarantined` | having something that cannot be trusted | investigate, then roll back or re-admit |
| `missing` | an **embedded** feature that is not there | this is a defect; fix the installation |

Five different next actions. A renderer that prints any two of them as one
word has told its operator to do the wrong thing, so the vocabulary is kept
apart here and a test asserts no two share a value.

A decoy that is `DISABLED` and one that is `ELIGIBLE` both report
`unavailable` — in both, nothing is listening — and the decoy's own reason
says which. That is a deliberate merge of two *lifecycle* states onto one
*freshness* word, not a collapse of two freshness words.

## 4. An absent peer and an absent embedded feature are not the same fact

An external AZ-04 or AZ-06 peer that is not connected is `unavailable`, and
the row says so in as many words: *"a capability extension and its absence is
unavailable, not a defect"*. **A node with no peers is the designed node.**

An embedded feature that is not there is `missing` and the row carries
`defect=True`. Describing both with one word makes a required feature read
like an optional one — and it is the required one whose absence somebody has
to act on.

## 5. Two things the view never claims, and one it never says continues

`enforcement_capable` and `baseline_ready` are **derived properties**, both
`False` unless Edge is `verified-ready`. Nothing in this product produces
that state ([#44](https://github.com/01rabbit/Azazel-Nexus/issues/44)), so
both are `False` on every node this repository can build. The test asserts it
over **every combination** of the other five axes — 108 of them — because "we
are ready" inferred from a capability the node happens to have is exactly the
claim that must be impossible.

`NEXUS_ALWAYS` lists what continues whatever any axis says: audit, the
operator plane, deterministic explanations, inventory and commissioning.

**"Edge deterministic decisions" is deliberately not in it.** It is the line
an operator most wants to read, and on a node whose Edge is `absent` or
`unknown` it would be a claim about a component that is not there. The edge
row adds it, and only when Edge is `verified-ready`. A test asserts no row
claims it otherwise.

Every row must say what continues; a row with an empty list is refused. A node
that prints only what it lost is telling its operator it is broken while it is
doing its job (`operator.CapabilityReport.retained`, issue #29, restated per
axis).

## 6. What is not done yet

**The view is not wired into `azazel-nexus status`.** It is named here because
an unnamed gap is how `lite_cache.py` came to be a library nothing used — the
defect this series found in E1 and fixed in
[#59](https://github.com/01rabbit/Azazel-Nexus/pull/59).

Two things that wiring needs, and neither is a display decision:

1. **The embedded stores have no declared paths.** `IMPLEMENTATION_SPEC.md`
   §3 puts `knowledge-lite/` and `deception-lite/` under `/data/azazel/`, a
   tier `layout.LAYOUT` does not declare at all. Adding it decides the data
   volume, its ownership, and the encrypted-volume question, which is
   packaging rather than display. The services themselves read an absent root
   correctly — `unavailable` and `DISABLED` — so this blocks the wiring, not
   the honesty of it.
2. **`read_cognition` takes `HostFacts` it cannot supply.** On a node with no
   declared provider it uses only the resource profile; the rest of
   `HostFacts` would have to be invented to call it. The fix is to take the
   profile directly and make host facts optional, refusing admission with
   *"no host facts have been established"* when a provider is declared
   without them. That is a small API change and it is E4's second half.

Also not here: nothing writes these events to the audit ledger yet.
