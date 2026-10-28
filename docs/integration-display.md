# The six axes, and the words that must stay apart

Status: **implemented and wired** (`src/azazel_nexus/integration.py`,
rendered by `azazel-nexus status`), unit tested and mutation checked.
This is E4 of [#53](https://github.com/01rabbit/Azazel-Nexus/issues/53) /
[#55](https://github.com/01rabbit/Azazel-Nexus/issues/55).

Related: [capability model](capability-model.md) ·
[degradation matrix](degradation-matrix.md) ·
[the Knowledge Lite trust chain](knowledge-lite-trust.md) ·
[M.I.O. runtime](mio-runtime.md) · [Deception Lite](deception-lite.md) ·
[Edge package verification](edge-package-verification.md)

## 1. Why this is data and not a renderer

A distinction is lost in the data long before it is lost on a screen. This
module produces rows; what prints them is somebody else's problem. That split
is what lets the rules below be tested as rules rather than as strings.

## 2. Six axes, reported independently

| axis | values |
| --- | --- |
| `capability` | `CORE` / `LITE` / `FULL` |
| `freshness` | `available` / `stale` / `unavailable` / `quarantined` / `missing` / `control-plane-only` / `loopback-only` |
| `cognition_route` | `CORE ONLY` / `LOCAL` / `HYBRID`, with remote `disabled` / `unavailable` |
| `knowledge_supplier` | `Knowledge Lite` / `AZ-04 peer` / `none` |
| `deception_supplier` | `Deception Lite` / `AZ-06 peer` / `none` |
| `edge` | `absent` / `corrupt` / `version-mismatch` / `digest-mismatch` / `unhealthy` / `not-running` / `unknown` / `verified-ready` ([Edge package verification](edge-package-verification.md)) |

**Independent** means an input that moves one axis moves only that one.
`tests/unit/test_integration.py` varies each input on its own and asserts the
other five do not follow — a test that built one view and read six values
would prove nothing.

Two inputs move two axes, and the tests say so explicitly rather than
treating it as an exception to discover: a Knowledge Lite that becomes
`available` is also a *supplier*, and a decoy that becomes `exposed` is too.

## 3. Six words that are not five

| word | means | what the operator does |
| --- | --- | --- |
| `disabled` | somebody decided not to connect | change the decision, if that is wanted |
| `unavailable` | an attempt that did not arrive, or nothing admitted | connect it, or install content |
| `stale` | having something too old to serve | refresh it |
| `quarantined` | having something that cannot be trusted | investigate, then roll back or re-admit |
| `missing` | an **embedded** feature that is not there | this is a defect; fix the installation |
| **`control-plane-only`** | the feature's code is here, its control plane works, and **its functional layer does not exist yet** | nothing on this node; the work is tracked |

Six different next actions. A renderer that prints any two of them as one word
has told its operator to do the wrong thing, so the vocabulary is kept apart
here and a test asserts no two share a value.

**`control-plane-only` exists because `unavailable` means *supply content and
it works*.** Saying that of a feature nothing could accept content for sends
an operator looking for something no path can deliver.

It is what every embedded feature reports today, and
`src/azazel_nexus/functional_readiness.py` holds which and why:

| feature | implemented | the functional layer still needs |
| --- | --- | --- |
| Knowledge Lite | trust / cache / generation / rollback | an accepted signed bundle format and a supply route ([#67](https://github.com/01rabbit/Azazel-Nexus/issues/67)) |
| M.I.O. | admission / profile / sanitizer / local-first degradation | `HG-05` measured, so a provider can be admitted ([#68](https://github.com/01rabbit/Azazel-Nexus/issues/68)) |
| Deception Lite | lifecycle / isolation requirement / disable / quarantine | a runtime that starts a decoy, loopback-only ([#69](https://github.com/01rabbit/Azazel-Nexus/issues/69)) |

**A feature reporting `control-plane-only` supplies nothing**, whatever it
holds — a cache with a verified artifact still cannot answer a query, because
nothing can read the artifact.

### The declarations cannot go stale quietly

A hand-maintained "not done yet" list goes stale the day someone finishes the
work and forgets the list. Each entry is paired with a test in
`tests/unit/test_functional_readiness.py` that asserts the **mechanical
reason** it is true: the default claim reader that refuses, the resource gate
that always rejects, the decoy module that defines no verb able to start
anything. When one of those stops being true, its test fails, and whoever made
it stop being true has to come and update the declaration.

A decoy that is `DISABLED` and one that is `ELIGIBLE` both report
`unavailable` — in both, nothing is listening — and the decoy's own reason
says which. That is a deliberate merge of two *lifecycle* states onto one
*freshness* word, not a collapse of two freshness words.

## 4. An absent peer and an embedded feature that cannot supply are not the same fact

An external AZ-04 or AZ-06 peer that is not connected is `unavailable`, and
the row says so in as many words: *"a capability extension and its absence is
unavailable, not a defect"*. **A node with no peers is the designed node.**

An embedded feature that is not there is `missing` and the row carries
`defect=True`. An embedded feature that is there and cannot supply its
capability is `control-plane-only`. Describing any of these with one word
makes a required feature read like an optional one — and it is the required
one whose absence somebody has to act on.

Both embedded rows say so in as many words: *"which is not the same fact as an
external peer being absent"*.

## 5. Two things the view never claims, and one it never says continues

`enforcement_capable` and `baseline_ready` are **derived properties**, both
`False` unless Edge is `verified-ready`. `edge_package.py`
([#44](https://github.com/01rabbit/Azazel-Nexus/issues/44)) is the only
module in the product that produces that state, and it reaches it only from a
package it verified on disk with all five checks passing — which a node built
from this repository cannot do, because no probe runner is shipped
([Edge package verification](edge-package-verification.md) §7). The test
asserts it over **every combination** of the other five axes — 108 of them —
because "we
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

## 6. On the screen

`azazel-nexus status` prints the six axes with a reason under each, then the
two claims, then what continues:

```text
integration:
    capability: CORE
        the node is CORE; a capability state is what the node can do ...
    freshness [knowledge_lite]: control-plane-only
        the control plane is implemented and the functional layer is not:
        no signed Knowledge bundle format is accepted ... (Nexus#67). This is
        an embedded feature that cannot supply its capability, which is not
        the same fact as an external peer being absent. The cache itself
        reports: no Knowledge Lite artifact has been admitted ...
    freshness [deception_lite]: loopback-only
        the functional layer exists and reaches only this host: decoys start
        and listen, and only on private Unix sockets ... (Nexus#69) ... The
        runtime itself reports: no decoy catalogue ...
    cognition_route [mio]: CORE ONLY; remote M.I.O. disabled; local M.I.O. control-plane-only
        ... (Nexus#68) | resource: ... | topology: ... | trust: ...
    knowledge_supplier [knowledge]: none
        ... AZ-04 peer is a capability extension and its absence is
        unavailable, not a defect
    deception_supplier [deception]: none
        ...
    edge [edge_core]: absent
        no Edge package is installed on this node. This is a deployment step,
        not a security finding; enforcement-capable and baseline-ready are
        not claimed

enforcement capable: no
baseline ready: no
continuing regardless: audit, deterministic explanations, inventory and
                       commissioning, operator plane
```

What continues is printed **last and always** — not as a footnote a long list
of losses pushes off the screen. A test asserts its position.

Two things the wiring needed, and how each was resolved without inventing
anything:

1. **The embedded stores are under `/data/azazel/`, a tier
   `layout.LAYOUT` does not declare.** The paths are named in `cli.py` rather
   than added to the layout, because that tier's volume, ownership and
   encryption are a packaging decision. Naming them is safe because **both
   services read an absent root correctly** — Knowledge Lite reports
   `unavailable`, the decoy runtime `disabled`. A node without the tier gets
   the truth, not an error, and **not a defect**: an uncommissioned node is
   not a broken one.
2. **`read_cognition` required `HostFacts` a node may not have.** It now takes
   the measured `profile` directly and `host` optionally. `host=None` is a
   fact — *nothing has established what this node is* — and it refuses
   admission at the compatibility gate rather than being filled in, because an
   invented `os_abi` makes a tuple match something nobody tested.

**The clock is read in `main` and passed down.** `--as-of` makes a status
reproducible, and a test parses `_integration_view` to assert it reads no
clock of its own: a status built from a hidden wall clock cannot be replayed
from its inputs.

## 7. What is recorded, and what is still not

**Transitions are recorded by the component that causes them, with their
reason** ([#55](https://github.com/01rabbit/Azazel-Nexus/issues/55)).
`az-watchdog` is the runtime owner that narrows a capability: every fence goes
through `WatchdogService._fence`, which appends a `watchdog.fenced` entry to
its own audit ledger (`watchdog.jsonl`, the leaf `main()` already wires). The
entry carries the reason and the state the unit left, not only the state it
reached:

| field | value |
| --- | --- |
| `unit` | the fixed unit name |
| `reason` | the `FenceReason` value |
| `previous_state` | `in_service`, or `fenced` |
| `previous_reason` | the earlier `FenceReason`, or `null` |
| `state` | `fenced` |
| `detail` | printable ASCII, at most 256 characters |
| `occurred_at` | transition timestamp |

- **An identical observation is not a transition.** The unit is masked again,
  and nothing is appended; a periodic probe of a fenced unit does not grow the
  ledger. A change of reason alone is a transition and is recorded.
- **A restart is not a transition.** Stored fences are re-masked and nothing
  is appended. An unreadable fence file fails closed with every unit fenced
  for `fence_store_unreadable`, a reason that names the file, not the unit;
  the first real observation of a unit after that is therefore a transition
  and is recorded, rather than being mistaken for a repeat.
- **A failed append neither stops the fence nor invents a record.** The
  transition is held in memory with its original prior state and time, and
  retried when the same unit is next observed (an observation of another unit
  does not retry it). A corrupt ledger is treated like an unwritable one. That
  retry queue does not survive a restart: a transition whose record failed and
  whose daemon then restarted is not in the ledger.
- **`detail` is bounded and exception text is excluded.** Deadline and
  generation exceptions record `probe_deadline_exceeded` and
  `generation_verification_refused`, respectively. Restart diagnostics retain
  at most 256 characters, with non-printable/non-ASCII characters replaced by
  spaces. The separate `reason` carries the operator's condition code.

**Still not done: the view itself is not written.** `IntegrationView.as_event()`
and the rows' `as_event()` have no caller on the operator path, deliberately:
`status` is read-only and must work on a node whose ledger cannot be written.
The watchdog's ledger is its own leaf, not the `az-auditd` chain. `az-auditd`
declares a matching `watchdog.fenced` schema derived from `UNIT_NAMES` and
`FenceReason`, including bounded detail and the previous/current state fields.
Nothing yet submits watchdog records to that central chain.

## 8. The edge axis carries eight words, not two

[#44](https://github.com/01rabbit/Azazel-Nexus/issues/44) requires the five
Edge checks to fail **separately** on the display as well as in the decision,
so the edge row leads with one word per distinct next action:

| word | what it means | what an operator does |
| --- | --- | --- |
| `absent` | no package at the fixed location | install it; this is a deployment step |
| `corrupt` | a package is there and cannot be read as the pinned one | replace it; nothing about it was verified |
| `version-mismatch` | the manifest declares another version | install the pinned one; this one was not evaluated |
| `digest-mismatch` | the artifact is not the one its manifest describes | **a security finding**; report it, do not repair it |
| `unhealthy` | the health contract answered and did not say healthy | read the posture checks in the answer |
| `not-running` | present, matched, healthy, and the payload is not up | start it |
| `unknown` | no package root is configured, or a check was not run | nobody looked; this grants nothing either |
| `verified-ready` | all five checks passed | nothing |

Folding these into "Edge: not ready" would send somebody to install a package
that is already installed and has been tampered with. The leading word names
the **earliest** failure in check order, so a digest mismatch is never buried
under a consequence discovered later, and all five checks are printed
underneath whatever the leading word says.


## 9. Integrated Edge loop observations (I3)

After the unchanged six-axis integration view, status prints a Fabric status
projection line and a separate `edge loop:` section. This adds no axis values,
readiness claims or enforcement authority. Intake and explainer each report
`running`, `stale (snapshot expired)` (over 30 seconds), or
`unavailable (snapshot absent or refused)`. A fresh snapshot is observation evidence,
not a process probe; the explainer writes only on change and quiet snapshots
can become stale.

Intake includes last processed age, processed and accepted counts, top refusal
counters (always including `evidence_segment_full` when nonzero) and
`storage_failed`. A last intake line shows the Deception Lite decoy apart from
Edge, as `decoy (Deception Lite; Nexus's own observation, not Edge's; not
hardware evidence): accepted N; last accepted Ns ago; refused M (CODE=n, …)`
or `decoy (Deception Lite): not listening (decoy socket not open); refused M`;
the decoy's refusal codes appear there and not among Edge's.
An incident whose evidence was not all stored is marked
`(evidence not stored)`. Explainer includes explained count, chain integrity, the
fixed recovery hint, last-attempt M.I.O./Knowledge availability and audit drops.
The operator sees up to five recent pseudonymous incidents, severity/count,
technique ids, a sanitized explanation summary and validated citation fields,
for example `T1110 Brute Force [claim T1110] (static; Knowledge Lite bundle
sha256:0123456789ab generation 7; as of 2026-10-18T00:00:00Z; source: MITRE
ATT&CK technique)`: freshness, the shortened bundle digest, generation, the
lookup instant and the bundle's dataset citation (`source: not declared` when
it has none; a citation with address or number syntax is not shown). Rows
written before these fields existed read `(bundle, generation and lookup time
not recorded)`. Every action reads
`Edge would isolate (observe-only, not executed)`; a closed incident only means
the observation group ended. Missing or malformed recent data is independently
unavailable. No address or raw attacker text is rendered from loop snapshots.

Fabric's optional `StatusView` is now projected from the capability state and
available set status already shows. Failure reports a fixed code; no exception
text enters the screen. The deterministic summary remains available regardless
of loop components or Fabric. See [I3 choices and limits](integration-loop.md#i3--operator-view-and-audit-explain--audit--implemented).
