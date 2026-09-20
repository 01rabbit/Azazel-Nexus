# Degradation matrix

What stops and what continues, for every condition in every failure mode
(Nexus#30, the consumer side of SO-06).

The acceptance condition inherited from SO-06 is severe and is restated here
because it decides how this table is read:

> "100% continuation" means **zero divergence on the deterministic path**. Not
> "nearly the same".

So the column that matters is the last one, and it reads `yes` in every row.
That is not a claim made by this document: it is
`tests/unit/test_degradation_matrix.py`, which asserts it once per cell and
again for every simultaneous pair, and `Outcome` refuses to be constructed
with a core capability missing.

**This table is generated from `azazel_nexus.degradation.MATRIX`** and checked
against it by `test_the_document_matches_the_table_it_describes`. A row here
that no longer matches the code is a failing test, not a stale document.

## The conditions

| Condition | Degrades | Beyond the core capabilities, also continues |
| --- | --- | --- |
| `local_model_absent` | the depth of explanation and advice | — |
| `remote_path_unreachable` | remote advice | `local_cognition` |
| `knowledge_node_absent` | extended threat context | — |
| `deception_node_absent` | materialisation of a bounded environment | — |
| `knowledge_lite_absent` | the tactical cache | — |
| `knowledge_lite_expired` | the tactical cache, which is present and must be shown as stale | — |
| `deception_lite_absent` | the embedded bounded-environment runtime | — |
| `audit_pressure` | records with the longest retention. The chain itself does not stop | — |

`knowledge_lite` appears under two conditions on purpose: one says there is no
tactical cache, the other says there is one and it has lapsed. A table that
merged them would make a node serving stale intelligence look like a node
serving none.

`deception_lite_absent` is a row issue #30 does not list. Its fourth row
covers the **external** AZ-06 node; the embedded Deception Lite runtime is a
separate component that `capability.py` already sources a capability from.
Leaving it out would have left one optional component whose failure nothing
tests — and would have read as though that component were out of scope. It is
not.

## The five failure modes

| Mode | Disposition | What it means |
| --- | --- | --- |
| `absent` | `not_configured` | Not configured on this node at all |
| `refusing` | `refused` | Configured and reachable, and it declined |
| `hanging` | `deadline_exceeded` | Configured and reachable, and it did not answer inside the budget |
| `corrupt` | `quarantined` | Answered, and the answer could not be used |
| `expired` | `stale` | Answered with something whose validity has lapsed |

One disposition per mode, and no two modes share one. *"We have no Knowledge
node"* and *"the Knowledge node returned something we could not parse"* call
for different operator actions; a system that renders both as "unavailable"
has thrown the difference away before anyone could act on it.

**A hanging component is modelled, never reproduced.** The clock is injected,
and a test advances a counter past a budget and returns. No test in this
repository sleeps, and `test_no_test_here_can_hang` parses both files to keep
it that way. A suite that proved its timeout handling by actually hanging is a
suite that stops being run.

## The matrix

| Condition | Mode | Disposition | Deterministic path intact |
| --- | --- | --- | --- |
| `local_model_absent` | `absent` | `not_configured` | yes |
| `local_model_absent` | `refusing` | `refused` | yes |
| `local_model_absent` | `hanging` | `deadline_exceeded` | yes |
| `local_model_absent` | `corrupt` | `quarantined` | yes |
| `local_model_absent` | `expired` | `stale` | yes |
| `remote_path_unreachable` | `absent` | `not_configured` | yes |
| `remote_path_unreachable` | `refusing` | `refused` | yes |
| `remote_path_unreachable` | `hanging` | `deadline_exceeded` | yes |
| `remote_path_unreachable` | `corrupt` | `quarantined` | yes |
| `remote_path_unreachable` | `expired` | `stale` | yes |
| `knowledge_node_absent` | `absent` | `not_configured` | yes |
| `knowledge_node_absent` | `refusing` | `refused` | yes |
| `knowledge_node_absent` | `hanging` | `deadline_exceeded` | yes |
| `knowledge_node_absent` | `corrupt` | `quarantined` | yes |
| `knowledge_node_absent` | `expired` | `stale` | yes |
| `deception_node_absent` | `absent` | `not_configured` | yes |
| `deception_node_absent` | `refusing` | `refused` | yes |
| `deception_node_absent` | `hanging` | `deadline_exceeded` | yes |
| `deception_node_absent` | `corrupt` | `quarantined` | yes |
| `deception_node_absent` | `expired` | `stale` | yes |
| `knowledge_lite_absent` | `absent` | `not_configured` | yes |
| `knowledge_lite_absent` | `refusing` | `refused` | yes |
| `knowledge_lite_absent` | `hanging` | `deadline_exceeded` | yes |
| `knowledge_lite_absent` | `corrupt` | `quarantined` | yes |
| `knowledge_lite_absent` | `expired` | `stale` | yes |
| `knowledge_lite_expired` | `absent` | `not_configured` | yes |
| `knowledge_lite_expired` | `refusing` | `refused` | yes |
| `knowledge_lite_expired` | `hanging` | `deadline_exceeded` | yes |
| `knowledge_lite_expired` | `corrupt` | `quarantined` | yes |
| `knowledge_lite_expired` | `expired` | `stale` | yes |
| `deception_lite_absent` | `absent` | `not_configured` | yes |
| `deception_lite_absent` | `refusing` | `refused` | yes |
| `deception_lite_absent` | `hanging` | `deadline_exceeded` | yes |
| `deception_lite_absent` | `corrupt` | `quarantined` | yes |
| `deception_lite_absent` | `expired` | `stale` | yes |
| `audit_pressure` | `absent` | `not_configured` | yes |
| `audit_pressure` | `refusing` | `refused` | yes |
| `audit_pressure` | `hanging` | `deadline_exceeded` | yes |
| `audit_pressure` | `corrupt` | `quarantined` | yes |
| `audit_pressure` | `expired` | `stale` | yes |

## What retention pressure may never release

Under audit pressure the node releases the longest-retention records first:
`capture_spool`, then `explanatory_advice`, then `evidence_objects`. The audit
chain is not on that list and cannot be added to it — `retain_under_pressure`
raises rather than dropping it.

A node that freed space by dropping links would have a ledger that reports
itself intact while missing entries, which is worse than having no ledger,
because it is believed.

