# Local model runtime admission (#97)

The purpose of this work is **not to run a model.** It is to fix the
boundary before anything can, because a containment written after the thing
it contains is a containment shaped by what that thing turned out to need.

Nothing described here starts a process on any node this build runs on. That
is the shipped state, not a limitation being worked around.

---

## 1. Three refusals, and none of them is redundant

| refusal | where | what defeats it |
| --- | --- | --- |
| the runtime allowlist is empty | `model_runtime.RUNTIMES` | a reviewed code change adding a runtime |
| the unit is not granted | `activation.UnitDefinition.wiring` | the same code change |
| the Core reserve is unmeasured | `model_runtime.readiness` | taking the measurement (`HG-05`) |

Wire a runtime and the reserve still refuses. Measure the reserve and the
empty allowlist still refuses. Grant the unit by hand and inference still
refuses; the service starts only after its installer-owned audit leaf is writable.

Each answers a different question, so none substitutes for another:
*is there a binary here*, *may this node run it at boot*, and *is this node
in a state where running it is safe*.

---

## 2. The service boundary, and the account that is not reused

`az-mio-locald` — its own unit, its own system account (`azmio`), its own
socket (`mio`), its own runtime directory, one writable path, and
`PrivateNetwork=yes` on top of the `IPAddressDeny=any` every unit here
carries.

**It is not the fetch service and shares nothing with it.**

| | `azfetch` | `azmio` |
| --- | --- | --- |
| may reach the network | yes, one address family | **no network namespace at all** |
| may run a program | no | one, from a fixed list |
| writes | `/var/lib/azazel/fetch` | `/var/lib/azazel/mio` |
| socket | `fetch` | `mio` |

`ServiceProfile` refuses a profile that sets both `is_artifact_fetcher` and
`is_model_host`: together they are a path from a remote byte to a local
execution, which is the shape the two accounts exist to keep apart. #98's
remote inference transport inherits neither account, neither allowlist and
neither egress exception.

---

## 3. What a caller may say: two symbols

The metadata verb `model.activate` takes `model_id` and
`runtime_id` — both `IDENTIFIER`.

`protocol.ArgumentKind` has **no free-text member**, so there is no way to
*express* a command, a path, an environment variable, a socket address or a
model option in a request. That is not a check this service performs; it is a
shape a request cannot take. A control plane that could pass a model option
could pass one that loads a plugin, and every sentence in this document would
be advisory.

The service resolves both symbols itself: the runtime through the package's
own allowlist, the artifact through the directory it owns. **The caller never
names a file and never names a program.**

### The runtime allowlist is code, not commissioned data

`RUNTIMES` lives in `src/azazel_nexus/model_runtime.py`. A runtime arrives by
a reviewed change to that file — never as commissioned data, never as an
operator setting, never as something discovered on the node.

This is deliberately *unlike* the Source Registry, and the difference is the
principle: **an endpoint is a fact about a deployment; a binary is a thing
that executes.** Signed deployment data is the right shape for the first and
the wrong shape for the second.

A `RuntimeBinary` also cannot be declared with an argv that has a hole in it
(`{…}` or `%…`): an argv with a hole is an argv something fills.

---

## 4. The model is data

| refused | because |
| --- | --- |
| an executable bit (any of the three) | a file the node may execute is a file something may arrange to have executed |
| not a regular file | a symlink, a fifo or a device is a name for something else, and what it names can change after the check |
| archive magic | unpacking is the step where one file becomes many, and one of them is a script |
| an ELF header or a `#!` line | it is a program |

Checked by **content**, at the file's own offsets: an extension is a claim by
whoever wrote the filename, and `ustar` lives at byte 257 rather than at the
start.

Checked with `lstat`, so a symlink is judged as a symlink rather than as
whatever it currently points at.

**Refused, never repaired.** Clearing an executable bit would be this module
deciding that a file which arrived executable was meant not to be — and the
interesting question is who made it executable.

No hook, no plugin load, no archive extraction, no tool call. `model_import`
already refuses `shutil` for the same reason: importing it would put
`unpack_archive` one attribute away from a module whose contract is that it
unpacks nothing.

---

## 5. Containment, and the two numbers the unit file must not state

`Containment` is memory, CPU, processes, file size, a deadline, loopback-only
and no outbound network. It is **derived from the measured Core reserve**, so
there is no containment on a node that has not measured one — which is every
node this build runs on.

That is the point rather than a limitation. A limit chosen without a
measurement is a number somebody liked, and a cgroup set from it either
strangles the node's own work or fails to protect it. Which of the two it did
is discovered on the node, not here.

### What the unit file states

`CPUQuota=40%`, `TasksMax=64`, `LimitFSIZE=16777216`, `PrivateNetwork=yes`.
These need no measurement. The quota is below half on purpose: the
deterministic path is what this product *is*, and a provider that can take
most of the CPU is a provider that decides how fast the arbiter runs.

### What it must not state, and `ServiceProfile` refuses

- **`MemoryMax`** — derived from the measured reserve and the provider's
  *declared need*. Not from the spare: a provider given everything the node
  can spare will use everything the node can spare, and the reserve then
  holds only because nothing else asked. A ceiling at the declared need is
  also what makes the declaration mean something — a provider that exceeds it
  is one whose declaration was wrong, and the node finds out by the limit
  rather than by running short.
- **`RuntimeMaxSec`** — this bounds how long the **unit** runs. The deadline
  this product needs bounds **one inference**. Putting the inference deadline
  on the host would terminate a healthy long-running service on a timer and
  record it as a failure: a restart loop that reads, from the journal,
  exactly like a provider that keeps dying.

Both belong to the scope one provider runs in, not to the host. A static
value for either would be an invented number in the one file an operator
trusts.

---

## 6. `HG-05` refuses a node that is sound in every other way

Catalog valid, artifact verified and inert, runtime resolved, admission
granted — and **still no activation**, because the Core reserve is unmeasured.

> "Verified" and "may be used" are not the same word.

`readiness` checks the reserve **first**, ahead of admission and ahead of the
artifact. Every other reason it could give is something an operator can go
and fix on this node; the unmeasured reserve is not, today. Reporting a
fixable reason while an unfixable one also holds sends them to do work that
will not help and tells them the real answer afterwards.

`ActivationReadiness` has three values. `REFUSED` and `NOT_ASSESSED` are both
"no" and are not the same fact: one is a decision, the other is the absence
of one. Collapsing them is how a node that never checked comes to look like a
node that checked and was satisfied.

---

## 7. Edge authority is unchanged, in every state

**The deterministic arbiter from Azazel-Edge holds the final authority to
decide and to enforce.** `FULL -> LITE -> CORE` is a capability state, never
an authority state.

A local model runtime is the component most likely to be mistaken for an
exception, because it is the one that appears to think. So
`tests/unit/test_mio_locald.py` enumerates the states — absent, refused for
an unmeasured reserve, refused for an unwired runtime, ready on a fixture
node, crashed, rolled back — and asserts the same properties across all of
them:

- the deterministic path is never blocked
- no state grants an Edge baseline (the unit is `SUPPORTING`, never
  `EDGE_BASELINE` and never `ENFORCEMENT`)
- `model_runtime` uses no name touching a lease, an unmask, a grant or
  enforcement — scanned over the **syntax tree**, because prose about
  granting is prose, and a scan that confused the two would be silenced by
  whoever next explains why nothing is granted
- the Edge answer is identical whatever the runtime is doing

Enumerating the states is the point. A test that drove one of them would
report an invariant it had checked once.

---

## 8. What this does not establish

- No real model, no real inference, no real provider admission. Every test
  fixture is package-owned and fixed, and none claims otherwise.
- `HG-05` remains unmeasured. Nothing here takes the measurement or stands in
  for it.
- What systemd actually enforces is `HG-01`/`HG-02` and is not executed by
  any test in this repository.

The M.I.O. status expression is unchanged:

> M.I.O. routing and commissioning control plane implemented; provider
> execution unavailable pending hardware evidence and provider integration


## 8. Closed-choice local advice

Production admission remains closed: `RUNTIMES` is empty and HG-05 is unmeasured.
The following pipeline runs only with explicitly injected admitted test/bench
components. It adds no authority, environment settings or remote route. P2/P3
frames remain NEVER_REMOTE, including when a local attempt fails.

After the existing scope/information gate and admission checks, deterministic
matching supplies at most three playbooks. Each option has its own 160-character
title and 160-character first interpretation line, independent of the separate
1200-character reference cap. `other_suspicious` and `benign` are always options;
`undetermined` is system-derived and never offered to the model.

Two temperature-zero requests use a grammar permitting exactly one A–E letter,
with the options reversed on the second pass. The user message and selection
instructions are otherwise identical. Letter probabilities are mapped back to
option IDs and averaged. Disagreeing argmax selections or a top-minus-runner-up
margin below `MARGIN_MIN=0.10` produce `undetermined`. This threshold is provisional,
not tuned on held-out data and not a precision claim. Without a complete usable
single-token probability distribution on both passes, only selection agreement
is used; no margin is invented. Invalid letters fail the request safely.

Benign is retained only without an injection marker in the question or context,
and with affirmative evidence in a system-sourced kind: `change_record`,
`change_ticket`, `maintenance_window`, `asset_inventory`, `baseline`, `schedule`,
`approval_record`. Alert, log and telemetry kinds cannot establish benign.
English terms require token boundaries; Japanese terms require term boundaries.
Simple negations such as 未承認 / 不承認 / 承認なし / not approved / unapproved /
unplanned / unscheduled veto that item. A failed guard yields `undetermined`,
never an attack class. The integrating collector must assign `kind` from trusted
configuration, never copy it from log content. Attacker text inside a legitimate
system-sourced item remains a residual risk; these lexical guards do not establish
semantic truth or authenticate a change approval.

For a definite candidate, a separate conditioned JSON generation returns only
`reason`, `check_1..3`, `missing` (each at most 160 characters). Reason must contain
an exact quoted situation phrase of at least three characters. Existing instruction,
Unicode, language, lexical grounding and degenerate-output checks apply to every
model field. Opposite-class reason vocabulary drops the explanation. Negation
semantics are intentionally conservative: even a negated opposite term can drop
it. Explanation failures preserve outcome `advisory`, the candidate and trusted
text, with audit reason `explanation_dropped:<fixed reason>`. Undetermined skips
explanation. Untrusted injection-bearing items cannot ground or supply quotations.
The older advisory reader remains a shared lexical validator; its free verdict
schema is no longer a local service response.

One monotonic absolute deadline starts before frame processing. Each generation
receives only the remaining budget, reserving 20 ms for delivery; explanation is
skipped with less than one second left. An explanation timeout keeps the validated
candidate. Optional Knowledge lookup is skipped as `skipped_deadline_contract`:
its existing synchronous callable cannot accept a remaining budget. Bench fixtures
can still supply bounded Knowledge references to explanation. As with existing
HTTP transport, the injected server must honor the supplied deadline; no Python
wrapper can cancel an arbitrary blocking injected callable.

## 9. Delivered provenance and process boundary

Every document starts with the fixed Japanese or English local-small-model
provenance banner, explicitly saying that candidates are not conclusions and an
operator must verify evidence. Any template playbook adds the unreviewed-template
notice. Candidate and other hypotheses use system-set labels. Matcher evidence
lists keyword, technique-ID and context-kind hits. Other candidates retain equal
title prominence, including benign as a hypothesis. State says converged or split;
there are no high/medium/low confidence labels. Measuring precision before adding
such labels remains follow-up work.

`fields` contains system labels, separate trusted check/first-response/missing
fields per playbook, and separate `model_reason`, `model_check_1..3`, `model_missing`
fields only when the explanation passes. Without matches, fixed generic trusted
checks/missing are supplied. Citations are deterministic whole fact tokens from
retained situation text, capped at 512 characters and explicitly marked untrusted.
The display evidence preview is capped at 1000 characters; full evidence is in
machine fields. Trusted text is never joined with model text.

The machine contract is exactly `candidate` (`option_id`, `kind`), `alternatives`
(option ID/kind/title), `match_evidence` (option ID/keywords/technique IDs/context
kinds), `provenance` (`route: local`, `model_id`, `mode: closed_choice`,
`playbooks_reviewed`, `state: converged|split`, `guard: null|fixed reason`), and
`explanation_source: model|trusted`. Socket client and entry service independently
validate bounds, exact keys, identities, evidence correspondence and state/guard
consistency. Old `playbook` and `knowledge` envelopes are rejected and not forwarded.
Gated replies keep their existing shape. Audit contains fixed reasons, IDs, scores,
digests and counts, never situation or generated prose.

## 10. b11716 probability compatibility and evaluation

The pinned upstream [server-task.cpp](https://github.com/ggml-org/llama.cpp/blob/b11716/tools/server/server-task.cpp)
serializes chat `logprobs.content[].top_logprobs`; the
[server context](https://github.com/ggml-org/llama.cpp/blob/b11716/tools/server/server-context.cpp)
has pre-sampling and post-sampling probability paths. Pre-sampling probabilities
are vocabulary probabilities, so top 20 may omit some grammar letters. Post-sampling
probabilities can lose alternatives at temperature zero. Source inspection therefore
establishes endpoint support, not usable probabilities for this particular model
and image. Docker/image execution was unavailable in the implementation sandbox.
The actual request asks for `logprobs=true`, `top_logprobs=20` plus per-request
GBNF. The parser accepts only all option letters, finite nonpositive logprobs,
positive non-one-hot probabilities, and a single token matching the delivered
letter. Missing/incomplete/malformed probabilities use agreement fallback. Fake
endpoint tests cover both response paths without needing a socket bind.

See [Reasoning playbooks](reasoning-playbooks.md) for the offline evaluation contract.
No measured quality improvement, target-machine latency, or precision is claimed.
Online re-review is deferred: P2/P3 never leave the node; P0/P1 would require remote
opt-in/trust and a frame-retention design absent from this build.
