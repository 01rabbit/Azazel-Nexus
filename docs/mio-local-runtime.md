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


## 8. Local embedding retrieval (v3)

Production admission remains closed: `RUNTIMES` is empty and HG-05 is unmeasured.
Injected test/bench components grant no production authority. P2/P3 remain
NEVER_REMOTE. There is no model verdict or letter selection.

A second `LocalServer` uses the same pinned llama-server binary over AF_UNIX,
with `--embedding --pooling cls`, CPU execution and no network. It embeds bge-m3
Q8_0 documents: Japanese/English titles, first interpretation in each language,
and all Japanese/English keywords, exactly matching the development probe.
Queries are question + newline + context texts separated by newlines. Normalized
cosine similarity supplies at most three candidates, with entry ID as a stable
tie-break. Keyword/technique/context-kind hits are displayed as 照合の根拠 only.

The locald-owned writable directory holds a document-vector cache keyed by
composed library content/layer digests and embedding model digest. It contains no
situation text. Reloading changed libraries invalidates the in-memory key; the
first admitted retrieval prepares documents, loading a bounded integrity-checked
cache or recomputing it in batches. Writes stage in a private temporary file,
fsync, then atomically promote. Invalid checksums, dimensions or vectors cause
recomputation. The checksum detects corruption; locald ownership is the cache's
trust boundary. An unavailable embedding runtime uses the keyword baseline,
with audited method `keyword` and visible 「照合は簡易方式」. Such fallback has no
fabricated similarity and can never produce a clear state.

Scope rejects only when the existing security lexicon misses AND maximum cosine
similarity is below SCOPE_MIN=0.40. The existing insufficient-information check
is retained. Entryd defers scope to locald because it has no embedding scores;
it still handles the existing insufficient-information gate. Runtime admission,
reserve, artifact and provider gates must pass before embeddings can execute.

Candidates are 「該当する可能性のある類型（類似度順の候補）」 with similarities
rounded to two decimals. Deterministic states use provisional development values
SIM_MIN=0.55 and GAP_MIN=0.09:

- 「候補が明確」: top1 >= SIM_MIN and top1 minus top2 >= GAP_MIN.
- 「候補が拮抗」: other above-threshold cases; a lone candidate has no measured gap.
- 「該当する類型なし」: top1 below SIM_MIN; generic trusted checks and
  other_suspicious wording, with no model explanation.
- 「正当な活動の根拠あり（要確認）」: affirmative, non-negated support in a
  collector-controlled system item and no injection. Benign is first among
  alternatives, never the primary candidate, and state cannot be clear.

The system-kind allowlist is `change_record`, `change_ticket`,
`maintenance_window`, `asset_inventory`, `baseline`, `schedule`, `approval_record`.
Alert/log/telemetry cannot establish benign evidence. Boundaries and conservative
item-wide negation guards remain. Collectors must assign kinds from trusted
configuration, never from log text. Planted text inside a system-sourced item is
a residual risk. Similarity is not correctness or calibrated confidence.

## 9. Optional explanation and delivery

At most one explanation generation is conditioned on the top candidate.
`reason`, `check_1..3`, `missing` are <=160 characters and labeled モデル生成.
Reason must quote retained situation text, with the existing language, grounding,
instruction, degeneration and opposite-class checks. Any refusal, timeout or
provider error drops model text and preserves candidate/trusted guidance.
No-class results skip generation. The fixed provenance banner and template notice
remain. Trusted procedures and model prose stay in visibly separate fields;
citations are deterministic and marked as untrusted situation data.

One monotonic deadline covers retrieval and explanation, with 20 ms delivery
reserve and explanation skipped below one second remaining. Optional synchronous
Knowledge lookup remains skipped until it accepts a remaining deadline. Bench
fixtures can provide references. Injected clients must honor their deadlines.

The strict machine fields remain `candidate`, `alternatives`, `match_evidence`,
`provenance`, `explanation_source`. Provenance now uses `mode: embedding_retrieval`,
`state: clear|split|none`, `retrieval: embedding|keyword`, ordered `similarities`,
`benign_evidence`, `guard: null`, plus route/model/review metadata. Socket client
and entryd independently validate exact keys, bounds, finite sorted scores,
state/threshold consistency and the prohibition on benign primary candidates.
Old model-pick documents are rejected. Maximum response is 48 KiB; audit contains
fixed symbols, IDs, digests and counts, never situation or generated prose.

## 10. Evaluation limits

See [Reasoning playbooks](reasoning-playbooks.md) for the benchmark contract and
[model catalog](model-catalog.md#embedding-retrieval-development-artifact) for the
embedding artifact declaration. Existing 14 cases and the former heldout 30 are
now development data; a NEW independently supplied set is required for final
pass/fail. Fake-server checks establish mechanics, not model accuracy or device
latency. No target-machine precision, quality improvement or admission is claimed.
Online re-review stays deferred: P2/P3 never leave; P0/P1 require opt-in/trust and
a retention design absent from this build.
