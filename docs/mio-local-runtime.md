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


## 8. Bounded local advice (Milestone 3)

The separate payload verb `mio.local.infer` accepts the situation frame
specified in [the entry contract](mio-runtime.md#local-advisory-payload-path-milestone-3).
It has one bounded ordinal argument, `deadline_ms`; the caller cannot choose
a model, runtime, path or option. It admits SERVICE only, and the daemon's
`PrincipalPolicy` resolves only `azmioentry`. `model.activate` retains its
existing principal and identifier contract.

`LocalRuntimeService` has trusted composition points for admission, reserve,
model/runtime IDs, runtime resolution and a server implementing the
`mio_serve.LocalServer.infer` contract. Inference checks admission, the reserve,
runtime resolution and the inspected model before calling the server. The
production defaults refuse. The prompt uses fixed generation limits (1024
output tokens, temperature 0); callers cannot override them.
`local_advisory.build_prompt` constructs the messages. `LocalServer` sends
`response_format` with a JSON schema requiring string `advice` and a `fields` object with seven required strings:
`interpretation`, `check_1`, `check_2`, `check_3`, `alternative`, `missing`, and
`cited_facts`. Generation strings are nonempty, with advice capped at 200 characters and each
field (including `cited_facts`) at 160; extra fields
are refused. The schema constrains generation;
`read_local_advisory` still independently checks every response and retains its
512-character reader limits for older valid replies. The 1024-token budget
(previously 512) gives bounded JSON more room to close; only worst-case
generation latency increases, while short replies can finish earlier. Existing
request deadlines remain in force.
Test-only compositions can inject a runtime resolver and `LocalServer` without
adding an entry to production `RUNTIMES` or opening the admission gate.

Advice is returned to the caller only after the bounded advisory reader
accepts it. Malformed JSON, instruction shapes and oversized output become
NOT_ADVICE; timeout becomes TIMED_OUT; runtime exceptions become FAILED.
Exception messages and advisory-refusal details are never recorded. The
router owns terminal outcomes and the existing fallback/privacy rules.
`local.jsonl` contains only request digests/counts, advisory digests/counts
and fixed refusal codes, plus the shared protocol's bounded refusal metadata.
Tests use fake servers and sentinel text; they do not require llama-server.


## 9. Deterministic local quality guards

`gate_frame(frame)` validates a frame and returns either `None` (continue with
normal admission checks) or a fixed reply with `outcome` and `reason` equal to
`out_of_scope` or `insufficient_information`, plus `advice` and empty `fields`.
Entry and local services apply this gate before observing or invoking a provider.
The entry reply uses the deterministic handoff route. The audit records the
request digest/counts and `mio.local.gated` with only the fixed reason.
These replies do not establish provider admission or measured Core reserve.

The scope gate uses a fixed Japanese/English security operations vocabulary
against question and context text. With no context, an in-scope question also
needs a concrete target: a number, address/host identifier, or labelled
host/account/user. Otherwise the fixed answer requests the target host/account,
time, source, count/volume, and related logs. Scope is checked first.
This lexical gate is intentionally conservative; it does not infer intent.

`build_prompt(frame)` replaces the entire text of any context item containing
an injection marker (ignore previous instructions, including the “all” variant;
`rm -rf`; 無視して; `enforcement=`; `block_all`) with a fixed omission marker.
It does not mutate the caller's frame. The original frame must be passed to
`read_local_advisory(text, frame)` after inference. On accepted advice, the reader
adds the fixed observation “入力に命令調の文字列が含まれていた” when a marker was
present, independently of model compliance. The original item is excluded from
citation evidence. Matching is lexical and does not detect every injection.

The local reader retains all `read_advisory` instruction/URL/control/size checks.
It additionally refuses malformed local fields as `local_schema`, unknown numeric
or structured identifier tokens in advice or any field as `ungrounded_facts`,
and language mismatches as `language_mismatch`. Facts must occur in the question,
retained non-injection context, or the exact trusted reference actually sent in
the prompt. Model text and source are NFKC-normalized before exact token matching,
including numeric formatting. ASCII identifiers containing both letters and digits
(with internal `.`, `_`, or `-`) and IPv6 literals must match as whole tokens;
numeric fragments of identifiers or addresses cannot ground separate claims.
Reference-only allowances are limited to ATT&CK `Tdddd[.ddd]` / `TAdddd`, `D3-...`,
`CVE-yyyy-nnnn...`, and standalone four-digit Windows event IDs (including
`Event ID NNNN` / `イベントID NNNN`). Small reference numbers such as `3`, `5`,
and `10` cannot substantiate situation counts. Unlabelled plain lowercase words
without digits remain unchecked, a known limit of lexical grounding. Prose shapes
are not facts: hyphenated or dotted words without digits (`command-and-control`,
`e.g`) unless they carry `@`, `/`, `:` or are domain names, and list enumerators
(`1. `). `60-second` grounds as `60`. A digit-free span of 12+ characters occurring
three times in one value is a looping generation and refuses as `degenerate`. When
a value reaches its generation cap (advice 200, fields 160) without ending a
sentence, the trailing fragment is deleted back to the last sentence end; nothing
is added. These checks are lexical and do not catch wrong-but-fluent claims. Model-written
`cited_facts` prose overlap is no longer a refusal criterion. After validation,
that field is replaced with source fact tokens used in the answer, deduplicated
in source order and joined with `、` (Japanese) or `, ` (English), capped at 512
characters. Reference-only facts are not rendered as situation citations. With
no quoted facts it says 「状況から引用できる具体的な事実はありません」 or
“No specific facts quoted from the situation.” The response digest and audit
counts describe this final delivered document.

Advice matching `[A-Za-z0-9_.:-]{1,64}` is replaced with the validated
`interpretation` in either language. For Japanese questions, each prose field
still requires kana; other label-like fields of at most 32 characters are tokens
and exempt from that prose check. English prose to Japanese questions remains
refused. English questions require Latin letters and no Japanese characters.
This is a deterministic language heuristic, not language detection.
These failures become NOT_ADVICE with fixed refusal codes. The frame-less reader
form exists for re-reading validated socket replies and checks shape/safety only;
inference and quality evaluation must supply the original frame.

## Reasoning reference injection

The system prompt in both languages instructs the model to adapt generic
references to the facts without copying them, and to copy only exact short
situation phrases into `cited_facts`. `reference_message` shares the exact
1200-character capped reference between prompt construction and validation.
The quality benchmark passes this same reference and reports refusal counts
by reason in its metrics and Japanese summary.

The service supports optional signed-pack playbook data and a deadline-bound
Knowledge lookup callable. Matching occurs after the existing frame gate and
admission checks, before inference. Accepted replies attach deterministic
reference metadata from trusted inputs; gated replies are unchanged. Lookup
failures proceed without Knowledge and audit a fixed unavailable state.

Production `main()` leaves both dependencies unset because it has no active
Mission Pack / commissioned installed-inventory resolver. The exact injection
and trust-refresh requirements, schema, matcher and offline benchmark options
are documented in [Reasoning playbooks](reasoning-playbooks.md).
