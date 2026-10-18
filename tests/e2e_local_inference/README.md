# Real local inference E2E

Run in the b11716 container with the repository mounted:

```sh
AZ_LLAMA_SERVER=/path/to/llama-server AZ_GGUF_DIR=/dir/with/gguf \
  PYTHONPATH=src:runtime/src python -m pytest -q tests/e2e_local_inference
```

Without both variables, an executable server, and a GGUF file, the suite
skips. Once assets exist, missing implementation APIs and inference failures
are failures, not skips. Nothing is downloaded. The smallest GGUF is selected
by size, then filename; the benchmark lane covers the full model matrix.
The supplied binary must be the plan's CPU b11716 build. The harness labels
its record b11716; it does not independently attest the binary's build tag.

Each case starts a fresh Python subprocess with a short temporary
`AZAZEL_ROOT` set before runtime imports. It stages a hard link to the real
GGUF (copies across filesystems), fixes a `RuntimeBinary` argv, and starts
`LocalServer` over AF_UNIX. The binary itself is linked into the package
executable path under that root. No real keys or network transport are used.
The fixture reserve and predictions are explicitly test evidence, never HG-05
or production admission. The production `RUNTIMES` mapping stays untouched.

The service path is composed in process: entryd -> router -> locald ->
`LocalServer`. Requests use the real `mio.advise` registry binding and
`transport.Request`, with a test operator principal. This does not establish
kernel peer authorization or service socket ownership; existing transport
tests cover those boundaries.

## Integration seams for lanes A/B

The fixed `LocalServer(record, root=..., socket_path=...,
start_deadline_s=...)`, `start`, `health`, `infer(request, deadline_s=...)`,
and `stop` contract is used directly. Inference results must be dataclass
records with `text` and `tokens_out`. The existing `RuntimeBinary` constructor
holds the fixed model argv; no unspecified record-builder name is assumed.

All constructor alignment is confined to `harness.compose`:

* `LocalRuntimeService(staging, reserve, admitted, runtime, server)` takes
  `admitted(model_id) -> bool`, `runtime(runtime_id) -> RuntimeBinary`, and
  a server instance implementing the fixed LocalServer contract.
* `MioRouter(local, remote)` uses the existing constructor injection.
* `MioEntryService(router, profile_reader, local_admitted, local_refusal,
  predictions)` takes an injected router, a profile reader, admission
  boolean/reason, and fixture predictions. These entry constructor keyword
  names are integration assumptions: the orchestration contract fixes the
  verb and flow but does not specify the entry constructor signature.

The harness deliberately fails if these seams are absent; it never mutates
production module globals or private service members to make a test pass.
Entry verb arguments are bound by their declared names from a closed set of
test identifiers, privacy class, and deadline. Payload is the situation frame
object itself. If lane A chooses a different payload wrapper, align `invoke`.

## Evidence and limitations

The four privacy classes must return actual model advice with an ANSWERED
local terminal event. No response text is substituted for positive tests.
Each case verifies the audit chain and scans persisted state for question,
context, and raw real or injected response text. Raw model output is never
printed by the harness.

Instruction, oversized, and malformed JSON cases first call the real model,
then replace the returned result's text via the injected test server adapter.
They test the locald/parser/router refusal path deterministically, not the
probability of a model producing hostile output. They require NOT_ADVICE,
exactly one spent fallback to deterministic handoff, and no answered terminal.
The oversized case tests advisory byte bounds, not an oversized HTTP body.

The deadline case shortens only the adapter's actual LocalServer call to one
microsecond. Route selection gets a viable deadline, allowing the actual
Unix HTTP deadline to be observed as TIMED_OUT. The missing socket case
stops a previously healthy real server and removes its socket before dispatch.
No TimeoutError or socket exchange is fabricated.

The Linux crash case obtains the real server PID using SO_PEERCRED and
checks its `/proc` command line before SIGKILL. It verifies health loss,
one allowed restart, a second real crash, and a fence persisted through
`BudgetLedger` reload. This composes `LocalServer` with the existing production
`RestartBudget` and `BudgetLedger` in the harness; it does not establish the
new long-lived supervisor's internal budget wiring. The plan does not name
that API. The crash case is skipped on macOS.

Edge checks compare the fixed deterministic cognition reading and persistent
state outside M.I.O. before/after answer, timeout, refusal, and crash. A test
authority/expired-lease marker must stay byte-identical. This is evidence that
the local path writes no authority state; it does not run the external Edge
arbiter, which is not part of this repository.

Every child process has a 300-second outer deadline and always calls stop in
`finally`. If a platform denies AF_UNIX binds, classify the run as an
environment failure; never substitute a fake server and call it real evidence.
