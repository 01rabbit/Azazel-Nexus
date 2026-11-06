# Real local inference E2E

Run in the b11716 container with the repository mounted:

```sh
python -m pip install -e '.[dev,mio]' -e ./runtime
AZ_LLAMA_SERVER=/path/to/llama-server AZ_GGUF_DIR=/dir/with/gguf \
  PYTHONPATH=src:runtime/src python -m pytest -q tests/e2e_local_inference
```

The `mio` extra resolves the exact source commit pinned in `pyproject.toml`; do
not install MIO from a floating branch for this test.

Without both variables, an executable server, and a supported candidate GGUF file, the suite
skips. Once assets exist, missing implementation APIs and inference failures
are failures, not skips. Nothing is downloaded. The smallest supported candidate GGUF is selected
by size, then filename; the benchmark lane covers the full model matrix.
The supplied binary must be the plan's CPU b11716 build. The harness labels
its record b11716; it does not independently attest the binary's build tag.

Each case starts a fresh Python subprocess with a short temporary
`AZAZEL_ROOT` set before runtime imports. It stages a hard link to the real
GGUF (copies across filesystems), uses `llama_server_record` to fix its argv, and starts
`LocalServer` over AF_UNIX. The binary itself is linked into the package
executable path under that root. No real keys or network transport are used.
The fixture reserve and predictions are explicitly test evidence, never HG-05
or production admission. The production `RUNTIMES` mapping stays untouched.

The service path is composed in process: entryd -> router -> locald ->
`LocalServer`. Requests use the real `mio.advise` registry binding and
`transport.Request`, with a test operator principal. This does not establish
kernel peer authorization or service socket ownership; existing transport
tests cover those boundaries.

## Composition

The harness uses the real `llama_server_record`, `LocalServer`,
`LocalRuntimeService`, `MioRouter`, and `MioEntryService` APIs. Locald receives
fixture model/runtime IDs, a runtime resolver, reserve, test-only admission
and the observed server object. Entry receives `router`, `profile_reader`,
`local_admitted` and `predictions_reader` constructor injections. Admission is
a callable. All production defaults stay closed.

Locald uses `local_advisory.build_prompt`; LocalServer sends the shared
`response_format` JSON schema and locald still calls `read_local_advisory`.
The supported candidate names and digests, plus the single container entry
script, are in the [bench README](../../bench/mio_local/README.md).

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
`BudgetLedger` reload. `LocalServer` receives the fixture `RestartBudget` and
`BudgetLedger`; its own `start()` spends and persists the budget, and refuses
the exhausted restart. The crash case is skipped on macOS.

Edge checks compare the fixed deterministic cognition reading and persistent
state outside M.I.O. before/after answer, timeout, refusal, and crash. A test
authority/expired-lease marker must stay byte-identical. This is evidence that
the local path writes no authority state; it does not run the external Edge
arbiter, which is not part of this repository.

## MIO shared generation scenario (fixture-authorized lab evidence only)

Everything above is the existing **local advisory** path: `mio.advise` ->
router -> locald `_infer` -> `LocalServer`, which returns advice through
`local_advisory`. The `generation` scenarios cover a different path, the **MIO
shared generation result**: entryd's ordinary `mio.advise` fast-assess call ->
`LocalRuntimeService` (`mio.local.assess`) -> `GenerationLane` -> the pinned
`azazel_mio` `AssistantCore` -> the real `llama-server`. Its outcome is a
`slow_analysis` receipt that is polled via `mio.local.generation.result`. It is
not the advisory text returned by the router.

**Fixture admission.** `GenerationLane` is closed in production. The scenario
uses a test-only `GenerationLane` subclass that accepts one unsealed,
test-only `GenerationCapability`. It does not set or patch
`GENERATION_ADMISSION_ENABLED` or `LOCAL_MODEL_ADMISSION_ENABLED`, mints no
production seal, and touches no HG/admission code. The scenario asserts both
constants stay `False` and that production `authorized()` rejects this
capability in the currently closed configuration. That assertion does not
isolate seal validation from the closed feature flags. The printed receipt is labeled
"FIXTURE-AUTHORIZED LAB EVIDENCE ONLY". It is not HG-05, HG, or production
admission evidence.

**Composition.** A small test adapter (`InProcessLocaldAdapter`) replaces only
`entry.local` so the ordinary fast-assess and result calls reach
`LocalRuntimeService.handle` directly. This stays **in-process** (service
composition). It is not a production socket/process test: there are no
azmio/azexplain accounts, no AF_UNIX service sockets and no peer-credential
checks. For these generation cases only, `llama-server` is a separate test
process launched by the harness from the fixed fixture argv, and its actual
HTTP request/response travels over AF_UNIX. This bypasses Nexus's production
`LocalServer` startup/admission lifecycle **only inside this disposable test
process**; production flags stay false. It proves model-wire interoperability
for the fixture path, not that a Nexus production model can be admitted or
started. The serving process writes stdout/stderr to `/dev/null` unless the diagnostic option below is set.

**What is checked.**
- `generation`: `slow_analysis` goes `queued` -> `complete`, with
  `generation_method == "model"`. The probe records calls to the real
  fixture AF_UNIX HTTP boundary; tokens and timings are recorded from successful
  real responses. A response without usage stays `unknown` and is never
  invented. This fixture lane has a 30-second deadline. A slow CPU model or
  constrained JSON response can time out/degrade; this scenario asserts
  completion and does not test that timeout outcome.
- `generation_degraded`: the real server is stopped before inference dispatch.
  `llama-server` is stopped before dispatch. The fixture records one failed
  AF_UNIX request and expects a typed `degraded` receipt with unknown usage and
  an explicit model-free `static_reference` fallback, with no successful call
  records. No model-generated text or provider-side failure is claimed. This is
  not a timeout case.
- In both: Edge reading and non-M.I.O. authority state are unchanged, and
  formatted Python root-logger messages and persisted files contain no
  question, context, or response text. The harness prints only counts, states and numbers; optional server logs may
  contain server-provided content and must remain in local evidence.
- The Nexus route remains the deterministic handoff in both cases: the fixture
  capability authorizes only the isolated slow GenerationLane job and does not
  admit the router's local advice provider. The model-free fast result and
  model-backed slow receipt remain separate. Because route admission is closed,
  the fast result may be produced by entryd's existing model-free shared-core
  fallback when locald is absent; this test does not attribute it to a separate
  locald process.

The model is the smallest supported candidate GGUF present, chosen by the
existing runner (no new selection and no download). The scenario was written
against, but not yet run in, a specific environment: the tested environment
(host, binary build, model file, resulting numbers) must be recorded by
whoever runs it. Until then none of it is claimed as tested.

**Unproven production gates.** This does not show that a production generation
admission loader, sealed capability, HG-05 admission, real service sockets and
accounts, or real-time latency under the 0.25 s fast budget behave correctly.
The generation job runs asynchronously on a CPU-only server, so its timings
are not production figures.

Every child process has a 300-second outer deadline and always calls stop in
`finally`. If a platform denies AF_UNIX binds, classify the run as an
environment failure; never substitute a fake server and call it real evidence.

## Optional diagnostic capture

Set `AZ_E2E_TELEMETRY_DIR` to an existing writable evidence directory for the
generation fixture. It records the child stdout/stderr and a JSON file with
HTTP phase times and byte counts, process CPU/RSS samples, cgroup v2 files,
argv, health and props. Capture is best effort and recording failures do not
change the scenario result. These requests are non-streaming: the first body
byte is not a token and a timeout before headers cannot establish TTFT or token
speed. Cgroup files reflect what the container can see; hidden ancestor limits
are not established. This does not extend the generation deadline or alter
admission. The other local advisory scenarios use their existing server path.
