# M.I.O. deterministic quality bench

This tool is outside both shipped distributions. It does not admit models,
modify runtime registrations, or measure HG-05. No LLM grading is performed.

`eval_set.json` preserves the fourteen original quality frames, including their
privacy classes. Each case adds `expected_scope`, `expected_insufficient`,
`injection`, `language`, and `key_points`. Each key point is a group of
case-insensitive substring alternatives; matching any alternative covers that
point. Labels express expected behavior, never gate the actual requests.

Run the fake-server tests from the repository root:

```sh
PYTHONPATH=src:runtime/src python3 -m pytest -q bench/mio_quality
```

Run a real campaign with an already-built `az-llama:b11716` image containing
Python 3.11+ and llama-server:

```sh
bench/mio_quality/run_in_container.sh /absolute/models /absolute/new-output
```

The optional third argument selects a model filename. The default is
`qwen2.5-1.5b-instruct-q4_k_m.gguf`. Docker mounts `/src` and `/models` read-only,
`/out` writable, and disables container networking. No packages are downloaded.
The model and executable SHA-256 digests are recorded. The source must include
Lane A's public API before a real campaign can run.

The runner uses the existing bench server builder and runtime inference request,
including `advisory_response_format()`. It applies `gate_frame`, `build_prompt`,
and `read_local_advisory`. Gated cases never call inference; generation is
sequential with temperature zero. Startup/request errors remain in denominators.
The integration adapter uses Lane A's `gate_frame(frame)` contract: `None`
continues inference; a fixed reply dictionary contains `reason`, `advice`, and
`fields`. The reader receives `read_local_advisory(text, frame=original_frame)`.
Missing gate support fails explicitly.

The JSON result has `provenance=bench`, model and evaluation-set digests, runtime
options, per-case outcomes, raw model text, and accepted/fixed advice. Treat this
output as sensitive local evaluation data: the frames include P2 material. It
is retained intentionally for separate human/LLM review and is never sent to a
service by this tool. The companion summary is Japanese Markdown.

Metrics include their numerator and denominator:

- Acceptance and citation rates use the twelve expected model-answer cases.
  Citation checks require at least one exact source identifier/number with no
  invented token, or a literal qualitative excerpt. This is a proxy independent
  of the authoritative reader, not semantic verification.
- Language rate uses all fourteen delivered answers, checking every nonempty
  text separately: Japanese requires kana; English requires Latin letters and
  no Japanese/CJK text. Refused or missing answers score zero.
- Scope and insufficient-information accuracy use all fourteen cases, comparing
  observed gate reasons to labels. These overall accuracies include negatives.
- Injection acknowledgment uses only the injection-labeled case. A fixed
  Japanese/English phrase list recognizes a warning in delivered text.
- Keyword coverage is the micro-average of covered key-point groups across all
  cases. It cannot recognize negation or establish technical correctness.
- Raw and delivered instruction rates use all cases and the existing public
  advisory reader's instruction-shape refusal. The separate delivered-output
  zero flag checks whether any delivered text matches those shapes. Zero is
  not evidence of successful availability; inspect acceptance and errors too.

Outputs are created exclusively, so campaigns do not overwrite old results.
Production admission remains closed independently of every score here.
