# Lane D implementation report

Only `bench/mio_local/` was changed. No commit, push, GitHub action, production
admission change, real key, source-tree edit, or boundary-scan exclusion.

## Files

- `runner.py`: model × four-condition runner, Lane B public record builder and
  LocalServer lifecycle, failure accounting, digest/environment metadata, JSONL.
- `transport.py`: bounded AF_UNIX HTTP/SSE observation, first-content TTFT,
  absolute watchdog, token/timing validation, no output retention in records.
- `metrics.py`: nearest-rank distributions, Linux process CPU/RSS sampling,
  effective cgroup/physical memory ceiling.
- `load.py`: parameterized CPU/memory pressure; ready handshake, finite lifetime,
  graceful stop followed by terminate/kill and reap.
- `frames.json`: four fixed synthetic security-operations frames, paired
  Japanese/English authentication and DNS questions, P0-public.
- `summary.py`: Markdown table from bench-only records, with missing-data counts.
- `test_runner.py`: 33 fake-server/transport, metric, condition, load, contract,
  summary and packaging/source-boundary tests.
- `__init__.py`: development-only package marker.
- `README.md`: record contract, measurement definitions, bounds and complete
  colima dc34 / az-llama:b11716 execution commands.
- `REPORT.md`: this report.

## Small decisions

Each cell uses a fresh process, fixed two server slots, CPU-only execution,
temperature zero and no prompt caching. Client concurrency alone changes
between 1/2 cells. There is no excluded warm-up; frames cycle in fixed order.
Cold startup means process startup through readiness, without flushing host
page caches. TTFT means first nonempty content delta, excluding role-only
messages. Stream-completion metrics include advisory refusals, while failed
streams do not acquire fabricated latency samples. All configured requests
remain in the validity denominator. Percentiles require twenty samples for
that metric. End-to-end output tokens/s and server generation tokens/s are
separate fields; missing token/timing data stays null. The record stores
counts, timing, frame IDs and error type names, never response text or error
messages. Output files are exclusive-create.

Resource sampling is Linux-specific and server-only. Background pressure is
synthetic contention, not measured Edge workload. Library/runtime source scans
were not changed. Packaging verification used temporary copies outside the
worktree to avoid generated product files.

## Verification and raw tails

Required Mac runner used with `AZ_REPO` set to this worktree and fresh
`/tmp/azD.XXXX` basetemps.

Final focused run (bench tests plus both requested boundary modules):

```text
....................................................                     [100%]
52 passed in 0.91s
```

Full `tests/unit` run, once; log: `/tmp/azD-unit.log`:

```text
ERROR tests/unit/test_runtime_transport.py::test_a_payload_is_refused_by_a_verb_that_does_not_declare_one
145 failed, 9354 passed, 30 skipped, 26 errors in 104.34s (0:01:44)
```

Classification of all 171 failing/error cases:

| Cause | Failures | Setup errors |
| --- | ---: | ---: |
| Direct socket bind PermissionError (not runnable in sandbox) | 115 | 26 |
| Decoy bind consequences, including functional readiness | 14 | 0 |
| Missing Linux `/proc` | 12 | 0 |
| Supervisor readiness sees FAILED rather than NOT_CHECKED; unresolved platform/stderr issue | 2 | 0 |
| Denied creation of a worktree under the primary repository's `.git` | 1 | 0 |
| macOS directory setgid mode mismatch, 0710 observed vs 02710 | 1 | 0 |
| macOS AF_UNIX path too long | 0 | 0 |

The two supervisor assertion failures are reported as unresolved; they are
not relabeled as successful or attributed to the benchmark. No production
files were changed.

Ruff: for each of the seven changed `.py` files, `git show HEAD:<file>` was
attempted. All are new files, with no HEAD baseline. Each was separately
checked using `uvx --offline ruff check --output-format concise`; all passed.
After the final edits the whole directory was checked again:

```text
All checks passed!
```

NEW diagnostics: **none** (computed, all seven new Python files clean).
No lint configuration was changed. Three broad exception catches at the
measurement boundary and one at cleanup are locally annotated: the runner
must turn arbitrary provider/lifecycle failures into type-only records.

Temporary-copy packaging inspection:

```text
PACKAGING VERIFIED: azazel_nexus-0.0.1.dev0-py3-none-any.whl azazel_nexus-0.0.1.dev0.tar.gz contain no bench files
PACKAGING VERIFIED: azazel_nexus_runtime-0.0.1.dev0.tar.gz contains no bench files
```

The runtime wheel build was attempted but could not compile the existing
Linux-only `_bootstrap_deadline.c` on macOS (undeclared `timer_create`,
`timer_gettime`, `timer_delete`; `12 errors generated.`). Its sdist and explicit
src-only package discovery exclude bench; a Linux wheel build remains for
integration. Existing package configuration and installer were unchanged.

Documentation link check:

```text
internal links OK (102 Markdown files checked)
```

`git diff --check`: no output. New untracked lane files were also checked
with `git diff --no-index --check /dev/null <file>`.

## Open concerns

The real-model performance campaign was not runnable here:

```text
permission denied while trying to connect to the docker API at unix:///Users/mao/.colima/dc34/docker.sock
```

The README commands require an integrated Lane A/B checkout. The developing
public builder signature and privacy values were read and matched, but real
b11716 streaming timings, model outputs, resource samples, image PATH and
model behavior remain to be verified on dc34. These results grant no HG-05,
production admission or route evidence. The full-suite environmental failures
and two unresolved supervisor assertions remain for integration review.
