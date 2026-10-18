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
| runtime bytes lack or mismatch their architecture pin | `model_runtime.RUNTIMES` | reviewed per-architecture build digests |
| no model has operator approval | `cognition.admit_local_model` | future reviewed approval/staging evidence implementation |
| the Core reserve is unmeasured | `model_runtime.readiness` | hardware measurement (`HG-05`) |

RUNTIMES pins exactly one runtime, llama.cpp b11716. Resolving it refuses a
missing/nonregular binary, wrong digest, pending digest or unknown architecture.
Installing a binary grants no model admission. The locald unit is not granted
by activation until a model is admitted. This build has no production
admission-evidence loader, so `local_model_provider` remains unwired.
Admission remains closed in this build, including after a supplied reserve:
the existing approval gate still refuses. No model is started by default.

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

## 5. Containment and the 8 GiB target

The generated host unit declares `MemoryMax=4G`, `MemorySwapMax=0`, `CPUQuota=40%`, `TasksMax=64`,
`LimitFSIZE=16777216`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`
and `IPAddressDeny=any`. The memory ceiling covers locald and both children;
it is a conservative safety ceiling, **not** measured capacity or admission.
The binary at `/usr/libexec/azazel/llama-server` is executable under this unit:
there is no NoExecPaths/ExecPaths restriction, and ProtectSystem=strict makes
package paths read-only. Both servers share this containment and use separate
AF_UNIX sockets. No additional executable exemption or network family is added.

After admission, each declared memory need must pass `containment_for` against
the measured reserve/envelope; combined needs must fit 3840 MiB, leaving 256 MiB
beneath the host ceiling for locald/cache. Hardware must validate that margin.
Qwen container RSS was approximately **1.23 GiB**; bge-m3 RSS is **measure later**.
Neither is hardware evidence. The host must never have RuntimeMaxSec: request
and startup deadlines belong to LocalServer, not the long-running daemon.

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

Production admission remains closed: `RUNTIMES` pins exactly one runtime and HG-05 is unmeasured.
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
similarity is below SCOPE_MIN=0.45. The existing insufficient-information check
is retained. Entryd defers scope to locald because it has no embedding scores;
it still handles the existing insufficient-information gate. Runtime admission,
reserve, artifact and provider gates must pass before embeddings can execute.

Candidates are 「該当する可能性のある類型（類似度順の候補）」 with similarities
rounded to two decimals. Deterministic states use SIM_MIN=0.52 and GAP_MIN=0.05,
calibrated in `docs/evidence/mio-threshold-calibration-2026-10-18.md`:

- 「候補が明確」: top1 >= SIM_MIN, top1 minus top2 >= GAP_MIN, no benign support and
  no collector-attached system record (change record, schedule, inventory, approval…).
  The record rule is wording-independent: neutral records defeat the benign lexicon,
  so any such record keeps the state at most 「候補が拮抗」 and the display asks the
  operator to check it.
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

## Pinned runtime build and offline installation

`tools/build_llama_runtime.sh` builds b11716 from a fixed HTTPS tarball and a
reviewed SHA-256, failing before extraction on mismatch. It uses a fixed source/
build path, SOURCE_DATE_EPOCH, UTC/C locale, prefix maps, fixed build metadata,
`-Werror=date-time`, no native CPU tuning/GPU/BLAS/OpenMP/curl, static project
libraries and static libstdc++/libgcc where possible. glibc remains dynamically linked.
Binary release
pins exist only in `model_runtime.LLAMA_RUNTIME_DIGESTS`. Pending pins refuse.

The orchestrator runs the following exact command once with `ARCH=arm64` and
once with `ARCH=amd64`; Docker must not be run by this lane. Create `out-$ARCH`
first and retain the image digest, compiler/cmake/package versions and logs.
The base image is pinned by digest. Apt repository contents/toolchain packages
remain unpinned; the build uses network access for apt and the source download.
Retain the package set and logs and compare two clean build hashes.

```sh
ARCH=arm64
mkdir -p "out-$ARCH"
docker run --rm --platform "linux/$ARCH" \
  -v "$PWD:/repo:ro" -v "$PWD/out-$ARCH:/out" debian@sha256:913f6706df59a68922d1dd08f78c2476560a8d367897200a6005b00e5f67c2d5 \
  sh -ec 'apt-get update; apt-get install -y --no-install-recommends build-essential cmake curl ca-certificates; sh /repo/tools/build_llama_runtime.sh /out'
```

The script prints the resulting llama-server SHA-256. Review and fill the two
architecture pins; never derive trust by executing an unverified binary.
Install offline as root with `packaging/install.sh --llama-runtime /path/to/llama-server`.
It verifies before mutation, then stages, rehashes and atomically publishes a
root:root 0755 binary at `/usr/libexec/azazel/llama-server`. No network or model
execution occurs. Omitting the option installs no runtime binary. Pending pins,
unknown architectures and mismatched bytes refuse with a clear error.

`main()` accepts only internal commissioning candidates, never command-line or
environment model settings. It calls the existing admission function before
artifact/runtime resolution or LocalServer construction, audits refusals,
loads separate persistent restart budgets, and stops owned children on exit.
Each startup is bounded at 120 seconds; the generated unit allows 300 seconds
for two startups plus verification before readiness.
No production candidate/approval evidence loader is implemented: the default
candidate set is empty and audited. The approval gate remains closed even if
candidates are supplied internally. Future loader work must bind the verified
catalog, promoted artifact, tested tuple, reserve and operator approval.
An admitted embedding role injects EmbeddingRetriever. Explanation has no
server by default; only a separately admitted generative role supplies one.
The recommended configuration remains retrieval + trusted text, per the
[container development results](evidence/mio-candidates-2026-10-18.md).

The installer owns `/var/lib/azazel/mio` as azmio:azmio 0750; locald keeps its
ledger there, separate from entryd's 0700 state leaf. Cache, restart ledgers
and both model sockets use the same locald-owned directory. Promoted weights
stay under root-owned `/var/lib/azazel/models/store`. Root-owned staging/store
are setgid azmio 2750; verified promotion changes data mode to 0640, granting
azmio read access without write or executable bits. No model bytes move into
the checkout. Binary pins must use the `sha256:<64 lowercase hex>` format.

The orchestrator built linux/arm64 twice from clean containers using the image
above: gcc 14.2.0-19, cmake 3.31.6-2, binutils 2.44-3 and
libc6 2.41-12+deb13u4. Both binaries hashed to
`eca8b1abbd8f7a5b121d2d0b7486829fc191736206cacf8556e878175c4ca8a6`.
That arm64 binary served bge-m3 embeddings and reproduced held-out retrieval
recall@1 **14/20**, recall@3 **17/20** exactly. These are container build and
retrieval results, not hardware evidence; HG-05 remains open.

linux/amd64 was built twice from clean containers with the same image and the
same toolchain versions. Both binaries hashed to
`e1671cd4167b39b29fe34bb906f62d610b289aed19301445c4844764467fb701`, and that
binary served bge-m3 embeddings over its AF_UNIX socket. On an Apple Silicon
host, build amd64 in a Rosetta-backed VM (`colima start --vm-type vz
--vz-rosetta`); under qemu user emulation cc1plus crashed with a segmentation
fault on both attempts, which is an emulator fault, not a source or flag issue.
Real x86_64 hardware remains part of the HIL campaign.

Runtime verification requires root ownership and no group/other write bits on
the executable and every parent through `/`, rejecting symlinked parents.
Linux hashes an O_NOFOLLOW descriptor and executes that same descriptor via
`/proc/self/fd` with `pass_fds`. On platforms without procfs, verification is
repeated immediately before Popen; a residual pathname replacement window
remains there. Root can still modify an open inode; root is the trust boundary.
Installation inputs may reside in untrusted directories: their digest is checked
before and after copying, ownership/mode are set on staging, and promotion fsyncs
the destination directory.

Catalog roles must match the provider admission role and the tested compatibility
tuple's `model_role`. An omitted tuple role supports legacy generative providers
only; embedding providers require an explicit embedding tuple. Catalog `/2`
entries retain generative semantics and refuse known bge-m3 embedding digests;
`/3` carries its role in the signed payload. These bindings grant no admission.
