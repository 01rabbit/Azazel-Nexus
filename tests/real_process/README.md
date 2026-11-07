# Isolated M.I.O. and Knowledge process tests

`test_knowledge_context_process_interop.py` exercises Nexus's actual
`KnowledgeClient.request_context()` against the actual Knowledge app and mTLS
listener in a separate child process. The test creates a temporary CA and
client/server certificates, binds the Knowledge listener to loopback, sends
only sanitizer-approved P0 data, and verifies the signed Fabric response,
correlation, advisory-only authority and short expiry through Nexus's normal
client verifier. Database, keys and server state are temporary. It does not
wire the optional client into Nexus's normal service composition or configure
production trust, credentials or network access.

`test_mio_process_integration.py` is intentionally outside `tests/unit`: it
needs Linux `SO_PEERCRED`, a root orchestrator only inside a disposable
container, and temporary service accounts. The 500 ms case launches the
production `knowledge_lited`, `mio_locald`, and `mio_entryd` mains; an
`azexplain` peer sends the public `mio.advise` request through entryd. The
normal-entry case additionally starts production `edge_intaked` and
`incident_explaind`: it sends one bounded producer-shaped alert as `azedge`
through the public `edge-intake` socket, waits for the persisted explanation,
and checks the MIO reply's own fast-assistance Knowledge status and T1110 ref
separately from the explainer's independent Knowledge query and persisted
ref. Both paths use the real shared MIO core and actual Knowledge Lite
daemon. The `synthetic-reader` case uses the producer-shaped fixture admitted
by the shared reader and re-signed with the suite's test key. The
`knowledge-builder` case instead commissions the checked-in
`tests/fixtures/knowledge-lite-real/` archive, generated with the unmodified
`build-lite` CLI from Knowledge main at 09d234cd and signed by an ephemeral lab
key whose seed is discarded. That archive crosses the real LiteImport and
auditd boundaries. In that case, the MIO fast-assistance Knowledge outcome must
be `not_queried`; a `timeout` fails the case. Neither data source is live
upstream producer, authenticity, or full-node interoperability proof. This
does not claim that Edge's dirty MIO adapter uses Knowledge. No product
principal rules or model admission are changed.

The standard `nexus-main-run.sh` unit command does not select this test. Run
the focused process suite under the suite lock with a cached Linux arm64
Python 3.12 image and a compatible offline wheelhouse. The committed
`run-docker.sh` accepts the source checkout, wheel, wheelhouse, suite lock,
image, and Docker context through environment variables:

```sh
NEXUS_SRC=/path/to/nexus-shared-mio-adapter \
NEXUS_EXPECTED_HEAD=<full-40-character-commit> \
KNOWLEDGE_SRC=/path/to/knowledge-context-producer \
KNOWLEDGE_EXPECTED_HEAD=<full-40-character-commit> \
MIO_WHEEL_DIR=/path/to/directory/with/verified-wheel \
FABRIC_WHEEL_DIR=/path/to/directory/with/fixed-knowledge-context-wheel \
WHEELHOUSE=/path/to/offline/linux-arm64-py312-wheelhouse \
SUITE_LOCK=/path/to/suite-lock.sh \
IMAGE=sha256:cached-linux-arm64-python312-image \
DOCKER_CONTEXT=colima-rosetta SUITE_CONTEXT=rosetta \
  bash "$NEXUS_SRC/tests/real_process/run-docker.sh"
```

Before starting Docker, the wrapper requires clean Nexus and Knowledge source
trees and compares each checkout's full HEAD to the supplied commit. The
container runner checks the SHA-256 of the runtime MIO wheel
(`a99fdc1bb15484581b41cb1bd22914b4d1e1f452499278b5f42902daacc2a3cb`) and
the Fabric `v0.10.0` tag-source test wheel
(`b22356fd672cd60471606d3a7b73ccdba99091e680fedd854381a29d76e21424`)
before installing offline. The Fabric wheel was rebuilt from the exact signed
release source commit; it is a local test artifact, not a published PyPI
wheel. The tagged package contains the Knowledge Context v1 contract, which
remains experimental. It copies both source mounts into unique `/tmp` directories,
provisions only temporary container identities/groups, runs the Knowledge
process test with the MIO process suite, then removes the shared MIO wheel and
runs the degraded MIO phase. An exit trap removes only directories created for
that run. All source and dependency mounts are read-only; the test container
is removed after the run. Suite phases, including the no-wheel phase, are in
`run-container.sh`.

The fallback case starts only `mio_entryd` (no `mio_locald`, so its socket is
absent) and sends one ordinary `mio.advise` request as `azexplain`. The reply
must either carry the shared core's result (which queries no Knowledge) or the
explicit `dependency_unavailable` degradation when the MIO package is absent.
It is not model admission, and it does not change the route.

The tests use lab-only signing keys; the real-producer phase imports the
checked-in signed bundle unchanged, retaining its empty T1110 summary.
Separate synthetic producer-shaped rows are admitted with the suite test key.

For the `synthetic-reader` case, Knowledge data is the producer-shaped fixture
re-signed with the suite's test key and given a test-only description so the
shared core can project the advisory. For the `knowledge-builder` case, the
data is the real `build-lite` output described above. Those Lite cases do not
prove live producer authentication. The separate mTLS process test proves the
bounded software client/listener interoperability path only; it is not
production service composition, credential lifecycle, release, or deployment
evidence. No model is admitted or invoked; it is not admission or HG evidence.
