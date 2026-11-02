# Bounded M.I.O. service process test

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
MIO_WHEEL_DIR=/path/to/directory/with/verified-wheel \
WHEELHOUSE=/path/to/offline/linux-arm64-py312-wheelhouse \
SUITE_LOCK=/path/to/suite-lock.sh \
IMAGE=sha256:cached-linux-arm64-python312-image \
DOCKER_CONTEXT=colima-rosetta SUITE_CONTEXT=rosetta \
  bash "$NEXUS_SRC/tests/real_process/run-docker.sh"
```

The container runner checks the pinned MIO wheel digest before installing it
offline, provisions only temporary container identities/groups, and copies
the source mount into a unique `/tmp` directory created for that run. It
installs and selects this process test plus the fast-assistance unit tests
from that copy, then removes the shared MIO wheel and runs the degraded
process phase. An exit trap removes only the created temporary source
directory. All source and dependency mounts are read-only; the test container
is removed after the run. Suite phases, including the no-wheel phase, are
kept in `run-container.sh`.

The fallback case starts only `mio_entryd` (no `mio_locald`, so its socket is
absent) and sends one ordinary `mio.advise` request as `azexplain`. The reply
must either carry the shared core's result (which queries no Knowledge) or the
explicit `dependency_unavailable` degradation when the MIO package is absent.
It is not model admission, and it does not change the route.

For the `synthetic-reader` case, Knowledge data is the producer-shaped fixture
re-signed with the suite's test key and given a test-only description so the
shared core can project the advisory. For the `knowledge-builder` case, the
data is the real `build-lite` output described above. Neither proves live
producer authentication or full-node interoperability. No model is admitted or
invoked; it is not admission or HG evidence.
