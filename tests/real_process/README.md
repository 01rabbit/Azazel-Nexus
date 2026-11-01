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
daemon. The fixture is test-key-signed after admission and is not evidence of
live Knowledge producer authentication or full-node interoperability. This
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
offline, provisions only temporary container identities/groups, installs the
source copy into the container, and selects this process test plus the
fast-assistance unit tests. It then removes the shared MIO wheel and runs the
degraded process phase. All source and dependency mounts are read-only; the
test container is removed after the run. Suite phases, including the
no-wheel phase, are kept in `run-container.sh`.

Knowledge data is based on the checked-in producer-shaped fixture, then
re-signed with the suite's test key and given a test-only description so the
shared core can project the advisory. This proves the current consumer path
with the read-only Knowledge service, not live producer authentication or
full-node interoperability. No model is admitted or invoked; it is not
admission or HG evidence.
