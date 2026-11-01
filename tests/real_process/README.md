# Bounded M.I.O. service process test

`test_mio_process_integration.py` is intentionally outside `tests/unit`: it
needs Linux `SO_PEERCRED`, a root orchestrator only inside a disposable
container, and temporary service accounts. It launches the production
`knowledge_lited`, `mio_locald`, and `mio_entryd` mains under their named UIDs.
An operator UID sends the public `mio.advise` protocol request through
entryd; locald calls the real shared MIO core and the existing read-only
Knowledge client reaches the real Knowledge Lite daemon over its service
socket. The test does not change product principal rules or model admission.

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
fast-assistance unit tests. All source and dependency mounts are read-only;
the test container is removed after the run. The successful run and earlier
incomplete setup attempts are recorded in the candidate's external evidence
report.

Knowledge data is based on the checked-in producer-shaped fixture, then
re-signed with the suite's test key and given a test-only description so the
shared core can project the advisory. This proves the current consumer path
with the read-only Knowledge service, not live producer authentication or
full-node interoperability. No model is admitted or invoked; it is not
admission or HG evidence.
