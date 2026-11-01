#!/usr/bin/env bash
set -euo pipefail

: "${NEXUS_SRC:?set NEXUS_SRC to this Nexus checkout}"
: "${MIO_WHEEL_DIR:?set MIO_WHEEL_DIR to the directory containing the pinned wheel}"
: "${WHEELHOUSE:?set WHEELHOUSE to a compatible offline wheelhouse}"
: "${SUITE_LOCK:?set SUITE_LOCK to the suite-lock.sh path}"
: "${IMAGE:?set IMAGE to a cached Linux arm64 Python 3.12 image or digest}"

docker_context=${DOCKER_CONTEXT:-colima-rosetta}
suite_context=${SUITE_CONTEXT:-rosetta}

bash "$SUITE_LOCK" "$suite_context" docker --context "$docker_context" run --rm \
  --pull=never --platform linux/arm64 --network=none --user 0:0 \
  --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID \
  --cap-add=DAC_OVERRIDE --cap-add=KILL --cpus=2 --memory=3g --pids-limit=192 \
  --mount "type=bind,src=$NEXUS_SRC,dst=/src,readonly" \
  --mount "type=bind,src=$MIO_WHEEL_DIR,dst=/wheel,readonly" \
  --mount "type=bind,src=$WHEELHOUSE,dst=/wheels,readonly" \
  "$IMAGE" bash /src/tests/real_process/run-container.sh
