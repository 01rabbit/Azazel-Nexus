#!/usr/bin/env bash
set -euo pipefail

: "${NEXUS_SRC:?set NEXUS_SRC to this Nexus checkout}"
: "${NEXUS_EXPECTED_HEAD:?set NEXUS_EXPECTED_HEAD to the fixed Nexus commit}"
: "${KNOWLEDGE_SRC:?set KNOWLEDGE_SRC to the fixed Knowledge checkout}"
: "${KNOWLEDGE_EXPECTED_HEAD:?set KNOWLEDGE_EXPECTED_HEAD to the fixed Knowledge commit}"
: "${MIO_WHEEL_DIR:?set MIO_WHEEL_DIR to the directory containing the pinned wheel}"
: "${FABRIC_WHEEL_DIR:?set FABRIC_WHEEL_DIR to the wheel built from the exact official Fabric v0.10.0 tag}"
: "${WHEELHOUSE:?set WHEELHOUSE to a compatible offline wheelhouse}"
: "${SUITE_LOCK:?set SUITE_LOCK to the suite-lock.sh path}"
: "${IMAGE:?set IMAGE to a cached Linux arm64 Python 3.12 image or digest}"

for source_spec in "Nexus:$NEXUS_SRC:$NEXUS_EXPECTED_HEAD" \
                   "Knowledge:$KNOWLEDGE_SRC:$KNOWLEDGE_EXPECTED_HEAD"; do
  IFS=: read -r name path expected <<<"$source_spec"
  actual=$(git -C "$path" rev-parse HEAD)
  if [[ "$actual" != "$expected" ]]; then
    echo "$name source HEAD mismatch: expected $expected, found $actual" >&2
    exit 1
  fi
  if [[ -n "$(git -C "$path" status --porcelain --untracked-files=all)" ]]; then
    echo "$name source tree is not clean at the fixed HEAD" >&2
    exit 1
  fi
done

docker_context=${DOCKER_CONTEXT:-colima-rosetta}
suite_context=${SUITE_CONTEXT:-rosetta}

bash "$SUITE_LOCK" "$suite_context" docker --context "$docker_context" run --rm \
  --pull=never --platform linux/arm64 --network=none --user 0:0 \
  --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID \
  --cap-add=DAC_OVERRIDE --cap-add=KILL --cpus=2 --memory=3g --pids-limit=192 \
  --mount "type=bind,src=$NEXUS_SRC,dst=/src,readonly" \
  --mount "type=bind,src=$KNOWLEDGE_SRC,dst=/knowledge,readonly" \
  --mount "type=bind,src=$MIO_WHEEL_DIR,dst=/wheel,readonly" \
  --mount "type=bind,src=$FABRIC_WHEEL_DIR,dst=/fabric-wheel,readonly" \
  --mount "type=bind,src=$WHEELHOUSE,dst=/wheels,readonly" \
  --env NEXUS_EXPECTED_HEAD="$NEXUS_EXPECTED_HEAD" \
  --env KNOWLEDGE_EXPECTED_HEAD="$KNOWLEDGE_EXPECTED_HEAD" \
  "$IMAGE" bash /src/tests/real_process/run-container.sh
