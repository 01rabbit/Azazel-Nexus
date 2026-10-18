#!/bin/sh
# Run only in the documented Debian trixie build container. Never runs a model.
set -eu
umask 022
[ "$(. /etc/os-release; printf '%s' "$VERSION_CODENAME")" = trixie ] || {
    echo 'Debian trixie is required' >&2; exit 1;
}
[ "$#" -eq 1 ] || { echo 'usage: build_llama_runtime.sh OUTPUT_DIRECTORY' >&2; exit 2; }
OUTPUT=$(CDPATH= cd -- "$1" && pwd)
SOURCE_URL=https://codeload.github.com/ggml-org/llama.cpp/tar.gz/refs/tags/b11716
# Source pin must be supplied by review; never trust a downloaded checksum.
SOURCE_SHA256=a411ee5e422528bb4c4396a3796948cda73f20edb1f5d4949248175b633335df
case "$SOURCE_SHA256" in *[!0-9a-f]*|'') echo 'source digest not pinned; refusing build' >&2; exit 1;; esac
[ "${#SOURCE_SHA256}" -eq 64 ] || exit 1
export SOURCE_DATE_EPOCH=1767225600
export TZ=UTC LC_ALL=C
BUILD_ROOT=/build/azazel-llama-b11716
[ ! -e "$BUILD_ROOT" ] || { echo 'fixed build directory must be absent' >&2; exit 1; }
mkdir -p "$BUILD_ROOT"
cd "$BUILD_ROOT"
curl --fail --location --proto '=https' --tlsv1.2 "$SOURCE_URL" -o source.tar.gz
printf '%s  source.tar.gz\n' "$SOURCE_SHA256" | sha256sum --check --strict
mkdir source
tar -xzf source.tar.gz --strip-components=1 -C source
# Stable build metadata, independent of git discovery and wall clock.
FLAGS="-ffile-prefix-map=$BUILD_ROOT=/usr/src/llama.cpp -fdebug-prefix-map=$BUILD_ROOT=/usr/src/llama.cpp -Werror=date-time"
cmake -S source -B build \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_C_FLAGS="$FLAGS" -DCMAKE_CXX_FLAGS="$FLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS='-static-libgcc -static-libstdc++ -Wl,--build-id=none' \
    -DLLAMA_BUILD_NUMBER=11716 -DLLAMA_BUILD_COMMIT=b11716 \
    -DGGML_NATIVE=OFF -DGGML_CPU_ALL_VARIANTS=OFF \
    -DGGML_CUDA=OFF -DGGML_METAL=OFF -DGGML_VULKAN=OFF \
    -DGGML_BLAS=OFF -DGGML_OPENMP=OFF -DLLAMA_CURL=OFF \
    -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=ON
cmake --build build --target llama-server --parallel 2
install -m 0755 build/bin/llama-server "$OUTPUT/llama-server"
sha256sum "$OUTPUT/llama-server"
