"""What an unsigned bundle can make the Lite reader spend before trust.

`lite_bundle._read_members` runs before any signature is checked. These tests
fix the ceiling on what it inflates: the producer's 100:1 rule against the
archive's own size, applied while inflating, so a small hostile archive is
refused after a bounded amount of work and memory rather than after the
gigabyte its tar headers declare.
"""

from __future__ import annotations

import tarfile
import tracemalloc
import zlib

import pytest

from azazel_nexus import lite_bundle
from azazel_nexus.lite_bundle import BundleRefused, TrustAnchors, verify_bundle

MIB = 1024 * 1024
ANCHORS = TrustAnchors(threshold=1, keys={"k": b"\x01" * 32})


def zero_bomb(members: int, size: int) -> bytes:
    """A gzip'd tar of `members` zero-filled members, built without holding them."""
    deflate = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    chunk = b"\0" * MIB
    out = []
    for index in range(members):
        info = tarfile.TarInfo(f"tables/zero{index}.jsonl")
        info.size = size
        out.append(deflate.compress(info.tobuf(format=tarfile.PAX_FORMAT)))
        for _ in range(size // MIB):
            out.append(deflate.compress(chunk))
    out.append(deflate.compress(b"\0" * 1024))
    out.append(deflate.flush())
    return b"".join(out)


def refuse(raw: bytes) -> BundleRefused:
    with pytest.raises(BundleRefused) as caught:
        verify_bundle(raw, anchors=ANCHORS)
    return caught.value


def test_an_unsigned_zero_bomb_is_refused_within_the_ratio_ceiling():
    raw = zero_bomb(4, 64 * MIB)  # declares 256 MiB from well under 1 MiB
    declared = 4 * 64 * MIB
    limit = (lite_bundle.MAX_RATIO * len(raw) + 2 * lite_bundle.MAX_MANIFEST_BYTES
             + lite_bundle.TAR_OVERHEAD_BYTES)
    assert limit < declared // 4
    tracemalloc.start()
    try:
        refused = refuse(raw)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert (refused.gate.value, refused.code) == ("archive", "BUNDLE_DECOMPRESSION_BOMB")
    # Inflated output is the reader's whole spend: at most the limit, a step,
    # and the bytearray's growth margin -- never the declared quarter gigabyte.
    assert peak < 2 * limit + 2 * lite_bundle.INFLATE_STEP_BYTES, (peak, limit)


def test_inflation_stops_at_the_limit_and_not_at_the_end_of_the_stream(monkeypatch):
    raw = zero_bomb(1, 64 * MIB)
    produced = []
    real = zlib.decompressobj

    class Counting:
        def __init__(self, *args):
            self.inner = real(*args)

        def decompress(self, data, max_length=0):
            chunk = self.inner.decompress(data, max_length)
            produced.append(len(chunk))
            return chunk

        def __getattr__(self, name):
            return getattr(self.inner, name)

    monkeypatch.setattr(lite_bundle.zlib, "decompressobj", Counting)
    assert refuse(raw).code == "BUNDLE_DECOMPRESSION_BOMB"
    limit = (lite_bundle.MAX_RATIO * len(raw) + 2 * lite_bundle.MAX_MANIFEST_BYTES
             + lite_bundle.TAR_OVERHEAD_BYTES)
    assert sum(produced) <= limit + lite_bundle.INFLATE_STEP_BYTES
    assert sum(produced) < 64 * MIB


def test_declared_content_over_the_ratio_is_refused_before_it_is_read():
    # Inflation stays under its limit because the content is short, but the
    # tar header declares more than 100x the archive: refused on the header.
    info = tarfile.TarInfo("tables/a.jsonl")
    info.size = 10 * MIB
    deflate = zlib.compressobj(9, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
    raw = deflate.compress(info.tobuf(format=tarfile.PAX_FORMAT) + b"{}\n") + deflate.flush()
    assert refuse(raw).code == "BUNDLE_DECOMPRESSION_BOMB"


@pytest.mark.parametrize("prefix,encoding", [(b"\xef\xbb\xbf", "utf-8"), (b"", "utf-16")])
def test_a_manifest_that_is_not_plain_utf8_is_refused(prefix, encoding):
    import gzip
    import io

    body = prefix + '{"bundle_version": 1}'.encode(encoding)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as archive:
            for name, data in (("manifest.json", body), ("manifest.sig", b"k:00\n")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    refused = refuse(buf.getvalue())
    assert (refused.gate.value, refused.code) == ("manifest", "BUNDLE_MANIFEST_INVALID")
