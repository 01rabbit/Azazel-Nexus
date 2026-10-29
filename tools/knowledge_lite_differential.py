"""Knowledge Lite differential: Knowledge's own verifier beside Nexus's (P5).

`contract/azazel-knowledge-lite/` proves that Nexus reads what Knowledge's
fixture emitter writes. It does not prove that the two *verifiers* agree,
and the fixture's anchor carries none of the gates a production anchor uses
(`key_roles`, `required_signer_role`, `minimum_security_epoch`,
`accepted_export_policy_digests`). This tool closes that gap:

1. Lab keys are generated for this run only. Their seeds live in a private
   temporary directory, are handed to Knowledge's `bundle_build.py
   build-lite` as `--sign-key` files, are overwritten and removed when the
   run ends, and are never printed. The published fixture key is not used.
2. Knowledge's own `tools/lite_fixture.py` row writer fills a source
   database, and Knowledge's own `build-lite` builds and signs the bundles
   (one per signer set, one below the security epoch, one whose indicators
   have expired).
3. Every case -- those bundles, and mutations of them re-signed with the lab
   key where a gate after the signature is the point -- is judged by
   Knowledge's `azazel_knowledge.bundle.verify.verify_bundle` in a separate
   `python -I` process, and by Nexus's `lite_bundle.verify_bundle` here.
4. Both verdicts are compared with `EXPECTED`, which records what each side
   says and, where they differ, `DIVERGENCES` says which side is right and on
   what evidence. The run fails on any verdict that is not the recorded one,
   and on any case both accept whose delivered members differ.

    python tools/knowledge_lite_differential.py --knowledge /path/to/Azazel-Knowledge

The Knowledge checkout is only read. Knowledge's core dependencies (PyYAML,
idna, PyNaCl) must be importable by this interpreter.

Nexus CI cannot fetch Azazel-Knowledge (a private repository), so it cannot
run step 2 or the Knowledge column of step 3. `tests/unit/test_knowledge_lite_
differential.py` instead runs `nexus_only()`: the same cases, built from the
Knowledge-emitted `contract/azazel-knowledge-lite/lite.tar.gz` re-signed with a
key generated in the test, judged by Nexus alone against the recorded Nexus
column. The Knowledge column is re-measured only by this tool, locally
(`docs/knowledge-lite-differential.md`).
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

REPO = Path(__file__).resolve().parents[1]
CONTRACT = REPO / "contract" / "azazel-knowledge-lite"

#: The role a production anchor would require of a Lite signer, and the role
#: of a key provisioned for something else. Names are this tool's own: the
#: producer prescribes none (ADR-0015 D5b), only that they be compared.
ROLE = "knowledge-lite-publisher"
OTHER_ROLE = "knowledge-full-bundle"

#: What the Knowledge-built bundles declare. The epoch is above 1 so that the
#: "below the minimum" bundle is still a bundle Knowledge is willing to build.
BUILD_VERSION = 2
BUILD_EPOCH = 3
BUILD_AS_OF = "2026-09-19T00:00:00Z"
BUILD_PROFILE = "knowledge-lite-16g"
ALIAS_SCOPE = "nexus-differential"

#: Lab key labels. A signs Lite; B holds another role; C holds none; D is not
#: in any anchor; E is a second Lite signer for the two-signature anchor.
KEY_LABELS = ("A", "B", "C", "D", "E")

ACCEPTED = "accepted"


@dataclass(frozen=True)
class Signer:
    """Ed25519 signing for the lab keys. Never part of the product."""

    sign: Callable[[bytes, bytes], bytes]
    public: Callable[[bytes], bytes]


def nacl_signer() -> Signer:
    from nacl.signing import SigningKey

    return Signer(
        sign=lambda seed, message: SigningKey(seed).sign(message).signature,
        public=lambda seed: SigningKey(seed).verify_key.encode(),
    )


@dataclass
class LabKeys:
    """Seeds generated for one run. Held in memory; see `write_seed`."""

    signer: Signer
    seeds: dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def generate(cls, signer: Signer) -> "LabKeys":
        return cls(signer=signer, seeds={label: os.urandom(32) for label in KEY_LABELS})

    def public_hex(self, label: str) -> str:
        return self.signer.public(self.seeds[label]).hex()

    def key_id(self, label: str) -> str:
        # Knowledge's key id: the first 8 hex digits of the verify key.
        return self.public_hex(label)[:8]

    def line(self, label: str, message: bytes) -> str:
        return f"{self.key_id(label)}:{self.signer.sign(self.seeds[label], message).hex()}"


# -- bundle bytes ------------------------------------------------------------


def canonical(manifest: Mapping) -> bytes:
    """Knowledge's `canonical_manifest_bytes`: what its signature covers."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def unpack(raw: bytes) -> list[tuple[str, bytes]]:
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        return [(m.name, archive.extractfile(m).read()) for m in archive.getmembers()]


def pack(members, *, links=()) -> bytes:
    """Gzip'd tar with the producer's zeroed metadata, members in order."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as archive:
            for name, data in members:
                info = tarfile.TarInfo(name=name)
                info.size, info.mtime, info.mode = len(data), 0, 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(data))
            for name, target in links:
                info = tarfile.TarInfo(name=name)
                info.type, info.linkname, info.mtime = tarfile.SYMTYPE, target, 0
                archive.addfile(info)
    return buf.getvalue()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Base:
    """One signed bundle, split so that cases can be derived from it."""

    def __init__(self, raw: bytes, keys: LabKeys) -> None:
        members = unpack(raw)
        if [n for n, _ in members[:2]] != ["manifest.json", "manifest.sig"]:
            raise SystemExit("the base bundle does not start with manifest.json, manifest.sig")
        self.raw = raw
        self.keys = keys
        self.manifest_bytes = members[0][1]
        self.manifest = json.loads(self.manifest_bytes)
        if canonical(self.manifest) != self.manifest_bytes:
            raise SystemExit("the base manifest is not in Knowledge's canonical form")
        self.content = members[2:]

    def signed(self, manifest=None, *, signers=("A",), content=None, order=None,
               manifest_bytes=None, signed_bytes=None, extra_lines=(), links=()) -> bytes:
        manifest = self.manifest if manifest is None else manifest
        body = canonical(manifest) if manifest_bytes is None else manifest_bytes
        message = body if signed_bytes is None else signed_bytes
        lines = [self.keys.line(label, message) for label in signers] + list(extra_lines)
        sig = ("\n".join(lines) + "\n").encode("ascii")
        content = self.content if content is None else content
        members = [("manifest.json", body), ("manifest.sig", sig), *content]
        if order is not None:
            members = order(members)
        return pack(members, links=links)

    def with_files(self, extra: Mapping[str, bytes], *, tables=None) -> tuple[dict, list]:
        manifest = json.loads(self.manifest_bytes)
        manifest["files"] = {**manifest["files"], **{n: _sha(b) for n, b in extra.items()}}
        if tables is not None:
            manifest["tables"] = sorted({*manifest["tables"], *tables})
        return manifest, [*self.content, *sorted(extra.items())]


# -- anchors -----------------------------------------------------------------


def anchors_toml(keys: LabKeys, *, policy_digest: str, epoch: int, threshold=1,
                 labels=("A", "B", "C"), roles=None, revoked=(), accepted=None) -> str:
    """A production-shaped anchor: every gate Knowledge defines is set."""
    roles = {"A": ROLE, "B": OTHER_ROLE} if roles is None else roles
    accepted = [policy_digest] if accepted is None else accepted
    out = [f"threshold = {threshold}",
           f'required_signer_role = "{ROLE}"',
           f"minimum_security_epoch = {epoch}",
           "accepted_export_policy_digests = [" + ", ".join(f'"{d}"' for d in accepted) + "]",
           "revoked = [" + ", ".join(f'"{keys.key_id(r)}"' for r in revoked) + "]",
           "", "[keys]"]
    out += [f'"{keys.key_id(label)}" = "{keys.public_hex(label)}"' for label in labels]
    out += ["", "[key_roles]"]
    out += [f'"{keys.key_id(label)}" = "{role}"' for label, role in sorted(roles.items())]
    return "\n".join(out) + "\n"


@dataclass(frozen=True)
class Case:
    name: str
    bundle: bytes
    anchors: str
    watermark: int = 0


def build_cases(bases: Mapping[str, bytes], keys: LabKeys) -> list[Case]:
    """Every case, from the signed bases. The same list in both modes.

    `bases` holds `valid` (signed by A), `signed_B`, `signed_C`, `signed_D`,
    `signed_AB`, `signed_AE`, `epoch_low` (one below the valid one) and
    `expired`. Locally Knowledge builds all of them; in CI they are derived
    from the Knowledge-emitted contract fixture.
    """
    base = Base(bases["valid"], keys)
    m = base.manifest
    digest = m["profile"]["selection_inputs"]["export_policy_digest"]
    epoch = m["security_epoch"]
    version = m["bundle_version"]
    prod = anchors_toml(keys, policy_digest=digest, epoch=epoch)

    def declared(extra, tables=None) -> bytes:
        manifest, content = base.with_files(extra, tables=tables)
        return base.signed(manifest, content=content)

    def edit(**changes):
        out = json.loads(base.manifest_bytes)
        for key, value in changes.items():
            if value is _DROP:
                out.pop(key, None)
            else:
                out[key] = value
        return out

    no_policy = json.loads(base.manifest_bytes)
    no_policy["profile"]["selection_inputs"].pop("export_policy_digest")
    first_table = base.content[0]
    pretty = json.dumps(m, indent=2, sort_keys=True).encode("utf-8")
    deep = "tables/a/b/c/d/e/f/g/x.jsonl"  # nine path components
    deep_ok = "tables/a/b/c/d/e/f/x.jsonl"  # eight
    long_name = "tables/" + "n" * 100 + "/" + "m" * 100 + ".jsonl"  # 214 bytes
    long_component = "tables/" + "n" * 290 + ".jsonl"  # one component over NAME_MAX
    many = {f"tables/extra{i:02d}.jsonl": b"{}\n" for i in range(62)}

    cases = [
        Case("valid", bases["valid"], prod),
        Case("expired", bases["expired"], prod),
        Case("rollback_advances", bases["valid"], prod, version - 1),
        Case("rollback_equal", bases["valid"], prod, version),
        Case("signer_other_role", bases["signed_B"], prod),
        Case("signer_no_role", bases["signed_C"], prod),
        Case("signer_unknown", bases["signed_D"], prod),
        Case("signer_revoked", bases["valid"],
             anchors_toml(keys, policy_digest=digest, epoch=epoch, revoked=("A",))),
        Case("threshold2_one_signature", bases["valid"],
             anchors_toml(keys, policy_digest=digest, epoch=epoch, threshold=2)),
        Case("threshold2_one_holds_role", bases["signed_AB"],
             anchors_toml(keys, policy_digest=digest, epoch=epoch, threshold=2)),
        Case("threshold2_both_hold_role", bases["signed_AE"],
             anchors_toml(keys, policy_digest=digest, epoch=epoch, threshold=2,
                          labels=("A", "B", "C", "E"), roles={"A": ROLE, "B": OTHER_ROLE, "E": ROLE})),
        Case("threshold0_bad_signature", _flip_signature(bases["valid"]),
             anchors_toml(keys, policy_digest=digest, epoch=epoch, threshold=0)),
        Case("epoch_below_minimum", bases["epoch_low"], prod),
        Case("epoch_missing", base.signed(edit(security_epoch=_DROP)), prod),
        Case("epoch_boolean", base.signed(edit(security_epoch=True)), prod),
        Case("policy_not_accepted", bases["valid"],
             anchors_toml(keys, policy_digest=digest, epoch=epoch, accepted=["0" * 64])),
        Case("policy_missing", base.signed(no_policy), prod),
        Case("format_unsupported", base.signed(edit(bundle_format_version=2)), prod),
        Case("kind_differential", base.signed(edit(kind="differential", base_version=version - 1)),
             prod, version - 1),
        Case("version_string", base.signed(edit(bundle_version=str(version))), prod),
        Case("version_boolean", base.signed(edit(bundle_version=True)), prod),
        Case("corrupt_signature", _flip_signature(bases["valid"]), prod),
        Case("corrupt_payload", base.signed(content=[(first_table[0], first_table[1] + b" ")]
                                            + base.content[1:]), prod),
        Case("truncated", _truncate(bases["valid"]), prod),
        Case("member_missing", base.signed(content=base.content[1:]), prod),
        Case("member_undeclared", base.signed(content=[*base.content, ("tables/zz.jsonl", b"{}\n")]),
             prod),
        Case("member_duplicate", base.signed(content=[*base.content, first_table]), prod),
        Case("member_symlink", base.signed(links=(("tables/link.jsonl", "/etc/passwd"),)), prod),
        Case("member_dotdot", declared({"tables/../escape.jsonl": b"{}\n"}), prod),
        Case("member_nine_components", declared({deep: b"{}\n"}), prod),
        Case("member_eight_components", declared({deep_ok: b"{}\n"}), prod),
        Case("member_name_214_bytes", declared({long_name: b"{}\n"}), prod),
        Case("member_component_296_bytes", declared({long_component: b"{}\n"}), prod),
        Case("members_over_64", declared(many), prod),
        Case("ratio_over_100", declared({"tables/zeros.jsonl": b"\0" * (4 << 20)}),
             prod),
        Case("manifest_not_first", base.signed(order=lambda ms: [*ms[2:], *ms[:2]]), prod),
        Case("manifest_pretty_signed_canonical",
             base.signed(manifest_bytes=pretty, signed_bytes=canonical(m)), prod),
        Case("manifest_pretty_signed_raw", base.signed(manifest_bytes=pretty), prod),
        Case("manifest_shadows_trust", base.signed(edit(trust={})), prod),
        Case("manifest_shadows_key_roles", base.signed(edit(key_roles={})), prod),
        Case("manifest_local_tier_table", declared(
            {"tables/reaction.jsonl": b"{}\n"}, tables=("reaction",)), prod),
        Case("signature_33_lines", base.signed(extra_lines=[f"{i:08x}:00" for i in range(32)]), prod),
    ]
    names = [c.name for c in cases]
    if len(set(names)) != len(names):
        raise SystemExit("duplicate case names")
    return cases


_DROP = object()


def _flip_signature(raw: bytes) -> bytes:
    members = unpack(raw)
    line = members[1][1].decode("ascii").splitlines()[0]
    key_id, _, hex_sig = line.partition(":")
    flipped = hex_sig[:-1] + ("0" if hex_sig[-1] != "0" else "1")
    return pack([members[0], ("manifest.sig", f"{key_id}:{flipped}\n".encode("ascii")),
                 *members[2:]])


def _truncate(raw: bytes) -> bytes:
    """Cut the tar inside its last content member, as the producer's fixture does."""
    tar_bytes = gzip.decompress(raw)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r") as archive:
        last = [m for m in archive.getmembers() if m.isreg() and m.size > 0][-1]
    cut = last.offset_data + last.size // 2
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as gz:
        gz.write(tar_bytes[:cut])
    return buf.getvalue()


# -- the recorded verdicts ----------------------------------------------------

_T = "BUNDLE_SIGNATURE_THRESHOLD_NOT_MET"
_ROLE = "BUNDLE_SIGNER_ROLE_NOT_PERMITTED"

#: case -> (Knowledge's verdict, Nexus's verdict). Measured against
#: Azazel-Knowledge 2445c1b; see docs/knowledge-lite-differential.md.
EXPECTED: dict[str, tuple[str, str]] = {
    "valid": (ACCEPTED, ACCEPTED),
    "expired": (ACCEPTED, ACCEPTED),
    "rollback_advances": (ACCEPTED, ACCEPTED),
    "rollback_equal": ("BUNDLE_VERSION_REGRESSION", "BUNDLE_VERSION_REGRESSION"),
    "signer_other_role": (_ROLE, _ROLE),
    "signer_no_role": (_ROLE, _ROLE),
    "signer_unknown": (_T, _T),
    "signer_revoked": ("BUNDLE_REVOKED_SIGNER", "BUNDLE_REVOKED_SIGNER"),
    "threshold2_one_signature": (_T, _T),
    "threshold2_one_holds_role": (_ROLE, _ROLE),
    "threshold2_both_hold_role": (ACCEPTED, ACCEPTED),
    "threshold0_bad_signature": (ACCEPTED, "ANCHORS_INVALID"),
    "epoch_below_minimum": ("BUNDLE_SECURITY_EPOCH_TOO_LOW", "BUNDLE_SECURITY_EPOCH_TOO_LOW"),
    "epoch_missing": ("BUNDLE_SECURITY_EPOCH_MISSING", "BUNDLE_SECURITY_EPOCH_MISSING"),
    "epoch_boolean": ("BUNDLE_SECURITY_EPOCH_INVALID", "BUNDLE_SECURITY_EPOCH_INVALID"),
    "policy_not_accepted": ("BUNDLE_EXPORT_POLICY_NOT_ACCEPTED", "BUNDLE_EXPORT_POLICY_NOT_ACCEPTED"),
    "policy_missing": ("BUNDLE_EXPORT_POLICY_MISSING", "BUNDLE_EXPORT_POLICY_MISSING"),
    "format_unsupported": ("BUNDLE_FORMAT_UNSUPPORTED", "BUNDLE_FORMAT_UNSUPPORTED"),
    "kind_differential": (ACCEPTED, "BUNDLE_KIND_UNSUPPORTED"),
    "version_string": (ACCEPTED, "BUNDLE_VERSION_INVALID"),
    "version_boolean": (ACCEPTED, "BUNDLE_VERSION_INVALID"),
    "corrupt_signature": (_T, _T),
    "corrupt_payload": ("BUNDLE_FILE_HASH_MISMATCH", "BUNDLE_FILE_HASH_MISMATCH"),
    "truncated": ("BUNDLE_ARCHIVE_UNREADABLE", "BUNDLE_ARCHIVE_UNREADABLE"),
    "member_missing": ("BUNDLE_FILE_MISSING", "BUNDLE_FILE_MISSING"),
    "member_undeclared": ("BUNDLE_UNDECLARED_MEMBER", "BUNDLE_UNDECLARED_MEMBER"),
    "member_duplicate": ("BUNDLE_DUPLICATE_MEMBER", "BUNDLE_DUPLICATE_MEMBER"),
    "member_symlink": ("BUNDLE_UNSAFE_MEMBER", "BUNDLE_UNSAFE_MEMBER"),
    "member_dotdot": ("BUNDLE_UNSAFE_MEMBER", "BUNDLE_UNSAFE_MEMBER"),
    "member_nine_components": ("BUNDLE_MEMBER_PATH_TOO_DEEP", "BUNDLE_MEMBER_PATH_TOO_DEEP"),
    "member_eight_components": (ACCEPTED, ACCEPTED),
    "member_name_214_bytes": (ACCEPTED, "BUNDLE_MEMBER_NAME_TOO_LONG"),
    "member_component_296_bytes": ("BUNDLE_ARCHIVE_UNREADABLE", "BUNDLE_MEMBER_NAME_TOO_LONG"),
    "members_over_64": (ACCEPTED, "BUNDLE_TOO_MANY_MEMBERS"),
    "ratio_over_100": ("BUNDLE_DECOMPRESSION_BOMB", ACCEPTED),
    "manifest_not_first": ("BUNDLE_MANIFEST_MISSING", ACCEPTED),
    "manifest_pretty_signed_canonical": (ACCEPTED, _T),
    "manifest_pretty_signed_raw": (_T, ACCEPTED),
    "manifest_shadows_trust": ("BUNDLE_SHADOWS_TRUST_ANCHOR", ACCEPTED),
    "manifest_shadows_key_roles": (ACCEPTED, "BUNDLE_SHADOWS_TRUST_ANCHOR"),
    "manifest_local_tier_table": ("BUNDLE_TOUCHES_LOCAL_TIER", ACCEPTED),
    "signature_33_lines": (ACCEPTED, "BUNDLE_SIGNATURE_MALFORMED"),
}

#: Every case the two verifiers disagree on: which side is stricter, and
#: which side the evidence says is right. `docs/knowledge-lite-differential.md`
#: carries the same list with its owner decisions.
DIVERGENCES: dict[str, tuple[str, str]] = {
    "threshold0_bad_signature": ("nexus", "Knowledge accepts a bundle with no valid signature "
                                 "when anchors.toml says threshold = 0. Nexus refuses the anchor"),
    "kind_differential": ("nexus", "Lite is full-only by Nexus design (ADR-0017); Knowledge's "
                          "verifier also serves full-node differential bundles"),
    "version_string": ("nexus", "Knowledge coerces bundle_version with int(); its builder emits "
                       "an integer and its own epoch gate refuses non-integers"),
    "version_boolean": ("nexus", "int(True) == 1 in Knowledge; Nexus refuses a non-integer"),
    "member_name_214_bytes": ("nexus", "Nexus caps member names at 200, Knowledge at 1024 bytes; "
                              "no builder emits a name near either"),
    "member_component_296_bytes": ("both refuse", "Knowledge's 1024-byte cap does not bound one "
                                   "component, so staging hits the filesystem's NAME_MAX and the "
                                   "OSError surfaces as BUNDLE_ARCHIVE_UNREADABLE: a refusal "
                                   "under the wrong code"),
    "members_over_64": ("nexus", "Nexus caps members at 64, Knowledge at 256; builders emit at most 14"),
    "ratio_over_100": ("knowledge", "Knowledge also caps the decompression ratio at 100:1; Nexus "
                       "caps only absolute sizes"),
    "manifest_not_first": ("knowledge", "Knowledge requires manifest.json, manifest.sig as the "
                           "first two members; Nexus reads all members first and ignores order"),
    "manifest_pretty_signed_canonical": ("nexus", "Knowledge signs canonical bytes and verifies "
                                         "canonical(json.loads(raw)); Nexus verifies the raw bytes"),
    "manifest_pretty_signed_raw": ("knowledge", "the same difference the other way: Nexus accepts "
                                   "a signature over non-canonical bytes Knowledge never emits"),
    "manifest_shadows_trust": ("knowledge", "Knowledge's forbidden manifest fields include "
                               "anchors/trust and its rollback state fields; Nexus's list does not"),
    "manifest_shadows_key_roles": ("nexus", "Nexus also forbids key_roles, required_signer_role, "
                                   "minimum_security_epoch and accepted_export_policy_digests"),
    "manifest_local_tier_table": ("knowledge", "Knowledge refuses a bundle naming a local-tier "
                                  "table; Nexus has no local tier and serves only tables it reads"),
    "signature_33_lines": ("nexus", "Nexus caps manifest.sig at 32 lines"),
}


# -- the two verifiers ----------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    verdict: str
    files: Mapping[str, str] = field(default_factory=dict)


def nexus_verdict(case: Case, work: Path) -> Verdict:
    from azazel_nexus.lite_bundle import BundleRefused, read_anchors, verify_bundle

    path = work / f"{case.name}.anchors.toml"
    path.write_text(case.anchors, encoding="utf-8")
    try:
        anchors = read_anchors(path)
        accepted = verify_bundle(case.bundle, anchors=anchors,
                                 last_imported_version=case.watermark)
    except BundleRefused as exc:
        return Verdict(exc.code)
    except Exception as exc:  # noqa: BLE001 - recorded, never hidden
        return Verdict(f"exception:{type(exc).__name__}")
    return Verdict(ACCEPTED, {n: _sha(b) for n, b in sorted(accepted.members.items())})


#: Runs inside Knowledge's interpreter environment with `python -I`, so neither
#: this checkout nor the current directory is on its path.
KNOWLEDGE_VERIFY = r'''
import hashlib, json, sys
from pathlib import Path
knowledge, work = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(knowledge / "src"))
from azazel_knowledge.bundle.verify import BundleVerifyError, verify_bundle
out = {}
for case in json.loads((work / "cases.json").read_text()):
    d = work / "cases" / case
    try:
        vb = verify_bundle(d / "bundle.tar.gz", d / "anchors.toml", d / "state.toml", d / "staging")
        files = {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in sorted(vb.file_paths.items())}
        out[case] = {"verdict": "accepted", "files": files}
    except BundleVerifyError as exc:
        out[case] = {"verdict": exc.code}
    except Exception as exc:
        out[case] = {"verdict": "exception:" + type(exc).__name__}
print(json.dumps(out))
'''

#: Fills a source database with Knowledge's own fixture row writer and reports
#: the export-policy digest Knowledge computes for its default policy.
KNOWLEDGE_SOURCE = r'''
import importlib.util, json, sys
from pathlib import Path
knowledge, work = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(knowledge / "src"))
spec = importlib.util.spec_from_file_location("lite_fixture", knowledge / "tools" / "lite_fixture.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
from azazel_knowledge.bundle.lite_policy import load_export_policy
fixture._write_source_db(work / "live.db", expiry=fixture.LIVE_UNTIL)
fixture._write_source_db(work / "expired.db", expiry=fixture.EXPIRED_AT)
policy = load_export_policy(fixture.DEFAULT_POLICY_PATH)
print(json.dumps({"policy_digest": policy.digest, "policy": str(fixture.DEFAULT_POLICY_PATH)}))
'''


def _run(args, **kwargs) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, **kwargs)
    if result.returncode != 0:
        raise SystemExit(f"{Path(args[2]).name if len(args) > 2 else args[0]} failed:\n"
                         f"{result.stderr[-4000:]}")
    return result


def write_seed(path: Path, seed: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(seed.hex())


def destroy(paths) -> None:
    """Overwrite then unlink each seed file. Best effort before rmtree."""
    for path in paths:
        try:
            size = path.stat().st_size
            with path.open("r+b") as handle:
                handle.write(b"\0" * size)
                handle.flush()
                os.fsync(handle.fileno())
            path.unlink()
        except FileNotFoundError:
            pass


def knowledge_bases(knowledge: Path, keys: LabKeys, work: Path) -> dict[str, bytes]:
    """Let Knowledge's own builder produce every base bundle."""
    python = sys.executable
    meta = json.loads(_run([python, "-I", "-c", KNOWLEDGE_SOURCE, str(knowledge), str(work)]).stdout)
    seed_files = {label: work / f"lab-{label}.seed" for label in KEY_LABELS}
    alias = work / "alias.key"
    try:
        for label, path in seed_files.items():
            write_seed(path, keys.seeds[label])
        write_seed(alias, os.urandom(16))
        plans = {
            "valid": ("live.db", ("A",), BUILD_EPOCH),
            "signed_B": ("live.db", ("B",), BUILD_EPOCH),
            "signed_C": ("live.db", ("C",), BUILD_EPOCH),
            "signed_D": ("live.db", ("D",), BUILD_EPOCH),
            "signed_AB": ("live.db", ("A", "B"), BUILD_EPOCH),
            "signed_AE": ("live.db", ("A", "E"), BUILD_EPOCH),
            "epoch_low": ("live.db", ("A",), BUILD_EPOCH - 1),
            "expired": ("expired.db", ("A",), BUILD_EPOCH),
        }
        bases = {}
        for name, (db, signers, epoch) in plans.items():
            out = work / f"{name}.tar.gz"
            args = [python, "-I", str(knowledge / "tools" / "bundle_build.py"), "build-lite",
                    "--source-db", str(work / db), "--out", str(out),
                    "--version", str(BUILD_VERSION), "--profile", BUILD_PROFILE,
                    "--export-policy", meta["policy"], "--alias-key-file", str(alias),
                    "--alias-scope", ALIAS_SCOPE, "--as-of", BUILD_AS_OF,
                    "--intel-generation", "1", "--stats-generation", "1",
                    "--attack-version", "fixture-v1", "--config-hash", "nexus-differential",
                    "--security-epoch", str(epoch)]
            for label in signers:
                args += ["--sign-key", str(seed_files[label])]
            _run(args)
            bases[name] = out.read_bytes()
    finally:
        destroy([*seed_files.values(), alias])
    recorded = json.loads(unpack(bases["valid"])[0][1])["profile"]["selection_inputs"]
    if recorded["export_policy_digest"] != meta["policy_digest"]:
        raise SystemExit("the manifest records a policy digest Knowledge does not compute")
    return bases


def knowledge_verdicts(knowledge: Path, cases, work: Path) -> dict[str, Verdict]:
    root = work / "cases"
    for case in cases:
        d = root / case.name
        d.mkdir(parents=True)
        (d / "bundle.tar.gz").write_bytes(case.bundle)
        (d / "anchors.toml").write_text(case.anchors, encoding="utf-8")
        (d / "state.toml").write_text(f"last_imported_version = {case.watermark}\n", encoding="utf-8")
    (work / "cases.json").write_text(json.dumps([c.name for c in cases]), encoding="utf-8")
    raw = json.loads(_run([sys.executable, "-I", "-c", KNOWLEDGE_VERIFY, str(knowledge),
                           str(work)]).stdout)
    return {name: Verdict(v["verdict"], v.get("files", {})) for name, v in raw.items()}


# -- the CI mode ---------------------------------------------------------------


def contract_bases(keys: LabKeys) -> dict[str, bytes]:
    """The bases derived from the Knowledge-emitted contract fixture.

    The content and manifest are Knowledge's; only the signature is replaced
    by one from a lab key, so the published fixture key signs nothing here.
    """
    valid = Base(_resign_fixture((CONTRACT / "lite.tar.gz").read_bytes(), keys, ("A",)), keys)
    out = {"valid": valid.raw}
    for name, signers in (("signed_B", ("B",)), ("signed_C", ("C",)), ("signed_D", ("D",)),
                          ("signed_AB", ("A", "B")), ("signed_AE", ("A", "E"))):
        out[name] = valid.signed(signers=signers)
    low = json.loads(valid.manifest_bytes)
    low["security_epoch"] -= 1
    out["epoch_low"] = valid.signed(low)
    out["expired"] = _resign_fixture((CONTRACT / "negative" / "expired.tar.gz").read_bytes(),
                                     keys, ("A",))
    return out


def _resign_fixture(raw: bytes, keys: LabKeys, signers) -> bytes:
    members = unpack(raw)
    body = members[0][1]
    sig = ("\n".join(keys.line(label, body) for label in signers) + "\n").encode("ascii")
    return pack([members[0], ("manifest.sig", sig), *members[2:]])


@dataclass
class Row:
    case: str
    knowledge: str | None
    nexus: str
    content_agrees: bool | None
    expected: tuple[str, str]

    @property
    def agree(self) -> bool | None:
        return None if self.knowledge is None else self.knowledge == self.nexus

    @property
    def as_recorded(self) -> bool:
        k_ok = self.knowledge is None or self.knowledge == self.expected[0]
        return k_ok and self.nexus == self.expected[1] and self.content_agrees is not False


def compare(cases, nexus: Mapping[str, Verdict], knowledge: Mapping[str, Verdict] | None) -> list[Row]:
    rows = []
    for case in cases:
        n = nexus[case.name]
        k = None if knowledge is None else knowledge[case.name]
        content = None
        if k is not None and k.verdict == ACCEPTED and n.verdict == ACCEPTED:
            content = dict(k.files) == dict(n.files)
        rows.append(Row(case.name, None if k is None else k.verdict, n.verdict, content,
                        EXPECTED.get(case.name, ("?", "?"))))
    return rows


def nexus_only(signer: Signer) -> list[Row]:
    keys = LabKeys.generate(signer)
    cases = build_cases(contract_bases(keys), keys)
    with tempfile.TemporaryDirectory(prefix="nexus-differential-") as tmp:
        nexus = {c.name: nexus_verdict(c, Path(tmp)) for c in cases}
    return compare(cases, nexus, None)


def differential(knowledge: Path, signer: Signer) -> list[Row]:
    keys = LabKeys.generate(signer)
    with tempfile.TemporaryDirectory(prefix="knowledge-differential-") as tmp:
        work = Path(tmp)
        os.chmod(work, 0o700)
        bases = knowledge_bases(knowledge, keys, work)
        cases = build_cases(bases, keys)
        nexus = {c.name: nexus_verdict(c, work) for c in cases}
        k = knowledge_verdicts(knowledge, cases, work)
    keys.seeds.clear()
    return compare(cases, nexus, k)


def render(rows, *, knowledge_rev: str | None = None) -> str:
    lines = []
    if knowledge_rev:
        lines.append(f"knowledge: {knowledge_rev}")
    lines.append("| case | Knowledge | Nexus | agree | as recorded |")
    lines.append("|---|---|---|---|---|")
    for r in rows:
        agree = "-" if r.agree is None else ("yes" if r.agree else "NO")
        if r.content_agrees is False:
            agree += " (content differs)"
        lines.append(f"| {r.case} | {r.knowledge or '-'} | {r.nexus} | {agree} | "
                     f"{'yes' if r.as_recorded else 'NO'} |")
    agree = sum(1 for r in rows if r.agree)
    differ = sum(1 for r in rows if r.agree is False)
    bad = [r.case for r in rows if not r.as_recorded]
    lines.append(f"cases={len(rows)} agree={agree} differ={differ} not_as_recorded={len(bad)}"
                 + (f" ({', '.join(bad)})" if bad else ""))
    return "\n".join(lines)


def _rev(knowledge: Path) -> str:
    try:
        return subprocess.run(["git", "-C", str(knowledge), "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--knowledge", type=Path, help="a read-only Azazel-Knowledge checkout")
    parser.add_argument("--nexus-only", action="store_true",
                        help="judge the contract-fixture cases with Nexus alone (the CI mode)")
    parser.add_argument("--json", type=Path, help="also write the rows as JSON here")
    args = parser.parse_args(argv)
    if not args.nexus_only and (
            args.knowledge is None or not (args.knowledge / "tools" / "bundle_build.py").is_file()):
        parser.error("--knowledge must name an Azazel-Knowledge checkout")
    signer = nacl_signer()
    if args.nexus_only:
        rows, rev = nexus_only(signer), None
    else:
        rows, rev = differential(args.knowledge.resolve(), signer), _rev(args.knowledge)
    print(render(rows, knowledge_rev=rev))
    if args.json:
        args.json.write_text(json.dumps([r.__dict__ | {"agree": r.agree, "as_recorded": r.as_recorded}
                                         for r in rows], indent=2, default=list) + "\n")
    return 0 if all(r.as_recorded for r in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
