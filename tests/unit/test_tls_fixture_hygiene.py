"""The committed test keys are test-only, and that is checked (#105).

`tests/fixtures/tls` holds private keys in the repository on purpose: they
authenticate a loopback server that exists for the length of a test, and
committing them is what makes the TLS tests run everywhere without an
`openssl` binary.

That is only true while they stay where they are. A private key committed to
a repository is a compromised key, so the one thing that must never happen is
for this material -- or anything derived from it -- to appear somewhere that
matters. This is the check that says so.

It is a **content** scan, not a path scan. A file that had been copied,
renamed, base64'd into a config or pasted into a packaging script would keep
its key bytes, and the key bytes are what is searched for.
"""

from __future__ import annotations

import base64
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
TLS = REPO / "tests" / "fixtures" / "tls"

#: Everywhere this material would matter if it appeared. Named individually
#: rather than as "everything but the fixtures", so that a new directory is
#: considered rather than silently covered or silently missed.
GUARDED = (
    ("production source", REPO / "src"),
    ("privileged runtime", REPO / "runtime" / "src"),
    ("packaging", REPO / "packaging"),
    ("operational units and profiles", REPO / "ops"),
    ("operator tooling", REPO / "tools"),
    ("continuous integration", REPO / ".github"),
    ("documentation", REPO / "docs"),
)

#: Directories that are neither fixtures nor guarded: build output and the
#: virtualenv. Skipped because scanning them says nothing about this
#: repository.
IGNORED_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", "build", "dist"}


def _fixture_secrets() -> dict:
    """The key material to hunt for, in the forms it could travel in."""

    secrets = {}
    for path in sorted(TLS.glob("*.key")):
        text = path.read_text(encoding="ascii")
        body = "".join(
            line for line in text.splitlines() if not line.startswith("-----")
        ).strip()
        assert body, f"{path.name} carries no key body"
        raw = base64.b64decode(body)
        secrets[path.name] = {
            # The PEM body, whole and in pieces -- a reformatted copy keeps
            # the base64 even when the line breaks move.
            "pem-body": body.replace("\n", ""),
            "pem-head": body[:64],
            # And the DER bytes, for a copy that was decoded on the way.
            "der-head": raw[:32],
        }
    return secrets


SECRETS = _fixture_secrets()


def _files_under(root: pathlib.Path):
    if not root.exists():
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if set(path.parts) & IGNORED_PARTS:
            continue
        yield path


@pytest.mark.parametrize("label, root", GUARDED, ids=[label for label, _ in GUARDED])
def test_no_fixture_key_appears_in_a_place_that_matters(label, root) -> None:
    """Production source, packaging, runtime, CI, ops and docs."""

    offenders = []
    for path in _files_under(root):
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        text = blob.decode("utf-8", "ignore")
        for name, forms in SECRETS.items():
            if forms["pem-head"] in text or forms["pem-body"] in text:
                offenders.append(f"{path.relative_to(REPO)} carries {name}")
            elif forms["der-head"] in blob:
                offenders.append(f"{path.relative_to(REPO)} carries {name} (DER)")
    assert offenders == [], f"test-only key material reached {label}: {offenders}"


def test_the_scan_is_not_vacuous() -> None:
    """It finds the fixtures where they live, so a pass means it looked."""

    found = []
    for path in _files_under(TLS):
        blob = path.read_bytes()
        text = blob.decode("utf-8", "ignore")
        for name, forms in SECRETS.items():
            if forms["pem-head"] in text or forms["der-head"] in blob:
                found.append(name)
    assert set(found) == set(SECRETS), "the scan cannot see the fixtures themselves"


def test_no_fixture_key_is_a_signing_or_credential_key() -> None:
    """Catalog signing, registry signing, operator credentials, release
    signing: named because these are the roles where a reused key would be
    worst, and where "it is only a test key" would be said most readily."""

    roles = (
        "catalog", "registry", "signing", "release", "operator", "credential",
        "commission", "anchor", "trust",
    )
    offenders = []
    for label, root in GUARDED:
        for path in _files_under(root):
            if not any(role in path.name.lower() for role in roles):
                continue
            blob = path.read_bytes()
            text = blob.decode("utf-8", "ignore")
            for name, forms in SECRETS.items():
                if forms["pem-head"] in text or forms["der-head"] in blob:
                    offenders.append(f"{path.relative_to(REPO)} ({label}) carries {name}")
    assert offenders == []


def test_no_private_key_lives_outside_the_fixture_directory() -> None:
    """Broader than the material above: **any** private key elsewhere.

    A second set of test keys added somewhere convenient would not be caught
    by scanning for these bytes, and would be exactly as committed.
    """

    # A header **with a body**. The header alone is not key material, and it
    # appears legitimately as a rejected input elsewhere in the suite --
    # `test_source_registry.py` checks that a client identity spelled like a
    # PEM header is refused. Flagging that would train a reader to ignore
    # this check, which is worse than not having it.
    marker = re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s]*[A-Za-z0-9+/=\s]{100,}"
    )
    offenders = []
    for path in sorted(REPO.rglob("*")):
        if not path.is_file() or set(path.parts) & IGNORED_PARTS:
            continue
        if TLS in path.parents:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if marker.search(text):
            offenders.append(str(path.relative_to(REPO)))
    assert offenders == [], f"a private key lives outside the fixtures: {offenders}"
    # Positive control: the pattern still matches real material. A tightened
    # regex that matched nothing would pass this test for the wrong reason.
    assert marker.search((TLS / "server.key").read_text(encoding="ascii"))


def test_the_fixture_directory_says_what_it_is() -> None:
    """A reader who finds a private key in a repository should learn why
    within one file, not by inference."""

    readme = (TLS / "README.md").read_text(encoding="utf-8")
    assert "test-only" in readme.lower()
    assert "committed" in readme.lower()
    assert "run every time" in readme.lower()


def test_no_fixture_certificate_is_trusted_by_the_host() -> None:
    """A self-signed CA with no path to a public root, which is the only
    reason committing the leaf keys is harmless."""

    import ssl

    store = ssl.create_default_context()
    system = {entry["serialNumber"] for entry in store.get_ca_certs()}
    for path in sorted(TLS.glob("*.crt")):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(path))
        loaded = {entry["serialNumber"] for entry in context.get_ca_certs()}
        assert not (loaded & system), f"{path.name} is in the host trust store"
