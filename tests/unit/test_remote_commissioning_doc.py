"""The commissioning document describes the implementation, and carries no
real material (#116).

Two failure modes, both checked:

- the document drifts from `provider_registry.py`, so an operator building a
  bundle from it produces something the verifier refuses
- the document acquires a real endpoint, credential or pin, because
  somebody found it convenient to paste one in while testing

The second is why this file exists at all. A preparation document is exactly
where a real value gets left behind.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from azazel_nexus.provider_registry import (
    PROVIDER_DOMAIN,
    PROVIDER_SCHEMA,
    ProviderRecord,
    provider_registry_payload,
)
from azazel_nexus.sanitizer import PrivacyClass

DOC = Path(__file__).resolve().parents[2] / "docs" / "remote-commissioning.md"


def test_the_document_exists():
    assert DOC.is_file(), "the commissioning document is missing"


def test_the_example_bundle_has_exactly_the_fields_the_verifier_reads():
    """Generated from the same code the verifier uses, then compared against
    the document -- so drift is a failure here rather than a refusal on a
    node somebody is commissioning."""

    record = ProviderRecord(
        provider_id="example-provider",
        host="provider.example.test",
        port=443,
        path_template="/v1/{model}/advise",
        certificate_pin="sha256:" + "0" * 64,
        client_identity="node-client-identity",
        model_id="advisor",
        max_request_bytes=65536,
        max_response_bytes=65536,
        deadline_seconds=20,
        allowed_privacy_classes=(PrivacyClass.P1_SANITIZED,),
    )
    payload = json.loads(
        provider_registry_payload(
            version=1, commissioning_digest="sha256:" + "0" * 64, records=[record]
        )
    )
    text = DOC.read_text(encoding="utf-8")

    for key in sorted(payload):
        assert f'"{key}"' in text, f"the document omits the top-level {key!r}"
    for key in sorted(payload["providers"][0]):
        assert f'"{key}"' in text, f"the document omits the provider field {key!r}"


def test_the_document_names_the_schema_and_the_domain():
    text = DOC.read_text(encoding="utf-8")
    assert PROVIDER_SCHEMA in text
    assert PROVIDER_DOMAIN.rstrip(b"\x00").decode() in text


def test_the_document_states_the_canonicalisation_the_verifier_uses():
    text = DOC.read_text(encoding="utf-8")
    assert "sort_keys=True" in text and 'separators=(",", ":")' in text


def test_the_document_carries_no_private_key_material():
    text = DOC.read_text(encoding="utf-8")
    for forbidden in (
        "BEGIN PRIVATE KEY",
        "BEGIN RSA",
        "BEGIN EC PRIVATE",
        "BEGIN OPENSSH",
        "-----BEGIN",
    ):
        assert forbidden not in text, f"the document carries {forbidden!r}"


def test_the_document_carries_no_real_pin_or_digest():
    """Every `sha256:` in it is the all-zero placeholder.

    A real one would be a real provider's key fingerprint sitting in a file
    that is read aloud -- and worse, one somebody might paste into a bundle
    believing it was an example.
    """

    text = DOC.read_text(encoding="utf-8")
    digests = set(re.findall(r"sha256:([0-9a-f]{64})", text))
    real = sorted(d for d in digests if set(d) != {"0"})
    assert real == [], f"the document carries non-placeholder digests: {real}"


def test_every_hostname_in_the_document_is_a_reserved_example_name():
    """`.test`, `.example` and `.invalid` are reserved by RFC 2606 and
    resolve nowhere. Anything else is somebody's actual host."""

    text = DOC.read_text(encoding="utf-8")
    hosts = set(re.findall(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", text))
    offenders = sorted(
        host
        for host in hosts
        if not host.endswith((".test", ".example", ".invalid", ".md", ".py", ".json"))
        and not host.startswith(("docs.", "tests."))
        and host
        not in {
            "provider_registry.py",
            "hardware-gates.md",
            "mio-local-runtime.md",
            "runtime-lifecycle.md",
            "test_mio_remoted.py",
            "test_remote_commissioning_doc.py",
        }
    )
    assert offenders == [], f"the document names real-looking hosts: {offenders}"


@pytest.mark.parametrize(
    "requirement",
    [
        "the provider and the contract are identified",
        "the sanitizer role key is commissioned",
        "revocation and rollback have a runbook and a named owner",
        "the decision to connect is recorded",
    ],
)
def test_the_checklist_keeps_its_separate_confirmations(requirement):
    """A single 'yes' covering all of them is a person consenting to one
    thing and authorising nine."""

    text = DOC.read_text(encoding="utf-8")
    assert requirement in text, f"the checklist lost {requirement!r}"


def test_the_document_states_that_the_transport_refusal_does_not_relax():
    """The one guarantee most likely to be argued away once a real provider
    exists."""

    text = DOC.read_text(encoding="utf-8")
    assert "does not relax when a real provider exists" in text
    assert "P2-mission" in text and "P3-restricted" in text


def test_the_document_does_not_claim_a_provider_is_commissioned():
    text = DOC.read_text(encoding="utf-8").lower()
    for claim in (
        "provider is commissioned",
        "connection is established",
        "inference is available",
    ):
        assert claim not in text, f"the document claims {claim!r}"
    assert "preparation, not permission" in DOC.read_text(encoding="utf-8")
