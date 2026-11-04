"""CORE and the released Fabric pin stay safe before Knowledge Context v1."""

from __future__ import annotations

import importlib.util

import pytest

from azazel_nexus.knowledge_context_adapter import (
    KnowledgeContextRefused,
    make_request,
)
from azazel_nexus.sanitizer import PrivacyClass, SanitizerPolicy


def has_context_profile():
    try:
        return importlib.util.find_spec("azazel_fabric.knowledge_context") is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def make_p0_request():
    policy = SanitizerPolicy.from_mapping({
        "version": "context-availability-test-1",
        "remote_default": "deny",
        "classes": {
            "P0-public": {"remote": "allow", "fields": ["indicator"]},
        },
        "aliases": [],
        "redactions": [],
        "limits": {"max_bytes": 2048},
    })
    return make_request(
        {"indicator": "203.0.113.7"},
        privacy_class=PrivacyClass.P0_PUBLIC,
        policy=policy,
        mission="availability-test",
        alias_key=b"test-only",
        requested_at="2026-11-04T12:00:00Z",
    )


def test_missing_or_released_without_context_contract_stays_unavailable():
    if has_context_profile():
        request = make_p0_request()
        assert request.schema_version == "knowledge-context-request/v1"
        return
    with pytest.raises(KnowledgeContextRefused, match="does not fit Fabric v1"):
        make_p0_request()
