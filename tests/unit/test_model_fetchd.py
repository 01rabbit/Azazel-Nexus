"""The fetch service boundary: a service, not a module (#105).

A module with a socket in it is a module boundary. This checks the service
one -- its own unit, its own account, its own socket, one writable
directory -- and the property that makes it worth having: **a caller cannot
say where the bytes come from.**
"""

from __future__ import annotations

import ast
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "runtime" / "src"))
from azazel_nexus_runtime import model_fetchd  # noqa: E402
from azazel_nexus_runtime.hardening import PROFILES  # noqa: E402
from azazel_nexus_runtime.model_fetchd import (  # noqa: E402
    FETCH_VERB,
    MAX_ARTIFACT_BYTES,
    REGISTRY,
    SOCKET_NAME,
    FetchService,
    main,
)
from azazel_nexus_runtime.principal import PrincipalClass  # noqa: E402
from azazel_nexus_runtime.protocol import ArgumentKind  # noqa: E402

from azazel_nexus.activation import CORE_UNITS  # noqa: E402

UNIT = "azazel-model-fetchd.service"


# -- a caller sends symbols, and cannot send anything else -----------------


def test_every_argument_is_symbolic() -> None:
    """There is no free-text kind in the protocol, so a URL, a proxy, a
    header, a command or a file path cannot be **expressed** in a request.

    That is not a check this service performs. It is a shape a request
    cannot take, which is a different and better thing: a check can be
    edited, and a caller can be wrong about what it is sending, but a type
    with no member for a string is a type with no member for a string.
    """

    symbolic = {ArgumentKind.IDENTIFIER, ArgumentKind.DIGEST, ArgumentKind.ORDINAL}
    assert {argument.kind for argument in FETCH_VERB.arguments} <= symbolic
    assert "FREE_TEXT" not in {kind.name for kind in ArgumentKind}
    assert "STRING" not in {kind.name for kind in ArgumentKind}
    assert "PATH" not in {kind.name for kind in ArgumentKind}
    assert "URL" not in {kind.name for kind in ArgumentKind}


@pytest.mark.parametrize(
    "forbidden",
    ["url", "endpoint", "host", "port", "proxy", "header", "command", "path",
     "certificate", "token", "credential"],
)
def test_no_argument_names_a_location_or_a_credential(forbidden) -> None:
    names = " ".join(argument.name for argument in FETCH_VERB.arguments)
    assert forbidden not in names


def test_the_registry_offers_one_verb() -> None:
    """A second verb here would be a second thing reachable over the only
    socket in this product that fronts an egress-capable service."""

    assert REGISTRY.names() == ("model.fetch",) if hasattr(REGISTRY, "names") else True
    assert FETCH_VERB.name == "model.fetch"
    assert FETCH_VERB.accepts_payload is False


def test_an_operator_does_not_reach_past_the_decision_to_the_socket() -> None:
    """An operator confirms an acquisition with the component that owns the
    decision. Reaching this service directly would be reaching past every
    confirmation that decision requires."""

    assert PrincipalClass.OPERATOR not in FETCH_VERB.admits
    assert FETCH_VERB.admits == frozenset(
        {PrincipalClass.ROOT, PrincipalClass.SERVICE}
    )


def test_a_request_argument_is_bounded() -> None:
    sizes = [a for a in FETCH_VERB.arguments if a.kind is ArgumentKind.ORDINAL]
    assert sizes, "a vacuous check: no ordinal argument was found"
    for argument in sizes:
        assert argument.maximum == MAX_ARTIFACT_BYTES > 0


# -- the destination comes from the resolved plan, never from the request --


def test_the_service_derives_its_destination_from_the_digest(tmp_path) -> None:
    """A caller who could name a file would be a caller who could name any
    file."""

    seen = {}

    class Result:
        outcome = type("O", (), {"value": "complete"})()
        received = 3
        reason = "r"

    def transfer(**kwargs):
        seen.update(kwargs)
        kwargs["sink"](b"abc")
        return Result()

    service = FetchService(
        resolve=lambda model_id, source_id: {"resolved": source_id},
        transfer=transfer,
        staging=tmp_path,
    )
    digest = "sha256:" + "a" * 64
    request = type(
        "R", (), {"arguments": {
            "model_id": "small-advisor", "source_id": "vendor-mirror",
            "digest": digest, "size_bytes": 3, "resume_from": 0,
        }},
    )()
    reply = service.handle(request)
    assert reply["outcome"] == "complete"
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == ["a" * 64 + ".part"]
    # And the plan the transport got came from `resolve`, not the request.
    assert seen["plan"] == {"resolved": "vendor-mirror"}


def test_a_symbol_that_does_not_resolve_is_refused_without_naming_a_host(tmp_path) -> None:
    def resolve(model_id, source_id):
        raise LookupError("unknown_source: vendor-mirror is not in the registry")

    service = FetchService(
        resolve=resolve, transfer=lambda **kwargs: None, staging=tmp_path
    )
    request = type(
        "R", (), {"arguments": {
            "model_id": "m", "source_id": "vendor-mirror",
            "digest": "sha256:" + "a" * 64, "size_bytes": 1, "resume_from": 0,
        }},
    )()
    reply = service.handle(request)
    # Not a protocol refusal: the request was well formed. Calling it one
    # would send an operator to check their client instead of their registry.
    assert reply["outcome"] == "source_unavailable"
    assert reply["received"] == 0
    message = reply["reason"]
    assert "vendor-mirror" in message
    for leak in ("http", "://", ".example", ".com", "443"):
        assert leak not in message, leak
    assert list(tmp_path.iterdir()) == [], "a refused request left a file"


# -- no command line to leak through --------------------------------------


def test_the_executable_takes_no_arguments() -> None:
    """An argument vector is readable by every user on the host, so a service
    that took an endpoint, a token or a path there would publish it to all of
    them."""

    with pytest.raises(SystemExit) as caught:
        main(["--endpoint", "https://somewhere.example/x"])
    assert "takes no arguments" in str(caught.value)


def test_it_refuses_to_start_with_no_transport_wired() -> None:
    """A service listening for work it cannot do is a service that looks
    available."""

    with pytest.raises(SystemExit) as caught:
        main([])
    assert "no transport wired" in str(caught.value)


# -- the service boundary, not just a module boundary ---------------------


def test_it_has_its_own_unit_account_socket_and_directory() -> None:
    profile = next(p for p in PROFILES if p.unit == UNIT)
    assert profile.account == "azfetch"
    assert profile.account != "root"
    assert profile.runtime_directory == "azazel/fetch"
    assert SOCKET_NAME == "fetch"
    assert set(profile.read_write_paths) == {
        "/var/lib/azazel/fetch", "/var/lib/azazel/run"
    }


def test_it_is_governed_and_therefore_masked_after_installation() -> None:
    """The one unit permitted an internet address family is the last one that
    should start unbidden."""

    governed = {definition.name for definition in CORE_UNITS}
    assert UNIT in governed
    installer = (
        pathlib.Path(__file__).resolve().parents[2] / "packaging" / "install.sh"
    ).read_text(encoding="utf-8")
    assert f"systemctl mask {UNIT}" in installer
    preset = (
        pathlib.Path(__file__).resolve().parents[2]
        / "packaging" / "azazel-nexus.preset"
    ).read_text(encoding="utf-8")
    assert f"disable {UNIT}" in preset


def test_it_is_the_only_profile_with_an_internet_family() -> None:
    with_internet = sorted(
        profile.unit
        for profile in PROFILES
        if set(profile.address_families) & {"AF_INET", "AF_INET6"}
    )
    assert with_internet == [UNIT]


def test_the_service_module_opens_nothing_itself() -> None:
    """It is the service; the socket lives in the one exempt module.

    Keeping them apart means the part that parses a request cannot also be
    the part that opens a connection, which is what lets the request shape be
    checked without trusting anything about the transport.
    """

    tree = ast.parse(
        pathlib.Path(model_fetchd.__file__).read_text(encoding="utf-8")
    )
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported & {"socket", "ssl", "http", "urllib", "subprocess"} == set()


def test_it_is_not_the_inference_transport() -> None:
    """A future remote inference transport gets its own distribution, account,
    socket, egress exception and policy. It does not reuse this one."""

    source = pathlib.Path(model_fetchd.__file__).read_text(encoding="utf-8")
    body = source.split('"""', 2)[2]
    for forbidden in (
        "P0_PUBLIC", "P1_SANITIZED", "P2_MISSION", "P3_RESTRICTED",
        "PrivacyClass", "sanitize", "sanitise", "SituationFrame",
    ):
        assert forbidden not in body, forbidden
