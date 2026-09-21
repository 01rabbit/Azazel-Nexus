"""The test-only signer uses test-only keys, and they stay in the tests.

Nexus verifies and never signs. `tests/unit/signing_oracle.py` exists because
a signed fixture has to be signed by something, and it lives outside the
product where the "no signer" scan cannot reach it.

That arrangement is only safe while two things hold, so both are checked
rather than assumed:

1. **The seeds are fixed test values and nothing else.** No production key, no
   commissioned trust key, no release key. This repository holds none of
   those, and nothing here reads one from a file, an environment variable or
   a network.
2. **Nothing the oracle derives leaks out of the tests.** Not into the
   product, not into the vendored contract, not into a fixture's metadata.

Seed material is never printed by anything here. A seed is a private value;
the public key it derives is not, which is why the public key is what gets
searched for below.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from signing_oracle import public_key_for

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests" / "unit"

#: Every seed this suite signs with, by the module that declares it. Listed so
#: that a new one has to be added here, where the rules below then apply to it.
TEST_SEEDS = {
    "test_lite_revocation.TRUSTED_SEED": bytes(range(32)),
    "test_lite_revocation.OTHER_SEED": bytes(range(32, 64)),
    "test_lite_revocation.SECOND_TRUSTED_SEED": bytes(range(64, 96)),
    "test_lite_bundle.SEED": bytes(range(96, 128)),
}


def test_every_declared_seed_is_distinct() -> None:
    """Two suites sharing a seed makes one suite's key look like another's."""

    assert len({bytes(seed) for seed in TEST_SEEDS.values()}) == len(TEST_SEEDS)


def test_the_declared_seeds_are_the_ones_the_suite_actually_uses() -> None:
    """A list that drifts from the code is a list that guards nothing."""

    declared = {name.split(".", 1)[1]: seed for name, seed in TEST_SEEDS.items()}
    for module_name in {name.split(".", 1)[0] for name in TEST_SEEDS}:
        tree = ast.parse((TESTS / f"{module_name}.py").read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                name = getattr(target, "id", "")
                if name.endswith("SEED") and name in declared:
                    assert eval(compile(ast.Expression(node.value), "<seed>", "eval")) == (
                        declared[name]
                    ), f"{module_name}.{name} is not the seed this file declares"


def test_no_seed_is_read_from_the_environment_a_file_or_a_network() -> None:
    """A fixed test value, not something the host could substitute."""

    oracle = (TESTS / "signing_oracle.py").read_text(encoding="utf-8")
    tree = ast.parse(oracle)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    for forbidden in ("os", "socket", "urllib", "subprocess", "secrets", "random"):
        assert forbidden not in imported, (
            f"the oracle imports {forbidden}; a seed it could obtain from the "
            "host is a seed this file cannot vouch for"
        )


@pytest.mark.parametrize("name", sorted(TEST_SEEDS))
def test_no_test_key_appears_in_the_product_or_the_vendored_contract(name: str) -> None:
    """Nothing the oracle derives leaks out of the tests.

    The **public** key is searched for, because that is the value that would
    show up somewhere it should not. The seed is private and is never written
    anywhere -- including here, where only its derived public key is used.
    """

    public = public_key_for(TEST_SEEDS[name]).hex()
    assert len(public) == 64

    searched = 0
    for directory in (
        ROOT / "src",
        ROOT / "runtime" / "src",
        ROOT / "contract",
        ROOT / "docs",
        ROOT / "packaging",
    ):
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix in {".gz", ".pyc"}:
                continue
            searched += 1
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            assert public not in text, f"a test public key appears in {path}"
    assert searched > 10, "a vacuous scan: almost nothing was searched"


def test_the_product_still_contains_no_signer() -> None:
    """The reason the oracle is outside it, restated where the oracle lives.

    The rule is `test_lite_signature.py`'s, imported rather than rewritten. A
    first draft here used `name.startswith("sign")` and flagged
    `signature_of` and `signature_digest` -- the same over-broad match that
    once flagged `SIGNATURE_BYTES`. A second, subtly different copy of a rule
    is a rule that disagrees with itself.
    """

    from test_lite_signature import _SIGNING_VERB

    package = ROOT / "src" / "azazel_nexus"
    offenders = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _SIGNING_VERB.match(node.name.lstrip("_")):
                    offenders.append(f"{path.name}:{node.name}")
    assert offenders == [], f"{offenders} look like a signer in the product"

    # Non-vacuity: the rule must still match an actual signing verb.
    assert _SIGNING_VERB.match("sign_detached")
    assert not _SIGNING_VERB.match("signature_of")
