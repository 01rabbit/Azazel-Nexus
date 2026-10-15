"""Independent declared bootstrap assembly and selected publication wiring."""

from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import inspect
import os
from pathlib import Path

import pytest

from azazel_nexus.bootstrap_deployment import encode_bootstrap_deployment
from azazel_nexus.bootstrap_generation_store import _load_at
from azazel_nexus.bootstrap_selection import BootstrapSelection
from azazel_nexus.generation import GenerationRefused
from azazel_nexus.operator_trust import ApprovalRefused
from azazel_nexus_runtime import bootstrap_declared_context as declared_context
from azazel_nexus_runtime import bootstrap_provisioning as provisioning
from azazel_nexus_runtime.node_config import DeclaredNode
from test_bootstrap_deployment_store import declaration
from test_bootstrap_generation import _bootstrap_metadata, _config, _context
from test_bootstrap_prestart_policy import policy

BOOT = "11111111-1111-4111-8111-111111111111"
APPROVAL = "22222222-2222-4222-8222-222222222222"


def _declared_inputs():
    deployment = declaration()
    config = _config()
    context = _context(
        {"bootstrap.json": config}, node_digest=deployment.node_digest,
        boot_id=BOOT, approval_id=APPROVAL,
        security_epoch=deployment.security_epoch,
        revocation_digest=deployment.revocation_digest,
        policy_digest=deployment.policy_digest,
        approval_policy_digest=deployment.approval_policy_digest,
    )
    selection = BootstrapSelection(
        "sha256:" + sha256(encode_bootstrap_deployment(deployment)).hexdigest(),
        BOOT, APPROVAL, context.generation, context.generation_digest,
    )
    return deployment, DeclaredNode("node-a"), selection, policy(), context, config


@pytest.fixture
def declared(monkeypatch):
    values = _declared_inputs()
    deployment, node, selection, selected_policy, context, _config_bytes = values
    monkeypatch.setattr(declared_context, "load_bootstrap_deployment", lambda: deployment)
    monkeypatch.setattr(declared_context, "load_declared_node", lambda: node)
    monkeypatch.setattr(declared_context, "load_bootstrap_selection", lambda: selection)
    monkeypatch.setattr(declared_context, "load_declared_prestart_policy",
                        lambda *, deployment: selected_policy)
    monkeypatch.setattr(declared_context, "read_boot_id", lambda: BOOT)
    return values


def test_declared_context_is_assembled_from_separate_admin_inputs_not_candidate(
    declared,
):
    deployment, _node, selection, selected_policy, expected, _config_bytes = declared
    result = declared_context.load_declared_bootstrap_context()

    assert result.context == expected
    assert result.operator == deployment.operator
    assert result.context.approval_id == selection.approval_id
    assert result.context.package_digest == selected_policy.package_digest
    assert result.context.unit_closure_digest == selected_policy.unit_closure_digest
    assert "context" not in inspect.signature(
        declared_context.load_declared_bootstrap_context
    ).parameters


@pytest.mark.parametrize("changed_source", ["deployment", "node", "selection", "boot", "policy"])
def test_declared_context_refuses_source_changes_on_reread(monkeypatch, declared, changed_source):
    deployment, node, selection, selected_policy, _context, _config_bytes = declared
    if changed_source == "deployment":
        values = iter((deployment, replace(deployment, security_epoch=deployment.security_epoch + 1)))
        monkeypatch.setattr(declared_context, "load_bootstrap_deployment", lambda: next(values))
    elif changed_source == "node":
        values = iter((node, DeclaredNode("node-b")))
        monkeypatch.setattr(declared_context, "load_declared_node", lambda: next(values))
    elif changed_source == "selection":
        values = iter((selection, replace(selection, approval_id="33333333-3333-4333-8333-333333333333")))
        monkeypatch.setattr(declared_context, "load_bootstrap_selection", lambda: next(values))
    elif changed_source == "boot":
        values = iter((BOOT, "44444444-4444-4444-8444-444444444444"))
        monkeypatch.setattr(declared_context, "read_boot_id", lambda: next(values))
    else:
        values = iter((selected_policy, replace(selected_policy, package_digest="sha256:" + "9" * 64)))
        monkeypatch.setattr(declared_context, "load_declared_prestart_policy",
                            lambda *, deployment: next(values))

    with pytest.raises(ApprovalRefused, match="declared bootstrap context refused"):
        declared_context.load_declared_bootstrap_context()


@pytest.fixture
def publication_store(tmp_path):
    root = tmp_path / "generations"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    return root


def _patch_public_store(monkeypatch, root):
    import azazel_nexus.bootstrap_generation_publish as publisher

    @contextmanager
    def directory():
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    monkeypatch.setattr(publisher, "_generation_directory", directory)
    original_publish = publisher._publish_at

    def publish_for_test(fd, **kwargs):
        kwargs["owner"] = os.getuid()
        return original_publish(fd, **kwargs)

    monkeypatch.setattr(publisher, "_publish_at", publish_for_test)


def _read_published(root: Path, expected):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return _load_at(fd, owner=os.getuid(), expected=expected)
    finally:
        os.close(fd)


def test_public_selected_publisher_writes_generation_readable_by_actual_reader(
    declared, publication_store, monkeypatch,
):
    deployment, _node, _selection, _policy, context, config = declared
    selected = declared_context.load_declared_bootstrap_context()
    metadata = _bootstrap_metadata(context)
    monkeypatch.setattr(provisioning, "load_declared_bootstrap_context", lambda: selected)
    _patch_public_store(monkeypatch, publication_store)

    result = provisioning.publish_selected_bootstrap_generation(
        metadata=metadata,
        config=config,
        confirmed_digest=provisioning.selected_publication_digest(
            metadata=metadata, config=config, selected=selected,
        ),
        confirmed_publish=True,
    )

    assert result == _read_published(publication_store, context)
    assert (publication_store / str(context.generation) / "generation.json").read_bytes() == metadata
    assert (publication_store / str(context.generation) / "tree" / "bootstrap.json").read_bytes() == config
    assert not (publication_store / f".bootstrap-{context.generation}.pending").exists()
    assert deployment.operator == selected.operator


@pytest.mark.parametrize("change", ["approval_id", "operator"])
def test_old_confirmation_refuses_same_payload_after_selected_identity_changes(
    declared, publication_store, monkeypatch, change,
):
    deployment, _node, _selection, _policy, context, config = declared
    selected = declared_context.load_declared_bootstrap_context()
    metadata = _bootstrap_metadata(context)
    old_confirmation = provisioning.selected_publication_digest(
        metadata=metadata, config=config, selected=selected,
    )
    changed = (
        replace(selected, context=replace(context, approval_id="33333333-3333-4333-8333-333333333333"))
        if change == "approval_id"
        else replace(selected, operator="operator-b")
    )
    monkeypatch.setattr(provisioning, "load_declared_bootstrap_context", lambda: changed)
    _patch_public_store(monkeypatch, publication_store)

    with pytest.raises(GenerationRefused, match="selected bootstrap publication refused"):
        provisioning.publish_selected_bootstrap_generation(
            metadata=metadata, config=config,
            confirmed_digest=old_confirmation, confirmed_publish=True,
        )
    assert list(publication_store.iterdir()) == []
    assert deployment.operator != changed.operator or change == "approval_id"


def test_selection_mutation_at_final_recheck_retains_pending_and_blocks_reader(
    declared, publication_store, monkeypatch,
):
    _deployment, _node, _selection, _policy, context, config = declared
    selected = declared_context.load_declared_bootstrap_context()
    changed = replace(
        selected,
        context=replace(context, approval_id="33333333-3333-4333-8333-333333333333"),
    )
    metadata = _bootstrap_metadata(context)
    snapshots = iter((selected, selected, changed))
    monkeypatch.setattr(
        provisioning, "load_declared_bootstrap_context", lambda: next(snapshots),
    )
    _patch_public_store(monkeypatch, publication_store)

    with pytest.raises(GenerationRefused, match="selected bootstrap publication refused"):
        provisioning.publish_selected_bootstrap_generation(
            metadata=metadata, config=config,
            confirmed_digest=provisioning.selected_publication_digest(
                metadata=metadata, config=config, selected=selected,
            ),
            confirmed_publish=True,
        )

    assert (publication_store / f".bootstrap-{context.generation}.pending").exists()
    with pytest.raises(GenerationRefused):
        _read_published(publication_store, context)
