"""Interactive bootstrap generation preview/publication CLI, temp-only."""

from dataclasses import replace
from io import BytesIO, StringIO
import sys

import pytest

from azazel_nexus.bootstrap_generation_publish import (
    BootstrapGenerationDurabilityUncertain,
)
from azazel_nexus_runtime import bootstrap_cli as cli
from azazel_nexus_runtime import bootstrap_provisioning as provisioning
from azazel_nexus_runtime import debian_packages
from azazel_nexus_runtime.bootstrap_declared_context import DeclaredBootstrapContext
from test_bootstrap_generation import _bootstrap_metadata
from test_runtime_bootstrap_provisioning import (
    _declared_inputs,
    _patch_public_store,
    _read_published,
)


class FakeInput:
    def __init__(self, data: bytes, *, tty: bool):
        self.buffer = BytesIO(data)
        self._tty = tty

    def isatty(self):
        return self._tty


def _fixture():
    _deployment, _node, _selection, policy, context, config = _declared_inputs()
    return DeclaredBootstrapContext(
        context, "operator-a", policy.systemd_profile_digest
    ), _bootstrap_metadata(context), config


def _selected_digest(metadata, config, selected):
    return provisioning.selected_publication_digest(
        metadata=metadata, config=config, selected=selected,
    )


def _preview_bytes(metadata, config, *, tail=b""):
    return metadata + b"\n" + config + b"\n" + tail


def _publish_bytes(metadata, config, selected):
    digest = _selected_digest(metadata, config, selected)
    return _preview_bytes(metadata, config) + digest.encode() + b"\nPUBLISH\n"


def test_preview_reads_two_canonical_lines_and_runs_actual_selected_verifier(monkeypatch):
    selected, metadata, config = _fixture()
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    output = StringIO()

    result = cli.run_generation(
        source=FakeInput(_preview_bytes(metadata, config), tty=False),
        out=output, publish=False,
    )

    assert result == 0
    assert _selected_digest(metadata, config, selected) in output.getvalue()
    assert "Preview only; no files published." in output.getvalue()
    assert "NOT approval" in output.getvalue()


def test_preview_non_tty_never_calls_publisher(monkeypatch):
    selected, metadata, config = _fixture()
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    monkeypatch.setattr(cli, "publish_selected_bootstrap_generation",
                        lambda **_kwargs: pytest.fail("preview called publisher"))

    result = cli.run_generation(
        source=FakeInput(_preview_bytes(metadata, config), tty=False),
        out=StringIO(), publish=False,
    )
    assert result == 0


def test_actual_cli_dispatches_preview_operation(monkeypatch):
    selected, metadata, config = _fixture()
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    monkeypatch.setattr(sys, "stdin", FakeInput(_preview_bytes(metadata, config), tty=False))
    output = StringIO()
    monkeypatch.setattr(sys, "stdout", output)

    assert cli.main(["generation-preview"]) == 0
    assert "Preview only" in output.getvalue()


@pytest.mark.parametrize("case", ["wrong-digest", "wrong-word", "noncanonical-metadata", "oversized", "trailing-preview", "wrong-tty"])
def test_cli_refuses_bad_confirmation_records_bounds_trailing_input_and_tty(
    monkeypatch, case,
):
    selected, metadata, config = _fixture()
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    monkeypatch.setattr(cli, "publish_selected_bootstrap_generation",
                        lambda **_kwargs: pytest.fail("invalid input reached publisher"))
    if case == "wrong-digest":
        data = _preview_bytes(metadata, config) + b"sha256:" + b"0" * 64 + b"\nPUBLISH\n"
        source = FakeInput(data, tty=True)
        publish = True
    elif case == "wrong-word":
        data = _preview_bytes(metadata, config) + _selected_digest(metadata, config, selected).encode() + b"\nNO\n"
        source = FakeInput(data, tty=True)
        publish = True
    elif case == "noncanonical-metadata":
        data = _preview_bytes(metadata + b" ", config)
        source = FakeInput(data, tty=False)
        publish = False
    elif case == "oversized":
        data = b"{" + b" " * 65536 + b"\n" + config + b"\n"
        source = FakeInput(data, tty=False)
        publish = False
    elif case == "trailing-preview":
        data = _preview_bytes(metadata, config, tail=b"extra\n")
        source = FakeInput(data, tty=False)
        publish = False
    else:
        data = _preview_bytes(metadata, config)
        source = FakeInput(data, tty=True)
        publish = False

    result = cli.run_generation(source=source, out=StringIO(), publish=publish)
    assert result == 1


def test_publish_requires_tty_two_exact_confirmations_and_dispatches_actual_operation(monkeypatch):
    selected, metadata, config = _fixture()
    calls = []
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    monkeypatch.setattr(
        cli, "publish_selected_bootstrap_generation",
        lambda **kwargs: calls.append(kwargs),
    )
    output = StringIO()
    monkeypatch.setattr(sys, "stdin", FakeInput(_publish_bytes(metadata, config, selected), tty=True))
    monkeypatch.setattr(sys, "stdout", output)

    assert cli.main(["generation-publish"]) == 0
    assert len(calls) == 1
    assert calls[0] == {
        "metadata": metadata,
        "config": config,
        "confirmed_digest": _selected_digest(metadata, config, selected),
        "confirmed_publish": True,
    }
    assert "Enter canonical" in output.getvalue()
    assert "Type PUBLISH" in output.getvalue()


@pytest.mark.parametrize("phase", ["preview-reread", "publication-reread"])
def test_changed_selection_between_preview_and_publication_refuses(monkeypatch, phase):
    selected, metadata, config = _fixture()
    changed = replace(
        selected,
        context=replace(selected.context, approval_id="33333333-3333-4333-8333-333333333333"),
    )
    if phase == "preview-reread":
        values = iter((selected, changed))
        monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: next(values))
        input_data = _preview_bytes(metadata, config)
    else:
        monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
        monkeypatch.setattr(provisioning, "load_declared_bootstrap_context", lambda: changed)
        input_data = _publish_bytes(metadata, config, selected)

    assert cli.run_generation(
        source=FakeInput(input_data, tty=phase == "publication-reread"),
        out=StringIO(), publish=phase == "publication-reread",
    ) == 1


def test_actual_cli_publisher_reader_integration_uses_only_private_temp_store(
    tmp_path, monkeypatch,
):
    selected, metadata, config = _fixture()
    context = selected.context
    root = tmp_path / "generation-store"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    monkeypatch.setattr(provisioning, "load_declared_bootstrap_context", lambda: selected)
    _patch_public_store(monkeypatch, root)

    monkeypatch.setattr(sys, "stdin", FakeInput(_publish_bytes(metadata, config, selected), tty=True))
    monkeypatch.setattr(sys, "stdout", StringIO())
    result = cli.main(["generation-publish"])

    assert result == 0
    assert _read_published(root, context).number == context.generation


def test_nonterminal_publication_refuses_before_reading_or_inspecting_host(monkeypatch):
    class Pipe:
        def isatty(self):
            return False

        @property
        def buffer(self):
            pytest.fail("refused publication read input")

    monkeypatch.setattr(cli, "load_declared_bootstrap_context",
                        lambda: pytest.fail("refused publication inspected host"))
    assert cli.run_generation(source=Pipe(), out=StringIO(), publish=True) == 1


def test_durability_uncertainty_returns_exit_two(monkeypatch):
    selected, metadata, config = _fixture()
    monkeypatch.setattr(cli, "load_declared_bootstrap_context", lambda: selected)
    monkeypatch.setattr(
        cli, "publish_selected_bootstrap_generation",
        lambda **_kwargs: (_ for _ in ()).throw(
            BootstrapGenerationDurabilityUncertain("synthetic uncertainty")
        ),
    )
    output = StringIO()

    result = cli.run_generation(
        source=FakeInput(_publish_bytes(metadata, config, selected), tty=True),
        out=output, publish=True,
    )

    assert result == 2
    assert "durability UNCONFIRMED" in output.getvalue()


def test_cli_refuses_wrong_operation_type_without_publication():
    selected, metadata, config = _fixture()
    result = cli.run_generation(
        source=FakeInput(_preview_bytes(metadata, config), tty=False),
        out=StringIO(), publish=1,
    )
    assert result == 1


def test_package_observation_outputs_digest_only_and_is_not_admission(monkeypatch):
    snapshot = debian_packages.parse_package_output(
        b"dpkg\t1.22.22\tarm64\tii \nsecret-package\t1.0\tarm64\tii \n"
    )
    monkeypatch.setattr(cli, "observe_installed_packages", lambda: snapshot)
    output = StringIO()

    assert cli.run_package_observation(out=output) == 0
    text = output.getvalue()
    assert "Native architecture: arm64" in text
    assert "Installed package records: 2" in text
    assert snapshot.digest in text
    assert "secret-package" not in text
    assert "not package authenticity" in text


def test_actual_cli_dispatches_read_only_package_observation(monkeypatch):
    snapshot = debian_packages.parse_package_output(b"dpkg\t1.22.22\tarm64\tii \n")
    monkeypatch.setattr(cli, "observe_installed_packages", lambda: snapshot)
    output = StringIO()
    monkeypatch.setattr(sys, "stdout", output)

    assert cli.main(["observe-packages"]) == 0
    assert snapshot.digest in output.getvalue()
    assert "Native architecture: arm64" in output.getvalue()


def test_package_observation_refusal_emits_no_inventory(monkeypatch):
    monkeypatch.setattr(
        cli, "observe_installed_packages",
        lambda: (_ for _ in ()).throw(debian_packages.PackageObservationRefused("secret detail")),
    )
    output = StringIO()

    assert cli.run_package_observation(out=output) == 1
    assert output.getvalue() == "Package observation refused; no package inventory was emitted.\n"
    assert "secret detail" not in output.getvalue()
