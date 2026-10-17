import pytest

import azazel_nexus_runtime.runtime_paths as runtime_paths


@pytest.mark.parametrize(
    ("name", "leaf"),
    [
        ("audit", "audit"),
        ("commission", "commission"),
        ("watchdog", "watchdog"),
    ],
)
def test_socket_path_uses_the_installer_owned_service_leaf(tmp_path, monkeypatch, name, leaf):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)

    assert runtime_paths.socket_path(name) == (
        tmp_path / "var/lib/azazel/run" / leaf / f"{name}.sock"
    )
    assert not (tmp_path / "var/lib/azazel/run" / leaf).exists()


@pytest.mark.parametrize("name", ["unknown", "audit/other", "", None, []])
def test_socket_path_rejects_non_declared_names(name):
    with pytest.raises(ValueError, match="not declared"):
        runtime_paths.socket_path(name)


def test_service_audit_sinks_and_watchdog_state_use_private_installed_leaves(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    state_root = tmp_path / "var/lib/azazel/state"
    for service, leaf_name in (
        ("audit", "auditd"),
        ("commission", "commission"),
        ("watchdog", "watchdog"),
    ):
        leaf = state_root / leaf_name
        leaf.mkdir(parents=True)
        runtime_paths.audit_sink(service)({"service": service})
        assert (leaf / "refusals.jsonl").read_text(encoding="utf-8") == (
            f'{{"service":"{service}"}}\n'
        )

    assert runtime_paths.ledger_dir() == state_root / "audit"
    assert runtime_paths.watchdog_state_dir() == state_root / "watchdog"
    assert not (state_root / "audit" / "refusals.jsonl").exists()
    assert list(state_root.glob("refusals.jsonl")) == []


def test_service_audit_sink_rejects_undeclared_names():
    with pytest.raises(ValueError, match="not declared"):
        runtime_paths.audit_sink("activated")
