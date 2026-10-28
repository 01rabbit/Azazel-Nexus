"""Fetch commissioning, fetch-only handoff, and the separate root importer."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from azazel_nexus import model_fetched_cli
from azazel_nexus_runtime import activated, model_fetch, model_fetchd, runtime_paths
from azazel_nexus_runtime.artifact_egress import EgressResult, Outcome
from test_model_acquire_e2e import boundaries, response, servers, setup  # noqa: F401
from test_model_import import COMMISSIONING, NOW, WEIGHTS, _write_catalog, trusted

from azazel_nexus.activation import ARTIFACT_TRANSPORT
from azazel_nexus.cli import main as cli
from azazel_nexus.model_catalog import artifact_filename
from azazel_nexus.model_import import ModelImport


@pytest.fixture
def commissioned(tmp_path, setup):  # noqa: F811 - imported pytest fixture
    scenario = setup()
    directory = tmp_path / "commission"
    directory.mkdir()
    (directory / "trust.json").write_text(json.dumps({
        "catalog_keys": {k: v.hex() for k, v in trusted().items()},
        "commissioning_digest": COMMISSIONING,
    }))
    from nacl.signing import SigningKey
    doc = json.loads((directory / "trust.json").read_text())
    doc["registry_keys"] = {"registry": bytes(SigningKey(b"r" * 32).verify_key).hex()}
    (directory / "trust.json").write_text(json.dumps(doc))
    (directory / "sources.signed").write_bytes((tmp_path / "registry").read_bytes())
    (directory / "catalog.signed").write_bytes(scenario.models.catalog_path.read_bytes())
    tls = Path(__file__).parents[1] / "fixtures/tls"
    for name, fixture in (("ca.pem", "trusted-ca.crt"), ("client.pem", "client.crt"),
                          ("client.key", "client.key")):
        (directory / name).write_bytes((tls / fixture).read_bytes())
    (directory / "addresses.json").write_text(json.dumps({"allowed_addresses": ["127.0.0.1", "::1"]}))
    (directory / "consent.json").write_text(json.dumps({
        "sources": ["vendor-primary"], "operator": "test-root", "at": NOW,
    }))
    return directory, scenario


def test_valid_commissioning(commissioned):
    directory, scenario = commissioned
    result = model_fetch.load_fetch_commissioning(directory)
    assert result.catalog.entry(scenario.entry.model_id) == scenario.entry
    assert result.allowed_addresses == ("127.0.0.1", "::1")
    assert result.consent.covers("vendor-primary")


@pytest.mark.parametrize("name", ["trust.json", "sources.signed", "catalog.signed", "ca.pem",
                                  "addresses.json", "consent.json"])
@pytest.mark.parametrize("bad", [None, b"secret-parser-sentinel", b"x" * (4 * 1024 * 1024 + 1)])
def test_required_files_fail_closed(commissioned, name, bad):
    directory, _ = commissioned
    if bad is None:
        (directory / name).unlink()
    else:
        (directory / name).write_bytes(bad)
    with pytest.raises(model_fetch.FetchNotCommissioned) as caught:
        model_fetch.load_fetch_commissioning(directory)
    assert any(name in item for item in caught.value.missing)
    assert "sentinel" not in str(caught.value)


@pytest.mark.parametrize("same_id", [False, True])
def test_shared_signing_key_refused(commissioned, same_id):
    directory, _ = commissioned
    path = directory / "trust.json"
    doc = json.loads(path.read_text())
    doc["registry_keys"] = {"catalog-key" if same_id else "other": next(iter(doc["catalog_keys"].values()))}
    path.write_text(json.dumps(doc))
    with pytest.raises(model_fetch.FetchNotCommissioned, match="trust.json"):
        model_fetch.load_fetch_commissioning(directory)


@pytest.mark.parametrize("values", [[], [123], ["hostname.test"], ["127.0.0.1"] * 257])
def test_addresses_are_bounded_literals(commissioned, values):
    directory, _ = commissioned
    (directory / "addresses.json").write_text(json.dumps({"allowed_addresses": values}))
    with pytest.raises(model_fetch.FetchNotCommissioned, match="addresses.json"):
        model_fetch.load_fetch_commissioning(directory)


@pytest.mark.parametrize("name", ["client.pem", "client.key"])
def test_client_pair_required(commissioned, name):
    directory, _ = commissioned
    (directory / name).unlink()
    with pytest.raises(model_fetch.FetchNotCommissioned, match=name):
        model_fetch.load_fetch_commissioning(directory)


def test_client_identity_optional(commissioned):
    directory, _ = commissioned
    (directory / "client.pem").unlink()
    (directory / "client.key").unlink()
    assert model_fetch.load_fetch_commissioning(directory).client_key is None


def test_activation_requires_valid_commissioning(commissioned, monkeypatch):
    directory, _ = commissioned
    monkeypatch.setattr(runtime_paths, "fetch_commission_dir", lambda: directory)
    assert ARTIFACT_TRANSPORT in activated.wired_capabilities()
    (directory / "consent.json").unlink()
    assert activated.wired_capabilities() == frozenset()


def test_uncommissioned_main(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    with pytest.raises(SystemExit, match="no transport wired.*trust.json"):
        model_fetchd.main([])


def test_main_composes_and_passes_hooks(commissioned, monkeypatch):
    directory, _scenario = commissioned
    from azazel_nexus_runtime import principal, serve
    monkeypatch.setattr(runtime_paths, "fetch_commission_dir", lambda: directory)
    monkeypatch.setattr(principal.PrincipalPolicy, "resolve", lambda: "test-policy")
    calls = []
    def serving(**options):
        assert options["policy"] == "test-policy"
        assert isinstance(options["handler"].__self__, model_fetchd.FetchService)
        assert options["path"] == runtime_paths.socket_path("fetch")
        options["ready"]()
        assert options["stop"]()
        calls.append(options)
        return 0
    monkeypatch.setattr(serve, "serve_forever", serving)
    stopped = []
    assert model_fetchd.main([], ready=lambda: stopped.append(True), stop=lambda: bool(stopped)) == 0
    assert calls


@pytest.mark.parametrize("real_tls", [False, True])
def test_ready_handoff(setup, servers, tmp_path, real_tls):  # noqa: F811
    scenario = setup(servers(response(WEIGHTS)) if real_tls else None)
    ready = tmp_path / "ready"
    def transport(**kwargs):
        kwargs["sink"](WEIGHTS)
        return EgressResult(Outcome.COMPLETE, len(WEIGHTS), 200, "complete")
    options = {"handoff": "ready", "ready_dir": ready, "models": None,
               "catalog": scenario.models.catalog()}
    if not real_tls:
        options["transport"] = transport
    reply = scenario.service(**options).handle(scenario.request())
    assert reply["outcome"] == "fetched"
    assert reply["retained"] == "ready" and reply["admitted"] is False
    assert "model-import-fetched " + scenario.entry.model_id in reply["offline_import"]
    assert (ready / artifact_filename(scenario.entry)).read_bytes() == WEIGHTS
    assert not list(scenario.models.store.glob("*"))
    assert ModelImport(scenario.models).current_generation() is None


@pytest.mark.parametrize("outcome", [Outcome.INTERRUPTED, Outcome.TIMED_OUT, Outcome.REFUSED])
def test_failed_fetch_never_ready(setup, tmp_path, outcome):  # noqa: F811
    scenario = setup()
    ready = tmp_path / "ready"
    def transport(**kwargs):
        return EgressResult(outcome, 0, 200, "test")
    reply = scenario.service(handoff="ready", ready_dir=ready, models=None,
                             catalog=scenario.models.catalog(), transport=transport).handle(scenario.request())
    assert reply["outcome"] != "fetched"
    assert not list(ready.glob("*"))


@pytest.fixture
def cli_ready(tmp_path, monkeypatch, setup, private_os):  # noqa: F811
    private_os(model_fetched_cli)
    import os

    from azazel_nexus.model_paths import fetch_ready_dir, models_root
    monkeypatch.setenv("AZAZEL_ROOT", str(tmp_path))
    monkeypatch.setattr(model_fetched_cli.os, "geteuid", lambda: 0)
    scenario = setup()
    root = models_root()
    root.mkdir(parents=True)
    _write_catalog(root, [scenario.entry])
    (root / "trust/trust.json").write_text(json.dumps({
        "catalog_keys": {k: v.hex() for k, v in trusted().items()},
        "commissioning_digest": COMMISSIONING,
    }))
    ready = fetch_ready_dir()
    ready.mkdir(parents=True)
    path = ready / artifact_filename(scenario.entry)
    path.write_bytes(WEIGHTS)
    return SimpleNamespace(root=root, path=path, entry=scenario.entry)


def test_cli_promotes(cli_ready):
    from io import StringIO

    from azazel_nexus.model_import import CommissionedModels
    output = StringIO()
    assert cli(["model-import-fetched", cli_ready.entry.model_id], out=output) == 0
    assert output.getvalue() == "promoted\n"
    assert not cli_ready.path.exists()
    assert (cli_ready.root / "store" / artifact_filename(cli_ready.entry)).read_bytes() == WEIGHTS
    models = CommissionedModels(cli_ready.root, trusted(), COMMISSIONING)
    assert ModelImport(models).current_generation().installed[cli_ready.entry.model_id] == cli_ready.entry.digest


def test_cli_tampered_quarantined(cli_ready):
    from io import StringIO
    cli_ready.path.write_bytes(b"x" * len(WEIGHTS))
    output = StringIO()
    assert cli(["model-import-fetched", cli_ready.entry.model_id], out=output) == 1
    assert "digest" in output.getvalue()
    assert output.getvalue().startswith("refused:")
    assert cli_ready.path.exists()
    assert list((cli_ready.root / "quarantine").glob("*.held"))
    assert not list((cli_ready.root / "store").glob("*"))


def test_cli_requires_root(cli_ready, monkeypatch):
    import os
    from io import StringIO
    monkeypatch.setattr(model_fetched_cli.os, "geteuid", lambda: 123)
    output = StringIO()
    assert cli(["model-import-fetched", cli_ready.entry.model_id], out=output) == 1
    assert "root_required" in output.getvalue()
    assert cli_ready.path.exists()


def test_cli_requires_ready(cli_ready):
    from io import StringIO
    cli_ready.path.unlink()
    output = StringIO()
    assert cli(["model-import-fetched", cli_ready.entry.model_id], out=output) == 1
    assert "ready_absent" in output.getvalue()


def test_main_socket_hooks(commissioned, monkeypatch):
    import tempfile

    from azazel_nexus_runtime import principal

    from azazel_nexus.layout import create_layout

    directory, _ = commissioned
    with tempfile.TemporaryDirectory(prefix="azf-", dir="/tmp") as short:
        root = Path(short)
        create_layout(root)
        monkeypatch.setattr(runtime_paths, "ROOT", root)
        monkeypatch.setattr(runtime_paths, "fetch_commission_dir", lambda: directory)
        monkeypatch.setattr(principal.PrincipalPolicy, "resolve", lambda: principal.PrincipalPolicy(None, frozenset()))
        stopped = []
        assert model_fetchd.main([], ready=lambda: stopped.append(True), stop=lambda: bool(stopped)) == 0
        assert stopped
        assert not runtime_paths.socket_path("fetch").exists()


def test_fetch_paths_honor_runtime_root(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime_paths, "ROOT", tmp_path)
    assert runtime_paths.models_root() == tmp_path / "var/lib/azazel/models"
    assert runtime_paths.fetch_dir() == tmp_path / "var/lib/azazel/fetch"
    assert runtime_paths.fetch_commission_dir() == runtime_paths.fetch_dir() / "commission"
    assert runtime_paths.fetch_partial_dir() == runtime_paths.fetch_dir() / "partial"
    assert runtime_paths.fetch_ready_dir() == runtime_paths.fetch_dir() / "ready"
    assert runtime_paths.socket_path("fetch") == tmp_path / "var/lib/azazel/run/fetch/fetch.sock"


def test_fetch_layout_ownership():
    from azazel_nexus.layout import spec_for
    expected = {
        "/var/lib/azazel/models": ("root", "azmio"),
        "/var/lib/azazel/fetch/commission": ("root", "azfetch"),
        "/var/lib/azazel/fetch/partial": ("azfetch", "azfetch"),
        "/var/lib/azazel/fetch/ready": ("azfetch", "azfetch"),
    }
    for path, (owner, group) in expected.items():
        spec = spec_for(path)
        assert (spec.owner, spec.group, spec.mode) == (owner, group, 0o750)


@pytest.mark.parametrize("name", ["client.pem", "client.key"])
def test_invalid_client_identity(commissioned, name):
    directory, _ = commissioned
    (directory / name).write_bytes(b"invalid-private-sentinel")
    with pytest.raises(model_fetch.FetchNotCommissioned) as caught:
        model_fetch.load_fetch_commissioning(directory)
    assert any(name in item for item in caught.value.missing)
    assert "sentinel" not in str(caught.value)


@pytest.mark.parametrize("at", ["yesterday", "2026-01-01", "2026-01-01T00:00:00", "2026-99-01T00:00:00Z"])
def test_consent_requires_rfc3339(commissioned, at):
    directory, _ = commissioned
    path = directory / "consent.json"
    doc = json.loads(path.read_text())
    doc["at"] = at
    path.write_text(json.dumps(doc))
    with pytest.raises(model_fetch.FetchNotCommissioned, match="consent.json"):
        model_fetch.load_fetch_commissioning(directory)


@pytest.mark.parametrize("change", ["size", "mtime", "inode", "optional", "dangling"])
def test_activation_caches_validation_and_notices_changes(commissioned, monkeypatch, change):
    import os

    directory, _ = commissioned
    monkeypatch.setattr(runtime_paths, "fetch_commission_dir", lambda: directory)
    monkeypatch.setattr(activated, "_fetch_validation_cache", None)
    if change in ("optional", "dangling"):
        (directory / "client.pem").unlink()
        (directory / "client.key").unlink()
    original = model_fetch.load_fetch_commissioning
    calls = []

    def load(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(model_fetch, "load_fetch_commissioning", load)
    assert ARTIFACT_TRANSPORT in activated.wired_capabilities()
    assert ARTIFACT_TRANSPORT in activated.wired_capabilities()
    assert len(calls) == 1
    path = directory / "consent.json"
    info = path.stat()
    if change == "size":
        path.write_text("invalid-longer-document")
    elif change == "mtime":
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000))
    elif change == "inode":
        replacement = directory / "replacement"
        replacement.write_bytes(path.read_bytes())
        os.utime(replacement, ns=(info.st_atime_ns, info.st_mtime_ns))
        replacement.replace(path)
    elif change == "optional":
        (directory / "client.key").write_text("invalid")
    else:
        (directory / "client.key").symlink_to(directory / "missing-key")
    wired = ARTIFACT_TRANSPORT in activated.wired_capabilities()
    assert wired == (change in ("mtime", "inode"))
    assert len(calls) == 2
    assert (ARTIFACT_TRANSPORT in activated.wired_capabilities()) == wired
    assert len(calls) == 2


def test_activation_fails_closed_on_stat_error(commissioned, monkeypatch):
    directory, _ = commissioned
    monkeypatch.setattr(runtime_paths, "fetch_commission_dir", lambda: directory)
    assert ARTIFACT_TRANSPORT in activated.wired_capabilities()
    original = Path.stat

    def stat(path, *args, **kwargs):
        if path == directory / "consent.json":
            raise PermissionError("sentinel")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", stat)
    assert ARTIFACT_TRANSPORT not in activated.wired_capabilities()
    assert activated._fetch_validation_cache is None


def test_activation_refuses_files_changed_during_validation(commissioned, monkeypatch):
    directory, _ = commissioned
    monkeypatch.setattr(runtime_paths, "fetch_commission_dir", lambda: directory)
    monkeypatch.setattr(activated, "_fetch_validation_cache", None)
    original = model_fetch.load_fetch_commissioning

    def load(path):
        result = original(path)
        (path / "consent.json").write_text("invalid-after-validation")
        return result

    monkeypatch.setattr(model_fetch, "load_fetch_commissioning", load)
    assert ARTIFACT_TRANSPORT not in activated.wired_capabilities()
    assert activated._fetch_validation_cache is None
