"""Runtime adapter seams; no host interface change or production enrollment."""

import pytest

from azazel_nexus_runtime import commission_cli
from azazel_nexus_runtime.netlink import LinkRecord, NetlinkMalformed, NetlinkUnavailable


def _records(mac="02:00:00:00:00:01"):
    return (LinkRecord(1, "synthetic0", mac),)


def test_reader_uses_permanent_address_and_detects_changes(monkeypatch):
    batches = iter((_records(), _records(), _records("02:00:00:00:00:02")))
    monkeypatch.setattr(commission_cli, "read_links", lambda: next(batches))
    reader = commission_cli._PermanentAddresses()
    assert reader("synthetic0") == "02:00:00:00:00:01"
    assert reader("missing") is None
    assert reader.unchanged()
    assert not reader.unchanged()


def test_missing_permanent_address_has_no_current_mac_fallback(monkeypatch):
    monkeypatch.setattr(commission_cli, "read_links", lambda: (LinkRecord(1, "synthetic0", None, "missing"),))
    assert commission_cli._PermanentAddresses()("synthetic0") is None


def test_duplicate_kernel_identity_is_refused(monkeypatch):
    monkeypatch.setattr(commission_cli, "read_links", lambda: _records() * 2)
    with pytest.raises(NetlinkUnavailable):
        commission_cli._PermanentAddresses()("synthetic0")


@pytest.mark.parametrize("argv", [[], ["status"], ["--sysfs", "/tmp/fake", "commission"]])
def test_disallowed_commands_do_not_collect(monkeypatch, argv):
    def forbidden():
        raise AssertionError("unexpected kernel read")
    monkeypatch.setattr(commission_cli, "read_links", forbidden)
    assert commission_cli.main(argv) == 2


def test_help_does_not_collect(monkeypatch):
    monkeypatch.setattr(commission_cli, "read_links", lambda: pytest.fail("kernel read"))
    assert commission_cli.main(["--help"]) == 0


def test_noninteractive_commission_is_refused(monkeypatch):
    monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: False)
    assert commission_cli.main(["commission"]) == 1


@pytest.mark.parametrize("changed", [False, True])
def test_review_success_is_buffered_until_inventory_recheck(monkeypatch, capsys, changed):
    batches = iter((_records(), _records("02:00:00:00:00:02") if changed else _records()))
    monkeypatch.setattr(commission_cli, "read_links", lambda: next(batches))
    def library(args, *, out, permanent_mac_reader, **kwargs):
        assert permanent_mac_reader("synthetic0")
        print("assigned bindings verified", file=out)
        return 0
    monkeypatch.setattr(commission_cli, "library_main", library)
    assert commission_cli.main(["commission-review", "--operator", "operator-a"]) == (1 if changed else 0)
    output = capsys.readouterr()
    assert ("assigned bindings verified" in output.out) is not changed


def test_confirmation_uses_explicit_answer_and_fresh_kernel_state(monkeypatch):
    monkeypatch.setattr(commission_cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(commission_cli.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(commission_cli, "read_links", _records)
    answers = iter(("observation", "CONFIRM"))
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    def library(args, *, ask, confirm, permanent_mac_reader, **kwargs):
        assert permanent_mac_reader("synthetic0")
        assert ask("pick", ("skip", "observation")) == "observation"
        assert confirm("selected set")
        return 0
    monkeypatch.setattr(commission_cli, "library_main", library)
    assert commission_cli.main(["commission"]) == 0


@pytest.mark.parametrize("final_read", [False, True])
def test_malformed_kernel_data_is_redacted_and_never_reports_success(monkeypatch, capsys, final_read):
    calls = 0

    def read():
        nonlocal calls
        calls += 1
        if not final_read or calls == 2:
            raise NetlinkMalformed("private-kernel-payload")
        return _records()

    def library(args, *, out, permanent_mac_reader, **kwargs):
        permanent_mac_reader("synthetic0")
        print("assigned bindings verified", file=out)
        return 0

    monkeypatch.setattr(commission_cli, "read_links", read)
    monkeypatch.setattr(commission_cli, "library_main", library)
    assert commission_cli.main(["commission-review", "--operator", "operator-a"]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "private-kernel-payload" not in output.err
    assert "Commissioning stopped" in output.err
