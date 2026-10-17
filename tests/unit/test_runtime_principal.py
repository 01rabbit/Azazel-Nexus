"""Installation-owned service identity for the M.I.O. entry daemon."""

from types import SimpleNamespace

from azazel_nexus_runtime import principal


def test_entry_account_resolves_as_service_without_operator_elevation(monkeypatch):
    queried = []

    def account(name):
        queried.append(name)
        if name == "azmioentry":
            return SimpleNamespace(pw_uid=9002)
        raise KeyError(name)

    monkeypatch.setattr(principal.pwd, "getpwnam", account)
    monkeypatch.setattr(
        principal.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=9001)
    )
    policy = principal.PrincipalPolicy.resolve()
    assert "azmioentry" in queried
    assert policy.classify(9002, 9001, 42).classes == frozenset(
        {principal.PrincipalClass.SERVICE}
    )
