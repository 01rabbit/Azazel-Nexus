"""Service identity is granted by each daemon policy."""

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
    policy = principal.PrincipalPolicy.resolve(service_accounts=("azmioentry", "azarbiter"))
    assert "azmioentry" in queried
    assert policy.classify(9002, 9001, 42).classes == frozenset(
        {principal.PrincipalClass.SERVICE}
    )


def test_default_audit_and_fetch_policy_does_not_admit_entry_service(monkeypatch):
    import pytest
    from azazel_nexus_runtime import auditd, model_fetchd
    from azazel_nexus_runtime.protocol import RequestRefused

    def account(name):
        if name == "azmioentry":
            return SimpleNamespace(pw_uid=9002)
        raise KeyError(name)

    monkeypatch.setattr(principal.pwd, "getpwnam", account)
    monkeypatch.setattr(principal.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=9001))
    # Both daemons use resolve() without an explicit service_accounts override.
    policy = principal.PrincipalPolicy.resolve()
    caller = policy.classify(9002, 9002, 42)
    assert principal.PrincipalClass.SERVICE not in caller.classes
    for registry, verb in ((auditd.REGISTRY, "audit.append"),
                           (model_fetchd.REGISTRY, "model.fetch")):
        with pytest.raises(RequestRefused):
            registry.resolve(verb, caller)
