# azazel-nexus-runtime

The OS service layer for Azazel-Nexus.

`azazel_nexus` holds what the node decides: state, contracts, the audit model,
and the refusals that make them checkable. It imports nothing that can spawn a
process, open a socket, or touch host storage, and a static scan enforces that
against its source. That is not a limitation of the library — it is why its
decisions can be tested at all.

This distribution is where the privileged half lives: Unix domain sockets,
netlink reads, and systemd operations. The dependency runs one way. The library
never imports this package, and CI proves it by importing the library in a job
where this package is not installed.

Nothing here listens on a network. Daemons that serve clients use Unix domain
sockets and identify callers from operating-system peer credentials. The
activation oneshot is different: it calls only the systemd system bus through
the fixed D-Bus method table in `systemd_bus.py`; it never starts a unit. Its
production composition supplies no authenticated admission evidence yet, so
it withholds all governed services and records that decision rather than
assuming readiness. Its `state/activation.jsonl` is a local controller ledger,
not the `az-auditd` segmented shared chain; it is neither signed nor anchored.
