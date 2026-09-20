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

Nothing here listens on a network. Every daemon speaks over a Unix domain
socket and identifies its callers from the operating system's peer
credentials — never from anything a caller says about itself.
