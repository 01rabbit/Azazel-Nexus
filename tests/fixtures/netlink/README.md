# Captured netlink responses

`rtm_getlink_dump.bin` is a real `RTM_GETLINK` dump, captured once from the
container this repository was developed in. It is here so the parser can be
exercised deterministically: parsing is the half of `az-commissiond` that CI
can establish, and reading from a live socket is the half it cannot.

What this fixture is evidence for: the parser handles the shape a Linux
kernel actually produces, including a mixture of interfaces that carry
`IFLA_PERM_ADDRESS` and interfaces that do not — the capture contains both.

What it is **not** evidence for: that a permanent MAC can be read on the
target hardware. That is `HG-04` in `docs/hardware-gates.md`, it stays open,
and a capture from one virtualised NIC does not touch it.

The negative cases beside it are constructed rather than captured. A kernel
does not emit a truncated attribute on request, and the parser has to refuse
one anyway.
