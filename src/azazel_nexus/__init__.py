"""AZ-07 Nexus Gateway.

Nexus integrates. It does not decide and it does not enforce: Azazel-Edge's
deterministic arbiter holds the only decision and enforcement authority, in
every capability state.

`CORE`, `LITE` and `FULL` are capability states, not authority levels.
Degrading to `CORE` removes capabilities; it never moves authority, and
restoring one never grants any.
"""

__all__ = ["__version__"]

__version__ = "0.0.1.dev0"
