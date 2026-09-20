"""The OS service layer. Privileged, separated, and one-way dependent.

`azazel_nexus` holds the decisions; this package holds the ability to act on
them. The dependency runs one way and is checked both statically and by a CI
job that imports the library where this package is not installed.
"""
