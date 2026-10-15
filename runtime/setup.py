"""Build the fixed Linux deadline backend against the target Python/ABI."""

from setuptools import Extension, setup


setup(ext_modules=[Extension(
    "azazel_nexus_runtime._bootstrap_deadline",
    sources=["src/azazel_nexus_runtime/_bootstrap_deadline.c"],
    libraries=["rt"],
)])
