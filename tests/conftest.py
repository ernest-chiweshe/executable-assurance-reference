"""Explicit provenance opt-in for full regression of a reviewed adaptation."""


def pytest_addoption(parser):
    parser.addoption("--source-adaptation-manifest", default=None,
                     help="Explicit relative source-adaptation manifest; default trace is strict")
    parser.addoption("--source-adaptation-sha256", default=None,
                     help="Independently supplied SHA256 of the explicit adaptation manifest")
