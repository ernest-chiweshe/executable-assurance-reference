"""Reference-authored package initializer (not the production file).

The production ``factory/public_fetch/__init__.py`` at 6bba989a re-exports the crawler, fetch service, artifact store
and projection, none of which this reference composes. Only the verbatim URL policy, contracts and drivers that the
governed HTTP delivery adapter imports are carried here (pinned in source-provenance.json).
"""
