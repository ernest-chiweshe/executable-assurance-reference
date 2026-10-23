"""Attempt-local dependency collection for composed namespace adapters."""
from contextvars import ContextVar
from contextlib import contextmanager
from .evidence_publication import Dependency
from .evidence_service import EvidenceError

_current=ContextVar('evidence_dependencies',default=None)

@contextmanager
def collect_dependencies():
    found=[];token=_current.set(found)
    try:yield found
    finally:_current.reset(token)

def observe(scope,snapshot,kind='read'):
    found=_current.get()
    if found is None:return
    dep=Dependency(scope,snapshot.version,snapshot.tree_root,snapshot.state_root,kind)
    if dep not in found:
        if len(found)>=256:raise EvidenceError('dependency limit exceeded')
        found.append(dep)
