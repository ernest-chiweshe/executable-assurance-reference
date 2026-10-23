"""Test-only import path for retained frozen care parser; no runtime package change."""
from pathlib import Path
import factory

_ROOT = Path(__file__).resolve().parents[2]
_ORIGINALS = _ROOT / "docs/provenance/operator-policy/originals/factory"
assert (_ORIGINALS / "care/policy.py").is_file()
factory.__path__.append(str(_ORIGINALS))
