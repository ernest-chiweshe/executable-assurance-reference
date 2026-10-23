"""Run packaged tests against installed runtime modules, never an editable source tree."""
from pathlib import Path
import os,sys,sysconfig

def main():
    root=Path(__file__).resolve().parents[1]
    os.environ.pop('PYTHONPATH',None)
    site=Path(sysconfig.get_paths()['purelib']).resolve()
    import assurance_reference,regulated_core,factory
    for module in (assurance_reference,regulated_core,factory):
        if not Path(module.__file__).resolve().is_relative_to(site):
            raise RuntimeError('Runtime must be installed in this interpreter environment')
    os.chdir(root)
    sys.path.insert(0,str(root/'scripts'))
    import pytest
    return pytest.main(['tests','-p','public_pytest','--public-only','-p','no:cacheprovider',*sys.argv[1:]])

if __name__ == '__main__':
    raise SystemExit(main())
