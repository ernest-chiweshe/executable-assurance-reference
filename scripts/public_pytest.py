"""Explicit public profile; preserve the private denominator and fail on drift."""
from pathlib import Path
import hashlib,json,sys,sysconfig
import pytest
ROOT=Path(__file__).resolve().parents[1]
MANIFEST=json.loads((ROOT/'PUBLIC-TEST-PARTITION.json').read_bytes())
ROWS={x['nodeid']:x for x in MANIFEST['tests']}

def pytest_addoption(parser):
    parser.addoption('--public-only',action='store_true',help='Run the enumerated public tests; report every private exclusion')
    parser.addoption('--public-shard',default=None,help='Optional disjoint index/count shard, e.g. 0/4')
    parser.addoption('--public-report',help='Write the exact public/private selection and installed import audit')

def pytest_ignore_collect(collection_path,config):
    if not config.getoption('--public-only'):return None
    try:relative=collection_path.relative_to(ROOT).as_posix()
    except ValueError:return None
    if relative in MANIFEST['collection_excluded_files']:return True

def pytest_collection_modifyitems(session,config,items):
    if not config.getoption('--public-only'):return
    ignored=set(MANIFEST['collection_excluded_files'])
    expected={n for n in ROWS if n.split('::')[0] not in ignored}
    actual={x.nodeid for x in items}
    if actual!=expected:raise pytest.UsageError('Public test collection differs from manifest: missing='+repr(sorted(expected-actual))+' extra='+repr(sorted(actual-expected)))
    for name,pin in MANIFEST['test_file_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=pin:raise pytest.UsageError('Test source pin differs: '+name)
    selected=[];excluded=[]
    for item in items:
        if ROWS[item.nodeid]['scope']=='private':excluded.append(item)
        else:selected.append(item)
    full_selected=list(selected)
    shard=config.getoption('--public-shard');other_shards=[]
    if shard:
        try:index,count=map(int,shard.split('/'))
        except ValueError:raise pytest.UsageError('Shard must be index/count')
        if not 0<=index<count or count>8:raise pytest.UsageError('Invalid shard bounds')
        selected=[x for x in full_selected if int(hashlib.sha256(x.nodeid.encode()).hexdigest(),16)%count==index]
        other_shards=[x for x in full_selected if x not in selected]
    items[:]=selected
    config.hook.pytest_deselected(items=excluded+other_shards)
    session.public_profile={'total':MANIFEST['total_tests'],'public_total':len(full_selected),'shard':shard,'other_shard_count':len(other_shards),'selected':len(selected),'private_excluded':MANIFEST['private_tests'],'uncollected_private':[n for n in ROWS if n.split('::')[0] in ignored],'excluded':[r for r in ROWS.values() if r['scope']=='private'],'selected_nodes':[x.nodeid for x in selected]}

def pytest_sessionfinish(session,exitstatus):
    if not session.config.getoption('--public-only'):return
    site=Path(sysconfig.get_paths()['purelib']).resolve();origins={};bad=[];historical={}
    for name,module in tuple(sys.modules.items()):
        if name.split('.')[0] in {'assurance_reference','regulated_core','factory'} and getattr(module,'__file__',None):
            path=Path(module.__file__).resolve();origins[name]=str(path)
            if not path.is_relative_to(site):
                fixture=MANIFEST.get('historical_fixture_modules',{}).get(name)
                if fixture and path==(ROOT/fixture['path']).resolve() and hashlib.sha256(path.read_bytes()).hexdigest()==fixture['sha256']:
                    historical[name]=str(path)
                else:bad.append(name)
    result=getattr(session,'public_profile',{'collection_failed':True})
    if bad:session.exitstatus=1
    result.update(exitstatus=int(session.exitstatus),module_origins=origins,unapproved_noninstalled_modules=bad,historical_fixture_modules=historical,site_packages=str(site))
    report=session.config.getoption('--public-report')
    if report:Path(report).write_text(json.dumps(result,indent=2)+'\n')

def pytest_terminal_summary(terminalreporter):
    if terminalreporter.config.getoption('--public-only'):
        terminalreporter.write_sep('=',f"Public profile: {MANIFEST['public_tests']} selected; {MANIFEST['private_tests']} declared private out of {MANIFEST['total_tests']}. Private cases are not passes.")
