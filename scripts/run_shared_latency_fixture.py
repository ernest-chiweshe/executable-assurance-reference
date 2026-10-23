"""Run the unchanged benchmark with explicitly selected isolated fixture wiring."""
import os,sys,runpy
from pathlib import Path
root=Path(__file__).resolve().parents[1]
if not os.environ.get('REFERENCE_ISOLATED_PG_DATA'):raise SystemExit('isolated PostgreSQL required')
os.environ['REFERENCE_SHARED_EVIDENCE_FIXTURE']='1'
sys.path.insert(0,str(root/'tests'))
runpy.run_path(str(root/'scripts/bench_governed_latency.py'),run_name='__main__')
