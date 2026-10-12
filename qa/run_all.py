"""Run all QA layers, save UTF-8 logs and generate report. Non-zero exit = failed acceptance tests."""
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'qa/results'
OUT.mkdir(parents=True,exist_ok=True)
env=dict(os.environ,PYTHONIOENCODING='utf-8')
codes=[]
for script,log in [('run_extended.py','extended-run.log'),('run_browser.py','browser-run.log'),
                   ('semantic_robustness.py','semantic-offline.log'),('semantic_safety.py','semantic-safety.log')]:
    print('Running',script,flush=True)
    with (OUT/log).open('w',encoding='utf8') as out:
        p=subprocess.run([sys.executable,str(ROOT/'qa'/script)],cwd=ROOT,env=env,stdout=out,stderr=subprocess.STDOUT)
    codes.append(p.returncode)
    print(script,'exit',p.returncode,flush=True)
# Update the evidence snapshot after each complete run, not on report-only rebuilds.
import shutil,json
baseline_status=json.loads((OUT/'baseline-status.json').read_text(encoding='utf8')) if (OUT/'baseline-status.json').exists() else {'missing':1}
if not baseline_status.get('baseline-eval',1) and (ROOT/'eval/report.json').exists():shutil.copyfile(ROOT/'eval/report.json',OUT/'baseline-eval.json')
codes.extend(baseline_status.values())
subprocess.run([sys.executable,str(ROOT/'qa/build_report.py')],cwd=ROOT,env=env,check=True)
import json
evaluation=json.loads((OUT/'baseline-eval.json').read_text(encoding='utf8'))
eval_failed=any(r.get('status')!='PASS' for c in evaluation['configs'] for r in c['runs'])
sys.exit(int(any(codes) or eval_failed))
