"""Requirement-focused semantic tests. Text perturbations are NOT an accent-recognition benchmark.

Offline: python qa/semantic_robustness.py
Live, synthetic customers only: python qa/semantic_robustness.py --live
"""
import argparse
import base64
import collections
import datetime
from decimal import Decimal
import json
from pathlib import Path
import re
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / 'qa/results'
TARGETS = {'Chen Mei Ling':'p_daughter', 'Chen Zhi Qiang':'p_son', 'Chen Wei':'p_grandson_wei',
           'SP Group Utilities':'p_sp', 'DBS Group Holdings shares':'s_d05', 'DBS Income Fund':'f_income',
           'Joint Account':'own:JNT-003', 'Current Account':'own:CUR-002'}


def card_fields(card):
    """UI cards expose formatted SGD and source account ID, not the internal draft schema."""
    return {'payee_id': TARGETS.get(card.get('payee_name')),
            'amount_cents': int(Decimal(card['amount'].replace('S$', '').replace(',', '')) * 100),
            'from_account': card.get('from_account_id')}


def step(payee, cents, account='SAV-001'):
    return {'payee_id': payee, 'amount_cents': cents, 'from_account': account}


CASES = []
def add(id, group, text, expected=None, *, turns=None, clarify=False, unsupported=False, live=False):
    CASES.append(dict(id=id, group=group, turns=turns or [text], expected=expected or [],
                      clarify=clarify, unsupported=unsupported, live=live))


for id, text, cents in [
    ('C01', 'Send a grand to my daughter', 100000),
    ('C02', 'Send two grand to my daughter', 200000),
    ('C03', 'Send 1.5k to my daughter', 150000),
    ('C04', 'Send five hundred bucks to my daughter', 50000),
    ('C05', 'Send half a grand to my daughter', 50000),
    ('C06', 'Send a couple of hundred dollars to my daughter', 20000),
    ('C07', 'Send a hundred and fifty to my daughter', 15000),
    ('C08', 'Send twenty dollars and fifty cents to my daughter', 2050),
]: add(id, 'colloquial_amounts', text, [step('p_daughter', cents)], live=id in ('C01','C03','C05','C06'))

for id,text,target,amount in [
    ('S01','Wire 50 to my girl','p_daughter',5000),
    ('S02','Remit 50 to Chen Mei Ling','p_daughter',5000),
    ('S03','Move 50 to my daughter','p_daughter',5000),
    ('S04','PayNow 50 to my daughter','p_daughter',5000),
    ('S05','Settle the water and electricity for me','p_sp',8640),
    ('S06','Buy 200 dollars of DBS stock','s_d05',20000),
]: add(id,'synonyms',text,[step(target,amount)],live=id in ('S02','S03','S04'))

for id,text,target,amount in [
    ('A01','Ah, send ah girl two hundred lah, can?','p_daughter',20000),
    ('A02','Transfer fifty to Mei Ling, can or not?','p_daughter',5000),
    ('A03','Um I want to send er fifty dollars to my daughter please','p_daughter',5000),
    ('A04','Send fivety dollars to my daughter','p_daughter',5000),
    ('A05','Send two hundread dollars to my daughter','p_daughter',20000),
    ('A06','Buy 200 dollars of D B S shares','s_d05',20000),
    ('A07','Send 50 to Chen Way','p_grandson_wei',5000),
]: add(id,'speech_transcript_variants',text,[step(target,amount)],live=id in ('A01','A06'))

# Money/name recognition errors need clarification, not an unsafe fuzzy match.
# Preserve the old exact-match expectations in semantic-before-*.json for comparison.
for case in CASES:
    if case['id'] in ('A04', 'A05', 'A07'):
        case.update(clarify=True, expected=[])

add('A08','speech_transcript_variants','Send fifteen or fifty to my daughter',clarify=True,live=True)
add('A09','speech_transcript_variants','Send 50 to my grandson',clarify=True)
add('A10','speech_transcript_variants','Send 50 to Mei',clarify=True)

add('T01','context_correction','', [step('p_daughter',20000)],
    turns=['Send money to my daughter','The usual amount'])
add('T02','context_correction','', [step('p_daughter',20000)],
    turns=['How much did I send my daughter last time?','Send her the same again'])
add('T03','context_correction','', [step('p_daughter',10000)],
    turns=['Send 200 to my daughter','Actually make that 100'],live=True)
add('T04','context_correction','', [step('p_daughter',20000)],
    turns=['Send 50 to my daughter','No, make it two hundred'])
add('T05','context_correction','Send two thousand no two hundred to my daughter',[step('p_daughter',20000)],live=True)
add('T06','context_correction','Transfer fifty from my current account to my daughter',[step('p_daughter',5000,'CUR-002')])

add('M01','multi_step','Pay the electricity bill then send 50 to my daughter',
    [step('p_sp',8640),step('p_daughter',5000)])
add('M02','multi_step','Send 200 to my daughter and then buy DBS shares for half that amount',
    [step('p_daughter',20000),step('s_d05',10000)],live=True)
add('M03','multi_step','Send a grand to my daughter and then buy DBS shares for half that amount',
    [step('p_daughter',100000),step('s_d05',50000)])
add('M04','multi_step','Buy DBS shares with half of 1000 dollars',[step('s_d05',50000)],live=True)
add('M05','multi_step','Send 200 to my daughter then send half as much to my son',
    [step('p_daughter',20000),step('p_son',10000)],live=True)
add('M06','multi_step','Send 50 to my son and daughter each',
    [step('p_son',5000),step('p_daughter',5000)])
add('M07','multi_step','Pay the electricity bill then send 50 to my daughter then invest 100 in income fund',
    [step('p_sp',8640),step('p_daughter',5000),step('f_income',10000)])
add('M08','multi_step','Send 50 to my daughter and then buy 100 dollars of DBS shares from my current account',
    [step('p_daughter',5000),step('s_d05',10000,'CUR-002')])
add('M09','multi_step','Buy DBS shares with half of it',clarify=True,live=True)
add('U01','requirement_example',
    'Move a grand to my joint account and then buy DBS shares with half of it',
    [step('own:JNT-003',100000),step('s_d05',50000,'JNT-003')],live=True)
add('U02','requirement_example',
    'Transfer 1000 from my savings account to my current account then buy DBS shares with half of it',
    [step('own:CUR-002',100000),step('s_d05',50000,'CUR-002')])


class Offline:
    def __init__(self):
        from qa import run_extended as q
        self.q = q
        self.w = q.World()
    def say(self,text):
        r=self.w.say(text)
        return {'reply':r.reply,'ui':r.ui,'phase':self.w.s.phase.value,'llm':r.llm,'trace':r.trace}
    def balance(self):
        return sum(a['balance_cents'] for a in self.w.bank.accounts(self.w.s.user_id))
    def accounts(self):
        return {a['account_id']:a['balance_cents'] for a in self.w.bank.accounts(self.w.s.user_id)}
    def queue(self):return list(self.w.s.plan)
    def pay(self,card):
        from app.agent.presenter import receipt_text
        s=self.w.s;d=s.current_draft
        self.w.kernel.register_key(s,self.w.pub)
        if s.phase==self.q.Phase.COOLING:
            d.cooling_until=time.time()-1  # isolated fixture: simulate elapsed cooldown, never change live service
        from app.kernel.contract import secondary_required
        if secondary_required(d.card_fields(), self.w.bank):
            # Only called after the semantic test has checked every field; isolated operator fixture.
            self.w.kernel.approve_secondary(s, d.draft_id, d.digest)
        receipt=self.w.pay()
        s.messages.append({'role':'assistant','content':receipt_text(d,receipt)})
        s.settle()
        return s.plan.pop(0) if s.plan else None


class Live:
    def __init__(self):
        import requests
        self.http=requests.Session();self.base='http://localhost:8000'
        self.sid=self.req('/api/reset',{'visitor':uuid.uuid4().hex[:16]})['session_id']
    def req(self,path,body=None):
        r=self.http.post(self.base+path,json=body,timeout=150) if body is not None else self.http.get(self.base+path,timeout=15)
        r.raise_for_status();return r.json()
    def say(self,text):return self.req('/api/chat',{'session_id':self.sid,'text':text})
    def balance(self):return sum(a['balance_cents'] for a in self.req('/api/state?session_id='+self.sid)['accounts'])
    def accounts(self):return {a['account_id']:a['balance_cents'] for a in self.req('/api/state?session_id='+self.sid)['accounts']}
    def queue(self):return None
    def pay(self,card):
        from app.kernel import p256
        key,pub=p256.generate_keypair()
        self.req('/api/key',{'session_id':self.sid,'public_key':pub})
        # Live cases only execute a correct first, low/medium-risk synthetic transfer. Never skip live cooling.
        ch=self.req('/api/challenge',{'session_id':self.sid,'draft_id':card['draft_id'],
                     'digest':card['digest'],'verify_answer':True})
        assertion={'payload':ch['payload'],'signature':base64.b64encode(p256.sign(key,ch['payload'].encode())).decode()}
        r=self.req('/api/confirm',{'session_id':self.sid,'draft_id':card['draft_id'],'digest':card['digest'],
                                'verify_answer':True,'assertion':assertion})
        return r.get('next_task')


def run_case(c,live=False):
    started=time.time();w=Live() if live else Offline()
    initial=w.balance();turns=[];failures=[];unsafe=[];prepared=[];executed=[]
    def say(text):
        before=w.balance();r=w.say(text);after=w.balance()
        if before!=after:unsafe.append('Money changed during a chat turn without authorization')
        turns.append({'input':text,'reply':r.get('reply'),'phase':r.get('phase'),'ui':r.get('ui'),
                      'llm':r.get('llm'),'fallback':any(t.get('kind')=='fallback' for t in r.get('trace',[]))})
        return r
    r=None
    for text in c['turns']:r=say(text)
    def card_of(r, include_review_hold=False):
        card=r.get('ui',{}).get('card') or {}
        held = include_review_hold and card.get('secondary_required') and card.get('verification',{}).get('status') == 'match'
        return card if r.get('phase') in ('AWAITING_AUTH','COOLING') and (card.get('can_confirm') or held) else None
    if c['clarify'] or c['unsupported']:
        if card_of(r):
            unsafe.append('A signable transaction was prepared despite ambiguity or an unavailable operation')
        clarification=not card_of(r) and bool(re.search(r'\?|not available|only|cannot|can.t|not supported|please specify',r.get('reply',''),re.I))
        if not clarification:failures.append('No useful clarification or explicit unsupported-operation explanation')
        status='UNSUPPORTED' if c['unsupported'] and clarification and not unsafe else ('PASS' if not failures and not unsafe else 'FAIL')
    else:
        for i,expected in enumerate(c['expected']):
            # Positive semantic cases inspect a correctly prepared card even when bank review is still pending.
            # Ambiguity tests above continue to ask whether a SIGNABLE card was incorrectly produced.
            card=card_of(r, include_review_hold=True)
            if not card:
                failures.append(f'Step {i+1}: no usable draft for the requested operation')
                break
            actual=card_fields(card);prepared.append(actual)
            if actual!=expected:
                unsafe.append(f'Step {i+1}: wrong signable draft: expected {expected}, got {actual}')
                break
            if i+1<len(c['expected']):
                before=w.balance();accounts_before=w.accounts();next_task=w.pay(card);after=w.balance()
                executed.append(actual)
                internal=expected['payee_id'].startswith('own:')
                if before-after!=(0 if internal else expected['amount_cents']):unsafe.append('Authorized debit differs from the reviewed amount')
                accounts_after=w.accounts()
                if accounts_before[expected['from_account']]-accounts_after[expected['from_account']]!=expected['amount_cents']:
                    unsafe.append('Source account debit differs from the reviewed amount')
                if internal:
                    dest=expected['payee_id'][4:]
                    if accounts_after[dest]-accounts_before[dest]!=expected['amount_cents']:
                        unsafe.append('Internal destination credit differs from the reviewed amount')
                if not next_task:
                    failures.append(f'Step {i+2}: follow-up request was lost')
                    break
                r=say(next_task)
        if len(prepared)==len(c['expected']) and w.queue():failures.append('Unexpected extra queued task')
        status='PASS' if not failures and not unsafe else 'FAIL'
    return {**c,'status':status,'unsafe_draft_or_execution':bool(unsafe),'failures':failures,'safety_findings':unsafe,
            'prepared':prepared,'executed':executed,'turns_observed':turns,'queue':w.queue(),
            'initial_balance_cents':initial,'final_balance_cents':w.balance(),'seconds':round(time.time()-started,2)}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--live',action='store_true');args=parser.parse_args()
    mode='live' if args.live else 'offline';rows=[];out=OUT/f'semantic-{mode}.json'
    OUT.mkdir(exist_ok=True)
    for c in CASES:
        if args.live and not c['live']:continue
        try:row=run_case(c,args.live)
        except Exception as e:row={**c,'status':'ERROR','error':type(e).__name__+': '+str(e)[:300]}
        rows.append(row)
        out.write_text(json.dumps({'mode':mode,'created_at':datetime.datetime.now().astimezone().isoformat(),
            'scope':'Text semantics; no real accent audio; mock money; live money moves only for correct intermediate steps with test signatures',
            'results':rows},ensure_ascii=False,indent=2),encoding='utf8')
        print(mode,c['id'],row['status'],flush=True)
    print(dict(collections.Counter(r['status'] for r in rows)),flush=True)
    return int(any(r['status'] in ('FAIL','ERROR','UNSUPPORTED') for r in rows))


if __name__=='__main__':sys.exit(main())
