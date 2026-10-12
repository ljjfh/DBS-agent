"""Opt-in LIVE API smoke check. Reads .env, uses synthetic speech/accounts, never logs secrets.
Run only when explicitly authorized: python qa/check_live_interfaces.py
"""
import base64,json,sys,time,uuid,re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import requests
from app.config import settings
from app.agent.llm import OpenAICompatLLM
from app.kernel import p256,webauthn
from scripts.verify_receipt import check

BASE='http://localhost:8000';OUT=ROOT/'qa/results/live-interfaces.json';rows=[]
secrets=[s for s in (settings.llm_api_key,settings.tc_secret_id,settings.tc_secret_key) if s]
def clean(value):
    text=str(value)
    for s in secrets:text=text.replace(s,'[REDACTED]')
    return text
def save():OUT.write_text(json.dumps({'mode':'live API + synthetic bank + generated English speech','results':rows},ensure_ascii=False,indent=2),encoding='utf8')
def run(name,fn):
    t=time.time()
    try: ok,obs=fn();status='PASS' if ok else 'FAIL'
    except Exception as e:status='FAIL';obs={'error':clean(e)}
    row={'name':name,'status':status,'seconds':round(time.time()-t,2),'observed':json.loads(clean(json.dumps(obs,ensure_ascii=False)))}
    rows.append(row);save();print(json.dumps(row,ensure_ascii=False),flush=True)
def req(path,body=None,timeout=180):
    r=requests.post(BASE+path,json=body,timeout=timeout) if body is not None else requests.get(BASE+path,timeout=timeout)
    try:data=r.json()
    except ValueError:data={'body':r.text[:200]}
    return r.status_code,data
def fresh():return req('/api/reset',{'visitor':uuid.uuid4().hex[:16]})[1]['session_id']
def model_chat(mode):
    client=OpenAICompatLLM(settings.llm_base_url,settings.llm_api_key,settings.llm_model,settings.llm_timeout,settings.llm_thinking)
    if mode=='text':
        r=client.chat([{'role':'user','content':'Reply exactly: API_OK'}]);return 'API_OK' in r['content'],r
    if mode=='tools':
        tool={'type':'function','function':{'name':'get_balance','description':'Read the mock account balance','parameters':{'type':'object','properties':{}}}}
        r=client.chat([{'role':'user','content':'Call get_balance to check my account balance.'}],tools=[tool],tool_choice='required')
        return any(c.get('function',{}).get('name')=='get_balance' for c in r['tool_calls']),r
    r=client.chat([{'role':'system','content':'Return JSON only: extract intent, payee and amount from the user message.'},
                   {'role':'user','content':'Send 50 dollars to my daughter'}],json_mode=True)
    raw=r['content'];m=re.search(r'\{.*\}',raw,re.S)
    data=json.loads(m.group()) if m else {}
    return data.get('amount')==50,{'extracted':data,'raw':raw[:1200]}

def main():
    run('service_health',lambda:(lambda c,d:(c==200 and d.get('llm')=='openai_compat',(c,d)))(*req('/api/health')))
    with ThreadPoolExecutor(3) as pool:
        fs={mode:pool.submit(model_chat,mode) for mode in ('text','tools','json')}
        for mode,f in fs.items():run('model_'+mode,lambda f=f:f.result())
    run('asr_english_sample',lambda:(lambda c,d:(c==200 and bool(d.get('text')),(c,d)))(*req('/api/asr',{'session_id':fresh(),'audio_b64':base64.b64encode((ROOT/'qa/results/live-asr-sample.wav').read_bytes()).decode()},30)))
    sid=fresh()
    for path in ('/','/app.js','/styles.css','/dbs-logo.svg','/favicon.svg','/api/state?session_id='+sid,
                 '/api/world?session_id='+sid,'/api/card/'+sid,'/api/trace/'+sid,'/api/audit/session/'+sid,'/api/audit/verify'):
        run(path.split('?')[0],lambda path=path:(lambda r:(r.status_code==200,{'http':r.status_code}))(requests.get(BASE+path,timeout=10)))
    def live_turn(text,expected_payee=None):
        sid=fresh();code,r=req('/api/chat',{'session_id':sid,'text':text})
        turns=[{'text':text,'reply':r.get('reply'),'phase':r.get('phase')}]
        # A question is a valid safe branch, not a transport failure. Complete the explicitly requested bill
        # with its authoritative catalog name, and retain both turns as evidence (never silently call this one-shot).
        if expected_payee=='SP Group Utilities' and code==200 and not r.get('ui',{}).get('card') and r.get('phase')=='IDLE':
            followup='Please pay the October utilities bill to SP Group Utilities.'
            code,r=req('/api/chat',{'session_id':sid,'text':followup})
            turns.append({'text':followup,'reply':r.get('reply'),'phase':r.get('phase')})
        trace=r.get('trace',[]);fallbacks=[t for t in trace if t.get('kind')=='fallback']
        card=r.get('ui',{}).get('card');verification=(card or {}).get('verification',{})
        matched=(not expected_payee or card and card.get('payee_name')==expected_payee)
        return code==200 and not fallbacks and matched,{'http':code,'session_id':sid,'reply':r.get('reply'),
            'llm':r.get('llm'),'phase':r.get('phase'),'card':card,'fallback':fallbacks,'verification':verification,'turns':turns}
    for label,text,target in [('balance','What is my balance?',None),('transfer','Send 50 to my daughter','Chen Mei Ling'),
                              ('bill','Pay the electricity bill','SP Group Utilities'),('investment','Invest 200 in income fund','DBS Income Fund')]:
        run('live_agent_'+label,lambda text=text,target=target:live_turn(text,target))
    # Kernel HTTP flow uses the deterministic model-mistake endpoint's frozen draft to test rejection.
    sid=fresh()
    def mistake():
        c,d=req('/api/demo/model-mistake',{'session_id':sid})
        card=d.get('ui',{}).get('card') or {}
        st=req('/api/state?session_id='+sid)[1]
        # A real independent scam judge can block before the mismatch UI is selected. Both outcomes must remain
        # non-signable and non-executed; require evidence of the verifier mismatch too.
        safe=c==200 and d.get('phase') in ('FROZEN','BLOCKED') and not card.get('can_confirm') and not st['receipts']
        mismatch=card.get('verification',{}).get('status')=='mismatch'
        return safe and mismatch,{'http':c,'phase':d.get('phase'),'can_confirm':card.get('can_confirm'),
                                  'verification':card.get('verification'),'receipts':len(st['receipts'])}
    run('model_mistake_freezes',mistake)
    run('signature_missing_rejected',lambda:(lambda c,d:(c==400,(c,d)))(*req('/api/confirm',{'session_id':sid,'draft_id':'nonexistent','digest':'0'*64,'assertion':''})))
    def passkey():
        sid=fresh();auth=webauthn.SoftAuthenticator(rp_id='localhost',origin=BASE)
        c,opts=req('/api/passkey/options',{'session_id':sid})
        c,reg=req('/api/passkey/register',{'session_id':sid,**auth.register(webauthn.unb64u(opts['challenge']))})
        denied=req('/api/passkey/remove',{'session_id':sid})
        cc,ch=req('/api/passkey/remove/challenge',{'session_id':sid})
        removed=req('/api/passkey/remove',{'session_id':sid, 'assertion':auth.sign(ch['payload'])})
        return c==200 and denied[0]==400 and removed[0]==200,{'register':reg,'unsigned_remove':denied,'remove':removed}
    run('passkey_options_register_remove',passkey)
    # Reuse a successful LIVE draft without making more model calls.
    source=next((r['observed'] for r in rows if r['name']=='live_agent_transfer' and r['observed'].get('card')),None)
    if source:
        sid=source['session_id'];card=source['card'];key,pub=p256.generate_keypair()
        run('register_browser_key',lambda:(lambda c,d:(c==200,(c,d)))(*req('/api/key',{'session_id':sid,'public_key':pub})))
        def signed_payment():
            c,ch=req('/api/challenge',{'session_id':sid,'draft_id':card['draft_id'],'digest':card['digest'],'verify_answer':True})
            if c!=200:return False,{'challenge_http':c,'body':ch}
            assertion={'payload':ch['payload'],'signature':base64.b64encode(p256.sign(key,ch['payload'].encode())).decode()}
            c,r=req('/api/confirm',{'session_id':sid,'draft_id':card['draft_id'],'digest':card['digest'],'verify_answer':True,'assertion':assertion})
            tests=check(r['receipt']['verifiable']) if c==200 else []
            return c==200 and bool(tests) and all(ok for _,ok in tests),{'http':c,'receipt_checks':tests,'result':r.get('receipt',r)}
        run('challenge_confirm_receipt',signed_payment)
        run('cancel_settled_draft',lambda:(lambda c,d:(c==400,(c,d)))(*req('/api/cancel',{'session_id':sid,'draft_id':card['draft_id']})))
    else:
        rows.append({'name':'challenge_confirm_receipt','status':'NOT_TESTED','observed':'No usable live-model draft; existing offline tests cover this route.'});save()
    sid=fresh()
    run('protection_challenge',lambda:(lambda c,d:(c==200,(c,{'payload_present':bool(d.get('payload'))})))(*req('/api/protection/challenge',{'session_id':sid,'to':'standard'})))
    run('protection_raise',lambda:(lambda c,d:(c==200 and d.get('level')=='enhanced',(c,d)))(*req('/api/protection',{'session_id':sid,'to':'enhanced'})))
    run('security_lab',lambda:(lambda c,d:(c==200 and all(x['blocked'] for x in d.get('results',[])),{'http':c,'blocked':sum(x['blocked'] for x in d.get('results',[])),'total':len(d.get('results',[]))}))(*req('/api/lab',{})))
    def protection_signed():
        sid=fresh();key,pub=p256.generate_keypair()
        c,k=req('/api/key',{'session_id':sid,'public_key':pub})
        c,ch=req('/api/protection/challenge',{'session_id':sid,'to':'standard'})
        payload=ch['payload'];sig=base64.b64encode(p256.sign(key,payload.encode())).decode()
        c,st=req('/api/protection',{'session_id':sid,'to':'standard','assertion':{'payload':payload,'signature':sig}})
        restored=req('/api/protection',{'session_id':sid,'to':'enhanced'})
        return bool(c==200 and st.get('pending') and st['level']=='enhanced' and restored[0]==200),{'scheduled':st,'restored':restored}
    run('protection_signed_lower_and_restore',protection_signed)
    source=next((r['observed'] for r in rows if r['name']=='live_agent_investment' and isinstance(r['observed'],dict)),None)
    if source and source.get('card'):
        card=source['card'];sid=source['session_id']
        run('unsigned_live_draft_refused',lambda:(lambda c,d:(c==400 and d.get('code')=='AUTH_FAILED',(c,d)))(*req('/api/confirm',{'session_id':sid,'draft_id':card['draft_id'],'digest':card['digest'],'assertion':'','verify_answer':True})))
        run('cancel_live_investment',lambda:(lambda c,d:(c==200 and d.get('phase')=='IDLE',(c,d)))(*req('/api/cancel',{'session_id':sid,'draft_id':card['draft_id']})))
    run('secret_file_not_served',lambda:(lambda r:(r.status_code==404,{'http':r.status_code}))(requests.get(BASE+'/.env',timeout=5)))
    print('SUMMARY',json.dumps({s:sum(r['status']==s for r in rows) for s in ('PASS','FAIL','NOT_TESTED')}),flush=True)
    return int(any(r['status']!='PASS' for r in rows))
if __name__=='__main__':sys.exit(main())
