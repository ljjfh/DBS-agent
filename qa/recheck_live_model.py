"""Selected follow-up checks after the first live run; retains original evidence."""
import json,re,time,sys
import check_live_interfaces as q
q.rows[:]=json.loads(q.OUT.read_text(encoding='utf8'))['results']
start=len(q.rows)
original_run=q.run
selected=sys.argv[sys.argv.index('--only')+1:] if '--only' in sys.argv else []
def run_selected(name,fn):
    if not selected or name in selected:original_run(name,fn)
q.run=run_selected
for mode in ('text','tools','json'):
    q.run('model_'+mode+'_sequential_retry',lambda mode=mode:q.model_chat(mode))
source=next(r['observed'] for r in q.rows if r['name']=='live_agent_bill')
def bill():
    c,r=q.req('/api/chat',{'session_id':source['session_id'],'text':'Yes, pay the October utilities bill.'})
    card=r.get('ui',{}).get('card');fb=[t for t in r.get('trace',[]) if t.get('kind')=='fallback']
    if c==200 and card:
        cancelled=q.req('/api/cancel',{'session_id':source['session_id'],'draft_id':card['draft_id']})
    else:cancelled=None
    return c==200 and bool(card) and card.get('payee_name')=='SP Group Utilities' and not fb and cancelled[0]==200,{
        'http':c,'reply':r.get('reply'),'llm':r.get('llm'),'card':card,'fallback':fb,'cancelled':cancelled}
q.run('bill_clarification_then_cancel',bill)
def balance():
    c,r=q.req('/api/chat',{'session_id':q.fresh(),'text':'What is my balance?'})
    fb=[t for t in r.get('trace',[]) if t.get('kind')=='fallback']
    return c==200 and not fb,{'http':c,'reply':r.get('reply'),'llm':r.get('llm'),'fallback':fb}
q.run('balance_sequential_retry',balance)
print('SUMMARY',json.dumps({s:sum(r['status']==s for r in q.rows) for s in ('PASS','FAIL','NOT_TESTED')}),flush=True)
sys.exit(int(any(r['status']!='PASS' for r in q.rows[start:])))
