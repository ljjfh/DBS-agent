"""Headless installed Edge E2E tests; isolated :random-port server, no real microphone/cloud calls.
Requires pip install -r qa/requirements.txt. Uses actual DOM/WebCrypto/HTTP, mocked SpeechRecognition events.
"""
import json
import re
import sys
import time
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
import run_extended as q

SR = r"""
window.__speech=[];
class FakeSpeech {
  constructor(){window.__speech.push(this);this.starts=0;}
  start(){this.starts++;}
  stop(){queueMicrotask(()=>this.onend?.());}
  emit(items){const results=items.map(([text,final])=>{const r=[{transcript:text}];r.isFinal=final;return r;});this.onresult?.({results,resultIndex:0});}
  end(){this.onend?.();}
  fail(error){this.onerror?.({error});this.onend?.();}
}
window.SpeechRecognition=FakeSpeech;window.webkitSpeechRecognition=FakeSpeech;
"""

def main():
    server,thread,base=q.start_http()
    base=base.replace("127.0.0.1","localhost")
    with sync_playwright() as pw:
        browser=pw.chromium.launch(channel="msedge",headless=True)
        def run(id,title,expected,fn,priority="P2",mobile=False,senior=False):
            if "--only" in sys.argv and id not in sys.argv[sys.argv.index("--only")+1:]: return
            def wrapped():
                q.runtime.bank.reset()
                context=browser.new_context(viewport={"width":390,"height":844} if mobile else {"width":1440,"height":1000},accept_downloads=True)
                context.add_init_script(SR)
                context.add_init_script("if(localStorage.getItem('readAloud')===null)localStorage.setItem('readAloud', 'false');"+("localStorage.setItem('senior', 'true');" if senior else ""))
                page=context.new_page();errors=[];chats=[]
                page.on("pageerror",lambda e:errors.append(str(e)))
                page.on("request",lambda r:chats.append(r.post_data_json.get("text")) if r.url.endswith("/api/chat") else None)
                try:
                    page.goto(base);page.wait_for_selector("#text")
                    result,obs=fn(page,chats)
                    obs={"details":obs,"page_errors":errors,"chat_requests":chats}
                    if not result or errors:
                        page.screenshot(path=str(q.OUT/(id+".png")),full_page=True)
                    elif (q.OUT/(id+".png")).exists():
                        (q.OUT/(id+".png")).unlink()
                    return result and not errors,obs
                finally:context.close()
            q.record(id,"浏览器端到端",title,expected,wrapped,priority)

        def state(p):
            return p.evaluate("async()=>{const sid=JSON.parse(localStorage.getItem('sid'));return await (await fetch('/api/state?session_id='+encodeURIComponent(sid))).json()}")
        def say(p,text):
            p.locator("#text").fill(text)
            with p.expect_response(lambda r:r.url.endswith("/api/chat")) as res:p.locator("#composer [type=submit]").click()
            response=res.value.json();p.wait_for_timeout(150);return response
        def confirm(p):
            if p.locator('[data-v="yes"]').is_visible():p.locator('[data-v="yes"]').click()
            p.locator("#c-go").click();p.locator(".mf-pad").click()
        def balance(p):return state(p)["accounts"][0]["balance_cents"]
        def home(p,c):
            d=state(p);return {a['account_id'] for a in d['accounts']}=={'SAV-001','CUR-002','JNT-003'} and len(d["payees"])==10,dict(accounts=len(d["accounts"]),payees=len(d["payees"]))
        run("B01","首页账户/账单/持仓加载","三账户、七外部收款方（含信用卡账单）和三个自有账户目标；无JS异常",home)
        for route,title in [("activity","Transactions"),("contacts","Payees"),("audit","Audit trail"),("lab","Security lab"),("settings","Settings")]:
            def nav(p,c,route=route,title=title):
                p.locator(f'[data-page="{route}"]').click();expect(p.locator("h1")).to_have_text(title)
                if route=="audit":expect(p.locator("#integrity")).to_contain_text("Chain intact")
                return True,{"heading":p.locator("h1").inner_text()}
            run("B_nav_"+route,"导航 "+title,"页面成功展示",nav)
        def pay(p,c):
            say(p,"Send 50 to my daughter");before=balance(p)
            with p.expect_response(lambda r:r.url.endswith("/api/confirm")) as res:confirm(p)
            receipt=res.value.json();expect(p.locator("#confirm")).not_to_be_visible()
            d=state(p)
            return before-balance(p)==5000 and len(d["receipts"])==1,dict(status=res.value.status,receipts=len(d["receipts"]),balance=balance(p))
        run("B_pay","点击模拟指纹完成付款","浏览器真实签名，扣50并展示回执",pay,"P1")
        def cancel(p,c):
            say(p,"Send 50 to my daughter");p.locator("#c-cancel").click();expect(p.locator("#confirm")).not_to_be_visible()
            return state(p)["phase"]=="IDLE" and balance(p)==325000,state(p)["phase"]
        run("B_cancel","取消确认卡","不扣款、清除待办",cancel,"P1")
        def sensor_cancel(p,c):
            say(p,"Send 50 to my daughter");p.locator("#c-go").click();p.locator(".mf-cancel").click()
            return balance(p)==325000 and p.locator("#c-go").is_enabled(),{"balance":balance(p)}
        run("B_sensor_cancel","取消模拟指纹","未扣款，可重新确认",sensor_cancel,"P1")
        def refresh(p,c):
            say(p,"Send 50 to my daughter");p.reload();expect(p.locator("#confirm")).to_be_visible()
            return "S$50.00" in p.locator("#confirm").inner_text(),{"card":p.locator("#confirm .amt").inner_text()}
        run("B_restore","刷新恢复待确认卡","相同金额草稿恢复",refresh,"P1")
        def doubleclick(p,c):
            say(p,"Send 50 to my daughter");p.locator("#c-go").click();p.locator(".mf-pad").dblclick()
            expect(p.locator("#confirm")).not_to_be_visible(timeout=8000)
            d=state(p);return balance(p)==320000 and len(d["receipts"])==1,{"balance":balance(p),"receipts":len(d["receipts"])}
        run("B_doubleclick","重复点击指纹","只执行一笔",doubleclick,"P1")
        def download(p,c):
            pay(p,c);p.locator('[data-page="activity"]').click()
            with p.expect_download() as dl:p.locator(".dl").first.click()
            file=dl.value;file.save_as(str(q.OUT/"sample-receipt.json"))
            r=json.loads((q.OUT/"sample-receipt.json").read_text(encoding="utf8"));checks=q.check_receipt(r)
            return all(ok for _,ok in checks),checks
        run("B_download","下载回执并离线验签","导出JSON可被验证",download,"P1")
        def lost(p,c):
            say(p,"Send 50 to my daughter")
            def drop(route):route.fetch();route.abort("failed")
            p.route("**/api/confirm",drop);confirm(p)
            p.wait_for_timeout(2300);d=state(p)
            text=p.locator("#stage").inner_text();card_open=p.locator("#confirm").is_visible()
            enabled=card_open and p.locator("#c-go").is_enabled()
            p.screenshot(path=str(q.OUT/"lost-response.png"),full_page=True)
            recovered=bool(re.search(r"pending|unknown|checking|completed|receive|uncertain",text,re.I)) and not enabled
            return recovered,{"server_receipts":len(d["receipts"]),"server_balance":balance(p),"confirm_enabled":enabled,"screen":text[-1600:]}
        run("B_lost_response","后端已付款但确认响应丢失","查询原交易状态，不能继续显示可重试付款",lost,"P1")
        def cancel_failure(p,c):
            say(p,"Send 50 to my daughter");p.route("**/api/cancel",lambda r:r.abort("failed"));p.locator("#c-cancel").click();p.wait_for_timeout(250)
            d=state(p);body=p.locator("#main").inner_text()
            return "cancelled" not in body.lower() and p.locator("#confirm").is_visible(),{"server_phase":d["phase"],"screen":body[-2000:]}
        run("B_cancel_network","取消请求网络失败","保留待办并提示取消未完成",cancel_failure,"P1")
        def settings(p,c):
            before=state(p)["protection"];p.locator("#senior-toggle").click();p.reload();expect(p.locator("body")).to_have_class(re.compile("senior"))
            return state(p)["protection"]==before,{"body_class":p.locator("body").get_attribute("class"),"protection":before}
        run("B_senior","适老模式持久化","刷新保留适老模式且风控等级不变",settings)
        def layout(p,c):
            dims=p.evaluate("({width:innerWidth,scroll:document.documentElement.scrollWidth})")
            p.screenshot(path=str(q.OUT/("senior-mobile.png" if "senior" in (p.locator("body").get_attribute("class") or "") else "standard-mobile.png")),full_page=True)
            return dims["scroll"]<=dims["width"],dims
        run("B_mobile","390px标准视图","整页无横向溢出",layout,mobile=True)
        run("B_mobile_senior","390px适老视图","整页无横向溢出",layout,mobile=True,senior=True)
        def xss(p,c):
            say(p,'<img src=x onerror="window.__xss=1"> What is my balance?')
            return not p.evaluate("!!window.__xss") and p.locator("#stage img").count()==0,{"injected_images":p.locator("#stage img").count()}
        run("B_xss","对话显示HTML片段","作为文本展示不执行",xss,"P1")
        def speech(p,c,mode):
            p.locator("#mic").click()
            p.evaluate("window.__speech.at(-1).emit([['Send fifty',false]])")
            p.wait_for_timeout(400)
            premature=len(c)
            if mode=="restart":p.evaluate("window.__speech.at(-1).end()")
            if mode=="network":
                p.evaluate("window.__speech.at(-1).fail('network')");p.wait_for_timeout(400)
                return not c,{"requests":c,"expected":"network error with partial utterance must not auto-submit"}
            if mode=="restart":p.evaluate("window.__speech.at(-1).emit([[' to my daughter',true]])")
            else:p.evaluate("window.__speech.at(-1).emit([['Send fifty to my daughter',true]])")
            p.locator("#mic").click();p.wait_for_timeout(450)
            return premature==0 and len(c)==1 and "daughter" in c[0],{"premature":premature,"requests":c}
        for mode in ("normal","restart","network"):
            run("B_voice_"+mode,"模拟识别事件："+mode,"完整说完才提交一次；故障保留未完成文本",lambda p,c,m=mode:speech(p,c,m),"P1")
        def pause(p,c):
            p.locator("#mic").click();p.evaluate("window.__speech.at(-1).emit([['Send fifty',true]])")
            p.wait_for_timeout(3200);early=len(c)
            p.evaluate("window.__speech.at(-1).emit([['Send fifty to my daughter',true]])")
            p.locator("#mic").click();p.wait_for_timeout(400)
            return early==0 and len(c)==1 and "daughter" in c[0],{"after_3_2_seconds":early,"requests":c}
        run("B_voice_pause","适老语音中途停顿3.2秒","不提前提交，续说后整句发送",pause,"P1",senior=True)
        def missing(p,c):
            p.evaluate("delete window.SpeechRecognition;delete window.webkitSpeechRecognition")
            p.locator("#mic").click()
            return "doesn't support voice" in p.locator("#stage").inner_text() and not c,{"screen":p.locator("#stage").inner_text()[-500:]}
        run("B_voice_missing","浏览器无语音识别支持","提供文字输入提示",missing)
        def frozen(p,c):
            p.locator('[data-page="lab"]').click();p.locator("#lab-mistake").click();p.wait_for_timeout(500)
            d=state(p);return d["phase"]=="FROZEN" and not p.locator("#confirm").is_visible(),{"phase":d["phase"]}
        run("B_frozen","模型误写金额演示","冻结草稿，无法签名",frozen,"P1")
        def lab(p,c):
            p.locator('[data-page="lab"]').click();p.locator("#lab-run").click()
            expect(p.locator(".lab-score")).to_contain_text("22 / 22",timeout=20000)
            return True,{"score":p.locator(".lab-score").inner_text()}
        run("B_lab","浏览器运行安全实验室","22种内置攻击被阻止",lab,"P1")
        def bill(p,c):
            p.locator('#bills .pay').first.click();expect(p.locator('#confirm .amt')).to_have_text('S$86.40')
            with p.expect_response(lambda r:r.url.endswith('/api/confirm')):confirm(p)
            expect(p.locator('#confirm')).not_to_be_visible()
            d=state(p);return d['bills'][0]['status']=='paid' and balance(p)==316360,dict(bill=d['bills'][0],balance=balance(p))
        run('B_bill','点击账单Pay并支付','金额来自账单，结清后状态更新',bill,'P1')
        def investment(p,c):
            say(p,'Invest 200 in income fund')
            with p.expect_response(lambda r:r.url.endswith('/api/confirm')):confirm(p)
            expect(p.locator('#confirm')).not_to_be_visible()
            d=state(p);return any('Income Fund' in h['name'] for h in d['holdings']) and balance(p)==305000,dict(holdings=d['holdings'],balance=balance(p))
        run('B_investment','投资后持仓更新','扣款200且增加目标基金持仓',investment,'P1')
        def multi(p,c):
            say(p,'Pay the electricity bill then send 50 to my daughter')
            with p.expect_response(lambda r:r.url.endswith('/api/confirm')):confirm(p)
            expect(p.locator('#confirm .amt')).to_have_text('S$50.00',timeout=10000)
            first=balance(p)
            with p.expect_response(lambda r:r.url.endswith('/api/confirm')):confirm(p)
            expect(p.locator('#confirm')).not_to_be_visible()
            d=state(p);return first==316360 and balance(p)==311360 and len(d['receipts'])==2,dict(after_first=first,after_second=balance(p),receipts=len(d['receipts']))
        run('B_multi','账单+转账顺序执行','各自签名确认，第二笔不提前扣款',multi,'P1')
        def audit_export(p,c):
            say(p,'What is my balance?');p.locator('[data-page="audit"]').click()
            expect(p.locator('#integrity')).to_contain_text('Chain intact')
            with p.expect_download() as dl:p.locator('#a-export').click()
            dl.value.save_as(str(q.OUT/'sample-audit.json'))
            data=json.loads((q.OUT/'sample-audit.json').read_text(encoding='utf8'))
            return data['integrity']['ok'] and len(data['entries'])>0,dict(integrity=data['integrity'],entries=len(data['entries']))
        run('B_audit_export','审计导出','可下载且完整性通过',audit_export)
        def preferences(p,c):
            p.locator('[data-page="settings"]').click();p.locator('#s-large').click();p.locator('#s-read').click()
            p.reload();p.locator('[data-page="settings"]').click()
            return 'large' in p.locator('body').get_attribute('class') and p.locator('#s-read').get_attribute('aria-checked')=='true',{'large':p.locator('body').get_attribute('class'),'read':p.locator('#s-read').get_attribute('aria-checked')}
        run('B_preferences','大字和朗读设置','用户设置刷新后保留',preferences)
        def reset(p,c):
            pay(p,c);p.locator('[data-page="settings"]').click();p.locator('#s-reset').click();expect(p.locator('#text')).to_be_visible()
            d=state(p);return balance(p)==325000 and not d['receipts'],dict(balance=balance(p),receipts=len(d['receipts']))
        run('B_reset','重置演示','余额恢复，当前回执清空',reset)
        def no_voice(p,c):
            p.locator('#mic').click();p.evaluate("window.__speech.at(-1).fail('not-allowed')")
            return not c and 'permission' in p.locator('#hint').inner_text(),{'hint':p.locator('#hint').inner_text()}
        run('B_voice_permission','语音权限拒绝','提示权限问题不自动提交',no_voice)
        def trace(p,c):
            say(p,'What is my balance?');p.locator('#trace-toggle').click();expect(p.locator('#trace')).to_have_attribute('aria-hidden','false')
            content=p.locator('#tlist').inner_text();p.locator('#trace-close').click()
            return 'get_balance' in content and p.locator('#trace').get_attribute('aria-hidden')=='true',{'trace':content[:600]}
        run('B_trace','轨迹面板','显示工具调用且可关闭',trace)
        browser.close()
    server.should_exit=True;thread.join(5)
    result={"browser":"Installed Microsoft Edge, headless", "speech":"Synthetic SpeechRecognition events; no physical microphone",
            "counts":{k:sum(r["status"]==k for r in q.RESULTS) for k in ("PASS","FAIL","ERROR")},"results":q.RESULTS}
    if "--only" in sys.argv and (q.OUT/"browser.json").exists():
        previous=json.loads((q.OUT/"browser.json").read_text(encoding="utf8"))
        replacements={r['id']:r for r in result['results']}
        result['results']=[replacements.pop(r['id'],r) for r in previous['results']]+list(replacements.values())
        result['counts']={k:sum(r['status']==k for r in result['results']) for k in ('PASS','FAIL','ERROR')}
    (q.OUT/"browser.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf8")
    print(result["counts"])
    return int(any(r["status"]!="PASS" for r in q.RESULTS))

if __name__=="__main__":sys.exit(main())
