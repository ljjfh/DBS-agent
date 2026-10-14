// Offline end-to-end review: real browser WebCrypto, reviewer credential, evidence and responsive layout.
// npm install playwright (or use the bundled runtime's NODE_PATH); requires installed Microsoft Edge.
const {chromium} = require('playwright');
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const assert = require('node:assert/strict');

(async () => {
  const root = path.resolve(__dirname, '..');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'star-contract-browser-'));
  const output = path.join(__dirname, 'results'); fs.mkdirSync(output, {recursive:true});
  const port = await new Promise(resolve => {const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
  const base = `http://localhost:${port}`;
  const env = {...process.env, PYTHONUTF8:'1', PYTHONIOENCODING:'utf-8', LLM_PROVIDER:'offline',
    TENCENTCLOUD_SECRET_ID:'', TENCENTCLOUD_SECRET_KEY:'', LEDGER_PATH:path.join(temp,'ledger.sqlite3'),
    AUDIT_PATH:path.join(temp,'audit.jsonl'), PASSKEY_PATH:path.join(temp,'keys.json'), RULE_FIXED_HOUR:'14',
    RULE_COOLDOWN_SECONDS:'1', SECONDARY_REVIEW_KEY:'isolated-browser-test-reviewer', PUBLIC_DEMO:'1'};
  const server=spawn(process.env.PYTHON || 'python',['-m','uvicorn','app.server:app','--host','127.0.0.1','--port',String(port),'--no-proxy-headers'],
    {cwd:root,env,windowsHide:true,stdio:['ignore','pipe','pipe']});
  let serverLog='';server.stderr.on('data',b=>serverLog+=b.toString());
  let browser;
  const errors=[], checks=[];
  const pass=name=>{checks.push({name,status:'PASS'});console.log('PASS',name);};
  try {
    for(let i=0;i<100;i++){try{if((await fetch(base+'/api/health')).ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
    browser=await chromium.launch({channel:'msedge',headless:true});
    const context=await browser.newContext({viewport:{width:1440,height:1050}});
    await context.addInitScript(()=>localStorage.setItem('readAloud','false'));
    const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
    await page.goto(base);await page.locator('#welcome-enter').click();await page.locator('#text').waitFor();
    async function say(text){await page.locator('#text').fill(text);const result=page.waitForResponse(r=>r.url().endsWith('/api/chat'));
      await page.locator('#composer [type=submit]').click();return (await result).json();}
    await say('Send 50 to my daughter');
    await page.locator('#c-go').click();await page.locator('.mf-pad').click();
    await page.locator('#confirm').waitFor({state:'hidden'});
    const normal = await page.evaluate(async()=>{
      const sid=JSON.parse(localStorage.getItem('sid'));
      return (await fetch('/api/state?session_id='+encodeURIComponent(sid))).json();
    });
    assert.equal(normal.receipts[0].decision.action,'executed');
    assert.equal(normal.receipts[0].decision.checks.authorization.status,'pass');pass('Real WebCrypto payment stores executed contract evidence');
    await page.locator('#safety .decision-panel summary').click();
    await page.screenshot({path:path.join(output,'contract-customer.png'),fullPage:true});

    const large=await say('Send 1500 to my daughter');
    assert.equal(large.ui.card.secondary_required,true);
    assert.equal(await page.locator('#c-go').isDisabled(),true);
    const sid=await page.evaluate(()=>JSON.parse(localStorage.getItem('sid')));
    const ticket={session_id:sid,draft_id:large.ui.card.draft_id,digest:large.ui.card.digest};
    const denied=await context.request.post(base+'/api/review/secondary',{data:{...ticket,operation:'approve'}});
    assert.equal(denied.status(),403);pass('Customer cannot self-approve a large payment');
    await page.screenshot({path:path.join(output,'contract-awaiting-review.png')});

    const reviewContext=await browser.newContext({viewport:{width:1440,height:1050}});
    await reviewContext.addInitScript(()=>localStorage.setItem('readAloud','false'));
    const reviewer=await reviewContext.newPage();reviewer.on('pageerror',e=>errors.push(e.message));
    await reviewer.goto(base);await reviewer.locator('#welcome-enter').click();
    await reviewer.locator('[data-page="lab"]').click();
    await reviewer.locator('#review-key').fill(env.SECONDARY_REVIEW_KEY);
    await reviewer.locator('#review-file').setInputFiles({name:'review-ticket.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(ticket))});
    await reviewer.locator('#review-inspect').click();await reviewer.locator('#review-approve').waitFor();
    assert.match(await reviewer.locator('#review-out').innerText(),/1,500/);
    await reviewer.locator('#review-approve').click();await reviewer.getByText(/Approved for five minutes/).waitFor();
    await page.locator('#review-refresh').click();
    await page.waitForFunction(()=>!document.querySelector('#c-go').disabled);
    await page.locator('#c-go').click();await page.locator('.mf-pad').click();
    await page.locator('#confirm').waitFor({state:'hidden'});pass('Separate review followed by customer signature completes payment');

    await reviewer.locator('#contract-run').click();
    await reviewer.getByText('8 / 8 scenarios behaved as expected').waitFor({timeout:60000});
    await reviewer.locator('.contract-case .decision-panel summary').first().click();
    await reviewer.locator('.contract-showcase').scrollIntoViewIfNeeded();
    await reviewer.screenshot({path:path.join(output,'contract-lab-desktop.png')});
    assert.match(await reviewer.locator('.contract-table').innerText(),/0\/4/);pass('Eight real sandbox outcomes and labelled gate comparison are visible');
    await reviewer.setViewportSize({width:390,height:844});
    await reviewer.locator('#contract-run').scrollIntoViewIfNeeded();
    const overflow=await reviewer.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
    assert.equal(overflow,false);
    await reviewer.screenshot({path:path.join(output,'contract-lab-mobile.png')});pass('Mobile risk evidence has no horizontal page overflow');
    assert.deepEqual(errors,[]);pass('No browser JavaScript errors');
    fs.writeFileSync(path.join(output,'contract-browser.json'),JSON.stringify({checks,errors,scope:'Offline Edge; real WebCrypto; simulated reviewer; temporary ledger'},null,2));
  } catch(e) {
    console.error(e);console.error(serverLog.slice(-2000));process.exitCode=1;
    fs.writeFileSync(path.join(output,'contract-browser.json'),JSON.stringify({checks,errors,failure:String(e)},null,2));
  } finally {
    if(browser)await browser.close();server.kill();
    // OS temp directory is deliberately retained if server shutdown is still asynchronous on Windows.
  }
})();
