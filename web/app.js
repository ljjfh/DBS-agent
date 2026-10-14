// Star · DBS digibank concept — frontend
// Layout and visual language from the team's Aegis prototype; agent, kernel, signing and Senior mode from Star.
// No inline script or style anywhere, so the server's strict Content-Security-Policy applies.

const $ = (sel, el = document) => el.querySelector(sel);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const store = {
  get(k, d){ try{ const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); }catch{ return d; } },
  set(k, v){ try{ localStorage.setItem(k, JSON.stringify(v)); }catch{} },
};
// Online demo (server PUBLIC_DEMO=1): this browser's own demo customer, so testers never see each other's payments,
// resets or passkeys. Locally the server doesn't ask for it and everyone is the same Mdm Chen.
const VISITOR = (() => {
  let v = store.get('vid', null);
  if(!/^[a-f0-9]{16}$/.test(v || '')){ v = [...crypto.getRandomValues(new Uint8Array(8))].map(b => b.toString(16).padStart(2, '0')).join(''); store.set('vid', v); }
  return v;
})();
const visitorMode = () => !!state.health.public_demo;

const state = {
  sid: store.get('sid', null), page: 'overview', data: null, health: {},
  senior: store.get('senior', false), large: store.get('large', false), readAloud: store.get('readAloud', null),
  messages: [], check: null, card: null, verify: null, coolTimer: null, busy: false,
};

// ---------------------------------------------------------------- Icons (generic, project-native)
const P = {
  home:'M3 10 12 3l9 7v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1z',
  transfer:'M4 7h15m-4-4 4 4-4 4M20 17H5m4-4-4 4 4 4',
  users:'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m20 0v-2a4 4 0 0 0-3-3.87M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8m8-7.87a4 4 0 0 1 0 7.75',
  shield:'m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6',
  audit:'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zm0 0v6h6M8 13h8m-8 4h6',
  lab:'M9 3h6m-5 0v7L4 20h16l-6-10V3M7 15h10',
  settings:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M12 2v3m0 14v3M2 12h3m14 0h3M5 5l2 2m10 10 2 2M5 19l2-2M17 7l2-2',
  spark:'m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5z',
  mic:'M12 3a3 3 0 0 0-3 3v6a3 3 0 0 0 6 0V6a3 3 0 0 0-3-3M5 10v2a7 7 0 0 0 14 0v-2M12 19v3m-4 0h8',
  send:'M12 19V5m-6 6 6-6 6 6',
  lock:'M6 10h12v11H6zm2 0V6a4 4 0 0 1 8 0v4m-4 5v2',
  wallet:'M3 7h18v14H3zm0 0V4h15v3m-1 6h4v4h-4z',
  bolt:'m13 2-9 12h7l-1 8 10-13h-7z',
  coin:'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18m0-14v10m-3-7.5c0-1 1.3-1.8 3-1.8s3 .8 3 1.8-1.3 1.7-3 1.7-3 .8-3 1.8 1.3 1.8 3 1.8 3-.8 3-1.8',
  phone:'M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2',
  alert:'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0',
  family:'M9 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6m8 1a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5M3 20v-1a6 6 0 0 1 12 0v1m1-6.5a4.5 4.5 0 0 1 5 4.5v1',
  trace:'M4 6h16M4 12h10M4 18h7',
  download:'M12 3v12m-5-5 5 5 5-5M5 17v4h14v-4',
  refresh:'M3 5v5h5m13 9v-5h-5M4 10a8 8 0 0 1 13-6l4 4M3 16l4 4a8 8 0 0 0 13-6',
  senior:'M12 7a3 3 0 1 0 0-6 3 3 0 0 0 0 6m-4 16 1-9-3 3m9 6-1-9 3 3M9 14l3-5 3 5',
  chart:'M4 20V10m6 10V4m6 16v-7m4 7H2',
  fingerprint:'M7 11c0-3 2.2-5 5-5s5 2 5 5v2M9.5 11c0-1.4 1.1-2.5 2.5-2.5s2.5 1.1 2.5 2.5v3c0 2-1 4-2 5M12 11v3c0 1.5-.5 3-1.5 4.5M7 14c0 2 .5 3.5 1.5 5M17 16c-.2 1.3-.6 2.5-1.2 3.5',
};
const icon = (n, cls = '') => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${P[n] || P.spark}"/></svg>`;

const NAV = [
  ['overview', 'Overview', 'home', 'Your workspace'], ['activity', 'Transactions', 'transfer'], ['contacts', 'Payees', 'users'],
  ['audit', 'Audit trail', 'audit', 'Trust & transparency'], ['lab', 'Security lab', 'lab'], ['settings', 'Settings', 'settings'],
];
const KIND = {user:'User', thought:'Thought', action:'Action', observation:'Observe', rule:'Rule', guard:'Guard', judge:'Judge',
  state:'State', sign:'Sign', exec:'Execute', plan:'Plan', asr:'ASR', fallback:'Fallback', handoff:'Handoff', evidence:'Evidence', ui:'UI',
  verify:'Verifier', gateway:'Gateway', model:'Model', api:'DBS API'};

// ---------------------------------------------------------------- Basics
async function api(path, body){
  const opt = body ? {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)} : {};
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if(!r.ok) throw Object.assign(new Error(data.error || r.statusText), {data, status: r.status});
  return data;
}
function toast(msg){ const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 2600); }
function download(name, obj){
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], {type:'application/json'}));
  a.download = name; document.body.appendChild(a); a.click(); a.remove();
}
const today = () => new Date().toLocaleDateString('en-SG', {weekday:'long', day:'numeric', month:'long', year:'numeric'});
const greeting = () => { const h = new Date().getHours(); return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening'; };
const readAloudOn = () => state.readAloud === null ? state.senior : state.readAloud;
const live = () => state.health.llm && !String(state.health.llm).startsWith('offline');
const protLevel = () => state.data?.protection?.level || 'enhanced';

async function refresh(){
  try{
    const d = await api('/api/state' + (state.sid ? `?session_id=${encodeURIComponent(state.sid)}` : ''));
    state.data = d; state.sid = d.session_id; store.set('sid', d.session_id);
    renderAccounts(); renderBills(); renderHoldings();
    const pill = $('#prot-pill'); if(pill){ pill.className = `pill prot ${protLevel()}`; pill.lastChild.textContent = protLevel() === 'enhanced' ? 'Enhanced protection' : 'Standard protection'; }
    if(['activity', 'contacts', 'settings'].includes(state.page)) renderPage();
  }catch(e){
    if(e.data?.code === 'SESSION_NOT_FOUND'){ state.sid = null; store.set('sid', null); return refresh(); }
    console.error(e);
  }
}

// ---------------------------------------------------------------- Read aloud (browser TTS; slower in Senior mode)
const VOICE_PREFS = ['Samantha','Google US English','Microsoft Aria','Microsoft Jenny','Karen','Moira','Tessa','Serena','Google UK English Female','Victoria'];
let voiceCache = null;
function pickVoice(){
  if(voiceCache) return voiceCache;
  const en = speechSynthesis.getVoices().filter(v => /^en[-_]/i.test(v.lang));
  voiceCache = VOICE_PREFS.map(n => en.find(v => v.name.startsWith(n))).find(Boolean) || en.find(v => /female/i.test(v.name)) || null;
  return voiceCache;
}
if('speechSynthesis' in window) speechSynthesis.onvoiceschanged = () => { voiceCache = null; };
// Spoken question -> spoken answer, in every mode. Typed questions follow the "Read every answer aloud" setting.
function speak(text, force = false){
  const want = force || readAloudOn() || state.voiceTurn;
  if(!want || !('speechSynthesis' in window) || !text) return;
  if(!state.queueSpeech) speechSynthesis.cancel();
  state.queueSpeech = false;
  const u = new SpeechSynthesisUtterance(text); const v = pickVoice();
  if(v){ u.voice = v; u.lang = v.lang; } else u.lang = 'en-US';
  u.rate = state.senior ? 0.82 : 0.95;
  speechSynthesis.speak(u);
}

// ---------------------------------------------------------------- Shell
function render(){
  document.body.classList.toggle('senior', state.senior);
  document.body.classList.toggle('large', state.large && !state.senior);
  const navHtml = NAV.map(([id, label, ic, group]) => (group ? `<div class="nav-label">${group}</div>` : '') +
    `<button class="nav-btn ${state.page === id ? 'active' : ''}" data-page="${id}" ${state.page === id ? 'aria-current="page"' : ''}>${icon(ic)}<span class="nav-text">${label}</span></button>`).join('');
  const current = NAV.find(n => n[0] === state.page)?.[1] || 'Overview';
  $('#app').innerHTML = `
  <div class="layout">
    <nav class="sidebar" aria-label="Main">
      <div class="brand"><img src="/dbs-logo.svg" alt="DBS"><span>digibank</span></div>
      <div class="brand-note">Star · concept prototype</div>
      <div class="nav">${navHtml}</div>
      <div class="side-bottom">
        <div class="trust-mini">${icon('shield')}<div><b>Your money. Your decision.</b><p>Star can only prepare payments. Your phone signs every one.</p></div></div>
        <button class="profile" id="switch-customer" aria-haspopup="true" aria-expanded="false" title="Switch demo customer">
          <span class="avatar">${customer().initials}</span><div>${esc(customer().name)}<small>${customer().tag} · switch customer</small></div></button>
        <div class="customer-menu" id="customer-menu" hidden>${customerChoices()}</div>
      </div>
    </nav>
    <div class="workspace">
      <header class="topbar">
        <div class="breadcrumb">
          <span class="mobile-brand"><img src="/dbs-logo.svg" alt="DBS"><span>digibank</span></span>
          <span class="crumbs">digibank</span><span class="crumbs" aria-hidden="true">›</span><strong class="crumbs">${state.senior ? 'Simple view' : current}</strong>
        </div>
        <div class="top-actions">
          <span class="pill ${live() ? 'live' : ''}" title="Language model"><span class="dot"></span>${live() ? 'Live model' : 'Offline rules'}</span>
          <span class="pill" title="Speech recognition"><span class="dot"></span>${state.health.asr === 'tencent' ? 'Tencent ASR' : 'Browser voice'}</span>
          <button class="pill prot ${protLevel()}" id="prot-pill" title="Account protection level (a bank setting, not a screen setting)" aria-label="${protLevel() === 'enhanced' ? 'Enhanced protection' : 'Standard protection'}">${icon('shield')}${protLevel() === 'enhanced' ? 'Enhanced protection' : 'Standard protection'}</button>
          <button class="icon-btn" id="trace-toggle" aria-pressed="${$('#trace').classList.contains('open')}">${icon('trace')}<span class="label">Agent trace</span></button>
          <button class="senior-toggle" id="senior-toggle" aria-pressed="${state.senior}">${icon('senior')}${state.senior ? 'Standard view' : 'Simple view'}</button>
        </div>
      </header>
      <main id="main" tabindex="-1"></main>
    </div>
  </div>`;
  $('#app').querySelectorAll('.nav-btn').forEach(b => b.onclick = () => go(b.dataset.page));
  $('#switch-customer').onclick = () => { const menu = $('#customer-menu'); menu.hidden = !menu.hidden;
    $('#switch-customer').setAttribute('aria-expanded', String(!menu.hidden)); };
  bindCustomerChoices($('#app'));
  $('#senior-toggle').onclick = () => setSenior(!state.senior);
  $('#trace-toggle').onclick = () => toggleTrace();
  $('#prot-pill').onclick = () => go('settings');
  renderPage();
}
function go(page){ state.page = page; render(); $('#main')?.focus({preventScroll:true}); window.scrollTo(0, 0); }
function setSenior(on){
  state.senior = on; store.set('senior', on);
  if(on) state.page = 'overview';
  render(); toast(on ? 'Simple view. More room, larger text. Take your time.' : 'Standard view');
}
function toggleTrace(force){
  const t = $('#trace'); const open = force ?? !t.classList.contains('open');
  t.classList.toggle('open', open); t.setAttribute('aria-hidden', String(!open));
  $('#trace-toggle')?.setAttribute('aria-pressed', String(open));
}
$('#trace-close').onclick = () => toggleTrace(false);

function renderPage(){
  const m = $('#main'); if(!m) return;
  if(state.page === 'overview') return state.senior ? seniorHome(m) : overview(m);
  ({activity, contacts, audit: auditPage, lab: labPage, settings: settingsPage}[state.page] || overview)(m);
}

// ---------------------------------------------------------------- Overview (standard)
function overview(m){
  m.innerHTML = `
    <section class="hero">
      <div><div class="eyebrow">DBS digibank · Star assistant</div><h1>${greeting()}, ${esc(everyday() ? customer().name.split(' ')[0] : customer().name)}.</h1>
        <p>${everyday() ? 'Pay, transfer and invest by just saying it. You sign every payment.' : 'A little help with your everyday banking. At your pace.'}</p></div>
      <div class="date">${today()}</div>
    </section>
    <section class="accounts" id="accounts" aria-label="Accounts"></section>
    <div class="main-grid">
      ${assistantHtml()}
      <section class="card safety" id="safety" aria-live="polite"></section>
    </div>
    <div class="overview-details">
      <section class="card bills" id="bills"></section>
      <section class="card bills" id="regular"></section>
      <section class="card bills" id="holdings"></section>
      <section class="card bills" id="cards"></section>
    </div>`;
  bindAssistant(); renderAccounts(); renderSafety(); renderBills(); renderHoldings();
}
function seniorHome(m){
  const sav = state.data?.accounts?.[0];
  m.innerHTML = `
    <div class="senior-hello"><div><div class="simple-eyebrow">YOUR EVERYDAY BANKING</div><h1>Hello, ${esc(customer().name)}</h1><p class="simple-intro">One thing at a time. You're in control.</p></div>
      <div class="bal">Savings <b>${esc(sav ? sav.balance : '…')}</b></div></div>
    ${assistantHtml()}`;
  bindAssistant();
}
function renderAccounts(){
  const el = $('#accounts'); const d = state.data;
  if(state.senior && state.page === 'overview'){ const b = $('.senior-hello .bal b'); if(b && d) b.textContent = d.accounts[0].balance; return; }
  if(!el || !d) return;
  const split = s => { const [cur, num] = [s.slice(0, 2), s.slice(2)]; return `<span>${esc(cur)}</span>${esc(num)}`; };
  el.innerHTML = `
    <div class="balance"><div class="label">Total available balance</div><div class="value">${split(d.total_balance)}</div>
      <div class="foot"><span class="dot"></span>Across ${d.accounts.length} accounts · updated just now</div></div>` +
    d.accounts.map(a => `<div class="card acct"><div class="top"><span class="ico">${icon('wallet')}</span><span>•• ${esc(a.account_id.slice(-3))}</span></div>
      <div><div class="value">${split(a.balance)}</div><div class="name">${esc(a.name)}</div></div></div>`).join('');
}
function renderBills(){
  const el = $('#bills'); const d = state.data; if(!el || !d) return;
  const unpaid = d.bills.filter(b => b.status === 'unpaid').length;
  el.innerHTML = `<h3>Upcoming bills <small>${unpaid} due</small></h3>` + d.bills.map(b => `
    <div class="bill"><span class="ico">${icon('bolt')}</span><div>${esc(b.title)}<small>Due ${esc(b.due)}</small></div>
      <div>${esc(b.amount)} ${b.status === 'unpaid' ? `<button class="pay" data-bill="${esc(b.title)}">Pay</button>` : '<span class="paid">Paid</span>'}</div></div>`).join('');
  el.querySelectorAll('.pay').forEach(b => b.onclick = () => send(`Pay the ${b.dataset.bill}`));
}

function renderHoldings(){
  const el = $('#holdings'); const d = state.data; if(!el || !d) return;
  el.innerHTML = `<h3>Investments <small>${esc(d.risk_profile)} profile</small></h3>` + (d.holdings.length ? d.holdings.map(h => `
    <div class="bill"><span class="ico">${icon('chart')}</span><div>${esc(h.name)}<small>${esc(h.asset_class)} · ${esc(h.units)} units</small></div>
      <div class="hold-val">${esc(h.value)}<small class="${h.gain_cents > 0 ? 'up' : h.gain_cents < 0 ? 'down' : ''}">${esc(h.gain)}</small></div></div>`).join('')
    : '<p class="footnote">No investments yet.</p>') +
    `<p class="footnote">Demo prices. Ask "How are my investments doing?"</p>`;
  const cards = $('#cards');
  if(cards) cards.innerHTML = `<h3>Cards</h3>` + (d.cards || []).map(c => `
    <div class="bill"><span class="ico">${icon('wallet')}</span><div>${esc(c.name)}<small>${esc(c.masked)}</small></div>
      <div>${c.status === 'locked' ? '<span class="locked">Locked</span>' : `<button class="pay lock" data-card="${esc(c.name)}">Lock</button>`}</div></div>`).join('') +
    `<p class="footnote">Locking is instant. Unlock in the DBS app or call 1800 111 1111.</p>`;
  cards?.querySelectorAll('.lock').forEach(b => b.onclick = () => send(`Lock my ${b.dataset.card}`));
  renderRegular();
}
// DBS Standing Instructions, GIRO and Limits APIs, in one small panel
function renderRegular(){
  const el = $('#regular'); const d = state.data; if(!el || !d) return;
  const ord = n => n + (n % 100 >= 11 && n % 100 <= 13 ? 'th' : ({1: 'st', 2: 'nd', 3: 'rd'}[n % 10] || 'th'));
  const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  const sis = (d.standing_instructions || []).map(x => `
    <div class="bill"><span class="ico">${icon('transfer')}</span><div>${esc(x.amount)} to ${esc(x.to)}<small>${x.frequency === 'monthly'
      ? `Every month on the ${ord(x.day)}` : `Every ${days[x.day - 1]}`} · next ${esc(x.next)}</small></div></div>`).join('');
  const giro = (d.giro || []).map(g => `
    <div class="bill"><span class="ico">${icon('bolt')}</span><div>${esc(g.biller)}<small>GIRO · ${g.status === 'active' ? `up to ${esc(g.max)}` : esc(g.status)}</small></div></div>`).join('');
  const lim = d.limits || {};
  el.innerHTML = `<h3>Regular payments <small>Daily limit ${esc(lim.daily || '')}${lim.pending ? ` → ${esc(lim.pending)} soon` : ''}</small></h3>` +
    (sis + giro || '<p class="footnote">No regular payments.</p>') +
    `<p class="footnote">Ask Star to set up, stop or change these, or your daily limit.</p>`;
}

// "Behind your request": the checks behind the latest request, in plain words
function decisionPanel(record){
  const labels = {intent:'Intent', plan:'Plan dependencies', policy:'Transaction policy', secondary_approval:'Separate approval', authorization:'Authorization', execution:'Execution'};
  const marks = {pass:'PASS', fail:'FAILED', pending:'PENDING', not_applicable:'NOT REQUIRED'};
  const ex = record.verifier?.extracted || {};
  const cents = v => Number.isInteger(v) ? `S$${(v/100).toFixed(2)}` : 'Not stated';
  return `<details class="decision-panel"><summary>Transaction safety evidence · ${esc(record.action.replaceAll('_',' '))}</summary>
    <p class="footnote">Policy ${esc(record.policy_version)} · ${esc(record.stage)}<br>${esc(record.evidence_scope)}</p>
    <blockquote>${esc(record.raw_text || 'No transcript recorded')}</blockquote>
    <div class="evidence-compare"><div><b>AI draft</b><p>${esc(record.draft?.payee)}<br>${esc(cents(record.draft?.amount_cents))}<br>${esc(record.draft?.from_account)}</p></div>
    <div><b>Validation reading</b><p>${esc(ex.payee || 'Not stated')}<br>${esc(ex.amount == null ? 'Not stated' : 'S$'+ex.amount)}<br>${esc(ex.from_account || 'Not stated')}</p></div></div>
    <p class="footnote">${esc(record.verifier?.engine)}${record.verifier?.mode === 'offline_shared_parser' ? ' · Shared offline parser; not two independent models.' : ''}</p>
    <ol class="contract-checks">${Object.entries(record.checks || {}).map(([key,c]) => `<li class="${esc(c.status)}"><b>${esc(labels[key] || key)}</b><span>${esc(marks[c.status] || c.status)}</span><small>${esc(c.detail)}</small></li>`).join('')}</ol>
    <p><b>Decision:</b> ${esc(record.action.replaceAll('_',' '))}</p>
    <p class="footnote">Rules: ${esc((record.reason_codes || []).join(', ') || 'No risk flags')}<br>Still needed: ${esc((record.required_evidence || []).join(', ') || 'None')}</p>
    </details>`;
}

function bindContractLab(){
  $('#contract-run').onclick = async () => {
    const button = $('#contract-run'); button.disabled = true;
    $('#contract-out').textContent = 'Running isolated fault injection…';
    try{
      const data = await api('/api/lab/contract', {});
      $('#contract-out').innerHTML = `<h3>${data.passed} / ${data.total} scenarios behaved as expected</h3>
        <details class="decision-panel"><summary>How these results were measured</summary><p class="footnote">${esc(data.methodology)}</p></details>
        <div class="contract-cases">${data.cases.map(r => `<article class="contract-case"><h3>${esc(r.title)}</h3>
          <p>${esc(r.principle)} · ${r.fault_injected ? 'Injected fault' : 'Normal control'}</p>
          <p class="${r.expected_behavior_met ? 'contract-pass' : 'contract-fail'}">${r.expected_behavior_met ? 'Expected behavior observed' : 'Unexpected result'} · ${esc(r.code)}</p>
          <p>${esc(Object.entries(r.decision.checks).filter(([k,c])=>k !== 'execution' && c.status === 'fail').map(([,c])=>c.detail).join(' ') || (r.id === 'secondary' ? 'Approval from the separate reviewer is missing.' : ''))}</p>
          <p><b>Ledger debit:</b> S$${(r.ledger_debit_cents/100).toFixed(2)}</p>
          ${r.external_balance_change ? '<p class="footnote">The fixture changes the balance externally before execution; the attempted transaction must debit zero.</p>' : ''}
          ${decisionPanel(r.decision)}</article>`).join('')}</div>
        <h3>Which checks prevent unsafe candidates reaching authorization?</h3>
        <p class="footnote">Counterfactual gate replay on five fixed candidates, including one normal control. This is not a live-model benchmark.</p>
        <div class="contract-table"><table class="table"><thead><tr><th>Checks enabled</th><th>Unsafe admitted</th><th>Normal admitted</th></tr></thead><tbody>
        ${data.comparison.map(r => `<tr><td>${esc(r.label)}</td><td>${r.unsafe_candidates_admitted}/${r.unsafe_candidates}</td><td>${r.normal_candidates_admitted}/${r.normal_candidates}</td></tr>`).join('')}</tbody></table></div>
        <button class="btn secondary" id="contract-download">Download measured evidence</button>`;
      $('#contract-download').onclick = () => download('contract-evidence.json', data);
    }catch(e){$('#contract-out').textContent = e.message;}finally{button.disabled = false;}
  };
  $('#review-inspect').onclick = async () => {
    const out = $('#review-out');
    try{
      const file = $('#review-file').files[0]; if(!file) throw new Error('Select a customer review ticket first.');
      if(file.size > 4096) throw new Error('Review ticket is too large.');
      const ticket = JSON.parse(await file.text());
      const key = $('#review-key').value;
      const request = async operation => {
        const response = await fetch('/api/review/secondary', {method:'POST', headers:{'Content-Type':'application/json','X-Review-Key':key},
          body:JSON.stringify({session_id:ticket.session_id, draft_id:ticket.draft_id, digest:ticket.digest, operation})});
        const data = await response.json(); if(!response.ok) throw new Error(data.error || 'Review failed'); return data;
      };
      const {card} = await request('inspect');
      out.innerHTML = `<h3>Review this exact transaction</h3><p>${esc(card.amount)} to ${esc(card.payee_name)}<br>From ${esc(card.from_account)}</p>
        <blockquote>${esc(card.you_said)}</blockquote><p class="footnote">Card ${esc(card.digest)}</p>
        ${decisionPanel(card.decision)}<button class="btn primary" id="review-approve">Approve as simulated bank reviewer</button>`;
      $('#review-key').value = '';
      $('#review-approve').onclick = async () => {
        const b = $('#review-approve'); b.disabled = true;
        try{await request('approve'); out.textContent = 'Approved for five minutes or until the card expires. The customer must still refresh and sign the exact card.';}
        catch(e){out.textContent = e.message;}
      };
    }catch(e){out.textContent = e.message;}
  };
}

function renderSafety(){
  const el = $('#safety'); if(!el) return;
  const c = state.check;
  const row = (st, title, detail) => `<div class="check ${st}"><span class="s">${{pass:'✓', warn:'!', pending:'…', fail:'✕', idle:'·'}[st]}</span><div>${esc(title)}<small>${esc(detail)}</small></div></div>`;
  const rows = c ? c.rows.map(r => row(...r)).join('') : [
    row('idle', 'Star prepares, never pays', 'The assistant can only draft. It has no tool that moves money.'),
    row('idle', 'Checked against what you said', 'The payee and amount must come from your own words.'),
    row('idle', 'A second, independent check', 'A separate reader re-reads only your words. If anything differs, the payment is frozen.'),
    row('idle', 'Bank safety rules', 'Limits, new payees, unusual amounts, scam signs.'),
    row('idle', 'Your fingerprint signs', 'Your device checks your fingerprint or face and signs the exact payment.'),
  ].join('');
  el.innerHTML = `<div class="safety-head"><span class="shield">${icon('shield')}</span><div><h3>Behind your request</h3>
      <div class="sub">${c ? esc(c.title) : 'What happens before any money moves'}</div></div></div>
    <div class="checks">${rows}</div>${c?.decision ? decisionPanel(c.decision) : ''}
    <button class="text-btn" id="open-trace">Open the full agent trace ›</button>`;
  $('#open-trace').onclick = () => toggleTrace(true);
}
function checksFromCard(card, phase, method){
  if(card.decision){
    const labels = {intent:'Faithful to your words', plan:'Earlier steps completed', policy:'Transaction policy',
      secondary_approval:'Separate approval', authorization:'Your authorization', execution:'Execution'};
    const r = card.decision;
    return {title:`${card.amount} to ${card.payee_name}`, decision:r,
      rows:Object.entries(r.checks).map(([key, c]) => [c.status === 'not_applicable' ? 'idle' : c.status,
        labels[key] || key, c.detail])};
  }
  const v = card.verification || {};
  const FIELD = {payee: 'who', amount: 'amount', from_account: 'account', asset_class: 'asset', type: 'type'};
  const matched = Object.entries(v.fields || {}).filter(([, st]) => st === 'match').map(([k]) => FIELD[k] || k);
  const ver = v.status === 'mismatch' ? ['fail', 'Independent check: does not match', (v.mismatches || []).join(' ')]
    : v.status === 'match' ? ['pass', 'Independent check matched', `A separate reader heard the same ${matched.join(', ') || 'request'}.`]
    : ['warn', 'Independent check unavailable', 'Without it, this payment cannot be signed.'];
  const ev = card.payee_from_user === false ? ['warn', 'Check who this is for', "You didn't mention this person."]
    : card.amount_from_user === false ? ['warn', 'Check the amount', "You didn't say this amount, so it was filled in."]
    : ['pass', 'Matches what you said', card.you_said ? `“${card.you_said}”` : 'Payee and amount come from your words.'];
  const lvl = card.risk_level;
  const rules = lvl === 'LOW' ? ['pass', 'Bank safety rules passed', 'Known payee, usual amount, within limits.']
    : lvl === 'MEDIUM' ? ['warn', 'Please take a second look', card.reasons.join(' ')]
    : lvl === 'HIGH' ? (phase === 'done' ? ['pass', 'Cooling-off completed', card.reasons.join(' ')]
      : ['pending', 'Cooling-off before you can confirm', card.reasons.join(' ')])
    : ['fail', 'Stopped by the rules', card.reasons.join(' ')];
  const auth = phase === 'done' ? ['pass', method === 'passkey' ? 'Signed with your fingerprint / face' : 'Signed after your (simulated) fingerprint',
      'Checked by the bank, then checked again by the payment gateway before the money moved.']
    : phase === 'cancelled' ? ['idle', 'Cancelled', 'No money moved.']
    : phase === 'frozen' ? ['idle', 'Frozen', 'This draft can never be signed. Nothing moved.']
    : lvl === 'BLOCK' ? ['idle', 'Nothing to sign', 'This payment will not be made.']
    : ['pending', 'Waiting for you', 'Nothing moves until you check the card and sign.'];
  const prep = card.kind === 'investment' ? 'in' : 'to';
  return {title: `${card.amount} ${prep} ${card.payee_name}`, rows: [['pass', 'Request understood', `${card.title}: ${card.amount} ${prep} ${card.payee_name}`], ev, ver, rules, auth]};
}

// ---------------------------------------------------------------- Assistant
function assistantHtml(){
  return `<section class="card assistant" aria-label="Star assistant">
    <div class="section-top"><h2>${icon('spark')}Star · your banking assistant</h2>
      <span class="tiny-badge ${live() ? 'live' : ''}">${live() ? 'Live model' : 'Offline rules'}</span></div>
    <div class="stage" id="stage" aria-live="polite"></div>
    <div class="composer-wrap">
      <form class="composer" id="composer">
        <button type="button" class="mic" id="mic" aria-label="Tap to speak, tap again to stop">${icon('mic')}<span>${state.senior ? 'Tap to speak' : 'Speak'}</span></button>
        <label class="sr" for="text">Type your request</label>
        <textarea id="text" rows="1" placeholder="${state.senior ? 'Or type here' : 'e.g. Send 200 to my daughter'}"></textarea>
        <button class="send" type="submit" aria-label="Send">${icon('send')}<span class="label">Send</span></button>
      </form>
      <div class="hint" id="hint" role="status" aria-live="polite" aria-atomic="true"></div>
      <div class="composer-foot">${icon('lock')}Star prepares · you check · your phone signs. No money moves without you.</div>
    </div></section>`;
}
function bindAssistant(){
  const ta = $('#text');
  $('#composer').onsubmit = e => { e.preventDefault(); send(ta.value); };
  ta.onkeydown = e => { if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); send(ta.value); } };
  $('#mic').onclick = micToggle;
  renderStage();
}
const SUGGEST = [
  ['coin', 'Has my pension come in?'], ['family', 'Send 200 to my daughter from my current account'],
  ['users', 'Send 50 to my grandson'], ['transfer', 'Move 1000 to my joint account'],
  ['bolt', 'Pay my credit card bill'], ['family', 'Send 100 to my son every month on the 1st'],
  ['refresh', 'What regular payments do I have?'], ['lock', 'Lower my daily transfer limit to 1000'],
  ['chart', 'Buy 300 dollars of Apple shares'], ['transfer', 'Send 350 to my son and invest 1000 in a fixed deposit'],
  ['alert', 'The police say I must move my savings to a safe account', 'danger'],
];
// Alex (everyday customer): same bank, same safety, quicker conversations
const SUGGEST_EVERYDAY = [
  ['family', 'Send mum 500'], ['bolt', 'Pay my credit card bill in full'], ['users', 'Transfer 45 to Ryan'],
  ['refresh', 'What did I spend this month?'], ['chart', 'Buy 2000 of the STI ETF'],
  ['transfer', 'Move 3000 to my current account, then put half of it in the income fund'],
  ['alert', 'A bank officer called and asked for my OTP to unlock my account', 'danger'],
];
const CUSTOMERS = {
  chen: {name: 'Mdm Chen', initials: 'MC', tag: 'Senior care', about: 'Plain words, amounts read in words, gentle reminders. Enhanced protection.'},
  alex: {name: 'Alex Tan', initials: 'AT', tag: 'Everyday', about: 'Short, direct answers. Same safety checks. Standard protection.'},
};
const customer = () => CUSTOMERS[state.data?.customer] || CUSTOMERS.chen;
const everyday = () => state.data?.persona === 'everyday';
const SUGGEST_SENIOR = [['coin', 'Has my pension come in?'], ['bolt', 'Pay my bills'], ['family', 'Send money to my family'], ['phone', 'Talk to a real person']];
function renderStage(){
  const st = $('#stage'); if(!st) return;
  if(!state.messages.length){
    const list = state.senior ? SUGGEST_SENIOR : everyday() ? SUGGEST_EVERYDAY : SUGGEST;
    st.innerHTML = `<div class="welcome"><span class="spark">${icon('spark')}</span><div>
        <h3>${state.senior ? 'What would you like to do?' : everyday() ? `Hi ${esc(customer().name.split(' ')[0])}, what do you need?` : 'What can I help you with today?'}</h3>
        <p>${state.senior ? 'Choose below, or tap Speak and tell me in your own words.' : everyday() ? 'Type or speak. Every payment still needs your fingerprint.' : "Tell me in your own words. We'll take it one step at a time."}</p></div></div>
      <div class="suggest-label">A place to start</div>
      <div class="suggestions">${list.map(([ic, t, cls]) => `<button class="suggestion ${cls || ''}" data-say="${esc(t)}">${icon(ic)}${esc(t)}</button>`).join('')}</div>`;
    st.querySelectorAll('.suggestion').forEach(b => b.onclick = () => send(b.dataset.say));
    return;
  }
  st.innerHTML = state.messages.map((m, i) => {
    if(m.role === 'user') return `<div class="msg user">${m.demo ? '<small class="demo-tag">Demo input</small>' : ''}${esc(m.text)}</div>`;
    if(m.type === 'demo-intro') return `<div class="demo-intro" role="note"><b>${icon('lab')} Safety test: a broken AI model</b>
      For this test we swap in a model with a deliberate bug: it writes <strong>10&times; the amount</strong> you say.
      The checks after it are the real ones. Watch whether the wrong amount can reach you.</div>`;
    if(m.type === 'caught') return caughtHTML(m);
    if(m.type === 'typing') return `<div class="typing"><span class="thinking-dot" aria-hidden="true"></span>I'm working on your request…</div>`;
    if(m.type === 'choices') return m.done ? '' : `<div class="choices" role="group" aria-label="Choose one">${m.options.map((o, j) =>
      `<button class="choice" data-i="${i}" data-j="${j}"><span>${esc(o.label)}</span><small>${esc(o.detail || '')}</small></button>`).join('')}</div>`;
    if(m.type === 'plan') return `<div class="plan" role="note"><b>I'll do this in ${m.items.length} steps. You check and confirm each one.</b>
      <ol>${m.items.map(x => `<li>${esc(x)}</li>`).join('')}</ol></div>`;
    if(m.type === 'frozen') return `<div class="alert-block frozen" role="alert"><b>Frozen: this didn't match what you said</b>
      <ul>${m.items.map(x => `<li>${esc(x)}</li>`).join('')}</ul><small>A second, independent check re-read your own words. Nothing was sent.</small>
      <div class="acts"><button class="again" type="button">Say it again</button></div></div>`;
    if(m.type === 'blocked') return `<div class="alert-block" role="alert"><b>I've stopped this for you</b>${esc(m.text)}${m.hint ? `<small class="demo-hint">${esc(m.hint)}</small>` : ''}
      <div class="acts"><a href="tel:1799">Call ScamShield 1799</a><button class="notify" type="button">Tell my family</button></div></div>`;
    if(m.type === 'next') return m.done ? '' : `<div class="next-chips"><button class="nx-go" data-i="${i}">Continue: ${esc(m.task)}</button><button class="nx-no" data-i="${i}">Not now</button></div>`;
    return `<div class="msg bot ${m.ok ? 'ok' : ''}"><span class="who">Star</span>${m.receipt ? '<strong class="receipt-heading">Transaction completed</strong>' : ''}${esc(m.text)}<button class="replay" data-i="${i}" aria-label="Read this aloud">🔊</button>${m.receipt ? `<button class="receipt" data-i="${i}">${icon('download')} Download signed receipt</button>` : ''}</div>`;
  }).join('');
  st.querySelectorAll('.choice').forEach(b => b.onclick = () => { const m = state.messages[b.dataset.i]; m.done = true; send(m.options[b.dataset.j].send); });
  st.querySelectorAll('.replay').forEach(b => b.onclick = () => speak(state.messages[b.dataset.i].text, true));
  st.querySelectorAll('.receipt').forEach(b => b.onclick = () => { const r = state.messages[b.dataset.i].receipt; download(`receipt-${r.txn_id}.json`, r); });
  st.querySelectorAll('.again').forEach(b => b.onclick = () => { $('#text')?.focus(); if(state.senior) micToggle(); });
  st.querySelectorAll('.notify').forEach(b => b.onclick = () => push({role:'bot', text:'This demo cannot send family alerts. Please call your family contact, Chen Mei Ling, directly.'}));
  st.querySelectorAll('.nx-go').forEach(b => b.onclick = () => { const m = state.messages[b.dataset.i]; m.done = true; send(m.task); });
  st.querySelectorAll('.nx-no').forEach(b => b.onclick = () => { state.messages[b.dataset.i].done = true; push({role:'bot', text:'OK. Just call me whenever you need me.'}); });
  st.scrollTop = st.scrollHeight;
  st.lastElementChild?.scrollIntoView({block:'nearest'});
}
function push(m){ state.messages.push(m); renderStage(); }

// "Simulate a model mistake": show WHY it stopped, side by side, so nobody wonders why S$50 "failed"
function showCaught(r){
  const c = r.ui.card, d = r.demo, frozen = r.ui.type === 'frozen';
  const heard = d.heard_amount != null ? 'S$' + Number(d.heard_amount).toLocaleString('en-SG', {minimumFractionDigits: 2}) : 'no amount';
  push({type:'caught', said: d.said, drafted: c.amount, payee: c.payee_name, heard, frozen});
  speak(`Safety test passed. The faulty model wrote ${c.amount}, but the independent check heard ${heard}. ` +
        `It was stopped before you were asked to confirm. Nothing was sent.`);
  state.check = {title: 'Safety test passed', rows: [
    ['fail', 'Faulty AI draft', `${c.amount} to ${c.payee_name}: the planted 10× bug`],
    ['pass', 'Independent check', `Re-read your words, heard ${heard}: mismatch found`],
    ['pass', frozen ? 'Frozen' : 'Blocked', 'No confirmation card, nothing to sign'],
    ['pass', 'Your money', 'S$0 moved']]};
  renderSafety(); refresh();
}
function caughtHTML(m){
  const stage = (label, cls, note) => `<li class="${cls}"><span>${label}</span><small>${note}</small></li>`;
  return `<div class="caught" role="alert">
    <div class="caught-head"><span class="caught-badge">${m.frozen ? 'Caught and frozen' : 'Caught and blocked'}</span>
      <b>The wrong amount never reached you. Nothing was sent.</b></div>
    <div class="caught-grid">
      <div class="cg said"><small>1 · You said</small><strong class="quote">“${esc(m.said)}”</strong><span>to ${esc(m.payee)}</span></div>
      <div class="cg bad"><small>2 · The faulty model drafted</small><strong>${esc(m.drafted)}</strong><span>10&times; too much (the planted bug)</span></div>
      <div class="cg good"><small>3 · The independent check heard</small><strong>${esc(m.heard)}</strong><span>it re-read your own words only</span></div>
    </div>
    <ol class="caught-path">
      ${stage('AI draft', 'x', 'wrong amount')}${stage('2nd check', 'ok', 'mismatch found')}
      ${stage('Card', 'skip', 'never shown')}${stage('Fingerprint', 'skip', 'never asked')}${stage('Your money', 'ok', 'S$0 moved')}
    </ol>
    <small class="caught-foot">Why this matters: an AI can mishear or make things up. Here it can only write a draft, and a second,
      independent check compares that draft with what you actually said before anything is shown or signed.</small>
  </div>`;
}
// After a payment is confirmed, the next step of the user's own plan is prepared right away (it still needs its own
// confirmation). After a cancel we ask instead, because the user may have changed their mind.
function continueWith(task, payment = true){
  setTimeout(() => {
    push({role:'bot', text: payment ? `Next step: “${task}”. I'm preparing it now — you'll check and confirm it the same way.`
                                    : `Next: “${task}”.`});
    state.queueSpeech = true;                        // don't cut off the "Done" read-out; queue after it
    send(task, '/api/chat', state.voiceTurn, true);
  }, 300);
}
function offerNext(task){
  setTimeout(() => { push({role:'bot', text:`You also asked: “${task}”. Shall we do that now?`}); push({type:'next', task}); }, 500);
}
// After a page refresh the server may still hold a payment waiting for the fingerprint: bring its card back.
async function restorePending(){
  if(state.data?.pending_change && !['AWAITING_AUTH', 'COOLING'].includes(state.data?.phase)){
    push({role:'bot', text:`You have a change waiting: ${state.data.pending_change.title}. Please check it and confirm, or cancel it.`});
    return openChange(state.data.pending_change);
  }
  if(!['AWAITING_AUTH', 'COOLING'].includes(state.data?.phase)) return;
  try{
    const r = await api('/api/card/' + encodeURIComponent(state.sid));
    if(!r.card) return;
    state.check = checksFromCard(r.card, 'pending'); renderSafety();
    push({role:'bot', text:`You have a payment waiting: ${r.card.amount} ${r.card.kind === 'investment' ? 'in' : 'to'} ${r.card.payee_name}. Please check it and confirm, or cancel it.`});
    openConfirm(r.card);
  }catch{}
}

function stopSpeaking(){ try{ speechSynthesis?.cancel(); }catch{} }
async function send(text, endpoint = '/api/chat', voice = false, auto = false, demo = false){
  text = String(text || '').trim(); if(!text || state.busy) return;
  if(!auto) stopSpeaking();                         // a new question interrupts the previous answer
  state.voiceTurn = voice;
  if(state.page !== 'overview') go('overview');
  state.busy = true; $('#text') && ($('#text').value = '');
  state.messages = state.messages.filter(m => m.type !== 'choices' || m.done);
  if(demo) push({type:'demo-intro'});
  push({role:'user', text, demo}); push({type:'typing'});
  try{
    const r = await api(endpoint, {session_id: state.sid, text});
    state.sid = r.session_id; store.set('sid', r.session_id);
    state.messages = state.messages.filter(m => m.type !== 'typing');
    addTrace(r.trace); handleTurn(r);
  }catch(e){
    state.messages = state.messages.filter(m => m.type !== 'typing');
    push({role:'bot', text: e.status === 403 ? e.message : 'There was a connection problem. Please try again.'}); console.error(e);
  }finally{ state.busy = false; }
}
function handleTurn(r){
  const ui = r.ui || {type:'text'};
  if(r.demo?.kind === 'model_mistake' && ui.card){ showCaught(r); return; }
  if(ui.plan?.length > 1) push({type:'plan', items: ui.plan});
  if(ui.type === 'blocked' && !ui.card){
    push({type:'blocked', text:r.reply, hint: ui.hint}); speak(r.speak);
    state.check = {title:'Stopped before reaching the payment step', rows:[
      ['pass', 'Request heard', 'We listened to everything you said.'],
      ['fail', 'Looks like a scam', (ui.reasons || []).join(' ') || 'This matches common scam patterns.'],
      ['idle', 'No payment prepared', 'Star did not draft anything.'], ['idle', 'Nothing to sign', 'Your money stays where it is.']]};
    renderSafety(); return;
  }
  push({role:'bot', text:r.reply}); speak(r.speak);
  if(ui.type === 'change'){ openChange(ui.card); if(ui.next_task) continueWith(ui.next_task, false); refresh(); return; }
  if(ui.card){ state.check = checksFromCard(ui.card, ui.type === 'blocked' ? 'blocked' : ui.type === 'frozen' ? 'frozen' : 'pending'); renderSafety();
    if(ui.type === 'blocked') push({type:'blocked', text: ui.card.reasons.join(' ')});
    else if(ui.type === 'frozen') push({type:'frozen', items: ui.card.verification.mismatches});
    else openConfirm(ui.card); }
  if(ui.type === 'choose') push({type:'choices', options: ui.options});
  if(ui.next_task) continueWith(ui.next_task, false);
  if(ui.offer_next) offerNext(ui.offer_next);
  refresh();
}

// ---------------------------------------------------------------- Account change card (add payee / raise limit / GIRO)
// Same idea as a payment: code builds the card from the request, the device signs exactly this change.
function openChange(c){
  state.card = null; state.change = c;
  renderChange(); const dlg = $('#confirm'); if(!dlg.open) dlg.showModal();
  setTimeout(() => $('#c-go')?.focus(), 50);
}
function renderChange(){
  const c = state.change; if(!c) return;
  $('#confirm').innerHTML = `
    <div class="cbody">
      <h2 id="c-title">${esc(c.title)}</h2>
      <p class="review-intro">Take a moment to check the details. Nothing changes until you confirm. You can cancel below.</p>
      ${c.you_said ? `<div class="said"><span class="k">Based on what you said</span><q>${esc(c.you_said)}</q></div>` : ''}
      ${c.rows.map(([k, v]) => `<div class="crow"><span class="k">${esc(k)}</span><span class="v">${esc(v)}</span></div>`).join('')}
      <div class="risk MEDIUM"><b>Before you confirm</b><ul><li>${esc(c.note)}</li></ul></div>
    </div>
    <div class="cfoot">
      <button type="button" class="btn secondary" id="c-cancel">Cancel</button>
      <button type="button" class="btn primary" id="c-go" ${state.signMode === 'none' ? 'disabled' : ''}>${icon('fingerprint')}Confirm with fingerprint</button>
    </div>
    <div class="signnote">Confirmation code ${esc(c.digest.slice(0, 8))}…${esc(c.digest.slice(-4))} · Star can only ask for this change; it happens only after your device signs exactly this card.</div>`;
  $('#c-cancel').onclick = async () => {
    const ch = state.change; closeConfirm();
    try{ const r = await api('/api/change/cancel', {session_id: state.sid, change_id: ch.change_id}); push({role:'bot', text:r.reply}); speak(r.speak); }catch(e){ push({role:'bot', text:e.message}); }
    refresh();
  };
  $('#c-go').onclick = () => { stopSpeaking(); confirmChange(); };
}
async function confirmChange(){
  const c = state.change; const btn = $('#c-go'); btn.disabled = true; btn.textContent = 'Touch the sensor…';
  try{
    if(state.signMode === 'device' && !state.data?.passkey?.enrolled) await mockFingerprint({what: c.title});
    await ensureSigner();
    const ch = await api('/api/change/challenge', {session_id: state.sid, change_id: c.change_id});
    const assertion = await signPayload(ch.payload, ch.passkey);
    const r = await api('/api/change/confirm', {session_id: state.sid, change_id: c.change_id, assertion});
    closeConfirm(); addTrace(r.trace); push({role:'bot', text:r.reply, ok:true}); speak(r.speak);
    if(r.next_task) continueWith(r.next_task);
    refresh();
  }catch(e){
    const msg = e.name === 'NotAllowedError' ? 'The fingerprint check was cancelled. Nothing was changed.' : e.message;
    addTrace(e.data?.trace); push({role:'bot', text:msg}); speak(msg);
    if(['NO_CHANGE', 'EXPIRED'].includes(e.data?.code)) closeConfirm(); else renderChange();
  }
}

// ---------------------------------------------------------------- Confirmation card
function openConfirm(c){
  state.change = null;
  state.card = c; state.verify = null; clearInterval(state.coolTimer);
  renderConfirm(); const dlg = $('#confirm'); if(!dlg.open) dlg.showModal();
  setTimeout(() => $('#c-go')?.focus(), 50);
  if(c.cooldown_left > 0){
    state.coolTimer = setInterval(async () => {
      state.card.cooldown_left = Math.max(0, state.card.cooldown_left - 1);
      if(state.card.cooldown_left === 0){
        clearInterval(state.coolTimer);
        try{ const r = await api('/api/card/' + state.sid); if(r.card) state.card = r.card; }catch{}
      }
      renderConfirm();
    }, 1000);
  }
}
function renderConfirm(){
  const c = state.card; if(!c) return;
  const needVerify = !!c.verify_question, cooling = c.cooldown_left > 0;
  const canGo = c.can_confirm && !cooling && (!needVerify || state.verify === true) && state.signMode !== 'none';
  const rel = c.payee_relation ? ` (${esc(c.payee_relation)})` : '';
  $('#confirm').innerHTML = `
    <div class="cbody">
      <h2 id="c-title">${esc(c.title)}</h2>
      <p class="review-intro">Check the recipient, amount and account. Nothing is sent until you confirm. You can cancel below.</p>
      ${c.you_said ? `<div class="said"><span class="k">Based on what you said</span><q>${esc(c.you_said)}</q></div>` : ''}
      <div class="crow ${c.payee_from_user === false ? 'unsaid' : ''}"><span class="k">${c.kind === 'investment' ? 'Invest in' : 'To'}</span><span class="v">${esc(c.payee_name)}${rel}<small>${esc(c.payee_account)}</small>
        ${c.payee_from_user === false ? `<span class="flag">You didn't mention this ${c.kind === 'investment' ? 'product' : 'person'}</span>` : ''}</span></div>
      ${c.kind === 'investment' ? `<div class="crow"><span class="k">Asset</span><span class="v">${esc(c.asset_class)}</span></div>` : ''}
      <div class="crow amount ${c.amount_from_user === false ? 'unsaid' : ''}"><span class="k">Amount</span>
        <div class="amt">${esc(c.amount)}</div><div class="words">${esc(c.amount_words)}${c.amount_note ? ' · ' + esc(c.amount_note) : c.amount_source === 'bill' ? ' · exact amount from your bill' : ''}</div>
        ${c.amount_from_user === false ? '<span class="flag">You didn\'t say this amount — please check it</span>' : ''}</div>
      <div class="crow"><span class="k">From</span><span class="v">${esc(c.from_account)}</span></div>
      ${c.schedule ? `<div class="crow"><span class="k">Repeats</span><span class="v">${esc(c.schedule)}<small>Nothing is taken today. You can stop it any time.</small></span></div>` : ''}
      ${c.verification?.status === 'match' ? `<div class="vcheck">${icon('shield')}<span>${/offline/i.test(c.verification.engine) ? 'An offline check (shared parser)' : 'A separate model check'} matched your transaction details.</span></div>` : ''}
      ${c.secondary_required ? `<div class="secondary-wait"><b>Separate approval needed</b><p>A demo bank reviewer must approve this exact payment. You will still need to sign afterwards.</p><button type="button" class="btn secondary" id="review-ticket">Download review ticket</button><button type="button" class="btn secondary" id="review-refresh">Check approval status</button><small>Simulated review channel; not a real bank callback.</small></div>` : ''}
      ${c.decision ? decisionPanel(c.decision) : ''}
      ${c.risk_level !== 'LOW' ? `<div class="risk ${esc(c.risk_level)}"><b>${c.risk_level === 'MEDIUM' ? 'Please take a second look' : "For your safety, let's wait a little"}</b><ul>${c.reasons.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}
      ${needVerify ? `<div class="verify"><div class="q">${esc(c.verify_question)}</div><div class="yesno">
        <button type="button" data-v="yes" aria-pressed="${state.verify === true}">Yes</button>
        <button type="button" data-v="no" aria-pressed="${state.verify === false}">No / Not sure</button></div></div>` : ''}
      ${state.uvFail ? `<div class="uvhelp">${icon('fingerprint')}<div><b>Your fingerprint wasn't checked</b><small>A password manager signed without asking for your fingerprint, face or PIN, so the bank refused it. Set it up again and choose <b>Windows Hello / this device</b> when asked where to save it.</small>
        <button type="button" class="btn secondary" id="c-repk">Set up fingerprint again</button></div></div>` : ''}
      ${cooling ? `<div class="cool">Please wait ${c.cooldown_left} more second${c.cooldown_left === 1 ? '' : 's'}<small>A good moment to call your family and check.</small></div>` : ''}
    </div>
    <div class="cfoot">
      <button type="button" class="btn secondary" id="c-cancel">Cancel</button>
      <button type="button" class="btn primary" id="c-go" ${canGo ? '' : 'disabled'}>${icon('fingerprint')}${state.signMode === 'none' ? "Can't sign in this browser" : 'Confirm with fingerprint'}</button>
    </div>
    <div class="signnote">Confirmation code ${esc(c.digest.slice(0, 8))}…${esc(c.digest.slice(-4))} · ${state.signMode === 'none' ? esc(NO_SIGNER) : state.signMode === 'device'
      ? "demo: the fingerprint sensor is simulated. Your tap unlocks this browser's private key, which signs exactly this card; the bank and its payment gateway each verify that signature."
      : "your device checks your fingerprint or face, then signs exactly this card. The bank and its payment gateway each verify the signature."}</div>`;
  $('#confirm').querySelectorAll('.yesno button').forEach(b => b.onclick = () => {
    state.verify = b.dataset.v === 'yes';
    if(state.verify === false){ const t = "That's OK. If you're not sure, let's not send it yet. You can check with your family first."; push({role:'bot', text:t}); speak(t); }
    renderConfirm();
  });
  $('#c-cancel').onclick = cancelCard;
  $('#c-go').onclick = () => { stopSpeaking(); confirmCard(); };
  $('#review-ticket') && ($('#review-ticket').onclick = () => download('review-ticket.json', {
    session_id:state.sid, draft_id:c.draft_id, digest:c.digest}));
  $('#review-refresh') && ($('#review-refresh').onclick = async () => {
    try{const r = await api('/api/card/' + state.sid); if(r.card){state.card = r.card; renderConfirm();}}
    catch(e){toast(e.message);}
  });
  $('#c-repk') && ($('#c-repk').onclick = async () => {
    try{
      await removePasskey(); await refresh(); await enrolPasskey();
      state.uvFail = false; renderConfirm(); toast('Fingerprint set up again. Check the card and confirm.');
    }catch(e){ toast(e.name === 'NotAllowedError' ? 'Set-up was cancelled. Nothing changed.' : e.message); }
  });
}
$('#confirm').addEventListener('cancel', e => { e.preventDefault(); cancelCard(); });
function closeConfirm(){ clearInterval(state.coolTimer); const d = $('#confirm'); if(d.open) d.close(); state.card = null; state.change = null; state.uvFail = false; }
async function cancelCard(){
  const c = state.card; if(!c || state.confirming) return;
  try{
    const r = await api('/api/cancel', {session_id: state.sid, draft_id: c.draft_id}); closeConfirm(); push({role:'bot', text:r.reply}); speak(r.speak);
    if(r.next_task) offerNext(r.next_task);
    state.check = checksFromCard({...c, decision:r.decision}, 'cancelled'); renderSafety();
  }catch(e){ push({role:'bot', text:'Cancellation could not be confirmed. The payment is still waiting. Please try again.'}); renderConfirm(); }
}
async function confirmCard(){
  const c = state.card; const btn = $('#c-go');
  if(!c || state.confirming) return;
  state.confirming = true; let submitted = false;
  btn.disabled = true; btn.textContent = 'Touch the sensor…';
  const verify_answer = c.verify_question ? state.verify : null;
  try{
    if(state.signMode === 'device' && !state.data?.passkey?.enrolled) await mockFingerprint(c);
    await ensureSigner();
    const ch = await api('/api/challenge', {session_id: state.sid, draft_id: c.draft_id, digest: c.digest, verify_answer});
    const assertion = await signPayload(ch.payload, ch.passkey);
    submitted = true; store.set('pendingPayment', {sid:state.sid, card:c});
    const r = await api('/api/confirm', {session_id: state.sid, draft_id: c.draft_id, digest: c.digest, assertion, verify_answer});
    store.set('pendingPayment', null); closeConfirm(); addTrace(r.trace);
    push({role:'bot', text: r.reply, ok: true, receipt: r.receipt?.verifiable}); speak(r.speak);
    state.check = checksFromCard({...c, decision:r.receipt?.verifiable?.decision}, 'done', r.receipt?.verifiable?.authorization?.method); renderSafety();
    if(r.next_task) continueWith(r.next_task);      // multi-step request: go straight on to the next step
    refresh();
  }catch(e){
    if(submitted && (!e.status || e.status >= 500)){ await recoverPayment(c); return; }
    store.set('pendingPayment', null);
    const msg = e.name === 'NotAllowedError' ? 'The fingerprint check was cancelled or timed out. Nothing was sent.'
      : e.name === 'SecurityError' ? `Fingerprint signing needs a website name, not an address like ${location.hostname}. Please open http://localhost:${location.port || 80} and try again. Nothing was sent.`
      : e.message;
    addTrace(e.data?.trace);
    if(e.data?.decision){state.check = checksFromCard({...c, decision:e.data.decision}, 'rejected'); renderSafety();}
    if(e.data?.code === 'UV_REQUIRED'){ state.uvFail = true; push({role:'bot', text:UV_HELP}); speak(UV_HELP); }
    else { push({role:'bot', text:msg}); speak(msg); }
    if(['NOT_AWAITING_AUTH', 'RECHECK_BLOCKED'].includes(e.data?.code) || String(e.data?.code || '').startsWith('GW_')) closeConfirm(); else renderConfirm();
  }finally{ state.confirming = false; }
}

async function recoverPayment(c){
  try{
    const r = await api(`/api/transaction/${encodeURIComponent(state.sid)}/${encodeURIComponent(c.draft_id)}`);
    if(r.status === 'SUCCESS'){
      store.set('pendingPayment', null); closeConfirm();
      push({role:'bot', text:r.reply, ok:true, receipt:r.receipt?.verifiable});
      state.check = checksFromCard({...c, decision:r.receipt?.verifiable?.decision}, 'done'); renderSafety(); await refresh(); return;
    }
  }catch{}
  push({role:'bot', text:'Payment status is uncertain. Check its status before making another payment.'});
  const btn = $('#c-go'); btn.disabled = false; btn.textContent = 'Check payment status';
  btn.onclick = () => recoverPayment(c);
  $('#c-cancel').disabled = true;
}

async function removePasskey(){
  const ch = await api('/api/passkey/remove/challenge', {session_id:state.sid});
  const assertion = await signPayload(ch.payload, ch.passkey);
  await api('/api/passkey/remove', {session_id:state.sid, assertion});
}


// ---------------------------------------------------------------- Signing: passkey (real fingerprint / face) first
// A passkey lives in the device's secure hardware and is unlocked by the OS's own biometric prompt (Touch ID,
// Face ID, Windows Hello). We ask for userVerification "required" and sign SHA-256 of the exact payment payload.
// Devices without one fall back to a non-extractable browser key (no biometric; the UI says so).
const NO_SIGNER = "This browser can't check your fingerprint or face, so it can't sign payments. On iPhone open the link in Safari, " +
  "on Android or a computer in Chrome (not inside an app like WeChat), on a device with a screen lock. Nothing was sent.";
const UV_HELP = "Your device signed without checking your fingerprint, face or PIN, so the bank refused it. Nothing was sent. " +
  "This happens when a password manager (for example Microsoft Password Manager in Edge) holds the passkey. Tap " +
  "\u201cSet up fingerprint again\u201d, and when your computer asks where to save it, choose Windows Hello / this device.";
const b64u = buf => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), ch => ch.charCodeAt(0));
const IP_HOST = /^(\d{1,3}(\.\d{1,3}){3}|\[.*\])$/;
// 'device'      DEFAULT for the demo: a simulated fingerprint screen, then this browser's non-extractable key signs
//               the exact card (the DBS brief allows mock biometrics; signatures and gateway checks are real)
// 'passkey'     opt-in (Settings): this device's real Touch ID / Face ID / Windows Hello
// 'passkey-any' opt-in on a device without a sensor: the browser offers a phone (QR code) or a security key
// 'none'        this browser can't sign at all
const browserKeyAllowed = () => state.health.browser_key !== false;
const passkeyMode = () => state.signMode === 'passkey' || state.signMode === 'passkey-any';
const realBioOn = () => !!store.get('realBio', false);
const canDeviceSign = () => !!(window.crypto?.subtle && window.indexedDB);
async function passkeyCapability(){
  if(IP_HOST.test(location.hostname) || !window.PublicKeyCredential || !window.isSecureContext) return null;
  try{ return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable() ? 'passkey' : 'passkey-any'; }catch{ return null; }
}
async function detectSignMode(){
  const real = await passkeyCapability();
  if(real && (realBioOn() || state.data?.passkey?.enrolled || !browserKeyAllowed())) return real;
  return browserKeyAllowed() && canDeviceSign() ? 'device' : (real || 'none');
}

// The demo's fingerprint sensor: a clearly labelled simulation. Tapping it is the user's explicit approval; what
// follows is real cryptography (the browser key signs the exact card, the bank and the gateway verify it).
function mockFingerprint(c){
  return new Promise((resolve, reject) => {
    const host = $('#confirm'); if(!host){ reject(new Error('No card')); return; }
    host.querySelector('.mockfp')?.remove();
    const el = document.createElement('div');
    el.className = 'mockfp'; el.setAttribute('role', 'group'); el.setAttribute('aria-label', 'Simulated fingerprint sensor');
    el.innerHTML = `<div class="mf-badge">Demo · simulated fingerprint sensor</div>
      <button type="button" class="mf-pad" aria-label="Touch to confirm">${icon('fingerprint')}</button>
      <b class="mf-title">Touch the sensor to confirm</b>
      <div class="mf-what">${esc(c.what || `${c.amount} ${c.kind === 'investment' ? 'in' : 'to'} ${c.payee_name}`)}</div>
      <small>In the real DBS app this is Face ID or Touch ID. Here, your tap unlocks this browser's private key,
        which signs exactly this card. The bank and its payment gateway each check that signature.</small>
      <button type="button" class="btn secondary mf-cancel">Cancel</button>`;
    host.appendChild(el);
    const pad = el.querySelector('.mf-pad'); pad.focus();
    let done = false;
    pad.onclick = () => {
      if(done) return; done = true;
      el.classList.add('scanning'); el.querySelector('.mf-title').textContent = 'Reading fingerprint…';
      setTimeout(() => {
        el.classList.remove('scanning'); el.classList.add('matched');
        el.querySelector('.mf-title').textContent = 'Fingerprint matched (simulated)';
        setTimeout(() => { el.remove(); resolve(); }, 450);
      }, 900);
    };
    el.querySelector('.mf-cancel').onclick = () => { el.remove(); const e = new Error('Cancelled'); e.name = 'NotAllowedError'; reject(e); };
  });
}
async function ensureSigner(){
  if(state.signMode === 'none') throw new Error(NO_SIGNER);
  if(passkeyMode()){
    if(!state.data?.passkey?.enrolled){ toast('First time: your device will ask you to save a passkey for Star.'); await enrolPasskey(); }
  }else if(!state.data?.passkey?.enrolled){
    await ensureDeviceKey();
  }
}
async function enrolPasskey(){
  const o = await api('/api/passkey/options', {session_id: state.sid});
  const cred = await navigator.credentials.create({publicKey: {
    challenge: unb64u(o.challenge), rp: {id: o.rp_id, name: o.rp_name},
    user: {id: unb64u(o.user_id), name: o.user_name, displayName: o.display_name},
    pubKeyCredParams: [{type: 'public-key', alg: -7}, {type: 'public-key', alg: -257}],   // ES256 (Mac, phones) or RS256 (some Windows Hello)
    timeout: 60000, attestation: 'none',
    // A built-in sensor when there is one; otherwise let the browser offer a phone (QR code) or a security key
    authenticatorSelection: {...(state.signMode === 'passkey' ? {authenticatorAttachment: 'platform'} : {}),
                             userVerification: 'required', residentKey: 'discouraged'},
    excludeCredentials: o.exclude.map(id => ({type: 'public-key', id: unb64u(id)})),
  }});
  const r = await api('/api/passkey/register', {session_id: state.sid, credential_id: b64u(cred.rawId),
    client_data_json: b64u(cred.response.clientDataJSON), attestation_object: b64u(cred.response.attestationObject)});
  addTrace([{kind:'sign', label:`Passkey ${r.key_id} enrolled: your device's fingerprint / face check now signs your payments`}]);
  await refresh(); return r;
}
async function signPayload(payload, passkey){
  if(passkey?.enrolled && !await passkeyCapability())
    throw new Error('Your account signs payments with the real fingerprint or face check on the device where you set it up. ' +
      'Please use that device, or turn off "Real Face ID / fingerprint" in Settings for this demo.');
  if(passkey?.enrolled){
    const challenge = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
    const a = await navigator.credentials.get({publicKey: {challenge, rpId: location.hostname, userVerification: 'required', timeout: 60000,
      allowCredentials: passkey.credential_ids.map(id => ({type: 'public-key', id: unb64u(id)}))}});
    addTrace([{kind:'sign', label:'Your device checked your fingerprint / face and signed the exact card (passkey, ES256)', detail: JSON.parse(payload)}]);
    return {type: 'webauthn', payload, credential_id: b64u(a.rawId), authenticator_data: b64u(a.response.authenticatorData),
      client_data_json: b64u(a.response.clientDataJSON), signature: b64u(a.response.signature)};
  }
  const keyId = await ensureDeviceKey();
  const signature = await deviceSign(payload);
  addTrace([{kind:'sign', label:`Simulated fingerprint approved; browser key ${keyId} signed the exact card (ECDSA P-256)`, detail: JSON.parse(payload)}]);
  return {payload, signature};
}

// Fallback: a non-extractable ECDSA P-256 key in this browser (IndexedDB). The server only sees the public half.
const KEYDB = {name:'star-device', store:'keys', id:'device-key'};
const idb = () => new Promise((ok, no) => { const r = indexedDB.open(KEYDB.name, 1);
  r.onupgradeneeded = () => r.result.createObjectStore(KEYDB.store); r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error); });
async function idbGet(){ const db = await idb(); return new Promise((ok, no) => { const t = db.transaction(KEYDB.store).objectStore(KEYDB.store).get(KEYDB.id); t.onsuccess = () => ok(t.result); t.onerror = () => no(t.error); }); }
async function idbPut(v){ const db = await idb(); return new Promise((ok, no) => { const t = db.transaction(KEYDB.store, 'readwrite').objectStore(KEYDB.store).put(v, KEYDB.id); t.onsuccess = () => ok(); t.onerror = () => no(t.error); }); }
let deviceKey = null;
async function ensureDeviceKey(){
  if(!window.crypto?.subtle) throw new Error('This browser cannot create a secure signing key. Please open the app via localhost or HTTPS.');
  if(!deviceKey) deviceKey = await idbGet().catch(() => null);
  if(!deviceKey){
    const pair = await crypto.subtle.generateKey({name:'ECDSA', namedCurve:'P-256'}, false, ['sign', 'verify']);
    deviceKey = {privateKey: pair.privateKey, publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey)};
    await idbPut(deviceKey).catch(() => {});
  }
  const {kty, crv, x, y} = deviceKey.publicJwk;
  const r = await api('/api/key', {session_id: state.sid, public_key: {kty, crv, x, y}});
  state.keyId = r.key_id; return r.key_id;
}
async function deviceSign(payload){
  const sig = await crypto.subtle.sign({name:'ECDSA', hash:'SHA-256'}, deviceKey.privateKey, new TextEncoder().encode(payload));
  return b64(sig);
}

// ---------------------------------------------------------------- Agent trace
function addTrace(items){
  const list = $('#tlist');
  (items || []).forEach(it => {
    const el = document.createElement('div');
    el.className = 'ti' + (it.kind === 'user' ? ' turn' : '');
    el.innerHTML = `<div class="k k-${esc(it.kind)}">${esc(KIND[it.kind] || it.kind)}</div><div class="l">${esc(it.label)}</div>` +
      (it.detail !== undefined ? `<details><summary>Details</summary><pre>${esc(JSON.stringify(it.detail, null, 2))}</pre></details>` : '');
    list.appendChild(el);
  });
  list.scrollTop = list.scrollHeight;
}

// ---------------------------------------------------------------- Other pages
function head(eyebrow, title, sub){ return `<div class="page-head"><div class="eyebrow">${eyebrow}</div><h1>${title}</h1>${sub ? `<p>${sub}</p>` : ''}</div>`; }
function activity(m){
  const d = state.data;
  m.innerHTML = head('Your workspace', 'Transactions', 'Recent activity on your accounts. Payments made with Star come with a signed receipt.') + `
    <section class="card"><div class="table-scroll"><table class="table"><thead><tr><th>Date</th><th>Description</th><th class="num">Amount</th></tr></thead>
      <tbody>${(d?.transactions || []).map(t => `<tr><td>${esc(t.date)}</td><td>${esc(t.desc)}</td><td class="num ${t.amount_cents > 0 ? 'in' : ''}">${esc(t.amount)}</td></tr>`).join('')}</tbody></table></div></section>
    <section class="card panel page-gap"><h2>Signed receipts</h2>
      ${(d?.receipts || []).length ? `<table class="table"><tbody>${d.receipts.map((r, i) => `<tr><td>${esc(r.txn_id)}</td><td>${esc(r.card.payee_name)}<small class="method">${r.authorization?.method === 'passkey' ? 'Fingerprint / face (passkey)' : 'Simulated fingerprint + device key'}</small></td>
        <td class="num">S$${(r.card.amount_cents / 100).toFixed(2)}</td><td class="num"><button class="btn secondary dl" data-i="${i}">${icon('download')}Download</button></td></tr>`).join('')}</tbody></table>
        <p class="footnote">Anyone can check a receipt offline: <code class="k">python scripts/verify_receipt.py receipt.json</code></p>`
      : '<p class="footnote">No payments in this session yet.</p>'}</section>`;
  m.querySelectorAll('.dl').forEach(b => b.onclick = () => { const r = d.receipts[b.dataset.i]; download(`receipt-${r.txn_id}.json`, r); });
}
function contacts(m){
  const d = state.data;
  const people = (d?.payees || []).filter(p => p.type === 'person'), billers = (d?.payees || []).filter(p => p.type !== 'person');
  const card = p => `<div class="card contact"><span class="avatar">${esc(p.name.split(' ').map(w => w[0]).join('').slice(0, 2))}</span><div><b>${esc(p.name)}</b><small>${esc(p.relation)} · ${esc(p.masked_account)}</small></div></div>`;
  m.innerHTML = head('Your workspace', 'Payees', 'Star can only send money to people saved here. Adding a new payee needs the bank app or a branch.') +
    `<div class="contacts">${people.map(card).join('')}</div><h2 class="sub-head">Billers</h2><div class="contacts">${billers.map(card).join('')}</div>`;
}
async function auditPage(m){
  m.innerHTML = head('Trust & transparency', 'Audit trail', 'Every step is appended to a hash chain: each record carries the hash of the one before, so edits are detectable.') +
    `<section class="card panel"><div class="row-actions"><span id="integrity" class="status ok">Checking…</span>
      <button class="btn secondary" id="a-refresh">${icon('refresh')}Refresh</button><button class="btn secondary" id="a-export">${icon('download')}Export JSON</button></div>
      <div id="entries" class="lab-list"></div></section>`;
  const load = async () => {
    const a = await api(`/api/audit/session/${encodeURIComponent(state.sid)}`);
    $('#integrity').className = 'status ' + (a.integrity.ok ? 'ok' : 'bad');
    $('#integrity').textContent = a.integrity.ok ? `✓ Chain intact · ${a.integrity.records} records` : `✕ Chain broken at line ${a.integrity.broken_at_line}`;
    $('#entries').innerHTML = a.entries.length ? a.entries.slice().reverse().map(e => `<div class="audit-entry"><b>${esc(e.event)}</b>
      <div class="meta">${new Date(e.ts * 1000).toLocaleTimeString()} · ${esc(e.hash.slice(0, 16))}…</div>
      <details><summary>Details</summary><pre>${esc(JSON.stringify(e.data, null, 2))}</pre></details></div>`).join('') : '<p class="footnote">No activity in this session yet.</p>';
    $('#a-export').onclick = () => download(`audit-${state.sid}.json`, a);
  };
  $('#a-refresh').onclick = load; load().catch(e => toast(e.message));
}
function labPage(m){
  m.innerHTML = head('Trust & transparency', 'Security lab', 'Real attacks against the real kernel, each in a fresh sandbox. Your session is never touched.') + `
    <section class="card panel">
      <div class="arch"><span>You speak</span><i>→</i><span>Agent drafts</span><i>‖</i><span class="edge">Verifier re-reads your words</span><i>→</i><span class="edge">Evidence + rules</span><i>→</i><span>You check the card</span><i>→</i><span class="edge">Fingerprint signs</span><i>→</i><span class="edge">Kernel verifies</span><i>→</i><span class="edge">Gateway re-verifies</span><i>→</i><span>Ledger</span></div>
      <p class="footnote">The model lives left of the red boxes. It has no tool that can sign, authorize or pay, and the ledger only accepts instructions carrying your device's signature.</p>
      <div class="row-actions"><button class="btn primary" id="lab-run">${icon('lab')}Run all attacks</button>
        <button class="btn secondary" id="lab-mistake">${icon('alert')}Simulate a model mistake</button></div>
      <p class="footnote">"Simulate a model mistake" is the same check, live in your chat: “Send 50 to my daughter” goes to a deliberately faulty model that drafts S$500, and you watch the real verifier, kernel and gateway stop it. The risk demonstration below runs every case at once in a sandbox.</p>
      <div id="lab-out"></div></section>
    <section class="card panel page-gap contract-showcase">
      <p class="eyebrow">Intent → Plan → Authorization → Execution</p>
      <h2>Transaction safety contract</h2>
      <p>Four enforceable promises: follow your intent, use completed dependencies, execute exactly what you sign, and recheck conditions before posting.</p>
      <p class="footnote">Fault injection runs against a fresh synthetic ledger. No customer session or real model is used.</p>
      <button class="btn primary" id="contract-run">Run risk demonstration</button>
      <div id="contract-out" aria-live="polite"></div>
    </section>
    <section class="card panel page-gap">
      <h2>Simulated bank review desk</h2>
      <p>A separate demo operator inspects the exact card before approving. This is not a real bank callback or customer identity check.</p>
      <label for="review-key">Reviewer credential</label>
      <input type="password" id="review-key" autocomplete="off" placeholder="Configured by the server operator">
      <label for="review-file">Customer review ticket (.json)</label><input type="file" id="review-file" accept=".json,application/json">
      <button class="btn secondary" id="review-inspect">Inspect pending transaction</button>
      <div id="review-out" aria-live="polite"></div>
    </section>`;
  bindContractLab();
  $('#lab-mistake').onclick = () => send('Send 50 to my daughter', '/api/demo/model-mistake', false, false, true);
  $('#lab-run').onclick = async () => {
    $('#lab-out').innerHTML = '<p class="footnote">Running…</p>';
    try{
      const {results} = await api('/api/lab', {});
      const ok = results.filter(r => r.blocked).length;
      $('#lab-out').innerHTML = `<div class="lab-score">${ok} / ${results.length} attacks blocked</div><div class="lab-list">${results.map(r =>
        `<div class="lab-item ${r.blocked ? 'pass' : 'fail'}"><span class="s">${r.blocked ? '✓' : '✕'}</span><div><b>${esc(r.name)}</b> <code>${esc(r.code)}</code><small>${esc(r.detail)}</small></div></div>`).join('')}</div>
        <p class="footnote">A fixed set of checks, not a penetration test. See docs/SECURITY.md for what is simulated.</p>`;
      addTrace([{kind:'guard', label:`Security lab: ${ok}/${results.length} attacks blocked`, detail: results}]);
    }catch(e){ $('#lab-out').innerHTML = `<p class="footnote">Could not run the lab: ${esc(e.message)}</p>`; }
  };
}
function settingsPage(m){
  const sw = (id, on, title, sub) => `<div class="setting"><div>${title}<small>${sub}</small></div><button class="switch" role="switch" id="${id}" aria-checked="${on}" aria-label="${esc(title)}"></button></div>`;
  const pr = state.data?.protection || {level: 'enhanced'}, pk = state.data?.passkey || {};
  const when = t => new Date(t * 1000).toLocaleString('en-SG', {weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'});
  const delay = Math.round((pr.delay_seconds || 86400) / 3600);
  m.innerHTML = head('Your workspace', 'Settings') + `
    <section class="card settings protection">
      <div class="setting"><div>Account protection<small>This is a bank setting, not a screen setting: switching to Standard view doesn't change it.
        Raising it is instant. Lowering it needs your fingerprint and only starts ${delay >= 1 ? `${delay} hours` : `${pr.delay_seconds} seconds`} later, so nobody can rush you into it on the phone.</small></div></div>
      <div class="levels" role="radiogroup" aria-label="Protection level">
        <button role="radio" class="level ${pr.level === 'enhanced' ? 'on' : ''}" data-to="enhanced" aria-checked="${pr.level === 'enhanced'}"><b>Enhanced</b><small>Recommended for seniors. Waits before payments over S$1,000, stops scam-like requests, double-checks late at night and for risky investments.</small></button>
        <button role="radio" class="level ${pr.level === 'standard' ? 'on' : ''}" data-to="standard" aria-checked="${pr.level === 'standard'}"><b>Standard</b><small>Fewer interruptions: waits only over S$3,000, scam-like requests get a warning instead of a stop. "Safe account" requests are always stopped.</small></button>
      </div>
      ${pr.pending ? `<div class="pending">Standard protection starts ${esc(when(pr.pending.effective_at))}. <button class="btn secondary" id="p-cancel">Keep Enhanced</button></div>` : ''}
      <p class="footnote">Always on for everyone: Star only drafts, every draft is checked against your words by two separate engines, your device signs every payment, and the payment gateway refuses anything unsigned.</p>
    </section>
    <section class="card settings page-gap">
      ${sw('s-realbio', passkeyMode(), 'Real Face ID / fingerprint (optional)', passkeyMode()
        ? (pk.enrolled ? `On. Passkey ${esc((pk.key_ids || [])[0] || '')} on this device signs every payment after its own fingerprint, face or PIN check.`
                       : 'On. The first payment asks this device to save a passkey (Touch ID, Face ID, Windows Hello).')
        : "Off: the demo shows a simulated fingerprint sensor. Turn on to use this device's real Touch ID, Face ID or Windows Hello instead.")}
    </section>
    <section class="card settings page-gap">
      <div class="setting"><div>Demo customer<small>Same bank and the same safety checks; Star talks to each customer differently.</small></div></div>
      <div class="customer-list">${customerChoices()}</div>
    </section>
    <section class="card settings page-gap">
      ${sw('s-senior', state.senior, 'Simple view', 'Larger text, fewer choices and an easy-to-find voice button. You can choose whether replies are read aloud in Settings.')}
      ${sw('s-large', state.large, 'Larger text in standard view', 'Makes the normal dashboard easier to read.')}
      ${sw('s-read', readAloudOn(), 'Read every answer aloud', 'Answers to questions you speak are always read aloud. Tap the microphone to stop one.')}
      <div class="setting"><div>Language model<small>${esc(state.health.model || '')}</small></div><code class="k">${live() ? 'live' : 'offline rules'}</code></div>
      <div class="setting"><div>Speech recognition<small>Without Tencent Cloud keys the browser's own recognition is used.</small></div><code class="k">${esc(state.health.asr || '')}</code></div>
      <div class="setting"><div>Independent verifier<small>The second engine that re-reads only your words and can freeze a payment.</small></div><code class="k">${esc(state.health.verifier || '')}</code></div>
      <div class="setting"><div>Browser signing key (fallback)<small>Only used on devices without a fingerprint or face sensor.</small></div><code class="k">${esc(state.keyId || 'not created')}</code></div>
      <div class="setting"><div>Reset demo<small>New session, balances and bills restored. Old audit records are kept.</small></div><button class="btn secondary" id="s-reset">${icon('refresh')}Reset</button></div>
    </section>`;
  $('#s-senior').onclick = () => setSenior(!state.senior);
  bindCustomerChoices(m);
  $('#s-large').onclick = () => { state.large = !state.large; store.set('large', state.large); render(); };
  $('#s-read').onclick = () => { state.readAloud = !readAloudOn(); store.set('readAloud', state.readAloud); if(!state.readAloud) speechSynthesis?.cancel(); renderPage(); };
  $('#s-reset').onclick = resetDemo;
  m.querySelectorAll('.level').forEach(b => b.onclick = () => setProtection(b.dataset.to));
  $('#p-cancel') && ($('#p-cancel').onclick = () => setProtection('enhanced'));
  $('#s-realbio') && ($('#s-realbio').onclick = async () => {
    const on = !passkeyMode();
    if(on){
      if(!await passkeyCapability()){ toast("This browser can't use a real fingerprint or face here. The simulated sensor stays on."); return; }
      store.set('realBio', true);
    }else{
      try{ if(pk.enrolled){ await removePasskey(); await refresh(); } }
      catch(e){ toast('Identity verification was not completed. Your passkey is still enabled.'); return; }
      store.set('realBio', false);
    }
    state.signMode = await detectSignMode(); renderPage();
    toast(on ? 'Real fingerprint / face is on.' : 'Back to the simulated fingerprint sensor.');
  });
  $('#pk-setup') && ($('#pk-setup').onclick = async () => { try{ await enrolPasskey(); toast('Fingerprint signing is set up.'); renderPage(); }catch(e){ toast(e.name === 'NotAllowedError' ? 'Set-up cancelled.' : e.message); } });
  $('#pk-remove') && ($('#pk-remove').onclick = async () => { await removePasskey(); await refresh(); toast('Identity verified. Passkey removed from this demo.'); });
}
async function setProtection(to){
  const cur = state.data?.protection;
  if(to === cur?.level && !cur?.pending) return;
  try{
    if(to === 'enhanced'){
      await api('/api/protection', {session_id: state.sid, to}); toast('Enhanced protection is on.');
    }else{
      await ensureSigner();
      const ch = await api('/api/protection/challenge', {session_id: state.sid, to});
      const assertion = await signPayload(ch.payload, ch.passkey);
      const st = await api('/api/protection', {session_id: state.sid, to, assertion});
      toast(`Standard protection will start ${new Date(st.pending.effective_at * 1000).toLocaleString('en-SG')}. You can cancel before then.`);
    }
  }catch(e){ toast(e.name === 'NotAllowedError' ? 'Cancelled. Nothing changed.' : e.message); }
  await refresh();
}
// ---------------------------------------------------------------- Demo customers (same risk engine, different conversation)
function customerChoices(){
  return Object.entries(CUSTOMERS).map(([id, c]) => `<button class="customer-choice ${state.data?.customer === id ? 'on' : ''}" data-customer="${id}"
    aria-pressed="${state.data?.customer === id}"><span class="avatar">${c.initials}</span><span><b>${esc(c.name)} · ${c.tag}</b><small>${esc(c.about)}</small></span></button>`).join('');
}
function bindCustomerChoices(root){
  root.querySelectorAll('.customer-choice').forEach(b => b.onclick = () => switchCustomer(b.dataset.customer));
}
async function switchCustomer(id, quiet = false){
  if(state.data?.customer === id){ $('#customer-menu') && ($('#customer-menu').hidden = true); return; }
  const r = await api('/api/reset', {session_id: state.sid, persona: id, world: true, ...(visitorMode() ? {visitor: VISITOR} : {})});
  state.sid = r.session_id; store.set('sid', r.session_id);
  state.messages = []; state.check = null; $('#tlist').innerHTML = ''; closeConfirm();
  if(id === 'alex'){ state.senior = false; store.set('senior', false); }
  await refresh(); go('overview'); if(!quiet) toast(`Now banking as ${CUSTOMERS[id].name} (${CUSTOMERS[id].tag})`);
}
async function resetDemo(){
  const r = await api('/api/reset', {session_id: state.sid, world: true, ...(visitorMode() ? {visitor: VISITOR} : {})});
  state.sid = r.session_id; store.set('sid', r.session_id);
  state.messages = []; state.check = null; $('#tlist').innerHTML = ''; closeConfirm();
  await refresh(); go('overview'); toast('Demo reset');
}

// ---------------------------------------------------------------- Voice input
// Preferred: record 16 kHz mono WAV -> Tencent Cloud SentenceRecognition on the server (with payee hotwords).
// Fallback: the browser's own speech recognition when the server has no ASR keys.
// Recording ends when the customer taps the mic again, or by itself once they have been quiet for a while
// after speaking (longer in Senior mode, because pauses mid-sentence are normal), or at the hard cap.
const rec = {ctx:null, stream:null, node:null, chunks:[], rate:48000, on:false, timer:null, sr:null,
             t0:0, heard:0, lastVoice:0, noise:null, final:'', interim:'', stopping:false, shown:0};
const MAX_SEC = 50;                                  // Tencent SentenceRecognition accepts up to 60 s
const VOICE = {silenceMs: () => state.senior ? 4000 : 3000, noSpeechMs: 12000, minSpeechMs: 300};
const hint = t => { const h = $('#hint'); if(h) h.textContent = t; };
async function micToggle(){
  if(rec.on) return stopRec();
  stopSpeaking();                                   // barge-in: tapping the mic cuts the answer off at once
  if(state.health.asr === 'tencent') return startWavRec();
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if(!SR){ push({role:'bot', text:"This browser doesn't support voice input. Please use Chrome, or type instead."}); return; }
  Object.assign(rec, {final:'', interim:'', stopping:false, t0:Date.now(), lastVoice:0, heard:0, err:''});
  startBrowserSR(SR); setRec(true);
  rec.timer = setInterval(() => {                   // the browser recogniser has no audio level, so its results count as speech
    const now = Date.now();
    if(now - rec.t0 > MAX_SEC * 1000) return stopRec();
    if(rec.lastVoice && now - rec.lastVoice > VOICE.silenceMs()) return stopRec();
    if(!rec.lastVoice && now - rec.t0 > VOICE.noSpeechMs) return stopRec();
    listeningHint(now);
  }, 250);
}
function startBrowserSR(SR){
  const sr = rec.sr = new SR();
  sr.lang = 'en-SG'; sr.continuous = true; sr.interimResults = true; sr.maxAlternatives = 1;
  sr.onresult = e => {
    let fin = '', mid = '';
    for(let i = 0; i < e.results.length; i++){ const t = e.results[i][0].transcript; if(e.results[i].isFinal) fin += t + ' '; else mid += t; }
    rec.final = (rec.base || '') + fin; rec.interim = mid; rec.lastVoice = Date.now();
    const ta = $('#text'); if(ta) ta.value = (rec.final + rec.interim).trim();   // show what has been heard so far
  };
  sr.onerror = e => {
    if(e.error === 'not-allowed' || e.error === 'service-not-allowed'){ rec.stopping = true; rec.err = 'Microphone permission is off. You can type your request, or allow access in your browser and try again.'; }
    else if(e.error === 'network' || e.error === 'audio-capture'){ rec.stopping = true; rec.err = "Voice input isn't working right now. Please type instead."; }
  };
  sr.onend = () => {
    // Chrome ends a session on its own after a pause or a network blip; keep listening until we decide to stop.
    if(rec.on && !rec.stopping && rec.sr === sr){
      rec.base = rec.final; rec.interim && (rec.base += rec.interim + ' '); rec.interim = '';
      try{ sr.start(); return; }catch{ /* fall through and finish */ }
    }
    if(rec.sr === sr) finishBrowserSR();
  };
  rec.base = ''; sr.start();
}
function finishBrowserSR(){
  const text = (rec.final + ' ' + rec.interim).replace(/\s+/g, ' ').trim();
  rec.sr = null; rec.base = ''; setRec(false);
  if(rec.err){ const err = rec.err; rec.err = ''; if($('#text')) $('#text').value = text; hint(err + ' Your words were not sent. Check the text before sending.'); return; }
  if(!text){ hint(rec.err || "I didn't catch that. Tap Speak to try again, or type your request."); rec.err = ''; return; }
  rec.err = '';
  addTrace([{kind:'asr', label:'Browser speech recognition: ' + text}]);
  send(text, undefined, true);
}
function listeningHint(now){
  if(now - rec.shown < 500) return; rec.shown = now;
  const left = MAX_SEC - Math.floor((now - rec.t0) / 1000);
  hint(left <= 10 ? `Recording stops in ${left} s. Tap the mic when you're done.`
                  : "I'm listening. Tap when you're finished, or pause to send.");
}
async function startWavRec(){
  try{ rec.stream = await navigator.mediaDevices.getUserMedia({audio:{channelCount:1, echoCancellation:true, noiseSuppression:true}}); }
  catch{ push({role:'bot', text:'Microphone permission is off. You can type your request, or allow access in your browser and try again.'}); return; }
  rec.ctx = new (window.AudioContext || window.webkitAudioContext)(); rec.rate = rec.ctx.sampleRate; rec.chunks = [];
  Object.assign(rec, {t0:Date.now(), heard:0, lastVoice:0, noise:null, stopping:false});
  const src = rec.ctx.createMediaStreamSource(rec.stream);
  rec.node = rec.ctx.createScriptProcessor(4096, 1, 1);
  rec.node.onaudioprocess = e => {
    const x = new Float32Array(e.inputBuffer.getChannelData(0));
    rec.chunks.push(x);
    voiceActivity(x, x.length / rec.rate * 1000);
  };
  src.connect(rec.node); rec.node.connect(rec.ctx.destination);
  setRec(true); $('#mic')?.classList.add('live');
  rec.timer = setTimeout(stopRec, MAX_SEC * 1000);
}
// Simple energy-based voice activity detection. The noise floor is learnt from the quietest moments, so a soft voice
// in a quiet room still counts as speech; silence only ends the recording after real speech has been heard.
function voiceActivity(x, ms){
  if(!rec.on || rec.stopping) return;
  let sum = 0; for(let i = 0; i < x.length; i++) sum += x[i] * x[i];
  const rms = Math.sqrt(sum / x.length), now = Date.now();
  rec.noise = rec.noise === null ? Math.min(rms, 0.02) : Math.min(0.03, rms < rec.noise ? rms : rec.noise * 0.995 + rms * 0.005);
  const speaking = rms > Math.max(0.01, rec.noise * 3);
  if(speaking){ rec.heard += ms; rec.lastVoice = now; }
  $('#mic')?.style.setProperty('--lvl', Math.min(1, rms * 8).toFixed(2));
  const armed = rec.heard >= VOICE.minSpeechMs;
  if(armed && now - rec.lastVoice > VOICE.silenceMs()) return stopRec();
  if(!armed && now - rec.t0 > VOICE.noSpeechMs) return stopRec();   // send what we have; the recogniser decides
  listeningHint(now);
}
async function stopRec(){
  if(rec.stopping && !rec.sr) return;
  rec.stopping = true;
  clearTimeout(rec.timer); clearInterval(rec.timer);
  if(rec.sr){ try{ rec.sr.stop(); }catch{ finishBrowserSR(); } return; }   // onend sends what was heard
  setRec(false);
  rec.node?.disconnect(); rec.stream?.getTracks().forEach(t => t.stop()); await rec.ctx?.close();
  rec.node = rec.stream = rec.ctx = null;
  const wav = encodeWav(downsample(flatten(rec.chunks), rec.rate, 16000), 16000);
  rec.chunks = [];
  if(wav.byteLength < 16000){ hint('I need a little more to go on. Please try again or type your request.'); return; }
  hint('Recognizing…');
  try{
    const r = await api('/api/asr', {session_id: state.sid, audio_b64: b64(wav)});
    hint(''); addTrace([{kind:'asr', label:`Tencent Cloud ASR (${r.engine}, ${r.latency_ms}ms): ${r.text}`}]);
    if(r.text) send(r.text, undefined, true); else hint("I didn't catch that. You can try again or type your request.");
  }catch(e){ hint('Voice input is unavailable right now. Please try again or type your request.'); }
}
function setRec(on){
  rec.on = on; const mic = $('#mic');
  if(mic){ mic.classList.toggle('rec', on); if(!on){ mic.classList.remove('live'); mic.style.removeProperty('--lvl'); } }
  const label = $('#mic span'); if(label) label.textContent = on ? (state.senior ? 'Tap when done' : 'Listening… tap to stop') : (state.senior ? 'Tap to speak' : 'Speak');
  rec.shown = 0;
  hint(on ? "I'm listening. Tap when you're finished, or pause to send." : '');
}
function flatten(chunks){ const n = chunks.reduce((a, c) => a + c.length, 0), out = new Float32Array(n); let o = 0; chunks.forEach(c => { out.set(c, o); o += c.length; }); return out; }
function downsample(buf, from, to){
  if(from === to) return buf;
  const ratio = from / to, len = Math.floor(buf.length / ratio), out = new Float32Array(len);
  for(let i = 0; i < len; i++){ const s = Math.floor(i * ratio), e = Math.min(buf.length, Math.floor((i + 1) * ratio)); let sum = 0; for(let j = s; j < e; j++) sum += buf[j]; out[i] = sum / Math.max(1, e - s); }
  return out;
}
function encodeWav(samples, rate){
  const buf = new ArrayBuffer(44 + samples.length * 2), v = new DataView(buf);
  const w = (o, s) => { for(let i = 0; i < s.length; i++) v.setUint8(o + i, s.charCodeAt(i)); };
  w(0, 'RIFF'); v.setUint32(4, 36 + samples.length * 2, true); w(8, 'WAVE'); w(12, 'fmt ');
  v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true); v.setUint32(24, rate, true);
  v.setUint32(28, rate * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true); w(36, 'data'); v.setUint32(40, samples.length * 2, true);
  for(let i = 0; i < samples.length; i++){ const s = Math.max(-1, Math.min(1, samples[i])); v.setInt16(44 + i * 2, s < 0 ? s * 0x8000 : s * 0x7FFF, true); }
  return buf;
}
function b64(buf){ let s = ''; const b = new Uint8Array(buf); for(let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); }

// ---------------------------------------------------------------- Start
document.addEventListener('keydown', e => { if(e.key === 'Escape' && $('#trace').classList.contains('open') && !$('#confirm').open) toggleTrace(false); });
async function init(){
  try{ state.health = await api('/api/health'); }catch{}
  if(visitorMode() && !state.sid){
    try{ const r = await api('/api/reset', {visitor: VISITOR}); state.sid = r.session_id; store.set('sid', r.session_id); }catch{}
  }
  await refresh();
  if(!state.data) throw new Error('The demo service is not ready. Please try again in a moment.');
  state.signMode = await detectSignMode();      // after refresh: an enrolled passkey keeps being used
  render();
  const pending = store.get('pendingPayment', null);
  if(pending && pending.sid === state.sid){ state.card = pending.card; renderConfirm(); await recoverPayment(pending.card); }
  else restorePending();
}

// Launch screen is local-only: no bank API, microphone or biometric request before entry.
const welcome = $('#welcome'), enter = $('#welcome-enter');
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
let motionPaused = reducedMotion.matches, animationId = 0, fieldTime = 0, lastFrame = 0;
const canvas = $('#welcome-canvas'), ctx = canvas.getContext('2d');
const pointer = {x:0, y:0, active:false}, glow = {x:0, y:0, strength:0};
let fieldWidth = 1, fieldHeight = 1, particles = [], ripples = [], cursorTrail = [];
function resizeField(){
  if(welcome.hidden || welcome.classList.contains('leaving')) return;
  const rect = welcome.getBoundingClientRect();
  fieldWidth = rect.width; fieldHeight = rect.height;
  const scale = Math.min(devicePixelRatio || 1, 2);
  canvas.width = Math.round(fieldWidth * scale); canvas.height = Math.round(fieldHeight * scale);
  ctx?.setTransform(scale,0,0,scale,0,0);
  // Even coverage at every viewport size, with bounded work on large monitors.
  const count = Math.min(1600, Math.max(260, Math.round(fieldWidth * fieldHeight / 1500)));
  particles = Array.from({length:count}, (_, i)=>({
    u:(i*.61803398875)%1, v:(i*.75487766625)%1,
    phase:i*2.39996, size:.65+(i%7)*.16, dx:0, dy:0, lane:i%5, index:i
  }));
  if(motionPaused) paintField();
}
function paintField(timestamp = 0){
  animationId = 0;
  if(welcome.hidden || welcome.classList.contains('leaving')) return;
  const dt = lastFrame ? Math.min(timestamp-lastFrame,40) : 16;
  lastFrame = timestamp;
  if(!motionPaused) fieldTime += dt*.00015;
  if(ctx){
    ctx.clearRect(0,0,fieldWidth,fieldHeight);
    glow.strength += ((pointer.active && !motionPaused ? 1 : 0)-glow.strength)*.1;
    glow.x += (pointer.x-glow.x)*.18; glow.y += (pointer.y-glow.y)*.18;
    const reach = Math.min(210, Math.max(130,fieldWidth*.15));
    if(glow.strength>.01){
      const halo = ctx.createRadialGradient(glow.x,glow.y,0,glow.x,glow.y,reach);
      halo.addColorStop(0,`rgba(229,0,25,${.24*glow.strength})`);
      halo.addColorStop(.5,`rgba(244,93,120,${.1*glow.strength})`);
      halo.addColorStop(1,'rgba(229,0,25,0)');
      ctx.fillStyle=halo;ctx.fillRect(0,0,fieldWidth,fieldHeight);
    }
    const step=motionPaused ? 0 : dt/16.667;
    // Flowing silk-like ribbons cross a quieter, full-page star field.
    const cells=new Map(), cellSize=76;
    const rendered=[];
    for(let lane=0;lane<5;lane++)for(let strand=0;strand<9;strand++){
      ctx.beginPath();
      for(let n=0;n<=64;n++){
        const u=n/64, x=u*fieldWidth;
        const y=fieldHeight*(.17+lane*.165)+Math.sin(u*7+fieldTime+lane*.8)*fieldHeight*.11+(strand-4)*12*Math.sin(u*3+fieldTime*.4+lane);
        if(n===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
      }
      ctx.strokeStyle=`rgba(211,13,52,${strand===4?.19:.055})`;
      ctx.lineWidth=strand===4?1.2:.75;ctx.stroke();
    }
    for(const p of particles){
      const ribbon=p.index%3!==0;
      const depth=.4+(p.index%11)/10;
      const travel=(p.u+fieldTime*.018*depth)%1;
      const parallax=pointer.active ? (glow.x-fieldWidth/2)*.012*depth : 0;
      const x=travel*fieldWidth+Math.sin(fieldTime*.6+p.phase)*18+parallax;
      const ribbonY=fieldHeight*(.17+p.lane*.165)+Math.sin(travel*7+fieldTime+p.lane*.8)*fieldHeight*.11;
      const y=ribbon ? ribbonY+(p.v-.5)*85 : p.v*fieldHeight+Math.cos(fieldTime*.7+p.phase)*16;
      const vx=x-pointer.x, vy=y-pointer.y, distance=Math.hypot(vx,vy);
      const influence=pointer.active&&!motionPaused ? Math.max(0,1-distance/reach) : 0;
      const force=influence*influence*105, d=Math.max(distance,1);
      let tx=(vx/d-vy/d*1.5)*force, ty=(vy/d+vx/d*1.5)*force, pulse=0;
      for(const ring of ripples){
        const rx=x-ring.x, ry=y-ring.y, rd=Math.hypot(rx,ry);
        const hit=Math.max(0,1-Math.abs(rd-ring.radius)/65)*(1-ring.age/1800);
        tx+=rx/Math.max(rd,1)*hit*42;ty+=ry/Math.max(rd,1)*hit*42;pulse=Math.max(pulse,hit);
      }
      const ease=motionPaused?1:1-Math.pow(.9,step);
      p.dx+=(tx-p.dx)*ease;p.dy+=(ty-p.dy)*ease;
      const px=x+p.dx, py=y+p.dy;
      const wave=.5+.5*Math.sin(p.u*8+p.v*5+fieldTime*1.8);
      // Keep the headline region quiet without breaking the full-screen field.
      const center=Math.max(0,1-Math.abs(px-fieldWidth/2)/(fieldWidth*.3))*Math.max(0,1-Math.abs(py-fieldHeight*.5)/(fieldHeight*.28));
      const alpha=(.23+wave*.36+influence*.42+pulse*.35)*(1-center*.55);
      const point={x:px,y:py,alpha,energy:influence+pulse};rendered.push(point);
      const key=`${Math.floor(px/cellSize)},${Math.floor(py/cellSize)}`;
      if(!cells.has(key))cells.set(key,[]);cells.get(key).push(point);
      ctx.beginPath();ctx.arc(px,py,p.size*depth+influence*2+pulse*2,0,Math.PI*2);
      ctx.fillStyle=`rgba(211,13,52,${Math.min(.95,alpha)})`;ctx.fill();
      if(p.index%37===0 || influence>.65){
        const length=3+wave*3+influence*5;
        ctx.beginPath();ctx.moveTo(px-length,py);ctx.lineTo(px+length,py);
        ctx.moveTo(px,py-length);ctx.lineTo(px,py+length);
        ctx.strokeStyle=`rgba(229,0,36,${alpha*.65})`;ctx.lineWidth=.7;ctx.stroke();
      }
    }
    // Spatial buckets bound the cost of constellation connections.
    let links=0;
    for(let i=0;i<rendered.length && links<1900;i+=2){
      const p=rendered[i], cx=Math.floor(p.x/cellSize), cy=Math.floor(p.y/cellSize);
      let neighbors=0;
      for(let dx=-1;dx<=1;dx++)for(let dy=-1;dy<=1;dy++){
        for(const q of cells.get(`${cx+dx},${cy+dy}`)||[]){
          if(q===p || neighbors>=3 || links>=1900)continue;
          const dist=Math.hypot(p.x-q.x,p.y-q.y);
          if(dist>70 || dist<8)continue;
          ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(q.x,q.y);
          ctx.strokeStyle=`rgba(208,15,55,${(1-dist/70)*(.2+Math.min(1,p.energy+q.energy)*.4)*Math.min(p.alpha,q.alpha)*2})`;
          ctx.lineWidth=.65;ctx.stroke();neighbors++;links++;
        }
      }
    }
    // Staggered shooting stars: translucent tails with a sharp red-white core.
    if(!motionPaused)for(let i=0;i<5;i++){
      const progress=(fieldTime*.22+i*.213)%1;
      if(progress>.72)continue;
      const t=progress/.72, x=t*(fieldWidth+320)-160;
      const y=fieldHeight*(.1+i*.19)+Math.sin(t*3+i)*90;
      const tail=100+(i%3)*45, opacity=Math.sin(t*Math.PI)*.7;
      const beam=ctx.createLinearGradient(x-tail,y-35,x,y);
      beam.addColorStop(0,'rgba(229,0,35,0)');beam.addColorStop(.8,`rgba(229,0,35,${opacity*.3})`);
      beam.addColorStop(1,`rgba(229,0,35,${opacity})`);
      ctx.beginPath();ctx.moveTo(x-tail,y-35);ctx.lineTo(x,y);ctx.strokeStyle=beam;ctx.lineWidth=1.8;ctx.stroke();
      ctx.beginPath();ctx.arc(x,y,2.2,0,Math.PI*2);ctx.fillStyle=`rgba(229,0,35,${opacity})`;ctx.fill();
    }
    if(pointer.active && !motionPaused){
      cursorTrail.push({x:glow.x,y:glow.y,age:0});
      if(cursorTrail.length>40)cursorTrail.shift();
    }
    cursorTrail=cursorTrail.filter(p=>(p.age+=motionPaused?0:dt)<650);
    for(let i=1;i<cursorTrail.length;i++){
      const p=cursorTrail[i], prev=cursorTrail[i-1];
      ctx.beginPath();ctx.moveTo(prev.x,prev.y);ctx.lineTo(p.x,p.y);
      const fade=Math.max(0,1-p.age/650);
      ctx.strokeStyle=`rgba(229,0,35,${fade*.16})`;ctx.lineWidth=9*fade;ctx.stroke();
      ctx.strokeStyle=`rgba(229,0,35,${fade*.65})`;ctx.lineWidth=1.6;ctx.stroke();
    }
    ripples=ripples.filter(r=>r.age<1800);
    for(const ring of ripples){
      ring.age+=motionPaused?0:dt;ring.radius+=step*7;
      const alpha=Math.max(0,1-ring.age/1800);
      for(let spark=0;spark<32;spark++){
        const angle=spark*Math.PI/16+ring.age*.0004;
        const radius=ring.radius*(.82+(spark%3)*.09);
        const x=ring.x+Math.cos(angle)*radius,y=ring.y+Math.sin(angle)*radius;
        ctx.beginPath();ctx.moveTo(x,y);ctx.lineTo(x-Math.cos(angle)*18*alpha,y-Math.sin(angle)*18*alpha);
        ctx.strokeStyle=`rgba(223,9,38,${alpha*.65})`;ctx.lineWidth=1.3;ctx.stroke();
      }
      for(let layer=0;layer<2;layer++){
        ctx.beginPath();ctx.arc(ring.x,ring.y,Math.max(0,ring.radius-layer*14),0,Math.PI*2);
        ctx.strokeStyle=`rgba(225,15,53,${alpha*(layer?.12:.4)})`;ctx.lineWidth=layer?4:1;ctx.stroke();
      }
    }
  }
  if(!motionPaused && !document.hidden) animationId=requestAnimationFrame(paintField);
}
function syncMotion(){
  cancelAnimationFrame(animationId);lastFrame=0;
  welcome.classList.toggle('motion-paused', motionPaused);
  if(motionPaused){ripples=[];cursorTrail=[];}
  paintField();
}
reducedMotion.addEventListener('change', e=>{motionPaused=e.matches;syncMotion();});
function trackPointer(e){
  const rect=welcome.getBoundingClientRect();
  if(!pointer.active){glow.x=e.clientX-rect.left;glow.y=e.clientY-rect.top;}
  pointer.x=e.clientX-rect.left;pointer.y=e.clientY-rect.top;pointer.active=true;
}
welcome.addEventListener('pointermove',trackPointer,{passive:true});
welcome.addEventListener('pointerdown',e=>{
  trackPointer(e);
  if(!motionPaused){ripples.push({x:pointer.x,y:pointer.y,radius:0,age:0});if(ripples.length>5)ripples.shift();}
},{passive:true});
welcome.addEventListener('pointerleave',()=>{pointer.active=false;});
welcome.addEventListener('pointercancel',()=>{pointer.active=false;});
welcome.addEventListener('pointerup',e=>{if(e.pointerType!=='mouse')pointer.active=false;});
document.addEventListener('visibilitychange',()=>{cancelAnimationFrame(animationId);lastFrame=0;if(!document.hidden&&!welcome.hidden)paintField();});
const fieldObserver = new ResizeObserver(resizeField);fieldObserver.observe(welcome);
resizeField();syncMotion();
// The launch screen picks the demo customer: Mdm Chen (senior care, the main demo) or Alex Tan (everyday)
const enterAlt = $('#welcome-alt');
async function enterAs(customerId, btn){
  if(enter.disabled || enterAlt.disabled)return;
  enter.disabled=true; enterAlt.disabled=true; btn.setAttribute('aria-busy','true');
  $('#welcome-status').textContent=`Opening ${customerId === 'alex' ? "Alex Tan's" : "Mdm Chen's"} account…`;
  try{
    await init();
    if(state.data?.customer !== customerId) await switchCustomer(customerId, true);
    $('#app').hidden=false;
    document.body.classList.remove('welcome-active');
    welcome.classList.add('leaving');welcome.inert=true;fieldObserver.disconnect();
    cancelAnimationFrame(animationId);
    const skip=$('.skip-link');skip.href='#main';skip.textContent='Skip to main content';
    const main=$('#main');if(main){main.setAttribute('tabindex','-1');main.focus({preventScroll:true});}
    setTimeout(()=>{welcome.hidden=true;},reducedMotion.matches||motionPaused?0:450);
  }catch(e){
    $('#welcome-status').textContent='Unable to connect to the demo. Please try again in a moment.';
    enter.disabled=false;enterAlt.disabled=false;btn.removeAttribute('aria-busy');
  }
}
enter.addEventListener('click', () => enterAs('chen', enter));
enterAlt.addEventListener('click', () => enterAs('alex', enterAlt));

// Decorative click acknowledgement only. Never dispatches an action or changes
// disabled, busy, payment, microphone, or confirmation state. Capture runs before
// existing handlers so controls that re-render still receive the same one click.
const tapTimers = new WeakMap();
document.addEventListener('click', e=>{
  const button=e.target instanceof Element ? e.target.closest('button') : null;
  if(!button || button.disabled || button.getAttribute('aria-disabled')==='true')return;
  if(!button.closest('#app, #confirm, #trace, #welcome'))return;
  const rect=button.getBoundingClientRect();
  const x=e.detail===0 ? rect.width/2 : e.clientX-rect.left;
  const y=e.detail===0 ? rect.height/2 : e.clientY-rect.top;
  button.style.setProperty('--tap-x',`${Math.max(0,Math.min(rect.width,x))}px`);
  button.style.setProperty('--tap-y',`${Math.max(0,Math.min(rect.height,y))}px`);
  clearTimeout(tapTimers.get(button));
  button.classList.remove('tap-feedback');
  // Restart the local pseudo-element ripple for successive, legitimate clicks.
  void button.offsetWidth;
  button.classList.add('tap-feedback');
  tapTimers.set(button,setTimeout(()=>{
    button.classList.remove('tap-feedback');
    button.style.removeProperty('--tap-x');button.style.removeProperty('--tap-y');
    tapTimers.delete(button);
  },600));
},true);
