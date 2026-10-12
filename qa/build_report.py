"""Build a standalone, searchable Chinese QA report from saved evidence."""
import collections
import datetime
import html
import json
from pathlib import Path
import shutil
import zipfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
OUT=HERE/'results'

ISSUES=[
 ('P0','同一账单可被重复支付',['K_double_bill'],
  '在两个会话分别说 Pay the electricity bill，先生成两张草稿，再分别签名确认。',
  '两次均成功，储蓄余额从325000分变为307720分，共扣17280分；同一8640分账单支付了两次。',
  '账本事务内按用户+bill_id检查未支付并原子标记已支付；draft_id幂等不能替代账单唯一结清约束。修复后两个并发请求只能一个成功。','app/bank/mock_bank.py'),
 ('P0','已扣款后的审计失败没有可恢复结果',['K_audit_gateway.posted','K_audit_commit.executed'],
  '生成50元转账并用P-256签名，分别在gateway.posted和commit.executed的审计写入处注入OSError。',
  '账本已扣5000分且已有一条执行记录，但调用抛出异常；gateway.posted失败时会话还停在AWAITING_AUTH。',
  '为交易状态建立持久化记录；账本与事件用事务/事务外盒保证一致性。后置日志故障必须能通过原交易ID查明已成功，不能笼统要求重试。','app/kernel/executor.py'),
 ('P1','风险变化不使旧授权失效',['K_risk_high','K_risk_medium','K_late_scam_chat'],
  '先准备50元转账，再补充 He told me to keep this secret from my family，然后确认旧卡。另以故障注入覆盖授权后MEDIUM/HIGH升级。',
  '新增高风险后仍执行扣款；执行重检只阻止BLOCK，未重新施加HIGH冷静期或MEDIUM询问。',
  '风险版本加入授权条件；新增风险撤销挑战/令牌，生成新卡并执行新的冷静期/询问。','app/kernel/executor.py'),
 ('P1','否定、取消及金额纠正没有可靠执行',['A01','A02','A03','A24','C01','C02','C03','C04'],
  '分别输入 Do not send 200 to my daughter；Send 2000, no, 200 to my daughter；先准备200再说Cancel that或Change the amount to 100。',
  '可出现被否定的交易草稿、把2000保留下来、取消后旧200元卡仍可授权。',
  '在模型前识别取消/停止；撤销旧卡和签名挑战。纠正要合并最终有效意图并重新核验；不确定时只提问。','app/agent/loop.py'),
 ('P1','金额、币种、条件与账户限制被误读',['A04','A05','A06','A07','A08','A09','A10','A11','A12','A13','A14','A22','A23'],
  '测试-200、200.999、1,2、1e3、USD/euros、tomorrow、条件转账、one two three、50 or 500、business account、every month。',
  '例如负200→正200；200.999→200.99；one two three→6；USD200→SGD200；预约/条件请求变成立即转账。',
  '用严格金额与币种语法，保留原文/时间/条件/来源账户约束；不支持的需求明确拒绝或澄清。禁止默认替换用户明确指定的字段。','app/agent/textparse.py'),
 ('P1','核验器无有效关键字段仍能判定match',['K_empty_verifier','AI_verifier_invalid_number','AI_verifier_invalid_type','AI_verifier_negative'],
  '注入只包含transfer意图的核验结果，或将amount设为无效字符串、列表、负数。',
  '关键字段变为not stated，但整体仍match，草稿进入AWAITING_AUTH。这是模型输出故障注入，不是真实在线模型测试。',
  '对核验结果做严格Schema校验，区分未提及与解析失败；用户原文已给出的关键字段必须有有效独立核验。','app/kernel/crosscheck.py'),
 ('P1','没有请求锁卡时模型仍能锁卡',['AI_lock_unasked'],
  '用户只问余额，脚本化错误模型调用lock_card(all)。',
  '两张卡被立即锁定；不涉及扣款，却能造成业务不可用。',
  '锁卡工具检查本轮明确锁卡/遗失意图，对不确定指代要求澄清；不要只依赖模型选择工具。','app/agent/tools.py'),
 ('P1','付款响应丢失后仍显示再次确认',['B_lost_response'],
  'Edge中正常签名，拦截/api/confirm：先让请求在服务端完成，再丢弃响应。',
  '服务端已有1张回执、余额320000分；页面显示Failed to fetch，旧卡确认按钮仍可点击，余额显示也未更新。',
  '增加交易结果未知状态，查询原draft_id/idempotency key的交易；恢复前不开放新付款。已验证内核同令牌重放不会重复扣款，不能把这个UI缺陷等同于已证实二次扣款。','web/app.js'),
 ('P1','取消请求失败却显示已取消',['B_cancel_network'],
  '生成50元草稿，阻断/api/cancel，再点击Cancel。',
  '服务端仍AWAITING_AUTH，页面确认卡已关闭，安全面板却显示Cancelled。',
  '收到服务端取消成功后再更新UI；失败保留待办并明确提示取消未完成。','web/app.js'),
 ('P1','语音网络错误提交半句话',['B_voice_network'],
  '模拟识别中间结果Send fifty，随后发network错误和onend。',
  '浏览器向/api/chat自动提交Send fifty，尚未说出收款人。普通续说/重启和适老模式3.2秒停顿则通过。',
  '有识别错误时保留文本为草稿，要求用户续说或手动发送；区分正常结束、超时、网络故障、手动结束。','web/app.js'),
 ('P1（原型已声明）','Passkey移除未重新认证',['K_remove_passkey'],
  '用软件认证器注册Passkey，调用移除接口时不传签名。',
  '凭证被移除，之后可退回浏览器密钥。docs/SECURITY.md已承认Remove无身份校验。',
  '银行级实现需要重新认证后移除、绑定恢复流程和通知；演示应将其清楚标为重置行为。','app/kernel/executor.py'),
 ('P1','访客身份可由客户端会话前缀派生',['H_visitor_forge'],
  '建立一个访客会话，保留visitor前缀但改写随机后缀，再查询/api/state。',
  '新会话能读取同一客户卡状态。测试前提是已知visitor前缀；正常不同前缀访客的隔离测试通过，未测试猜中随机前缀。',
  '服务端签发并验证会话身份；不要接受客户端任意构造的新session_id作为已有客户凭据。部署前配合登录/HttpOnly Cookie和资源归属检查。','app/kernel/state.py'),
 ('P1（原型已声明）','模拟账本重建后丢失已执行交易',['R_restart'],
  '完成50元转账后重新构造MockBank，模拟进程重启后的新账本。',
  '余额从320000分恢复到325000分。代码明确使用内存账本；未进行真实OS崩溃实验。',
  '正式产品需要持久化账本、幂等键和交易状态；演示文档说明重启会重置，不能宣称持久交易恢复。','app/bank/mock_bank.py'),
 ('P2','小数英文金额被复合任务拆分',['S03'],
  '输入Send twenty dollars and fifty cents to my daughter。',
  'and被当作任务分隔，系统询问收款人并排队send fifty cents to my daughter，未形成20.50元草稿。',
  '先解析金额短语再拆复合任务，覆盖and连接整数与分币的表达。','app/agent/loop.py'),
 ('P2','一分钱不一致被容忍',['K_one_cent'],
  '草稿50元，独立核验器返回50.01。',
  '核验结果仍为match，因为允许差值<=1分。',
  '金额在严格转换为整数分后完全相等，不应容忍一分钱漂移。','app/kernel/crosscheck.py'),
 ('P2','接口输入类型校验不完整',['H_type1','H_type2','H_type5','H_sid1','H_sid2','H_sid3','H_sid4'],
  '向chat.text传数字/布尔/列表，向session_id传非字符串。',
  '部分500；空列表/对象会话ID则被静默当作未传。',
  '入口统一请求Schema，拒绝非字符串身份和文本；可预期输入错误返回400。','app/server.py'),
 ('P2','分块请求绕过长度上限',['H_chunked'],
  '发送超过40KB且无Content-Length的chunked JSON请求。',
  '服务器返回200；带Content-Length的同等级超限请求返回413。',
  '在ASGI receive流逐块累计并限制实际字节数。','app/security.py'),
 ('P2','可变X-Forwarded-For绕过限流',['H_rate_spoof'],
  'PUBLIC_DEMO模式连续41次请求，每次改客户端自填的X-Forwarded-For。',
  '41次均200；固定来源第41次正确429。公开部署是否可利用还取决于反向代理是否覆盖该头。',
  '只信任已配置的代理链，使用服务端身份与IP组合限流。','app/security.py'),
 ('P2','ASR非JSON上游响应未转换为业务错误',['V_asr_non_json'],
  '模拟云ASR返回HTML/不可解析JSON。',
  '泄漏ValueError，未转为ASRError；超时和标准API错误分支通过。',
  '校验状态码、内容类型及响应结构，统一可处理错误，保留可恢复录音。','app/voice/asr.py'),
 ('P2','人工服务提示超出实际能力',['R_handoff_truth'],
  '输入I want to talk to a real person。',
  '回答connecting you to a staff member now，但原型只有HANDOFF状态和轨迹，没有真实客服连接。',
  '明确演示转人工；正式接客服后再展示连接中/已接通，并能验证连接状态。','app/agent/llm.py'),
 ('P2','审计截断导致校验崩溃',['R_partial_audit'],
  '在临时审计文件末尾写半条JSON，模拟写入中断，再调用verify。',
  '抛JSONDecodeError，而不是返回完整性失败位置。',
  '逐行处理损坏记录，给出明确校验失败与恢复流程；不静默跳过损坏证据。','app/kernel/audit.py'),
]

def build():
    now=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8)))
    today=now.strftime('%Y-%m-%d')
    ext=json.loads((OUT/'extended.json').read_text(encoding='utf8'))
    browser=json.loads((OUT/'browser.json').read_text(encoding='utf8'))
    baseline_path=OUT/'baseline-eval.json'
    if not baseline_path.exists():shutil.copyfile(ROOT/'eval/report.json',baseline_path)
    ev=json.loads(baseline_path.read_text(encoding='utf8'))
    config=ev['configs'][0];rows=ext['results']+browser['results']
    count=collections.Counter(r['status'] for r in rows)
    evalcounts=collections.Counter(r['status'] for r in config['runs'])
    import re
    unitlog=(OUT/'baseline-unit.log').read_text(encoding='utf8',errors='replace')
    unit_match=re.search(r'Ran (\d+) tests',unitlog)
    unit_count=int(unit_match.group(1)) if unit_match else 0
    baseline_status=json.loads((OUT/'baseline-status.json').read_text(encoding='utf8'))
    baseline_ok=not any(baseline_status.values())
    metadata={'commit':ext['commit'],'created_at':now.isoformat(),
              'new_cases':len(rows),'counts':dict(count),'original_unit_tests':unit_count,'baseline_exit_codes':baseline_status,'original_lab':22,
              'eval_unique_cases':len({r['id'] for r in config['runs']}),'eval_runs':len(config['runs']),'eval_counts':dict(evalcounts)}
    (OUT/'summary.json').write_text(json.dumps(metadata,ensure_ascii=False,indent=2),encoding='utf8')
    e=html.escape
    summary=f'''修复后检查 {len(rows)} 项：{count['PASS']} 项通过、{count['FAIL']} 项失败、{count['ERROR']} 项运行错误。
单元/HTTP及新增恢复测试 {unit_count} 项；基线脚本状态：{'全部完成且退出码为0' if baseline_ok else '存在失败，请查看baseline-status.json'}。
原有对话评测 {len(config['runs'])} 次：{evalcounts['PASS']} 次通过、{sum(v for k,v in evalcounts.items() if k!='PASS')} 次未通过；内置安全实验室22种攻击。
上轮52项扩展失败的对应断言已保留。通过当前测试不等同于真实资金产品安全认证；真实DBS、实机生物识别及真人适老性仍需验收。'''
    scope='''范围：此仓库本地修复版本，基于main尚未提交；离线英文规则模式、模拟银行、真实测试P-256签名、软件WebAuthn认证器（原有测试）、本机Edge无头浏览器。
安全故障注入使用脚本化模型/核验结果，并非真实在线模型评测。ASR适配器用模拟响应，语音时序用模拟SpeechRecognition事件。
没有测试真实DBS账户、真实扣款、云模型效果、真实麦克风识别率、Windows Hello实体验证、iOS/Safari/Android设备、长时间负载或真实老年用户可用性。
所有新增测试使用临时账本/审计/凭证和随机端口，不连接正在运行的localhost:8000。已修复业务代码，未推送GitHub。'''
    procedure='''1. 固定LLM_PROVIDER=offline、风控小时=14，并使用独立临时数据目录。
2. 重跑原有及新增单元测试、22项实验室攻击及84场景×3次评测。
3. 按正常/否定/模糊/纠正/重复/非法类型生成新用例；核对草稿、资金、状态、回执，而非只核对回复文本。
4. 用真实P-256签名走授权与执行；注入风险升级、账单竞争、审计失败、无效核验输出。
5. Edge模拟用户点击、下载、刷新、付款响应丢失、取消失败及语音事件，保存失败截图。
6. 复核失败断言、区分产品问题和测试夹具问题，导出预期/实际/证据/修复建议。'''
    matrix=[
        ('转账与来源账户','S01–S08、K01/K02、B_pay、B_doubleclick','正常主流程通过；异常语义失败'),
        ('账单支付','S09/S10、K03、K_double_bill、B_bill','正常结清通过；跨草稿重复结清失败'),
        ('投资/基金/债券/ETF/SGX/US股票','S11–S19、K04–K06、B_investment','各产品草稿通过，选取基金/定存/美股完成签名执行'),
        ('余额/养老金/流水/账单/持仓/收款人查询','Q01–Q06、首页及导航','离线查询通过；复杂措辞见原评测失败'),
        ('多轮澄清与复合任务','C01–C07、M01/M02、B_multi','孙子消歧和顺序授权通过；纠正/取消失败'),
        ('锁卡/禁止解锁','L01–L03、AI_lock_unasked','正常锁卡与禁止解锁通过；模型误锁卡失败'),
        ('诈骗防护/动态风险','F01–F04、K_risk_*、K_late_scam_chat、原有hard评测','未发现无签名扣款；新增风险重检与变体诈骗提醒存在缺口'),
        ('双引擎核验/模型降级','AI_*、K_empty_verifier、B_frozen','显式字段不一致可冻结；无效字段处理失败'),
        ('签名/防篡改/重放/过期/余额','原有passkey测试、K_*、B_pay','密码学校验及普通防重通过；身份移除与恢复仍需加强'),
        ('账户保护','P_signed_delay、P_bad_signature、B_senior','签名降低且24小时延迟，取消降低通过'),
        ('回执/审计/下载/人工服务','K_receipt_tamper、B_download、B_audit_export、R_*','正常导出验签通过；审计故障、虚假客服提示失败'),
        ('Web安全/隔离/限流','H_*、B_xss','跨源/Host/静态文件保护通过；类型/分块/身份/限流有缺口'),
        ('语音/权限/续说/云ASR异常','B_voice_*、V_asr_*','正常续说通过；网络错误半句提交与非JSON响应失败'),
        ('适老/大字/朗读设置/移动布局/重置','B_senior/B_preferences/B_mobile*、B_reset','所测Edge视口与设置通过；真人可用性待验证'),
    ]
    matrix=[(name, ids, '对应扩展用例通过；详情见逐项记录' if not count['FAIL'] and not count['ERROR'] else '请查看逐项记录及下方失败项') for name,ids,_ in matrix]
    failure_ids={r['id'] for r in rows if r['status']=='FAIL'}
    mapped={id for item in ISSUES for id in item[2]}
    # Do not silently omit failures when tests evolve.
    unmapped=sorted(failure_ids-mapped)
    findings=''
    mdissues=[]
    for idx,(priority,title,ids,steps,actual,fix,source) in enumerate(ISSUES,1):
        active=[id for id in ids if id in failure_ids]
        if not active:continue
        findings+=f'<article class="issue"><div class="tag">{e(priority)} · #{idx}</div><h3>{e(title)}</h3><p><b>复现：</b>{e(steps)}</p><p><b>实际：</b>{e(actual)}</p><p><b>建议与验收：</b>{e(fix)}</p><p class="muted">用例 {e(", ".join(active))} · <a href="../{source}">{e(source)}</a></p></article>'
        mdissues.append(f'### {priority} · {title}\n\n- 用例：{", ".join(active)}\n- 复现：{steps}\n- 实际：{actual}\n- 建议与验收：{fix}\n- 代码：[{source}](../{source})\n')
    casehtml=''.join(f'<details class="case {r["status"]}" data-group="{e(r["group"])}"><summary><span class="tag">{r["status"]}</span> <b>{e(r["id"])}</b> · {e(r["title"])}</summary><p>{e(r["group"])} · {e(r["priority"])} · {r["ms"]}ms</p><p><b>预期：</b>{e(r["expected"])}</p><pre>{e(json.dumps(r["observed"],ensure_ascii=False,indent=2))}</pre></details>' for r in rows)
    table='<table><thead><tr><th>功能</th><th>证据</th><th>结果</th></tr></thead><tbody>'+''.join('<tr>'+''.join(f'<td>{e(x)}</td>' for x in row)+'</tr>' for row in matrix)+'</tbody></table>'
    hardfails=[r for r in config['runs'] if r['status']!='PASS']
    uniq={r['id']:r for r in hardfails}
    evalhtml=''.join(f'<details><summary>{e(id)} · {e(" → ".join(r["turns"]))}</summary><pre>{e(json.dumps({k:r.get(k) for k in ("reply","error","checks","status")},ensure_ascii=False,indent=2))}</pre></details>' for id,r in uniq.items())
    commands='''# 安装浏览器测试依赖（只需一次，使用已安装的Edge）
.\\.venv\\Scripts\\python.exe -m pip install -r qa\\requirements.txt
# 一键重跑并生成报告；发现失败退出码为1
.\\.venv\\Scripts\\python.exe qa\\run_all.py
# 分别运行
.\\.venv\\Scripts\\python.exe qa\\run_extended.py
.\\.venv\\Scripts\\python.exe qa\\run_browser.py
.\\.venv\\Scripts\\python.exe qa\\build_report.py'''
    report=f'''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DBS Agent 全功能测试报告</title>
<style>body{{margin:0;background:#f3f5f8;color:#14253e;font:16px/1.75 system-ui,"Microsoft YaHei",sans-serif}}main{{max-width:1120px;margin:auto;padding:32px 24px 80px}}h1{{font-size:32px;margin-bottom:4px}}h2{{margin-top:38px}}h3{{margin:6px 0}}.muted{{color:#58677a;font-size:14px}}.intro,.issue,details,.panel{{background:white;border:1px solid #dce2ea;border-radius:12px;padding:18px 22px;margin:12px 0}}.intro{{border-top:5px solid #d91335}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.stats div{{background:#172e50;color:white;border-radius:10px;padding:16px}}.stats strong{{display:block;font-size:30px}}.tag{{font-size:13px;font-weight:700;color:#a32132}}.PASS .tag{{color:#126545}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f9;padding:16px;font-size:13px;max-height:500px;overflow:auto}}table{{width:100%;border-collapse:collapse;background:white}}th,td{{text-align:left;padding:12px;border:1px solid #dce2ea;vertical-align:top}}button,input{{font:inherit;padding:8px 12px;margin:4px;border:1px solid #9aaabc;border-radius:7px}}button{{cursor:pointer;background:white}}summary{{cursor:pointer}}img{{max-width:100%;border:1px solid #ccd3de}}.shots{{display:grid;grid-template-columns:2fr 1fr;gap:16px;align-items:start}}a{{color:#215ba8}}@media(max-width:700px){{main{{padding:18px 12px}}.stats{{grid-template-columns:1fr 1fr}}table{{font-size:13px}}.shots{{display:block}}}}</style>
<main><p class="muted">本地可复现验收 · {today} · <code>{e(ext['commit'][:12])}</code></p><h1>DBS Agent 全功能测试报告</h1><p class="muted">离线规则 · 签名交易 · 风控边界 · Edge界面 · 故障恢复</p>
<div class="intro">{''.join('<p>'+e(p)+'</p>' for p in summary.splitlines())}</div>
<div class="stats"><div>新增检查<strong>{len(rows)}</strong></div><div>通过<strong>{count['PASS']}</strong></div><div>失败<strong>{count['FAIL']}</strong></div><div>运行错误<strong>{count['ERROR']}</strong></div></div>
<h2>范围与限制</h2><div class="panel">{''.join('<p>'+e(p)+'</p>' for p in scope.splitlines())}</div>
<h2>测试流程</h2><div class="panel">{''.join('<p>'+e(p)+'</p>' for p in procedure.splitlines())}</div>
<h2>功能覆盖矩阵</h2>{table}
<h2>需要处理的问题</h2><p>P0：交易账务/结果一致性，应先修复；P1：安全、意图或恢复流程缺陷；P2：健壮性与表达。分级是本次项目验收判断，不是CVSS评分。</p>{findings}
<h2>原有对话评测</h2><p>{evalcounts['PASS']}/{len(config['runs'])} 次通过；下列仅显示未通过场景。</p>{evalhtml}
<h2>浏览器证据</h2><p>左图：付款响应丢失后的当前页面；右图：适老模式390px布局。</p><div class="shots"><a href="results/lost-response.png"><img src="results/lost-response.png" alt="付款响应丢失"></a><a href="results/senior-mobile.png"><img src="results/senior-mobile.png" alt="适老移动界面"></a></div>
<h2>全部新增用例与实际输出</h2><div><button data-filter="ALL">全部</button><button data-filter="FAIL">只看失败</button><button data-filter="PASS">只看通过</button><input id="search" placeholder="搜索用例、功能或输入" aria-label="搜索用例"></div><p id="shown" class="muted"></p>{casehtml}
<h2>复跑命令</h2><pre>{e(commands)}</pre><p>详细原始数据：<a href="results/extended.json">后端/语义结果</a> · <a href="results/browser.json">浏览器结果</a> · <a href="results/baseline-eval.json">原评测</a> · <a href="README.md">测试说明</a>。业务代码已修复，原失败断言作为回归标准保留。</p>
<p class="muted">生成时间：{e(metadata['created_at'])}；未归类失败：{e(str(unmapped))}</p></main>
<script>let selected='ALL';function filter(){{let n=0;const text=document.querySelector('#search').value.toLowerCase();document.querySelectorAll('.case').forEach(el=>{{const show=(selected==='ALL'||el.classList.contains(selected))&&el.textContent.toLowerCase().includes(text);el.hidden=!show;if(show)n++;}});document.querySelector('#shown').textContent=`显示 ${{n}} 条用例`;}}document.querySelectorAll('[data-filter]').forEach(b=>b.onclick=()=>{{selected=b.dataset.filter;filter();}});document.querySelector('#search').oninput=filter;filter();</script></html>'''
    (HERE/'report.html').write_text(report,encoding='utf8')
    md=f'# DBS Agent 全功能测试报告\n\n版本：`{ext["commit"]}`\n\n{summary}\n\n## 测试范围\n\n{scope}\n\n## 测试流程\n\n{procedure}\n\n## 功能覆盖\n\n| 功能 | 用例 | 结果 |\n|---|---|---|\n'+''.join('| '+' | '.join(row)+' |\n' for row in matrix)+'\n## 问题与复现\n\n'+'\n'.join(mdissues)+f'\n## 复跑\n\n```powershell\n{commands}\n```\n\n完整用例输出及截图见[交互报告](report.html)。\n'
    (HERE/'REPORT.md').write_text(md,encoding='utf8')
    with zipfile.ZipFile(HERE/('DBS-QA-'+today.replace('-','')+'.zip'),'w',zipfile.ZIP_DEFLATED) as z:
        for p in HERE.rglob('*'):
            if p.is_file() and p.suffix not in ('.zip','.pyc') and '__pycache__' not in p.parts and 'runs' not in p.relative_to(HERE).parts and p.name not in ('browser-run.log','browser-rerun.log','results-run.log'):
                z.write(p,p.relative_to(ROOT))
    print(json.dumps(metadata,ensure_ascii=False))
    if unmapped:print('Unmapped failures:',unmapped)

if __name__=='__main__':build()
