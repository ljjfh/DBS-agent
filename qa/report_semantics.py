"""Render current semantic evidence, keeping before-fix runs separately."""
import collections
import html
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
datasets = {mode: json.loads((HERE/'results'/f'semantic-{mode}.json').read_text(encoding='utf8'))
            for mode in ('offline', 'live')}
md = '''# 语义鲁棒性修复与复测

本轮修改业务代码后重新测试。所有交易均为模拟资金，未连接真实 DBS 账户。

## 当前结果

| 模式 | 用例 | PASS | FAIL | ERROR | UNSUPPORTED | 错误可授权草稿或未授权执行 |
|---|---:|---:|---:|---:|---:|---:|
'''
for mode, data in datasets.items():
    rows = data['results']
    counts = collections.Counter(r['status'] for r in rows)
    unsafe = sum(bool(r.get('unsafe_draft_or_execution')) for r in rows)
    md += f"| {mode} | {len(rows)} | {counts['PASS']} | {counts['FAIL']} | {counts['ERROR']} | {counts['UNSUPPORTED']} | {unsafe} |\n"
md += '''
## 修复内容

- `Actually make that 100`、`No, make it two hundred` 等更正会取消旧卡并创建新卡，旧签名不能支付新金额。更正仍经过诈骗扫描、独立校验和风险规则。
- 支持 a grand、half a grand、a couple of hundred、数字中的 and、remit/move/PayNow、分开拼写的 D B S；水电作为同一账单处理。
- 比例指代绑定上一任务的草稿 ID，仅在该任务有成功签名回执时取整数分金额的一半；父任务取消、未执行或结果包含半分钱时要求明确金额。修改父任务金额后引用也同步更新。
- 模型没有创建草稿时不能声称已准备。对明确金额和目标的请求，模型漏调工具可由离线解析器完成，但仍需独立校验和用户确认；工具明确拒绝后不走新增回退。
- 自有账户互转在同一账本事务中扣减来源账户并增加目标账户，校验账户归属及不同账户，签名绑定目标 ID。赛题示例可演示“1000 转联名账户，再从该账户拿 500 买 DBS 股份”。

## 测试标准调整，避免误报通过

原 A04（fivety）、A05（hundread）、A07（Chen Way）要求系统猜测正确金额或姓名。现改为“明确澄清且不生成可授权草稿”。这三项 PASS 表示安全处理，不代表无需澄清的自动理解能力。
U01/U02 原为 UNSUPPORTED 探测，现已实现模拟账户互转，改为检查两步金额、来源、目标；转账后检查来源扣款、目标入账和总余额守恒。
首页浏览器断言同步更新为三个账户、六个外部收款对象和三个内部账户目标。没有放宽金额或签名安全断言。
修复前证据：[离线原始结果](results/semantic-before-offline.json)、[真实模型原始结果](results/semantic-before-live.json)。第一轮修复仍失败的记录：[首次复测](results/semantic-fix-first-live.json)。

## 安全回归与方法

额外 14 项安全测试见 [semantic_safety.py](semantic_safety.py) 与 [执行日志](results/semantic-safety.log)：旧授权失效、更正诈骗扫描、换收款人需重述、取消父任务、父金额更正、无关历史回执、半分钱、歧义金额、近音姓名、内部资金守恒及幂等、存储失败回滚、未知账户、相同账户和篡改目标。
每条语义用例从独立客户开始，聊天不得扣款；对比确认卡的目标、整数分金额和来源账户。只有正确的中间步骤才签名，最后一步核对草稿，不执行。离线测试可模拟冷静期已过，真实服务测试不跳过冷静期。
系统保留原始输入及解析轨迹。比例解析在模型调用前以已完成回执为依据；模型校验读取的是明确展开后的当前任务。离线解析与离线校验共享解析器，不能当作两套完全独立模型。

## 能力边界

- 联名账户是零初始余额的**模拟单人授权账户**；没有实现真实 DBS 接口、联名账户共同签署规则或真实证券下单。
- 本轮只有文字和转写扰动，没有真实口音音频，不能推断语音识别准确率。
- 真实模型结果是固定用例本轮运行结果，不能证明所有自然语言输入都不会出错。仍保留歧义澄清、独立字段校验及逐笔签名。

## 复跑

```powershell
.\\.venv\\Scripts\\python.exe qa\\run_all.py
.\\.venv\\Scripts\\python.exe qa\\semantic_robustness.py --live
.\\.venv\\Scripts\\python.exe qa\\report_semantics.py
```

`run_all.py` 已包含离线语义和安全测试；真实模型测试需本地服务开启，单独运行。任一失败返回非零退出码。

## 逐项证据

'''
details = []
for mode, data in datasets.items():
    md += f"\n### {mode} — {data['created_at']}\n\n"
    for row in data['results']:
        title = f"{mode} · {row['id']} · {row['status']}"
        md += f"- **{row['id']} {row['status']}**：{' → '.join(row['turns'])}\n"
        for note in row.get('failures', []) + row.get('safety_findings', []):
            md += '  - ' + note + '\n'
        if row.get('error'):
            md += '  - ' + row['error'] + '\n'
        details.append('<details><summary>' + html.escape(title + ' · ' + ' → '.join(row['turns'])) +
                       '</summary><pre>' + html.escape(json.dumps(row, ensure_ascii=False, indent=2)) + '</pre></details>')
md += '\n完整回复、确认卡与资金变化见 [HTML 证据](semantic-report.html) 和 results/semantic-*.json。\n'
(HERE/'SEMANTIC_REPORT.md').write_text(md, encoding='utf8')
page = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>语义鲁棒性修复复测</title><style>body{max-width:1080px;margin:30px auto;padding:0 20px;font:16px/1.7 system-ui;color:#18304c}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f8;padding:18px}details{border:1px solid #ccd7e2;padding:12px;margin:12px 0}summary{cursor:pointer}</style>
<h1>语义鲁棒性修复复测</h1><p>三项转写歧义按安全澄清验收；未测试真实口音音频。联名账户为模拟单人授权账户。</p>
<p><a href="SEMANTIC_REPORT.md">修复说明、统计与测试边界</a></p>''' + ''.join(details) + '</html>'
(HERE/'semantic-report.html').write_text(page, encoding='utf8')
print('Updated SEMANTIC_REPORT.md and semantic-report.html')
