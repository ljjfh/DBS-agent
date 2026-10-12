"""Save this complete rerun and compare assertion statuses with the archived prior run."""
import collections,datetime,html,json,shutil
from pathlib import Path
root=Path(__file__).resolve().parent
run=json.loads((root/'current-run.json').read_text(encoding='utf8'))
archive=root.parent/Path(run['directory'])
now=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat()
extended=json.loads((root/'results/extended.json').read_text(encoding='utf8'))
browser=json.loads((root/'results/browser.json').read_text(encoding='utf8'))
evaluation=json.loads((root/'results/baseline-eval.json').read_text(encoding='utf8'))['configs'][0]
live=json.loads((root/'results/live-interfaces.json').read_text(encoding='utf8'))
changes=[]
for filename,current in [('extended.json',extended),('browser.json',browser)]:
    old=json.loads((archive/'before-results'/filename).read_text(encoding='utf8'))['results']
    old={r['id']:r['status'] for r in old}
    changes.extend({'id':r['id'],'before':old.get(r['id']),'after':r['status']} for r in current['results'] if old.get(r['id'])!=r['status'])
rows=extended['results']+browser['results']
counts=dict(collections.Counter(r['status'] for r in rows))
livecounts=dict(collections.Counter(r['status'] for r in live['results']))
summary={'run_id':run['run_id'],'completed_at':now,'commit':extended['commit'],
         'extended_counts':counts,'live_attempt_counts':livecounts,'status_changes':changes,
         'conclusion':'Not all acceptance tests pass. Primary live interfaces are working; safety and recovery failures remain.'}
(archive/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8')
text=f'''# 完整复跑结果 · 2026-10-13

**未全部通过。** 接入真实模型和语音后，接口可用；产品安全与异常流程的失败仍可复现。

本轮：`{run['run_id']}`；版本：`{extended['commit']}`；完成时间：{now}。

| 测试层 | 通过 | 失败 |
|---|---:|---:|
| 原有单元及HTTP测试 | 158 | 0 |
| 内置安全实验室 | 22 | 0 |
| 原有对话评测（84场景各3次） | 228 | 24 |
| 扩展后端/语义/安全测试 | {extended['counts']['PASS']} | {extended['counts']['FAIL']} |
| Edge浏览器端到端 | {browser['counts']['PASS']} | {browser['counts']['FAIL']} |
| 真实API首轮 | 32 | 1 |
| 账单确认后补充检查 | 1 | 0 |

扩展测试总计170项，118通过、52失败，0项运行错误。与上一轮逐用例状态比较：{len(changes)}项变化。相同的52项失败仍存在，不能通过再次运行或接上模型自动消失。

真实API首轮唯一未满足预期的场景是“Pay the electricity bill”：模型先询问是否支付utilities账单。用户明确确认后，成功生成S$86.40草稿并取消。原始FAIL保留，这并不是接口HTTP故障。含补充检查，真实接口记录为34次尝试、33通过、1次首轮未满足预期。

本轮模型文本、工具调用、JSON输出与余额/转账/投资均成功，未记录离线fallback。余额对话约9.93秒、转账草稿约8.24秒、投资草稿约5.45秒。真实腾讯云英文语音调用约1.28秒成功。初始并行模型探测日志中的seconds是收集future结果的等待时间，不能用来比较各请求实际时长。

## 仍需优先修复

1. 两个草稿可重复支付同一账单。
2. 审计写入失败时，已扣款却抛异常，缺少结果恢复。
3. 风险升级后旧确认卡仍可支付。
4. 否定、取消、纠正金额及币种等需求解析错误。
5. 网络失败后的付款/取消页面状态不准确。
6. 语音网络错误仍会提交半句话。

原有困难对话评测仍有8个场景反复失败，涉及复杂表达、多轮上下文及诈骗变体提醒。52个扩展失败归并为21类问题/原型限制，不是52个独立漏洞。

本次只改进测试记录和复跑脚本，未修复应用业务代码。银行仍为模拟账本；接口连通不代表真实金融产品安全验收通过。浏览器语音时序测试为模拟事件；真实云ASR使用合成英文样本；没有替代真人或实体生物认证验收。

[全部扩展用例与截图](report.html) · [真实API逐项证据](results/live-interfaces.json) · [测试源码与复跑说明](README.md)
'''
(root/'RERUN_20261013.md').write_text(text,encoding='utf8')
(root/'LIVE_API_CHECK.md').write_text(text.replace('# 完整复跑结果','# 本轮接口与完整测试结果',1),encoding='utf8')
shutil.copytree(root/'results',archive/'after-results',dirs_exist_ok=True)
for name in ('report.html','REPORT.md','LIVE_API_CHECK.md','RERUN_20261013.md'):
    shutil.copy2(root/name,archive/name)
print(json.dumps(summary,ensure_ascii=False))
