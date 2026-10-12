# 语义鲁棒性修复与复测

本轮修改业务代码后重新测试。所有交易均为模拟资金，未连接真实 DBS 账户。

## 当前结果

| 模式 | 用例 | PASS | FAIL | ERROR | UNSUPPORTED | 错误可授权草稿或未授权执行 |
|---|---:|---:|---:|---:|---:|---:|
| offline | 41 | 41 | 0 | 0 | 0 | 0 |
| live | 17 | 17 | 0 | 0 | 0 | 0 |

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
.\.venv\Scripts\python.exe qa\run_all.py
.\.venv\Scripts\python.exe qa\semantic_robustness.py --live
.\.venv\Scripts\python.exe qa\report_semantics.py
```

`run_all.py` 已包含离线语义和安全测试；真实模型测试需本地服务开启，单独运行。任一失败返回非零退出码。

## 逐项证据


### offline — 2026-10-13T01:10:21.312127+08:00

- **C01 PASS**：Send a grand to my daughter
- **C02 PASS**：Send two grand to my daughter
- **C03 PASS**：Send 1.5k to my daughter
- **C04 PASS**：Send five hundred bucks to my daughter
- **C05 PASS**：Send half a grand to my daughter
- **C06 PASS**：Send a couple of hundred dollars to my daughter
- **C07 PASS**：Send a hundred and fifty to my daughter
- **C08 PASS**：Send twenty dollars and fifty cents to my daughter
- **S01 PASS**：Wire 50 to my girl
- **S02 PASS**：Remit 50 to Chen Mei Ling
- **S03 PASS**：Move 50 to my daughter
- **S04 PASS**：PayNow 50 to my daughter
- **S05 PASS**：Settle the water and electricity for me
- **S06 PASS**：Buy 200 dollars of DBS stock
- **A01 PASS**：Ah, send ah girl two hundred lah, can?
- **A02 PASS**：Transfer fifty to Mei Ling, can or not?
- **A03 PASS**：Um I want to send er fifty dollars to my daughter please
- **A04 PASS**：Send fivety dollars to my daughter
- **A05 PASS**：Send two hundread dollars to my daughter
- **A06 PASS**：Buy 200 dollars of D B S shares
- **A07 PASS**：Send 50 to Chen Way
- **A08 PASS**：Send fifteen or fifty to my daughter
- **A09 PASS**：Send 50 to my grandson
- **A10 PASS**：Send 50 to Mei
- **T01 PASS**：Send money to my daughter → The usual amount
- **T02 PASS**：How much did I send my daughter last time? → Send her the same again
- **T03 PASS**：Send 200 to my daughter → Actually make that 100
- **T04 PASS**：Send 50 to my daughter → No, make it two hundred
- **T05 PASS**：Send two thousand no two hundred to my daughter
- **T06 PASS**：Transfer fifty from my current account to my daughter
- **M01 PASS**：Pay the electricity bill then send 50 to my daughter
- **M02 PASS**：Send 200 to my daughter and then buy DBS shares for half that amount
- **M03 PASS**：Send a grand to my daughter and then buy DBS shares for half that amount
- **M04 PASS**：Buy DBS shares with half of 1000 dollars
- **M05 PASS**：Send 200 to my daughter then send half as much to my son
- **M06 PASS**：Send 50 to my son and daughter each
- **M07 PASS**：Pay the electricity bill then send 50 to my daughter then invest 100 in income fund
- **M08 PASS**：Send 50 to my daughter and then buy 100 dollars of DBS shares from my current account
- **M09 PASS**：Buy DBS shares with half of it
- **U01 PASS**：Move a grand to my joint account and then buy DBS shares with half of it
- **U02 PASS**：Transfer 1000 from my savings account to my current account then buy DBS shares with half of it

### live — 2026-10-13T01:13:52.875162+08:00

- **C01 PASS**：Send a grand to my daughter
- **C03 PASS**：Send 1.5k to my daughter
- **C05 PASS**：Send half a grand to my daughter
- **C06 PASS**：Send a couple of hundred dollars to my daughter
- **S02 PASS**：Remit 50 to Chen Mei Ling
- **S03 PASS**：Move 50 to my daughter
- **S04 PASS**：PayNow 50 to my daughter
- **A01 PASS**：Ah, send ah girl two hundred lah, can?
- **A06 PASS**：Buy 200 dollars of D B S shares
- **A08 PASS**：Send fifteen or fifty to my daughter
- **T03 PASS**：Send 200 to my daughter → Actually make that 100
- **T05 PASS**：Send two thousand no two hundred to my daughter
- **M02 PASS**：Send 200 to my daughter and then buy DBS shares for half that amount
- **M04 PASS**：Buy DBS shares with half of 1000 dollars
- **M05 PASS**：Send 200 to my daughter then send half as much to my son
- **M09 PASS**：Buy DBS shares with half of it
- **U01 PASS**：Move a grand to my joint account and then buy DBS shares with half of it

完整回复、确认卡与资金变化见 [HTML 证据](semantic-report.html) 和 results/semantic-*.json。
