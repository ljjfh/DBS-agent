# DBS Agent 全功能测试报告

版本：`b5ba6d4e4e9670231374f5728cdd6adbdd570d53`

修复后检查 170 项：170 项通过、0 项失败、0 项运行错误。
单元/HTTP及新增恢复测试 170 项；基线脚本状态：全部完成且退出码为0。
原有对话评测 252 次：252 次通过、0 次未通过；内置安全实验室22种攻击。
上轮52项扩展失败的对应断言已保留。通过当前测试不等同于真实资金产品安全认证；真实DBS、实机生物识别及真人适老性仍需验收。

## 测试范围

范围：此仓库本地修复版本，基于main尚未提交；离线英文规则模式、模拟银行、真实测试P-256签名、软件WebAuthn认证器（原有测试）、本机Edge无头浏览器。
安全故障注入使用脚本化模型/核验结果，并非真实在线模型评测。ASR适配器用模拟响应，语音时序用模拟SpeechRecognition事件。
没有测试真实DBS账户、真实扣款、云模型效果、真实麦克风识别率、Windows Hello实体验证、iOS/Safari/Android设备、长时间负载或真实老年用户可用性。
所有新增测试使用临时账本/审计/凭证和随机端口，不连接正在运行的localhost:8000。已修复业务代码，未推送GitHub。

## 测试流程

1. 固定LLM_PROVIDER=offline、风控小时=14，并使用独立临时数据目录。
2. 重跑原有及新增单元测试、22项实验室攻击及84场景×3次评测。
3. 按正常/否定/模糊/纠正/重复/非法类型生成新用例；核对草稿、资金、状态、回执，而非只核对回复文本。
4. 用真实P-256签名走授权与执行；注入风险升级、账单竞争、审计失败、无效核验输出。
5. Edge模拟用户点击、下载、刷新、付款响应丢失、取消失败及语音事件，保存失败截图。
6. 复核失败断言、区分产品问题和测试夹具问题，导出预期/实际/证据/修复建议。

## 功能覆盖

| 功能 | 用例 | 结果 |
|---|---|---|
| 转账与来源账户 | S01–S08、K01/K02、B_pay、B_doubleclick | 对应扩展用例通过；详情见逐项记录 |
| 账单支付 | S09/S10、K03、K_double_bill、B_bill | 对应扩展用例通过；详情见逐项记录 |
| 投资/基金/债券/ETF/SGX/US股票 | S11–S19、K04–K06、B_investment | 对应扩展用例通过；详情见逐项记录 |
| 余额/养老金/流水/账单/持仓/收款人查询 | Q01–Q06、首页及导航 | 对应扩展用例通过；详情见逐项记录 |
| 多轮澄清与复合任务 | C01–C07、M01/M02、B_multi | 对应扩展用例通过；详情见逐项记录 |
| 锁卡/禁止解锁 | L01–L03、AI_lock_unasked | 对应扩展用例通过；详情见逐项记录 |
| 诈骗防护/动态风险 | F01–F04、K_risk_*、K_late_scam_chat、原有hard评测 | 对应扩展用例通过；详情见逐项记录 |
| 双引擎核验/模型降级 | AI_*、K_empty_verifier、B_frozen | 对应扩展用例通过；详情见逐项记录 |
| 签名/防篡改/重放/过期/余额 | 原有passkey测试、K_*、B_pay | 对应扩展用例通过；详情见逐项记录 |
| 账户保护 | P_signed_delay、P_bad_signature、B_senior | 对应扩展用例通过；详情见逐项记录 |
| 回执/审计/下载/人工服务 | K_receipt_tamper、B_download、B_audit_export、R_* | 对应扩展用例通过；详情见逐项记录 |
| Web安全/隔离/限流 | H_*、B_xss | 对应扩展用例通过；详情见逐项记录 |
| 语音/权限/续说/云ASR异常 | B_voice_*、V_asr_* | 对应扩展用例通过；详情见逐项记录 |
| 适老/大字/朗读设置/移动布局/重置 | B_senior/B_preferences/B_mobile*、B_reset | 对应扩展用例通过；详情见逐项记录 |

## 问题与复现


## 复跑

```powershell
# 安装浏览器测试依赖（只需一次，使用已安装的Edge）
.\.venv\Scripts\python.exe -m pip install -r qa\requirements.txt
# 一键重跑并生成报告；发现失败退出码为1
.\.venv\Scripts\python.exe qa\run_all.py
# 分别运行
.\.venv\Scripts\python.exe qa\run_extended.py
.\.venv\Scripts\python.exe qa\run_browser.py
.\.venv\Scripts\python.exe qa\build_report.py
```

完整用例输出及截图见[交互报告](report.html)。
