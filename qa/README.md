# DBS Agent 扩展验收测试

仅使用模拟账户。所有新增测试强制离线模型、临时审计/凭证、独立内存账本和随机HTTP端口，不请求正在运行的8000端口。银行、ASR上游、真实模型都不使用真实凭据。

```powershell
.\.venv\Scripts\python.exe -m pip install -r qa\requirements.txt
.\.venv\Scripts\python.exe qa\run_all.py
```

浏览器测试依赖本机安装的 Microsoft Edge。无头浏览器会真实执行页面JS、WebCrypto签名、HTTP请求和下载；SpeechRecognition被事件模拟器替代，不代表真实麦克风准确率。软件WebAuthn认证器也不能替代Windows Hello实体设备验收。

- [完整可搜索报告](report.html)：功能矩阵、风险分级、复现步骤、全部预期与实际输出、截图。
- [纯文本报告](REPORT.md)：方便后续修复或贴进产品文档。
- `run_extended.py`：原有基线＋新增语义/执行/模型故障/接口测试；`--skip-baseline`仅跳过基线。
- `run_browser.py`：UI端到端。`--only B_preferences`可重跑选定用例并合并结果；不能代表一次完整重跑。
- `build_report.py`：只重建报告和ZIP，不执行测试。
- `results/`：JSON证据、基线日志、截图与合成数据回执。没有私钥或真实客户信息。

**退出码1是验收失败，不是运行器失效。** JSON中FAIL表示断言与产品行为不符；ERROR表示用例出现未预期异常，需要检查栈信息。已知缺陷保留为失败回归用例，未使用expectedFailure掩盖。

统计按测试断言计算。同一根因可能导致多个失败；内置安全实验室也会在浏览器中再验证一次，不能把各层数量解释为独立漏洞数量。原有评测脚本即使有场景失败也可能返回0，必须读取JSON中的逐项结果。

复跑后查看 report.html 与 FIX_REPORT.md。修复包含签名移除Passkey、SQLite账本恢复和审计待补写队列；原失败断言仍保留。

`run_all.py` 会因任何单元、扩展、浏览器测试或对话评测失败而返回非零。`results/baseline-status.json` 保存基线脚本退出码。

真实API独立检查使用 `check_live_interfaces.py`，会读取.env；离线一键测试不会使用这些密钥。实机麦克风、Windows Hello、跨浏览器和真实老年人可用性仍属后续验收范围。

赛题语义专项见 [SEMANTIC_REPORT.md](SEMANTIC_REPORT.md)。包含41项离线、17项真实模型及14项安全回归；离线与安全测试已并入 `run_all.py`。真实模型单独运行 `python qa/semantic_robustness.py --live`，随后用 `python qa/report_semantics.py` 汇总。三项不确定转写按安全澄清验收；修复前证据保留，详见报告中的标准调整说明。
