# 小星 · DBS 智能交易 Agent（Hackathon 原型 v0.1）

面向所有人、针对老年人优化的对话式交易 Agent。核心原则：**LLM 负责听懂，代码负责决定，用户本人负责授权**。

> 原型，非 DBS 官方产品。银行接口为 Mock，生物识别为模拟。

## 5 分钟跑起来

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                     # 不填 key 也能跑（离线模式）
uvicorn app.server:app --reload --port 8000
```

打开 http://localhost:8000 ，点下方快捷按钮或直接说话/打字。右侧是 Agent 轨迹面板（路演用）。

```bash
python -m unittest discover tests     # 32 个单元测试（内核 + Harness 护栏）
python eval/run_eval.py               # 评测集 + 攻击测试，输出 eval/report.md
python eval/run_eval.py -v --only t1  # 看单个用例的完整轨迹
```

## 接入腾讯混元 / 其他模型

`.env` 里设置：

```
LLM_PROVIDER=openai_compat
LLM_API_KEY=你的 key
LLM_BASE_URL=https://api.hunyuan.cloud.tencent.com/v1
LLM_MODEL=控制台里可用、支持 Function Calling 的模型名
```

任何 OpenAI 兼容的 `/chat/completions` 接口都可以（混元国际版、赛事提供的其他模型等），只改这三项。
线上模型超时或报错时，会自动降级到离线模式，轨迹面板会显示 `Fallback`。

## 接入腾讯云 ASR

`.env` 填 `TENCENTCLOUD_SECRET_ID / SECRET_KEY`。前端会录 16k 单声道 WAV（单次最长 15 秒），后端调用一句话识别，
并自动把收款人称呼（女儿、阿囡、陈美玲……）作为临时热词传入。没配密钥时，前端改用浏览器自带的语音识别（Chrome）。

可调的只有：引擎（`ASR_ENGINE`）、热词表、识别后处理。ASR 本身的识别能力改不了，所以我们的设计是
**假设 ASR 会听错**：金额和收款人必须回读确认，授权只认生物识别。

## 架构与目录

```
用户（语音/文字）
  └─ web/index.html          适老界面：大字、单屏单问、确认卡、拦截页、Agent 轨迹面板、录音转 WAV、TTS
      └─ app/server.py       HTTP 接口；/api/confirm 是唯一能让钱动的入口（需要 digest + 生物识别）
          ├─ app/agent/      ── 不可信区：模型只能读、只能起草 ──
          │   ├─ loop.py         受限 ReAct 循环 + Harness（规划拆分、话术预检、步数上限、输出校验、降级）
          │   ├─ tools.py        工具网关：读/草稿/控制三级工具，动态收缩，参数校验，返回内容去注入
          │   ├─ llm.py          OpenAI 兼容客户端 + 离线规则模型（同接口）
          │   ├─ fraud.py        诈骗研判：确定性话术规则 + 独立第二次模型调用（只能升级）
          │   ├─ prompts.py      系统提示 + 每轮结构化状态摘要
          │   ├─ presenter.py    确认卡（完全由程序从草稿生成）与语音复述
          │   └─ textparse.py    中文金额解析、别名匹配、金额读法
          ├─ app/kernel/     ── 确定性内核：模型不可达 ──
          │   ├─ rules.py        规则引擎（限额/新收款人/异常金额/深夜/频率/诈骗升级）
          │   ├─ state.py        会话状态机（只能按序推进）
          │   ├─ signing.py      所见即所签：digest + 一次性 HMAC 授权令牌（防篡改、防重放）
          │   ├─ executor.py     起草 → 授权 → 执行前复检 → 幂等执行
          │   └─ audit.py        追加式哈希链审计日志
          ├─ app/bank/mock_bank.py   Mock 银行与固定测试世界（陈阿姨、女儿、儿子、两张账单）
          └─ app/voice/asr.py        腾讯云一句话识别（TC3 签名 + 热词）
eval/   cases.json（36 条，9 类）+ run_eval.py（跑分 + 6 项攻击测试）
tests/  内核测试 + “作恶模型”Harness 测试
```


2. 用 Miora 出适老 UI 稿，替换 `web/index.html` 的样式。
3. 加“添加新收款人”流程（强制冷静期），以及家人守护审批页。
4. 确认卡与风险理由多语言化（英、马来、泰米尔）。
5. 腾讯云 TTS 慢速播报；ASR 低置信度字段回读。
