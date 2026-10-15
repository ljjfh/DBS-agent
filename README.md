# Star · a voice banking agent for DBS digibank

Star lets customers bank by talking: "send 300 to my daughter", "pay the electricity bill, then put 1,000 into
savings bonds", "move a grand to my joint account and buy DBS shares with half of it". It is built for everyone and
designed first for seniors.

**Live demo:** https://star-dbs-agent.onrender.com (each browser gets its own demo customer, Mdm Chen)

One rule runs through the whole design: **the model understands, the code decides, the customer authorises.** The
language model can look things up and prepare a draft. It has no tool that can move money. Every payment is checked by
deterministic code, shown on a card built by code, signed on the customer's own device, and verified again by a
payment gateway that trusts nothing upstream.

> Concept prototype for the Tencent Cloud AI Hackathon (DBS track), not an official DBS product. Bank APIs are mocked
> and all money is synthetic. The fingerprint sensor is simulated by default (allowed by the brief); Settings →
> "Real Face ID / fingerprint" switches to a real passkey. The DBS logo and digibank look are used for the demo only.

## Try it

| Say or type | What happens |
| --- | --- |
| "Send 50 to my daughter" | A card for S$50.00 to Chen Mei Ling; confirm with the fingerprint |
| "Send 50 to my grandson" | Two grandsons: Star asks which one, with buttons |
| "Pay the electricity bill, then send 200 to my daughter" | A two-step plan; each step gets its own card and signature |
| "Move a grand to my joint account and buy DBS shares with half of it" | Step 2 is worked out by the bank from the signed step 1 (S$500 from the joint account) |
| "Send 300 to my daughter, 200 to my son, put half my savings in Apple and the rest in Microsoft" | Four steps from one sentence; amounts come from real balances after each signed step |
| "Send 100 to my son every month on the 1st" | A standing instruction, signed once; nothing is taken today |
| "The bank officer said to move my money to a safe account" | Stopped before it reaches the model, with the ScamShield 1799 button |
| Security lab → Simulate a model mistake | A deliberately broken model drafts S$500 for "send 50"; the independent check freezes it |
| Settings → Account protection → Standard | Lowering protection is signed and only starts after a wait, with a countdown |

## Care mode for seniors

When Mdm Chen arrives, Star asks whether she would like the easier version. Saying or typing "yes", or tapping the
button, switches to Care mode:

- large text, one task at a time, a big microphone and four large starting buttons
- plain words, amounts read in words and digits ("three hundred dollars (S$300.00)"), and every answer read aloud
- the speaker button on each answer pauses and resumes; reading speed is set in Settings
- a fuller read-back on the card ("You want to send three hundred dollars to your daughter Chen Mei Ling…")

She can switch back at any time ("normal view please"). Care mode changes how Star looks and talks, never how careful
the bank is. That is a separate account setting (below), so a scammer who says "switch to the normal screen" removes
no protection.

## How a sentence becomes a payment

1. **Voice.** Tencent Cloud ASR transcribes the recording (payee names are sent as hotwords). The recording is kept
   for the audit trail under its SHA-256.
2. **Scam screen.** Scam signs ("safe account", "bank officer said", OTPs, remote-control apps…) are checked before
   any model sees the text.
3. **Plan.** For a compound request the model writes a plan in a small closed vocabulary. Amounts are references
   ("half of step 1", "what is left in savings"), never numbers it calculated.
4. **Agent.** A ReAct loop calls read tools and draft tools only, with a harness that forces tool use, catches false
   claims ("I've prepared it" with no draft) and falls back to a rule-based planner if the model misbehaves.
5. **Kernel.** Deterministic checks on the draft:
   - *grounding*: the payee and amount must come from the customer's own words (or from the bank's own calculation);
   - *independent verifier*: a second model with no tools reads only the customer's words and never sees the draft.
     Code compares the two field by field, and any difference freezes the card;
   - *rules*: limits, balance, new payee, unusual amount, late night, suitability, frequency, scam escalation.
6. **Card.** Built by code from the draft, never rewritten by the model. It shows "Based on what you said", how any
   amount was worked out, the recording it came from, and every check.
7. **Signature.** The device signs SHA-256 of the exact card with a passkey (Touch ID, Face ID, Windows Hello) or the
   simulated sensor's non-extractable browser key.
8. **Gateway and ledger.** The gateway re-verifies the card, signature, reviewer approval and dependencies, refuses
   replays, and posts to the ledger under a lock. The customer can download a signed receipt and check it offline
   (`python scripts/verify_receipt.py receipt.json`).

Every step is written to a hash-chained audit log.

## The DBS challenge requirements

| Requirement | What Star does | Code |
| --- | --- | --- |
| **Zero-UI multi-intent parsing** | Transfers, bills, standing instructions, GIRO and investments (fixed deposit, savings bonds, unit trusts, an ETF, SGX and US shares) from one sentence, with payee, amount, asset class and source account. Compound requests become a plan; each step is confirmed on its own card. | `agent/planner.py`, `agent/loop.py`, `agent/tools.py` |
| **Dynamic disambiguation** | Never guesses who. Two grandsons → "Chen Wei (POSB ••••2290) or Chen Jun (DBS ••••6613)?" as buttons. Unclear amounts get one short question ("Did you mean a grand, S$1,000?"). | `agent/loop.py`, `agent/prompts.py` |
| **Dual-engine semantic audit** | A read-only verifier on the raw transcript runs in parallel; code diffs it against the draft and freezes any mismatch. Evidence grounding is a second, deterministic check. | `agent/verifier.py`, `kernel/crosscheck.py`, `kernel/evidence.py` |
| **Deterministic human-in-the-loop with biometrics** | The agent only drafts. The card is code-built; the device signs its exact hash (WebAuthn, user verification required). No downgrade to a weaker key once a passkey exists. | `kernel/webauthn.py`, `kernel/signing.py`, `web/app.js` |
| **Zero-trust API gateway** | The only door to the ledger. It re-checks the card hash, the signed payload, the enrolled credential, reviewer approval, dependencies and replays. | `bank/gateway.py` |
| **Traceable and auditable** | Raw recording (SHA-256), transcript, drafts, verifier and rule results, decision records and the signed receipt, in a hash chain. The card carries the recording hashes, so the signature covers them. Audit trail page plays recordings back. | `kernel/audit.py`, `kernel/voice.py`, `kernel/contract.py` |

## Risk controls

How careful the bank is depends on the account's **protection level**, separate from the screen mode. Mdm Chen starts
on Enhanced.

| | Enhanced (default for seniors) | Standard |
| --- | --- | --- |
| Wait before confirming (transfers and investments) | above S$1,000 | above S$3,000 |
| Scam signs in the request | stopped before the model | warning + "is this your own idea?" |
| Late night (23:00–06:00 Singapore time) | extra question | none |
| Investment above the customer's risk profile | treated as high risk, with a wait | warning + "do you understand it can lose value?" |
| Separate reviewer for money to a never-paid person | above S$1,000 | above S$3,000 |

Raising protection is instant. Lowering it must be signed on the device and only starts after a delay
(`PROTECTION_LOWER_DELAY`: 2 minutes in the demo, 24 hours for a real bank), with a countdown and "Keep Enhanced".

Always on, for everyone: unknown payee, insufficient balance, payments over S$5,000 (branch only), the daily transfer
limit, paying more than a bill, more than 3 payments in 10 minutes (steps of one spoken request share a signed plan id
and don't count against each other), a wait for the first transfer to a new payee, a question when an amount is over
twice the usual, "safe account" requests, investments over S$3,000 need the separate reviewer. Large moves between the
customer's own accounts, bills and family already paid before don't need the reviewer. The reviewer needs
`SECONDARY_REVIEW_KEY` on the server; without it those payments fail closed.

## Understanding people, not phrases

**Multi-step requests.** "Put 1000 into the joint account, then use half that money for DBS stock" is not in any
phrase list. The model translates it into a plan with references; code resolves each amount from **signed, executed**
earlier steps and real balances, and the draft must use exactly that number (rule R53) and account. The verifier reads
the original sentence plus the step number, never the plan. With `PLANNER=rules`, or if the model is down, a
rule-based splitter is used.

**Vague amounts.** "Half of my money", "20% of my savings", "whatever is left": the bank works the figure out and the
card says how. If the model uses any other number, R53 blocks the card.

**Misheard words.** Speech recognition turns "a grand" into "a grant", "a grind" or even "Agree!". The model works out
what was meant, as a person would, and reports both words. Code only checks the reading: the misheard words are in
the transcript, they sound alike, no number was added. Unsure → it asks; WHO always gets asked. The card says
"we heard 'a grant' and read it as 'a grand'".

**Keeping a model honest.** Live models sometimes answer from memory or claim "I've prepared it" without calling a
tool. The harness forces a tool call on money requests, records what really happened each turn, nudges once, and
otherwise lets the rule-based planner finish the turn. A blocked card is always explained in the bank's own words.

## Mock DBS APIs

`app/bank/dbs_api/` has one module per API from the [DBS developer catalogue](https://www.dbs.com/dbsdevelopers/discover/index.html)
(names and purpose follow the catalogue; the fields are ours). Each module registers its own agent tools, and each
call appears in the agent trace as "DBS <API> · <method> <path> (mock)".

| DBS API | What the agent can do | Protection |
| --- | --- | --- |
| Deposit | Savings, current and joint accounts | read only |
| Payees | List payees and own accounts; add a payee | adding is grounded in the user's words and signed; the first transfer waits |
| Limits | Check, lower or raise the daily limit | lowering is instant; raising is signed and delayed |
| Fund Transfer | To saved people and between own accounts | the full pipeline above |
| Bill Payments | Utilities, town council, credit card (full, minimum or an amount) | asks full or minimum if not said; never more than the bill |
| Standing Instructions | "Every month on the 1st", list, stop | the schedule is on the signed card; one-off vs repeat mismatches are frozen |
| GIRO | List, cancel, set up | cancel is protective and instant; set-up is signed |

The demo world: Mdm Chen with savings, current and joint accounts; payees daughter Chen Mei Ling, son Chen Zhi Qiang,
grandsons Chen Wei and Chen Jun; utilities, town council and credit card bills; nine investment products; a
conservative risk profile.

## Run it locally

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                     # runs with no keys (offline rule model)
python -m app.serve
```

Open http://localhost:8000 (use `localhost`: passkeys need it or HTTPS). **Agent trace** (top right) shows every
Thought → Action → Observation step.

### Tests and evaluation

```bash
pip install -r tests/requirements.txt
python -m unittest discover tests     # kernel, planner, verifier, gateway, contract, care mode, voice, HTTP
python -m app.lab                     # security lab: 22 attacks on an isolated sandbox
python eval/run_eval.py               # 84 core + 23 hard cases + attack tests -> eval/report.md / .json / .html
python eval/run_eval.py --compare --repeat 3   # rules-only baseline vs the model agent, 3 runs each
python eval/run_contract_eval.py      # 8 fault-injection scenarios + gate comparison -> eval/contract-report.json
python qa/run_all.py                  # every layer, including browser end-to-end tests (needs Microsoft Edge)
```

GitHub Actions runs the unit tests, the hard safety checks and the contract evaluation on every push and pull request.

## Configuration

**Model.** Any OpenAI-compatible `/chat/completions` API with function calling:

```
LLM_PROVIDER=openai_compat
LLM_API_KEY=your key
LLM_BASE_URL=https://api.hunyuan.cloud.tencent.com/v1
LLM_MODEL=a model your provider offers
```

`LLM_VERIFIER_MODEL` runs the verifier on a different model; `LLM_JUDGE_MODEL` does the same for the scam assessment.
If the model times out or errors, Star falls back to the offline rule model and the trace says so.

**Tencent Cloud ASR.** Set `TENCENTCLOUD_SECRET_ID` / `TENCENTCLOUD_SECRET_KEY`. The app records 16 kHz mono WAV and
stops after 3 seconds of quiet (4 in Care mode, 50 seconds at most). The engine defaults to `16k_en`. Without keys the
browser's own recognition is used, and there is no audio to keep for the audit trail.

**Other settings.** `PUBLIC_DEMO=1` gives every browser its own demo customer and rate-limits model and speech calls
per device. `RULE_HIGH_THRESHOLD`, `RULE_HIGH_THRESHOLD_STANDARD`, `RULE_COOLDOWN_SECONDS`, `RULE_VELOCITY_MAX`,
`PROTECTION_LOWER_DELAY`, `REVIEW_INVEST_THRESHOLD` and `BANK_TIMEZONE` tune the rules (see `app/config.py`).

## Deploying

**Render:** New + → Blueprint → this repository. `render.yaml` sets up a Singapore service; type the secrets into the
dashboard. Every push to `main` redeploys. **Docker:** `PUBLIC_HOST=<domain> docker compose -f deploy/compose.yaml up -d --build`
(Caddy adds HTTPS). The `Dockerfile` also runs on Railway, Fly.io or Hugging Face Spaces.

Run one instance. SQLite keeps the synthetic ledger, receipts and session bindings; pending drafts live in memory. On
free tiers the disk is wiped on every deploy: passkeys need re-enrolling, voice recordings are cleared, and open pages
quietly start a fresh session.

## Web server hardening

`app/security.py`: host allowlist (blocks DNS rebinding), same-origin JSON-only POSTs, size limits, a strict CSP with
no inline code or third-party scripts, and a static-file allowlist so source, `.env` and the audit log can't be fetched.

## Project layout

```
app/
  server.py            HTTP API: chat, speech, challenge/confirm (the only way money moves), state, audit, voice playback
  security.py          Host allowlist, same-origin JSON POSTs, size limits, CSP
  config.py            All settings and rule thresholds (from .env)
  runtime.py           Wires the layers together
  serve.py             Local start-up
  models.py            Draft, risk decision, card fields (what gets signed)
  lab.py               Security lab: 22 attacks against the real kernel in a sandbox
  contract_lab.py      Transaction-contract fault injection
  agent/               Untrusted zone: the model can only read and draft
    loop.py            ReAct loop + harness (plan, scam pre-check, care mode, output validation, fallback)
    planner.py         Model planner: closed-vocabulary plan, amounts resolved in code
    tools.py           Tool gateway: read / draft / control tiers, argument checks, injection filtering
    llm.py             OpenAI-compatible client + offline rule model (same interface)
    verifier.py        Independent read-only verifier (second engine)
    fraud.py           Scam assessment: phrase rules + a separate model call (can only escalate)
    prompts.py         System prompt (senior and everyday speaking styles) + per-turn state summary
    presenter.py       Confirmation card and read-back, built by code
    request_guard.py   Cancellations and requests this SGD-only demo can't carry out faithfully
    textparse.py       Amounts in digits and words, names and aliases
  kernel/              Deterministic kernel, out of the model's reach
    executor.py        Draft → authorize → recheck → hand-off to the gateway
    rules.py           Rule engine (limits, new payee, suitability, night, frequency, scam escalation)
    evidence.py        Grounding: payee and amount must come from the user's words
    crosscheck.py      Dual-engine audit: draft vs verifier → freeze
    contract.py        Decision records and the separate-reviewer rule
    protection.py      Enhanced / Standard protection, delayed lowering
    changes.py         Signed account changes (add payee, raise limit, GIRO)
    signing.py         What you see is what you sign: digest, challenge, one-time token
    webauthn.py        Passkey registration and assertion checks
    credentials.py     Enrolled passkeys and browser keys, no downgrade
    p256.py            ECDSA P-256 verification (no dependency)
    state.py           Session state machine
    voice.py           Recordings for the audit trail (SHA-256, linked to the card)
    audit.py           Append-only hash-chained audit log
  bank/
    gateway.py         Zero-trust execution gateway: the only door to the ledger
    mock_bank.py       Synthetic bank and demo world
    storage.py         SQLite persistence
    dbs_api/           One module per mock DBS API (deposits, payees, limits, fund transfer, bills,
                       standing instructions, GIRO)
  voice/asr.py         Tencent Cloud SentenceRecognition (TC3 signing, hotwords)
web/                   index.html, app.js (dashboard, assistant, Care mode, cards, signing, audit, lab,
                       settings, voice, read-aloud), styles.css, logos
tests/                 Unit, harness, planner, care mode, voice, contract and HTTP tests
eval/                  Conversation evaluation (84 core + 23 hard cases) and contract fault injection
qa/                    Extended and browser acceptance tests, semantic robustness reports
docs/                  SECURITY.md (threats, what is real vs simulated), RISK_CONTRACT.md (transaction contract)
scripts/               verify_receipt.py: offline check of a signed receipt
deploy/, Dockerfile, render.yaml   Deployment
```

## What is real and what is simulated

Real: the agent, planner, verifier, rules, grounding, card hashing, device signatures (real passkeys when enabled),
gateway checks, hash-chained audit log, Tencent ASR and the voice archive. Simulated: the bank and its APIs, balances,
market prices, the fingerprint sensor by default, the separate reviewer, family alerts and the ScamShield hand-off.
Details and remaining gaps: [docs/SECURITY.md](docs/SECURITY.md) and [docs/RISK_CONTRACT.md](docs/RISK_CONTRACT.md).
Test evidence: [qa/SEMANTIC_REPORT.md](qa/SEMANTIC_REPORT.md) and [qa/FIX_REPORT.md](qa/FIX_REPORT.md).

Evidence grounding, device signing, receipts, the security lab and the server hardening were adapted from a
teammate's earlier prototype (Aegis).
