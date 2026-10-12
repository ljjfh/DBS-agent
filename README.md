# Star · DBS Conversational Transaction Agent (Hackathon prototype v0.4)

A conversational transaction agent for everyone, optimized for elderly users. Core principle:
**the LLM understands, the code decides, and the user authorizes.**

> Prototype, not an official DBS product. The bank API is mocked. **The fingerprint sensor is simulated by default**
> (the DBS brief allows mock biometrics): a clearly labelled sensor screen, and the user's tap unlocks a
> non-extractable browser key that signs the exact card, which the kernel and the payment gateway both verify. Settings
> → "Real Face ID / fingerprint" switches to a real **passkey** (Touch ID / Face ID / Windows Hello). The DBS logo and digibank
> look are used for the hackathon demo only. What is real and what is simulated: [docs/SECURITY.md](docs/SECURITY.md).

## The five DBS challenge requirements, and where they live

| Requirement | What Star does | Code | Try it |
| --- | --- | --- | --- |
| **Zero-UI multi-intent parsing** | Transfers, bill payments and **investments** (fixed deposit, Singapore Savings Bonds, unit trusts, an ETF, **SGX and US shares** such as DBS, Singtel, Apple, Microsoft — demo prices), with payee, amount, asset class and **source account**, turned into a structured draft. Compound requests ("send 350 to my son and invest 1000 in a fixed deposit") become a plan the agent works through step by step, the user confirming each one. Also: portfolio ("how are my investments doing?") and **instant card lock** for a lost wallet (protective, so no fingerprint needed; unlocking is not possible through Star). | `agent/tools.py` (draft tools), `agent/loop.py` (plan), `models.Draft` | "Put 200 into the income fund from my current account" · "Pay the electricity bill, then send 200 to my daughter" |
| **Dynamic disambiguation** | Never guesses: asks one short question; when two payees match it names both with their account tails, as tap buttons. | `agent/llm.py`, `agent/loop._choices`, prompt | "Send 50 to my grandson" → "Do you mean Chen Wei (POSB ••••2290) or Chen Jun (DBS ••••6613)?" |
| **Dual-engine semantic audit** | A separate **read-only verifier** (no tools, can run on a different model) starts **in parallel**, sees only the user's raw transcript, never the draft, and extracts payee / amount / asset / account. Plain code compares it with the draft; any difference **freezes** it (it can never be signed) and the user is told what didn't match. Deterministic evidence grounding is a second check on top. | `agent/verifier.py`, `kernel/crosscheck.py`, `kernel/evidence.py` | Security lab → **Simulate a model mistake** (the model drafts S$500 for "Send 50 to my daughter") |
| **Deterministic HITL with native biometrics** | The agent can only draft. The confirmation card is built by code. The device signs SHA-256 of the exact card with a **WebAuthn passkey, userVerification required** (Touch ID / Face ID / Windows Hello; ES256 or RS256). The server checks the challenge, origin, rp id, the UV flag, the signature and the counter. No downgrade to a weaker key once a passkey exists. | `kernel/webauthn.py`, `kernel/credentials.py`, `web/app.js` | Confirm any payment on a Mac with Touch ID in Chrome / Safari |
| **Zero-trust API gateway** | The ledger is only reachable through an **execution gateway** that trusts nobody upstream, not even the kernel: it re-checks that the card hashes to the signed digest, the signed payload is for exactly this card, the signature verifies against an *enrolled* credential, and the signature was never used before. The agent has no tool that can write to the ledger. | `bank/gateway.py` | Security lab: "Call the ledger gateway directly", "Give the gateway a real signature for a different payment" |

**Keeping a small model honest.** Live models sometimes answer from memory ("I can't find a grandson") or claim
"I've prepared it" without calling a tool. The harness: forces a tool call on the first step of a money request
(`tool_choice=required`, skipped automatically if the API doesn't support it); records in the history what really
happened each turn; tells the model once when it answered without looking or claimed without drafting; and if it
still doesn't, lets the rule-based planner finish that turn. Every step shows in the Agent trace and is counted by
the eval as a model mistake caught.

**Protection levels are an account setting, not a screen setting.** Senior mode only changes the look. How careful
the bank is (cooling-off threshold, scam phrases stopped vs warned, late-night checks, risky investments) is
*Enhanced* or *Standard* protection. Raising it is instant. Lowering it must be signed with the fingerprint and only
takes effect after 24 h, so a scammer on the phone can't say "tap Standard view" and remove the protection. The hard
safety boundary (draft only, two-engine check, device signature, gateway) is the same for everyone.

## Running it

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                     # runs without any keys (offline mode)
uvicorn app.server:app --reload --port 8000
```

Open http://localhost:8000 (use `localhost`, not your LAN IP — see "Security" below). You land on a DBS digibank-style
dashboard: balances, the Star assistant, "Behind your request" (the live safety checks) and upcoming bills. Speak,
type, or tap a bill's **Pay** button. **Agent trace** (top right) opens the full Thought → Action → Observation log.

Things to try: "Invest 1000 in savings bonds", "Send 50 to my daughter from my current account", "Send 50 to my
grandson", the scam example, then **Security lab → Run all attacks** (22) and **Simulate a model mistake**, and
**Settings → Account protection**.

**Senior mode** (top-right button, remembered per browser) turns the same app into a one-task screen for elderly
users: 20px+ text, no sidebar, a large round microphone, four big "what do you want to do" buttons, one question at
a time with tap-to-answer choices, replies read aloud slowly, and a bigger confirmation card with the amount in
words. Settings also has "Larger text", "Read replies aloud" and "Reset demo".

```bash
python -m unittest discover tests     # 158 tests (kernel, passkeys, verifier, gateway, protection, Harness, HTTP)
python -m app.lab                    # security lab: 22 real attacks on an isolated sandbox
python eval/run_eval.py               # core + hard suites + attack tests -> eval/report.md / .json / .html
python eval/run_eval.py --compare --repeat 3   # the headline run: rules-only baseline vs LLM agent, 3x each
python eval/run_eval.py -v --only t1  # full trace for a single case
LLM_PROVIDER=offline python eval/run_eval.py   # force the offline baseline even if .env has a model configured
```

## Deploying online

The app is one Python web service (no build step, no database). Passkeys need HTTPS, which every option below
provides. Set `PUBLIC_DEMO=1` on any shared server: each browser then gets its own demo customer (its own balances,
payments, resets and passkey), "Reset demo" only resets that browser, and model/speech calls are rate-limited per
device so the API keys can't be drained.

**Render (quickest, free):** New + → Blueprint → pick this repository. `render.yaml` sets everything up in the
Singapore region; type the secrets (`LLM_*`, `TENCENTCLOUD_*`) into the dashboard when asked. Every push to `main`
redeploys. Free instances sleep after ~15 idle minutes (the first visit then takes about a minute); switch the plan
to Starter for judging week.

**Tencent Cloud Lighthouse / any Linux server with Docker:** copy `.env` to the server, then
`PUBLIC_HOST=<your domain> docker compose -f deploy/compose.yaml up -d --build`. Caddy gets the HTTPS certificate
automatically. Without a domain, use `<server IP with dashes>.sslip.io` (e.g. `43-128-1-2.sslip.io`).

**Anything else that runs a Dockerfile** (Railway, Fly.io, Hugging Face Spaces): the `Dockerfile` listens on `$PORT`;
the platform's hostname is allowed automatically, or set `PUBLIC_HOST`.

Notes: sessions live in memory, so run one instance. On free tiers the disk is wiped on every deploy, so passkeys
need re-enrolling (one fingerprint). If the model endpoint isn't reachable from the server (e.g. a campus-only API),
Star falls back to the offline rule model and the trace says so.

## Connecting a model (Tencent Hunyuan, Qwen or others)

Set in `.env`:

```
LLM_PROVIDER=openai_compat
LLM_API_KEY=your key
LLM_BASE_URL=https://api.hunyuan.cloud.tencent.com/v1
LLM_MODEL=a model name your provider offers that supports Function Calling
```

Optional: `LLM_VERIFIER_MODEL` runs the independent verifier on a different model (more independent engines).

Any OpenAI-compatible `/chat/completions` API works (Hunyuan international, a university Qwen endpoint, models
provided by the competition, etc.); only change these settings. The variable name must be exactly `LLM_MODEL`.
If the online model times out or errors, the agent automatically falls back to offline mode and the trace panel
shows `Fallback` with the error. Check the trace after your first message to confirm the model is really in use.

## Connecting Tencent Cloud ASR

Set `TENCENTCLOUD_SECRET_ID / SECRET_KEY` in `.env`. The frontend records 16k mono WAV and stops when the
customer taps the mic again or has been quiet for 3 seconds after speaking (4 seconds in Senior mode; at most 50
seconds per recording), the backend calls SentenceRecognition, and payee names (daughter, Mei Ling, …) are passed in
automatically as temporary hotwords. Without keys, the frontend uses the browser's built-in speech recognition
(Chrome) in continuous mode with the same pause rules, showing the words in the text box as they are heard.

The engine defaults to `16k_en`. The international endpoint (`asr.intl.tencentcloudapi.com`) does **not** support
`16k_zh_large`; that engine is only available on the China endpoint.

You can tell which recognizer was used from the trace panel: `Tencent Cloud ASR (16k_en, …ms): …` versus
`Browser speech recognition: …`.

All we can tune is the engine (`ASR_ENGINE`), the hotword list, and post-processing. We can't change how well the
ASR itself recognizes speech, so the design **assumes the ASR will mishear**: amounts and payees are always read
back for confirmation, and authorization only accepts the biometric check.

## How a payment is authorized

1. The agent can only **draft**. While it works, the **independent verifier** re-reads only the user's words
   (in parallel). The kernel then checks the draft two ways: against the verifier's reading (`kernel/crosscheck.py`:
   any stated field that differs → **FROZEN**), and against the literal words (`kernel/evidence.py`: payee not said →
   HIGH, amount not said → MEDIUM, neither → BLOCK). Then the rules grade it (limits, new payee, suitability…).
2. The card shows exactly what will happen, including **"Based on what you said: …"** and the verifier's result.
3. On confirm, the browser asks for a **challenge** (the exact card + nonce + expiry). With a passkey, the browser
   calls `navigator.credentials.get` with `challenge = SHA-256(challenge)` and `userVerification: "required"`: the OS
   shows its own fingerprint / face prompt. By default (simulated sensor) the user taps the demo fingerprint screen
   and a non-extractable WebCrypto key signs the same challenge.
4. The kernel verifies (`kernel/webauthn.py` / `kernel/p256.py`, pure Python; uses `cryptography` if installed),
   consumes the challenge once, re-runs the rules, and hands the signed instruction to the **execution gateway**,
   which verifies everything again on its own before posting to the ledger.
5. The user can download a **signed receipt** and check it offline, passkey signatures included:
   `python scripts/verify_receipt.py receipt-TXN-XXXX.json`

With **Settings → "Real Face ID / fingerprint"** on, the first payment asks your Mac / phone to save a passkey (one
extra fingerprint touch); turning it off removes it and brings back the simulated sensor. Passkeys need `localhost`
or HTTPS; Chrome and Safari both work.

**On Windows** the prompt is **Windows Hello**: fingerprint, face, or the Windows Hello PIN (all three count as
"user verified"). Set it up first in Settings → Accounts → Sign-in options, then use Chrome or Edge on
`http://localhost:8000`. Both key types Windows Hello may create (ES256 and RSA/RS256) are supported. A PC without
Windows Hello set up is offered a phone (QR code) or a security key instead. If Edge saves the passkey in Microsoft
Password Manager, it may sign without a fingerprint check; the server refuses that and the card offers "Set up
fingerprint again" (choose Windows Hello / this device).

Open **Security lab** in the sidebar to run 22 real attacks: unsigned, attacker key, tampered amount, replay,
expiry, cooling-off bypass, balance drained before execution, payment never asked for, hidden instructions, audit
edits, **model writes the wrong amount / payee / account (frozen by the verifier)**, signing without the verifier,
**passkey without fingerprint check, downgrade to a browser key, passkey for another site**, **calling the ledger
gateway directly / with a signature for another payment**, and **switching off senior protection without a
fingerprint**. Ideas for evidence grounding, device signing, receipts and the lab were adapted from a teammate's
prototype (Aegis).

## Security of the web server

`app/security.py` hardens the local demo server (also adapted from Aegis):

- **Host allowlist** — only answers to `localhost`, `127.0.0.1`, `[::1]` (blocks DNS rebinding). To demo from a phone
  on the same Wi-Fi, add your laptop's IP: `ALLOWED_HOSTS=localhost,127.0.0.1,192.168.1.23`. Note that browsers only
  allow Web Crypto signing on `localhost` or HTTPS, so on a LAN IP the payment step needs an HTTPS tunnel.
- **Same-origin, JSON-only POSTs** — a foreign `Origin` gets 403, a form post gets 415, bodies over 32 KB (3 MB for
  speech) get 413; missing fields or malformed JSON get a clean 400.
- **Strict CSP** — no inline scripts or styles, no third-party code; framing denied; `nosniff`; `no-store`.
- **Static allowlist** — only `index.html`, `app.js`, `styles.css` and the two SVGs are ever served; source code,
  `.env` and the audit log can't be fetched.

## Architecture and layout

```
User (voice / text)
  └─ web/                    DBS digibank-style UI (layout, logo and HTTP hardening adapted from teammate's Aegis)
      ├─ index.html          Shell only (no inline code, so the strict CSP holds)
      ├─ app.js              Dashboard, assistant, Senior mode, confirmation card + device signing, Transactions,
      │                      Payees, Audit trail, Security lab, Settings, voice (WAV → Tencent ASR / browser), TTS
      └─ styles.css          DBS theme + Senior mode + Larger text + mobile layout
      └─ app/server.py       HTTP API; /api/confirm is the only way money can move (needs a device signature
                             over /api/challenge); /api/key registers the device key; /api/state feeds the
                             dashboard; /api/audit/session/{id} exports the audit trail; /api/lab runs the lab
      └─ app/security.py     Host allowlist, same-origin JSON-only POSTs, size limits, CSP and security headers
          ├─ app/agent/      ── Untrusted zone: the model can only read and draft ──
          │   ├─ loop.py         Constrained ReAct loop + Harness (plan splitting, phrase pre-check, step cap,
          │   │                  output validation, fallback)
          │   ├─ tools.py        Tool gateway: read / draft / control tiers, dynamic shrinking, argument
          │   │                  validation, injection filtering on results
          │   ├─ llm.py          OpenAI-compatible client + offline rule model (same interface)
          │   ├─ fraud.py        Scam assessment: deterministic phrase rules + a separate second model call
          │   │                  (can only escalate)
          │   ├─ verifier.py     Independent read-only verifier (2nd engine): transcript only, runs in parallel
          │   ├─ prompts.py      System prompt + structured per-turn state summary
          │   ├─ presenter.py    Confirmation card (generated entirely by code from the draft) and read-back
          │   └─ textparse.py    Amount parsing (digits and words), alias matching, amounts in words
          ├─ app/kernel/     ── Deterministic kernel: out of the model's reach ──
          │   ├─ rules.py        Rule engine (limits / new payee / unusual amount / late night / velocity /
          │   │                  scam escalation)
          │   ├─ state.py        Session state machine (can only advance in order)
          │   ├─ evidence.py     Grounding: payee / amount must come from the user's own words
          │   ├─ crosscheck.py   Dual-engine audit: field-by-field diff of draft vs verifier → freeze
          │   ├─ webauthn.py     Passkey registration + assertion verification (CBOR, UV flag, counter)
          │   ├─ credentials.py  Enrolled passkeys (per customer, kept across resets) + browser keys; no downgrade
          │   ├─ protection.py   Enhanced / Standard protection: account setting, delayed lowering
          │   ├─ signing.py      What you see is what you sign: digest, signed challenge, one-time token
          │   ├─ p256.py         ECDSA P-256 verification of browser Web Crypto signatures (no dependency)
          │   ├─ executor.py     Draft → authorize → pre-execution recheck → hand-off to the execution gateway
          │   └─ audit.py        Append-only hash-chained audit log
          ├─ app/lab.py      Security lab: 22 attacks against the real kernel in an isolated sandbox
          ├─ app/bank/gateway.py     Zero-trust execution gateway: the only door to the ledger, re-verifies signatures
          ├─ app/bank/mock_bank.py   Mock bank and fixed test world (Mdm Chen, two accounts, daughter, son, two
          │                          grandsons, two bills, four investment products, a conservative risk profile)
          └─ app/voice/asr.py        Tencent Cloud SentenceRecognition (TC3 signing + hotwords)
eval/   cases.json (46 core cases, incl. investments and source accounts) + cases_hard.json (23 hard cases: paraphrase, multi-turn, scams without
        keywords, injection, out of scope) + run_eval.py (scoring, baseline compare, pass^k, fallback
        detection, harness-intervention counts, latency, security-lab attacks, one-page HTML scorecard)
scripts/verify_receipt.py   offline check of a downloaded signed receipt
docs/SECURITY.md            threats, what is implemented, what is simulated, what remains
tests/  kernel tests + "misbehaving model" Harness tests + HTTP tests (real server on a free port)
        + test_hackathon.py (one class per DBS requirement, plus protection levels)
```
