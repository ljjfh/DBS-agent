"""Global settings: all read from environment variables / .env. Falls back to offline mode when there is no key."""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:  # python-dotenv is optional
    pass

ROOT = Path(__file__).resolve().parent.parent


def _f(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


def _hosts() -> list[str]:
    hosts = [h.strip().lower() for h in _f("ALLOWED_HOSTS", "localhost,127.0.0.1,[::1]").split(",") if h.strip()]
    fly = _f("FLY_APP_NAME", "")
    for h in [_f("PUBLIC_HOST", ""), _f("RENDER_EXTERNAL_HOSTNAME", ""), _f("RAILWAY_PUBLIC_DOMAIN", ""),
              _f("SPACE_HOST", ""), f"{fly}.fly.dev" if fly else ""]:
        h = h.strip().lower().removeprefix("https://").removeprefix("http://").rstrip("/")
        if h and h not in hosts:
            hosts.append(h)
    return hosts


class Settings:
    ledger_path = Path(_f("LEDGER_PATH", str(ROOT / "data" / "ledger.sqlite3")))
    # ---- Model (OpenAI-compatible API, defaults to Tencent Hunyuan) ----
    # offline = built-in rule "model": needs no key, and is the fallback when the online model is unavailable
    llm_provider = _f("LLM_PROVIDER", "offline")          # offline | openai_compat
    llm_base_url = _f("LLM_BASE_URL", "https://api.hunyuan.cloud.tencent.com/v1")
    llm_api_key = _f("LLM_API_KEY", "")
    llm_model = _f("LLM_MODEL", "hunyuan-turbos-latest")  # use a model name your console actually offers
    llm_judge_model = _f("LLM_JUDGE_MODEL", "")           # model for the scam assessment; empty = same as the main model
    # model for the independent verifier (second engine); empty = the judge model, else the main model.
    # Using a DIFFERENT model here makes the two engines more independent.
    llm_verifier_model = _f("LLM_VERIFIER_MODEL", "")
    planner = _f("PLANNER", "model").lower()            # model: the model writes the plan, code checks it; rules: regex splitter
    llm_timeout = float(_f("LLM_TIMEOUT", "30"))
    llm_max_tokens = int(_f("LLM_MAX_TOKENS", "600"))      # cap per call: a runaway generation can't stall a turn
    # A forced tool call (tool_choice=required) slower than this switches forced calls off for this model server;
    # the harness nudge + rule-based fallback still keep the model honest
    llm_required_slow = float(_f("LLM_REQUIRED_SLOW_SECONDS", "8"))
    # off = ask Qwen-style (vLLM) servers to skip the hidden "thinking" step: ~3x faster per call.
    # Leave empty for providers that don't accept chat_template_kwargs.
    llm_thinking = _f("LLM_THINKING", "").lower()

    # ---- Agent Harness ----
    max_steps = int(_f("AGENT_MAX_STEPS", "6"))           # step cap for constrained ReAct
    max_history_turns = int(_f("AGENT_MAX_HISTORY", "8"))

    # ---- Risk parameters (example values, configurable) ----
    single_txn_hard_limit = float(_f("RULE_HARD_LIMIT", "5000"))   # above this: blocked outright
    user_high_threshold = float(_f("RULE_HIGH_THRESHOLD", "1000")) # above this: cooling-off period (enhanced protection)
    user_high_threshold_standard = float(_f("RULE_HIGH_THRESHOLD_STANDARD", "3000"))  # same, standard protection
    # Lowering protection (enhanced -> standard) is signed on the device and only takes effect after this delay
    protection_delay = int(_f("PROTECTION_LOWER_DELAY", "86400"))
    cooldown_seconds = int(_f("RULE_COOLDOWN_SECONDS", "20"))      # 20 s for the demo, e.g. 600 in production
    velocity_window_min = int(_f("RULE_VELOCITY_WINDOW_MIN", "10"))
    velocity_max = int(_f("RULE_VELOCITY_MAX", "3"))
    secondary_review_key = _f("SECONDARY_REVIEW_KEY", "")
    review_invest_threshold = int(_f("REVIEW_INVEST_THRESHOLD", "3000"))  # investments above this need the reviewer  # independent demo operator; never returned to browsers
    night_start, night_end = 23, 6
    bank_timezone = _f("BANK_TIMEZONE", "Asia/Singapore")   # "late at night" is the customer's night
    # pin the "current hour" during evaluation so running it late at night doesn't change risk levels
    fixed_hour = int(os.environ["RULE_FIXED_HOUR"]) if os.getenv("RULE_FIXED_HOUR") else None

    # ---- Signing ----
    signing_secret = _f("SIGNING_SECRET", "dev-only-change-me").encode()
    auth_token_ttl = int(_f("AUTH_TOKEN_TTL", "120"))
    # device_key = the browser signs every payment with its own non-extractable P-256 key (default)
    # mock       = also accept the old "demo-fingerprint" string (only for quick scripts; never for the demo)
    auth_mode = _f("AUTH_MODE", "device_key")
    challenge_ttl = int(_f("CHALLENGE_TTL", "120"))
    # Hosts the web server answers to (DNS-rebinding protection). Add your LAN name/IP here to demo from another device.
    # On a hosting platform its public hostname is added automatically (Render, Railway, Fly.io, Hugging Face Spaces),
    # or set PUBLIC_HOST yourself (e.g. a Tencent Cloud server's domain).
    allowed_hosts = _hosts()
    # A shared online demo: every browser is its own demo customer, and nobody can reset everyone's world
    public_demo = _f("PUBLIC_DEMO", "0").lower() in ("1", "true", "yes")
    # The demo's default signer: a simulated fingerprint step unlocks a non-extractable browser key that signs the
    # exact card (the DBS brief allows mock biometrics). Real passkeys (Face ID / Touch ID / Windows Hello) are an
    # opt-in in Settings. Set ALLOW_BROWSER_KEY=0 to require a real passkey for every payment.
    allow_browser_key = _f("ALLOW_BROWSER_KEY", "1").lower() in ("1", "true", "yes")
    draft_ttl = int(_f("DRAFT_TTL", "600"))

    # ---- Tencent Cloud ASR (SentenceRecognition) ----
    tc_secret_id = _f("TENCENTCLOUD_SECRET_ID", "")
    tc_secret_key = _f("TENCENTCLOUD_SECRET_KEY", "")
    asr_endpoint = _f("ASR_ENDPOINT", "asr.intl.tencentcloudapi.com")
    asr_region = _f("ASR_REGION", "ap-singapore")
    asr_engine = _f("ASR_ENGINE", "16k_en")         # also: 16k_zh / 16k_zh-PY / 16k_ms

    # ---- Storage ----
    audit_path = Path(_f("AUDIT_PATH", str(ROOT / "data" / "audit.jsonl")))
    # Enrolled passkeys (public keys only). Kept across demo resets, like a phone enrolled with the bank.
    passkey_path = Path(_f("PASSKEY_PATH", str(ROOT / "data" / "passkeys.json")))

    @property
    def llm_enabled(self) -> bool:
        return self.llm_provider == "openai_compat" and bool(self.llm_api_key)

    @property
    def asr_enabled(self) -> bool:
        return bool(self.tc_secret_id and self.tc_secret_key)


settings = Settings()
