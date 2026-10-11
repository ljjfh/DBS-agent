"""全局配置：全部从环境变量 / .env 读取，没有 key 时自动走离线模式。"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:  # python-dotenv 不是必需的
    pass

ROOT = Path(__file__).resolve().parent.parent


def _f(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


class Settings:
    # ---- 模型（OpenAI 兼容接口，默认腾讯混元）----
    # offline = 内置规则“模型”，不需要 key，也是线上模型不可用时的降级方案
    llm_provider = _f("LLM_PROVIDER", "offline")          # offline | openai_compat
    llm_base_url = _f("LLM_BASE_URL", "https://api.hunyuan.cloud.tencent.com/v1")
    llm_api_key = _f("LLM_API_KEY", "")
    llm_model = _f("LLM_MODEL", "hunyuan-turbos-latest")  # 以控制台实际可用的模型名为准
    llm_judge_model = _f("LLM_JUDGE_MODEL", "")           # 诈骗研判用的模型，留空则与主模型相同
    llm_timeout = float(_f("LLM_TIMEOUT", "30"))

    # ---- Agent Harness ----
    max_steps = int(_f("AGENT_MAX_STEPS", "6"))           # 受限 ReAct 的步数上限
    max_history_turns = int(_f("AGENT_MAX_HISTORY", "8"))

    # ---- 风控参数（示例值，可配置）----
    single_txn_hard_limit = float(_f("RULE_HARD_LIMIT", "5000"))   # 超过直接拦截
    user_high_threshold = float(_f("RULE_HIGH_THRESHOLD", "1000")) # 超过触发冷静期
    cooldown_seconds = int(_f("RULE_COOLDOWN_SECONDS", "20"))      # Demo 用 20 秒，生产可设 600
    velocity_window_min = int(_f("RULE_VELOCITY_WINDOW_MIN", "10"))
    velocity_max = int(_f("RULE_VELOCITY_MAX", "3"))
    night_start, night_end = 23, 6
    # 评测时固定“当前小时”，避免深夜跑评测导致风险等级变化
    fixed_hour = int(os.environ["RULE_FIXED_HOUR"]) if os.getenv("RULE_FIXED_HOUR") else None

    # ---- 签名 ----
    signing_secret = _f("SIGNING_SECRET", "dev-only-change-me").encode()
    auth_token_ttl = int(_f("AUTH_TOKEN_TTL", "120"))
    draft_ttl = int(_f("DRAFT_TTL", "600"))

    # ---- 腾讯云 ASR（一句话识别）----
    tc_secret_id = _f("TENCENTCLOUD_SECRET_ID", "")
    tc_secret_key = _f("TENCENTCLOUD_SECRET_KEY", "")
    asr_endpoint = _f("ASR_ENDPOINT", "asr.intl.tencentcloudapi.com")
    asr_region = _f("ASR_REGION", "ap-singapore")
    asr_engine = _f("ASR_ENGINE", "16k_zh_large")         # 也可试 16k_zh-PY / 16k_en / 16k_ms

    # ---- 存储 ----
    audit_path = Path(_f("AUDIT_PATH", str(ROOT / "data" / "audit.jsonl")))

    @property
    def llm_enabled(self) -> bool:
        return self.llm_provider == "openai_compat" and bool(self.llm_api_key)

    @property
    def asr_enabled(self) -> bool:
        return bool(self.tc_secret_id and self.tc_secret_key)


settings = Settings()
