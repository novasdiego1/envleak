"""Detection rules for envleak.

Each rule finds one kind of credential. Rules are ordered: the agent/LLM
surface comes first because that's the surface nobody else scans.
"""

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern
    severity: str  # critical | high | medium
    group: str     # "agent" | "cloud" | "classic"


def _c(p: str) -> re.Pattern:
    return re.compile(p)


# --- The agent / LLM surface (the differentiator) -------------------------
AGENT_RULES = [
    Rule("openai-key", "OpenAI API key",
         _c(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "critical", "agent"),
    Rule("anthropic-key", "Anthropic API key",
         _c(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "critical", "agent"),
    Rule("google-ai-key", "Google AI / Gemini key",
         _c(r"\bAIza[0-9A-Za-z_-]{35}\b"), "critical", "agent"),
    Rule("groq-key", "Groq API key",
         _c(r"\bgsk_[A-Za-z0-9]{40,}\b"), "critical", "agent"),
    Rule("hf-token", "Hugging Face token",
         _c(r"\bhf_[A-Za-z0-9]{30,}\b"), "high", "agent"),
    Rule("replicate-token", "Replicate token",
         _c(r"\br8_[A-Za-z0-9]{30,}\b"), "high", "agent"),
    Rule("langsmith-key", "LangSmith API key",
         _c(r"\blsv2_(?:pt|sk)_[A-Za-z0-9]{20,}"), "high", "agent"),
    Rule("perplexity-key", "Perplexity API key",
         _c(r"\bpplx-[A-Za-z0-9]{32,}\b"), "high", "agent"),
    Rule("mistral-key", "Mistral API key",
         _c(r"(?i)\bmistral[_-]?api[_-]?key\b\s*[:=]\s*['\"]?([A-Za-z0-9]{24,})"),
         "high", "agent"),
    Rule("generic-llm-key", "LLM provider key in config",
         _c(r"(?i)\b(?:llm|openai|anthropic|together|fireworks|deepseek|xai)"
            r"[_-]?(?:api[_-]?)?key\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})"),
         "high", "agent"),
]

# --- Cloud / infra --------------------------------------------------------
CLOUD_RULES = [
    Rule("aws-access-key", "AWS access key ID",
         _c(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "critical", "cloud"),
    Rule("aws-secret", "AWS secret access key",
         _c(r"(?i)aws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
         "critical", "cloud"),
    Rule("gcp-sa", "GCP service-account private key",
         _c(r'"type"\s*:\s*"service_account"'), "critical", "cloud"),
    Rule("private-key", "Private key block",
         _c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
         "critical", "cloud"),
    Rule("docker-auth", "Docker registry auth",
         _c(r'"auths"\s*:\s*\{[^}]*"auth"\s*:\s*"[A-Za-z0-9+/=]{16,}"'),
         "high", "cloud"),
]

# --- Classic third-party --------------------------------------------------
CLASSIC_RULES = [
    Rule("github-token", "GitHub token",
         _c(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical", "classic"),
    Rule("gitlab-token", "GitLab token",
         _c(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "critical", "classic"),
    Rule("stripe-key", "Stripe secret key",
         _c(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"), "critical", "classic"),
    Rule("slack-token", "Slack token",
         _c(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "high", "classic"),
    Rule("telegram-bot", "Telegram bot token",
         _c(r"\b\d{8,10}:AA[A-Za-z0-9_-]{32,}\b"), "high", "classic"),
    Rule("sendgrid-key", "SendGrid API key",
         _c(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"), "high", "classic"),
    Rule("twilio-sid", "Twilio account SID",
         _c(r"\bAC[0-9a-fA-F]{32}\b"), "medium", "classic"),
    Rule("jwt", "JSON Web Token",
         _c(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
         "medium", "classic"),
    Rule("db-url", "Database URL with password",
         _c(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^\s:'\"]+:[^\s@'\"]{3,}@[^\s/'\"]+"), "critical", "classic"),
    Rule("crypto-priv", "Crypto private key / seed",
         _c(r"(?i)\b(?:private[_-]?key|mnemonic|seed[_-]?phrase)\b\s*[:=]\s*"
            r"['\"]?(0x[a-fA-F0-9]{64}|(?:[a-z]+\s+){11,23}[a-z]+)"),
         "critical", "classic"),
]

ALL_RULES = AGENT_RULES + CLOUD_RULES + CLASSIC_RULES

# Generic high-entropy assignment (catches what the rules above miss)
ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL)[A-Z0-9_]*)"
    r"\s*[:=]\s*['\"]?([^\s'\"#,;]{16,})"
)

PLACEHOLDERS = {
    "changeme", "your_key_here", "xxx", "todo", "placeholder", "example",
    "null", "none", "true", "false", "undefined", "secret", "password",
    "username", "user", "admin", "root", "test", "localhost",
}

# Credential pairs that only ever appear in docs and templates.
DOC_CREDENTIALS = (
    "user:password@", "username:password@", "admin:admin@", "root:root@",
    "user:pass@", "foo:bar@", "test:test@", ":password@", ":changeme@",
)

LOCAL_HOSTS = ("@localhost", "@127.0.0.1", "@0.0.0.0", "@db:", "@host.docker")

# A value that is really an expression, not a literal secret.
CODE_CHARS = set("()[]{}<>+*/\\ ")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def looks_like_code(value: str) -> bool:
    """True when the "secret" is actually a code expression."""
    v = value.strip().strip("'\"")
    if any(ch in CODE_CHARS for ch in v):
        return True
    if v.endswith((".upper", ".lower", ".strip", ".format", ".get")):
        return True
    if v.count(".") >= 1 and "_" not in v and not any(c.isdigit() for c in v):
        return True  # attribute access like key.upper
    return False


def looks_like_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"").lower()
    if any(d in v for d in DOC_CREDENTIALS):
        return True
    if any(h in v for h in LOCAL_HOSTS):
        return True
    if len(v) < 16:
        return True
    if v in PLACEHOLDERS:
        return True
    if v.startswith(("${", "{{", "<", "$(")):  # templated
        return True
    if any(p in v for p in ("your-", "your_", "example", "placeholder",
                            "changeme", "dummy", "fake", "sample", "xxxx")):
        return True
    if len(set(v)) <= 3:  # aaaaaaaa, 00000000
        return True
    return False
