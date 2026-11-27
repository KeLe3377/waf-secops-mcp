"""
日志安全清洗与敏感凭证脱敏模块（借鉴 zorak1103/dlia 安全边界设计）。
1. 防止攻击者在 URI / User-Agent 中夹带 Prompt Injection 欺骗大模型；
2. 对 Cookie / Bearer Token / API Key 等敏感凭证自动打码后再返回上下文。
"""

from __future__ import annotations

import re

INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"(reveal|print|output|show)\s+(your\s+)?(system\s+prompt|instructions)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a|an|in)\s+", re.IGNORECASE),
    re.compile(r"<\|?(system|im_start|im_end|endoftext)\|?>", re.IGNORECASE),
)

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"), "[REDACTED_JWT]"),
    (re.compile(r"((?:api[_-]?key|token|secret|password|passwd)\s*[=:]\s*)([^\s&;\"']+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Cookie:\s*)([^\r\n]+)", re.IGNORECASE), r"\1[REDACTED_COOKIE]"),
)


def detect_prompt_injection(text: str) -> bool:
    """判断原始日志字段是否包含疑似 Prompt Injection 载荷。"""
    return any(p.search(text) for p in INJECTION_PATTERNS)


def sanitize_log_text(text: str) -> str:
    """清洗疑似提示词注入载荷并对敏感凭证脱敏。"""
    cleaned = str(text or "")
    for pattern in INJECTION_PATTERNS:
        cleaned = pattern.sub("[REDACTED_PROMPT_INJECTION]", cleaned)
    for pattern, repl in SECRET_PATTERNS:
        cleaned = pattern.sub(repl, cleaned)
    return cleaned


def wrap_untrusted_log(text: str) -> str:
    """先清洗脱敏，再使用不可信数据边界包裹，防止模型将日志正文误当作指令执行。"""
    return f"<untrusted_log_data>\n{sanitize_log_text(text)}\n</untrusted_log_data>"
