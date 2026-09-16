"""Content safety checks for shared-memory writer inputs."""
from __future__ import annotations

import re
from typing import Iterable


class MemorySafetyError(ValueError):
    """Raised with a stable code; rejected content is never echoed."""


_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[A-Z0-9]{16})\b"),
    re.compile(r"\bAuthorization\s*:\s*Bearer\s+\S+", re.I),
    re.compile(r"\b(?:password|passwd|pwd|cookie|session(?:_id)?|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*[^\s,;]{8,}", re.I),
    re.compile(r"\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|COOKIE|API_KEY|PRIVATE_KEY)\s*=\s*[^\s]{8,}"),
    re.compile(r"(?:密码|口令|令牌|密钥|Cookie)\s*(?:是|[:：=])\s*[^\s,，;；]{8,}", re.I),
    re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://[^\s:/]+:[^\s/@]+@", re.I),
    re.compile(r"\bhttps?://[^\s/:]+:[^\s/@]+@", re.I),
    re.compile(r"\b[A-Za-z]:\\(?:Users|Documents and Settings|ProgramData|Windows|[^\\\s]+)\\", re.I),
    re.compile(r"(?<![\w:])/(?:home|Users|root|var/(?:lib|run)|etc)/[^\s]+"),
)

_TRANSCRIPT_LINE = re.compile(
    r"^\s*(?:\[?\d{1,2}:\d{2}(?::\d{2})?\]?\s*)?(?:用户|助手|user|assistant|human|ai|chatgpt)\s*[:：]",
    re.I | re.M,
)


def validate_memory_content(values: Iterable[str]) -> None:
    """Reject likely credentials, private paths, and raw chat transcripts."""
    for raw in values:
        value = str(raw or "")
        if not value:
            continue
        if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
            raise MemorySafetyError("memory_sensitive_content_rejected")
        if len(value) >= 300 and len(_TRANSCRIPT_LINE.findall(value)) >= 4:
            raise MemorySafetyError("memory_sensitive_content_rejected")
