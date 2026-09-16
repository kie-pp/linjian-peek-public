const PATTERNS = [
  /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/i,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  /\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[A-Z0-9]{16})\b/,
  /\bAuthorization\s*:\s*Bearer\s+\S+/i,
  /\b(?:password|passwd|pwd|cookie|session(?:_id)?|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*[^\s,;]{8,}/i,
  /\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|COOKIE|API_KEY|PRIVATE_KEY)\s*=\s*[^\s]{8,}/,
  /(?:密码|口令|令牌|密钥|Cookie)\s*(?:是|[:：=])\s*[^\s,，;；]{8,}/i,
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis):\/\/[^\s:/]+:[^\s/@]+@/i,
  /\bhttps?:\/\/[^\s/:]+:[^\s/@]+@/i,
  /\b[A-Za-z]:\\(?:Users|Documents and Settings|ProgramData|Windows|[^\\\s]+)\\/i,
  /(?:^|\s)\/(?:home|Users|root|var\/(?:lib|run)|etc)\/\S+/,
];

const TRANSCRIPT_LINE = /^\s*(?:\[?\d{1,2}:\d{2}(?::\d{2})?\]?\s*)?(?:用户|助手|user|assistant|human|ai|chatgpt)\s*[:：]/gim;

export function assertSafeMemoryContent(...values) {
  for (const raw of values) {
    const value = String(raw || "");
    if (!value) continue;
    if (PATTERNS.some((pattern) => pattern.test(value))) throw rejected();
    const transcriptLines = value.match(TRANSCRIPT_LINE) || [];
    if (value.length >= 300 && transcriptLines.length >= 4) throw rejected();
  }
}

function rejected() {
  const error = new Error("MEMORY_SENSITIVE_CONTENT_REJECTED");
  error.code = "MEMORY_SENSITIVE_CONTENT_REJECTED";
  return error;
}
