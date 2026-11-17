#!/usr/bin/env python3
"""
secret_guard: one detection engine, enforced at every point a secret can escape.

Enforcement points (subcommands):
  hook-prompt   AI assistant prompt hook. Blocks a secret before the prompt reaches the model.
  hook-tool     AI assistant tool hook. Blocks an agent action that carries a secret, reads a
                credential file, dumps the environment, skips git hooks, or edits the guard's
                own configuration.
  scan          Pre-commit and CI. Blocks a secret before it enters (or spreads through) git.
  rules         Lists the detection rules.

Design rules:
  * The raw secret is never printed or logged. Findings carry a rule id, a location, a masked
    preview and a keyed fingerprint (HMAC-SHA256) only.
  * Hooks fail closed. If the guard itself errors, the prompt or tool call is blocked.
  * Exceptions are for humans only. `guard:allow` markers and the fingerprint allowlist are
    honoured for reviewed files (pre-commit / CI) but never for prompts or agent actions, so
    neither a developer in a hurry nor a prompt-injected agent can wave a secret through.
  * Every block message says exactly how to fix it.

Standard library only. Python 3.9+.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import math
import os
import re
import shlex
import sys
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable, Iterator

VERSION = "2.0.0"

# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    pattern: re.Pattern
    severity: str  # critical | high | medium
    remediation: str
    generic: bool = False  # keyword-anchored: the value must also look like a real secret
    prefix: int = 0        # length of a fixed vendor prefix that is safe to show (ghp_, AKIA)


def _r(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


# Environment-variable names that usually hold a credential (DB_PASSWORD, GITHUB_TOKEN, ...).
SECRET_VAR = r"[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[A-Z0-9_]*"

# Order matters: specific rules first, generic rules last, so a value claimed by a specific
# rule is never reported a second time by a generic one on the same line.
RULES: list[Rule] = [
    Rule("aws-access-key-id", "AWS access key ID",
         _r(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), "critical",
         "Contain it now: python3 remediation/contain_aws_key.py <key id> (AKIA: deactivate, "
         "ASIA: revoke role sessions). Then move the workload to an IAM role or OIDC.", prefix=4),
    Rule("aws-secret-access-key", "AWS secret access key",
         _r(r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?[=:]\s*[\"']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+=])"),
         "critical",
         "Rotate the key pair and load credentials from an IAM role or Secrets Manager."),
    Rule("github-token", "GitHub token",
         _r(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), "critical",
         "Revoke the token in GitHub settings and use a GitHub App or OIDC instead.", prefix=4),
    Rule("github-fine-grained-pat", "GitHub fine-grained PAT",
         _r(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"), "critical",
         "Revoke the PAT and replace it with a scoped GitHub App token.", prefix=11),
    Rule("gitlab-token", "GitLab personal access token",
         _r(r"\b(glpat-[A-Za-z0-9_-]{20,})"), "critical",
         "Revoke the token in GitLab and use a project or group access token with minimal scope.", prefix=6),
    Rule("slack-token", "Slack token",
         _r(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), "high",
         "Revoke in the Slack admin console and store the replacement in a secrets manager.", prefix=5),
    Rule("slack-webhook", "Slack incoming webhook URL",
         _r(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"), "high",
         "Regenerate the webhook in Slack and load it from a secrets manager."),
    Rule("google-api-key", "Google API key",
         _r(r"\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])"), "high",
         "Restrict or regenerate the key in Google Cloud console.", prefix=4),
    Rule("stripe-live-key", "Stripe live secret key",
         _r(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), "critical",
         "Roll the key in the Stripe dashboard.", prefix=8),
    Rule("ai-provider-key", "AI provider API key (Anthropic / OpenAI)",
         _r(r"\b(sk-ant-[a-z]{2,8}\d{2}-[A-Za-z0-9_-]{32,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,})(?![A-Za-z0-9_-])"),
         "critical",
         "Revoke the key in the provider console. Route model access through the org gateway "
         "instead of personal keys.", prefix=7),
    Rule("azure-storage-key", "Azure storage account key",
         _r(r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)"), "critical",
         "Rotate the storage key and switch the workload to a managed identity."),
    # Mirrors the custom rule in .gitleaks.toml (a test keeps the two in sync).
    Rule("internal-service-token", "Internal platform service token",
         _r(r"\b(corp_svc_[A-Za-z0-9]{32})\b"), "high",
         "Revoke the token in the platform console and request a workload identity instead.", prefix=9),
    Rule("jwt", "JSON Web Token",
         _r(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), "medium",
         "Do not paste live session tokens. Invalidate the session if it is real.", prefix=3),
    Rule("credential-in-url", "Credentials embedded in a connection string",
         _r(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@\"']{1,64}:([^\s:/@\"']{6,128})@[^\s\"']+"), "high",
         "Remove the password from the URL and inject it at runtime from a secrets manager."),
    Rule("generic-secret-assignment", "Hardcoded secret assignment",
         _r(r"(?i)(?<![A-Za-z0-9])(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token"
            r"|token|client[_-]?secret|private[_-]?key)[\"']?\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']"),
         "medium",
         "Read the value from an environment variable or secrets manager instead of hardcoding it.",
         generic=True),
    Rule("env-secret-assignment", "Secret in an env-style assignment",
         _r(r"(?:^|[\s;&|(])(?:export\s+)?" + SECRET_VAR + r"=([^\s\"'#$`]{8,})"), "high",
         "Keep real values out of .env files in the repo and out of commands. Load them from a "
         "secrets manager, or keep .env git-ignored and commit only .env.example.",
         generic=True),
]

PRIVATE_KEY_RULE = Rule(
    "private-key", "Private key",
    _r(r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----"), "critical",
    "Treat the key as compromised: reissue it, then remove it from the file and from git history.")

ALL_RULES = RULES + [PRIVATE_KEY_RULE]

ALLOW_MARKER = "guard:allow"
PLACEHOLDER_HINTS = ("example", "changeme", "change_me", "placeholder", "dummy", "xxxx", "****",
                     "your_", "your-", "<", ">", "${", "{{", "redacted", "sample")
PLACEHOLDER_EXACT = {"password", "passwd", "secret", "pass", "test", "testing", "admin", "root",
                     "user", "token", "none", "null", "true", "false"}
REFERENCE_PREFIXES = ("/", "./", "../", "~", "$", "%", "arn:", "http://", "https://", "file:",
                      "vault:", "ssm:", "secretsmanager:", "projects/")
REFERENCE_SUFFIXES = (".json", ".pem", ".key", ".txt", ".yaml", ".yml", ".env", ".crt", ".p12")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def char_classes(s: str) -> int:
    return sum((any(c.islower() for c in s), any(c.isupper() for c in s),
                any(c.isdigit() for c in s), any(not c.isalnum() for c in s)))


def is_placeholder(value: str) -> bool:
    low = value.lower()
    return low in PLACEHOLDER_EXACT or any(h in low for h in PLACEHOLDER_HINTS) or len(set(value)) <= 2


def looks_like_secret(value: str) -> bool:
    """Extra checks for keyword-anchored rules, which see far more non-secrets than vendor rules."""
    if value.startswith(REFERENCE_PREFIXES) or value.lower().endswith(REFERENCE_SUFFIXES):
        return False  # a path, URL or secret-manager reference, not a value
    if re.search(r"[{}]|%\(?\w*\)?s", value) or re.fullmatch(r"[A-Za-z_][\w.]*\(.*\)", value):
        return False  # a template or code ({name}, %s, func(...)), not a literal
    if re.fullmatch(r"[a-z]+(?:[-_.][a-z]+)*", value):
        return False  # a secret's *name*, e.g. "orders-db-password"
    if re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", value):
        return False  # an env var name, e.g. "DB_PASSWORD"
    classes = char_classes(value)
    # Two or more character classes, and either three classes or reasonable entropy. This catches
    # short human passwords ("Summer2024!!") that a pure entropy threshold can never reach.
    return classes >= 2 and (classes >= 3 or shannon_entropy(value) >= 3.0)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    source: str          # file path, "prompt" or "tool:<name>:<field>"
    line: int            # 0 for policy findings that are not tied to a line
    preview: str         # masked, never the full secret
    fingerprint: str     # keyed hash prefix: dedupe and track without storing the value
    remediation: str


def mask(value: str, prefix: int = 0) -> str:
    """Show only a fixed vendor prefix (ghp_, AKIA), never characters of the secret itself.
    The length is not revealed either."""
    if prefix and len(value) >= prefix + 8:
        return value[:prefix] + "*" * 8
    return "*" * 8


FP_KEY_ENV = "SECRET_GUARD_FP_KEY"
_DEFAULT_FP_KEY = b"secret-guard/unset-org-key"


def fingerprint(value: str) -> str:
    """HMAC-SHA256, so a leaked audit log or SARIF file cannot be used to brute-force short
    passwords. Set SECRET_GUARD_FP_KEY to the same org-managed value on laptops and in CI so
    fingerprints (and the allowlist) match everywhere."""
    key = os.environ.get(FP_KEY_ENV, "").encode() or _DEFAULT_FP_KEY
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:16]


def scan_text(text: str, source: str, allowlist: set[str] | None = None,
              honor_exceptions: bool = True) -> list[Finding]:
    """Scan text for secrets. `honor_exceptions=False` ignores guard:allow and the allowlist."""
    allowlist = (allowlist or set()) if honor_exceptions else set()
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    lines = text.splitlines()

    def add(rule: Rule, value: str, lineno: int) -> None:
        fp = fingerprint(value)
        if fp in allowlist or (fp, lineno) in seen:
            return
        seen.add((fp, lineno))
        findings.append(Finding(rule.id, rule.description, rule.severity, source, lineno,
                                mask(value, rule.prefix), fp, rule.remediation))

    for lineno, line in enumerate(lines, start=1):
        if honor_exceptions and ALLOW_MARKER in line:
            continue
        for rule in RULES:
            for m in rule.pattern.finditer(line):
                value = m.group(1)
                if is_placeholder(value):
                    continue
                if rule.generic and not looks_like_secret(value):
                    continue
                add(rule, value, lineno)

    # Private keys span lines. Fingerprint the key material, not the header, so two different
    # keys never share a fingerprint (allowlisting one must not allowlist them all).
    for m in PRIVATE_KEY_RULE.pattern.finditer(text):
        lineno = text.count("\n", 0, m.start()) + 1
        if honor_exceptions and ALLOW_MARKER in lines[lineno - 1]:
            continue
        end = text.find(f"-----END {m.group(1)}-----", m.end())
        body = text[m.end():end if end != -1 else m.end() + 4096]
        material = re.sub(r"[^A-Za-z0-9+/=]", "", body)
        if len(material) < 32:
            continue  # a header mentioned in docs, not a key
        add(PRIVATE_KEY_RULE, m.group(1) + material, lineno)

    findings.sort(key=lambda f: f.line)
    return findings


def load_allowlist(path: Path) -> set[str]:
    """One fingerprint per line, each with a reason: `<fingerprint>  # owner, reason, ticket`."""
    entries: set[str] = set()
    if not path.is_file():
        return entries
    for n, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fp, _, reason = line.partition("#")
        if not reason.strip():
            print(f"secret_guard: ignoring {path}:{n}, every allowlist entry needs '# owner, reason'",
                  file=sys.stderr)
            continue
        entries.add(fp.strip())
    return entries


# --------------------------------------------------------------------------- #
# Agent policy: what a coding agent may not do even without a secret in the call
# --------------------------------------------------------------------------- #

SENSITIVE_FILE_GLOBS = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
                        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".git-credentials",
                        ".pgpass", ".npmrc", ".pypirc", "*.tfstate", "*.tfstate.*", "credentials.json",
                        "service-account*.json", "secrets.yaml", "secrets.yml", "*.ovpn", "*.kdbx",
                        "environ")
SENSITIVE_PATH_SUFFIXES = (".aws/credentials", ".kube/config", ".docker/config.json",
                           ".config/gh/hosts.yml")
SAFE_SUFFIXES = (".example", ".sample", ".template", ".tpl", ".dist", ".pub")

# Files that control the guard itself. An agent must not be able to switch it off.
PROTECTED_PATHS = (".claude/settings.json", ".claude/settings.local.json", ".secret-guard-allowlist",
                   ".gitleaks.toml", ".pre-commit-config.yaml")

WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
PATH_KEYS = ("file_path", "path", "notebook_path", "filename", "source", "destination", "uri")
SKIP_KEYS = {"old_string"}  # text already in the file; blocking its *removal* helps nobody

READ_VERBS = {"cat", "bat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "ag",
              "awk", "gawk", "sed", "cut", "sort", "uniq", "nl", "tac", "strings", "base64", "xxd",
              "od", "hexdump", "cp", "scp", "rsync", "curl", "wget", "nc", "ncat", "socat", "openssl",
              "gpg", "jq", "yq", "diff", "tee", "zip", "tar", "source", ".", "python", "python3",
              "node", "ruby", "perl", "vim", "vi", "nano", "dd", "type", "get-content"}
SECRET_VAR_REF = _r(r"\$\{?" + SECRET_VAR + r"\}?")
HOOK_BYPASS = [
    _r(r"\bgit\b[^;&|\n]*\bcommit\b[^;&|\n]*(?:--no-verify|\s-[a-zA-Z]*n[a-zA-Z]*\b)"),
    _r(r"\bgit\b[^;&|\n]*\bpush\b[^;&|\n]*--no-verify"),
    _r(r"\bSKIP=\S+[^;&|\n]*\bgit\b[^;&|\n]*\bcommit\b"),
    _r(r"\bgit\b[^;&|\n]*-c\s+core\.hooksPath="),
    _r(r"\bgit\s+config\b[^;&|\n]*core\.hooksPath"),
    _r(r"\bpre-commit\s+uninstall\b"),
]
WRITE_HINT = _r(r"(?:^|[\s;&|(])(?:rm|mv|cp|tee|truncate|ln|dd|chmod|chown|install|unlink|shred)\b"
                r"|\bsed\b[^;&|]*\s(?:-[a-zA-Z]*i|--in-place)|\bperl\b[^;&|]*\s-[a-zA-Z]*i"
                r"|\bgit\s+(?:rm|mv|checkout|restore|reset|update-index)\b|>|\bopen\(|write_text|\.write\(")


def _norm(p: str) -> str:
    return p.strip().strip("'\"").replace("\\", "/")


def is_sensitive_path(p: str) -> bool:
    p = _norm(p)
    if not p:
        return False
    name = p.rstrip("/").rsplit("/", 1)[-1].lower()
    if name.endswith(SAFE_SUFFIXES):
        return False
    if any(fnmatchcase(name, g) for g in SENSITIVE_FILE_GLOBS):
        return True
    return any(p == s or p.endswith("/" + s) for s in SENSITIVE_PATH_SUFFIXES)


def is_protected_path(p: str) -> bool:
    p = _norm(p)
    return any(p == s or p.endswith("/" + s) for s in PROTECTED_PATHS)


def _policy(rule_id: str, description: str, source: str, detail: str, remediation: str) -> Finding:
    return Finding(rule_id, description, "high", source, 0, "", fingerprint(f"{rule_id}:{detail}"),
                   remediation)


def _bash_words(cmd: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_./~*+-]+", cmd)


def _bash_segments(cmd: str) -> Iterator[list[str]]:
    for seg in re.split(r"[;&|\n]+|\$\(|`", cmd):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        if toks:
            yield toks


def check_bash(cmd: str, source: str) -> list[Finding]:
    out: list[Finding] = []
    words = _bash_words(cmd)
    sensitive = [w for w in words if is_sensitive_path(w)]
    verbs = {w.rsplit("/", 1)[-1].lower() for w in words}
    if sensitive and (verbs & READ_VERBS or "<" in cmd):
        out.append(_policy("sensitive-file-access", "Agent command reads a credential file", source,
                           sensitive[0],
                           f"The agent tried to read {sensitive[0]}. Its contents would go straight into "
                           "the model context. Ask the developer to run it, or use a secrets manager."))
    for toks in _bash_segments(cmd):
        head, args = toks[0], toks[1:]
        dump = ((head in ("env", "printenv", "export", "set") and not args)
                or (head in ("export", "declare") and args in (["-p"], ["-px"], ["-xp"]))
                or (head == "printenv" and any(re.fullmatch(SECRET_VAR, a) for a in args))
                or (head in ("echo", "printf") and SECRET_VAR_REF.search(" ".join(args))))
        if dump:
            out.append(_policy("env-dump", "Agent command prints secret environment variables", source,
                               head, "Printing the environment puts every token it holds into the model "
                               "context. Reference the variable by name instead of printing it."))
            break
    if any(p.search(cmd) for p in HOOK_BYPASS):
        out.append(_policy("hook-bypass", "Agent command skips git hooks", source, "hook-bypass",
                           "Agents may not use --no-verify, SKIP= or core.hooksPath. Fix what the hook "
                           "reported instead. A human can bypass, and CI will still scan the change."))
    if any(p in cmd for p in PROTECTED_PATHS) and WRITE_HINT.search(cmd):
        out.append(_policy("guard-tamper", "Agent command modifies secret_guard configuration", source,
                           "bash", "Guard configuration can only be changed by a human in a reviewed PR."))
    return out


def check_tool_policy(tool: str, tool_input: Any) -> list[Finding]:
    source = f"tool:{tool}"
    if not isinstance(tool_input, dict):
        return []
    if tool == "Bash":
        return check_bash(str(tool_input.get("command", "")), source)
    paths = [str(tool_input[k]) for k in PATH_KEYS if isinstance(tool_input.get(k), str)]
    writes = tool in WRITE_TOOLS or (tool.startswith("mcp__") and
                                     re.search(r"write|edit|create|move|delete|update", tool, re.I))
    out: list[Finding] = []
    for p in paths:
        if writes and is_protected_path(p):
            out.append(_policy("guard-tamper", "Agent edit to secret_guard configuration", source, p,
                               f"{p} controls the guard. Only a human can change it, in a reviewed PR."))
        elif not writes and is_sensitive_path(p):
            out.append(_policy("sensitive-file-access", "Agent read of a credential file", source, p,
                               f"The agent tried to read {p}. Its contents would go straight into the "
                               "model context. Commit a .env.example with placeholders for the agent to "
                               "read instead."))
    return out


def iter_strings(obj: Any, path: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if k not in SKIP_KEYS:
                yield from iter_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from iter_strings(v, f"{path}[{i}]")


# --------------------------------------------------------------------------- #
# Audit log (metrics come from here; raw secrets and previews never do)
# --------------------------------------------------------------------------- #


def audit_path() -> Path:
    return Path(os.environ.get("GUARD_AUDIT_LOG") or Path.home() / ".secret_guard" / "audit.jsonl")


def audit(event: str, findings: Iterable[Finding], blocked: bool) -> None:
    findings = list(findings)
    if not findings:
        return
    repo = os.environ.get("GITHUB_REPOSITORY") or Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).name
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        path = audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps({
                    "ts": now, "event": event, "blocked": blocked, "repo": repo,
                    "rule_id": f.rule_id, "severity": f.severity, "source": f.source, "line": f.line,
                    "fingerprint": f.fingerprint, "guard_version": VERSION}) + "\n")
    except OSError as exc:  # never let logging break enforcement
        print(f"secret_guard: could not write audit log ({type(exc).__name__})", file=sys.stderr)


HEADERS = {
    "prompt": "secret_guard blocked this prompt before it reached the AI model",
    "tool": "secret_guard blocked this {tool} call from the coding agent before it ran",
    "precommit": "secret_guard blocked this commit",
    "ci": "secret_guard found secrets in this change",
}
FOOTERS = {
    "prompt": "Nothing was sent. Describe the credential instead of pasting it (for example \"the "
              "token in $GITHUB_TOKEN\"). If you pasted it anywhere else, rotate it. Inline markers "
              "and the allowlist do not apply to prompts.",
    "tool": "The action did not run. The agent cannot grant itself an exception: `guard:allow` and "
            "the allowlist are ignored for agent actions. If this is a false positive, a human makes "
            "the change and it goes through review.",
    "files": "False positive? Add `guard:allow` to that line, or add the fingerprint to "
             ".secret-guard-allowlist as `<fp>  # owner, reason`. Both show up in code review. "
             "A real secret must be rotated, not just deleted: it is already in your history.",
}


def developer_message(findings: list[Finding], context: str, tool: str = "") -> str:
    lines = [HEADERS[context].format(tool=tool) + f": {len(findings)} issue(s)."]
    for f in findings:
        where = f"{f.source}:{f.line}" if f.line else f.source
        shown = f" ({f.preview})" if f.preview else ""
        lines.append(f"  [{f.severity.upper()}] {f.description} at {where}{shown} fp={f.fingerprint}")
        lines.append(f"      fix: {f.remediation}")
    lines.append(FOOTERS["files" if context in ("precommit", "ci") else context])
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Enforcement points
# --------------------------------------------------------------------------- #


def hook_prompt(payload: dict) -> int:
    """AI assistant prompt hook (Claude Code UserPromptSubmit). Exit 2 blocks the prompt."""
    findings = scan_text(str(payload.get("prompt") or ""), "prompt", honor_exceptions=False)
    if findings:
        audit("prompt", findings, blocked=True)
        print(developer_message(findings, "prompt"), file=sys.stderr)
        return 2
    return 0


def hook_tool(payload: dict) -> int:
    """AI assistant tool hook (Claude Code PreToolUse). Exit 2 blocks the tool call."""
    tool = str(payload.get("tool_name") or "unknown")
    tool_input = payload.get("tool_input") or {}
    findings = check_tool_policy(tool, tool_input)
    for key, value in iter_strings(tool_input):
        # Scan each field on its own: serialising to JSON escapes quotes and hides
        # `password = "..."` from the rules.
        findings += scan_text(value, f"tool:{tool}:{key}" if key else f"tool:{tool}",
                              honor_exceptions=False)
    if findings:
        audit("tool", findings, blocked=True)
        print(developer_message(findings, "tool", tool), file=sys.stderr)
        return 2
    return 0


def run_hook(kind: str, raw: str) -> int:
    """Hooks fail closed: an exit code other than 0 or 2 would let the action through."""
    try:
        payload = json.loads(raw) if raw.strip() else {}
        if not isinstance(payload, dict):
            raise ValueError("hook payload is not a JSON object")
        return hook_prompt(payload) if kind == "prompt" else hook_tool(payload)
    except Exception as exc:  # noqa: BLE001 - any failure must still produce a decision
        # Only the exception type is printed: its message could quote the payload.
        reason = f"secret_guard could not inspect this {kind} ({type(exc).__name__})."
        fail_open = os.environ.get("SECRET_GUARD_FAIL_MODE", "closed").lower() == "open"
        audit(kind, [_policy("guard-error", "Guard error", kind, type(exc).__name__, "")],
              blocked=not fail_open)
        if fail_open:
            print(reason + " Allowed because SECRET_GUARD_FAIL_MODE=open (break-glass, logged).",
                  file=sys.stderr)
            return 0
        print(reason + " Blocked because the guard fails closed. Retry. If it keeps happening, tell "
              "AppSec. Break-glass: SECRET_GUARD_FAIL_MODE=open (logged).", file=sys.stderr)
        return 2


def read_paths(files_from: str | None, null: bool) -> list[str]:
    if not files_from:
        return []
    data = sys.stdin.read() if files_from == "-" else Path(files_from).read_text()
    return [p for p in (data.split("\0") if null else data.splitlines()) if p]


MAX_BYTES = 5 * 1024 * 1024


def scan_files(paths: list[str], allowlist: set[str], fmt: str, fail_on: str, stage: str,
               output: str | None = None) -> int:
    order = {"medium": 0, "high": 1, "critical": 2}
    findings: list[Finding] = []
    for p in paths:
        path = Path(p)
        try:
            if not path.is_file() or path.stat().st_size > MAX_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue  # binary
        findings.extend(scan_text(data.decode("utf-8", errors="ignore"), path.as_posix(), allowlist))

    blocking = [f for f in findings if order[f.severity] >= order[fail_on]]
    report = None
    if fmt == "sarif":
        report = json.dumps(to_sarif(findings), indent=2)
    elif fmt == "json":
        report = json.dumps([asdict(f) for f in findings], indent=2)
    elif findings:
        print(developer_message(findings, stage), file=sys.stderr)
    if report is not None:
        if output:
            Path(output).write_text(report + "\n")
        else:
            print(report)
    if fmt != "text" and findings:
        print(f"secret_guard: {len(findings)} finding(s), {len(blocking)} at or above {fail_on}",
              file=sys.stderr)
    audit(stage, findings, blocked=bool(blocking))
    return 1 if blocking else 0


SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.0"}


def to_sarif(findings: list[Finding]) -> dict:
    level = {"critical": "error", "high": "error", "medium": "warning"}
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "secret_guard", "version": VERSION, "rules": [
                {"id": r.id, "shortDescription": {"text": r.description},
                 "help": {"text": r.remediation},
                 "defaultConfiguration": {"level": level[r.severity]},
                 "properties": {"security-severity": SECURITY_SEVERITY[r.severity],
                                "tags": ["security", "secrets"]}} for r in ALL_RULES]}},
            "results": [{
                "ruleId": f.rule_id,
                "level": level[f.severity],
                "message": {"text": f"{f.description} ({f.preview}). {f.remediation}"},
                "partialFingerprints": {"secretFingerprint/v2": f.fingerprint},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.source},
                    "region": {"startLine": max(f.line, 1)}}}],
            } for f in findings],
        }],
    }


def print_rules() -> int:
    for r in ALL_RULES:
        kind = "keyword+heuristics" if r.generic else "pattern"
        print(f"{r.id:<28} {r.severity:<9} {kind:<19} {r.description}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="secret_guard", description=__doc__.split("\n\n")[0])
    ap.add_argument("--version", action="version", version=f"secret_guard {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hook-prompt", help="read an AI prompt hook payload on stdin")
    sub.add_parser("hook-tool", help="read an AI tool-call hook payload on stdin")
    sub.add_parser("rules", help="list detection rules")
    s = sub.add_parser("scan", help="scan files (pre-commit / CI)")
    s.add_argument("paths", nargs="*")
    s.add_argument("--files-from", metavar="FILE", help="read paths from FILE ('-' for stdin)")
    s.add_argument("-z", "--null", action="store_true", help="paths in --files-from are NUL-separated")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--output", "-o", help="write json/sarif to this file instead of stdout")
    s.add_argument("--fail-on", choices=["medium", "high", "critical"], default="high")
    s.add_argument("--allowlist", default=".secret-guard-allowlist")
    s.add_argument("--stage", choices=["auto", "precommit", "ci"], default="auto",
                   help="where this scan runs, for metrics (auto: ci when $CI is set)")
    a = ap.parse_args(argv)

    if a.cmd == "hook-prompt":
        return run_hook("prompt", sys.stdin.read())
    if a.cmd == "hook-tool":
        return run_hook("tool", sys.stdin.read())
    if a.cmd == "rules":
        return print_rules()
    stage = a.stage
    if stage == "auto":
        stage = "ci" if os.environ.get("CI", "").lower() in ("true", "1") else "precommit"
    paths = list(a.paths) + read_paths(a.files_from, a.null)
    return scan_files(paths, load_allowlist(Path(a.allowlist)), a.format, a.fail_on, stage, a.output)


if __name__ == "__main__":
    sys.exit(main())
