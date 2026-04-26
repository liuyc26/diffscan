import re
import math
from dataclasses import dataclass, field
from typing import Optional
import git


@dataclass
class Rule:
    name: str
    description: str
    severity: str
    pattern: Optional[str] = None
    _regex: re.Pattern = field(init=False, default=None, repr=False)

    def __post_init__(self):
        if self.pattern:
            self._regex = re.compile(self.pattern, re.IGNORECASE)


RULES: list[Rule] = [
    # Cloud provider keys
    Rule("aws_access_key_id", "AWS Access Key ID", "critical",
         r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    Rule("aws_secret_access_key", "AWS Secret Access Key", "critical",
         r"(?i)aws.{0,30}['\"]([0-9a-zA-Z/+]{40})['\"]"),
    Rule("gcp_service_account", "GCP Service Account JSON", "critical",
         r'"type"\s*:\s*"service_account"'),
    Rule("azure_storage_key", "Azure Storage Account Key", "critical",
         r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
    Rule("azure_client_secret", "Azure Client Secret", "high",
         r"(?i)azure.{0,30}['\"]([A-Za-z0-9~._\-]{34,40})['\"]"),

    # Source control tokens
    Rule("github_pat", "GitHub Personal Access Token", "critical",
         r"ghp_[A-Za-z0-9]{36,}"),
    Rule("github_oauth", "GitHub OAuth Token", "critical",
         r"gho_[A-Za-z0-9]{36,}"),
    Rule("github_app_token", "GitHub App / Installation Token", "critical",
         r"(ghs_|ghu_)[A-Za-z0-9]{36,}"),
    Rule("github_refresh_token", "GitHub Refresh Token", "critical",
         r"ghr_[A-Za-z0-9]{76,}"),
    Rule("gitlab_pat", "GitLab Personal Access Token", "critical",
         r"glpat-[A-Za-z0-9\-_]{20,}"),
    Rule("bitbucket_token", "Bitbucket App Password / Token", "high",
         r"(?i)bitbucket.{0,20}['\"]([A-Za-z0-9_\-]{32,})['\"]"),

    # Payment & SaaS
    Rule("stripe_secret_key", "Stripe Secret Key", "critical",
         r"sk_live_[0-9a-zA-Z]{24,}"),
    Rule("stripe_restricted_key", "Stripe Restricted Key", "critical",
         r"rk_live_[0-9a-zA-Z]{24,}"),
    Rule("stripe_publishable_key", "Stripe Publishable Key", "high",
         r"pk_live_[0-9a-zA-Z]{24,}"),
    Rule("sendgrid_api_key", "SendGrid API Key", "critical",
         r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    Rule("twilio_account_sid", "Twilio Account SID", "high",
         r"AC[a-f0-9]{32}"),
    Rule("twilio_auth_token", "Twilio Auth Token", "critical",
         r"(?i)twilio.{0,20}['\"]([a-f0-9]{32})['\"]"),
    Rule("mailgun_api_key", "Mailgun API Key", "critical",
         r"key-[0-9a-zA-Z]{32}"),

    # Messaging & collaboration
    Rule("slack_token", "Slack Token", "critical",
         r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
    Rule("slack_webhook", "Slack Incoming Webhook URL", "high",
         r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24,}"),
    Rule("discord_token", "Discord Bot Token", "critical",
         r"[MN][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}"),
    Rule("telegram_bot_token", "Telegram Bot Token", "critical",
         r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}"),

    # Private keys & certificates
    Rule("private_key_header", "PEM Private Key", "critical",
         r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    Rule("pgp_private_key", "PGP Private Key", "critical",
         r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),

    # Auth tokens
    Rule("jwt_token", "JSON Web Token", "high",
         r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    Rule("bearer_token", "Bearer Token in Authorization Header", "high",
         r"(?i)(authorization|auth)\s*[:=]\s*['\"]?bearer\s+([A-Za-z0-9_\-\.]{20,})['\"]?"),
    Rule("basic_auth_url", "Credentials in URL", "critical",
         r"https?://[^:@\s]+:[^:@\s]+@[^\s]+"),

    # Database connection strings
    Rule("db_connection_string", "Database Connection String with Credentials", "critical",
         r"(postgres|postgresql|mysql|mariadb|mongodb|redis|mssql)://[^:@\s/]+:[^@\s/]+@[^\s]+"),

    # Generic high-signal patterns
    Rule("generic_api_key", "Generic API Key Assignment", "medium",
         r"(?i)(api[_\-]?key|api[_\-]?secret|app[_\-]?secret)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.]{20,})['\"]"),
    Rule("generic_secret", "Generic Secret / Password Assignment", "medium",
         r"(?i)(secret[_\-]?key|client[_\-]?secret|auth[_\-]?secret)\s*[:=]\s*['\"]([^\s'\"]{10,})['\"]"),
    Rule("generic_password", "Hardcoded Password", "medium",
         r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]"),
    Rule("private_key_var", "Private Key Variable Assignment", "high",
         r"(?i)(private[_\-]?key|priv[_\-]?key)\s*[:=]\s*['\"]([^\s'\"]{20,})['\"]"),

    # Entropy-based (handled separately, no pattern)
    Rule("high_entropy_string", "High-Entropy String (possible secret)", "medium"),
]


# Characters typical in secrets for entropy scanning
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS = set("0123456789abcdefABCDEF")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in freq.values())


def _high_entropy_tokens(line: str) -> list[str]:
    """Return tokens that look like high-entropy secrets."""
    found = []
    # Extract quoted strings and bare tokens that are long enough
    candidates = re.findall(r"['\"]([A-Za-z0-9+/=_\-\.]{20,})['\"]", line)
    candidates += re.findall(r"(?<![A-Za-z0-9])([a-f0-9]{32,64})(?![A-Za-z0-9])", line)
    for token in candidates:
        chars = set(token)
        if chars.issubset(_HEX_CHARS) and _shannon_entropy(token) > 3.5:
            found.append(token)
        elif chars.issubset(_B64_CHARS) and _shannon_entropy(token) > 4.5:
            found.append(token)
    return found


def mask_value(value: str) -> str:
    if len(value) <= 8:
        return "****"
    visible = max(4, len(value) // 6)
    return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]


def mask_line(line: str, secret: str) -> str:
    """Replace the secret in the line with its masked form."""
    if not secret:
        return line
    return line.replace(secret, mask_value(secret))


@dataclass
class RawFinding:
    rule_name: str
    description: str
    severity: str
    file_path: str
    line_number: int
    line_content: str
    matched_value: str


def scan_line(line: str, file_path: str, line_number: int) -> list[RawFinding]:
    findings: list[RawFinding] = []
    seen_values: set[str] = set()

    for rule in RULES:
        if rule.pattern is None:
            # Entropy rule — handled below
            continue
        for m in rule._regex.finditer(line):
            # Use the last capture group if present (the secret value), else full match
            value = m.group(m.lastindex) if m.lastindex else m.group(0)
            if value in seen_values:
                continue
            seen_values.add(value)
            findings.append(RawFinding(
                rule_name=rule.name,
                description=rule.description,
                severity=rule.severity,
                file_path=file_path,
                line_number=line_number,
                line_content=line,
                matched_value=value,
            ))

    # Entropy scan only if no rule already fired on this line
    if not findings:
        for token in _high_entropy_tokens(line):
            if token not in seen_values:
                seen_values.add(token)
                findings.append(RawFinding(
                    rule_name="high_entropy_string",
                    description="High-Entropy String (possible secret)",
                    severity="medium",
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line,
                    matched_value=token,
                ))

    return findings


# Files / extensions to skip
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".tgz", ".rar",
    ".bin", ".exe", ".dll", ".so", ".dylib", ".wasm",
    ".lock", ".sum",
}
_SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}


def _should_skip(file_path: str) -> bool:
    import os
    _, ext = os.path.splitext(file_path.lower())
    if ext in _SKIP_EXTENSIONS:
        return True
    if os.path.basename(file_path) in _SKIP_FILES:
        return True
    return False


def scan_commit_diff(diff_text: str, file_path: str) -> list[RawFinding]:
    """Scan added lines from a unified diff patch."""
    if _should_skip(file_path):
        return []

    findings: list[RawFinding] = []
    current_line = 0

    for raw_line in diff_text.splitlines():
        # Parse hunk headers to track line numbers: @@ -a,b +c,d @@
        hunk = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_line)
        if hunk:
            current_line = int(hunk.group(1)) - 1
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            current_line += 1
            line_content = raw_line[1:]  # strip leading '+'
            findings.extend(scan_line(line_content, file_path, current_line))
        elif raw_line.startswith("-"):
            pass  # skip removed lines
        else:
            current_line += 1

    return findings


def scan_repository(
    repo_path: str,
    since_commit: Optional[str] = None,
    depth: str = "latest",
    branch: str = "",
) -> tuple[list[RawFinding], list[str], str]:
    """
    Scan a git repository for secrets.

    branch: branch name, "all" (every branch), or "" (HEAD/default).
    depth:  "latest" | "incremental" | "all" | "<N>"

    Returns (findings, commit_hashes_scanned, head_commit_hash).
    """
    try:
        repo = git.Repo(repo_path, search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        raise ValueError(f"Not a git repository: {repo_path}")

    head_sha = repo.head.commit.hexsha

    if branch == "all":
        # Deduplicate commits across all local branches
        seen_shas: set[str] = set()
        commits: list = []
        for ref in repo.branches:
            for c in repo.iter_commits(ref):
                if c.hexsha not in seen_shas:
                    seen_shas.add(c.hexsha)
                    commits.append(c)
    else:
        ref = branch if branch else "HEAD"
        if depth == "all":
            commits = list(repo.iter_commits(ref))
        elif depth == "incremental" and since_commit:
            try:
                commits = list(repo.iter_commits(f"{since_commit}..{ref}"))
            except git.GitCommandError:
                commits = [repo.commit(ref)]
        elif depth.isdigit():
            commits = list(repo.iter_commits(ref, max_count=int(depth)))
        else:
            commits = [repo.commit(ref)]

    all_findings: list[RawFinding] = []
    scanned_shas: list[str] = []

    for commit in commits:
        scanned_shas.append(commit.hexsha)
        if commit.parents:
            diffs = commit.parents[0].diff(commit, create_patch=True)
        else:
            # Initial commit — diff against empty tree
            diffs = commit.diff(git.NULL_TREE, create_patch=True)

        for diff_item in diffs:
            file_path = diff_item.b_path or diff_item.a_path or "unknown"
            try:
                patch = diff_item.diff.decode("utf-8", errors="replace")
            except Exception:
                continue

            for finding in scan_commit_diff(patch, file_path):
                finding.file_path = file_path
                # Attach commit metadata
                finding_with_meta = RawFinding(
                    rule_name=finding.rule_name,
                    description=finding.description,
                    severity=finding.severity,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    line_content=finding.line_content,
                    matched_value=finding.matched_value,
                )
                finding_with_meta.__dict__["commit_hash"] = commit.hexsha
                finding_with_meta.__dict__["commit_message"] = (commit.message or "").strip()[:500]
                finding_with_meta.__dict__["author"] = str(commit.author)
                all_findings.append(finding_with_meta)

    return all_findings, scanned_shas, head_sha
