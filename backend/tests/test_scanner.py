"""Tests for the secret scanner engine."""
import pytest
from app.scanner import scan_line, scan_commit_diff, mask_value, _shannon_entropy, RULES


# ── Helpers ────────────────────────────────────────────────────────────────

def findings_for(line: str, file: str = "test.py", lineno: int = 1):
    return scan_line(line, file, lineno)

def rules_fired(line: str) -> set[str]:
    return {f.rule_name for f in findings_for(line)}

def added_lines_patch(*lines: str, start: int = 1) -> str:
    """Build a minimal unified diff patch with the given added lines."""
    patch = f"@@ -0,0 +{start},{len(lines)} @@\n"
    patch += "".join(f"+{l}\n" for l in lines)
    return patch


# ── Masking ────────────────────────────────────────────────────────────────

class TestMasking:
    def test_short_value_fully_masked(self):
        assert mask_value("abc") == "****"

    def test_long_value_shows_prefix_and_suffix(self):
        masked = mask_value("AKIAIOSFODNN7EXAMPLE")
        assert masked.startswith("AKIA")
        assert masked.endswith("MPLE")
        assert "****" in masked

    def test_masked_length_longer_than_original(self):
        # masked version should never reveal more than original
        original = "sk_live_AbCdEfGhIjKlMnOpQrStUvWx"
        masked = mask_value(original)
        assert original not in masked


# ── Entropy ────────────────────────────────────────────────────────────────

class TestEntropy:
    def test_uniform_string_low_entropy(self):
        assert _shannon_entropy("aaaaaaaaaa") < 1.0

    def test_random_b64_high_entropy(self):
        assert _shannon_entropy("aK9mP2xQrL5nT8wVbYjH3cGdFsEuIoZq") > 4.0

    def test_hex_hash_high_entropy(self):
        # SHA-256 has more uniform distribution than MD5 of empty string
        assert _shannon_entropy("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3") > 3.5

    def test_english_sentence_moderate_entropy(self):
        e = _shannon_entropy("the quick brown fox")
        assert 3.0 < e < 4.5


# ── Cloud provider keys ────────────────────────────────────────────────────

class TestAWSRules:
    def test_access_key_id(self):
        assert "aws_access_key_id" in rules_fired('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

    def test_access_key_id_abia_prefix(self):
        # ABIA + 16 chars, no trailing alphanumeric (would break the lookahead)
        assert "aws_access_key_id" in rules_fired("key=ABIAIOSFODNN7EXAMPLE ")

    def test_access_key_not_triggered_on_short(self):
        assert "aws_access_key_id" not in rules_fired('key = "AKIASHORT"')

    def test_secret_access_key(self):
        line = 'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert "aws_secret_access_key" in rules_fired(line)


class TestGCPRule:
    def test_service_account_json(self):
        assert "gcp_service_account" in rules_fired('"type": "service_account"')


# ── Source control tokens ──────────────────────────────────────────────────

class TestGitHubTokens:
    def test_personal_access_token(self):
        token = "ghp_" + "A" * 36
        assert "github_pat" in rules_fired(f'TOKEN = "{token}"')

    def test_oauth_token(self):
        token = "gho_" + "B" * 36
        assert "github_oauth" in rules_fired(f'token = "{token}"')

    def test_app_installation_token(self):
        token = "ghs_" + "C" * 36
        assert "github_app_token" in rules_fired(f'auth = "{token}"')

    def test_short_token_not_matched(self):
        assert "github_pat" not in rules_fired('token = "ghp_short"')


class TestGitLabToken:
    def test_pat(self):
        assert "gitlab_pat" in rules_fired('TOKEN="glpat-abcdefghij1234567890"')


# ── Payment & SaaS ─────────────────────────────────────────────────────────

class TestStripeRules:
    def test_stripe_secret_key(self):
        key = "sk_live_" + "a" * 24
        assert "stripe_secret_key" in rules_fired(f'STRIPE_KEY="{key}"')

    def test_stripe_publishable_key(self):
        key = "pk_live_" + "b" * 24
        assert "stripe_publishable_key" in rules_fired(f'key = "{key}"')

    def test_stripe_test_key_not_matched(self):
        # sk_test_ is not a production secret — not in rules
        key = "sk_test_" + "a" * 24
        assert "stripe_secret_key" not in rules_fired(f'key = "{key}"')


class TestSendGridRule:
    def test_sendgrid_api_key(self):
        key = "SG." + "a" * 22 + "." + "b" * 43
        assert "sendgrid_api_key" in rules_fired(f'key = "{key}"')


# ── Messaging ──────────────────────────────────────────────────────────────

class TestSlackRules:
    def test_bot_token(self):
        assert "slack_token" in rules_fired('token = "xoxb-1234567890-abcdefghij"')

    def test_webhook_url(self):
        url = "https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/abcdefghijklmnopqrstuvwx"
        assert "slack_webhook" in rules_fired(f'webhook = "{url}"')


# ── Private keys ───────────────────────────────────────────────────────────

class TestPrivateKeyRules:
    def test_rsa_private_key_header(self):
        assert "private_key_header" in rules_fired("-----BEGIN RSA PRIVATE KEY-----")

    def test_ec_private_key_header(self):
        assert "private_key_header" in rules_fired("-----BEGIN EC PRIVATE KEY-----")

    def test_openssh_private_key(self):
        assert "private_key_header" in rules_fired("-----BEGIN OPENSSH PRIVATE KEY-----")

    def test_pgp_private_key(self):
        assert "pgp_private_key" in rules_fired("-----BEGIN PGP PRIVATE KEY BLOCK-----")

    def test_public_key_not_matched(self):
        assert "private_key_header" not in rules_fired("-----BEGIN PUBLIC KEY-----")


# ── Auth tokens ────────────────────────────────────────────────────────────

class TestJWTRule:
    def test_valid_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert "jwt_token" in rules_fired(f'Authorization: Bearer {jwt}')

    def test_short_jwt_not_matched(self):
        assert "jwt_token" not in rules_fired("eyJhbG.eyJz.sig")


class TestBearerToken:
    def test_authorization_header(self):
        assert "bearer_token" in rules_fired('Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456')

    def test_auth_variable(self):
        assert "bearer_token" in rules_fired('auth = "Bearer mytoken_abcdefghijklmnopqrst"')


# ── Database URLs ──────────────────────────────────────────────────────────

class TestDatabaseURL:
    def test_postgres_url(self):
        assert "db_connection_string" in rules_fired(
            'DATABASE_URL = "postgresql://admin:supersecret@prod.db.io:5432/mydb"'
        )

    def test_mysql_url(self):
        assert "db_connection_string" in rules_fired(
            'DB = "mysql://root:password@localhost/app"'
        )

    def test_mongodb_url(self):
        assert "db_connection_string" in rules_fired(
            'MONGO_URI = "mongodb://user:pass@cluster.mongodb.net/db"'
        )

    def test_url_without_credentials_not_matched(self):
        # no password component
        assert "db_connection_string" not in rules_fired(
            'DB = "postgresql://localhost:5432/mydb"'
        )


class TestBasicAuthURL:
    def test_credentials_in_url(self):
        assert "basic_auth_url" in rules_fired('url = "https://user:pass@api.example.com"')


# ── Generic patterns ───────────────────────────────────────────────────────

class TestGenericPatterns:
    def test_api_key_assignment(self):
        assert "generic_api_key" in rules_fired('api_key = "abcdefghijklmnopqrstuvwxyz1234"')

    def test_apikey_no_separator(self):
        assert "generic_api_key" in rules_fired('apikey="ABCDEFGHIJKLMNOPQRSTUVWXYZ123"')

    def test_client_secret(self):
        assert "generic_secret" in rules_fired('client_secret = "mysupersecretvalue123"')

    def test_password_assignment(self):
        assert "generic_password" in rules_fired('password = "hunter12345"')

    def test_short_password_not_matched(self):
        # < 8 chars
        assert "generic_password" not in rules_fired('pwd = "abc"')


# ── Entropy detection ──────────────────────────────────────────────────────

class TestEntropyDetection:
    def test_high_entropy_b64_string_detected(self):
        line = 'secret = "aK9mP2xQrL5nT8wVbYjH3cGdFsEuIoZq"'
        assert "high_entropy_string" in rules_fired(line)

    def test_hex_hash_detected(self):
        # 40-char hex that doesn't trigger any named rule (no AKIA, ghp_, AC..., etc.)
        line = 'checksum = "1b4f0e9851971998e73207854c96b36c3d01cedf"'
        assert "high_entropy_string" in rules_fired(line)

    def test_normal_string_not_flagged(self):
        assert not findings_for('message = "hello world this is normal"')

    def test_entropy_suppressed_when_named_rule_fires(self):
        # A real AWS key should NOT also produce a high_entropy_string finding
        line = 'key = "AKIAIOSFODNN7EXAMPLE"'
        names = rules_fired(line)
        assert "aws_access_key_id" in names
        assert "high_entropy_string" not in names


# ── Diff parsing ───────────────────────────────────────────────────────────

class TestDiffParsing:
    def test_only_added_lines_scanned(self):
        patch = (
            "@@ -1,3 +1,3 @@\n"
            " context line\n"
            "-removed = \"AKIAIOSFODNN7EXAMPLE\"\n"   # removed — must NOT fire
            "+added_safe = \"nothing secret here\"\n"
        )
        findings = scan_commit_diff(patch, "config.py")
        assert not any(f.rule_name == "aws_access_key_id" for f in findings)

    def test_added_line_scanned(self):
        patch = added_lines_patch('KEY = "AKIAIOSFODNN7EXAMPLE"')
        findings = scan_commit_diff(patch, "config.py")
        assert any(f.rule_name == "aws_access_key_id" for f in findings)

    def test_line_number_tracked(self):
        patch = added_lines_patch("safe = 1", 'token = "ghp_' + 'A' * 36 + '"', start=10)
        findings = scan_commit_diff(patch, "app.py")
        assert findings[0].line_number == 11  # second line, starting at 10

    def test_binary_extension_skipped(self):
        patch = added_lines_patch('KEY = "AKIAIOSFODNN7EXAMPLE"')
        assert scan_commit_diff(patch, "image.png") == []

    def test_lock_file_skipped(self):
        patch = added_lines_patch('some_token = "ghp_' + 'X' * 36 + '"')
        assert scan_commit_diff(patch, "package-lock.json") == []

    def test_multiple_secrets_same_line(self):
        # Both an AWS key and a DB URL on the same line
        patch = added_lines_patch(
            'x="AKIAIOSFODNN7EXAMPLE" db="postgresql://u:p@h/d"'
        )
        names = {f.rule_name for f in scan_commit_diff(patch, "f.py")}
        assert "aws_access_key_id" in names
        assert "db_connection_string" in names

    def test_no_false_positives_on_empty_patch(self):
        assert scan_commit_diff("", "main.py") == []


# ── Rule coverage sanity check ─────────────────────────────────────────────

class TestRuleList:
    def test_all_named_rules_have_pattern_or_are_entropy(self):
        for rule in RULES:
            if rule.name != "high_entropy_string":
                assert rule.pattern is not None, f"{rule.name} has no pattern"
                assert rule._regex is not None, f"{rule.name} regex failed to compile"

    def test_severities_are_valid(self):
        valid = {"critical", "high", "medium", "low"}
        for rule in RULES:
            assert rule.severity in valid, f"{rule.name} has invalid severity: {rule.severity}"
