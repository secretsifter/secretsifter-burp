package com.secretscanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for Patterns.java — verifies that every anchored token
 * pattern matches known-good samples and rejects known-bad inputs.
 *
 * Rules:
 *  - Each test group covers one Pattern constant.
 *  - "match" tests use a realistic sample value.
 *  - "noMatch" tests use a value that is structurally close but invalid.
 */
@DisplayName("Patterns regression tests")
class PatternsTest {

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private static void assertMatches(Pattern p, String input) {
        assertTrue(p.matcher(input).find(),
                "Expected pattern to MATCH: " + input);
    }

    private static void assertNoMatch(Pattern p, String input) {
        assertFalse(p.matcher(input).find(),
                "Expected pattern NOT to match: " + input);
    }

    // =========================================================================
    // GitHub
    // =========================================================================

    @Nested @DisplayName("GitHub tokens")
    class GitHub {

        @Test void ghp_classic_match()   { assertMatches(Patterns.rulePattern("GITHUB_PAT_001"), "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"); }
        @Test void ghp_classic_noMatch() { assertNoMatch(Patterns.rulePattern("GITHUB_PAT_001"), "ghp_SHORT"); }

        @Test void gho_oauth_match()     { assertMatches(Patterns.rulePattern("GITHUB_PAT_002"),       "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"); }
        @Test void ghs_actions_match()   { assertMatches(Patterns.rulePattern("GITHUB_PAT_003"),     "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"); }
        @Test void ghr_refresh_match()   { assertMatches(Patterns.rulePattern("GITHUB_PAT_004"),     "ghr_" + "A".repeat(76)); }

        @Test void fine_pat_match()      { assertMatches(Patterns.rulePattern("GITHUB_PAT_005"),    "github_pat_" + "A".repeat(82)); }
        @Test void fine_pat_noMatch()    { assertNoMatch(Patterns.rulePattern("GITHUB_PAT_005"),    "github_pat_SHORT"); }
    }

    // =========================================================================
    // GitLab
    // =========================================================================

    @Nested @DisplayName("GitLab tokens")
    class GitLab {
        @Test void pat_match()    { assertMatches(Patterns.rulePattern("GITLAB_PAT_001"),    "glpat-ABCDEFGHIJabcdefghij"); }
        @Test void pat_noMatch()  { assertNoMatch(Patterns.rulePattern("GITLAB_PAT_001"),    "glpat-SHORT"); }
        @Test void deploy_match() { assertMatches(Patterns.rulePattern("GITLAB_PAT_002"), "gldt-ABCDEFGHIJabcdefghij"); }
    }

    // =========================================================================
    // npm
    // =========================================================================

    @Nested @DisplayName("npm token")
    class Npm {
        @Test void match()   { assertMatches(Patterns.rulePattern("NPM_TOKEN_001"), "npm_ABCDEFGHIJabcdefghij0123456789abcdef"); }
        @Test void noMatch() { assertNoMatch(Patterns.rulePattern("NPM_TOKEN_001"), "npm_SHORT"); }
    }

    // =========================================================================
    // Slack
    // =========================================================================

    @Nested @DisplayName("Slack tokens")
    class Slack {
        @Test void bot_match()     { assertMatches(Patterns.rulePattern("SLACK_TOKEN_001"),    "xoxb-1234567890-1234567890-ABCDEFabcdefABCDEFabcdef"); }
        @Test void user_match()    { assertMatches(Patterns.rulePattern("SLACK_TOKEN_002"),   "xoxp-1234567890-1234567890-1234567890-ABCDEFabcdefABCDEFabcdefABCDEFab"); }
        @Test void app_match()     { assertMatches(Patterns.rulePattern("SLACK_TOKEN_003"),    "xapp-1-A0123456789-1234567890123-" + "ab12".repeat(16)); }
        @Test void webhook_match() { assertMatches(Patterns.rulePattern("SLACK_TOKEN_005"),"https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/ABCDEFGHIJabcdefghijABCD"); }
    }

    // =========================================================================
    // Stripe
    // =========================================================================

    @Nested @DisplayName("Stripe keys")
    class Stripe {
        @Test void live_match()    { assertMatches(Patterns.rulePattern("STRIPE_KEY_001"),   "sk_live_ABCDEFGHIJabcdefghij0123456"); }
        @Test void test_match()    { assertMatches(Patterns.rulePattern("STRIPE_KEY_002"),   "sk_test_ABCDEFGHIJabcdefghij0123456"); }
        @Test void restricted()    { assertMatches(Patterns.rulePattern("STRIPE_KEY_003"),    "rk_live_ABCDEFGHIJabcdefghij0123456"); }
        @Test void pk_live_match() { assertMatches(Patterns.rulePattern("STRIPE_KEY_004"),       "pk_live_ABCDEFGHIJabcdefghij0123456"); }
        @Test void webhook_match() { assertMatches(Patterns.rulePattern("STRIPE_KEY_005"),"whsec_ABCDEFGHIJabcdefghij01234567890123456789"); }
        @Test void webhook_noMatch(){ assertNoMatch(Patterns.rulePattern("STRIPE_KEY_005"),"whsec_SHORT"); }
    }

    // =========================================================================
    // AWS
    // =========================================================================

    @Nested @DisplayName("AWS keys")
    class Aws {
        @Test void access_key_akia()  { assertMatches(Patterns.rulePattern("AWS_KEY_001"), "AKIAIOSFODNN7EXAMPLE"); }
        @Test void access_key_asia()  { assertMatches(Patterns.rulePattern("AWS_KEY_001"), "ASIAIOSFODNN7EXAMPLE"); }
        @Test void access_key_bad()   { assertNoMatch(Patterns.rulePattern("AWS_KEY_001"), "BKIAIOSFODNN7EXAMPLE"); }
        @Test void access_key_short() { assertNoMatch(Patterns.rulePattern("AWS_KEY_001"), "AKIA1234"); }
    }

    // =========================================================================
    // Google
    // =========================================================================

    @Nested @DisplayName("Google keys")
    class Google {
        @Test void api_key_match()     { assertMatches(Patterns.rulePattern("GOOGLE_KEY_001"),           "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"); }
        @Test void api_key_noMatch()   { assertNoMatch(Patterns.rulePattern("GOOGLE_KEY_001"),           "AIzaSHORT"); }
        @Test void oauth_client_match(){ assertMatches(Patterns.rulePattern("GOOGLE_KEY_002"),"123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"); }
    }

    // =========================================================================
    // OpenAI / Anthropic / Groq / xAI
    // =========================================================================

    @Nested @DisplayName("AI API keys")
    class AiKeys {
        @Test void openai_match()    { assertMatches(Patterns.rulePattern("OPENAI_KEY_001"),    "sk-" + "A".repeat(48)); }
        @Test void openai_noMatch()  { assertNoMatch(Patterns.rulePattern("OPENAI_KEY_001"),    "sk-SHORT"); }
        @Test void openai_proj()     { assertMatches(Patterns.rulePattern("OPENAI_KEY_002"),"sk-proj-" + "A".repeat(48)); }
        @Test void anthropic_match() { assertMatches(Patterns.rulePattern("ANTHROPIC_KEY_001"), "sk-ant-api01-" + "A".repeat(93)); }
        @Test void groq_match()      { assertMatches(Patterns.rulePattern("GROQ_KEY_001"),  "gsk_" + "A".repeat(52)); }
        @Test void groq_noMatch()    { assertNoMatch(Patterns.rulePattern("GROQ_KEY_001"),  "gsk_SHORT"); }
        @Test void xai_match()       { assertMatches(Patterns.rulePattern("XAI_KEY_001"),   "xai-" + "A".repeat(80)); }
        @Test void hf_match()        { assertMatches(Patterns.rulePattern("HF_KEY_001"), "hf_" + "A".repeat(34)); }
    }

    // =========================================================================
    // Shopify
    // =========================================================================

    @Nested @DisplayName("Shopify tokens")
    class Shopify {
        @Test void access_token() { assertMatches(Patterns.rulePattern("SHOPIFY_KEY_001"),  "shpat_" + "a".repeat(32)); }
        @Test void secret()       { assertMatches(Patterns.rulePattern("SHOPIFY_KEY_002"), "shpss_" + "a".repeat(32)); }
        @Test void custom()       { assertMatches(Patterns.rulePattern("SHOPIFY_KEY_003"), "shpca_" + "a".repeat(32)); }
    }

    // =========================================================================
    // SendGrid / Twilio / Mailgun
    // =========================================================================

    @Nested @DisplayName("Messaging API keys")
    class Messaging {
        @Test void sendgrid_match()   { assertMatches(Patterns.rulePattern("SENDGRID_KEY_001"),       "SG." + "A".repeat(22) + "." + "A".repeat(43)); }
        @Test void twilio_sid_match() { assertMatches(Patterns.rulePattern("TWILIO_SID_001"),     "AC" + "a".repeat(32)); }
        @Test void mailgun_match()    { assertMatches(Patterns.rulePattern("MAILGUN_KEY_001"), "key-" + "a".repeat(32)); }
        @Test void mailgun_noMatch()  { assertNoMatch(Patterns.rulePattern("MAILGUN_KEY_001"), "key-SHORT"); }
    }

    // =========================================================================
    // PEM Private Key
    // =========================================================================

    @Nested @DisplayName("PEM private key header")
    class Pem {
        // PEM_PRIVATE_KEY requires header + newline + ≥1 base64 line (to avoid matching stub comments).
        private static final String KEY_BODY = "\nMIIEpAIBAAKCAQEA1234567890ABCDEF\n";
        @Test void rsa_match()    { assertMatches(Patterns.rulePattern("PEM_PRIVKEY_001"), "-----BEGIN RSA PRIVATE KEY-----"    + KEY_BODY); }
        @Test void ec_match()     { assertMatches(Patterns.rulePattern("PEM_PRIVKEY_001"), "-----BEGIN EC PRIVATE KEY-----"     + KEY_BODY); }
        @Test void bare_match()   { assertMatches(Patterns.rulePattern("PEM_PRIVKEY_001"), "-----BEGIN PRIVATE KEY-----"        + KEY_BODY); }
        @Test void openssh_match(){ assertMatches(Patterns.rulePattern("PEM_PRIVKEY_001"), "-----BEGIN OPENSSH PRIVATE KEY-----" + KEY_BODY); }
        @Test void pub_noMatch()  { assertNoMatch(Patterns.rulePattern("PEM_PRIVKEY_001"), "-----BEGIN PUBLIC KEY-----"); }
    }

    // =========================================================================
    // JWT
    // =========================================================================

    @Nested @DisplayName("JWT token")
    class Jwt {
        @Test void match() {
            assertMatches(Patterns.rulePattern("JWT_TOKEN_001"),
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" +
                    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        }
        @Test void noMatch_twoSegments() {
            assertNoMatch(Patterns.rulePattern("JWT_TOKEN_001"), "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0");
        }
    }

    // =========================================================================
    // PII — SSN
    // =========================================================================

    @Nested @DisplayName("SSN patterns")
    class Ssn {
        @Test void valid_ssn()          { assertMatches(Patterns.SSN, "123-45-6789"); }
        @Test void invalid_000_prefix() { assertNoMatch(Patterns.SSN, "000-45-6789"); }
        @Test void invalid_666_prefix() { assertNoMatch(Patterns.SSN, "666-45-6789"); }
        @Test void invalid_900_prefix() { assertNoMatch(Patterns.SSN, "900-45-6789"); }
        @Test void invalid_00_middle()  { assertNoMatch(Patterns.SSN, "123-00-6789"); }
        @Test void invalid_0000_end()   { assertNoMatch(Patterns.SSN, "123-45-0000"); }
    }

    // =========================================================================
    // Credit Card — Luhn-valid samples
    // =========================================================================

    @Nested @DisplayName("Credit card candidate patterns")
    class CreditCard {
        @Test void visa_match()       { assertMatches(Patterns.CC_CANDIDATE, "4111111111111111"); }
        @Test void mastercard_match() { assertMatches(Patterns.CC_CANDIDATE, "5500005555555559"); }
        @Test void amex_match()       { assertMatches(Patterns.CC_CANDIDATE, "371449635398431"); }
        @Test void too_short()        { assertNoMatch(Patterns.CC_CANDIDATE, "41111111111"); }
    }

    // =========================================================================
    // Noise key filter (should not be treated as secrets)
    // =========================================================================

    @Nested @DisplayName("FORCED_NOISE_KEYS set")
    class NoiseKeys {
        @Test void contains_known_noise() {
            assertTrue(Patterns.FORCED_NOISE_KEYS.contains("client_id"));
            assertTrue(Patterns.FORCED_NOISE_KEYS.contains("redirect_uri"));
            assertTrue(Patterns.FORCED_NOISE_KEYS.contains("nonce"));
            assertTrue(Patterns.FORCED_NOISE_KEYS.contains("tenant_id"));
        }
        @Test void does_not_contain_real_secret_keys() {
            assertFalse(Patterns.FORCED_NOISE_KEYS.contains("api_key"));
            assertFalse(Patterns.FORCED_NOISE_KEYS.contains("client_secret"));
            assertFalse(Patterns.FORCED_NOISE_KEYS.contains("access_token"));
        }
    }

    // =========================================================================
    // DB / URL with credentials
    // =========================================================================

    @Nested @DisplayName("Credential-bearing URLs")
    class CredUrls {
        @Test void http_with_creds() {
            assertMatches(Patterns.URL_WITH_CREDS, "https://admin:s3cr3tP@ss@db.example.com/mydb");
        }
        @Test void no_creds() {
            assertNoMatch(Patterns.URL_WITH_CREDS, "https://db.example.com/mydb");
        }
        @Test void mongodb_conn() {
            assertMatches(Patterns.DB_CONN_STRING,
                    "mongodb://myuser:mypassword@cluster0.mongodb.net/mydb");
        }
        @Test void postgres_conn() {
            assertMatches(Patterns.DB_CONN_STRING,
                    "postgresql://pguser:pgpass@localhost:5432/appdb");
        }
    }

    // =========================================================================
    // Additional vendor tokens
    // =========================================================================

    @Nested @DisplayName("Additional vendor tokens")
    class Vendors {
        @Test void discord_webhook() {
            assertMatches(Patterns.rulePattern("DISCORD_TOKEN_002"),
                    "https://discord.com/api/webhooks/123456789012345678/" + "A".repeat(68));
        }
        @Test void telegram_bot() {
            assertMatches(Patterns.rulePattern("TELEGRAM_KEY_001"), "1234567890:AA" + "A".repeat(33)); }
        @Test void telegram_bad()  { assertNoMatch(Patterns.rulePattern("TELEGRAM_KEY_001"), "12345:AAshort"); }

        @Test void databricks()    { assertMatches(Patterns.rulePattern("DATABRICKS_KEY_001"),     "dapi" + "a".repeat(32)); }
        @Test void mailchimp()     { assertMatches(Patterns.rulePattern("MAILCHIMP_KEY_001"),      "a".repeat(32) + "-us12"); }
        @Test void supabase()      { assertMatches(Patterns.rulePattern("SUPABASE_KEY_001"),   "sbp_" + "a".repeat(40)); }
        @Test void razorpay_live() { assertMatches(Patterns.rulePattern("RAZORPAY_KEY_001"),  "rzp_live_" + "Ab1".repeat(4) + "Cd"); }
        @Test void razorpay_test() { assertMatches(Patterns.rulePattern("RAZORPAY_KEY_002"),  "rzp_test_" + "Ab1".repeat(4) + "Cd"); }
        @Test void okta_ssws()     { assertMatches(Patterns.rulePattern("OKTA_KEY_001"),"SSWS " + "A".repeat(40)); }
        @Test void circleci()      { assertMatches(Patterns.rulePattern("CIRCLECI_KEY_001"), "CCIPAT_" + "Ab1".repeat(7) + "C_" + "a1b2".repeat(10)); }
        @Test void sentry()        { assertMatches(Patterns.rulePattern("SENTRY_KEY_001"), "sntrys_eyJpYXQiOjE3MDAwMDAwMDB9" + "Ab1+".repeat(12) + "==_" + "Cd2/".repeat(10) + "Ab1"); }
        @Test void figma()         { assertMatches(Patterns.rulePattern("FIGMA_KEY_001"),    "figd_" + "A".repeat(43)); }
        @Test void do_pat()        { assertMatches(Patterns.rulePattern("DO_KEY_001"),"dop_v1_" + "a".repeat(64)); }
        @Test void planetscale()   { assertMatches(Patterns.rulePattern("PSQL_KEY_001"), "pscale_pw_" + "A".repeat(43)); }
        @Test void postman()       { assertMatches(Patterns.rulePattern("POSTMAN_KEY_001"),"PMAK-" + "a".repeat(24) + "-" + "A".repeat(34)); }
    }
}
