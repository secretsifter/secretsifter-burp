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

        @Test void ghp_classic_match()   { assertMatches(Patterns.GITHUB_PAT_CLASSIC, "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"); }
        @Test void ghp_classic_noMatch() { assertNoMatch(Patterns.GITHUB_PAT_CLASSIC, "ghp_SHORT"); }

        @Test void gho_oauth_match()     { assertMatches(Patterns.GITHUB_OAUTH,       "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"); }
        @Test void ghs_actions_match()   { assertMatches(Patterns.GITHUB_ACTIONS,     "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"); }
        @Test void ghr_refresh_match()   { assertMatches(Patterns.GITHUB_REFRESH,     "ghr_" + "A".repeat(76)); }

        @Test void fine_pat_match()      { assertMatches(Patterns.GITHUB_FINE_PAT,    "github_pat_" + "A".repeat(82)); }
        @Test void fine_pat_noMatch()    { assertNoMatch(Patterns.GITHUB_FINE_PAT,    "github_pat_SHORT"); }
    }

    // =========================================================================
    // GitLab
    // =========================================================================

    @Nested @DisplayName("GitLab tokens")
    class GitLab {
        @Test void pat_match()    { assertMatches(Patterns.GITLAB_PAT,    "glpat-ABCDEFGHIJabcdefghij"); }
        @Test void pat_noMatch()  { assertNoMatch(Patterns.GITLAB_PAT,    "glpat-SHORT"); }
        @Test void deploy_match() { assertMatches(Patterns.GITLAB_DEPLOY, "gldt-ABCDEFGHIJabcdefghij"); }
    }

    // =========================================================================
    // npm
    // =========================================================================

    @Nested @DisplayName("npm token")
    class Npm {
        @Test void match()   { assertMatches(Patterns.NPM_TOKEN, "npm_ABCDEFGHIJabcdefghij0123456789abcdef"); }
        @Test void noMatch() { assertNoMatch(Patterns.NPM_TOKEN, "npm_SHORT"); }
    }

    // =========================================================================
    // Slack
    // =========================================================================

    @Nested @DisplayName("Slack tokens")
    class Slack {
        @Test void bot_match()     { assertMatches(Patterns.SLACK_BOT,    "xoxb-1234567890-1234567890-ABCDEFabcdefABCDEFabcdef"); }
        @Test void user_match()    { assertMatches(Patterns.SLACK_USER,   "xoxp-1234567890-1234567890-1234567890-ABCDEFabcdefABCDEFabcdefABCDEFab"); }
        @Test void app_match()     { assertMatches(Patterns.SLACK_APP,    "xapp-1-ABCDEFGHIJabcdefghij0123"); }
        @Test void webhook_match() { assertMatches(Patterns.SLACK_WEBHOOK,"https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/ABCDEFGHIJabcdefghijABCD"); }
    }

    // =========================================================================
    // Stripe
    // =========================================================================

    @Nested @DisplayName("Stripe keys")
    class Stripe {
        @Test void live_match()    { assertMatches(Patterns.STRIPE_SECRET_LIVE,   "sk_live_ABCDEFGHIJabcdefghij0123456"); }
        @Test void test_match()    { assertMatches(Patterns.STRIPE_SECRET_TEST,   "sk_test_ABCDEFGHIJabcdefghij0123456"); }
        @Test void restricted()    { assertMatches(Patterns.STRIPE_RESTRICTED,    "rk_live_ABCDEFGHIJabcdefghij0123456"); }
        @Test void pk_live_match() { assertMatches(Patterns.STRIPE_PK_LIVE,       "pk_live_ABCDEFGHIJabcdefghij0123456"); }
        @Test void webhook_match() { assertMatches(Patterns.STRIPE_WEBHOOK_SECRET,"whsec_ABCDEFGHIJabcdefghij01234567890123456789"); }
        @Test void webhook_noMatch(){ assertNoMatch(Patterns.STRIPE_WEBHOOK_SECRET,"whsec_SHORT"); }
    }

    // =========================================================================
    // AWS
    // =========================================================================

    @Nested @DisplayName("AWS keys")
    class Aws {
        @Test void access_key_akia()  { assertMatches(Patterns.AWS_ACCESS_KEY, "AKIAIOSFODNN7EXAMPLE"); }
        @Test void access_key_asia()  { assertMatches(Patterns.AWS_ACCESS_KEY, "ASIAIOSFODNN7EXAMPLE"); }
        @Test void access_key_bad()   { assertNoMatch(Patterns.AWS_ACCESS_KEY, "BKIAIOSFODNN7EXAMPLE"); }
        @Test void access_key_short() { assertNoMatch(Patterns.AWS_ACCESS_KEY, "AKIA1234"); }
    }

    // =========================================================================
    // Google
    // =========================================================================

    @Nested @DisplayName("Google keys")
    class Google {
        // Test fixtures are obviously synthetic so they can't be misread as real keys.
        @Test void api_key_match()     { assertMatches(Patterns.GOOGLE_KEY,           "AIza" + "A".repeat(35)); }
        @Test void api_key_noMatch()   { assertNoMatch(Patterns.GOOGLE_KEY,           "AIzaSHORT"); }
        @Test void oauth_client_match(){ assertMatches(Patterns.GOOGLE_OAUTH_CLIENT_ID,"123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"); }
    }

    // =========================================================================
    // OpenAI / Anthropic / Groq / xAI
    // =========================================================================

    @Nested @DisplayName("AI API keys")
    class AiKeys {
        @Test void openai_match()    { assertMatches(Patterns.OPENAI_KEY,    "sk-" + "A".repeat(48)); }
        @Test void openai_noMatch()  { assertNoMatch(Patterns.OPENAI_KEY,    "sk-SHORT"); }
        @Test void openai_proj()     { assertMatches(Patterns.OPENAI_PROJECT,"sk-proj-" + "A".repeat(48)); }
        @Test void anthropic_match() { assertMatches(Patterns.ANTHROPIC_KEY, "sk-ant-api01-" + "A".repeat(93)); }
        @Test void groq_match()      { assertMatches(Patterns.GROQ_API_KEY,  "gsk_" + "A".repeat(52)); }
        @Test void groq_noMatch()    { assertNoMatch(Patterns.GROQ_API_KEY,  "gsk_SHORT"); }
        @Test void xai_match()       { assertMatches(Patterns.XAI_API_KEY,   "xai-" + "A".repeat(80)); }
        @Test void hf_match()        { assertMatches(Patterns.HUGGINGFACE_TOKEN, "hf_" + "A".repeat(34)); }
    }

    // =========================================================================
    // Shopify
    // =========================================================================

    @Nested @DisplayName("Shopify tokens")
    class Shopify {
        @Test void access_token() { assertMatches(Patterns.SHOPIFY_TOKEN,  "shpat_" + "a".repeat(32)); }
        @Test void secret()       { assertMatches(Patterns.SHOPIFY_SECRET, "shpss_" + "a".repeat(32)); }
        @Test void custom()       { assertMatches(Patterns.SHOPIFY_CUSTOM, "shpca_" + "a".repeat(32)); }
    }

    // =========================================================================
    // SendGrid / Twilio / Mailgun
    // =========================================================================

    @Nested @DisplayName("Messaging API keys")
    class Messaging {
        @Test void sendgrid_match()   { assertMatches(Patterns.SENDGRID,       "SG." + "A".repeat(22) + "." + "A".repeat(43)); }
        @Test void twilio_sid_match() { assertMatches(Patterns.TWILIO_SID,     "AC" + "a".repeat(32)); }
        @Test void mailgun_match()    { assertMatches(Patterns.MAILGUN_API_KEY, "key-" + "a".repeat(32)); }
        @Test void mailgun_noMatch()  { assertNoMatch(Patterns.MAILGUN_API_KEY, "key-SHORT"); }
    }

    // =========================================================================
    // PEM Private Key
    // =========================================================================

    @Nested @DisplayName("PEM private key header")
    class Pem {
        // PEM_PRIVATE_KEY requires header + newline + ≥1 base64 line (to avoid matching stub comments).
        private static final String KEY_BODY = "\nMIIEpAIBAAKCAQEA1234567890ABCDEF\n";
        @Test void rsa_match()    { assertMatches(Patterns.PEM_PRIVATE_KEY, "-----BEGIN RSA PRIVATE KEY-----"    + KEY_BODY); }
        @Test void ec_match()     { assertMatches(Patterns.PEM_PRIVATE_KEY, "-----BEGIN EC PRIVATE KEY-----"     + KEY_BODY); }
        @Test void bare_match()   { assertMatches(Patterns.PEM_PRIVATE_KEY, "-----BEGIN PRIVATE KEY-----"        + KEY_BODY); }
        @Test void openssh_match(){ assertMatches(Patterns.PEM_PRIVATE_KEY, "-----BEGIN OPENSSH PRIVATE KEY-----" + KEY_BODY); }
        @Test void pub_noMatch()  { assertNoMatch(Patterns.PEM_PRIVATE_KEY, "-----BEGIN PUBLIC KEY-----"); }
    }

    // =========================================================================
    // JWT
    // =========================================================================

    @Nested @DisplayName("JWT token")
    class Jwt {
        @Test void match() {
            assertMatches(Patterns.JWT_TOKEN,
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
                    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0" +
                    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        }
        @Test void noMatch_twoSegments() {
            assertNoMatch(Patterns.JWT_TOKEN, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0");
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
            assertMatches(Patterns.DISCORD_WEBHOOK,
                    "https://discord.com/api/webhooks/123456789012345678/" + "A".repeat(68));
        }
        @Test void telegram_bot() {
            assertMatches(Patterns.TELEGRAM_BOT_TOKEN, "1234567890:AA" + "A".repeat(33)); }
        @Test void telegram_bad()  { assertNoMatch(Patterns.TELEGRAM_BOT_TOKEN, "12345:AAshort"); }

        @Test void databricks()    { assertMatches(Patterns.DATABRICKS,     "dapi" + "a".repeat(32)); }
        @Test void mailchimp()     { assertMatches(Patterns.MAILCHIMP,      "a".repeat(32) + "-us12"); }
        @Test void supabase()      { assertMatches(Patterns.SUPABASE_PAT,   "sbp_" + "a".repeat(40)); }
        @Test void razorpay_live() { assertMatches(Patterns.RAZORPAY_LIVE,  "rzp_live_" + "A".repeat(20)); }
        @Test void razorpay_test() { assertMatches(Patterns.RAZORPAY_TEST,  "rzp_test_" + "A".repeat(20)); }
        @Test void okta_ssws()     { assertMatches(Patterns.OKTA_SSWS_TOKEN,"SSWS " + "A".repeat(40)); }
        @Test void circleci()      { assertMatches(Patterns.CIRCLECI_TOKEN, "ccipat_" + "A".repeat(40)); }
        @Test void sentry()        { assertMatches(Patterns.SENTRY_AUTH_TOKEN, "sntrys_" + "A".repeat(64)); }
        @Test void figma()         { assertMatches(Patterns.FIGMA_TOKEN,    "figd_" + "A".repeat(43)); }
        @Test void do_pat()        { assertMatches(Patterns.DO_ACCESS_TOKEN,"dop_v1_" + "a".repeat(64)); }
        @Test void planetscale()   { assertMatches(Patterns.PLANETSCALE_PW, "pscale_pw_" + "A".repeat(43)); }
        @Test void postman()       { assertMatches(Patterns.POSTMAN_API_KEY,"PMAK-" + "a".repeat(24) + "-" + "A".repeat(34)); }
    }
}
