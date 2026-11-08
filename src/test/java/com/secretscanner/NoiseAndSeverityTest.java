package com.secretscanner;

import burp.api.montoya.logging.Logging;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.PrintStream;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the 2026-10-24 noise-suppression audit: real secrets that used to be
 * dropped, duplicates that used to be reported several times, and severities read from key names.
 * All values are synthetic.
 */
@DisplayName("Noise suppression, duplicates and severity")
class NoiseAndSeverityTest {

    private static final Logging NOOP = new Logging() {
        @Override public PrintStream output()                              { return System.out; }
        @Override public PrintStream error()                               { return System.err; }
        @Override public void logToOutput(String message)                  {}
        @Override public void logToOutput(Object message)                  {}
        @Override public void logToError(String message)                   {}
        @Override public void logToError(String message, Throwable cause)  {}
        @Override public void logToError(Throwable cause)                  {}
        @Override public void raiseDebugEvent(String message)              {}
        @Override public void raiseInfoEvent(String message)               {}
        @Override public void raiseErrorEvent(String message)              {}
        @Override public void raiseCriticalEvent(String message)           {}
    };

    private static List<SecretFinding> scan(String body, String ct) {
        ScanSettings s = new ScanSettings();
        s.setTier(ScanSettings.ScanTier.FULL);
        return new SecretScanner(s, NOOP).scanText(body, ct, "https://app.example.test/static/main.js");
    }

    private static Optional<SecretFinding> withValue(List<SecretFinding> fs, String value) {
        return fs.stream().filter(f -> f.matchedValue().equals(value)).findFirst();
    }

    // ---- real secrets that used to be dropped -------------------------------------------

    @Test void shortRandomSecretsUnderSecretKeys() {
        for (String v : List.of("Xk9mP2qR7tLw", "Rk7Lq2Wm9Zp4Tn8Vx3B", "q7w2e9r4t1y8u3i6o5p0a2s4d6", "K7Q2M9X4P1R8T3W6Z5N0")) {
            List<SecretFinding> fs = scan("var cfg={clientSecret:\"" + v + "\"};", "application/javascript");
            assertTrue(withValue(fs, v).isPresent(), "missed " + v + " -> " + fs);
        }
    }

    @Test void shortPasswordsUnderPasswordKeys() {
        for (String v : List.of("Passw0rd2024", "Spring2025!", "Welcome2024Prod")) {
            List<SecretFinding> fs = scan("var cfg={adminPassword:\"" + v + "\"};", "application/javascript");
            Optional<SecretFinding> f = withValue(fs, v);
            assertTrue(f.isPresent(), "missed " + v);
            assertEquals("HIGH", f.get().severity());
        }
    }

    @Test void urlEncodedPasswordInConnectionString() {
        List<SecretFinding> fs = scan("db = \"postgres://appuser:Pa%24%24w0rd%21x@db.internal:5432/app\";",
                "application/javascript");
        assertTrue(fs.stream().anyMatch(f -> f.ruleId().startsWith("DB_CONN")), fs.toString());
    }

    @Test void weakButRealDefaultPassword() {
        List<SecretFinding> fs = scan("var cfg={smtpPassword:\"Changeme123!\"};", "application/javascript");
        assertTrue(withValue(fs, "Changeme123!").isPresent());
        // a bare placeholder is still a placeholder
        assertTrue(withValue(scan("var cfg={smtpPassword:\"changeme\"};", "application/javascript"), "changeme").isEmpty());
    }

    @Test void configKeyNamedWithKeySuffix() {
        String v = "InsecureShield-Config-Key-2024Q4";
        List<SecretFinding> fs = scan("const SP_CONFIG_KEY = \"" + v + "\";", "application/javascript");
        assertTrue(withValue(fs, v).isPresent(), fs.toString());
    }

    @Test void oneSignalStyleKeysAreNotEventHandlers() {
        String v = "9Kq8ZtR2mVx9LpW4nBy7cD3fGh2Jk4Lm6Np8";
        assertTrue(withValue(scan("var c={onesignalApiKey:\"" + v + "\"};", "application/javascript"), v).isPresent());
    }

    @Test void secretNamedPublicEnvVar() {
        String v = "Xk9mP2qR7tLwZq8Vb3Nc";
        List<SecretFinding> fs = scan("window.env={NEXT_PUBLIC_DB_PASSWORD:\"" + v + "\"};", "application/javascript");
        assertTrue(withValue(fs, v).isPresent(), fs.toString());
    }

    // ---- noise that must stay suppressed -----------------------------------------------

    @Test void identifiersStayQuiet() {
        for (String v : List.of("SystemNotificationEvents123", "PENDING_UNABLE_POSTPONE_PAYMENT_12_DAYS",
                "msal:acquireTokenStart", "userProfileSettingsV2")) {
            assertTrue(withValue(scan("var c={apiToken:\"" + v + "\"};", "application/javascript"), v).isEmpty(), v);
        }
    }

    // ---- duplicates --------------------------------------------------------------------

    @Test void oneFindingPerSecretPerResponse() {
        String body = "{\"aws\":{\"aws_access_key_id\":\"AKIAR4NXBZP7KMGVQJLT\"},\"apiKey\":\"AIzaSyD9tSrke72SzMh9Xq6xqGwPy8T3h7k8KcR\"}";
        List<SecretFinding> fs = scan(body, "application/json");
        assertEquals(1, fs.stream().filter(f -> f.matchedValue().equals("AKIAR4NXBZP7KMGVQJLT")).count(), fs.toString());
        assertEquals("AWS_KEY_001", withValue(fs, "AKIAR4NXBZP7KMGVQJLT").get().ruleId());
        assertEquals(1, fs.stream().filter(f -> f.matchedValue().startsWith("AIza")).count());
    }

    @Test void massExposureFoldsIntoOneFinding() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < 40; i++) {
            if (i > 0) sb.append(',');
            sb.append("{\"id\":").append(i).append(",\"passwordHash\":\"")
              .append(String.format("%064X", (long) i * 7919 + 1234567)).append("\"}");
        }
        sb.append(']');
        List<SecretFinding> fs = scan(sb.toString(), "application/json");
        long hashes = fs.stream().filter(f -> "passwordHash".equals(f.keyName())).count();
        assertEquals(1, hashes, fs.toString());
        assertTrue(fs.stream().filter(f -> "passwordHash".equals(f.keyName())).findFirst().get()
                .context().contains("distinct values"));
    }

    // ---- severity read from key words --------------------------------------------------

    @Test void severityFromKeyWords() {
        assertEquals("HIGH", withValue(scan("var c={jwtSecret:\"Xk9mP2qR7tLwZq8\"};", "application/javascript"),
                "Xk9mP2qR7tLwZq8").get().severity());
        assertEquals("HIGH", withValue(scan("var c={db_password:\"Summer2024!Prod\"};", "application/javascript"),
                "Summer2024!Prod").get().severity());
        Optional<SecretFinding> name = withValue(scan("var c={apiKeyName:\"Xk9mP2qR7tLwZq8Vb\"};", "application/javascript"),
                "Xk9mP2qR7tLwZq8Vb");
        name.ifPresent(f -> assertEquals("LOW", f.severity()));
    }

    // ---- overlapping vendor rules and JWT claims ----------------------------------------

    @Test void vendorNamedInContextWinsOverlap() {
        String v = "sk_live_" + "A1B2C3D4E5F6G7H8J9K0".repeat(2);       // Paystack shape, also Stripe-shaped
        List<SecretFinding> fs = scan("const PAYSTACK_SECRET = \"" + v + "\";", "application/javascript");
        assertEquals("PAYSTACK_KEY_001", withValue(fs, v).get().ruleId(), fs.toString());
    }

    @Test void jwtSeverityFollowsRoleClaim() {
        String service = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"role\":\"service_role\",\"iss\":\"supabase\"}".getBytes())
                + ".Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg";
        String anon = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"role\":\"anon\",\"iss\":\"supabase\"}".getBytes())
                + ".Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg";
        List<SecretFinding> fs = scan("const a=\"" + anon + "\"; const b=\"" + service + "\";", "application/javascript");
        assertEquals("HIGH", withValue(fs, service).get().severity());
        assertEquals("INFORMATION", withValue(fs, anon).get().severity());
    }

    // ---- generic stages (batch 6) ---------------------------------------------------------

    @Test void unquotedDotenvAndYamlAndProperties() {
        String env = "NODE_ENV=production\nAPI_KEY=Xk9mP2qR7tLwZq8Vb3NcDf6H\nDB_PASSWORD=Pr0d!Passw0rd#2024\n";
        List<SecretFinding> fs = new SecretScanner(full(), NOOP).scanText(env, "text/plain", "https://app.example.test/.env");
        assertTrue(withValue(fs, "Xk9mP2qR7tLwZq8Vb3NcDf6H").isPresent(), fs.toString());
        assertTrue(withValue(fs, "Pr0d!Passw0rd#2024").isPresent(), fs.toString());
        String yml = "spring:\n  datasource:\n    password: S3cr3tYamlPass!\n    url: jdbc:x\n";
        fs = new SecretScanner(full(), NOOP).scanText(yml, "application/x-yaml", "https://app.example.test/application.yml");
        assertTrue(withValue(fs, "S3cr3tYamlPass!").isPresent(), fs.toString());
    }

    @Test void connectionStringsWithEmptyUserAndDriverSuffix() {
        assertTrue(withValue(scan("var r=\"redis://:R3d1s_Pr0d_9x@cache.internal:6379\";", "application/javascript"),
                "R3d1s_Pr0d_9x").isPresent());
        assertTrue(withValue(scan("var p=\"postgresql+psycopg2://app:Pg_S3cret_77@db.internal/app\";", "application/javascript"),
                "Pg_S3cret_77").isPresent());
        assertTrue(withValue(scan("var c=\"Password=AdoP4ss!2024;Server=sql.internal;User ID=sa\";", "application/javascript"),
                "AdoP4ss!2024").isPresent());
    }

    @Test void urlCredentialPlaceholdersAreIgnored() {
        assertTrue(scan("x=\"https://user:<password>@db.example.test\"", "application/javascript").stream()
                .noneMatch(f -> f.ruleId().equals("URL_CREDS")));
    }

    @Test void apiKeyInQueryString() {
        String v = "crawler-svc-key-4f2a8b1c9d3e7f0a";
        List<SecretFinding> fs = scan("<!-- https://crawler.example.test/api?api_key=" + v + "&env=prod -->", "application/xml");
        assertTrue(withValue(fs, v).isPresent(), fs.toString());
    }

    @Test void base64BlobIsDecodedAndRescanned() {
        String inner = "{\"stripe\":\"sk_live_51HxQwErTyUiOpAsDfGhJkLzXcVb1234567890ab\",\"note\":\"api_key\"}";
        String b64 = java.util.Base64.getEncoder().encodeToString(inner.getBytes());
        List<SecretFinding> fs = scan("var blob=\"" + b64 + "\";", "application/javascript");
        Optional<SecretFinding> f = withValue(fs, "sk_live_51HxQwErTyUiOpAsDfGhJkLzXcVb1234567890ab");
        assertTrue(f.isPresent(), fs.toString());
        assertEquals(List.of("base64"), f.get().meta().decodeChain());
    }

    @Test void jsonServedAsHtmlIsWalked() {
        List<SecretFinding> fs = scan("{\"client_secret\":\"Pr0d!Xk9mP2qR7tLwZq8\",\"db_password\":\"Summer2024!Prod\"}", "text/html");
        assertTrue(withValue(fs, "Summer2024!Prod").isPresent(), fs.toString());
    }

    @Test void versionStringsAndMathSinAreNotSecrets() {
        assertTrue(withValue(scan("var c={appKey:\"v2.14.3-rc.12\"};", "application/javascript"), "v2.14.3-rc.12").isEmpty());
        ScanSettings s = full(); s.setPiiEnabled(true);
        assertTrue(new SecretScanner(s, NOOP).scanText("y=Math.sin(a); id=\"123-45-6789\";", "application/javascript",
                "https://app.example.test/a.js").stream().noneMatch(f -> f.ruleId().equals("SSN_PII")));
    }

    private static ScanSettings full() {
        ScanSettings s = new ScanSettings();
        s.setTier(ScanSettings.ScanTier.FULL);
        return s;
    }

    // ---- link following and chunk discovery (batch 7) ------------------------------------

    @Test void chunkDiscoveryCoversModernBundlers() {
        String js = "import(\"./assets/Login-9f3a1b2c.js\");n.p+\"static/js/\"+e+\".\"+{12:\"3f2a1b9c\",57:\"aa11bb22\"}[e]+\".chunk.js\";"
                + "const x=\"/_next/static/chunks/pages/_app-0a1b2c3d.js\";";
        List<String> urls = SecretScanner.extractWebpackChunkUrls(js, "https://app.example.test/static/js/main.js");
        assertTrue(urls.contains("https://app.example.test/static/js/assets/Login-9f3a1b2c.js"), urls.toString());
        assertTrue(urls.contains("https://app.example.test/_next/static/chunks/pages/_app-0a1b2c3d.js"), urls.toString());
        assertTrue(urls.stream().anyMatch(u -> u.endsWith("static/js/12.3f2a1b9c.chunk.js")), urls.toString());
        assertTrue(urls.stream().anyMatch(u -> u.endsWith("static/js/57.aa11bb22.chunk.js")), urls.toString());
    }

    @Test void scriptAndPreloadExtraction() {
        String html = "<script src=/app.js></script><link rel=\"modulepreload\" href=\"/assets/vendor-1a2b.js\">";
        assertEquals(List.of("https://app.example.test/app.js"),
                SecretScanner.extractScriptSrcs(html, "https://app.example.test/"));
        assertEquals(List.of("https://app.example.test/assets/vendor-1a2b.js"),
                SecretScanner.extractPreloadLinks(html, "https://app.example.test/"));
        assertEquals(List.of("https://app.example.test/assets/index-abc.js"),
                SecretScanner.extractAssetManifestUrls("{\"index.html\":{\"file\":\"assets/index-abc.js\"}}",
                        "https://app.example.test/"));
    }
}
