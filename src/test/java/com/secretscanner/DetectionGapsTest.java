package com.secretscanner;

import burp.api.montoya.logging.Logging;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.PrintStream;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the 2026-10-24 detection-gap fixes: template literals, values holding the
 * other quote character, bracket-assignment keys, escaped / entity-encoded JSON, string
 * concatenation, same-line comment GUIDs, separator-insensitive noise keys and the JSON walker's
 * placeholder guard. All values are synthetic.
 */
@DisplayName("Detection gaps")
class DetectionGapsTest {

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

    private static final String SECRET = "Rk7Lq2Wm9Zp4Tn8Vx3B";

    private static List<SecretFinding> scan(String body, String ct) {
        ScanSettings s = new ScanSettings();
        s.setTier(ScanSettings.ScanTier.FULL);
        return new SecretScanner(s, NOOP).scanText(body, ct, "https://app.example.test/static/main.js");
    }

    private static Optional<SecretFinding> withValue(List<SecretFinding> fs, String value) {
        return fs.stream().filter(f -> f.matchedValue().equals(value)).findFirst();
    }

    @Test void templateLiteralValue() {
        List<SecretFinding> fs = scan("var cfg={clientSecret:`" + SECRET + "`};", "application/javascript");
        assertTrue(withValue(fs, SECRET).isPresent(), fs.toString());
    }

    @Test void templateLiteralWithInterpolationIsNotASecret() {
        List<SecretFinding> fs = scan("var cfg={clientSecret:`${process.env.CS}" + SECRET + "`};", "application/javascript");
        assertTrue(fs.stream().noneMatch(f -> f.matchedValue().contains(SECRET)), fs.toString());
    }

    @Test void valueContainingTheOtherQuote() {
        String v = "Rk7L'q2Wm9Zp4Tn8Vx";
        List<SecretFinding> fs = scan("var cfg={apiSecret:\"" + v + "\"};", "application/javascript");
        assertTrue(withValue(fs, v).isPresent(), fs.toString());
    }

    @Test void bracketAssignmentKey() {
        List<SecretFinding> fs = scan("headers['x-api-key'] = \"" + SECRET + "\";", "application/javascript");
        Optional<SecretFinding> f = withValue(fs, SECRET);
        assertTrue(f.isPresent(), fs.toString());
        assertEquals("x-api-key", f.get().keyName());
    }

    @Test void jsonInsideAString() {
        String body = "{\"cfg\":\"{\\\"clientSecret\\\":\\\"" + SECRET + "\\\"}\"}";
        List<SecretFinding> fs = scan(body, "application/json");
        Optional<SecretFinding> f = withValue(fs, SECRET);
        assertTrue(f.isPresent(), fs.toString());
        assertEquals(body.indexOf(SECRET), f.get().matchOffset());
    }

    @Test void entityEncodedAttribute() {
        String body = "<html><body><div data-config=\"{&quot;clientSecret&quot;:&quot;" + SECRET
                + "&quot;}\"></div></body></html>";
        List<SecretFinding> fs = scan(body, "text/html");
        assertTrue(withValue(fs, SECRET).isPresent(), fs.toString());
    }

    @Test void concatenatedGenericSecret() {
        List<SecretFinding> fs = scan("var apiKey = \"Rk7Lq2Wm9\" + \"Zp4Tn8Vx3B\";", "application/javascript");
        assertTrue(withValue(fs, SECRET).isPresent(), fs.toString());
    }

    @Test void concatenatedVendorToken() {
        String token = "ghp_Ll6BVUlR0KN318G0n0otpdy30LIUkyT46Ntq";
        List<SecretFinding> fs = scan("var t = \"" + token.substring(0, 20) + "\" + \"" + token.substring(20) + "\";",
                "application/javascript");
        Optional<SecretFinding> f = withValue(fs, token);
        assertTrue(f.isPresent(), fs.toString());
        assertEquals("GITHUB_PAT_001", f.get().ruleId());
    }

    @Test void sameLineCommentGuid() {
        String guid = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";
        List<SecretFinding> fs = scan("var cfg = {\n  \"ClientId\": \"\", // \"" + guid + "\"\n};", "application/javascript");
        assertTrue(fs.stream().anyMatch(f -> f.ruleId().equals("COMMENTED_GUID") && f.matchedValue().equals(guid)),
                fs.toString());
    }

    @Test void noiseKeysMatchAcrossSeparators() {
        List<SecretFinding> fs = scan("{\"X_CSRF_TOKEN\":\"Rk7Lq2Wm9Zp4Tn8Vx3BqW\"}", "application/json");
        assertTrue(withValue(fs, "Rk7Lq2Wm9Zp4Tn8Vx3BqW").isEmpty(), fs.toString());
    }

    @Test void jsonWalkerAppliesPlaceholderGuard() {
        List<SecretFinding> fs = scan("{\"keys\":[\"sk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX\"]}", "application/json");
        assertTrue(fs.stream().noneMatch(f -> f.matchedValue().startsWith("sk_live_")), fs.toString());
    }

    @Test void hardcodedBearerInResponseIsReported() {
        String v = "Rk7Lq2Wm9Zp4Tn8Vx3BqW5e";
        List<SecretFinding> fs = scan("fetch(u,{headers:{Authorization:\"Bearer " + v + "\"}});", "application/javascript");
        assertTrue(withValue(fs, v).isPresent(), fs.toString());
    }

    // ---- noise: literals that are only part of a computed string ----------------------------

    @Test void reactInternalKeyPrefixIsNotASecret() {
        String body = "var randomKey = \"$\" + Math.random().toString(36).slice(2), "
                + "internalInstanceKey = \"__reactFiber$\" + randomKey, "
                + "internalRootNodeResourcesKey = \"__reactResources$\" + randomKey, "
                + "internalHoistableMarker = \"__reactMarker$\" + randomKey;";
        List<SecretFinding> fs = scan(body, "application/javascript");
        assertTrue(fs.stream().noneMatch(f -> f.matchedValue().startsWith("__react")), fs.toString());
    }

    @Test void concatOperandPrefixIsNotASecret() {
        List<SecretFinding> fs = scan("var sessionKey = \"Rk7Lq2Wm9Zp4Tn8Vx3B\" + suffix;", "application/javascript");
        assertTrue(withValue(fs, SECRET).isEmpty(), fs.toString());
    }

    @Test void wordShapedValueUnderSecretKeyIsNotASecret() {
        List<SecretFinding> fs = scan("var cfg={resourcesKey:\"internalHoistableMarker\"};", "application/javascript");
        assertTrue(withValue(fs, "internalHoistableMarker").isEmpty(), fs.toString());
    }

    @Test void realSecretNextToAConcatenationIsStillFound() {
        List<SecretFinding> fs = scan("var apiSecret = \"" + SECRET + "\"; var url = base + \"/v1\";", "application/javascript");
        assertTrue(withValue(fs, SECRET).isPresent(), fs.toString());
    }
}
