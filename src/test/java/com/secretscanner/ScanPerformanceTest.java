package com.secretscanner;

import burp.api.montoya.logging.Logging;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Inputs that used to make a FULL-tier scan take seconds to minutes, plus a check that the
 * GENERIC_KV rewrite finds exactly what the old pattern found.
 */
@DisplayName("Scan performance on pathological bodies")
class ScanPerformanceTest {

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

    /**
     * GENERIC_KV written plainly (no lookbehind, no possessive quantifiers), kept here only to prove
     * the fast form in Patterns finds exactly the same matches. Groups: 1 quoted key, 2 bare key,
     * 3 quote, 4 value.
     */
    private static final Pattern PLAIN_GENERIC_KV = Pattern.compile(
            "(?i)(?:[\"']([A-Za-z0-9_\\-]+(?:\\s[A-Za-z0-9_\\-]+){0,2})[\"']\\]?|([A-Za-z0-9_\\-]+))\\s*[:=]\\s*([\"'`])((?:(?!\\3)[^\\r\\n]){6,500})\\3");

    private static long fullScanMillis(String body, String contentType) {
        ScanSettings s = new ScanSettings();
        s.setTier(ScanSettings.ScanTier.FULL);
        s.setPiiEnabled(true);
        SecretScanner scanner = new SecretScanner(s, NOOP);
        long t0 = System.nanoTime();
        scanner.scanText(body, contentType, "https://perf.local/app.js");
        return (System.nanoTime() - t0) / 1_000_000;
    }

    @Test void longQuotedHexString() {
        StringBuilder sb = new StringBuilder("var wasm=\"");
        Random r = new Random(1);
        while (sb.length() < 100_000) sb.append("0123456789abcdef".charAt(r.nextInt(16)));
        sb.append("\";");
        long ms = fullScanMillis(sb.toString(), "application/javascript");
        assertTrue(ms < 3000, "100 KB quoted hex took " + ms + " ms");
    }

    @Test void unclosedScriptTags() {
        long ms = fullScanMillis("<html>" + "<script>".repeat(70_000), "text/html");
        assertTrue(ms < 3000, "560 KB of unclosed <script> took " + ms + " ms");
    }

    @Test void genericKvRewriteFindsTheSameMatches() {
        String[] parts = {"key", "apiKey", "\"", "'", ":", "=", " ", "\n", "-", "_", "abcdef1234", "\"User ID\"",
                "x", "9", "{", "}", ",", "\\", "secret_value_123", "`", "]", "['k']"};
        Random rnd = new Random(3);
        for (int t = 0; t < 30000; t++) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0, n = rnd.nextInt(16); i < n; i++) sb.append(parts[rnd.nextInt(parts.length)]);
            String s = sb.toString();
            assertEquals(matches(PLAIN_GENERIC_KV, s), matches(Patterns.GENERIC_KV, s), s);
        }
    }

    private static List<String> matches(Pattern p, String s) {
        List<String> out = new ArrayList<>();
        Matcher m = p.matcher(s);
        while (m.find()) out.add(m.start() + ":" + m.group(1) + "|" + m.group(2) + "|" + m.group(4));
        return out;
    }
}
