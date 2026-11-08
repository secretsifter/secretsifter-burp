package com.secretscanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Regression guards for two bugs caught in the 2026-10-26 review. */
@DisplayName("Review fixes")
class ReviewFixesTest {

    // ── Bug 1: isPublicByDesign matched "research*" via the "search" substring ──
    @Test void researchKeyIsNotTreatedAsPublicSearchKey() {
        String val = "AbC123def456GHI789jkl012MNO3";   // 28 alnum, matches the search-key value shape
        assertFalse(SecretScanner.isPublicByDesign("researchApiKey", val),
                "a research* key must not be suppressed as a public search-only key");
        assertFalse(SecretScanner.isPublicByDesign("market_research_token", val));
        // genuine search-only keys must still be recognised
        assertTrue(SecretScanner.isPublicByDesign("searchApiKey", val));
        assertTrue(SecretScanner.isPublicByDesign("algoliaSearchKey", val));
    }

    // ── Bug 2: redacted HTML report leaked a partial secret in the JSON context ──
    @Test void redactedReportDoesNotLeakSecretInContext() {
        String secret = "ZZTOPSECRET" + "k".repeat(140);   // long: trunc(context,120) will split it
        String context = "const config = { apiToken: '" + secret + "' };";
        SecretFinding f = SecretFinding.of("GENERIC_KV", "Generic KV", "apiToken", secret,
                "HIGH", "FIRM", 1, context, "https://app.example.test/main.js");
        String html = HtmlReportGenerator.generate(List.of(f), "target", "Bulk", true);
        assertFalse(html.contains("ZZTOPSECRET"),
                "redacted report must not contain any part of the secret");
        assertFalse(html.contains(secret), "redacted report must not contain the full secret");
    }
}
