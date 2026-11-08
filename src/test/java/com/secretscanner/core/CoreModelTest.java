package com.secretscanner.core;

import com.secretscanner.SecretFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Core finding model")
class CoreModelTest {

    private static SecretFinding finding(String value, String url, int offset) {
        return SecretFinding.of("AWS_KEY_001", "AWS Access Key ID", "aws_access_key_id", value,
                "HIGH", "CERTAIN", 1, "ctx", url, offset);
    }

    @Nested @DisplayName("FindingMeta")
    class Meta {
        @Test void defaultsToEmpty() {
            SecretFinding f = finding("AKIAABCDEFGHIJKLMNOP", "https://a/x.js", 10);
            assertSame(FindingMeta.EMPTY, f.meta());
            assertFalse(f.meta().isScored());
        }

        @Test void enrichmentKeepsIdentity() {
            SecretFinding f = finding("AKIAABCDEFGHIJKLMNOP", "https://a/x.js", 10);
            SecretFinding scored = f.withMeta(f.meta().withScore(90, List.of("anchored-rule"))
                    .withAsset("123456789012"));
            assertEquals(f, scored, "meta must not affect equality (BulkScanPanel uses indexOf)");
            assertEquals(f.hashCode(), scored.hashCode());
            assertEquals(90, scored.meta().score());
        }

        @Test void copiesCarryMeta() {
            SecretFinding f = finding("AKIAABCDEFGHIJKLMNOP", "u", 1).withMeta(FindingMeta.EMPTY.withReason("checksum-ok"));
            assertEquals(List.of("checksum-ok"), f.withSeverity("LOW").meta().reasons());
            assertEquals(List.of("checksum-ok"), f.withTargetUrl("https://t").meta().reasons());
        }

        @Test void rejectsBadScore() {
            assertThrows(IllegalArgumentException.class, () -> FindingMeta.EMPTY.withScore(101, List.of()));
        }

        @Test void legacyConstructorStillWorks() {
            SecretFinding f = new SecretFinding("R", "N", "k", "v", "HIGH", "FIRM", 1, "c", "u", "", -1);
            assertSame(FindingMeta.EMPTY, f.meta());
        }
    }

    @Nested @DisplayName("Fingerprints")
    class Fp {
        @Test void stableAndValueOnly() {
            assertEquals(Fingerprints.of("secret-value-1"), Fingerprints.of("secret-value-1"));
            assertNotEquals(Fingerprints.of("secret-value-1"), Fingerprints.of("secret-value-2"));
            assertEquals(16, Fingerprints.of("x").length());
        }

        @Test void keyedNotPlainHash() {
            byte[] saved = Fingerprints.randomKey();
            Fingerprints.setKey(saved);
            String a = Fingerprints.of("password123");
            Fingerprints.setKey(Fingerprints.randomKey());
            String b = Fingerprints.of("password123");
            Fingerprints.setKey(saved);
            assertNotEquals(a, b, "different keys must give different fingerprints");
            assertEquals(a, Fingerprints.of("password123"));
        }

        @Test void rejectsShortKey() {
            assertThrows(IllegalArgumentException.class, () -> Fingerprints.setKey(new byte[8]));
        }

        @Test void redaction() {
            assertEquals("AKIA************MNOP", Fingerprints.redact("AKIAABCDEFGHIJKLMNOP"));
            assertEquals("************", Fingerprints.redact("short-secret"));
            assertEquals("", Fingerprints.redact(""));
        }
    }

    @Nested @DisplayName("SecretGroup")
    class Grouping {
        @Test void groupsOccurrencesByValue() {
            List<SecretFinding> fs = List.of(
                    finding("AKIAAAAAAAAAAAAAAAAA", "https://a/1.js", 1),
                    finding("AKIABBBBBBBBBBBBBBBB", "https://a/1.js", 2),
                    finding("AKIAAAAAAAAAAAAAAAAA", "https://b/2.js", 3),
                    finding("AKIAAAAAAAAAAAAAAAAA", "https://a/1.js", 4));
            List<SecretGroup<SecretFinding>> g = SecretGroup.group(fs, SecretFinding::matchedValue, SecretFinding::sourceUrl);
            assertEquals(2, g.size());
            assertEquals(3, g.get(0).count());
            assertEquals(List.of("https://a/1.js", "https://b/2.js"), List.copyOf(g.get(0).locations()));
            assertSame(fs.get(0), g.get(0).representative());
            assertEquals(fs.get(0).fingerprint(), g.get(0).fingerprint());
        }
    }

    /** The engine packages must stay free of Burp so they can run headless (CLI, tests, CI). */
    @Test
    void enginePackagesHaveNoBurpImports() throws IOException {
        for (String pkg : List.of("core", "rules")) {
            Path dir = Paths.get("src/main/java/com/secretscanner/" + pkg);
            try (Stream<Path> files = Files.walk(dir)) {
                for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                    String src = Files.readString(p);
                    assertFalse(src.contains("import burp."), p + " imports Burp; the engine must stay Burp-free");
                    assertFalse(src.contains("burp.api."), p + " references the Montoya API");
                }
            }
        }
    }
}
