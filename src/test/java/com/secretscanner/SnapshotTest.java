package com.secretscanner;

import burp.api.montoya.logging.Logging;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * Golden-file regression test.
 *
 * Scans every file under src/test/resources/snapshot-corpus at each scan tier and compares
 * the full, sorted list of findings against snapshot/golden-findings.txt. Any refactor that
 * is meant to be behaviour-neutral must leave this file byte-identical.
 *
 * To accept an intended change: run with -Dsnapshot.update=true and review the diff.
 */
@DisplayName("Snapshot: findings on the fixed corpus are unchanged")
class SnapshotTest {

    private static final Path CORPUS = Paths.get("src/test/resources/snapshot-corpus");
    private static final Path GOLDEN = Paths.get("src/test/resources/snapshot/golden-findings.txt");

    private static final Logging NOOP_LOG = new Logging() {
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

    private static final Path GOLDEN_CUSTOM = Paths.get("src/test/resources/snapshot/golden-findings-custom.txt");
    private static final Path COMMUNITY_RULES = Paths.get("community-rules");

    @Test
    void findingsMatchGolden() throws IOException {
        compareToGolden(GOLDEN, render());
    }

    /**
     * Same corpus with the 288 published community custom rules enabled: once alongside the
     * built-in scanners (FULL tier) and once in raw custom-rules-only mode, which skips the
     * custom-rule false-positive gates.
     */
    @Test
    void customRuleFindingsMatchGolden() throws IOException {
        List<String> rules = new ArrayList<>();
        try (Stream<Path> s = Files.list(COMMUNITY_RULES)) {
            for (Path p : s.filter(f -> f.toString().endsWith(".txt")).sorted().toList())
                rules.addAll(Files.readAllLines(p, StandardCharsets.UTF_8));
        }
        StringBuilder out = new StringBuilder();
        out.append(render(List.of(ScanSettings.ScanTier.FULL), rules, false, "CUSTOM+FULL"));
        out.append(render(List.of(ScanSettings.ScanTier.FULL), rules, true, "CUSTOM-ONLY"));
        compareToGolden(GOLDEN_CUSTOM, out.toString());
    }

    private static void compareToGolden(Path golden, String actual) throws IOException {
        if (Boolean.getBoolean("snapshot.update") || !Files.exists(golden)) {
            Files.createDirectories(golden.getParent());
            Files.writeString(golden, actual, StandardCharsets.UTF_8);
            System.out.println("[SnapshotTest] golden written: " + golden.toAbsolutePath());
            return;
        }

        String expected = Files.readString(golden, StandardCharsets.UTF_8);
        if (!expected.equals(actual)) {
            Path got = golden.resolveSibling(golden.getFileName().toString().replace(".txt", ".actual.txt"));
            Files.writeString(got, actual, StandardCharsets.UTF_8);
            fail("Findings changed. Compare " + golden + " with " + got
                    + " (run with -Dsnapshot.update=true only if the change is intended).\n"
                    + firstDifference(expected, actual));
        }
    }

    /** Scans the corpus at every tier with built-in rules only. */
    static String render() throws IOException {
        StringBuilder out = new StringBuilder();
        for (ScanSettings.ScanTier tier : ScanSettings.ScanTier.values())
            out.append(render(List.of(tier), List.of(), false, null));
        return out.toString();
    }

    /** Scans the corpus and returns one sorted line per finding, prefixed with the tier (or label). */
    static String render(List<ScanSettings.ScanTier> tiers, List<String> customRules,
                         boolean customOnly, String label) throws IOException {
        List<Path> files;
        try (Stream<Path> s = Files.walk(CORPUS)) {
            files = s.filter(Files::isRegularFile)
                     .filter(p -> !p.getFileName().toString().equals("MANIFEST.md"))
                     .sorted(Comparator.comparing(p -> CORPUS.relativize(p).toString()))
                     .toList();
        }

        StringBuilder out = new StringBuilder();
        for (ScanSettings.ScanTier tier : tiers) {
            for (Path file : files) {
                String rel = CORPUS.relativize(file).toString().replace('\\', '/');
                String text = Files.readString(file, StandardCharsets.UTF_8);
                String url = "https://corpus.local/" + rel;

                ScanSettings settings = new ScanSettings();
                settings.setTier(tier);
                settings.setPiiEnabled(true);
                if (!customRules.isEmpty()) {
                    settings.setCustomRules(customRules);
                    settings.setCustomRulesEnabled(true);
                    settings.setCustomRulesOnly(customOnly);
                }
                SecretScanner scanner = new SecretScanner(settings, NOOP_LOG);

                List<String> lines = new ArrayList<>();
                for (SecretFinding f : scanner.scanText(text, contentTypeFor(rel), url)) {
                    lines.add(String.join("\t",
                            label != null ? label : tier.name(), rel,
                            f.ruleId(), f.ruleName(), f.keyName(), f.matchedValue(),
                            f.severity(), f.confidence(),
                            Integer.toString(f.lineNumber()), Integer.toString(f.matchOffset()),
                            f.sourceUrl(), Integer.toHexString(f.context() == null ? 0 : f.context().hashCode())));
                }
                lines.sort(null);
                for (String l : lines) out.append(l.replace("\n", "\\n").replace("\r", "\\r")).append('\n');
            }
        }
        return out.toString();
    }

    private static String contentTypeFor(String rel) {
        if (rel.endsWith(".js"))   return "application/javascript";
        if (rel.endsWith(".json")) return "application/json";
        if (rel.endsWith(".html")) return "text/html";
        if (rel.endsWith(".xml"))  return "application/xml";
        if (rel.endsWith(".css"))  return "text/css";
        return "text/plain";
    }

    private static String firstDifference(String a, String b) {
        String[] x = a.split("\n", -1), y = b.split("\n", -1);
        for (int i = 0; i < Math.min(x.length, y.length); i++) {
            if (!x[i].equals(y[i])) return "First difference at line " + (i + 1)
                    + ":\n  expected: " + x[i] + "\n  actual:   " + y[i];
        }
        return "Line counts differ: expected " + x.length + ", actual " + y.length;
    }
}
