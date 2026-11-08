package com.secretscanner;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Real front-end library bundles (src/test/resources/noise-corpus, see its README) contain no
 * secrets, so any finding above INFORMATION in them is a false positive. One test per bundle.
 */
@DisplayName("Noise corpus: library bundles report nothing")
class NoiseCorpusTest {

    @TestFactory
    Stream<DynamicTest> libraryBundlesReportNoSecrets() throws Exception {
        Path dir = corpusDir();
        List<Path> files;
        try (Stream<Path> s = Files.list(dir)) {
            files = s.filter(p -> p.toString().endsWith(".js") || p.toString().endsWith(".mjs")).sorted().collect(Collectors.toList());
        }
        assertFalse(files.isEmpty(), "noise corpus is empty: " + dir);
        return files.stream().map(f -> DynamicTest.dynamicTest(f.getFileName().toString(), () -> {
            ScanSettings s = new ScanSettings();
            s.setTier(ScanSettings.ScanTier.FULL);
            String body = Files.readString(f);
            List<SecretFinding> noise = new SecretScanner(s, null)
                    .scanText(body, "application/javascript", "http://127.0.0.1:5173/" + f.getFileName() + " [JS]")
                    .stream().filter(x -> !"INFORMATION".equals(x.severity())).collect(Collectors.toList());
            assertTrue(noise.isEmpty(), () -> f.getFileName() + " reported " + noise.size() + ": " + noise.stream()
                    .limit(10).map(x -> x.ruleId() + " " + x.keyName() + "=" + x.matchedValue())
                    .collect(Collectors.joining("; ")));
        }));
    }

    private static Path corpusDir() throws URISyntaxException {
        var url = NoiseCorpusTest.class.getResource("/noise-corpus");
        assertNotNull(url, "noise-corpus resource directory missing");
        return Path.of(url.toURI());
    }
}
