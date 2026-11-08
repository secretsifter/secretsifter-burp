package com.secretscanner.rules;

import com.secretscanner.Patterns;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.Locale;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Keyword prefilter")
class KeywordPrefilterTest {

    @Nested @DisplayName("Aho-Corasick matcher")
    class Matcher {

        @Test void findsOverlappingAndNestedKeywords() {
            KeywordPrefilter p = new KeywordPrefilter(List.of(
                    List.of("he"), List.of("she"), List.of("his", "hers"), List.of("xyz")));
            BitSet hit = p.candidates("ushers");
            assertTrue(hit.get(0));    // "he" inside "ushers"
            assertTrue(hit.get(1));    // "she"
            assertTrue(hit.get(2));    // "hers"
            assertFalse(hit.get(3));
        }

        @Test void caseInsensitive() {
            KeywordPrefilter p = new KeywordPrefilter(List.of(List.of("akia")));
            assertTrue(p.candidates("id=AKIAABCDEFGHIJKLMNOP").get(0));
        }

        @Test void emptyAndNonAsciiKeywordRulesAlwaysRun() {
            KeywordPrefilter p = new KeywordPrefilter(List.of(List.of(), List.of("café"), List.of("zzz")));
            BitSet hit = p.candidates("nothing here");
            assertTrue(hit.get(0));
            assertTrue(hit.get(1));
            assertFalse(hit.get(2));
        }

        @Test void nonAsciiInputDoesNotBreakMatching() {
            KeywordPrefilter p = new KeywordPrefilter(List.of(List.of("ghp_")));
            assertTrue(p.candidates("über ünïcödé ghp_x").get(0));
            assertFalse(p.candidates("ghép_x").get(0));
        }

        @Test void agreesWithNaiveContainsOnRandomText() {
            Random rnd = new Random(42);
            String alphabet = "abcAB_-.:0";
            List<List<String>> kws = new ArrayList<>();
            for (int r = 0; r < 40; r++) {
                List<String> k = new ArrayList<>();
                for (int j = 0; j < 1 + rnd.nextInt(3); j++) k.add(random(rnd, alphabet, 2 + rnd.nextInt(4)).toLowerCase(Locale.ROOT));
                kws.add(k);
            }
            KeywordPrefilter p = new KeywordPrefilter(kws);
            for (int t = 0; t < 2000; t++) {
                String text = random(rnd, alphabet, rnd.nextInt(60));
                BitSet hit = p.candidates(text);
                String low = text.toLowerCase(Locale.ROOT);
                for (int r = 0; r < kws.size(); r++) {
                    boolean expected = kws.get(r).stream().anyMatch(low::contains);
                    assertEquals(expected, hit.get(r), "rule " + r + " " + kws.get(r) + " on \"" + text + "\"");
                }
            }
        }

        private String random(Random rnd, String alphabet, int n) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < n; i++) sb.append(alphabet.charAt(rnd.nextInt(alphabet.length())));
            return sb.toString();
        }
    }

    @Nested @DisplayName("Required-literal analyzer")
    class Analyzer {
        @Test void literalPrefix()       { assertEquals(List.of("ghp_"), RequiredLiterals.of("\\bghp_[A-Za-z0-9]{36}\\b")); }
        @Test void alternationUnion()    { assertEquals(List.of("akia", "asia"), RequiredLiterals.of("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b")); }
        @Test void optionalJoins()       { assertEquals(List.of("aws_secret", "aws-secret", "awssecret"), RequiredLiterals.of("(?i)aws[_\\-]?secret")); }
        @Test void optionalAloneGivesNothing() { assertEquals(List.of(), RequiredLiterals.of("(?:ghp_)?[A-Za-z0-9]{36}")); }
        @Test void branchWithoutLiteralGivesNothing() { assertEquals(List.of(), RequiredLiterals.of("ghp_x|[0-9]+")); }
        @Test void tooShortGivesNothing() { assertEquals(List.of(), RequiredLiterals.of("\\b(?:AC|SK)[a-f0-9]{32}\\b")); }
        @Test void lookaroundIgnored()   { assertEquals(List.of("mfa."), RequiredLiterals.of("(?=\\S*[a-z])mfa\\.[A-Za-z0-9]{20,}")); }
        @Test void backreferenceIsSafe() { assertEquals(List.of(), RequiredLiterals.of("(abc)\\1")); }
        @Test void keepsStrongestFactor() { assertEquals(List.of("sk-ant-api"), RequiredLiterals.of("\\bsk-ant-api\\d{2}-[A-Za-z0-9\\-_]{93,}\\b")); }

        // Constructs whose literal text does not mean what it looks like: must give no keywords.
        @Test void controlEscapeIsNotLiteral()  { assertEquals(List.of(), RequiredLiterals.of("abc\\cJdef")); }
        @Test void bellEscapeIsNotLiteral()     { assertEquals(List.of(), RequiredLiterals.of("key\\aval")); }
        @Test void quotedSectionGivesNothing()  { assertEquals(List.of(), RequiredLiterals.of("\\Qa.b\\E")); }
        @Test void namedBackrefGivesNothing()   { assertEquals(List.of(), RequiredLiterals.of("(?<k>abc)\\k<k>")); }
        @Test void commentsModeGivesNothing()   { assertEquals(List.of(), RequiredLiterals.of("(?x) a b c d")); }
        @Test void unicodeCaseGivesNothing()    { assertEquals(List.of(), RequiredLiterals.of("(?iu)secret")); }
        @Test void flagsOnCompiledPattern() {
            assertEquals(List.of(), RequiredLiterals.of(java.util.regex.Pattern.compile("a b c", java.util.regex.Pattern.COMMENTS)));
            assertEquals(List.of(), RequiredLiterals.of(java.util.regex.Pattern.compile("secret", java.util.regex.Pattern.CASE_INSENSITIVE | java.util.regex.Pattern.UNICODE_CASE)));
            assertEquals(List.of("secret"), RequiredLiterals.of(java.util.regex.Pattern.compile("secret", java.util.regex.Pattern.CASE_INSENSITIVE)));
        }
        @Test void escapeInClassIsWide() {
            // [\h] is any horizontal whitespace, not the letter h: the class must not become a literal
            assertEquals(List.of("abc"), RequiredLiterals.of("abc[\\h]"));
        }
        @Test void escapedPunctuationIsLiteral() { assertEquals(List.of("a.b-c"), RequiredLiterals.of("a\\.b\\-c")); }

        /** Every community custom rule: wherever the analyzer gives keywords, they must be sound. */
        @Test void soundOnCommunityRules() throws Exception {
            for (java.nio.file.Path p : List.of(java.nio.file.Paths.get("community-rules/community-rules-standard.txt"),
                                                java.nio.file.Paths.get("community-rules/community-rules-extended.txt"))) {
                for (String line : java.nio.file.Files.readAllLines(p)) {
                    if (line.isBlank() || line.startsWith("#")) continue;
                    String[] parts = line.split(" \\| ", 3);
                    if (parts.length < 3) continue;
                    java.util.regex.Pattern pat;
                    try { pat = java.util.regex.Pattern.compile(parts[1].trim()); } catch (Exception e) { continue; }
                    List<String> kws = RequiredLiterals.of(pat);
                    KeywordPrefilter pf = new KeywordPrefilter(List.of(kws));
                    for (int seed = 0; seed < 30; seed++) {
                        for (String s : RegexExampleGenerator.generate(pat, parts[0] + "#" + seed, 1)) {
                            assertTrue(pf.candidates(s).get(0), parts[0] + ": keywords " + kws + " miss matching string " + s);
                        }
                    }
                }
            }
        }
    }

    /**
     * Soundness: for every built-in rule, every string the rule matches in our example sets must
     * make the prefilter report that rule. A failure here means the prefilter would hide a match.
     */
    @TestFactory
    Stream<DynamicTest> prefilterNeverHidesAMatch() {
        List<Object[]> cases = new ArrayList<>();
        List<Patterns.AnchoredRule> anchored = Patterns.ANCHORED_RULES;
        List<Patterns.CtxRule> context = Patterns.CONTEXT_GATED_RULES;
        List<RuleDef> anchoredDefs = RuleLoader.loadResource(Patterns.ANCHORED_RULES_RESOURCE);
        List<RuleDef> contextDefs = RuleLoader.loadResource(Patterns.CONTEXT_RULES_RESOURCE);
        for (int i = 0; i < anchored.size(); i++) cases.add(new Object[]{anchoredDefs.get(i), Patterns.ANCHORED_PREFILTER, i});
        for (int i = 0; i < context.size(); i++)  cases.add(new Object[]{contextDefs.get(i), Patterns.CONTEXT_PREFILTER, i});

        return cases.stream().map(c -> {
            RuleDef r = (RuleDef) c[0];
            KeywordPrefilter p = (KeywordPrefilter) c[1];
            int index = (int) c[2];
            return DynamicTest.dynamicTest("sound: " + r.id(), () -> {
                List<String> samples = new ArrayList<>(r.examples());
                samples.addAll(r.missedExamples());
                samples.addAll(RegexExampleGenerator.generate(r.pattern(), r.id(), 10));
                for (int seed = 0; seed < 40; seed++)
                    samples.addAll(RegexExampleGenerator.generate(r.pattern(), r.id() + "#" + seed, 1));
                for (String s : samples) {
                    if (!r.pattern().matcher(s).find()) continue;   // only strings the rule actually matches
                    assertTrue(p.candidates(s).get(index),
                            r.id() + ": prefilter skipped a string the rule matches: " + s);
                }
            });
        });
    }
}
