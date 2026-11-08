package com.secretscanner.rules;

import com.secretscanner.Patterns;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Per-rule example tests, one dynamic test per built-in rule.
 *
 * 1. Generated: the rule's own regex must produce at least one matching string, and the capture
 *    group the rule reports must be non-empty for it.
 * 2. Hand-written: every `examples` entry in the YAML must match (with a non-empty capture group)
 *    and every `negative_examples` entry must not match. Every `missed_examples` entry (a known
 *    real-world miss) must still miss, so fixing a gap forces it to be promoted to `examples`.
 */
@DisplayName("Rule examples")
class RuleExamplesTest {

    private static List<RuleDef> allRules() {
        List<RuleDef> rules = new ArrayList<>(RuleLoader.loadResource(Patterns.ANCHORED_RULES_RESOURCE));
        rules.addAll(RuleLoader.loadResource(Patterns.CONTEXT_RULES_RESOURCE));
        return rules;
    }

    @TestFactory
    Stream<DynamicTest> generatedExamplesMatch() {
        return allRules().stream().map(r -> DynamicTest.dynamicTest("generated: " + r.id(), () -> {
            List<String> gen = RegexExampleGenerator.generate(r.pattern(), r.id(), 3);
            assertFalse(gen.isEmpty(), r.id() + ": could not generate any matching string");
            for (String s : gen) assertCaptures(r, s, "generated");
        }));
    }

    @TestFactory
    Stream<DynamicTest> handWrittenExamples() {
        return allRules().stream()
                .filter(r -> !r.examples().isEmpty() || !r.negativeExamples().isEmpty() || !r.missedExamples().isEmpty())
                .map(r -> DynamicTest.dynamicTest("hand-written: " + r.id(), () -> {
                    for (String s : r.examples()) assertCaptures(r, s, "example");
                    for (String s : r.negativeExamples()) {
                        assertFalse(r.pattern().matcher(s).find(),
                                r.id() + ": negative example matched: " + s);
                    }
                    for (String s : r.missedExamples()) {
                        assertFalse(r.pattern().matcher(s).find(),
                                r.id() + ": missed example now matches; the gap is fixed, move it to examples: " + s);
                    }
                }));
    }

    private static void assertCaptures(RuleDef r, String s, String what) {
        Matcher m = r.pattern().matcher(s);
        assertTrue(m.find(), r.id() + ": " + what + " did not match: " + s);
        String captured = m.group(r.group());
        assertNotNull(captured, r.id() + ": capture group " + r.group() + " empty for " + what + ": " + s);
        assertFalse(captured.isEmpty(), r.id() + ": capture group " + r.group() + " empty for " + what + ": " + s);
    }
}
