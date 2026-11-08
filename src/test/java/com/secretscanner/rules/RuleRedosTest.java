package com.secretscanner.rules;

import com.secretscanner.Patterns;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.fail;

/**
 * ReDoS check: every built-in rule must finish scanning each hostile input within the budget.
 *
 * Hostile inputs are ~60 KB each: long runs of single characters common in tokens and code,
 * and, per rule, a generated near-match whose tail is stretched with the character that would
 * keep a greedy quantifier running, then broken so the match must fail and backtrack.
 */
@DisplayName("Rule ReDoS safety")
class RuleRedosTest {

    private static final int SIZE = 60_000;
    private static final long BUDGET_MS = 1_500;

    private static final List<String> GENERIC = List.of(
            "a".repeat(SIZE), "A".repeat(SIZE), "0".repeat(SIZE), " ".repeat(SIZE), "-".repeat(SIZE),
            "=".repeat(SIZE), "_".repeat(SIZE), ".".repeat(SIZE), "\n".repeat(SIZE),
            "aA0+/".repeat(SIZE / 5), "a=".repeat(SIZE / 2), "\"a\":".repeat(SIZE / 4),
            "eyJ".repeat(SIZE / 3), "key=".repeat(SIZE / 4), "token: ".repeat(SIZE / 7),
            // two-character runs that alternate a value character with a separator the pattern allows
            "a-".repeat(SIZE / 2), "a.".repeat(SIZE / 2), "a@".repeat(SIZE / 2), "0-".repeat(SIZE / 2),
            "a_".repeat(SIZE / 2), "a1b2c3d4-".repeat(SIZE / 9), "eyJ-".repeat(SIZE / 4));

    private static List<RuleDef> allRules() {
        List<RuleDef> rules = new ArrayList<>(RuleLoader.loadResource(Patterns.ANCHORED_RULES_RESOURCE));
        rules.addAll(RuleLoader.loadResource(Patterns.CONTEXT_RULES_RESOURCE));
        return rules;
    }

    @TestFactory
    Stream<DynamicTest> everyRuleIsLinearEnough() {
        return allRules().stream().map(r -> DynamicTest.dynamicTest("redos: " + r.id(), () -> {
            List<String> inputs = new ArrayList<>(GENERIC);
            // the rule's own keywords, repeated bare and with a separator (keeps the prefix part busy)
            for (String kw : RequiredLiterals.of(r.pattern())) {
                inputs.add(kw.repeat(Math.max(1, SIZE / kw.length())));
                inputs.add((kw + "-").repeat(Math.max(1, SIZE / (kw.length() + 1))));
                inputs.add((kw + "_").repeat(Math.max(1, SIZE / (kw.length() + 1))));
            }
            for (String g : RegexExampleGenerator.generate(r.pattern(), r.id(), 3)) {
                int cut = Math.max(1, g.length() * 2 / 3);
                char stretch = g.charAt(cut - 1);
                inputs.add(g.substring(0, cut) + String.valueOf(stretch).repeat(SIZE) + "\u0000");
                inputs.add((g + "\u0001").repeat(Math.max(1, SIZE / (g.length() + 1))));
            }
            for (String in : inputs) {
                long t0 = System.nanoTime();
                try {
                    Matcher m = r.pattern().matcher(DeadlineCharSequence.of(in, BUDGET_MS));
                    while (m.find()) { /* consume all matches */ }
                } catch (DeadlineCharSequence.RegexTimeoutException e) {
                    fail(r.id() + ": exceeded " + BUDGET_MS + " ms on a " + in.length()
                            + "-char input starting " + preview(in));
                }
                long ms = (System.nanoTime() - t0) / 1_000_000;
                if (ms > BUDGET_MS) fail(r.id() + ": took " + ms + " ms on input starting " + preview(in));
            }
        }));
    }

    private static String preview(String s) {
        String p = s.length() > 40 ? s.substring(0, 40) : s;
        return "\"" + p.replace("\n", "\\n") + "...\"";
    }
}
