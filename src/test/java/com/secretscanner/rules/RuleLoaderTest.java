package com.secretscanner.rules;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** The loader must reject every malformed rule file loudly instead of skipping rules. */
@DisplayName("RuleLoader strictness")
class RuleLoaderTest {

    private static List<RuleDef> load(String yaml) {
        return RuleLoader.load(new StringReader(yaml), "test.yaml");
    }

    private static String rule(String extra) {
        return "version: 1\nrules:\n"
             + "  - id: 'T_001'\n    name: 'Test'\n    key: 'test_key'\n    kind: anchored\n"
             + "    severity: HIGH\n    pattern: '\\bab(c)\\b'\n" + extra;
    }

    @Test void validRuleLoads() {
        RuleDef r = load(rule("    group: 1\n    flags: [CASE_INSENSITIVE]\n    examples: ['abc']\n")).get(0);
        assertEquals("T_001", r.id());
        assertEquals(RuleDef.Kind.ANCHORED, r.kind());
        assertEquals(1, r.group());
        assertTrue(r.pattern().matcher("ABC").find());
        assertEquals(List.of("abc"), r.examples());
    }

    @Test void unknownFieldRejected()    { assertThrows(RuleLoader.RuleLoadException.class, () -> load(rule("    severty: HIGH\n"))); }
    @Test void unknownFlagRejected()     { assertThrows(RuleLoader.RuleLoadException.class, () -> load(rule("    flags: [IGNORECASE]\n"))); }
    @Test void groupOutOfRangeRejected() { assertThrows(RuleLoader.RuleLoadException.class, () -> load(rule("    group: 2\n"))); }

    @Test void badSeverityRejected() {
        assertThrows(RuleLoader.RuleLoadException.class, () -> load(rule("").replace("severity: HIGH", "severity: SEVERE")));
    }

    @Test void badRegexRejected() {
        assertThrows(RuleLoader.RuleLoadException.class, () -> load(rule("").replace("'\\bab(c)\\b'", "'ab(c'")));
    }

    @Test void missingFieldRejected() {
        assertThrows(RuleLoader.RuleLoadException.class, () -> load(rule("").replace("    key: 'test_key'\n", "")));
    }

    @Test void duplicateIdRejected() {
        String twice = rule("") + "  - id: 'T_001'\n    name: 'Dup'\n    key: 'k'\n    kind: anchored\n"
                     + "    severity: LOW\n    pattern: 'x'\n";
        assertThrows(RuleLoader.RuleLoadException.class, () -> load(twice));
    }

    @Test void wrongVersionRejected() {
        assertThrows(RuleLoader.RuleLoadException.class, () -> load(rule("").replace("version: 1", "version: 2")));
    }
}
