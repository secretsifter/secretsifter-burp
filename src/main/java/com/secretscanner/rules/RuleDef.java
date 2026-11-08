package com.secretscanner.rules;

import java.util.List;
import java.util.regex.Pattern;

/**
 * One detection rule as declared in a YAML rule file under {@code src/main/resources/rules/}.
 *
 * Phase 1 carries the fields the built-in rules already use, plus optional metadata fields that
 * later phases fill in (examples, keywords, provenance, tags). Optional fields default to empty.
 * Has no Burp dependency so it can move into the core module unchanged.
 */
public record RuleDef(
        String       id,           // stable rule id, e.g. GITHUB_PAT_001
        String       name,         // human-readable rule name
        String       key,          // key name reported on findings, e.g. github_pat_classic
        Kind         kind,         // ANCHORED (format-anchored token) or CONTEXT (keyword-gated)
        String       severity,     // CRITICAL, HIGH, MEDIUM, LOW, INFORMATION
        Pattern      pattern,      // compiled regex (pattern text + flags from the file)
        int          group,        // capture group holding the secret; 0 = whole match
        List<String> keywords,     // literal keywords for prefiltering (optional)
        List<String> examples,     // strings the rule must match (optional)
        List<String> negativeExamples, // strings the rule must not match (optional)
        List<String> missedExamples,   // real-world strings the rule should match but does not yet;
                                       // tests assert they still miss, so a fix is noticed (optional)
        String       provider,     // vendor / service (optional)
        String       source,       // provenance: "secretsifter" or upstream repo@commit (optional)
        String       license,      // licence of the source rule (optional)
        String       cwe,          // e.g. CWE-798 (optional)
        String       owasp         // e.g. A07:2025 (optional)
) {
    public enum Kind { ANCHORED, CONTEXT }
}
