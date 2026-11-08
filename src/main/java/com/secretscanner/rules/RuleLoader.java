package com.secretscanner.rules;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Loads {@link RuleDef}s from YAML rule files.
 *
 * Strict by design: an unknown field, a missing required field, a duplicate id, an unknown
 * severity/kind/flag or an invalid regex is a load error naming the file and rule, so a typo
 * can never silently disable a rule. Uses SnakeYAML's SafeConstructor (no arbitrary types).
 *
 * File format:
 * <pre>
 * version: 1
 * rules:
 *   - id: GITHUB_PAT_001
 *     name: GitHub PAT (Classic)
 *     key: github_pat_classic
 *     kind: anchored            # anchored | context
 *     severity: HIGH
 *     pattern: '\bghp_[A-Za-z0-9]{36}\b'
 *     flags: [CASE_INSENSITIVE] # optional, java.util.regex.Pattern flag names
 *     group: 1                  # optional, default 0 (whole match)
 * </pre>
 */
public final class RuleLoader {

    public static final int SCHEMA_VERSION = 1;

    private static final Set<String> SEVERITIES = Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATION");

    private static final Set<String> ALLOWED_FIELDS = Set.of(
            "id", "name", "key", "kind", "severity", "pattern", "flags", "group",
            "keywords", "examples", "negative_examples", "missed_examples",
            "provider", "source", "license", "cwe", "owasp");

    private static final Map<String, Integer> FLAGS = new LinkedHashMap<>();
    static {
        FLAGS.put("UNIX_LINES",              Pattern.UNIX_LINES);
        FLAGS.put("CASE_INSENSITIVE",        Pattern.CASE_INSENSITIVE);
        FLAGS.put("COMMENTS",                Pattern.COMMENTS);
        FLAGS.put("MULTILINE",               Pattern.MULTILINE);
        FLAGS.put("LITERAL",                 Pattern.LITERAL);
        FLAGS.put("DOTALL",                  Pattern.DOTALL);
        FLAGS.put("UNICODE_CASE",            Pattern.UNICODE_CASE);
        FLAGS.put("CANON_EQ",                Pattern.CANON_EQ);
        FLAGS.put("UNICODE_CHARACTER_CLASS", Pattern.UNICODE_CHARACTER_CLASS);
    }

    private RuleLoader() {}

    /** Loads a rule file from the classpath (e.g. "/rules/builtin-anchored.yaml"). */
    public static List<RuleDef> loadResource(String resourcePath) {
        try (InputStream in = RuleLoader.class.getResourceAsStream(resourcePath)) {
            if (in == null) throw new RuleLoadException(resourcePath + ": rule file not found on classpath");
            return load(new InputStreamReader(in, StandardCharsets.UTF_8), resourcePath);
        } catch (IOException e) {
            throw new RuleLoadException(resourcePath + ": " + e.getMessage(), e);
        }
    }

    /** Parses one rule file. {@code origin} is used only in error messages. */
    public static List<RuleDef> load(Reader reader, String origin) {
        Object root = new Yaml(new SafeConstructor(new LoaderOptions())).load(reader);
        if (!(root instanceof Map<?, ?> doc)) throw new RuleLoadException(origin + ": top level must be a mapping");

        Object version = doc.get("version");
        if (!(version instanceof Integer v) || v != SCHEMA_VERSION)
            throw new RuleLoadException(origin + ": unsupported or missing version (expected " + SCHEMA_VERSION + ")");

        Object rules = doc.get("rules");
        if (!(rules instanceof List<?> list)) throw new RuleLoadException(origin + ": 'rules' must be a list");

        List<RuleDef> out = new ArrayList<>(list.size());
        Set<String> ids = new HashSet<>();
        int index = 0;
        for (Object item : list) {
            index++;
            if (!(item instanceof Map<?, ?> m)) throw new RuleLoadException(origin + ": rule #" + index + " must be a mapping");
            RuleDef rule = parseRule(m, origin, index);
            if (!ids.add(rule.id())) throw new RuleLoadException(origin + ": duplicate rule id " + rule.id());
            out.add(rule);
        }
        return List.copyOf(out);
    }

    private static RuleDef parseRule(Map<?, ?> m, String origin, int index) {
        String where = origin + ": rule #" + index;
        for (Object k : m.keySet()) {
            if (!ALLOWED_FIELDS.contains(String.valueOf(k)))
                throw new RuleLoadException(where + ": unknown field '" + k + "'");
        }

        String id = requireString(m, "id", where);
        where = origin + ": rule " + id;

        String severity = requireString(m, "severity", where);
        if (!SEVERITIES.contains(severity)) throw new RuleLoadException(where + ": unknown severity '" + severity + "'");

        String kindText = requireString(m, "kind", where);
        RuleDef.Kind kind;
        try {
            kind = RuleDef.Kind.valueOf(kindText.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new RuleLoadException(where + ": unknown kind '" + kindText + "'");
        }

        int flags = 0;
        for (String f : optionalStrings(m, "flags", where)) {
            Integer bit = FLAGS.get(f);
            if (bit == null) throw new RuleLoadException(where + ": unknown regex flag '" + f + "'");
            flags |= bit;
        }

        String regex = requireString(m, "pattern", where);
        Pattern pattern;
        try {
            pattern = Pattern.compile(regex, flags);
        } catch (PatternSyntaxException e) {
            throw new RuleLoadException(where + ": invalid regex: " + e.getDescription(), e);
        }

        int group = 0;
        Object g = m.get("group");
        if (g != null) {
            if (!(g instanceof Integer gi) || gi < 0) throw new RuleLoadException(where + ": 'group' must be a non-negative integer");
            group = gi;
        }
        if (group > pattern.matcher("").groupCount())
            throw new RuleLoadException(where + ": group " + group + " exceeds the pattern's " + pattern.matcher("").groupCount() + " groups");

        return new RuleDef(
                id,
                requireString(m, "name", where),
                requireString(m, "key", where),
                kind,
                severity,
                pattern,
                group,
                optionalStrings(m, "keywords", where),
                optionalStrings(m, "examples", where),
                optionalStrings(m, "negative_examples", where),
                optionalStrings(m, "missed_examples", where),
                optionalString(m, "provider", where),
                optionalString(m, "source", where),
                optionalString(m, "license", where),
                optionalString(m, "cwe", where),
                optionalString(m, "owasp", where));
    }

    private static String requireString(Map<?, ?> m, String field, String where) {
        Object v = m.get(field);
        if (!(v instanceof String s) || s.isEmpty())
            throw new RuleLoadException(where + ": missing or non-string '" + field + "'");
        return s;
    }

    private static String optionalString(Map<?, ?> m, String field, String where) {
        Object v = m.get(field);
        if (v == null) return "";
        if (!(v instanceof String s)) throw new RuleLoadException(where + ": '" + field + "' must be a string");
        return s;
    }

    private static List<String> optionalStrings(Map<?, ?> m, String field, String where) {
        Object v = m.get(field);
        if (v == null) return List.of();
        if (!(v instanceof List<?> l)) throw new RuleLoadException(where + ": '" + field + "' must be a list");
        List<String> out = new ArrayList<>(l.size());
        for (Object o : l) {
            if (!(o instanceof String s)) throw new RuleLoadException(where + ": '" + field + "' entries must be strings");
            out.add(s);
        }
        return List.copyOf(out);
    }

    /** Thrown when a rule file is malformed. */
    public static final class RuleLoadException extends RuntimeException {
        public RuleLoadException(String message) { super(message); }
        public RuleLoadException(String message, Throwable cause) { super(message, cause); }
    }

    /** Pattern flag names for a compiled pattern, in a stable order (used by the exporter). */
    public static List<String> flagNames(int flags) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, Integer> e : FLAGS.entrySet()) {
            if ((flags & e.getValue()) != 0) out.add(e.getKey());
        }
        return out;
    }
}
