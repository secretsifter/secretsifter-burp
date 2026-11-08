package com.secretscanner.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Pattern;

/**
 * Generates strings that a rule's regex should match, so every rule can be exercised even before
 * it has hand-written examples. Test-only.
 *
 * Supports the subset the rule files use: literals, escapes (\b \d \w \s \S \D \W \n \t \r \xhh
 * \\uhhhh and escaped punctuation), character classes with ranges and negation, '.', groups
 * (capturing, (?:...), (?<name>...)), inline flags such as (?i), lookahead (generates nothing;
 * the result is verified afterwards), alternation, and quantifiers ? * + {n} {n,} {n,m} with lazy
 * or possessive suffixes. Anchors ^ and $ generate nothing.
 *
 * {@link #generate} tries a deterministic attempt first, then seeded random attempts, and returns
 * only strings the compiled pattern actually finds.
 */
final class RegexExampleGenerator {

    /** Characters offered for '.' and negated classes, in preference order. */
    private static final String ALPHABET =
            "aB3cD5eF7gH9jK2mN4pQ6rS8tU1vW0xYzAbCdEfGhJkLmNoPqRsTuVwXyZ"
          + "-_./+=:~!@#$%&*,;?|^`()[]{}<>'\" \t\n\\";

    private final String src;
    private int pos;
    private final Random rnd;
    private final boolean deterministic;
    private int rotor;   // spreads deterministic picks across a class so output has variety

    private RegexExampleGenerator(String src, long seed, boolean deterministic) {
        this.src = src;
        this.rnd = new Random(seed);
        this.deterministic = deterministic;
    }

    /** Returns up to {@code max} distinct strings that {@code pattern} finds, or an empty list. */
    static List<String> generate(Pattern pattern, String seedKey, int max) {
        List<String> out = new ArrayList<>();
        long seed = seedKey.hashCode();
        for (int attempt = 0; attempt < 60 && out.size() < max; attempt++) {
            String s;
            try {
                s = new RegexExampleGenerator(pattern.pattern(), seed + attempt, attempt == 0).alternation();
            } catch (RuntimeException e) {
                continue;
            }
            if (pattern.matcher(s).find() && !out.contains(s)) out.add(s);
        }
        return out;
    }

    // alternation := sequence ('|' sequence)*
    private String alternation() {
        List<String> branches = new ArrayList<>();
        branches.add(sequence());
        while (peek() == '|') {
            pos++;
            branches.add(sequence());
        }
        return deterministic ? branches.get(0) : branches.get(rnd.nextInt(branches.size()));
    }

    // sequence := (atom quantifier?)*
    private String sequence() {
        StringBuilder sb = new StringBuilder();
        while (pos < src.length() && peek() != '|' && peek() != ')') {
            int atomStart = pos;
            String atom = atom();
            int[] q = quantifier();
            if (q == null) {
                sb.append(atom);
                continue;
            }
            int count = chooseCount(q[0], q[1]);
            if (count == 0) continue;
            sb.append(atom);
            for (int i = 1; i < count; i++) {
                int save = pos;
                pos = atomStart;
                sb.append(atom());   // regenerate so repeated classes vary
                pos = save;
            }
        }
        return sb.toString();
    }

    private int chooseCount(int min, int max) {
        int hi = max < 0 ? min + 4 : max;
        if (deterministic) return Math.max(min, Math.min(hi, min == 0 ? 0 : min));
        return min + rnd.nextInt(Math.min(hi - min, 6) + 1);
    }

    private String atom() {
        char c = src.charAt(pos++);
        switch (c) {
            case '^': case '$': return "";
            case '.': return String.valueOf(pick(ALPHABET.substring(0, 58)));
            case '[': return String.valueOf(charClass());
            case '(': return group();
            case '\\': return escape(false);
            default: return String.valueOf(c);
        }
    }

    private String group() {
        boolean lookaround = false;
        if (peek() == '?') {
            pos++;
            char k = src.charAt(pos);
            if (k == ':') {
                pos++;
            } else if (k == '=' || k == '!') {
                pos++;
                lookaround = true;
            } else if (k == '<' && (src.charAt(pos + 1) == '=' || src.charAt(pos + 1) == '!')) {
                pos += 2;
                lookaround = true;
            } else if (k == '<') {
                int end = src.indexOf('>', pos);
                pos = end + 1;                       // named group
            } else {
                // inline flags: (?i) or (?i:...)
                while (pos < src.length() && Character.isLetter(src.charAt(pos)) || src.charAt(pos) == '-') pos++;
                if (src.charAt(pos) == ')') { pos++; return ""; }
                pos++;                               // ':'
            }
        }
        String inner = alternation();
        expect(')');
        return lookaround ? "" : inner;
    }

    private char charClass() {
        boolean negate = false;
        if (peek() == '^') { negate = true; pos++; }
        StringBuilder members = new StringBuilder();
        boolean first = true;
        while (pos < src.length() && (peek() != ']' || first)) {
            first = false;
            char lo;
            String cls = null;
            char c = src.charAt(pos++);
            if (c == '\\') {
                String e = escape(true);
                if (e.length() == 1) lo = e.charAt(0); else { cls = e; lo = 0; }
            } else {
                lo = c;
            }
            if (cls != null) { members.append(cls); continue; }
            if (peek() == '-' && pos + 1 < src.length() && src.charAt(pos + 1) != ']') {
                pos++;
                char hi = src.charAt(pos++);
                if (hi == '\\') hi = escape(true).charAt(0);
                for (char x = lo; x <= hi; x++) members.append(x);
            } else {
                members.append(lo);
            }
        }
        expect(']');
        if (!negate) return pick(members.toString());
        StringBuilder allowed = new StringBuilder();
        for (char a : ALPHABET.toCharArray()) if (members.indexOf(String.valueOf(a)) < 0) allowed.append(a);
        return pick(allowed.toString());
    }

    /** Returns one literal char, or (inside a class) a multi-char set for \d \w \s. */
    private String escape(boolean inClass) {
        char e = src.charAt(pos++);
        switch (e) {
            case 'b': case 'B': return inClass ? "\b" : "";
            case 'd': return inClass ? "0123456789" : String.valueOf(pick("0123456789"));
            case 'w': return inClass ? "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                                     : String.valueOf(pick("aB3cD5eF7gH9_"));
            case 's': return inClass ? " \t\n\r\f" : " ";
            case 'S': return inClass ? "aB3cD5eF7gH9" : String.valueOf(pick("aB3cD5eF7gH9"));
            case 'D': return inClass ? "aBcDeF_-" : String.valueOf(pick("aBcDeF"));
            case 'W': return inClass ? "-./:=+ " : String.valueOf(pick("-./:=+"));
            case 'n': return "\n";
            case 't': return "\t";
            case 'r': return "\r";
            case 'f': return "\f";
            case 'x': { String h = src.substring(pos, pos + 2); pos += 2; return String.valueOf((char) Integer.parseInt(h, 16)); }
            case 'u': { String h = src.substring(pos, pos + 4); pos += 4; return String.valueOf((char) Integer.parseInt(h, 16)); }
            default: return String.valueOf(e);
        }
    }

    private int[] quantifier() {
        if (pos >= src.length()) return null;
        char c = src.charAt(pos);
        int[] q;
        if (c == '?') { pos++; q = new int[]{0, 1}; }
        else if (c == '*') { pos++; q = new int[]{0, -1}; }
        else if (c == '+') { pos++; q = new int[]{1, -1}; }
        else if (c == '{' && pos + 1 < src.length() && Character.isDigit(src.charAt(pos + 1))) {
            int end = src.indexOf('}', pos);
            String[] parts = src.substring(pos + 1, end).split(",", -1);
            int min = Integer.parseInt(parts[0]);
            int max = parts.length == 1 ? min : (parts[1].isEmpty() ? -1 : Integer.parseInt(parts[1]));
            pos = end + 1;
            q = new int[]{min, max};
        } else {
            return null;
        }
        if (pos < src.length() && (src.charAt(pos) == '?' || src.charAt(pos) == '+')) pos++;  // lazy / possessive
        return q;
    }

    private char pick(String set) {
        if (set.isEmpty()) throw new IllegalStateException("empty character set");
        if (deterministic) return set.charAt((rotor++ * 7) % set.length());
        return set.charAt(rnd.nextInt(set.length()));
    }

    private char peek() { return pos < src.length() ? src.charAt(pos) : '\0'; }

    private void expect(char c) {
        if (pos >= src.length() || src.charAt(pos) != c) throw new IllegalStateException("expected '" + c + "' at " + pos);
        pos++;
    }
}
