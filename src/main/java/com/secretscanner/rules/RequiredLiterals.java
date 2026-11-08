package com.secretscanner.rules;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Derives prefilter keywords from a regex: a set of lowercase literals such that every possible
 * match contains at least one of them. If no such set of useful length exists, returns an empty
 * list and the rule must always run.
 *
 * Soundness argument, per construct:
 * <ul>
 *   <li>a literal character must appear in the match;</li>
 *   <li>a sequence's matches contain every element's required strings, so any one element's
 *       OR-set is valid for the whole sequence (the strongest one is kept), and adjacent exact
 *       pieces are joined into longer literals;</li>
 *   <li>an alternation's matches come from one branch, so the union of the branches' OR-sets is
 *       valid only if every branch has one;</li>
 *   <li>a quantifier with minimum 0 guarantees nothing; with minimum &ge; 1 it keeps its child's set;</li>
 *   <li>lookarounds, anchors and \b consume nothing and guarantee nothing.</li>
 * </ul>
 * Literals are lowercased and matched against lowercased text, which is sound for both
 * case-sensitive and case-insensitive patterns (it can only run a rule more often, never less).
 */
public final class RequiredLiterals {

    /** Shortest keyword worth using; shorter ones would hit almost every response. */
    public static final int MIN_KEYWORD_LENGTH = 3;

    private static final int MAX_EXACT = 16;   // cap on the size of exact-string sets

    private final String src;
    private int pos;

    private RequiredLiterals(String src) { this.src = src; }

    /**
     * Keywords for a compiled pattern, honouring its flags. Patterns whose flags change how
     * literals are read (COMMENTS, LITERAL, UNICODE_CASE, CANON_EQ) get no keywords and always run.
     */
    public static List<String> of(java.util.regex.Pattern pattern) {
        int unsafe = java.util.regex.Pattern.COMMENTS | java.util.regex.Pattern.LITERAL
                   | java.util.regex.Pattern.UNICODE_CASE | java.util.regex.Pattern.CANON_EQ;
        if ((pattern.flags() & unsafe) != 0) return List.of();
        return of(pattern.pattern());
    }

    /** Keywords for {@code regex}, or an empty list if none can be guaranteed. */
    public static List<String> of(String regex) {
        Info info;
        try {
            RequiredLiterals p = new RequiredLiterals(regex);
            info = p.alternation();
            if (p.pos != regex.length()) return List.of();
        } catch (RuntimeException e) {
            return List.of();   // unsupported syntax: be safe, always run the rule
        }
        Set<String> best = info.bestRequired();
        if (best == null || minLen(best) < MIN_KEYWORD_LENGTH) return List.of();
        return List.copyOf(minimize(best));
    }

    // ---------------------------------------------------------------------------------------
    // Info: what a sub-pattern guarantees.
    //   exact    = the complete set of strings it can match (null if unknown or too large)
    //   required = an OR-set: every match contains at least one of these (null if none)
    // ---------------------------------------------------------------------------------------

    private record Info(Set<String> exact, Set<String> required) {
        static Info nothing() { return new Info(Set.of(""), null); }   // consumes nothing
        static Info unknown() { return new Info(null, null); }

        Set<String> bestRequired() {
            Set<String> fromExact = (exact != null && minLen(exact) > 0) ? exact : null;
            return stronger(required, fromExact);
        }
    }

    private Info alternation() {
        List<Info> branches = new ArrayList<>();
        branches.add(sequence());
        while (peek() == '|') { pos++; branches.add(sequence()); }
        if (branches.size() == 1) return branches.get(0);

        Set<String> exact = new LinkedHashSet<>();
        for (Info b : branches) {
            if (b.exact() == null) { exact = null; break; }
            exact.addAll(b.exact());
        }
        if (exact != null && exact.size() > MAX_EXACT) exact = null;

        Set<String> required = new LinkedHashSet<>();
        for (Info b : branches) {
            Set<String> r = b.bestRequired();
            if (r == null) { required = null; break; }
            required.addAll(r);
        }
        return new Info(exact, required);
    }

    private Info sequence() {
        Set<String> run = Set.of("");   // exact strings of the current run of adjacent exact atoms
        Set<String> best = null;        // strongest OR-set seen so far
        boolean allExact = true;        // whole sequence so far is one exact run
        while (pos < src.length() && peek() != '|' && peek() != ')') {
            Info a = quantified(atom());
            if (a.exact() != null) {
                Set<String> joined = cross(run, a.exact());
                if (joined != null) { run = joined; continue; }
                best = stronger(best, nonEmpty(run));   // run too large to extend: close it
                run = a.exact();
                allExact = false;
            } else {
                best = stronger(best, nonEmpty(run));   // non-exact atom ends the run
                best = stronger(best, a.required());
                run = Set.of("");
                allExact = false;
            }
        }
        best = stronger(best, nonEmpty(run));
        return new Info(allExact ? run : null, best);
    }

    private static Set<String> nonEmpty(Set<String> s) {
        return minLen(s) > 0 ? s : null;
    }

    private Info quantified(Info atom) {
        if (pos >= src.length()) return atom;
        char c = src.charAt(pos);
        int min, max;
        if (c == '?') { pos++; min = 0; max = 1; }
        else if (c == '*') { pos++; min = 0; max = -1; }
        else if (c == '+') { pos++; min = 1; max = -1; }
        else if (c == '{' && pos + 1 < src.length() && Character.isDigit(src.charAt(pos + 1))) {
            int end = src.indexOf('}', pos);
            String[] parts = src.substring(pos + 1, end).split(",", -1);
            min = Integer.parseInt(parts[0]);
            max = parts.length == 1 ? min : (parts[1].isEmpty() ? -1 : Integer.parseInt(parts[1]));
            pos = end + 1;
        } else {
            return atom;
        }
        if (pos < src.length() && (src.charAt(pos) == '?' || src.charAt(pos) == '+')) pos++;
        if (min == 0) {
            // guarantees nothing; if it can repeat at most once, it is "" or one of the atom's strings
            if (max == 1 && atom.exact() != null && atom.exact().size() < MAX_EXACT) {
                Set<String> opt = new LinkedHashSet<>(atom.exact());
                opt.add("");
                return new Info(opt, null);
            }
            return Info.unknown();
        }
        if (min == max && atom.exact() != null) {
            Set<String> rep = Set.of("");
            for (int i = 0; i < min && rep != null; i++) rep = cross(rep, atom.exact());
            if (rep != null) return new Info(rep, atom.required());
        }
        return new Info(null, atom.bestRequired());
    }

    private Info atom() {
        char c = src.charAt(pos++);
        switch (c) {
            case '^': case '$': return Info.nothing();
            case '.': return Info.unknown();
            case '[': return charClass();
            case '(': return group();
            case '\\': return escape();
            default: return literal(c);
        }
    }

    private Info literal(char c) {
        return new Info(Set.of(String.valueOf(c).toLowerCase(Locale.ROOT)), null);
    }

    private Info group() {
        boolean lookaround = false;
        if (peek() == '?') {
            pos++;
            char k = src.charAt(pos);
            if (k == ':') pos++;
            else if (k == '=' || k == '!') { pos++; lookaround = true; }
            else if (k == '<' && (src.charAt(pos + 1) == '=' || src.charAt(pos + 1) == '!')) { pos += 2; lookaround = true; }
            else if (k == '<') { pos = src.indexOf('>', pos) + 1; }
            else {
                int flagsStart = pos;
                while (pos < src.length() && (Character.isLetter(src.charAt(pos)) || src.charAt(pos) == '-')) pos++;
                String flags = src.substring(flagsStart, pos);
                // x (comments: whitespace is not literal) and u (Unicode case folding) change
                // what a literal matches; give up rather than risk an unsound keyword
                if (flags.indexOf('x') >= 0 || flags.indexOf('u') >= 0) throw new IllegalStateException("unsafe inline flag");
                if (src.charAt(pos) == ')') { pos++; return Info.nothing(); }   // inline flags (?i)
                pos++;                                                          // (?i:...)
            }
        }
        Info inner = alternation();
        expect(')');
        return lookaround ? Info.nothing() : inner;
    }

    private Info charClass() {
        boolean negate = peek() == '^';
        if (negate) pos++;
        Set<String> members = new LinkedHashSet<>();
        boolean first = true, wide = false;
        while (pos < src.length() && (peek() != ']' || first)) {
            first = false;
            char lo = src.charAt(pos++);
            if (lo == '\\') {
                char e = src.charAt(pos++);
                // only \n \t \r \f and escaped punctuation are known literals; any other letter or
                // digit escape (d w s p h v x c 0, unicode escapes ...) is treated as "any character"
                if (Character.isLetterOrDigit(e) && "ntrf".indexOf(e) < 0) {
                    if ((e == 'p' || e == 'P') && peek() == '{') pos = src.indexOf('}', pos) + 1;
                    wide = true;
                    continue;
                }
                lo = unescape(e);
            }
            if (peek() == '-' && pos + 1 < src.length() && src.charAt(pos + 1) != ']') {
                pos++;
                char hi = src.charAt(pos++);
                if (hi == '\\') hi = unescape(src.charAt(pos++));
                if (hi - lo > 4) wide = true;
                else for (char x = lo; x <= hi; x++) members.add(String.valueOf(x).toLowerCase(Locale.ROOT));
            } else {
                members.add(String.valueOf(lo).toLowerCase(Locale.ROOT));
            }
        }
        expect(']');
        if (negate || wide || members.size() > 4) return Info.unknown();
        return new Info(members, null);
    }

    private Info escape() {
        char e = src.charAt(pos++);
        switch (e) {
            case 'b': case 'B': case 'A': case 'z': case 'Z': case 'G': return Info.nothing();
            case 'd': case 'D': case 'w': case 'W': case 's': case 'S': case 'p': case 'P': case 'h': case 'R':
                if ((e == 'p' || e == 'P') && peek() == '{') pos = src.indexOf('}', pos) + 1;
                return Info.unknown();
            case 'x': { String h = src.substring(pos, pos + 2); pos += 2; return literal((char) Integer.parseInt(h, 16)); }
            case 'u': { String h = src.substring(pos, pos + 4); pos += 4; return literal((char) Integer.parseInt(h, 16)); }
            case 'n': case 't': case 'r': case 'f': return literal(unescape(e));
            default:
                // any other letter or digit escape (\Q \E \k \c \e \a \v \V \H \N \X \0 \1 ...) has
                // special meaning; only escaped punctuation is a plain literal
                if (Character.isLetterOrDigit(e)) throw new IllegalStateException("unsupported escape \\" + e);
                return literal(e);
        }
    }

    private static char unescape(char e) {
        switch (e) {
            case 'n': return '\n';
            case 't': return '\t';
            case 'r': return '\r';
            case 'f': return '\f';
            default: return e;
        }
    }

    private char peek() { return pos < src.length() ? src.charAt(pos) : '\0'; }

    private void expect(char c) {
        if (pos >= src.length() || src.charAt(pos) != c) throw new IllegalStateException("expected " + c);
        pos++;
    }

    // ---------------------------------------------------------------------------------------

    private static Set<String> cross(Set<String> a, Set<String> b) {
        if ((long) a.size() * b.size() > MAX_EXACT) return null;
        Set<String> out = new LinkedHashSet<>();
        for (String x : a) for (String y : b) out.add(x + y);
        return out;
    }

    private static int minLen(Set<String> s) {
        int m = Integer.MAX_VALUE;
        for (String x : s) m = Math.min(m, x.length());
        return s.isEmpty() ? 0 : m;
    }

    /** The more selective OR-set: longer shortest member, then fewer members. */
    private static Set<String> stronger(Set<String> a, Set<String> b) {
        if (a == null) return b;
        if (b == null) return a;
        int la = minLen(a), lb = minLen(b);
        if (la != lb) return la > lb ? a : b;
        return a.size() <= b.size() ? a : b;
    }

    /** Drops members that contain another member (the shorter one is always found first). */
    private static Set<String> minimize(Set<String> s) {
        Set<String> out = new LinkedHashSet<>();
        for (String x : s) {
            boolean redundant = false;
            for (String y : s) if (!y.equals(x) && x.contains(y)) { redundant = true; break; }
            if (!redundant) out.add(x);
        }
        return out;
    }
}
