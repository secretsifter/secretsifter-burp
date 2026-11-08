package com.secretscanner.core;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Extracts {@code <script>} block bodies from HTML in linear time.
 *
 * Replaces two regexes that went quadratic on malformed HTML (many {@code <script>} tags with
 * no closing tag, or a tag with no {@code >}):
 * <pre>
 *   inline: &lt;script(?![^&gt;]*\bsrc\s*=)[^&gt;]*&gt;([\s\S]*?)&lt;/script&gt;                      (CASE_INSENSITIVE)
 *   json:   &lt;script[^&gt;]+type\s*=\s*["']application/(?:json|ld\+json)["'][^&gt;]*&gt;([\s\S]*?)&lt;/script&gt;
 * </pre>
 * Results are identical to {@code Matcher.find()} over those regexes, group 1. The equivalence
 * rests on two facts: a start with no {@code >} or no later {@code </script>} fails, and so does
 * every later start; and a start nested inside a rejected tag can only succeed if the attribute
 * that rejected the outer tag lies before it.
 */
public final class ScriptBlocks {

    private static final Pattern SRC_ATTR  = Pattern.compile("\\bsrc\\s*=", Pattern.CASE_INSENSITIVE);
    private static final Pattern JSON_TYPE = Pattern.compile(
            "type\\s*=\\s*[\"']application/(?:json|ld\\+json)[\"']", Pattern.CASE_INSENSITIVE);

    private static final String OPEN  = "<script";
    private static final String CLOSE = "</script>";

    private ScriptBlocks() {}

    /** Bodies of inline scripts (no {@code src} attribute), in document order. */
    public static List<String> inline(String html) {
        return extract(html, false);
    }

    /** Bodies of {@code <script type="application/json">} and {@code ld+json} blocks. */
    public static List<String> json(String html) {
        return extract(html, true);
    }

    private static List<String> extract(String html, boolean json) {
        List<String> out = new ArrayList<>();
        if (html == null) return out;
        int from = 0;
        while (true) {
            int start = indexOfAscii(html, OPEN, from);
            if (start < 0) break;
            int tagStart = start + OPEN.length();
            int tagEnd = html.indexOf('>', tagStart);
            if (tagEnd < 0) break;                       // no '>' anywhere after: no later start can match
            if (json) {
                // [^>]+ before "type" needs at least one character
                boolean typed = tagStart + 1 <= tagEnd
                        && JSON_TYPE.matcher(html).region(tagStart + 1, tagEnd).find();
                if (!typed) {
                    // inner starts see a suffix of this tag, which has no type attribute either
                    from = tagEnd + 1;
                    continue;
                }
            } else {
                // transparent bounds: \b must see the character before the tag text, as in the regex
                var sm = SRC_ATTR.matcher(html).region(tagStart, tagEnd).useTransparentBounds(true);
                int lastSrc = -1;
                while (sm.find()) lastSrc = sm.start();
                if (lastSrc >= 0) {
                    // an inner "<script" whose tag text begins after the last src= could still match
                    from = Math.max(start + 1, lastSrc - OPEN.length() + 1);
                    continue;
                }
            }

            int close = indexOfAscii(html, CLOSE, tagEnd + 1);
            if (close < 0) break;                        // no closing tag after this point
            out.add(html.substring(tagEnd + 1, close));
            from = close + CLOSE.length();
        }
        return out;
    }

    /** Index of the next {@code <script} (any case) at or after {@code from}, or -1. */
    public static int indexOfScriptOpen(String s, int from) {
        return indexOfAscii(s, OPEN, from);
    }

    /** Index of the next {@code </script>} (any case) at or after {@code from}, or -1. */
    public static int indexOfScriptClose(String s, int from) {
        return indexOfAscii(s, CLOSE, from);
    }

    /** Case-insensitive (ASCII only, like the regex flag) indexOf for a lowercase needle. */
    static int indexOfAscii(String s, String lowerNeedle, int from) {
        int n = lowerNeedle.length();
        char first = lowerNeedle.charAt(0);
        for (int i = Math.max(0, from), last = s.length() - n; i <= last; i++) {
            if (lower(s.charAt(i)) != first) continue;
            int k = 1;
            while (k < n && lower(s.charAt(i + k)) == lowerNeedle.charAt(k)) k++;
            if (k == n) return i;
        }
        return -1;
    }

    private static char lower(char c) {
        return (c >= 'A' && c <= 'Z') ? (char) (c + 32) : c;
    }
}
