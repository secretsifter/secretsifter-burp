package com.secretscanner.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ScriptBlocks: linear extractor matches the old regexes")
class ScriptBlocksTest {

    private static final Pattern OLD_INLINE = Pattern.compile(
            "<script(?![^>]*\\bsrc\\s*=)[^>]*>([\\s\\S]*?)</script>", Pattern.CASE_INSENSITIVE);
    private static final Pattern OLD_JSON = Pattern.compile(
            "<script[^>]+type\\s*=\\s*[\"']application/(?:json|ld\\+json)[\"'][^>]*>([\\s\\S]*?)</script>",
            Pattern.CASE_INSENSITIVE);

    private static List<String> old(Pattern p, String s) {
        List<String> out = new ArrayList<>();
        Matcher m = p.matcher(s);
        while (m.find()) out.add(m.group(1));
        return out;
    }

    @Test void typicalPage() {
        String html = "<html><SCRIPT src=\"a.js\"></script><script>var a=1;</script>"
                + "<script type=\"application/json\" id=\"__NEXT_DATA__\">{\"k\":1}</script>"
                + "<script type='application/ld+json'>{}</Script><script async>x</SCRIPT>";
        assertEquals(old(OLD_INLINE, html), ScriptBlocks.inline(html));
        assertEquals(old(OLD_JSON, html), ScriptBlocks.json(html));
        assertEquals(4, ScriptBlocks.inline(html).size());
        assertEquals(2, ScriptBlocks.json(html).size());
    }

    @Test void nestedStartsInsideRejectedTag() {
        for (String html : List.of(
                "<script src=a <script>body</script>",
                "<script <script src=x>b</script>",
                "<script src=a <script src=b <script>c</script><script>d</script>",
                "<scriptsrc=x>e</script>",
                "<script datasrc=x>f</script>",
                "<scripttype=\"application/json\">{}</script>",
                "<script x type=\"application/json\" <script type='application/json'>{}</script>")) {
            assertEquals(old(OLD_INLINE, html), ScriptBlocks.inline(html), html);
            assertEquals(old(OLD_JSON, html), ScriptBlocks.json(html), html);
        }
    }

    @Test void randomizedAgainstRegex() {
        String[] parts = {"<script", "<SCRIPT", ">", "</script>", "</ScRiPt>", " src=", "src =", " type=\"application/json\"",
                " type='application/ld+json'", "x", " ", "\n", "datasrc=", "<", "/", "\"", "'"};
        Random rnd = new Random(7);
        for (int t = 0; t < 20000; t++) {
            StringBuilder sb = new StringBuilder();
            int n = rnd.nextInt(14);
            for (int i = 0; i < n; i++) sb.append(parts[rnd.nextInt(parts.length)]);
            String s = sb.toString();
            assertEquals(old(OLD_INLINE, s), ScriptBlocks.inline(s), s);
            assertEquals(old(OLD_JSON, s), ScriptBlocks.json(s), s);
        }
    }

    @Test void malformedInputIsFast() {
        String unclosed = "<html>" + "<script>".repeat(70_000);          // ~560 KB
        String noGt = "<script".repeat(80_000) + "</script>";
        String srcChain = "<script src= ".repeat(40_000) + ">";
        long t0 = System.nanoTime();
        assertTrue(ScriptBlocks.inline(unclosed).isEmpty());
        assertTrue(ScriptBlocks.json(unclosed).isEmpty());
        ScriptBlocks.inline(noGt);
        ScriptBlocks.json(noGt);
        ScriptBlocks.inline(srcChain);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue(ms < 1500, "took " + ms + " ms");
    }
}
