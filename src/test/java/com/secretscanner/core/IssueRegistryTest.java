package com.secretscanner.core;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Permanent issue IDs")
class IssueRegistryTest {

    private static IssueRegistry.Store mapStore(Map<String, String> m) {
        return new IssueRegistry.Store() {
            public String get(String k) { return m.get(k); }
            public void put(String k, String v) { m.put(k, v); }
        };
    }

    private static final Clock OCT_24_2026 = Clock.fixed(Instant.parse("2026-10-24T15:30:00Z"), ZoneOffset.UTC);
    private static final Clock NOV_02_2026 = Clock.fixed(Instant.parse("2026-11-02T09:00:00Z"), ZoneOffset.UTC);

    @Test void idShapeAndDate() {
        String id = new IssueRegistry(mapStore(new HashMap<>()), OCT_24_2026).idFor("sk_live_aaaa");
        assertTrue(id.matches("SS-102426-[0-9A-HJKMNP-TV-Z]{6}"), id);
    }

    @Test void sameSecretSameIdDifferentSecretDifferentId() {
        IssueRegistry r = new IssueRegistry(mapStore(new HashMap<>()));
        String a = r.idFor("sk_live_aaaa");
        String b = r.idFor("ghp_bbbb");
        assertNotEquals(a, b);
        assertEquals(a, r.idFor("sk_live_aaaa"));
    }

    @Test void secretKeepsTheDateItWasFirstSeen() {
        Map<String, String> m = new HashMap<>();
        String first = new IssueRegistry(mapStore(m), OCT_24_2026).idFor("secret-one");
        String later = new IssueRegistry(mapStore(m), NOV_02_2026).idFor("secret-one");
        assertEquals(first, later);
        assertTrue(new IssueRegistry(mapStore(m), NOV_02_2026).idFor("secret-two").startsWith("SS-110226-"));
    }

    /** The reported bug: two copies of the extension sharing preferences gave different secrets one ID. */
    @Test void twoCopiesSharingPreferencesNeverShareAnId() {
        Map<String, String> m = new ConcurrentHashMap<>();
        IssueRegistry a = new IssueRegistry(mapStore(m), OCT_24_2026);
        IssueRegistry b = new IssueRegistry(mapStore(m), OCT_24_2026);
        Map<String, String> idToValue = new HashMap<>();
        for (int i = 0; i < 2000; i++) {
            String v = "secret-" + i;
            String id = (i % 2 == 0 ? a : b).idFor(v);
            assertEquals(id, (i % 2 == 0 ? b : a).idFor(v), "copies disagree on " + v);
            String prev = idToValue.putIfAbsent(id, v);
            assertNull(prev, id + " given to both " + prev + " and " + v);
        }
    }

    @Test void clashingCodesAreResolved() {
        Map<String, String> m = new HashMap<>();
        IssueRegistry r = new IssueRegistry(mapStore(m), OCT_24_2026);
        String fp = IssueRegistry.fingerprint("victim");
        m.put("ss.iid2.id.SS-102426-" + IssueRegistry.code(fp, 0), "someone-else");   // force a clash
        String id = r.idFor("victim");
        assertEquals("SS-102426-" + IssueRegistry.code(fp, 1), id);
    }

    @Test void idsSurviveRestartAndAreNeverReused() {
        Map<String, String> m = new HashMap<>();
        IssueRegistry first = new IssueRegistry(mapStore(m));
        String a = first.idFor("secret-one");
        String b = first.idFor("secret-two");
        IssueRegistry second = new IssueRegistry(mapStore(m));      // Burp restarted
        assertEquals(a, second.idFor("secret-one"));
        assertEquals(b, second.idFor("secret-two"));
        assertNotEquals(a, second.idFor("secret-three"));
        assertEquals(first.installTag(), second.installTag());
    }

    @Test void storeNeverContainsTheSecret() {
        Map<String, String> m = new HashMap<>();
        new IssueRegistry(mapStore(m)).idFor("AKIAABCDEFGHIJKLMNOP");
        for (Map.Entry<String, String> e : m.entrySet()) {
            assertFalse(e.getKey().contains("AKIA"), e.getKey());
            assertFalse(e.getValue().contains("AKIA"), e.getValue());
        }
    }

    @Test void quotesAndWhitespaceDoNotChangeTheId() {
        IssueRegistry r = new IssueRegistry(mapStore(new HashMap<>()));
        String id = r.idFor("tok_123456");
        assertEquals(id, r.idFor("\"tok_123456\""));
        assertEquals(id, r.idFor("  'tok_123456' "));
        assertNotEquals(id, r.idFor("TOK_123456"));              // case matters for secrets
    }

    @Test void occurrenceRefsAreUniquePerLocationAndStable() {
        IssueRegistry r = new IssueRegistry(mapStore(new HashMap<>()));
        String a = r.occurrenceRef("v1", "https://a/x.js", 3, 120, "R1");
        String b = r.occurrenceRef("v1", "https://a/y.js", 3, 120, "R1");
        assertTrue(a.startsWith(r.idFor("v1") + "@"));
        assertNotEquals(a, b);
        assertEquals(a, r.occurrenceRef("v1", "https://a/x.js", 3, 120, "R1"));
    }

    @Test void concurrentAssignmentGivesOneIdPerSecret() {
        IssueRegistry r = new IssueRegistry(mapStore(new ConcurrentHashMap<>()));
        Map<String, String> seen = new ConcurrentHashMap<>();
        IntStream.range(0, 4000).parallel().forEach(i -> {
            String v = "secret-" + (i % 500);
            String id = r.idFor(v);
            String prev = seen.putIfAbsent(v, id);
            if (prev != null) assertEquals(prev, id);
        });
        Set<String> ids = new HashSet<>(seen.values());
        assertEquals(500, ids.size());
    }

    @Test void installTagShape() {
        assertTrue(new IssueRegistry(mapStore(new HashMap<>())).installTag().matches("[A-Z2-9]{4}"));
    }

    @Test void corruptStateRecovers() {
        Map<String, String> m = new HashMap<>(Map.of(
                "ss.iid.key", "not base64 !!", "ss.iid.tag", "x"));
        IssueRegistry r = new IssueRegistry(mapStore(m), OCT_24_2026);
        m.put("ss.iid2.fp." + IssueRegistry.fingerprint("v"), "garbage");
        assertTrue(r.idFor("v").startsWith("SS-102426-"));
        assertTrue(r.installTag().matches("[A-Z2-9]{4}"));
    }

    @Test void redactionByLength() {
        assertEquals("************", Fingerprints.redact("short-secret"));            // 12
        assertEquals("ab*********yz", Fingerprints.redact("abcdefghijxyz"));          // 13: 2 + 2 shown
        assertEquals("AKIA************MNOP", Fingerprints.redact("AKIAABCDEFGHIJKLMNOP"));
        String emoji = "😀".repeat(14);                                      // 14 code points
        String r = Fingerprints.redact(emoji);
        assertFalse(Character.isHighSurrogate(r.charAt(r.length() - 1)));
        assertTrue(List.of(r.codePoints().toArray()).size() > 0);
    }
}
