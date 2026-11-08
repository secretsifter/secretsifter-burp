package com.secretscanner.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Permanent, unique issue IDs for secrets: {@code SS-102426-7K4M2Q}.
 *
 * Format: {@code SS-MMDDYY-XXXXXX}. MMDDYY is the date the secret was first seen; XXXXXX is six
 * Crockford base32 characters (no I, L, O, U) derived from the secret's HMAC fingerprint (see
 * {@link Fingerprints}). The same secret found again in a later scan, on another page or another
 * target, keeps the ID it got first. The stored state never contains a secret.
 *
 * There is no counter. Earlier versions numbered secrets SS-000001, SS-000002, ... from a counter
 * read once at load; two copies of the extension sharing the preferences (both editions loaded, or
 * a reload while the old copy was still scanning) each counted from the same number and gave the
 * same ID to different secrets. A fingerprint-derived code needs no coordination: every copy computes
 * the same ID for the same secret. A clash between two secrets' codes on the same day (about 1 in
 * 10^9 per pair) is detected and resolved by deriving the next code.
 *
 * State lives in a small key/value {@link Store} (Burp preferences in the extension, a map in tests):
 * the HMAC key, a short random installation tag, and per secret its ID (fingerprint -> ID) and the
 * reverse entry used to detect clashes (ID -> fingerprint).
 * The installation tag tells reports from different machines apart; exported fingerprints let the
 * same secret be matched across machines.
 *
 * Has no Burp dependency.
 */
public final class IssueRegistry {

    /** Minimal persistent string store. */
    public interface Store {
        String get(String key);
        void put(String key, String value);
    }

    static final String KEY_HMAC = "ss.iid.key";
    static final String KEY_TAG  = "ss.iid.tag";
    static final String KEY_FP   = "ss.iid2.fp.";   // fingerprint -> issue ID
    static final String KEY_ID   = "ss.iid2.id.";   // issue ID -> fingerprint (clash detection)

    private static final char[] TAG_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();
    private static final char[] CROCKFORD    = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toCharArray();
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("MMddyy");
    private static final java.util.regex.Pattern ID_SHAPE =
            java.util.regex.Pattern.compile("SS-\\d{6}-[0-9A-HJKMNP-TV-Z]{6}");

    private static volatile IssueRegistry current = inMemory();

    private final Store store;
    private final byte[] hmacKey;
    private final String installTag;
    private final Map<String, String> cache = new ConcurrentHashMap<>();
    private final Clock clock;

    public IssueRegistry(Store store) {
        this(store, Clock.systemDefaultZone());
    }

    public IssueRegistry(Store store, Clock clock) {
        this.store = store;
        this.clock = clock;
        byte[] key = decode(store.get(KEY_HMAC));
        if (key == null || key.length < 32) {
            key = Fingerprints.randomKey();
            store.put(KEY_HMAC, Base64.getEncoder().encodeToString(key));
        }
        this.hmacKey = key;

        String tag = store.get(KEY_TAG);
        if (tag == null || !tag.matches("[A-Z2-9]{4}")) {
            tag = randomTag();
            store.put(KEY_TAG, tag);
        }
        this.installTag = tag;
    }

    /** Registry backed by a map, for tests and for code running before the extension installs one. */
    public static IssueRegistry inMemory() {
        Map<String, String> m = new ConcurrentHashMap<>();
        return new IssueRegistry(new Store() {
            public String get(String k) { return m.get(k); }
            public void put(String k, String v) { m.put(k, v); }
        });
    }

    /**
     * Makes {@code registry} the one used by {@link #current()} and installs its persisted HMAC key
     * for all fingerprints (called once at extension load). Constructing a registry has no global
     * side effects; only this does.
     */
    public static void install(IssueRegistry registry) {
        Fingerprints.setKey(registry.hmacKey);
        current = registry;
    }

    public static IssueRegistry current() {
        return current;
    }

    /** Short tag identifying this installation, e.g. {@code M4K2}. */
    public String installTag() {
        return installTag;
    }

    /** The value as fingerprinted: surrounding whitespace and one pair of matching quotes removed. */
    public static String normalize(String value) {
        if (value == null) return "";
        String v = value.strip();
        if (v.length() >= 2) {
            char a = v.charAt(0), b = v.charAt(v.length() - 1);
            if ((a == '"' || a == '\'' || a == '`') && a == b) v = v.substring(1, v.length() - 1).strip();
        }
        return v;
    }

    /** Keyed fingerprint of the normalized value. */
    public static String fingerprint(String value) {
        return Fingerprints.of(normalize(value));
    }

    /** Permanent ID for this secret value, assigned on first sight. */
    public String idFor(String value) {
        String fp = fingerprint(value);
        String id = cache.get(fp);
        if (id != null) return id;
        synchronized (this) {
            id = cache.get(fp);
            if (id != null) return id;
            String stored = store.get(KEY_FP + fp);
            if (stored != null && ID_SHAPE.matcher(stored.trim()).matches()) {
                id = stored.trim();
            } else {
                String date = LocalDate.now(clock).format(DATE);
                for (int attempt = 0; ; attempt++) {
                    id = "SS-" + date + "-" + code(fp, attempt);
                    String owner = store.get(KEY_ID + id);
                    if (owner == null || owner.equals(fp)) break;      // free, or already ours
                }
                store.put(KEY_ID + id, fp);
                store.put(KEY_FP + fp, id);
            }
            cache.put(fp, id);
            return id;
        }
    }

    /** Six Crockford base32 characters from SHA-256(fingerprint ":" attempt). */
    static String code(String fp, int attempt) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256")
                    .digest((fp + ":" + attempt).getBytes(StandardCharsets.UTF_8));
            long bits = 0;
            for (int i = 0; i < 4; i++) bits = (bits << 8) | (h[i] & 0xff);   // 32 bits, 30 used
            StringBuilder sb = new StringBuilder(6);
            for (int i = 5; i >= 0; i--) sb.append(CROCKFORD[(int) ((bits >>> (i * 5)) & 31)]);
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Reference to one sighting of an issue: the issue ID plus a short stable code for where it was
     * seen, e.g. {@code SS-102426-7K4M2Q@4f9a1c}. Unique per location, needs no storage.
     */
    public String occurrenceRef(String value, String sourceUrl, int line, int offset, String ruleId) {
        String where = (sourceUrl == null ? "" : sourceUrl) + '\n' + line + '\n' + offset + '\n'
                + (ruleId == null ? "" : ruleId);
        return idFor(value) + "@" + Fingerprints.of(where).substring(0, 6);
    }

    private static String randomTag() {
        SecureRandom r = new SecureRandom();
        StringBuilder sb = new StringBuilder(4);
        for (int i = 0; i < 4; i++) sb.append(TAG_ALPHABET[r.nextInt(TAG_ALPHABET.length)]);
        return sb.toString();
    }

    private static byte[] decode(String b64) {
        if (b64 == null || b64.isBlank()) return null;
        try { return Base64.getDecoder().decode(b64.trim()); } catch (IllegalArgumentException e) { return null; }
    }
}
