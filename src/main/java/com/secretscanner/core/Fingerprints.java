package com.secretscanner.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * Stable identifiers for secret values that never reveal the value.
 *
 * A fingerprint is HMAC-SHA256(key, value), truncated to 16 hex chars. Keyed, not a plain hash,
 * so a report or baseline file cannot be used to confirm guesses of a low-entropy secret
 * (a password) offline. The same value always gets the same fingerprint under the same key,
 * which is what grouping, baselines and false-positive memory need.
 *
 * The key defaults to a random per-process key. The extension should install a key persisted in
 * its own settings via {@link #setKey} so fingerprints stay stable across Burp restarts.
 */
public final class Fingerprints {

    private static final int KEY_BYTES = 32;
    private static final int FINGERPRINT_HEX = 16;

    private static volatile byte[] key = randomKey();

    private Fingerprints() {}

    /** Installs the HMAC key (at least 32 bytes). Findings fingerprinted earlier keep their old values. */
    public static void setKey(byte[] newKey) {
        if (newKey == null || newKey.length < KEY_BYTES)
            throw new IllegalArgumentException("fingerprint key must be at least " + KEY_BYTES + " bytes");
        key = newKey.clone();
    }

    /** A fresh random key, for callers that need to create and persist one. */
    public static byte[] randomKey() {
        byte[] k = new byte[KEY_BYTES];
        new SecureRandom().nextBytes(k);
        return k;
    }

    /** Fingerprint of a secret value. The value is used exactly as given (no trimming or case folding). */
    public static String of(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            byte[] h = mac.doFinal((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(h).substring(0, FINGERPRINT_HEX);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);   // guaranteed present in every JRE
        }
    }

    /**
     * Display form of a secret with most of it masked. Counts code points, so a masked value never
     * ends in half a surrogate pair. Up to 12 characters: fully masked. 13-19: first 2 and last 2
     * shown. 20 or more: first 4 and last 4 shown.
     */
    public static String redact(String value) {
        if (value == null || value.isEmpty()) return "";
        int[] cps = value.codePoints().toArray();
        int n = cps.length;
        if (n <= 12) return "*".repeat(n);
        int keep = n < 20 ? 2 : 4;
        return new String(cps, 0, keep) + "*".repeat(Math.min(n - 2 * keep, 16)) + new String(cps, n - keep, keep);
    }
}
