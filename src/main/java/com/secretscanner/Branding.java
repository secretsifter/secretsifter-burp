package com.secretscanner;

import javax.swing.JComponent;
import javax.swing.JScrollPane;

/**
 * Plain product identity for the BApp Store edition.
 *
 * This is a deliberately minimal shim: the extension ships with no third-party branding,
 * logos, or watermarks. The decorative helpers ({@link #wrap} / {@link #watermarkInBox})
 * are pass-throughs so existing call sites compile unchanged while rendering nothing extra.
 */
public final class Branding {

    private Branding() {}

    static final String NAME        = "SecretSifter";
    static final String TAGLINE     = "Runtime credential & secrets detection";
    static final String PROJECT_URL = "https://github.com/secretsifter/secretsifter-burp";

    /** No decorative wrapper — returns the content unchanged. */
    static JComponent wrap(JComponent content) { return content; }

    /** No watermark — returns the scroll pane unchanged. */
    static JComponent watermarkInBox(JScrollPane scroll) { return scroll; }

    /** Plain one-line banner for the extension log. */
    static String banner(String edition) {
        return "=== " + NAME + " (" + edition + ") ===";
    }

    /** No embedded logo in HTML reports. */
    static String logoSvg(boolean light) { return ""; }

    /** No embedded mark in HTML reports. */
    static String markDataUri() { return ""; }
}
