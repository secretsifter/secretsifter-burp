package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import com.secretscanner.core.IssueRegistry;

/**
 * Keeps issue-ID state ({@link IssueRegistry}) in Burp's global extension preferences, so IDs are
 * stable across scans, projects and restarts on this installation.
 */
final class BurpIssueStore implements IssueRegistry.Store {

    private final MontoyaApi api;

    BurpIssueStore(MontoyaApi api) {
        this.api = api;
    }

    @Override public String get(String key) {
        return api.persistence().preferences().getString(key);
    }

    @Override public void put(String key, String value) {
        api.persistence().preferences().setString(key, value);
    }

    /** Installs a registry backed by Burp preferences; falls back to an in-memory one if that fails. */
    static void install(MontoyaApi api) {
        try {
            IssueRegistry.install(new IssueRegistry(new BurpIssueStore(api)));
        } catch (RuntimeException e) {
            api.logging().logToError("[SecretSifter] issue IDs not persisted this session: " + e);
            IssueRegistry.install(IssueRegistry.inMemory());
        }
    }
}
