package com.secretscanner;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Scope monitor target matching")
class ScopeMonitorTest {

    @AfterEach void reset() { ScopeMonitor.clearWatched(); }

    @Test void hostAndPathBoundaries() {
        ScopeMonitor.addWatchedUrl("https://example.com");
        assertTrue(ScopeMonitor.isWatched("https://example.com/app.js"));
        assertTrue(ScopeMonitor.isWatched("http://example.com/"));
        assertFalse(ScopeMonitor.isWatched("https://example.com.evil.net/x"));
        assertFalse(ScopeMonitor.isWatched("https://example.community/x"));
    }

    @Test void schemeLessTargetWithPath() {
        ScopeMonitor.addWatchedUrl("app.example.com/portal");
        assertTrue(ScopeMonitor.isWatched("https://app.example.com/portal/main.js"));
        assertTrue(ScopeMonitor.isWatched("https://app.example.com/other"));      // same host is in scope
        assertFalse(ScopeMonitor.isWatched("https://evil.test/app.example.com/portal"));
    }
}
