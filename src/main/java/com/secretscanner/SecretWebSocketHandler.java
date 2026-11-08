package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyMessageHandler;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation;
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Scans WebSocket text frames passing through Burp's proxy, in both directions.
 *
 * Frames are scanned exactly like HTTP response bodies (same engine, tiers and noise
 * suppression), on a bounded background pool so the proxy is never blocked, and never modified:
 * every handler returns continueWith(original payload). Findings become Burp issues filed under
 * the WebSocket's upgrade URL and are routed to the Bulk Scan panel like proxy findings.
 */
public class SecretWebSocketHandler implements ProxyWebSocketCreationHandler {

    private final SecretScanner scanner;
    private final ScanSettings  settings;
    private final MontoyaApi    api;
    private final ExecutorService executor;
    private final AtomicLong queuedChars = new AtomicLong();
    private static final long MAX_QUEUED_CHARS = 64L * 1024 * 1024;

    public SecretWebSocketHandler(SecretScanner scanner, ScanSettings settings, MontoyaApi api) {
        this.scanner  = scanner;
        this.settings = settings;
        this.api      = api;
        ThreadPoolExecutor pool = new ThreadPoolExecutor(2, 2, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>(), r -> {
            Thread t = new Thread(r, "SecretSifter-WebSocketScanner");
            t.setDaemon(true);
            return t;
        });
        pool.allowCoreThreadTimeOut(true);
        this.executor = pool;
    }

    public void shutdown() {
        executor.shutdownNow();
    }

    @Override
    public void handleWebSocketCreation(ProxyWebSocketCreation creation) {
        String url;
        try {
            url = creation.upgradeRequest().url();
        } catch (RuntimeException e) {
            return;
        }
        if (url == null || settings.isExternalCdn(url)) return;
        final String wsUrl = url;
        creation.proxyWebSocket().registerProxyMessageHandler(new ProxyMessageHandler() {
            @Override
            public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage message) {
                submit(message.payload(), wsUrl, "server→client");
                return TextMessageReceivedAction.continueWith(message);
            }

            @Override
            public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage message) {
                submit(message.payload(), wsUrl, "client→server");
                return TextMessageToBeSentAction.continueWith(message);
            }

            @Override
            public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage message) {
                return BinaryMessageReceivedAction.continueWith(message);
            }

            @Override
            public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage message) {
                return BinaryMessageToBeSentAction.continueWith(message);
            }
        });
    }

    private void submit(String payload, String wsUrl, String direction) {
        if (!settings.isEnabled() || payload == null || payload.length() < 8
                || payload.length() > ScanSettings.MAX_SCAN_BYTES) return;
        long n = payload.length();
        if (queuedChars.addAndGet(n) > MAX_QUEUED_CHARS) { queuedChars.addAndGet(-n); return; }
        try {
            executor.submit(() -> {
                try {
                    scan(payload, wsUrl, direction);
                } catch (Exception e) {
                    if (api != null) api.logging().logToError("[SecretSifter] WebSocket scan error: " + e);
                } finally {
                    queuedChars.addAndGet(-n);
                }
            });
        } catch (RejectedExecutionException e) {
            queuedChars.addAndGet(-n);
        }
    }

    private void scan(String payload, String wsUrl, String direction) {
        String trimmed = payload.stripLeading();
        String ct = (trimmed.startsWith("{") || trimmed.startsWith("[")) ? "application/json" : "text/plain";
        // ws:// / wss:// shown as http(s) so Burp's site map and the scope checks accept it
        String httpUrl = wsUrl.replaceFirst("^ws://", "http://").replaceFirst("^wss://", "https://");
        List<SecretFinding> findings = scanner.scanText(payload, ct, httpUrl + " [WS " + direction + "]");
        if (findings.isEmpty()) return;

        Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
        for (SecretFinding f : findings) grouped.computeIfAbsent(f.ruleName(), k -> new ArrayList<>()).add(f);
        for (List<SecretFinding> group : grouped.values()) {
            try {
                if (SitemapDeduplicator.shouldAddProxy(group))
                    api.siteMap().add(SecretFinding.toGroupedAuditIssue(group, null, httpUrl));
            } catch (Exception ex) {
                api.logging().logToError("[SecretSifter] siteMap.add failed for WebSocket finding: " + ex);
            }
        }
        if (ScopeMonitor.isActive() && ScopeMonitor.isWatched(httpUrl)) {
            for (SecretFinding f : findings) ScopeMonitor.notify(f, httpUrl);
        }
    }
}
