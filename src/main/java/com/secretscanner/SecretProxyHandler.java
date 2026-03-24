package com.secretscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Proxy-level response handler — fires for ALL traffic through Burp's proxy
 * regardless of Burp's configured target scope.
 *
 * Primary role (always-on scanning):
 *   Scans every proxied response as it arrives — like JSMiner — so that anything
 *   appearing in the sitemap is automatically scanned without the user needing to
 *   configure a target scope.  Findings are injected directly via
 *   {@code api.siteMap().add(AuditIssue)} and appear immediately in
 *   Target → Site map → Issues and Dashboard → Issue Activity.
 *   For in-scope URLs where {@code SecretScanCheck.passiveAudit()} also fires,
 *   {@code consolidateIssues()} deduplicates issues with identical name+url+detail.
 *
 * Secondary role (Bulk Scan cross-origin routing):
 *   When a Bulk Scan session is running, findings for requests originating from a
 *   watched target (checked via URL, Referer, or Origin) are also routed to the
 *   Bulk Scan panel through ScopeMonitor.
 *
 * Performance:
 *   {@code handleResponseReceived()} returns {@code continueWith()} immediately;
 *   the actual scan runs on a background thread pool so the proxy pipeline is
 *   never blocked by pattern-matching work.
 *
 * This handler never modifies traffic — always returns continueWith(response).
 */
public class SecretProxyHandler implements ProxyResponseHandler {

    private final SecretScanner   scanner;
    private final ScanSettings    settings;
    private final MontoyaApi      api;
    /** Background thread pool — keeps proxy pipeline non-blocking. */
    private final ExecutorService executor;

    public SecretProxyHandler(SecretScanner scanner, ScanSettings settings, MontoyaApi api) {
        this.scanner  = scanner;
        this.settings = settings;
        this.api      = api;
        // 2 daemon threads: enough to drain the proxy queue without saturating CPU.
        // Daemon threads are automatically killed when Burp exits / extension unloads.
        this.executor = Executors.newFixedThreadPool(2, r -> {
            Thread t = new Thread(r, "SecretSifter-ProxyScanner");
            t.setDaemon(true);
            return t;
        });
    }

    /** Called by the extension unloading handler to drain any in-flight proxy scan tasks. */
    public void shutdown() {
        executor.shutdownNow();
        try { executor.awaitTermination(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        // Fast path: check the cheap guards synchronously on the proxy thread,
        // then hand the immutable snapshot to a background thread for scanning.
        if (!settings.isEnabled()) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        var req = interceptedResponse.initiatingRequest();
        if (req == null) return ProxyResponseReceivedAction.continueWith(interceptedResponse);

        String url = req.url();
        if (url == null || url.isBlank()) return ProxyResponseReceivedAction.continueWith(interceptedResponse);

        if (settings.isExternalCdn(url)) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse);
        }

        // Eagerly extract the response body and Content-Type on the proxy thread, BEFORE
        // returning continueWith().  The Montoya API's httpRequestResponse() may hold a
        // reference to the live InterceptedResponse rather than deep-copying its body bytes;
        // if Burp recycles the proxy buffer after continueWith() returns, a background-thread
        // call to response.bodyToString() would read an empty string and the response body
        // would never be scanned.  Extracting here guarantees the bytes are captured.
        final String responseBody = interceptedResponse.bodyToString();
        final String responseCt   = interceptedResponse.headerValue("Content-Type");

        // Snapshot the full request/response pair for request-header scanning and AuditIssue
        // construction.  continueWith() must not be called until after this line.
        HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(req, interceptedResponse);

        // Submit scan to background thread — proxy pipeline is unblocked immediately.
        executor.submit(() -> {
            try {
                List<SecretFinding> findings = scanner.scanRequestResponse(rr, responseBody, responseCt);
                if (!findings.isEmpty()) {
                    // Inject into Dashboard / sitemap: one AuditIssue per (URL, rule) group
                    Map<String, List<SecretFinding>> grouped = new LinkedHashMap<>();
                    for (SecretFinding f : findings)
                        grouped.computeIfAbsent(f.ruleName(), k -> new ArrayList<>()).add(f);
                    for (List<SecretFinding> group : grouped.values())
                        if (SitemapDeduplicator.shouldAdd(group))
                            api.siteMap().add(SecretFinding.toGroupedAuditIssue(group, rr));

                    // Route to Bulk Scan panel when a session is active
                    if (ScopeMonitor.isActive()) {
                        // Use rr.request() (immutable snapshot), not req (may be recycled by Burp
                        // after continueWith() returns on the proxy thread).
                        String referer  = rr.request().headerValue("Referer");
                        String origin   = rr.request().headerValue("Origin");
                        String routeUrl = resolveRouteUrl(url, referer, origin);
                        if (routeUrl != null) {
                            for (SecretFinding f : findings) {
                                ScopeMonitor.notify(f, routeUrl);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                if (api != null)
                    api.logging().logToError("[SecretSifter] ProxyHandler ERROR: " + e.toString());
            }
        });

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        // No interception needed on the send path
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    /**
     * Returns the URL to route findings to, or null if this request doesn't
     * belong to any watched target.
     *
     * Direct URL matching is always applied.  Cross-origin matching via Referer/Origin
     * is enabled only when ScopeMonitor.isCrossOriginFollow() is true (user opt-in via
     * the "Cross-origin APIs" checkbox).  When enabled, API calls fired by a watched
     * host's JavaScript (e.g. api.example.com called from app.example.com) are captured;
     * the trade-off is that unrelated third-party services reached from the same page
     * (e.g. analytics, CDN) may also appear in the panel.
     */
    private static String resolveRouteUrl(String url, String referer, String origin) {
        if (ScopeMonitor.isWatched(url)) return url;
        if (ScopeMonitor.isCrossOriginFollow()) {
            if (referer != null && ScopeMonitor.isWatched(referer)) return referer;
            if (origin  != null && ScopeMonitor.isWatched(origin))  return origin;
        }
        return null;
    }
}
