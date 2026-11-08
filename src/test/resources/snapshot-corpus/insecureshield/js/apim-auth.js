/**
 * InsecureShield — APIM Client Token Bootstrap
 *
 * On every page load the portal exchanges the Azure APIM subscription key
 * for a short-lived client-side access token. The token is stored in
 * sessionStorage and used as a Bearer credential for all subsequent API calls.
 *
 * Attack chain (SecretSifter demo):
 *   Step 1 — Scanner detects Ocp-Apim-Subscription-Key in outgoing request header
 *   Step 2 — Scanner detects access_token in response body
 *   Step 3 — Attacker replays token as Bearer → /api/policies, /api/users, /api/claims
 *
 * TODO: move subscription key to server-side token proxy before production release
 */

(async function bootstrapApimToken() {
    try {
        const cfg = window.APP_CONFIG && window.APP_CONFIG.apim;
        if (!cfg || !cfg.subscriptionKey) return;

        // POST to the local token endpoint — Ocp-Apim-Subscription-Key sent in header
        const res = await fetch(cfg.tokenEndpoint, {
            method:  'POST',
            headers: {
                'Content-Type':              'application/json',
                'Ocp-Apim-Subscription-Key': cfg.subscriptionKey   // key exposed in request header
            },
            body: JSON.stringify({ scope: cfg.scope })
        });

        if (!res.ok) return;

        const data = await res.json();

        // access_token exposed in response body — SecretSifter response scan picks this up
        if (data.access_token) {
            sessionStorage.setItem('apim_access_token', data.access_token);
            sessionStorage.setItem('apim_token_type',   data.token_type  || 'Bearer');
            sessionStorage.setItem('apim_token_scope',  data.scope       || '');
            sessionStorage.setItem('apim_token_expiry', String(Date.now() + (data.expires_in || 3600) * 1000));
        }
    } catch {
        // non-critical bootstrap — fail silently
    }
})();

/**
 * Returns the APIM-issued access token if present and not expired,
 * otherwise falls back to the session login token.
 */
function getApiToken() {
    const expiry = parseInt(sessionStorage.getItem('apim_token_expiry') || '0', 10);
    const apimToken = sessionStorage.getItem('apim_access_token');
    if (apimToken && Date.now() < expiry) return apimToken;
    return sessionStorage.getItem('token') || '';
}

window.getApiToken = getApiToken;
