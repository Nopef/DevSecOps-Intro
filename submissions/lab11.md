# Lab 11 — BONUS — Submission

## Task 1: TLS + Security Headers

### nginx.conf (SSL + header sections)

```nginx
    server {
        listen 80;
        return 308 https://$host$request_uri;
    }

    server {
        listen 443 ssl;
        http2 on;
        ssl_certificate     /etc/nginx/certs/localhost.crt;
        ssl_certificate_key /etc/nginx/certs/localhost.key;
        ssl_protocols TLSv1.3;
        ssl_prefer_server_ciphers off;
        ssl_ecdh_curve X25519:secp384r1;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 1d;
        ssl_session_tickets off;

        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        add_header Content-Security-Policy-Report-Only "default-src 'self'; ..." always;
    }
```

*(Full file: `labs/lab11/reverse-proxy/nginx.conf`)*

### A. HTTPS redirect proof

```
HTTP/1.1 308 Permanent Redirect
Location: https://localhost/
```

### B. TLS 1.3 proof

```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
```

### C. Security headers proof (all 6 present)

```
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
content-security-policy-report-only: default-src 'self'; ...
```

### What each header defends against (1 sentence each)

- **HSTS:** Forces browsers to use HTTPS only, preventing sslstrip/downgrade attacks on repeat visits.
- **X-Content-Type-Options: nosniff:** Stops browsers from MIME-sniffing responses into executable content types.
- **X-Frame-Options: DENY:** Blocks clickjacking by preventing the page from being embedded in iframes.
- **Referrer-Policy:** Limits leakage of full URLs in the `Referer` header to cross-origin destinations.
- **Permissions-Policy:** Disables sensitive browser APIs (camera, mic, geolocation) the app does not need.
- **Content-Security-Policy-Report-Only:** Monitors violations of a strict resource-loading policy without breaking Juice Shop during tuning.

---

## Task 2: Production Posture

### Rate limit proof

| HTTP code | Count out of 60 |
|-----------|----------------:|
| 401 | 6 |
| 429 | 54 |
| 5xx | 0 |

### Timeout enforced

```
(connection closed by nginx on slow/partial request — client_header_timeout 10s)
```

### Cipher hardening

```
Cipher is TLS_AES_256_GCM_SHA384
Protocol version: TLSv1.3
```

### Cert rotation runbook (7 steps)

1. **Detect expiry:** Monitor cert `notAfter` via Prometheus/openssl cron; alert at T-30 and T-7 days.
2. **Order new cert:** Request from ACME/Let's Encrypt or internal PKI with same SANs as current cert.
3. **Validate:** Verify chain, key match (`openssl x509 -noout -modulus`), and staging endpoint if available.
4. **Atomic swap:** Install new cert/key to staging path, `nginx -t`, then `reload` (not restart) to pick up files.
5. **Verify:** `openssl s_client -connect host:443 -servername host` + smoke test critical paths.
6. **Rollback plan:** Keep previous cert/key pair; on failure, restore files and `nginx -s reload` within minutes.
7. **Audit:** Log rotation event (who, when, serial numbers, ticket ID) in change-management / SIEM.

### What OCSP stapling buys you (production vs lab)

OCSP stapling lets the server attach a fresh revocation status to the TLS handshake, so clients avoid extra latency and privacy leaks from contacting the CA OCSP responder directly. On a self-signed lab cert there is no public CA OCSP responder, so stapling is configured but has no effect — in production with Let's Encrypt or enterprise PKI it reduces handshake round-trips and improves privacy.

---

## Bonus: WAF Sidecar with OWASP CRS

### Setup choice

- **WAF used:** ModSecurity v3 (`owasp/modsecurity-crs:nginx-alpine`)
- **OWASP CRS version:** 3.3.10 (CRS v3 ruleset in image)
- **Paranoia level:** 1
- **WAF port:** `9443` (8443 occupied by DefectDojo from Lab 10)

### Attack payload sent

`GET /rest/products/search?q=' OR 1=1--` (URL-encoded)

### Before WAF (Nginx alone)

```
no-waf: HTTP 500
```

*(Request reaches Juice Shop — not blocked by Nginx; 500 is app error on malicious query)*

### After WAF

```
with-waf: HTTP 403
```

### Audit log excerpt (the rule that fired)

```
ModSecurity: Access denied with code 403 (phase 2) ...
[id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"]
...
"ruleId":"942100"
"message":"SQL Injection Attack Detected via libinjection"
"data":"Matched Data: s&1c found within ARGS:q: ' OR 1=1--"
```

Rule ID: **942100** — OWASP CRS rule name: **SQL Injection Attack Detected via libinjection**

### Tradeoff analysis (3 sentences)

A WAF blocks exploit-shaped HTTP at the edge — categories of attacks that SAST/DAST miss at deploy time and that Conftest cannot see in runtime HTTP traffic. It costs operational overhead: tuning paranoia levels, false positives, audit-log storage, and another moving part in the request path. Skip a WAF for low-risk internal APIs behind mTLS, or when latency/complexity outweighs threat (e.g. static CDN-only sites with no user input).
