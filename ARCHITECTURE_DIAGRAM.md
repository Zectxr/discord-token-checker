# Security Architecture Diagram

## Complete System Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              END USER                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         REACT FRONTEND (UNTRUSTED)                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ • No secrets or API keys                                          │ │
│  │ • Input validation only (advisory)                                │ │
│  │ • Secure request client wrapper                                   │ │
│  │ • Response signature verification                                 │ │
│  │ • Session storage (cleared on tab close)                          │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
│  SecureClient.js:                                                        │
│  ├─ generateNonce() ─────────────> crypto.getRandomValues()             │
│  ├─ createSignature() ──────────> HMAC-SHA256(requestKey, message)      │
│  ├─ verifyResponseSignature() ─> constant-time comparison                │
│  └─ request() ──────────────────> Signed HTTP request + headers          │
│                                                                           │
│  Request Headers:                                                        │
│  ├─ X-Session-Token: session_id.signature                               │
│  ├─ X-Request-Timestamp: 1705267200000                                   │
│  ├─ X-Request-Nonce: a1b2c3d4e5f6...                                     │
│  ├─ X-Signature: HMAC-SHA256(requestKey, message)                        │
│  └─ User-Agent: browser identification                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                  ┌───────────────┼───────────────┐
                  │               │               │
                  ▼               ▼               ▼
            (HTTPS Only)    (HTTPS Only)    (HTTPS Only)
                  │               │               │
┌─────────────────────────────────────────────────────────────────────────┐
│                      VERCEL EDGE NETWORK                                │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ • Automatic HTTPS/TLS 1.3                                         │ │
│  │ • HSTS Headers (31536000s)                                        │ │
│  │ • DDoS Protection                                                 │ │
│  │ • WAF (Web Application Firewall)                                  │ │
│  │ • Geographic routing                                              │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    BACKEND API GATEWAY                                  │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ MIDDLEWARE PIPELINE                                               │ │
│  │                                                                    │ │
│  │ 1. Parse Request                                                  │ │
│  │    └─ JSON body parsing, limit 10KB                               │ │
│  │                                                                    │ │
│  │ 2. Extract Security Headers                                       │ │
│  │    └─ X-Session-Token, X-Signature, X-Timestamp, X-Nonce          │ │
│  │                                                                    │ │
│  │ 3. Authenticate Session                                           │ │
│  │    ├─ Lookup session in Redis                                     │ │
│  │    ├─ Verify token format and hash                                │ │
│  │    ├─ Check expiration                                            │ │
│  │    └─ Verify client fingerprint (MITM detection)                 │ │
│  │                                                                    │ │
│  │ 4. Verify Request Signature                                       │ │
│  │    ├─ Reconstruct message: timestamp|nonce|body|version           │ │
│  │    ├─ Calculate HMAC-SHA256(requestKey, message)                  │ │
│  │    └─ Constant-time comparison with provided signature            │ │
│  │                                                                    │ │
│  │ 5. Validate Timestamp Freshness                                   │ │
│  │    ├─ Check timestamp within ±5 minutes                           │ │
│  │    └─ Reject too old or future timestamps                         │ │
│  │                                                                    │ │
│  │ 6. Check Replay Protection                                        │ │
│  │    ├─ Query Redis for nonce                                       │ │
│  │    ├─ Reject if nonce exists (already used)                       │ │
│  │    └─ Store nonce with 5-minute TTL                               │ │
│  │                                                                    │ │
│  │ 7. Rate Limiting Layer 1 (IP-based)                               │ │
│  │    ├─ Get client IP from headers                                  │ │
│  │    ├─ Check Redis: ratelimit:ip:{ip}                              │ │
│  │    ├─ Increment counter, set 60-second window                     │ │
│  │    └─ Reject if count > 10/minute                                 │ │
│  │                                                                    │ │
│  │ 8. Rate Limiting Layer 2 (Session-based)                          │ │
│  │    ├─ Check Redis: ratelimit:session:{sessionId}                  │ │
│  │    ├─ Increment counter, set 1-hour window                        │ │
│  │    └─ Reject if count > 100/hour                                  │ │
│  │                                                                    │ │
│  │ 9. Rate Limiting Layer 3 (Device Fingerprint)                     │ │
│  │    ├─ Hash: user-agent|accept-language|ip                         │ │
│  │    ├─ Check Redis: ratelimit:fingerprint:{hash}                   │ │
│  │    ├─ Increment counter, set 60-second window                     │ │
│  │    └─ Reject if count > 20/minute                                 │ │
│  │                                                                    │ │
│  │ 10. Bot/Automation Detection                                      │ │
│  │    ├─ Analyze user-agent (headless, bot signatures)               │ │
│  │    ├─ Check header completeness                                   │ │
│  │    ├─ Analyze request timing patterns                             │ │
│  │    ├─ Check for suspicious headers                                │ │
│  │    └─ Calculate automation score (0-10)                           │ │
│  │       ├─ Score > 3: Aggressive rate limiting                      │ │
│  │       ├─ Score > 5: Challenge with CAPTCHA                        │ │
│  │       └─ Score > 8: Block request                                 │ │
│  │                                                                    │ │
│  │ 11. Input Validation                                              │ │
│  │    ├─ Validate token format (regex)                               │ │
│  │    ├─ Check token length (20-100 chars)                           │ │
│  │    └─ Reject unexpected fields                                    │ │
│  │                                                                    │ │
│  │ ✓ All validations passed → Continue to handler                   │ │
│  │ ✗ Any validation failed → Return error response                  │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   REQUEST HANDLER                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Token Validation Flow                                             │ │
│  │                                                                    │ │
│  │ 1. Extract token from request body                                │ │
│  │ 2. NEVER trust frontend - backend validates everything            │ │
│  │ 3. Query Discord API (backend only - user secret key)             │ │
│  │    └─ GET https://discord.com/api/v10/users/@me                   │ │
│  │       Authorization: Bearer <token>                               │ │
│  │ 4. Parse response (200 = valid, 401 = invalid, error = retry)    │ │
│  │ 5. Extract safe data (username, ID, email, etc.)                  │ │
│  │ 6. Hash token for audit logging (never store full token)          │ │
│  │ 7. Generate response                                              │ │
│  │    {                                                              │ │
│  │      "valid": true/false,                                         │ │
│  │      "details": { "username": "...", "id": "...", ... },          │ │
│  │      "checkId": "uuid",                                           │ │
│  │      "timestamp": 1705267200000                                    │ │
│  │    }                                                              │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   RESPONSE SIGNING                                      │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Generate Response Signature                                       │ │
│  │                                                                    │ │
│  │ 1. Create timestamp: Date.now() = 1705267200000                   │ │
│  │ 2. Serialize response: JSON.stringify(responseData)               │ │
│  │ 3. Create message: jsonResponse|timestamp                         │ │
│  │ 4. Calculate signature: HMAC-SHA256(responseKey, message)         │ │
│  │ 5. Add to response headers:                                       │ │
│  │    X-Response-Signature: signature                                │ │
│  │    X-Response-Timestamp: timestamp                                │ │
│  │ 6. Response body: JSON response data                              │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   SECURITY LOGGING                                      │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Log to multiple destinations:                                     │ │
│  │                                                                    │ │
│  │ 1. Console (real-time monitoring)                                 │ │
│  │ 2. File system (audit trail)                                      │ │
│  │ 3. Redis (short-term metrics)                                     │ │
│  │ 4. Alerts (critical events → PagerDuty, Slack)                   │ │
│  │                                                                    │ │
│  │ Events logged:                                                    │ │
│  │ ├─ TOKEN_VALIDATED (info)                                        │ │
│  │ ├─ RATE_LIMIT_EXCEEDED (warning)                                 │ │
│  │ ├─ INVALID_SIGNATURE (critical)                                  │ │
│  │ ├─ REPLAY_DETECTED (critical)                                    │ │
│  │ ├─ AUTOMATION_DETECTED (warning)                                 │ │
│  │ └─ SESSION_HIJACKING_ATTEMPTED (critical)                        │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                  │
                          ┌───────┴───────┐
                          │               │
                          ▼               ▼
                   (HTTPS Only)    (HTTPS Only)
                          │               │
                          │      ┌────────▼────────┐
                          │      │  REDIS CACHE    │
                          │      ├─────────────────┤
                          │      │ Sessions        │
                          │      │ Nonces          │
                          │      │ Rate limits     │
                          │      │ Bot scores      │
                          │      │ (All TTL'd)     │
                          │      └────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    FRONTEND RESPONSE HANDLER                            │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ 1. Receive response with signature headers                        │ │
│  │ 2. Verify response signature (prevents tampering)                 │ │
│  │    ├─ Get X-Response-Signature and X-Response-Timestamp           │ │
│  │    ├─ Verify timestamp freshness (< 30 seconds old)               │ │
│  │    ├─ Recalculate: HMAC-SHA256(responseKey, body|timestamp)       │ │
│  │    └─ Constant-time comparison with provided signature            │ │
│  │ 3. If verification fails → Throw security error                   │ │
│  │ 4. If verification passes → Trust response                        │ │
│  │ 5. Update UI with validation results                              │ │
│  │ 6. Clear sensitive data from memory                               │ │
│  │ 7. Display results to user                                        │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Security Layers Explained

### Layer 1: Transport Security
```
Browser ──HTTPS/TLS 1.3──> Vercel Edge ──HTTPS/TLS 1.3──> Backend
         └─ HSTS enforced ─┘
         └─ No HTTP fallback
```

### Layer 2: Request Authentication
```
Request = {
  body: { token: "discord_token" },
  timestamp: 1705267200000,
  nonce: "unique_random_value",
  signature: HMAC-SHA256(requestKey, message)
}
Backend verifies each component:
  ✓ Signature matches = No tampering
  ✗ Signature doesn't match = Attacker modified request
```

### Layer 3: Replay Protection
```
Request 1: nonce = "abc123"
  └─ Backend stores in Redis with 5-min TTL
  └─ Attacker captures and replays

Request 2 (replay): nonce = "abc123"
  └─ Backend checks Redis: nonce exists!
  └─ Rejects: "Nonce already used"
```

### Layer 4: Rate Limiting
```
Request from IP 1.2.3.4:
  Count 1: ✓ Allowed (ratelimit:ip:1.2.3.4 = 1)
  Count 2: ✓ Allowed (ratelimit:ip:1.2.3.4 = 2)
  ...
  Count 10: ✓ Allowed (ratelimit:ip:1.2.3.4 = 10)
  Count 11: ✗ Rejected (exceeded limit of 10/minute)
```

### Layer 5: Backend Validation
```
Frontend cannot:
  ✗ Decide if token is valid
  ✗ Access Discord API (user secret key on backend only)
  ✗ Bypass validation logic

Backend:
  ✓ Calls Discord API with secret key
  ✓ Gets authoritative answer
  ✓ Enforces all security rules
```

### Layer 6: Response Integrity
```
Backend response = { valid: true, username: "user" }
Signature = HMAC-SHA256(responseKey, response|timestamp)

Attacker in MITM:
  ✗ Tries to change response to { valid: true }
  ✗ Backend recalculates signature: DIFFERENT
  ✗ Frontend rejects: "Response tampering detected"
```

---

## Attack Prevention Example

### Scenario: Attacker bulk-checks 1000 tokens

```
Attacker's Script:
  for (let i = 0; i < 1000; i++) {
    fetch('/api/v1/tokens/validate', {
      body: JSON.stringify({ token: tokens[i] })
    });
  }

What Happens:

Request 1:
  ├─ IP rate limit: 1/10 ✓
  ├─ Session rate limit: 1/100 ✓
  ├─ Fingerprint rate limit: 1/20 ✓
  ├─ Automation score: 2 (within tolerance)
  └─ ✓ ALLOWED

Request 2-10:
  ├─ All limits: OK
  └─ ✓ ALLOWED

Request 11:
  ├─ IP rate limit: 11/10 ✗
  └─ ✗ REJECTED: Rate limit exceeded (retry after 60s)

Attacker tries from different IP (botnet):

Request 1 (IP 2):
  ├─ IP rate limit: 1/10 ✓
  ├─ Session rate limit: 11/100 ✗
  └─ ✗ REJECTED: Session limit exceeded

Attacker tries new session + IP rotation:

Request 1 (IP 3, new session):
  ├─ IP rate limit: 1/10 ✓
  ├─ Session rate limit: 1/100 ✓
  ├─ Fingerprint rate limit: 21/20 ✗
  │  (fingerprint is same across IPs - same headers)
  └─ ✗ REJECTED: Fingerprint rate limit exceeded

Attacker tries to replay captured signature:

Request with old nonce:
  ├─ Signature verification: ✓ (looks valid)
  ├─ Nonce check: redis.get("nonce:abc123") = exists!
  └─ ✗ REJECTED: Nonce already used (replay attack)

Attacker tries bot detection bypass:

Request with scraped headers:
  ├─ Automation detection: BOT_HEADERS + TIMING_PATTERNS
  ├─ Automation score: 8/10
  └─ ✗ BLOCKED: Challenge required (CAPTCHA)

Result: Attack completely mitigated! ✓
```

---

## Performance Impact

```
Secure Implementation Overhead:

Per-Request Latency:
  ├─ HMAC-SHA256 signing: ~1ms
  ├─ Redis lookup (session): ~5ms
  ├─ Redis lookup (nonce): ~5ms
  ├─ Redis update (rate limit): ~3ms
  ├─ Discord API call: ~200-500ms (bottleneck)
  └─ Response signing: ~1ms
  
  Total: ~215-520ms (dominated by Discord API)
  → Security overhead: <15ms (negligible)

Throughput:
  - Single backend: 100+ req/sec
  - With rate limiting: Configured to 10-100 req/min per user
  - Security impact: Minimal

Scalability:
  - Stateless backend (all state in Redis)
  - Horizontal scaling: Add more backend instances
  - Redis can handle thousands of concurrent sessions
```

---

## Summary

This architecture provides **defense in depth**:

1. **Transport Layer** → HTTPS/HSTS prevents eavesdropping
2. **Request Layer** → HMAC signatures prevent tampering
3. **Replay Layer** → Nonces prevent attack replay
4. **Validation Layer** → Backend-only logic prevents bypass
5. **Rate Limit Layer** → Multi-layer limits prevent abuse
6. **Response Layer** → Signatures prevent response tampering
7. **Behavioral Layer** → Bot detection prevents automation
8. **Monitoring Layer** → Comprehensive logging enables incident response

**No single point of failure** — compromising one layer doesn't compromise others.

