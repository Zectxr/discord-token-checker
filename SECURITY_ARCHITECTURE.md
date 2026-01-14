# Secure Discord Token Checker Architecture

## Executive Summary

This document defines a **zero-trust architecture** for a token checker that processes sensitive Discord tokens while defending against MITM, replay, tampering, frontend bypass, and automated abuse attacks.

---

## 1. Security Architecture Overview

### 1.1 Core Principles
- **Never trust the frontend**: Assume all frontend code is compromised or can be bypassed
- **Verify everything on backend**: All validation, authentication, and token checking occurs server-side
- **Defense in depth**: Multiple independent security layers prevent single-point-of-failure attacks
- **Minimize sensitive data exposure**: No tokens or secrets ever reach the frontend

### 1.2 Threat Model

| Threat | Attack Vector | Impact |
|--------|---------------|--------|
| **MITM** | Intercept HTTP traffic | Steal tokens, request tampering |
| **Replay** | Reuse valid signed requests | Bulk automated checks, DoS |
| **Tampering** | Modify request body | Bypass rate limits, escalate privileges |
| **Frontend Bypass** | Reverse-engineer API calls | Direct backend exploitation |
| **Automated Abuse** | Bot requests, API scraping | Resource exhaustion, DoS |

---

## 2. Frontend-Backend Communication Security

### 2.1 Request Flow Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     React Frontend                       │
│  (Untrusted: No secrets, no business logic)             │
└────────────────┬────────────────────────────────────────┘
                 │
        1. Generate Request Signature
        2. Add Timestamp + Nonce
        3. TLS 1.3 Encryption
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│                  Vercel Edge Network                      │
│  (Automatic HTTPS, DDoS protection, WAF)                │
└────────────────┬─────────────────────────────────────────┘
                 │
        4. Parse Signature
        5. Validate Timestamp
        6. Replay Detection (Nonce Store)
        7. Rate Limit Check
        8. Fingerprint Analysis
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│          Secure Backend (Node.js/Python)                 │
│  • Token validation                                      │
│  • Sensitive logic                                       │
│  • Database access                                       │
│  • Secrets management                                    │
└──────────────────────────────────────────────────────────┘
```

### 2.2 HTTPS Enforcement

**Frontend:**
```javascript
// Always use secure origins
const API_BASE = process.env.REACT_APP_API_URL; // Must be https://
const secure = API_BASE.startsWith('https://');
if (!secure && process.env.NODE_ENV === 'production') {
  throw new Error('API must use HTTPS');
}
```

**Backend:**
```javascript
// Enforced at Vercel level - no HTTP traffic accepted
// Set in vercel.json:
{
  "env": {
    "FORCE_HTTPS": "true"
  },
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        }
      ]
    }
  ]
}
```

---

## 3. HMAC-Signed Requests

### 3.1 Signature Generation Strategy

**Challenge**: Frontend doesn't have server secret (untrusted environment)

**Solution**: Use **sessionToken + public request key** pattern

```
┌──────────────────────────────────────────────┐
│ 1. User requests session token from backend  │
│    POST /api/v1/auth/session                 │
│    Returns: { sessionToken, requestKey }     │
└──────────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│ 2. Frontend generates HMAC signature         │
│    Key: requestKey (ephemeral, short-lived)  │
│    Data: timestamp + nonce + requestBody     │
└──────────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│ 3. Send to backend with:                     │
│    - sessionToken                            │
│    - Request signature                       │
│    - Timestamp + nonce                       │
│    - Body (plaintext)                        │
└──────────────────────────────────────────────┘
                    │
                    ▼
┌──────────────────────────────────────────────┐
│ 4. Backend verification:                     │
│    a) Lookup sessionToken → get master key   │
│    b) Derive requestKey from master key      │
│    c) Verify HMAC signature                  │
│    d) Check timestamp freshness              │
│    e) Verify nonce not in replay store       │
└──────────────────────────────────────────────┘
```

### 3.2 Signature Algorithm

```
HMAC_SHA256(
  key=requestKey,
  message=timestamp|nonce|JSON.stringify(body)|version
)

Output: hex-encoded signature
```

**Example:**
```
timestamp: 1705267200000
nonce: a1b2c3d4-e5f6-7890-abcd-ef1234567890
body: { "token": "..." }
version: "1"

message = "1705267200000|a1b2c3d4-e5f6-7890-abcd-ef1234567890|{\"token\":\"...\"}|1"
signature = HMAC_SHA256(requestKey, message)
```

---

## 4. Timestamp + Nonce Replay Protection

### 4.1 Replay Detection Strategy

**Problem**: Attacker captures valid signed request, replays it multiple times

**Solution**: Multi-layered replay prevention

```javascript
// Backend replay detection
function verifyRequestFreshness(req) {
  const MAX_SKEW_MS = 5 * 60 * 1000; // 5 minutes
  const now = Date.now();
  const timestamp = parseInt(req.headers['x-request-timestamp']);
  
  // 1. Check timestamp freshness (prevent old requests)
  if (Math.abs(now - timestamp) > MAX_SKEW_MS) {
    throw new Error('Request timestamp expired or from future');
  }
  
  // 2. Check nonce uniqueness (prevent replay within window)
  const nonce = req.headers['x-request-nonce'];
  const nonceKey = `nonce:${nonce}:${req.sessionId}`;
  
  const existingNonce = redisCache.get(nonceKey);
  if (existingNonce) {
    throw new Error('Nonce already used - replay attack detected');
  }
  
  // 3. Store nonce in fast cache with TTL
  redisCache.setex(nonceKey, MAX_SKEW_MS / 1000, timestamp);
  
  return true;
}
```

### 4.2 Nonce Generation

```javascript
// Frontend
function generateNonce() {
  // Use crypto API for true randomness
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Alternative UUID v4
function generateNonceUUID() {
  return crypto.randomUUID();
}
```

---

## 5. Rate Limiting Per IP & Fingerprint

### 5.1 Multi-Layer Rate Limiting

```
┌─────────────────────────────────────┐
│   Layer 1: IP-based rate limit      │
│   10 requests/minute per IP         │
└─────────────────────────────────────┘
                ▼
        (Pass check)
                ▼
┌─────────────────────────────────────┐
│   Layer 2: Session rate limit       │
│   50 requests/hour per session      │
└─────────────────────────────────────┘
                ▼
        (Pass check)
                ▼
┌─────────────────────────────────────┐
│   Layer 3: Fingerprint rate limit   │
│   20 requests/minute per fingerprint│
└─────────────────────────────────────┘
                ▼
        (Pass check)
                ▼
┌─────────────────────────────────────┐
│   Layer 4: Behavioral analysis      │
│   Detect suspicious patterns        │
└─────────────────────────────────────┘
```

### 5.2 IP-Based Rate Limiting

```javascript
async function checkIPRateLimit(ipAddress) {
  const key = `ratelimit:ip:${ipAddress}`;
  const count = await redis.incr(key);
  
  if (count === 1) {
    // First request, set TTL
    await redis.expire(key, 60); // 60 second window
  }
  
  const MAX_REQUESTS_PER_MINUTE = 10;
  if (count > MAX_REQUESTS_PER_MINUTE) {
    throw new RateLimitError('Too many requests', {
      retryAfter: 60,
      statusCode: 429
    });
  }
  
  return true;
}
```

### 5.3 Device Fingerprinting

```javascript
// Backend fingerprint extraction
function getFingerprint(req) {
  const crypto = require('crypto');
  
  // Components
  const userAgent = req.headers['user-agent'] || '';
  const acceptLanguage = req.headers['accept-language'] || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';
  const ipAddress = req.ip;
  
  // Build fingerprint string
  const fingerprintString = [
    userAgent,
    acceptLanguage,
    acceptEncoding,
    ipAddress
  ].join('|');
  
  // Hash for privacy
  const fingerprint = crypto
    .createHash('sha256')
    .update(fingerprintString)
    .digest('hex');
  
  return fingerprint;
}

// Rate limit per fingerprint
async function checkFingerprintRateLimit(fingerprint) {
  const key = `ratelimit:fingerprint:${fingerprint}`;
  const count = await redis.incr(key);
  
  if (count === 1) {
    await redis.expire(key, 60);
  }
  
  const MAX_PER_MINUTE = 20;
  if (count > MAX_PER_MINUTE) {
    throw new RateLimitError('Suspicious activity detected');
  }
  
  return true;
}
```

---

## 6. Backend-Only Token Validation

### 6.1 Why Backend-Only?

| Approach | Risk | Location |
|----------|------|----------|
| Frontend validation | Easily bypassed via DevTools | ❌ Untrusted |
| Backend validation | Authoritative, logged, monitored | ✅ Trusted |
| Both | False sense of security | ❌ Still exploitable |

### 6.2 Secure Backend Token Check

```javascript
// Secure server-side endpoint
app.post('/api/v1/tokens/validate', async (req, res) => {
  try {
    // 1. Authenticate session
    const session = validateSessionToken(req.headers['x-session-token']);
    if (!session) return res.status(401).json({ error: 'Unauthorized' });
    
    // 2. Verify request signature
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-request-timestamp'];
    const nonce = req.headers['x-request-nonce'];
    
    if (!verifySignature(signature, timestamp, nonce, req.body, session)) {
      return res.status(401).json({ error: 'Invalid signature' });
    }
    
    // 3. Check replay attack
    if (!checkReplayProtection(nonce, session.id)) {
      return res.status(429).json({ error: 'Duplicate request' });
    }
    
    // 4. Rate limit checks (IP, session, fingerprint)
    await checkAllRateLimits(req, session);
    
    // 5. Extract token from request
    const { token } = req.body;
    
    // 6. Validate token format (basic)
    if (!isValidTokenFormat(token)) {
      return res.status(400).json({ error: 'Invalid token format', valid: false });
    }
    
    // 7. Query Discord API with server secrets
    // Secrets NEVER exposed to frontend
    const proxyResponse = await checkTokenViaProxy(token);
    
    // 8. Build response with integrity protection
    const responseData = {
      valid: proxyResponse.valid,
      details: proxyResponse.details || null,
      timestamp: Date.now(),
      checkId: generateUUID() // For audit trails
    };
    
    // 9. Sign response for integrity verification (optional but recommended)
    const responseSignature = signResponse(responseData, session.responseKey);
    
    // 10. Log for security monitoring
    logValidationRequest({
      sessionId: session.id,
      fingerprint: getFingerprint(req),
      ipAddress: req.ip,
      tokenHash: hashToken(token),
      result: responseData.valid,
      timestamp: Date.now()
    });
    
    // 11. Return with security headers
    res.set({
      'X-Response-Signature': responseSignature,
      'X-Response-Timestamp': responseData.timestamp,
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache'
    });
    
    res.json(responseData);
    
  } catch (error) {
    logger.error('Token validation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
```

### 6.3 Discord API Proxy Pattern

```javascript
// Never expose Discord API directly to frontend
async function checkTokenViaProxy(token) {
  try {
    // Use backend to call Discord API
    const response = await fetch('https://discord.com/api/v10/users/@me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'User-Agent': 'SecureTokenChecker/1.0'
      },
      timeout: 10000
    });
    
    if (response.status === 200) {
      const userData = await response.json();
      // Log audit trail
      logTokenCheck(token, 'valid', userData.id);
      
      return {
        valid: true,
        details: {
          username: userData.username,
          id: userData.id,
          email: userData.email,
          // Don't leak unnecessary details
        }
      };
    } else if (response.status === 401) {
      return { valid: false, details: null };
    } else {
      throw new Error(`Unexpected status: ${response.status}`);
    }
  } catch (error) {
    logger.error('Discord API error:', error);
    throw error;
  }
}
```

---

## 7. Response Integrity Verification

### 7.1 Response Signing

```javascript
// Backend signs response
function signResponse(responseData, responseKey) {
  const crypto = require('crypto');
  const timestamp = Date.now();
  
  // Include timestamp in signature to prevent tampering
  const message = JSON.stringify(responseData) + '|' + timestamp;
  
  const signature = crypto
    .createHmac('sha256', responseKey)
    .update(message)
    .digest('hex');
  
  return signature;
}

// Frontend verifies response
function verifyResponseIntegrity(responseData, signature, timestamp, responseKey) {
  const crypto = require('crypto');
  const MAX_RESPONSE_AGE_MS = 30000; // 30 seconds
  
  // 1. Check timestamp freshness
  if (Date.now() - timestamp > MAX_RESPONSE_AGE_MS) {
    throw new Error('Response timestamp too old - possible replay');
  }
  
  // 2. Verify signature
  const message = JSON.stringify(responseData) + '|' + timestamp;
  const expectedSignature = crypto
    .createHmac('sha256', responseKey)
    .update(message)
    .digest('hex');
  
  // Use constant-time comparison
  if (!constantTimeEquals(signature, expectedSignature)) {
    throw new Error('Response signature invalid - possible tampering');
  }
  
  return true;
}
```

### 7.2 Constant-Time Comparison (prevent timing attacks)

```javascript
function constantTimeEquals(a, b) {
  if (a.length !== b.length) return false;
  
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}
```

---

## 8. Proxy & Automation Detection

### 8.1 Detection Signals

```javascript
function analyzeRequestForAutomation(req) {
  const signals = {
    suspicious: 0,
    maxScore: 0
  };
  
  // 1. Check user-agent for bot signatures
  const userAgent = req.headers['user-agent'] || '';
  const botPatterns = /bot|crawler|scraper|curl|wget|python|automation/i;
  if (botPatterns.test(userAgent)) {
    signals.suspicious++;
    signals.maxScore += 3;
  }
  
  // 2. Check for headless browser indicators
  if (userAgent.includes('HeadlessChrome') || 
      userAgent.includes('PhantomJS') ||
      userAgent.includes('Selenium')) {
    signals.suspicious++;
    signals.maxScore += 3;
  }
  
  // 3. Check for proxy/VPN indicators
  const suspiciousHeaders = [
    'x-forwarded-for',
    'x-real-ip',
    'x-proxy-authorization'
  ];
  
  if (suspiciousHeaders.some(h => req.headers[h])) {
    // Check if legitimate (behind CDN) or suspicious
    if (!isKnownCDN(req.headers['x-forwarded-for'])) {
      signals.suspicious++;
      signals.maxScore += 2;
    }
  }
  
  // 4. Check missing typical browser headers
  const browserHeaders = ['accept', 'accept-language', 'accept-encoding'];
  const missingHeaders = browserHeaders.filter(h => !req.headers[h]).length;
  
  if (missingHeaders >= 2) {
    signals.suspicious++;
    signals.maxScore += 1;
  }
  
  // 5. Check for rapid-fire requests from same fingerprint
  const fingerprint = getFingerprint(req);
  const recentRequests = getRecentRequestCount(fingerprint, 10000); // Last 10s
  
  if (recentRequests > 5) {
    signals.suspicious++;
    signals.maxScore += 2;
  }
  
  // 6. Check request timing patterns
  if (hasAbnormalTimingPattern(req.sessionId)) {
    signals.suspicious++;
    signals.maxScore += 2;
  }
  
  // 7. Check gzip compression handling
  if (!req.headers['accept-encoding']?.includes('gzip')) {
    signals.suspicious++;
    signals.maxScore += 1;
  }
  
  return {
    suspiciousSignals: signals.suspicious,
    automationScore: signals.maxScore,
    likelyAutomated: signals.maxScore >= 5
  };
}

// Response: Block or challenge automated requests
if (automationAnalysis.likelyAutomated) {
  // Option 1: Block entirely
  if (automationAnalysis.automationScore >= 8) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Option 2: Rate limit aggressively
  if (automationAnalysis.automationScore >= 5) {
    const limitedQuota = 5; // vs normal 50
    checkRateLimitStrict(req, limitedQuota);
  }
  
  // Option 3: Challenge with CAPTCHA
  return res.status(403).json({
    error: 'Challenge required',
    challenge: 'captcha',
    challengeId: generateChallenge()
  });
}
```

### 8.2 Known CDNs (Legitimate)

```javascript
const KNOWN_CDNS = {
  'cloudflare': ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22'],
  'vercel': ['34.64.0.0/10', '34.65.0.0/16'],
  'akamai': ['95.100.128.0/11'],
  'fastly': ['23.235.32.0/20', '43.249.72.0/21']
};

function isKnownCDN(ip) {
  // Check if IP belongs to known CDN ranges
  for (const [cdn, ranges] of Object.entries(KNOWN_CDNS)) {
    if (ranges.some(range => isIPInRange(ip, range))) {
      return true;
    }
  }
  return false;
}
```

---

## 9. Implementation Checklist

### Frontend Security
- [ ] No hardcoded secrets or API keys
- [ ] All requests go through secure request helper
- [ ] HMAC signature on every request
- [ ] Timestamp + nonce validation
- [ ] Response signature verification
- [ ] No caching of sensitive responses
- [ ] Clear sensitive data from memory

### Backend Security
- [ ] HTTPS enforced (HSTS headers)
- [ ] Session token validation
- [ ] Signature verification (constant-time)
- [ ] Replay attack detection
- [ ] Multi-layer rate limiting
- [ ] Request fingerprinting
- [ ] Discord API calls via proxy only
- [ ] Comprehensive logging & monitoring
- [ ] Bot detection heuristics

### Infrastructure
- [ ] Vercel security headers configured
- [ ] WAF (Web Application Firewall) enabled
- [ ] DDoS protection active
- [ ] Redis for rate limit & nonce store
- [ ] Secrets in environment variables
- [ ] CORS properly configured
- [ ] CSP headers set

---

## 10. Security Headers Reference

```javascript
// All responses should include:
res.set({
  // Prevent MIME type sniffing
  'X-Content-Type-Options': 'nosniff',
  
  // Prevent clickjacking
  'X-Frame-Options': 'DENY',
  
  // HTTPS enforcement
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  
  // Disable caching of sensitive data
  'Cache-Control': 'no-cache, no-store, must-revalidate',
  'Pragma': 'no-cache',
  'Expires': '0',
  
  // Content Security Policy
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'",
  
  // Cross-origin protections
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  
  // Remove server identification
  'Server': 'SecureServer/1.0'
});
```

---

## 11. Monitoring & Alerting

```javascript
// Log suspicious activity
function logSecurityEvent(eventType, details) {
  const event = {
    timestamp: Date.now(),
    type: eventType,
    details,
    severity: calculateSeverity(eventType)
  };
  
  // Log to system
  logger.warn(`[SECURITY] ${eventType}`, event);
  
  // Alert on critical events
  if (event.severity === 'CRITICAL') {
    alertSecurityTeam(event);
  }
  
  // Store for analysis
  auditStore.insert(event);
}

// Event types to monitor
const EVENT_TYPES = {
  'REPLAY_DETECTED': 'critical',
  'RATE_LIMIT_EXCEEDED': 'warning',
  'INVALID_SIGNATURE': 'critical',
  'AUTOMATION_DETECTED': 'warning',
  'PROXY_DETECTED': 'info',
  'TOKEN_INVALID': 'info',
  'UNUSUAL_PATTERN': 'warning'
};
```

---

## Conclusion

This architecture implements **defense in depth** with multiple independent security layers:

1. **Transport security** (HTTPS/HSTS)
2. **Request authentication** (HMAC signatures)
3. **Replay protection** (timestamps + nonces)
4. **Rate limiting** (IP, session, fingerprint)
5. **Backend validation** (server-side business logic)
6. **Response integrity** (signature verification)
7. **Automation detection** (behavioral analysis)

No single point of failure can compromise the entire system. Even if one layer is bypassed, others remain effective.
