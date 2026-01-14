# Common Bypass Attempts & Defense Strategies

This document outlines common attack vectors attackers use to compromise the token checker and the specific defenses implemented to prevent them.

---

## 1. MITM (Man-In-The-Middle) Attacks

### Attack Attempts

#### 1.1 HTTP Downgrade
```
Attacker: Intercepts HTTPS connection, downgrades to HTTP
Impact: All data including tokens exposed to eavesdropping
```

**Attacker Code:**
```javascript
// Proxy intercepts request
const response = await fetch('http://api.tokenchecker.app/validate', {
  method: 'POST',
  headers: { /* ... */ },
  body: tokenData
});
// All traffic visible to attacker
```

#### 1.2 SSL Stripping
```
Attacker: Removes HTTPS from response, modifies requests to HTTP
Impact: Creates fake "secure" connection that isn't
```

#### 1.3 Certificate Spoofing
```
Attacker: Issues fake SSL certificate for domain
Impact: Browser shows "secure" lock, traffic still exposed
```

### Defenses Implemented

#### Defense 1: HSTS (HTTP Strict Transport Security)
```javascript
// vercel.json - Enforced at edge
"headers": [
  {
    "key": "Strict-Transport-Security",
    "value": "max-age=31536000; includeSubDomains; preload"
  }
]
```

**How it works:**
- Browser caches this header for 1 year (31536000 seconds)
- All future requests **must** use HTTPS
- If attacker presents HTTP, browser refuses connection
- Can't downgrade even with DNS hijacking

**Verification:**
```javascript
// Frontend enforces
const API_URL = process.env.REACT_APP_API_URL;
if (!API_URL.startsWith('https://')) {
  throw new Error('SECURITY ERROR: Must use HTTPS');
}
```

#### Defense 2: Certificate Pinning (Optional)
```javascript
// For ultra-high security, pin certificate public key
const PINNED_CERT_HASH = 'sha256/AAAAAAA...';

async function validateCertificate(response) {
  // Verify certificate hash matches pinned value
  if (response.headers.get('X-Certificate-Hash') !== PINNED_CERT_HASH) {
    throw new Error('Certificate not pinned - possible MITM');
  }
}
```

#### Defense 3: TLS 1.3 Enforcement
```javascript
// Vercel automatically enforces TLS 1.3
// TLS 1.0/1.1/1.2 vulnerabilities mitigated:
// - BEAST attack (TLS 1.0)
// - POODLE attack (SSL 3.0 fallback)
// - CRIMES attack (compression-based)
```

#### Defense 4: HMAC Signature Verification
```javascript
// Even if attacker intercepts traffic, can't modify it
const message = timestamp + nonce + body;
const signature = HMAC_SHA256(secretKey, message);

// If attacker modifies body:
// signature = HMAC_SHA256(secretKey, MODIFIED_BODY) ≠ original
// Backend detects tampering immediately
```

---

## 2. Replay Attacks

### Attack Attempts

#### 2.1 Simple Request Replay
```javascript
// Attacker captures valid request
const validRequest = {
  method: 'POST',
  headers: {
    'X-Session-Token': 'abc123...',
    'X-Signature': 'def456...',
    'X-Request-Timestamp': '1705267200000',
    'X-Request-Nonce': 'xyz789...'
  },
  body: { token: 'discord_token_here' }
};

// Attacker replays 100 times
for (let i = 0; i < 100; i++) {
  fetch(API_URL, validRequest);
}
```

**Impact:** Bulk token validation without rate limiting, automated abuse

#### 2.2 Timestamp Forgery
```javascript
// Attacker changes timestamp
headers['X-Request-Timestamp'] = (Date.now() + 1000 * 60 * 60).toString(); // 1 hour in future

// Hopes to bypass freshness check
```

#### 2.3 Nonce Reuse
```javascript
// Attacker captures valid nonce
const nonce = 'a1b2c3d4e5f6...';

// Uses same nonce multiple times
for (let i = 0; i < 10; i++) {
  await sendRequest(nonce); // Reuse valid nonce
}
```

### Defenses Implemented

#### Defense 1: Timestamp Freshness Check
```javascript
// Backend validation
function verifyRequestFreshness(req) {
  const MAX_SKEW_MS = 5 * 60 * 1000; // 5 minutes
  const now = Date.now();
  const timestamp = parseInt(req.headers['x-request-timestamp']);
  
  // Check timestamp not too old
  if (now - timestamp > MAX_SKEW_MS) {
    throw new Error('Timestamp too old - replay detected');
  }
  
  // Check timestamp not in future (clock skew tolerance)
  if (timestamp - now > 30000) { // 30 seconds tolerance
    throw new Error('Timestamp in future - invalid request');
  }
  
  return true;
}
```

**Prevents:**
- Timestamp forgery (known window)
- Replays outside time window (automatic expiration)

#### Defense 2: Nonce-Based Replay Detection
```javascript
// Backend redis-backed nonce store
async function checkReplayProtection(nonce, sessionId) {
  const nonceKey = `nonce:${nonce}:${sessionId}`;
  const MAX_SKEW_MS = 5 * 60 * 1000;
  
  // Check if nonce exists (used before)
  const existingNonce = await redis.get(nonceKey);
  if (existingNonce) {
    logger.warn('Nonce reuse detected - replay attack', {
      nonce: nonce,
      sessionId: sessionId
    });
    throw new Error('Nonce already used');
  }
  
  // Store nonce with TTL = timestamp window
  await redis.setex(
    nonceKey,
    Math.ceil(MAX_SKEW_MS / 1000),
    Date.now()
  );
  
  return true;
}
```

**Prevents:**
- Immediate replay (nonce exists in store)
- Replay after expiration (TTL deletes old entries)
- Distributed replay (checks per-session)

#### Defense 3: Request Context Binding
```javascript
// Signature includes multiple context factors
const message = [
  timestamp,           // Changes every request
  nonce,              // Unique per request
  JSON.stringify(body), // Changes per request
  sessionId,          // Binds to session
  userFingerprint     // Binds to client device
].join('|');

const signature = HMAC_SHA256(requestKey, message);

// Attacker can't change signature without:
// 1. New valid nonce (only backend generates)
// 2. New valid timestamp (limited to 5-min window)
// 3. Matching requestKey (session secret)
// 4. Same device fingerprint (can't easily spoof)
```

**Attack complexity:** Extremely high - would need to recreate entire session + device context

#### Defense 4: Session Rotation
```javascript
// Sessions auto-expire and rotate keys
const SESSION_LIFETIME = 30 * 60 * 1000; // 30 minutes
const REQUEST_KEY_ROTATION = 5 * 60 * 1000; // 5 minutes

// After 5 minutes, requestKey changes
// Attacker's captured signature becomes invalid
// Even if replayed within time window, key no longer matches
```

---

## 3. Request Tampering

### Attack Attempts

#### 3.1 Body Modification
```javascript
// Attacker captures valid signed request
const validRequest = {
  body: { token: 'user_token_1' },
  signature: 'sig_for_user_token_1'
};

// Attacker modifies to check different token
validRequest.body.token = 'user_token_2'; // Changed!
// But signature still: sig_for_user_token_1
```

**Impact:** Bypass validation, check tokens other than intended

#### 3.2 Rate Limit Bypass via Parameter Injection
```javascript
// Attacker tries to inject rate limit parameters
const request = {
  token: 'some_token',
  ignoreRateLimit: true,  // ← Injection attempt
  priority: 'high'        // ← Another injection
};
```

#### 3.3 Session Token Forgery
```javascript
// Attacker generates fake session token
headers['X-Session-Token'] = 'forged_token_12345';

// Tries to send request with fake session
```

### Defenses Implemented

#### Defense 1: HMAC Signature Protection
```javascript
// Signature covers entire request
const message = `${timestamp}|${nonce}|${JSON.stringify(body)}|version`;
const signature = HMAC_SHA256(requestKey, message);

// Backend verification
const expectedSignature = HMAC_SHA256(requestKey, message);
if (signature !== expectedSignature) {
  throw new Error('Signature mismatch - tampering detected');
}
```

**Prevents:**
- ANY modification to body (signature becomes invalid)
- Parameter injection (not in signature scope)
- Replay with different body (new signature needed)

**Why this works:**
- Even single bit change in body changes HMAC completely
- Attacker can't forge signature without secret `requestKey`
- `requestKey` is session-specific and ephemeral

#### Defense 2: Strict Input Validation
```javascript
// Backend rejects unexpected parameters
app.post('/api/v1/tokens/validate', (req, res) => {
  // Only accept known fields
  const allowedFields = ['token'];
  const providedFields = Object.keys(req.body);
  
  const unexpectedFields = providedFields.filter(
    f => !allowedFields.includes(f)
  );
  
  if (unexpectedFields.length > 0) {
    logger.warn('Injection attempt detected', {
      unexpectedFields,
      sessionId: req.sessionId
    });
    return res.status(400).json({ error: 'Invalid request' });
  }
  
  // Continue processing only known fields
  const { token } = req.body;
  // ...
});
```

#### Defense 3: Session Token Validation
```javascript
// Backend maintains session registry
async function validateSessionToken(sessionToken) {
  // Look up session in database
  const session = await db.sessions.findOne({ token: sessionToken });
  
  if (!session) {
    throw new Error('Invalid session token');
  }
  
  // Check session expiration
  if (Date.now() > session.expiresAt) {
    await db.sessions.delete(session.id);
    throw new Error('Session expired');
  }
  
  // Check session not revoked
  if (session.revoked) {
    throw new Error('Session revoked');
  }
  
  return session;
}
```

**Prevents:**
- Forged session tokens (not in registry)
- Expired sessions (checked against TTL)
- Revoked sessions (logout invalidates)

#### Defense 4: Constant-Time Signature Comparison
```javascript
// Prevent timing attacks on signature verification
function constantTimeEquals(a, b) {
  if (a.length !== b.length) return false;
  
  let result = 0;
  // Compare ALL bytes, don't short-circuit
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  
  return result === 0;
}

// Usage
if (!constantTimeEquals(receivedSignature, expectedSignature)) {
  throw new Error('Invalid signature');
}
```

**Prevents:**
- Timing attacks where attacker measures response time to brute-force signatures
- With normal comparison: correct prefix matches faster than wrong prefix
- Constant-time: always takes same time regardless of match position

---

## 4. Frontend Bypass Attempts

### Attack Attempts

#### 4.1 Direct API Calls (Bypassing React)
```javascript
// Attacker calls backend API directly without React
// Expected: No session token → Rejected

// But attacker can create fake session
const fakeSessionToken = 'crafted_fake_token';

await fetch('https://api.tokenchecker.app/api/v1/tokens/validate', {
  method: 'POST',
  headers: {
    'X-Session-Token': fakeSessionToken,
    'X-Signature': 'crafted_signature',
    'X-Request-Timestamp': Date.now(),
    'X-Request-Nonce': 'crafted_nonce'
  },
  body: JSON.stringify({ token: 'target_token' })
});
```

#### 4.2 DevTools Manipulation
```javascript
// Attacker opens DevTools and:
// 1. Modifies request before sending
// 2. Reads sessionToken from memory
// 3. Copies XHR requests
// 4. Modifies response before JS processes it
```

#### 4.3 Service Worker Interception
```javascript
// Attacker installs service worker
// Intercepts and modifies all network requests
navigator.serviceWorker.register('malicious-sw.js');

// Or modifies responses:
self.addEventListener('fetch', (event) => {
  event.respondWith(async () => {
    const response = await fetch(event.request);
    const body = await response.json();
    body.results = [{ valid: true, token: 'hacked' }]; // Fake response
    return new Response(JSON.stringify(body));
  });
});
```

#### 4.4 Proxy Interception
```javascript
// Attacker routes traffic through proxy
// Example: Burp Suite, mitmproxy, Charles Proxy
// Modifies requests/responses in transit

mitmproxy:
  |
  ▼
[Browser] ← → [Proxy] ← → [Backend]
           ↓
     [Attacker intercepts & modifies]
```

### Defenses Implemented

#### Defense 1: Backend-Only Token Validation
```javascript
// Critical: Backend never trusts frontend decisions
// Frontend input is advisory only

// ❌ WRONG - Frontend decides if token is valid
if (token.length > 20 && token.includes('.')) {
  // Trust frontend validation
  return { valid: true };
}

// ✅ CORRECT - Backend always validates
async function validateToken(token) {
  // Verify format
  if (!isValidTokenFormat(token)) {
    return { valid: false };
  }
  
  // Query Discord API - authoritative source
  const response = await discordAPI.getUser(token);
  
  // Only Discord API result is trusted
  return {
    valid: response.status === 200,
    details: response.data || null
  };
}
```

**Impact:**
- Attacker can't fake validation results
- Direct API calls still require valid token + valid signature
- DevTools modification doesn't change backend logic

#### Defense 2: Session Binding to Client
```javascript
// Session is bound to specific client context
const session = {
  token: sessionToken,
  clientFingerprint: hashFingerprint({
    userAgent: req.headers['user-agent'],
    acceptLanguage: req.headers['accept-language'],
    acceptEncoding: req.headers['accept-encoding'],
    ipAddress: req.ip
  }),
  createdAt: Date.now(),
  expiresAt: Date.now() + 30 * 60 * 1000
};

// Verify client context matches
function verifyClientContext(req, session) {
  const currentFingerprint = hashFingerprint({
    userAgent: req.headers['user-agent'],
    acceptLanguage: req.headers['accept-language'],
    acceptEncoding: req.headers['accept-encoding'],
    ipAddress: req.ip
  });
  
  if (currentFingerprint !== session.clientFingerprint) {
    throw new Error('Client context mismatch - session hijacking detected');
  }
}
```

**Prevents:**
- Session token theft (unusable from different device/IP)
- Service worker from modifying requests (changes fingerprint)
- Proxy interception (different source IP)

#### Defense 3: Response Signature Verification
```javascript
// Frontend verifies response came from backend (not proxy)
// Proxy can't forge signature without secret responseKey

const responseData = { valid: true, username: 'user' };
const timestamp = Date.now();
const signature = HMAC_SHA256(responseKey, JSON.stringify(responseData) + timestamp);

// Response headers include:
// X-Response-Signature: signature
// X-Response-Timestamp: timestamp

// Frontend verification
try {
  await RequestSigner.verifyResponseSignature(
    responseData,
    signature,
    timestamp,
    session.responseKey
  );
  // Trust response
} catch (error) {
  throw new Error('Response tampering detected');
}
```

**Prevents:**
- Proxy injecting fake "valid: true" responses
- Attacker reading real response and modifying it
- Service worker intercepting and changing results

#### Defense 4: Timing Analysis & Device Fingerprinting
```javascript
// Backend detects request patterns inconsistent with browser

function detectAutomation(req) {
  const signals = [];
  
  // Browser header analysis
  if (!req.headers['accept'] || !req.headers['user-agent']) {
    signals.push('missing_browser_headers');
  }
  
  // Check for headless browser
  if (req.headers['user-agent'].includes('HeadlessChrome')) {
    signals.push('headless_chrome_detected');
  }
  
  // Check request timing
  const sessionTimings = getSessionRequestTimings(req.sessionId);
  if (sessionTimings.avgDelay < 100) { // Suspiciously fast
    signals.push('unnaturally_fast_requests');
  }
  
  // Check for automation libraries
  if (req.body.__automation === true) { // Selenium inserts this
    signals.push('automation_marker_detected');
  }
  
  if (signals.length >= 2) {
    return {
      likelyAutomated: true,
      action: 'block_or_challenge'
    };
  }
}

// Response: Block automated requests
if (detectAutomation(req).likelyAutomated) {
  return res.status(403).json({
    error: 'Access denied - suspicious activity',
    challenge: 'captcha'
  });
}
```

---

## 5. Automated Abuse

### Attack Attempts

#### 5.1 Bulk Token Validation via Bot
```javascript
// Attacker creates bot to check thousands of tokens
const tokens = loadTokenListFromFile('tokens.txt'); // 10,000 tokens

for (const token of tokens) {
  try {
    const result = await fetch(API_URL, {
      method: 'POST',
      body: JSON.stringify({ token })
    });
    const data = await result.json();
    if (data.valid) {
      saveValidToken(token); // Collect working tokens
    }
  } catch (e) {
    // Ignore errors
  }
}
```

**Impact:** Bulk compromise of Discord accounts

#### 5.2 Distributed Attack (Multiple IPs)
```javascript
// Attacker uses botnet or cloud proxies
const proxies = ['proxy1:8080', 'proxy2:8080', ...]; // 100 proxies

for (const proxy of proxies) {
  // Each proxy rotates IP
  // Rate limits reset per IP
  // Bypasses IP-based rate limiting
}
```

#### 5.3 Slow Distributed Attack
```javascript
// Attacker spreads requests over time/IPs to stay under radar
const TOKENS = ['token1', 'token2', ...];
const INTERVAL = 60000; // 1 request per minute
const PROXIES = getRotatingProxies();

setInterval(async () => {
  const token = TOKENS.shift();
  const proxy = PROXIES.rotate();
  
  await checkToken(token, proxy);
  // Slow enough to avoid rate limits?
}, INTERVAL);
```

### Defenses Implemented

#### Defense 1: Multi-Layer Rate Limiting
```javascript
// Layer 1: IP-based
async function checkIPRateLimit(ipAddress) {
  const key = `ratelimit:ip:${ipAddress}`;
  const count = await redis.incr(key);
  
  if (count === 1) {
    await redis.expire(key, 60); // 60 second window
  }
  
  const MAX_PER_MINUTE = 10;
  if (count > MAX_PER_MINUTE) {
    throw new RateLimitError(429, 'Rate limit exceeded');
  }
}

// Layer 2: Session-based (prevents account abuse)
async function checkSessionRateLimit(sessionId) {
  const key = `ratelimit:session:${sessionId}`;
  const count = await redis.incr(key);
  
  if (count === 1) {
    await redis.expire(key, 3600); // 1 hour window
  }
  
  const MAX_PER_HOUR = 100;
  if (count > MAX_PER_HOUR) {
    throw new RateLimitError(429, 'Session limit exceeded');
  }
}

// Layer 3: Fingerprint-based (detects distributed attacks)
async function checkFingerprintRateLimit(fingerprint) {
  const key = `ratelimit:fingerprint:${fingerprint}`;
  const count = await redis.incr(key);
  
  if (count === 1) {
    await redis.expire(key, 60);
  }
  
  const MAX_PER_MINUTE = 20;
  if (count > MAX_PER_MINUTE) {
    throw new RateLimitError(429, 'Too many similar requests');
  }
}
```

**Prevents:**
- Layer 1: Single IP bulk requests (10/min limit)
- Layer 2: Account abuse (100/hour limit)
- Layer 3: Botnet attacks (20/min with same fingerprint)

#### Defense 2: Adaptive Rate Limiting
```javascript
// Aggressively rate limit suspicious activity
function getAdaptiveRateLimit(req) {
  let baseLimit = 10; // Requests per minute
  
  // Factor in automation score
  const automationScore = analyzeRequestForAutomation(req);
  if (automationScore > 3) {
    baseLimit = 1; // Very strict for likely bots
  }
  
  // Factor in historical behavior
  const sessionHistory = getSessionHistory(req.sessionId);
  if (sessionHistory.suspiciousCount > 5) {
    baseLimit = 0; // Block suspicious sessions
  }
  
  // Factor in geographic anomalies
  if (isAnomalousLocation(req)) {
    baseLimit = Math.floor(baseLimit / 2); // Halve limit
  }
  
  return baseLimit;
}
```

#### Defense 3: Behavioral Analysis
```javascript
// Detect patterns of automated attacks
function detectBotnetBehavior(sessionId) {
  const requests = getRecentRequests(sessionId, 300000); // Last 5 min
  
  const indicators = {
    perfectTiming: 0,
    uniformErrors: 0,
    noHumanPause: 0,
    payloadPattern: 0
  };
  
  // Check for perfect intervals (bots are predictable)
  const intervals = [];
  for (let i = 1; i < requests.length; i++) {
    intervals.push(requests[i].timestamp - requests[i-1].timestamp);
  }
  
  const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
  const variance = intervals.reduce((sum, x) => sum + Math.pow(x - avgInterval, 2)) / intervals.length;
  
  if (variance < 100) { // Very regular intervals
    indicators.perfectTiming++;
  }
  
  // Check for uniform errors (all invalid, all valid)
  const results = requests.map(r => r.result);
  const validCount = results.filter(r => r.valid).length;
  const invalidCount = results.filter(r => !r.valid).length;
  
  if (validCount === 0 || invalidCount === 0) {
    indicators.uniformErrors++;
  }
  
  // Check for no human pauses (humans occasionally wait)
  const longPauses = intervals.filter(i => i > 5000).length;
  if (longPauses === 0 && requests.length > 10) {
    indicators.noHumanPause++;
  }
  
  // Check for repeated token patterns
  const uniqueTokens = new Set(requests.map(r => r.token));
  if (uniqueTokens.size < requests.length * 0.5) {
    indicators.payloadPattern++;
  }
  
  const totalIndicators = Object.values(indicators).reduce((a, b) => a + b);
  
  return {
    likelyBot: totalIndicators >= 2,
    indicators,
    confidence: totalIndicators / 4
  };
}

// Response: Block detected bots
if (detectBotnetBehavior(req.sessionId).likelyBot) {
  logger.warn('Bot activity detected', {
    sessionId: req.sessionId,
    indicators: botAnalysis.indicators
  });
  
  return res.status(403).json({
    error: 'Access denied - suspicious activity detected',
    action: 'contact_support'
  });
}
```

#### Defense 4: Rotating Secrets & Session Invalidation
```javascript
// Secrets rotate frequently to prevent exploitation
const SESSION_CONFIG = {
  lifetime: 30 * 60 * 1000, // 30 minutes
  requestKeyRotation: 5 * 60 * 1000, // 5 minutes
  responseKeyRotation: 5 * 60 * 1000
};

// If abuse is detected, revoke session immediately
async function revokeSession(sessionId) {
  const session = await db.sessions.findById(sessionId);
  session.revoked = true;
  session.revokedReason = 'Abuse detected';
  session.revokedAt = Date.now();
  
  await db.sessions.update(session);
  
  // Clear all nonces for this session
  await redis.del(`nonce:*:${sessionId}`);
  
  // Log security event
  logger.warn('Session revoked for abuse', { sessionId });
}
```

#### Defense 5: CAPTCHA for Suspicious Activity
```javascript
// Challenge suspicious requests with CAPTCHA
if (automationScore > 5 || rateViolations > 3) {
  return res.status(403).json({
    error: 'Challenge required',
    challengeType: 'captcha',
    challengeId: generateChallengeId(),
    captchaProvider: 'hcaptcha' // Privacy-focused alternative
  });
}

// After CAPTCHA verification, continue
app.post('/api/v1/challenge/verify', async (req, res) => {
  const { challengeId, captchaToken } = req.body;
  
  // Verify with hCaptcha
  const verified = await verifyCaptcha(captchaToken);
  
  if (!verified) {
    return res.status(400).json({ error: 'Challenge failed' });
  }
  
  // Mark session as verified
  const session = await db.sessions.findByChallengeId(challengeId);
  session.captchaVerified = true;
  session.captchaVerifiedAt = Date.now();
  
  await db.sessions.update(session);
  
  res.json({ success: true });
});
```

---

## 6. Response Tampering & Fake Results

### Attack Attempts

#### 6.1 Proxy Response Modification
```javascript
// Proxy intercepts response, modifies it
// Original: { valid: false }
// Modified: { valid: true }

// Attacker can then claim tokens are valid
```

#### 6.2 Local Response Interception
```javascript
// JavaScript intercepts fetch response before processing
const originalFetch = fetch;

fetch = function(...args) {
  return originalFetch(...args).then(response => {
    // Clone and modify response
    const clone = response.clone();
    clone.json().then(data => {
      data.valid = true; // Lie about validity
      // ... return modified response
    });
  });
};
```

### Defenses Implemented

#### Defense 1: Response Signature Verification
```javascript
// Every response is signed with ephemeral responseKey
const responseData = { valid: true, username: 'user' };
const timestamp = Date.now();

// Backend signs response
const signature = HMAC_SHA256(responseKey, JSON.stringify(responseData) + timestamp);

// Response headers:
// X-Response-Signature: signature
// X-Response-Timestamp: timestamp

// Frontend verification (in SecureClient.js)
async function verifyResponseSignature(responseData, signature, timestamp, responseKey) {
  // Verify signature (Attacker can't forge without responseKey)
  const expectedSignature = await hmacSha256(responseKey, JSON.stringify(responseData) + timestamp);
  
  if (signature !== expectedSignature) {
    throw new Error('Response tampering detected');
  }
  
  // Verify timestamp freshness
  const age = Date.now() - timestamp;
  if (age > 30000) {
    throw new Error('Response too old - possible replay');
  }
}
```

#### Defense 2: Timestamp Binding
```javascript
// Response timestamp must be recent
// Prevents attackers from using old valid responses

const MAX_RESPONSE_AGE = 30000; // 30 seconds

if (Date.now() - responseTimestamp > MAX_RESPONSE_AGE) {
  throw new Error('Response expired - possible tampering');
}
```

---

## Summary: Defense Layers

```
┌─────────────────────────────────────────┐
│ 1. TRANSPORT (HTTPS/HSTS)               │
│    └─ Prevents: MITM, eavesdropping     │
├─────────────────────────────────────────┤
│ 2. REQUEST AUTHENTICATION (HMAC)        │
│    └─ Prevents: Tampering, forgery      │
├─────────────────────────────────────────┤
│ 3. REPLAY PROTECTION (Nonce+Timestamp)  │
│    └─ Prevents: Replay, reuse           │
├─────────────────────────────────────────┤
│ 4. BACKEND VALIDATION                   │
│    └─ Prevents: Frontend bypass         │
├─────────────────────────────────────────┤
│ 5. RATE LIMITING (Multi-layer)          │
│    └─ Prevents: Automated abuse         │
├─────────────────────────────────────────┤
│ 6. RESPONSE INTEGRITY (Signature)       │
│    └─ Prevents: Response tampering      │
├─────────────────────────────────────────┤
│ 7. BEHAVIORAL ANALYSIS                  │
│    └─ Prevents: Bot attacks             │
├─────────────────────────────────────────┤
│ 8. MONITORING & ALERTING                │
│    └─ Prevents: Undetected attacks      │
└─────────────────────────────────────────┘
```

**No single point of failure** - compromising one layer doesn't compromise others.

