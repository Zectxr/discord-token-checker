# Quick Security Reference Guide

## 🎯 Implementation Priority

### Phase 1: Critical (Do First)
1. **HTTPS Enforcement** - Configure HSTS headers
2. **Backend Validation** - Move token checking to backend only
3. **HMAC Signatures** - Implement request signing
4. **Session Management** - Create session service

### Phase 2: Important (Do Next)
5. **Replay Protection** - Add nonce + timestamp validation
6. **Rate Limiting** - Implement multi-layer rate limiting
7. **Response Signing** - Sign responses for integrity

### Phase 3: Enhanced Security (Polish)
8. **Bot Detection** - Add automation detection
9. **Security Logging** - Comprehensive audit trails
10. **CAPTCHA** - Optional challenge system

---

## 🔐 Security Best Practices

### Frontend (React)
```javascript
✅ DO:
- Use secure request client (SecureClient.js)
- Validate token format before sending
- Clear sensitive data from DOM
- Store session in sessionStorage only
- Verify response signatures
- Use HTTPS only

❌ DON'T:
- Store tokens in localStorage
- Hardcode API URLs
- Trust frontend validation
- Send secrets to localStorage/cookies
- Skip response verification
- Use HTTP for any API calls
```

### Backend (Node.js)
```javascript
✅ DO:
- Validate ALL inputs on backend
- Use constant-time comparison for signatures
- Implement replay protection (nonces)
- Rate limit aggressively
- Log security events
- Use environment variables for secrets

❌ DON'T:
- Trust request signatures alone
- Skip timestamp validation
- Allow unlimited requests
- Log sensitive data
- Hardcode secrets in code
- Skip response signing
```

---

## 📊 Attack Prevention Matrix

| Attack | Frontend Defenses | Backend Defenses | Result |
|--------|------------------|------------------|--------|
| **MITM** | HTTPS only | HSTS headers | 🛡️ Prevented |
| **Replay** | Client validation | Nonce + timestamp | 🛡️ Prevented |
| **Tampering** | N/A | HMAC signature | 🛡️ Prevented |
| **Frontend Bypass** | Input validation | Backend-only logic | 🛡️ Prevented |
| **Automated Abuse** | Rate limiting | Multi-layer rate limit | 🛡️ Prevented |

---

## 🚀 Quick Start

### 1. Setup Backend
```bash
npm install
# Create .env file
NODE_ENV=production
REDIS_URL=redis://localhost:6379
# ... other env vars
```

### 2. Setup Frontend
```bash
npm install
# Create .env.local
REACT_APP_API_URL=https://api.tokenchecker.app
```

### 3. Test Secure Flow
```javascript
import TokenCheckerAPI from './utils/SecureClient';

const api = new TokenCheckerAPI();
const result = await api.validateToken('discord_token_here');
```

---

## 🔍 Testing Security

### Test 1: Request Tampering
```javascript
// Modify request body before sending
// ✅ Should fail: "Invalid signature"
```

### Test 2: Replay Attack
```javascript
// Capture and resend same request
// ✅ Should fail: "Nonce already used"
```

### Test 3: Rate Limiting
```javascript
// Send 15 requests in 60 seconds from same IP
// ✅ Should fail: "Rate limit exceeded"
```

### Test 4: Frontend Bypass
```javascript
// Call backend API directly with forged session
// ✅ Should fail: "Invalid session token"
```

### Test 5: Automation Detection
```javascript
// Send requests from headless browser
// ✅ Should fail or require CAPTCHA
```

---

## 📈 Monitoring Checklist

- [ ] Monitor failed authentication attempts
- [ ] Track rate limit violations
- [ ] Alert on signature verification failures
- [ ] Monitor for replay attack attempts
- [ ] Track bot detection signals
- [ ] Review security logs daily
- [ ] Monitor server resources
- [ ] Check Discord API limits
- [ ] Validate certificate expiration

---

## 🔧 Troubleshooting

### Problem: "Invalid signature"
**Cause**: Request body was modified in transit
**Solution**: 
- Check HTTPS is enforced
- Verify requestKey is not rotated
- Check timestamp/nonce are correct

### Problem: "Nonce already used"
**Cause**: Duplicate or replayed request
**Solution**:
- Client should generate new nonce each request
- Check Redis is working
- Verify TTL is set correctly

### Problem: "Session expired"
**Cause**: Session TTL expired
**Solution**:
- Create new session
- Increase SESSION_LIFETIME if needed

### Problem: "Rate limit exceeded"
**Cause**: Too many requests
**Solution**:
- Implement backoff strategy
- Check for bot/automated activity
- Reduce request frequency

---

## 🎓 Security Concepts Explained

### HMAC-SHA256 (Key-based hashing)
- **What**: Creates hash of data using secret key
- **Why**: Proves data wasn't tampered AND came from backend
- **How**: HMAC_SHA256(secret, message)

### Nonce (Number used once)
- **What**: Unique value per request
- **Why**: Prevents replay attacks (can't reuse same value)
- **How**: Generate random UUID per request, check not in Redis

### Timestamp Binding
- **What**: Include request time in signature
- **Why**: Prevents old intercepted requests being replayed
- **How**: Reject requests outside 5-minute window

### Rate Limiting Layers
- **Layer 1 (IP)**: 10/min - Blocks simple abuse
- **Layer 2 (Session)**: 100/hour - Prevents account abuse
- **Layer 3 (Fingerprint)**: 20/min - Detects distributed attacks

### Device Fingerprinting
- **What**: Hash of browser headers + IP
- **Why**: Identifies client device, prevents hijacking
- **How**: Hash user-agent, accept-language, IP together

---

## 📚 Key Files Reference

| File | Purpose |
|------|---------|
| `SECURITY_ARCHITECTURE.md` | Full architecture overview |
| `BACKEND_IMPLEMENTATION.md` | Backend code & setup |
| `BYPASS_ATTEMPTS.md` | Attack vectors & defenses |
| `src/utils/SecureClient.js` | Secure React client |
| `src/SecureApp.jsx` | Secure React component |

---

## 🆘 When to Call Security Team

- Repeated failed authentication attempts from same IP
- Multiple rate limit violations
- Signature verification failures
- Suspected bot activity
- Unusual geographic access patterns
- Certificate validation failures
- Database anomalies

---

## 📖 Further Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/nodejs-security/)
- [Discord API Security](https://discord.com/developers/docs/intro)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

