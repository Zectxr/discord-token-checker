# **Security Anti-Patterns Guide**

## **What NOT to Build - Common Mistakes in Token Checking Apps**

This guide explains security vulnerabilities and why they're dangerous.

---

## **Category 1: Token Handling Anti-Patterns**

### **❌ Anti-Pattern 1.1: Token Input Form**

```javascript
// BAD - Classic mistake
<input 
  type="text"
  placeholder="Enter your Discord token"
  value={token}
  onChange={(e) => setToken(e.target.value)}
/>
```

**Problems:**
1. Token visible on screen (shoulder surfer can see it)
2. Token stored in React state (accessible via DevTools)
3. Token copied to clipboard if user copy-pastes
4. No warning about the danger
5. Phishing-vulnerable (looks like any login form)

**Solution:**
```javascript
// GOOD - Use OAuth2 instead
<button onClick={() => startOAuthFlow()}>
  Login with Discord
</button>
```

---

### **❌ Anti-Pattern 1.2: Token in URL**

```javascript
// BAD
window.location = `https://yoursite.com/check?token=${userToken}`;

// or
fetch(`https://yoursite.com/api/check?token=${userToken}`);
```

**Problems:**
1. Token in browser history
2. Token in HTTP referer headers
3. Token in proxy/CDN logs
4. Token in browser autocomplete
5. Anyone with access to browser sees it

**Solution:**
```javascript
// GOOD - Use POST body and HTTPS
fetch('https://yoursite.com/api/check', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: userToken })
});
```

---

### **❌ Anti-Pattern 1.3: Token in Cookies Without Secure Flag**

```javascript
// BAD
document.cookie = `token=${accessToken}`;
```

**Problems:**
1. Accessible from JavaScript (XSS vulnerability)
2. Can be read by other scripts
3. Sent over HTTP if not marked Secure
4. Sent in cross-origin requests if not marked SameSite

**Solution:**
```javascript
// GOOD - Use HttpOnly cookies (backend sets this)
// Server: Set-Cookie: token=xyz; HttpOnly; Secure; SameSite=Strict
// Frontend: cannot access this cookie
```

---

### **❌ Anti-Pattern 1.4: Logging Tokens**

```javascript
// BAD
console.log('Checking token:', token);
logger.info('Token received:', token);
Analytics.track('token_check', { token });
```

**Problems:**
1. Tokens appear in browser console (visible in DevTools)
2. Tokens sent to logging service (leaked to third party)
3. Tokens in production logs (multiple access points)
4. Tokens in error reporting (Sentry, Rollbar, etc.)

**Solution:**
```javascript
// GOOD - Never log tokens
console.debug('Checking token'); // No token in message
logger.info('Token check started'); // Generic message
Analytics.track('token_check', { status: 'started' }); // No token
```

---

## **Category 2: Storage Anti-Patterns**

### **❌ Anti-Pattern 2.1: Token in LocalStorage**

```javascript
// BAD
localStorage.setItem('discord_token', accessToken);

// Later:
const token = localStorage.getItem('discord_token');
```

**Problems:**
1. Any XSS attack steals the token
2. Token persists forever
3. Anyone with device access gets it
4. No expiration handling
5. Not cleared on logout properly

**Solution:**
```javascript
// GOOD - Keep in memory only
const [token, setToken] = useState(null); // Memory only

// On logout:
setToken(null); // Cleared from memory
```

---

### **❌ Anti-Pattern 2.2: Token in SessionStorage**

```javascript
// BAD (slightly better than localStorage, but still risky)
sessionStorage.setItem('token', accessToken);
```

**Problems:**
1. Still vulnerable to XSS
2. Persists across tab closes
3. Accessible from any page on same domain
4. No protection from sophisticated attacks

**Solution:**
```javascript
// GOOD - Memory only + automatic cleanup
useEffect(() => {
  return () => {
    // Cleanup on unmount - token cleared from memory
    setToken(null);
  };
}, []);
```

---

### **❌ Anti-Pattern 2.3: Token in IndexedDB**

```javascript
// BAD
const db = indexedDB.open('discordTokens');
db.onsuccess = (e) => {
  e.target.result.add({ token: accessToken });
};
```

**Problems:**
1. Persistent storage (survives app restart)
2. Vulnerable to XSS
3. Can be queried by other scripts
4. Not encrypted by default

**Solution:**
```javascript
// GOOD - If you must persist, encrypt it
const encrypted = await crypto.encryptToken(token, userPassword);
localStorage.setItem('token', encrypted); // Only encrypted version
```

---

## **Category 3: API Call Anti-Patterns**

### **❌ Anti-Pattern 3.1: Custom Headers with Tokens**

```javascript
// BAD
fetch('https://discord.com/api/users/@me', {
  headers: {
    'Authorization': token,
    'X-API-Key': token, // Redundant
    'Custom-Header': token, // Wrong!
  }
});
```

**Problems:**
1. CORS will reject custom headers
2. Repeating token increases exposure
3. Non-standard headers rejected by Discord
4. Visible in network inspector

**Solution:**
```javascript
// GOOD - Standard Authorization header only
fetch('https://discord.com/api/v10/users/@me', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

---

### **❌ Anti-Pattern 3.2: No Error Handling**

```javascript
// BAD
const user = await fetch('https://discord.com/api/users/@me', {
  headers: { Authorization: token }
}).then(r => r.json());

// If request fails, token is still logged
```

**Problems:**
1. Token leaked in error messages
2. No fallback behavior
3. User sees cryptic errors
4. App crashes ungracefully

**Solution:**
```javascript
// GOOD - Proper error handling
try {
  const response = await fetch('https://discord.com/api/v10/users/@me', {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error('Invalid or expired token');
    }
    throw new Error('API error');
  }

  return await response.json();
} catch (error) {
  console.error('Failed to fetch user (no token logged)');
  throw error;
}
```

---

### **❌ Anti-Pattern 3.3: Sending Token to Wrong Domain**

```javascript
// BAD
fetch('https://suspicious-analytics.com/track', {
  method: 'POST',
  body: JSON.stringify({ token, action: 'check' })
});
```

**Problems:**
1. Token sent to third-party server
2. Third party now has full access to user's account
3. Third party could sell token
4. Data breach on analytics service exposes tokens

**Solution:**
```javascript
// GOOD - Only send to your own backend
fetch('https://tokencords.vercel.app/api/analyze', {
  method: 'POST',
  body: JSON.stringify({ action: 'check' }) // No token!
});

// Backend uses token from secure header
```

---

## **Category 4: Architecture Anti-Patterns**

### **❌ Anti-Pattern 4.1: Frontend Token Exchange**

```javascript
// BAD - Token exchange visible in frontend
const exchangeToken = async (authCode) => {
  const response = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    body: new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET, // ❌ EXPOSED!
      code: authCode,
    })
  });
  return response.json();
};
```

**Problems:**
1. Client secret visible in JavaScript bundle
2. Anyone can download and read the secret
3. Attacker can impersonate your app
4. Full access to user accounts

**Solution:**
```javascript
// GOOD - Token exchange on backend only
// Frontend sends auth code to backend
const response = await fetch('/api/discordOAuth', {
  method: 'POST',
  body: JSON.stringify({ code: authCode })
});

// Backend (Vercel Function):
// - Keeps CLIENT_SECRET in environment variable
// - Exchanges code for token
// - Returns token to frontend safely
```

---

### **❌ Anti-Pattern 4.2: No Token Expiration**

```javascript
// BAD
const [token, setToken] = useState(accessToken);

// Token used forever
useEffect(() => {
  setInterval(() => {
    fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${token}` }
    });
  }, 60000);
}, [token]);
```

**Problems:**
1. Token can be used indefinitely if stolen
2. User can't revoke access remotely
3. Increased attack window
4. No automatic cleanup

**Solution:**
```javascript
// GOOD - Token expiration
const [tokenExpiry, setTokenExpiry] = useState(Date.now() + 3600000); // 1 hour

useEffect(() => {
  if (Date.now() > tokenExpiry) {
    console.log('Token expired, redirecting to login');
    startOAuthFlow();
  }
}, [tokenExpiry]);
```

---

### **❌ Anti-Pattern 4.3: No Scope Limitations**

```javascript
// BAD - Requesting all permissions
const scopes = ['identify', 'email', 'dm_channels.read', 
                'connections', 'webhook.incoming', 'bot'];

// Now we have access to EVERYTHING
```

**Problems:**
1. User can't control what we access
2. If your app is compromised, attacker gets full access
3. Violates principle of least privilege
4. Discord may reject overly broad scopes

**Solution:**
```javascript
// GOOD - Minimal necessary scopes
const scopes = ['identify', 'email']; // Only what we need

// If user doesn't trust the scopes, they won't login
// If your app is compromised, damage is limited
```

---

## **Category 5: User Experience Anti-Patterns**

### **❌ Anti-Pattern 5.1: No Warning on Token Paste**

```javascript
// BAD - Silently accepts pasted tokens
<textarea 
  onChange={(e) => setToken(e.target.value)}
/>
```

**Problems:**
1. User might accidentally paste token from Discord PM
2. No warning about the danger
3. User doesn't understand what they're doing
4. Token now stored in memory/history

**Solution:**
```javascript
// GOOD - Detect and warn
const handlePaste = useTokenPasteDetection((warning) => {
  e.preventDefault();
  showModal(warning.title, warning.message);
});

<textarea onPaste={handlePaste} />
```

---

### **❌ Anti-Pattern 5.2: No Revocation UI**

```javascript
// BAD - No way for user to revoke access
// User must go to Discord settings and find your app

// Good UX:
<button onClick={() => {
  logout(); // Clear local state
  // Notify backend to revoke token
  fetch('/api/revoke-token', { method: 'POST' });
  // Show: "You've been logged out. Access revoked."
}}>
  Logout & Revoke Access
</button>
```

**Problems:**
1. User doesn't know how to revoke
2. Token might persist server-side
3. User must manually find Discord settings
4. Poor security awareness

**Solution:**
```javascript
// GOOD - One-click logout
<button onClick={logout}>
  Logout
</button>

// Plus link to Discord settings:
<a href="https://discord.com/user/settings/authorized-apps">
  Manage connected apps
</a>
```

---

### **❌ Anti-Pattern 5.3: No Security Education**

```javascript
// BAD - Just takes the token, no context
"Enter your token to check your security"
```

**Problems:**
1. User doesn't understand why they shouldn't do this
2. User might use this pattern elsewhere
3. No security awareness gained
4. User blames themselves if account hacked

**Solution:**
```javascript
// GOOD - Educate as you go
"We use OAuth2 - your password stays on Discord, 
 we never ask for your token. Here's why that matters..."

// Show education component with:
// - Why tokens are dangerous
// - How OAuth2 protects them
// - What to avoid
// - Best practices
```

---

## **Category 6: Deployment Anti-Patterns**

### **❌ Anti-Pattern 6.1: Secrets in Code**

```javascript
// BAD - Pushed to Git
const DISCORD_CLIENT_SECRET = 'kJS8d8sjsk...';
const API_KEY = 'abc123...';

export const config = { DISCORD_CLIENT_SECRET, API_KEY };
```

**Problems:**
1. Visible in Git history forever
2. Anyone with repo access steals secrets
3. Can't change secrets without code release
4. Automatic scanning finds them

**Solution:**
```bash
# GOOD - Environment variables only
# Vercel Dashboard:
DISCORD_CLIENT_SECRET=kJS8d8sjsk...
API_KEY=abc123...

# .gitignore prevents .env commits
.env
.env.local
```

---

### **❌ Anti-Pattern 6.2: No HTTPS**

```javascript
// BAD - HTTP allows token interception
http://tokencords.vercel.app/check
```

**Problems:**
1. MITM attacker intercepts token in transit
2. ISP/network admin can see all tokens
3. Public WiFi = immediate compromise
4. Regulatory compliance violations

**Solution:**
```bash
# GOOD - Vercel enforces HTTPS automatically
https://tokencords.vercel.app/check

# Redirect HTTP to HTTPS
# vercel.json headers enforce this
```

---

### **❌ Anti-Pattern 6.3: No Security Headers**

```javascript
// BAD - No protections
// App deployed with default headers only
```

**Problems:**
1. XSS attacks can run freely
2. Clickjacking possible
3. Token sent over insecure connections
4. No content protection

**Solution:**
```json
// GOOD - Security headers in vercel.json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains"
        }
      ]
    }
  ]
}
```

---

## **Red Flags Checklist**

When reviewing security, ask:

- [ ] Is the token ever visible on screen?
- [ ] Is the token stored longer than necessary?
- [ ] Is the token sent over HTTP?
- [ ] Is the token logged anywhere?
- [ ] Is the client secret in frontend code?
- [ ] Is there error handling that leaks token info?
- [ ] Can users revoke access?
- [ ] Are scopes minimal?
- [ ] Is there user education?
- [ ] Are security headers set?
- [ ] Is HTTPS enforced?
- [ ] Are secrets in .gitignore?
- [ ] Is there token expiration?
- [ ] Can users see what permissions they granted?
- [ ] Is there a logout button?

If you answer "no" to any of these, you have a security issue. 🚨

---

## **Summary: The Security Pyramid**

```
        🔒 HTTPS
       🔐 OAuth2
      🛡️ Short-lived tokens
     💾 No storage
    🧠 User education
   📋 Security headers
  🚨 Error handling
 ♻️ Token rotation
🔑 Minimal scopes
```

Build from the bottom up. Don't skip levels. 🏗️

