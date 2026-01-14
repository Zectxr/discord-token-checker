## **Discord Account Security Checker - OAuth2 Implementation**

### **Overview**

This document explains the OAuth2-based security checker system that protects user tokens and privacy.

---

## **Architecture**

```
┌─────────────────────┐
│   User's Browser    │
│   (React App)       │
└──────────┬──────────┘
           │
           │ "Login with Discord"
           ▼
┌─────────────────────┐
│ Discord OAuth2      │
│ Authorization       │
│ (discord.com)       │
└──────────┬──────────┘
           │
           │ Authorization Code
           ▼
┌─────────────────────┐
│ Vercel Function     │
│ /api/discordOAuth   │
│ (Backend)           │
└──────────┬──────────┘
           │
           │ Token Exchange (Secret)
           ▼
┌─────────────────────┐
│ Discord API v10     │
│ OAuth2 Token        │
│ (discord.com)       │
└──────────┬──────────┘
           │
           │ Access Token
           ▼
┌─────────────────────┐
│ React App           │
│ Calls Discord API   │
│ with Access Token   │
└─────────────────────┘
```

---

## **OAuth2 Flow Explained**

### **Step 1: User Clicks "Login with Discord"**

```javascript
const authUrl = new URL('https://discord.com/api/oauth2/authorize');
authUrl.searchParams.append('client_id', DISCORD_CLIENT_ID);
authUrl.searchParams.append('redirect_uri', 'https://tokencords.vercel.app/oauth-callback');
authUrl.searchParams.append('response_type', 'code');
authUrl.searchParams.append('scope', 'identify email');

window.location.href = authUrl.toString();
```

**What happens:**
- User is redirected to **official Discord login page**
- User logs in with their username/password
- Discord asks for permission (what data can we access?)
- User approves and is redirected back with an `authorization code`

### **Step 2: Exchange Code for Token (Backend)**

```javascript
// In Vercel Function (/api/discordOAuth)
const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
  method: 'POST',
  body: new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    client_secret: DISCORD_CLIENT_SECRET,  // NEVER expose this
    code: authCode,
    grant_type: 'authorization_code',
    redirect_uri: REDIRECT_URI,
  })
});
```

**Why this is important:**
- The `client_secret` is kept on the backend ONLY
- Frontend never sees the authorization code → token exchange
- This prevents attackers from intercepting the code

### **Step 3: Use Token Securely**

```javascript
// Frontend can now call Discord API
const response = await fetch('https://discord.com/api/v10/users/@me', {
  headers: { Authorization: `Bearer ${accessToken}` }
});
```

**Token lifecycle:**
- ✅ Token only exists in memory (not stored)
- ✅ Token is only used for the API call
- ✅ Token expires after a period (can't be reused forever)
- ✅ User can revoke at any time in Discord settings

---

## **Why OAuth2 is Better Than Tokens**

| Aspect | Manual Token | OAuth2 |
|--------|-------------|--------|
| **Password Safety** | User must type password into our app ❌ | Password never leaves Discord ✅ |
| **Token Exposure** | Token visible on screen ❌ | Token never shown to user ✅ |
| **Scope Control** | We can do ANYTHING ❌ | User controls what we can access ✅ |
| **Revocation** | User must regenerate password ❌ | User can revoke in one click ✅ |
| **Phishing Risk** | High (looks like login) ❌ | Low (official Discord domain) ✅ |
| **Token Replay** | Attacker can use it forever ❌ | Token expires automatically ✅ |

---

## **Token-Paste Detection**

The app detects when users try to paste Discord tokens and **prevents** the paste with a warning:

```javascript
// Patterns we detect
const botToken = /^[MN][A-Za-z\d_-]{24,25}\.[\w-]{6,7}\.[\w-]{27,38}$/;
const userToken = /^[\w-]{26}\.[\w-]{6}\.[\w-]{25,35}$/;

// When user tries to paste:
const risk = TokenPasteDetection.getRiskLevel(pastedText);
if (risk.level !== 'SAFE') {
  e.preventDefault(); // Block paste
  showWarning(TokenPasteDetection.createWarning(risk));
}
```

**Warnings shown:**
- 🚨 **CRITICAL**: "This is a Bot/User Token! Never paste tokens anywhere!"
- ⚠️ **WARNING**: "This might be sensitive data"

---

## **Setup Instructions**

### **1. Get Discord OAuth2 Credentials**

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Go to "OAuth2" → "General"
4. Copy **Client ID** and **Client Secret**
5. Add redirect URL: `https://tokencords.vercel.app/oauth-callback`

### **2. Set Environment Variables**

**In Vercel Dashboard:**

```bash
DISCORD_CLIENT_ID=your_client_id_here
DISCORD_CLIENT_SECRET=your_client_secret_here
DISCORD_REDIRECT_URI=https://tokencords.vercel.app/oauth-callback
```

**In `.env.local` (development):**

```bash
REACT_APP_DISCORD_CLIENT_ID=your_client_id_here
REACT_APP_DISCORD_REDIRECT_URI=http://localhost:5173/oauth-callback
```

### **3. Update App Component**

In `main.jsx`:

```javascript
import { OAuthProvider } from './context/OAuthContext';
import AppOAuth from './components/AppOAuth';

ReactDOM.createRoot(document.getElementById('root')).render(
  <OAuthProvider>
    <AppOAuth />
  </OAuthProvider>
);
```

### **4. Deploy to Vercel**

```bash
vercel --prod
```

---

## **What NOT to Do (Anti-Patterns)**

### ❌ **Anti-Pattern 1: Asking for User Token**

```javascript
// NEVER DO THIS
const token = prompt('Enter your Discord token');
fetch('https://discord.com/api/v10/users/@me', {
  headers: { Authorization: token }
});
```

**Why it's bad:**
- Token visible in prompt dialog
- Token stored in browser history
- User won't trust you
- Token can be stolen if device is compromised

### ❌ **Anti-Pattern 2: Storing Tokens in LocalStorage**

```javascript
// NEVER DO THIS
localStorage.setItem('discordToken', accessToken);

// Later...
const token = localStorage.getItem('discordToken');
```

**Why it's bad:**
- Any script can read localStorage (XSS attack)
- Token persists forever (not secure)
- Anyone with access to device can steal it

### ❌ **Anti-Pattern 3: Exposing Client Secret in Frontend**

```javascript
// NEVER DO THIS - exposing secret in React code
const DISCORD_CLIENT_SECRET = 'your_secret_here'; // ❌ VISIBLE IN BUNDLE

const tokenResponse = await fetch(/*...*/);
```

**Why it's bad:**
- Client secret is in the JavaScript bundle
- Anyone can download and read it
- Attackers can impersonate your app

### ❌ **Anti-Pattern 4: Long-Lived Tokens Without Refresh**

```javascript
// NEVER DO THIS
setInterval(() => {
  // Uses same token forever
  checkAccountSecurity(token);
}, 60000);
```

**Why it's bad:**
- Token can be stolen and used indefinitely
- No way to revoke access
- Increases attack window

### ❌ **Anti-Pattern 5: Logging Full Tokens**

```javascript
// NEVER DO THIS
console.log('User token:', accessToken); // ❌ In production logs
```

**Why it's bad:**
- Tokens appear in browser console
- Appears in server logs if sent
- Anyone can read it in DevTools

### ✅ **Anti-Pattern 6: Token in URL or Query Params**

```javascript
// NEVER DO THIS
window.location = `https://yoursite.com?token=${accessToken}`;
// Token appears in:
// - Browser history
// - Proxy logs
// - Referrer headers
```

---

## **Best Practices Summary**

### ✅ **DO:**
- ✅ Use OAuth2 for authentication
- ✅ Keep client secret on server only
- ✅ Use short-lived access tokens (1 hour max)
- ✅ Refresh tokens server-side if needed
- ✅ HTTPS only (never HTTP)
- ✅ Validate tokens on backend
- ✅ Log security events (not tokens)
- ✅ Give users granular permissions (scopes)
- ✅ Let users revoke access
- ✅ Rotate credentials regularly

### ❌ **DON'T:**
- ❌ Ask users for tokens directly
- ❌ Store tokens in localStorage
- ❌ Expose secrets in frontend code
- ❌ Log full tokens
- ❌ Use tokens in URLs
- ❌ Accept unvalidated tokens
- ❌ Store tokens without encryption
- ❌ Use tokens beyond their expiry
- ❌ Share tokens between apps
- ❌ Ignore user consent (always show permission screen)

---

## **Security Features Implemented**

1. **Token-Paste Detection** - Warns users if they try to paste a token
2. **OAuth2 Flow** - Industry-standard authentication
3. **Server-Side Token Exchange** - Client secret never exposed
4. **Secure Headers** - CSP, HSTS, X-Frame-Options
5. **HTTPS Only** - Enforced on Vercel
6. **Education UI** - Teaches users about risks
7. **Minimal Scopes** - Only `identify` and `email`
8. **Access Revocation** - Users can revoke instantly
9. **No Token Storage** - Tokens exist in memory only
10. **Runtime Integrity** - Detection of tampering/automation

---

## **Testing OAuth2 Flow**

```bash
# Start dev server
npm run dev

# Go to http://localhost:5173
# Click "Login with Discord"
# Approve permissions
# Should see your profile
# Check console - no tokens logged
```

---

## **Troubleshooting**

| Issue | Solution |
|-------|----------|
| "Invalid redirect URI" | Check Discord settings matches REDIRECT_URI exactly |
| Token exchange fails | Verify CLIENT_ID and CLIENT_SECRET in Vercel env vars |
| CORS error | Ensure Discord OAuth endpoint is being called from backend, not frontend |
| Token-paste warning doesn't show | Check browser allows clipboard access |
| User can't revoke access | Direct them to discord.com/user/settings/authorized-apps |

---

## **Next Steps**

1. ✅ Implement OAuth2 flow (this file)
2. ✅ Add token-paste detection (prevents mistakes)
3. ✅ Educate users on security best practices
4. ✅ Deploy to Vercel with proper credentials
5. ✅ Monitor for security issues
6. ✅ Consider backend for detailed audit logs

