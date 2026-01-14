# Backend Implementation Guide

Complete backend implementation for secure token checker on Vercel with Node.js/Express.

---

## 1. Project Setup

### 1.1 Package Dependencies

```bash
npm install express cors dotenv redis helmet express-rate-limit uuid crypto
```

### 1.2 Environment Variables (.env)

```env
# Environment
NODE_ENV=production
PORT=3000

# API Configuration
API_BASE_URL=https://api.tokenchecker.app
FRONTEND_URL=https://tokenchecker.app

# Discord API
DISCORD_API_URL=https://discord.com/api/v10

# Session Management
SESSION_LIFETIME=1800000
REQUEST_KEY_ROTATION=300000
RESPONSE_KEY_ROTATION=300000

# Rate Limiting
RATE_LIMIT_IP_MAX=10
RATE_LIMIT_IP_WINDOW=60
RATE_LIMIT_SESSION_MAX=100
RATE_LIMIT_SESSION_WINDOW=3600
RATE_LIMIT_FINGERPRINT_MAX=20
RATE_LIMIT_FINGERPRINT_WINDOW=60

# Redis
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=info

# Security
ENABLE_HTTPS_ONLY=true
ENABLE_BOT_DETECTION=true
ENABLE_CAPTCHA=false

# Secrets (use SecureSecrets management, NOT git)
HMAC_SECRET_KEY=<generate_with_crypto.randomBytes(32).toString('hex')>
```

---

## 2. Core Server Setup

### 2.1 Main Server File

```javascript
// api/server.js
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { createRedisClient } from './lib/redis.js';
import { setupSecurityHeaders } from './lib/security.js';
import authRoutes from './routes/auth.js';
import tokenRoutes from './routes/tokens.js';
import { errorHandler, notFoundHandler } from './middleware/errors.js';

dotenv.config();

const app = express();

// ============================================
// Middleware
// ============================================

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Session-Token', 'X-Signature', 'X-Request-Timestamp', 'X-Request-Nonce']
}));

// Body parsing
app.use(express.json({ limit: '10kb' })); // Limit payload size

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`[${req.method}] ${req.path} ${res.statusCode} ${duration}ms`);
  });
  
  next();
});

// ============================================
// API Routes
// ============================================

app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/tokens', tokenRoutes);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

// ============================================
// Error Handling
// ============================================

app.use(notFoundHandler);
app.use(errorHandler);

// ============================================
// Server Start
// ============================================

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

export default app;
```

### 2.2 Vercel Configuration

```json
{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "env": {
    "FORCE_HTTPS": "true",
    "NODE_ENV": "production"
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
        },
        {
          "key": "X-XSS-Protection",
          "value": "1; mode=block"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "geolocation=(), microphone=(), camera=()"
        }
      ]
    }
  ],
  "rewrites": [
    {
      "source": "/api/(.*)",
      "destination": "/api/server.js"
    }
  ]
}
```

---

## 3. Session Management

### 3.1 Session Service

```javascript
// lib/SessionService.js
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { redisClient } from './redis.js';

export class SessionService {
  static SESSION_LIFETIME = parseInt(process.env.SESSION_LIFETIME) || 1800000;
  static REQUEST_KEY_ROTATION = parseInt(process.env.REQUEST_KEY_ROTATION) || 300000;
  static RESPONSE_KEY_ROTATION = parseInt(process.env.RESPONSE_KEY_ROTATION) || 300000;

  /**
   * Create new session
   */
  static async createSession(req) {
    const sessionId = uuidv4();
    const sessionToken = this.generateToken();
    const requestKey = this.generateKey();
    const responseKey = this.generateKey();

    // Get client fingerprint
    const fingerprint = this.getClientFingerprint(req);

    const session = {
      id: sessionId,
      token: sessionToken,
      requestKey,
      responseKey,
      fingerprint,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.SESSION_LIFETIME,
      requestKeyRotatedAt: Date.now(),
      responseKeyRotatedAt: Date.now(),
      nonces: [],
      revoked: false
    };

    // Store in Redis with TTL
    const ttl = Math.ceil(this.SESSION_LIFETIME / 1000);
    await redisClient.setex(
      `session:${sessionId}`,
      ttl,
      JSON.stringify(session)
    );

    return {
      sessionToken,
      requestKey,
      responseKey,
      expiresAt: session.expiresAt
    };
  }

  /**
   * Retrieve session
   */
  static async getSession(sessionId) {
    const data = await redisClient.get(`session:${sessionId}`);
    if (!data) return null;

    const session = JSON.parse(data);

    // Check expiration
    if (Date.now() > session.expiresAt) {
      await redisClient.del(`session:${sessionId}`);
      return null;
    }

    // Check revocation
    if (session.revoked) {
      return null;
    }

    return session;
  }

  /**
   * Validate session token
   */
  static async validateSessionToken(sessionToken, req) {
    // Extract session ID from token (format: id.hash)
    const [sessionId, tokenHash] = sessionToken.split('.');

    if (!sessionId || !tokenHash) {
      throw new Error('Invalid session token format');
    }

    // Retrieve session
    const session = await this.getSession(sessionId);
    if (!session) {
      throw new Error('Session not found or expired');
    }

    // Verify token hash
    const expectedHash = crypto
      .createHmac('sha256', process.env.HMAC_SECRET_KEY)
      .update(sessionId)
      .digest('hex');

    if (!this.constantTimeEquals(tokenHash, expectedHash)) {
      throw new Error('Invalid session token');
    }

    // Verify client fingerprint (prevent session hijacking)
    const currentFingerprint = this.getClientFingerprint(req);
    if (currentFingerprint !== session.fingerprint) {
      console.warn('Session hijacking attempt detected', {
        sessionId,
        expectedFingerprint: session.fingerprint,
        currentFingerprint
      });
      
      // Revoke session
      await this.revokeSession(sessionId, 'fingerprint_mismatch');
      
      throw new Error('Session context changed - possible hijacking');
    }

    // Check key rotation
    const now = Date.now();
    if (now - session.requestKeyRotatedAt > this.REQUEST_KEY_ROTATION) {
      session.requestKey = this.generateKey();
      session.requestKeyRotatedAt = now;
    }

    if (now - session.responseKeyRotatedAt > this.RESPONSE_KEY_ROTATION) {
      session.responseKey = this.generateKey();
      session.responseKeyRotatedAt = now;
    }

    // Update session in Redis
    const ttl = Math.ceil((session.expiresAt - now) / 1000);
    if (ttl > 0) {
      await redisClient.setex(
        `session:${sessionId}`,
        ttl,
        JSON.stringify(session)
      );
    }

    return session;
  }

  /**
   * Revoke session
   */
  static async revokeSession(sessionId, reason = 'user_logout') {
    const session = await this.getSession(sessionId);
    if (session) {
      session.revoked = true;
      session.revokedReason = reason;
      session.revokedAt = Date.now();

      const ttl = Math.ceil((session.expiresAt - Date.now()) / 1000);
      if (ttl > 0) {
        await redisClient.setex(
          `session:${sessionId}`,
          ttl,
          JSON.stringify(session)
        );
      }

      // Clear all nonces for this session
      await redisClient.del(`nonce:*:${sessionId}`);

      console.log(`Session revoked: ${sessionId} (${reason})`);
    }
  }

  /**
   * Verify request signature
   */
  static verifyRequestSignature(signature, timestamp, nonce, body, requestKey) {
    const message = `${timestamp}|${nonce}|${JSON.stringify(body)}|1`;
    
    const expectedSignature = crypto
      .createHmac('sha256', requestKey)
      .update(message)
      .digest('hex');

    return this.constantTimeEquals(signature, expectedSignature);
  }

  /**
   * Generate response signature
   */
  static generateResponseSignature(responseData, timestamp, responseKey) {
    const message = JSON.stringify(responseData) + '|' + timestamp;
    
    return crypto
      .createHmac('sha256', responseKey)
      .update(message)
      .digest('hex');
  }

  /**
   * Constant-time comparison
   */
  static constantTimeEquals(a, b) {
    if (a.length !== b.length) return false;

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }

  /**
   * Generate secure token
   */
  static generateToken() {
    const sessionId = uuidv4();
    const hash = crypto
      .createHmac('sha256', process.env.HMAC_SECRET_KEY)
      .update(sessionId)
      .digest('hex');

    return `${sessionId}.${hash}`;
  }

  /**
   * Generate secret key
   */
  static generateKey() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Get client fingerprint
   */
  static getClientFingerprint(req) {
    const crypto = require('crypto');

    const components = [
      req.headers['user-agent'] || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || '',
      req.ip || req.headers['x-forwarded-for'] || 'unknown'
    ].join('|');

    return crypto
      .createHash('sha256')
      .update(components)
      .digest('hex');
  }
}

export default SessionService;
```

---

## 4. Request Validation Middleware

### 4.1 Authentication Middleware

```javascript
// middleware/authenticate.js
import SessionService from '../lib/SessionService.js';

export async function authenticate(req, res, next) {
  try {
    // Extract headers
    const sessionToken = req.headers['x-session-token'];
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-request-timestamp'];
    const nonce = req.headers['x-request-nonce'];

    // Validate presence
    if (!sessionToken || !signature || !timestamp || !nonce) {
      return res.status(401).json({
        error: 'Missing required security headers',
        missing: {
          sessionToken: !sessionToken,
          signature: !signature,
          timestamp: !timestamp,
          nonce: !nonce
        }
      });
    }

    // Validate session
    const session = await SessionService.validateSessionToken(sessionToken, req);

    // Verify timestamp freshness
    const now = Date.now();
    const requestTimestamp = parseInt(timestamp);
    const MAX_SKEW = 5 * 60 * 1000; // 5 minutes

    if (Math.abs(now - requestTimestamp) > MAX_SKEW) {
      return res.status(401).json({
        error: 'Request timestamp invalid or expired',
        skew: now - requestTimestamp
      });
    }

    // Verify signature
    const isValidSignature = SessionService.verifyRequestSignature(
      signature,
      timestamp,
      nonce,
      req.body,
      session.requestKey
    );

    if (!isValidSignature) {
      console.warn('Invalid signature detected', {
        sessionId: session.id,
        ip: req.ip
      });

      return res.status(401).json({
        error: 'Invalid request signature - possible tampering'
      });
    }

    // Verify nonce freshness (replay protection)
    const nonceKey = `nonce:${nonce}:${session.id}`;
    const existingNonce = await redisClient.get(nonceKey);

    if (existingNonce) {
      console.warn('Nonce reuse detected - replay attack', {
        nonce,
        sessionId: session.id
      });

      return res.status(429).json({
        error: 'Duplicate request - possible replay attack'
      });
    }

    // Store nonce with TTL
    const ttl = Math.ceil(MAX_SKEW / 1000);
    await redisClient.setex(nonceKey, ttl, Date.now());

    // Attach to request for later use
    req.session = session;
    req.requestTimestamp = requestTimestamp;
    req.requestNonce = nonce;

    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ error: error.message });
  }
}

export default authenticate;
```

### 4.2 Rate Limiting Middleware

```javascript
// middleware/rateLimit.js
import { redisClient } from '../lib/redis.js';
import SessionService from '../lib/SessionService.js';

export async function checkRateLimits(req, res, next) {
  try {
    const session = req.session;
    const ip = req.ip;
    const fingerprint = SessionService.getClientFingerprint(req);

    // Layer 1: IP-based rate limit
    await checkIPRateLimit(ip);

    // Layer 2: Session-based rate limit
    await checkSessionRateLimit(session.id);

    // Layer 3: Fingerprint-based rate limit
    await checkFingerprintRateLimit(fingerprint);

    next();
  } catch (error) {
    if (error.statusCode === 429) {
      return res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter: error.retryAfter
      });
    }

    console.error('Rate limit check error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

async function checkIPRateLimit(ip) {
  const key = `ratelimit:ip:${ip}`;
  const max = parseInt(process.env.RATE_LIMIT_IP_MAX) || 10;
  const window = parseInt(process.env.RATE_LIMIT_IP_WINDOW) || 60;

  const count = await redisClient.incr(key);

  if (count === 1) {
    await redisClient.expire(key, window);
  }

  if (count > max) {
    const error = new Error('IP rate limit exceeded');
    error.statusCode = 429;
    error.retryAfter = window;
    throw error;
  }
}

async function checkSessionRateLimit(sessionId) {
  const key = `ratelimit:session:${sessionId}`;
  const max = parseInt(process.env.RATE_LIMIT_SESSION_MAX) || 100;
  const window = parseInt(process.env.RATE_LIMIT_SESSION_WINDOW) || 3600;

  const count = await redisClient.incr(key);

  if (count === 1) {
    await redisClient.expire(key, window);
  }

  if (count > max) {
    const error = new Error('Session rate limit exceeded');
    error.statusCode = 429;
    error.retryAfter = window;
    throw error;
  }
}

async function checkFingerprintRateLimit(fingerprint) {
  const key = `ratelimit:fingerprint:${fingerprint}`;
  const max = parseInt(process.env.RATE_LIMIT_FINGERPRINT_MAX) || 20;
  const window = parseInt(process.env.RATE_LIMIT_FINGERPRINT_WINDOW) || 60;

  const count = await redisClient.incr(key);

  if (count === 1) {
    await redisClient.expire(key, window);
  }

  if (count > max) {
    const error = new Error('Fingerprint rate limit exceeded');
    error.statusCode = 429;
    error.retryAfter = window;
    throw error;
  }
}

export default checkRateLimits;
```

---

## 5. Token Validation Endpoint

### 5.1 Token Routes

```javascript
// routes/tokens.js
import express from 'express';
import authenticate from '../middleware/authenticate.js';
import checkRateLimits from '../middleware/rateLimit.js';
import { validateTokenHandler, multiValidateHandler } from '../handlers/tokens.js';

const router = express.Router();

/**
 * POST /api/v1/tokens/validate
 * Validate a single Discord token
 */
router.post(
  '/validate',
  authenticate,
  checkRateLimits,
  validateTokenHandler
);

/**
 * POST /api/v1/tokens/validate-batch
 * Validate multiple tokens
 */
router.post(
  '/validate-batch',
  authenticate,
  checkRateLimits,
  multiValidateHandler
);

export default router;
```

### 5.2 Token Handler

```javascript
// handlers/tokens.js
import { v4 as uuidv4 } from 'uuid';
import SessionService from '../lib/SessionService.js';
import { checkTokenViaDiscordAPI } from '../lib/discord.js';
import { detectAutomation } from '../lib/botDetection.js';
import { logSecurityEvent } from '../lib/logging.js';

export async function validateTokenHandler(req, res) {
  try {
    const { token } = req.body;
    const session = req.session;

    // Input validation
    if (!token || typeof token !== 'string') {
      return res.status(400).json({
        error: 'Invalid token',
        valid: false
      });
    }

    // Validate token format
    if (!isValidTokenFormat(token)) {
      return res.status(400).json({
        error: 'Invalid token format',
        valid: false
      });
    }

    // Detect automation/bots
    if (process.env.ENABLE_BOT_DETECTION === 'true') {
      const automationAnalysis = detectAutomation(req, session);

      if (automationAnalysis.likelyAutomated) {
        logSecurityEvent('AUTOMATION_DETECTED', {
          sessionId: session.id,
          automationScore: automationAnalysis.automationScore,
          signals: automationAnalysis.suspiciousSignals
        });

        if (automationAnalysis.automationScore >= 8) {
          return res.status(403).json({
            error: 'Access denied - suspicious activity detected'
          });
        }

        if (process.env.ENABLE_CAPTCHA === 'true') {
          return res.status(403).json({
            error: 'Challenge required',
            challengeType: 'captcha'
          });
        }
      }
    }

    // Query Discord API (backend only)
    const checkId = uuidv4();
    let tokenCheckResult;

    try {
      tokenCheckResult = await checkTokenViaDiscordAPI(token);
    } catch (error) {
      logSecurityEvent('TOKEN_CHECK_ERROR', {
        sessionId: session.id,
        checkId,
        error: error.message
      });

      return res.status(500).json({
        error: 'Token validation failed',
        valid: false,
        checkId
      });
    }

    // Log validation attempt
    logSecurityEvent('TOKEN_VALIDATED', {
      sessionId: session.id,
      checkId,
      tokenHash: hashToken(token),
      result: tokenCheckResult.valid,
      ip: req.ip
    });

    // Build response
    const responseData = {
      valid: tokenCheckResult.valid,
      details: tokenCheckResult.valid ? tokenCheckResult.details : null,
      checkId,
      timestamp: Date.now()
    };

    // Sign response
    const responseTimestamp = Date.now();
    const responseSignature = SessionService.generateResponseSignature(
      responseData,
      responseTimestamp,
      session.responseKey
    );

    // Set response headers
    res.set({
      'X-Response-Signature': responseSignature,
      'X-Response-Timestamp': String(responseTimestamp),
      'Cache-Control': 'no-cache, no-store, must-revalidate',
      'Pragma': 'no-cache'
    });

    res.json(responseData);
  } catch (error) {
    console.error('Token validation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

export async function multiValidateHandler(req, res) {
  try {
    const { tokens } = req.body;
    const session = req.session;

    // Validate input
    if (!Array.isArray(tokens)) {
      return res.status(400).json({ error: 'tokens must be an array' });
    }

    if (tokens.length === 0 || tokens.length > 100) {
      return res.status(400).json({
        error: 'Must provide 1-100 tokens'
      });
    }

    // Validate each token format
    const validTokens = tokens.filter(t => {
      if (typeof t !== 'string') return false;
      return isValidTokenFormat(t);
    });

    if (validTokens.length !== tokens.length) {
      return res.status(400).json({
        error: 'Some tokens have invalid format'
      });
    }

    // Check tokens
    const results = [];

    for (const token of validTokens) {
      try {
        const result = await checkTokenViaDiscordAPI(token);
        results.push({
          valid: result.valid,
          details: result.valid ? result.details : null
        });
      } catch (error) {
        results.push({
          valid: false,
          error: 'Check failed'
        });
      }
    }

    // Build response
    const responseData = {
      results,
      total: validTokens.length,
      validCount: results.filter(r => r.valid).length,
      timestamp: Date.now()
    };

    // Sign response
    const responseTimestamp = Date.now();
    const responseSignature = SessionService.generateResponseSignature(
      responseData,
      responseTimestamp,
      session.responseKey
    );

    res.set({
      'X-Response-Signature': responseSignature,
      'X-Response-Timestamp': String(responseTimestamp),
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    });

    res.json(responseData);
  } catch (error) {
    console.error('Batch validation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}

function isValidTokenFormat(token) {
  // Discord tokens typically 72-80 chars of base64-like data
  const tokenPattern = /^[\w\-\.]{20,100}$/;
  return tokenPattern.test(token);
}

function hashToken(token) {
  const crypto = require('crypto');
  return crypto
    .createHash('sha256')
    .update(token)
    .digest('hex')
    .slice(0, 8);
}
```

---

## 6. Discord API Integration

### 6.1 Discord Service

```javascript
// lib/discord.js
export async function checkTokenViaDiscordAPI(token) {
  try {
    // Query Discord API with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    const response = await fetch('https://discord.com/api/v10/users/@me', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'User-Agent': 'SecureTokenChecker/1.0'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.status === 200) {
      const userData = await response.json();

      return {
        valid: true,
        details: {
          id: userData.id,
          username: userData.username,
          email: userData.email || null,
          verified: userData.verified || false,
          locale: userData.locale || null,
          mfaEnabled: userData.mfa_enabled || false
        }
      };
    } else if (response.status === 401) {
      return { valid: false, details: null };
    } else {
      throw new Error(`Unexpected Discord API status: ${response.status}`);
    }
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('Discord API request timeout');
    }
    throw error;
  }
}
```

---

## 7. Logging & Monitoring

### 7.1 Security Logging

```javascript
// lib/logging.js
import fs from 'fs';
import path from 'path';

export function logSecurityEvent(eventType, details) {
  const event = {
    timestamp: new Date().toISOString(),
    type: eventType,
    details
  };

  // Log to console
  console.log(`[${eventType}]`, event);

  // Log to file for audit trail
  const logDir = path.join(process.cwd(), 'logs');
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  const logFile = path.join(logDir, `security-${Date.now().toString().slice(0, -3)}.log`);
  fs.appendFileSync(logFile, JSON.stringify(event) + '\n');

  // Alert on critical events
  if (isClassifiedCritical(eventType)) {
    alertSecurityTeam(event);
  }
}

function isClassifiedCritical(eventType) {
  const criticalEvents = [
    'INVALID_SIGNATURE',
    'REPLAY_DETECTED',
    'AUTOMATION_DETECTED',
    'SESSION_HIJACKING_ATTEMPTED'
  ];

  return criticalEvents.includes(eventType);
}

function alertSecurityTeam(event) {
  // Integration with alerting system (PagerDuty, Slack, etc.)
  console.error('🚨 SECURITY ALERT:', event);
}
```

---

## 8. Deployment on Vercel

### 8.1 Vercel API Handler

```javascript
// api/index.js (Vercel serverless)
import app from './server.js';

export default app;
```

### 8.2 Deployment Steps

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy to Vercel
vercel

# Set environment variables
vercel env add

# Monitor in production
vercel logs -f
```

---

## 9. Testing & Validation

### 9.1 Unit Tests

```javascript
// test/security.test.js
import SessionService from '../lib/SessionService.js';

describe('SessionService', () => {
  test('validateRequestSignature - valid signature', () => {
    const requestKey = SessionService.generateKey();
    const timestamp = Date.now();
    const nonce = 'test-nonce';
    const body = { token: 'test' };

    const signature = SessionService.generateRequestSignature(
      timestamp,
      nonce,
      body,
      requestKey
    );

    const isValid = SessionService.verifyRequestSignature(
      signature,
      timestamp,
      nonce,
      body,
      requestKey
    );

    expect(isValid).toBe(true);
  });

  test('validateRequestSignature - tampered body', () => {
    const requestKey = SessionService.generateKey();
    const timestamp = Date.now();
    const nonce = 'test-nonce';
    const body = { token: 'test' };

    const signature = SessionService.generateRequestSignature(
      timestamp,
      nonce,
      body,
      requestKey
    );

    const tamperedBody = { token: 'different' };

    const isValid = SessionService.verifyRequestSignature(
      signature,
      timestamp,
      nonce,
      tamperedBody,
      requestKey
    );

    expect(isValid).toBe(false);
  });
});
```

---

## 10. Security Checklist

- [ ] All environment variables securely stored (not in git)
- [ ] HTTPS enforced (HSTS headers)
- [ ] Session tokens properly validated
- [ ] HMAC signatures verified (constant-time comparison)
- [ ] Replay attack protection (nonces)
- [ ] Rate limiting on all layers
- [ ] Input validation on all endpoints
- [ ] Discord API called via backend only
- [ ] Response signatures enabled
- [ ] Bot detection implemented
- [ ] Security logging enabled
- [ ] Error messages don't leak sensitive data
- [ ] CORS properly configured
- [ ] Security headers set
- [ ] Regular security audits scheduled

---

This backend implementation provides defense-in-depth security across all threat vectors while maintaining high performance and scalability on Vercel's serverless platform.

