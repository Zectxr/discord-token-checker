/**
 * SECURE Request Client for Token Checker
 * 
 * This module handles all secure communication with the backend:
 * - HMAC signature generation
 * - Timestamp + nonce management
 * - Response integrity verification
 * - Error handling and retry logic
 * 
 * NEVER modify this file to send secrets or bypass security checks
 */

import crypto from 'crypto';

/**
 * Configuration
 */
const CONFIG = {
  API_URL: process.env.REACT_APP_API_URL || 'https://api.tokenchecker.app',
  SESSION_STORAGE_KEY: '__secure_session__',
  REQUEST_TIMEOUT_MS: 30000,
  MAX_RETRIES: 3,
  RETRY_DELAY_MS: 1000
};

/**
 * Validate configuration at initialization
 */
function validateConfig() {
  if (!CONFIG.API_URL.startsWith('https://')) {
    throw new Error(
      'SECURITY ERROR: API URL must use HTTPS. ' +
      'Set REACT_APP_API_URL to a secure URL in production.'
    );
  }
}

/**
 * Session Management
 * 
 * Session tokens are ephemeral and include:
 * - sessionToken: Used to identify the session
 * - requestKey: Used for signing requests (rotated frequently)
 * - responseKey: Used for verifying response signatures
 * - expiresAt: Session expiration time
 */
class SecureSession {
  constructor() {
    this.session = null;
  }

  /**
   * Initialize or get existing session
   */
  async getOrCreateSession() {
    // Check if session exists and is still valid
    if (this.session && Date.now() < this.session.expiresAt) {
      return this.session;
    }

    // Request new session from backend
    const session = await this.fetchNewSession();
    this.session = session;
    
    // Store in sessionStorage (cleared when tab closes)
    sessionStorage.setItem(
      CONFIG.SESSION_STORAGE_KEY,
      JSON.stringify(session)
    );
    
    return session;
  }

  /**
   * Fetch new session from backend
   */
  async fetchNewSession() {
    try {
      const response = await fetch(`${CONFIG.API_URL}/api/v1/auth/session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': this.getUserAgent()
        },
        // No authentication needed for session creation
      });

      if (!response.ok) {
        throw new Error(`Failed to create session: ${response.status}`);
      }

      const session = await response.json();
      
      // Validate session structure
      if (!session.sessionToken || !session.requestKey || !session.responseKey) {
        throw new Error('Invalid session response from server');
      }

      return session;
    } catch (error) {
      console.error('Session creation failed:', error);
      throw error;
    }
  }

  /**
   * Clear session (on logout)
   */
  clearSession() {
    this.session = null;
    sessionStorage.removeItem(CONFIG.SESSION_STORAGE_KEY);
  }

  /**
   * Get user agent for fingerprinting
   */
  getUserAgent() {
    return navigator.userAgent;
  }
}

/**
 * Request Signing & Verification
 */
class RequestSigner {
  /**
   * Generate cryptographically secure nonce
   */
  static generateNonce() {
    // Use crypto API for true randomness
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    
    // Convert to hex string
    return Array.from(array)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Create HMAC-SHA256 signature
   * 
   * Message format: timestamp|nonce|body|version
   * This prevents request tampering
   */
  static createSignature(timestamp, nonce, body, requestKey, version = '1') {
    const bodyString = typeof body === 'string' 
      ? body 
      : JSON.stringify(body);

    const message = `${timestamp}|${nonce}|${bodyString}|${version}`;

    // Use Web Crypto API for HMAC-SHA256
    return this.hmacSha256(requestKey, message);
  }

  /**
   * HMAC-SHA256 using Web Crypto API
   * 
   * Note: This requires requestKey to be a valid HMAC key format
   * Backend provides this in the session response
   */
  static async hmacSha256(key, message) {
    // Import key for Web Crypto API
    const keyData = new TextEncoder().encode(key);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    // Create signature
    const messageData = new TextEncoder().encode(message);
    const signature = await crypto.subtle.sign(
      'HMAC',
      cryptoKey,
      messageData
    );

    // Convert to hex string
    const signatureArray = new Uint8Array(signature);
    return Array.from(signatureArray)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Verify response signature
   * 
   * Prevents response tampering or man-in-the-middle attacks
   */
  static async verifyResponseSignature(
    responseData,
    signature,
    timestamp,
    responseKey
  ) {
    const MAX_RESPONSE_AGE_MS = 30000; // 30 seconds

    // 1. Check timestamp freshness
    const now = Date.now();
    const age = now - timestamp;

    if (age < 0 || age > MAX_RESPONSE_AGE_MS) {
      throw new Error(
        `Response timestamp invalid or too old (age: ${age}ms). ` +
        `Possible tampering or MITM attack detected.`
      );
    }

    // 2. Verify signature
    const message = JSON.stringify(responseData) + '|' + timestamp;
    const expectedSignature = await this.hmacSha256(responseKey, message);

    // Constant-time comparison to prevent timing attacks
    if (!this.constantTimeEquals(signature, expectedSignature)) {
      throw new Error(
        'Response signature verification failed. ' +
        'Possible tampering or MITM attack detected.'
      );
    }

    return true;
  }

  /**
   * Constant-time string comparison
   * 
   * Prevents timing attacks where attackers measure response time
   * to brute-force valid signatures
   */
  static constantTimeEquals(a, b) {
    if (a.length !== b.length) return false;

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }
}

/**
 * Secure HTTP Client
 * 
 * Handles all communication with backend:
 * - Automatic request signing
 * - Response verification
 * - Retry logic
 * - Error handling
 */
class SecureHttpClient {
  constructor() {
    this.session = new SecureSession();
    this.requestTimeout = CONFIG.REQUEST_TIMEOUT_MS;
  }

  /**
   * Make a signed request to backend
   * 
   * @param {string} endpoint - API endpoint (e.g., '/api/v1/tokens/validate')
   * @param {object} body - Request body
   * @param {object} options - Additional options
   * @returns {Promise<object>} Response data (verified)
   */
  async request(endpoint, body = {}, options = {}) {
    // Validate configuration
    validateConfig();

    // Get or create session
    const session = await this.session.getOrCreateSession();

    // Prepare request
    const timestamp = Date.now();
    const nonce = RequestSigner.generateNonce();
    const signature = await RequestSigner.createSignature(
      timestamp,
      nonce,
      body,
      session.requestKey
    );

    const url = `${CONFIG.API_URL}${endpoint}`;

    // Build request headers
    const headers = {
      'Content-Type': 'application/json',
      'X-Session-Token': session.sessionToken,
      'X-Request-Timestamp': String(timestamp),
      'X-Request-Nonce': nonce,
      'X-Signature': signature,
      'X-Request-Version': '1',
      'User-Agent': navigator.userAgent
    };

    // Attempt request with retry logic
    let lastError;
    for (let attempt = 1; attempt <= CONFIG.MAX_RETRIES; attempt++) {
      try {
        return await this.makeRequestAttempt(
          url,
          body,
          headers,
          session,
          options
        );
      } catch (error) {
        lastError = error;

        // Don't retry on 4xx errors (invalid request)
        if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500) {
          throw error;
        }

        // Retry on network or 5xx errors
        if (attempt < CONFIG.MAX_RETRIES) {
          const delayMs = CONFIG.RETRY_DELAY_MS * (2 ** (attempt - 1));
          await new Promise(resolve => setTimeout(resolve, delayMs));
        }
      }
    }

    throw lastError || new Error('Request failed after retries');
  }

  /**
   * Single request attempt with verification
   */
  async makeRequestAttempt(url, body, headers, session, options) {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error('Request timeout'));
      }, this.requestTimeout);

      fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        ...options
      })
        .then(async response => {
          clearTimeout(timeoutId);

          // Check HTTP status
          if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            const err = new Error(error.error || 'Request failed');
            err.statusCode = response.status;
            reject(err);
            return;
          }

          // Parse response
          const data = await response.json();

          // Verify response signature if provided
          const signature = response.headers.get('X-Response-Signature');
          const respTimestamp = parseInt(response.headers.get('X-Response-Timestamp'));

          if (signature && respTimestamp) {
            try {
              await RequestSigner.verifyResponseSignature(
                data,
                signature,
                respTimestamp,
                session.responseKey
              );
            } catch (error) {
              clearTimeout(timeoutId);
              reject(error);
              return;
            }
          }

          resolve(data);
        })
        .catch(error => {
          clearTimeout(timeoutId);
          reject(error);
        });
    });
  }

  /**
   * Logout and clear session
   */
  logout() {
    this.session.clearSession();
  }
}

/**
 * High-level API for token validation
 */
class TokenCheckerAPI {
  constructor() {
    this.client = new SecureHttpClient();
  }

  /**
   * Validate a single token
   * 
   * @param {string} token - Discord token to validate
   * @returns {Promise<object>} Validation result
   */
  async validateToken(token) {
    if (!token || typeof token !== 'string') {
      throw new Error('Invalid token: must be a non-empty string');
    }

    try {
      const result = await this.client.request('/api/v1/tokens/validate', {
        token
      });

      return {
        valid: result.valid,
        details: result.details || null,
        checkId: result.checkId,
        error: null
      };
    } catch (error) {
      console.error('Token validation error:', error);
      
      return {
        valid: false,
        details: null,
        checkId: null,
        error: error.message
      };
    }
  }

  /**
   * Validate multiple tokens
   * 
   * @param {string[]} tokens - Array of tokens to validate
   * @param {function} onProgress - Callback for progress updates
   * @returns {Promise<object[]>} Array of validation results
   */
  async validateTokens(tokens, onProgress = null) {
    const results = [];

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      const result = await this.validateToken(token);
      results.push(result);

      // Call progress callback
      if (onProgress) {
        onProgress({
          current: i + 1,
          total: tokens.length,
          result
        });
      }
    }

    return results;
  }

  /**
   * Logout
   */
  logout() {
    this.client.logout();
  }
}

// Export for use in React components
export default TokenCheckerAPI;
export { SecureHttpClient, RequestSigner, SecureSession };
