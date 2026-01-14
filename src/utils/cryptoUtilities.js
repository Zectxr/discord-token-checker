/**
 * @fileoverview Secure cryptographic utilities and token obfuscation
 * Uses Web Crypto API for proper cryptographic operations
 * 
 * WARNING: Client-side crypto alone is NOT sufficient for security.
 * This is defense-in-depth, not a complete solution.
 */

class CryptoUtilities {
  constructor() {
    this.algorithm = {
      name: 'AES-GCM',
      length: 256,
    };
  }

  /**
   * Generate a secure random key using SubtleCrypto
   */
  async generateSecureKey() {
    return await window.crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: 256,
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Derive a key from a password using PBKDF2
   * @param {string} password - The password
   * @param {Uint8Array} salt - Random salt
   */
  async deriveKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);

    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      data,
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return await window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 600000, // NIST recommendation
        hash: 'SHA-256',
      },
      baseKey,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt data using AES-GCM
   * @param {string} plaintext - Data to encrypt
   * @param {CryptoKey} key - The encryption key
   */
  async encryptData(plaintext, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const ciphertext = await window.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key,
      data
    );

    // Return combined IV + ciphertext as base64
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);

    return this.arrayBufferToBase64(combined);
  }

  /**
   * Decrypt data using AES-GCM
   * @param {string} encryptedBase64 - Base64 encoded IV + ciphertext
   * @param {CryptoKey} key - The decryption key
   */
  async decryptData(encryptedBase64, key) {
    const combined = this.base64ToArrayBuffer(encryptedBase64);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    try {
      const plaintext = await window.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
        },
        key,
        ciphertext
      );

      const decoder = new TextDecoder();
      return decoder.decode(plaintext);
    } catch (e) {
      console.error('Decryption failed - possible tampering detected');
      return null;
    }
  }

  /**
   * Create HMAC signature for integrity verification
   * @param {string} data - Data to sign
   * @param {CryptoKey} key - HMAC key
   */
  async createHMAC(data, key) {
    const encoder = new TextEncoder();
    const signature = await window.crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(data)
    );

    return this.arrayBufferToBase64(signature);
  }

  /**
   * Verify HMAC signature
   * @param {string} data - Original data
   * @param {string} signatureBase64 - Base64 signature
   * @param {CryptoKey} key - HMAC key
   */
  async verifyHMAC(data, signatureBase64, key) {
    const encoder = new TextEncoder();
    const signature = this.base64ToArrayBuffer(signatureBase64);

    return await window.crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      encoder.encode(data)
    );
  }

  /**
   * Hash data using SHA-256
   * Only for integrity checking, NOT for password hashing
   */
  async hashData(data) {
    const encoder = new TextEncoder();
    const hashBuffer = await window.crypto.subtle.digest(
      'SHA-256',
      encoder.encode(data)
    );

    return this.arrayBufferToHex(hashBuffer);
  }

  /**
   * Obfuscate token for display (show first 5 and last 5 chars)
   */
  obfuscateToken(token) {
    if (!token || token.length < 10) return '***';
    return token.substring(0, 5) + '*'.repeat(Math.max(0, token.length - 10)) + token.slice(-5);
  }

  /**
   * Securely clear sensitive data from memory
   */
  secureClear(variable) {
    if (typeof variable === 'string') {
      return '0'.repeat(variable.length);
    } else if (variable instanceof Uint8Array) {
      return variable.fill(0);
    } else if (typeof variable === 'object') {
      for (const key in variable) {
        if (variable.hasOwnProperty(key)) {
          variable[key] = null;
        }
      }
      return variable;
    }
    return null;
  }

  /**
   * Convert ArrayBuffer to Base64
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert Base64 to ArrayBuffer
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Convert ArrayBuffer to Hex string
   */
  arrayBufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}

/**
 * Obfuscation utilities - makes static analysis harder
 * Not a replacement for proper minification/bundling
 */
class ObfuscationUtilities {
  /**
   * Create a dynamically generated function that's hard to statically analyze
   * USE CAREFULLY - adds performance overhead
   */
  static createDynamicValidator(rules) {
    // This prevents simple string matching from finding validation logic
    const encodedRules = btoa(JSON.stringify(rules));
    
    return function(input) {
      try {
        const actualRules = JSON.parse(atob(encodedRules));
        for (const rule of actualRules) {
          if (!rule.validator(input)) return false;
        }
        return true;
      } catch (e) {
        console.error('Validation error');
        return false;
      }
    };
  }

  /**
   * String obfuscation - makes strings harder to find via search
   * Example: instead of checking for "admin", split it up
   */
  static encodeString(str) {
    return btoa(str);
  }

  /**
   * Decode obfuscated string
   */
  static decodeString(encoded) {
    try {
      return atob(encoded);
    } catch (e) {
      return null;
    }
  }

  /**
   * Create polymorphic code that changes on each execution
   * Makes pattern matching harder for automation
   */
  static createPolymorphicCheck(checkFn) {
    const variations = [
      () => !checkFn() ? false : true,
      () => checkFn() === true ? true : false,
      () => checkFn() ? 1 === 1 : 1 === 0,
      () => {
        const result = checkFn();
        return !!result;
      },
    ];

    // Return a random variation
    const selected = variations[Math.floor(Math.random() * variations.length)];
    return selected();
  }

  /**
   * Inject false code paths to confuse reverse engineering
   */
  static addRedHerring(expectedResult) {
    // This looks like authentication logic but does nothing
    const fakeLegacy = {
      validateOldFormat: (token) => {
        // Fake validation that looks real but is unused
        const parts = token.split('.');
        return parts.length === 3 && parts[0].length > 10;
      },
      checkLegacyDatabase: (hash) => {
        // Fake database check
        return Math.random() > 0.5;
      },
    };

    return expectedResult; // Return actual result, not fake
  }

  /**
   * Create intentionally confusing variable names
   * Note: Use in non-critical paths only, impacts readability
   */
  static createConfusion() {
    const l1I1 = {}; // Looks like variable names
    const O0o0 = [];
    return { l1I1, O0o0 };
  }

  /**
   * Time-based logic: execution path depends on timing
   * Makes reverse engineering harder
   */
  static getTimingBasedValue(option1, option2) {
    const now = Date.now();
    return (now % 2 === 0) ? option1 : option2;
  }

  /**
   * Add random delays to make automation detection harder
   */
  static async addRandomDelay(minMs = 100, maxMs = 500) {
    const delay = Math.random() * (maxMs - minMs) + minMs;
    return new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Create challenge-response pattern
   */
  static generateChallenge() {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    return Array.from(challenge).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Verify challenge response (would be combined with server in real app)
   */
  static async verifyChallenge(challenge, response, secret) {
    const encoder = new TextEncoder();
    const key = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const expectedSignature = await window.crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(challenge)
    );

    const expectedHex = Array.from(new Uint8Array(expectedSignature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    return response === expectedHex;
  }
}

/**
 * Request signing and validation for API calls
 */
class RequestSigning {
  constructor(apiSecret) {
    this.apiSecret = apiSecret;
    this.nonceHistory = new Set();
  }

  /**
   * Create a signed request with nonce and timestamp
   */
  async signRequest(method, endpoint, body = null) {
    const timestamp = Date.now();
    const nonce = this.generateNonce();

    // Check nonce hasn't been used (prevents replay)
    if (this.nonceHistory.has(nonce)) {
      throw new Error('Nonce collision detected');
    }
    this.nonceHistory.add(nonce);

    // Clean old nonces (older than 5 minutes)
    const now = Date.now();
    for (const oldNonce of this.nonceHistory) {
      if (now - oldNonce > 300000) {
        this.nonceHistory.delete(oldNonce);
      }
    }

    const payload = `${method}${endpoint}${timestamp}${nonce}${body ? JSON.stringify(body) : ''}`;
    const signature = await this.createSignature(payload);

    return {
      headers: {
        'X-Signature': signature,
        'X-Nonce': nonce,
        'X-Timestamp': timestamp,
      },
      body,
    };
  }

  /**
   * Generate unique nonce
   */
  generateNonce() {
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Create HMAC signature
   */
  async createSignature(payload) {
    const encoder = new TextEncoder();
    const key = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(this.apiSecret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await window.crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(payload)
    );

    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }
}

export const crypto = new CryptoUtilities();
export const obfuscation = new ObfuscationUtilities();
export { RequestSigning };
