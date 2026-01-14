/**
 * @fileoverview Security configuration and middleware hooks
 */

/**
 * Security configuration - adjust thresholds and behaviors
 */
export const securityConfig = {
  // Detection thresholds
  detection: {
    devToolsThreshold: 40, // Suspicion level to flag
    headlessThreshold: 50,
    automationThreshold: 45,
    tamperingThreshold: 60,
    overallThreshold: 50, // Flag if overall suspicion > 50
  },

  // Behavior settings
  behavior: {
    blockOnSuspicion: false, // Set true to completely block suspicious users
    logViolations: true,
    reportToBackend: false, // Would need backend endpoint
    backendUrl: '/api/security-report',
  },

  // Crypto settings
  crypto: {
    pbkdfIterations: 600000, // NIST recommended for PBKDF2
    encryptionAlgorithm: 'AES-GCM',
    keyLength: 256,
  },

  // Runtime integrity
  integrity: {
    freezeGlobals: true,
    monitorDOM: true,
    trapDangerousFunctions: true,
  },

  // Development mode overrides
  development: {
    disableDevToolsCheck: true,
    disableHeadlessCheck: true,
    allowLocalhost: true,
    logAllDetections: true,
  },
};

/**
 * Security middleware for API requests
 */
export class SecurityMiddleware {
  constructor() {
    this.requestInterceptors = [];
    this.responseInterceptors = [];
  }

  /**
   * Add request interceptor (for signing, security headers, etc.)
   */
  addRequestInterceptor(fn) {
    this.requestInterceptors.push(fn);
  }

  /**
   * Add response interceptor (for validation, etc.)
   */
  addResponseInterceptor(fn) {
    this.responseInterceptors.push(fn);
  }

  /**
   * Apply request interceptors
   */
  async processRequest(method, url, options = {}) {
    let request = { method, url, options };

    for (const interceptor of this.requestInterceptors) {
      request = await interceptor(request);
    }

    return request;
  }

  /**
   * Apply response interceptors
   */
  async processResponse(response) {
    let processed = response;

    for (const interceptor of this.responseInterceptors) {
      processed = await interceptor(processed);
    }

    return processed;
  }
}

/**
 * Secure fetch wrapper with anti-tampering
 */
export class SecureFetch {
  constructor(middleware = null) {
    this.middleware = middleware || new SecurityMiddleware();
    this.requestLog = [];
  }

  /**
   * Enhanced fetch with security checks
   */
  async fetch(url, options = {}) {
    // Add default security headers
    const headers = {
      'Cache-Control': 'no-store',
      'X-Requested-With': 'XMLHttpRequest',
      ...options.headers,
    };

    // Process through middleware
    const processed = await this.middleware.processRequest(
      options.method || 'GET',
      url,
      { ...options, headers }
    );

    // Log request (without sensitive data)
    this.requestLog.push({
      timestamp: Date.now(),
      url,
      method: processed.method,
    });

    try {
      const response = await fetch(processed.url, processed.options);

      // Check for suspicious response patterns
      this.validateResponse(response);

      // Process response through middleware
      const processed = await this.middleware.processResponse(response);

      return processed;
    } catch (error) {
      console.error('Fetch error:', error);
      throw error;
    }
  }

  /**
   * Validate response for tampering
   */
  validateResponse(response) {
    // Check Content-Type header
    const contentType = response.headers.get('content-type');
    if (!contentType) {
      console.warn('Missing Content-Type header');
    }

    // Check for integrity header (if available)
    const integrity = response.headers.get('x-integrity');
    if (!integrity) {
      console.debug('No integrity header in response');
    }

    // Check for redirection (potential man-in-the-middle)
    if (response.redirected) {
      console.warn('Response was redirected');
    }
  }

  /**
   * Get request log
   */
  getRequestLog() {
    return this.requestLog.slice(-50); // Last 50 requests
  }
}

/**
 * Error boundary for catching and handling security exceptions
 */
export class SecurityErrorBoundary extends Error {
  constructor(message, context = {}) {
    super(message);
    this.name = 'SecurityError';
    this.context = context;
    this.timestamp = Date.now();
  }

  /**
   * Log error securely
   */
  log() {
    console.error(`[${this.name}] ${this.message}`, {
      ...this.context,
      timestamp: this.timestamp,
    });
  }

  /**
   * Send error report (would go to backend)
   */
  async report() {
    const report = {
      error: this.name,
      message: this.message,
      context: this.context,
      timestamp: this.timestamp,
      userAgent: navigator.userAgent,
      url: window.location.href,
    };

    // Would send to backend
    console.warn('Security error report:', report);
  }
}

/**
 * CSP (Content Security Policy) validation helper
 * Note: CSP must be set via HTTP headers, not meta tags alone
 */
export const cspHelper = {
  /**
   * Recommended CSP header for maximum security
   */
  getRecommendedPolicy: () => `
    default-src 'self';
    script-src 'self' 'wasm-unsafe-eval';
    style-src 'self' 'nonce-{NONCE}';
    img-src 'self' data: https:;
    font-src 'self' data:;
    connect-src 'self' https://discordapp.com https://discord.com;
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
    upgrade-insecure-requests;
    block-all-mixed-content;
  `.trim(),

  /**
   * Validate that CSP is properly set
   */
  validateCSP: () => {
    // This can only check for meta tags (HTTP header enforcement is more secure)
    const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    return !!meta;
  },

  /**
   * Check for CSP violations
   */
  setupViolationListener: () => {
    document.addEventListener('securitypolicyviolation', (e) => {
      console.warn('CSP Violation:', {
        blockedURI: e.blockedURI,
        violatedDirective: e.violatedDirective,
        sourceFile: e.sourceFile,
        lineNumber: e.lineNumber,
      });
    });
  },
};

/**
 * CORS security helper
 */
export const corsHelper = {
  /**
   * Make CORS request safely
   */
  makeRequest: async (url, options = {}) => {
    // CORS is enforced by browser, but we can validate
    if (!url.startsWith('https://')) {
      console.warn('Non-HTTPS CORS request - potential downgrade attack');
    }

    return fetch(url, {
      ...options,
      credentials: 'same-origin',
      mode: 'cors',
    });
  },

  /**
   * Get expected CORS headers
   */
  getExpectedHeaders: () => ({
    'Access-Control-Allow-Origin': 'https://tokencords.vercel.app/',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Expose-Headers': 'X-Total-Count, X-Auth-Token',
  }),
};

/**
 * Subresource Integrity (SRI) helper
 */
export const sriHelper = {
  /**
   * Generate SRI hash for a file (would be done build-time)
   */
  generateHash: async (data) => {
    const hash = await window.crypto.subtle.digest('SHA-384', new TextEncoder().encode(data));
    const hashArray = Array.from(new Uint8Array(hash));
    const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));
    return `sha384-${hashBase64}`;
  },

  /**
   * Verify script integrity
   */
  verifyScriptIntegrity: (scriptElement) => {
    const integrity = scriptElement.getAttribute('integrity');
    return !!integrity && integrity.startsWith('sha');
  },

  /**
   * Get all scripts without SRI
   */
  findUnprotectedScripts: () => {
    return Array.from(document.querySelectorAll('script[src]')).filter(
      s => !s.getAttribute('integrity')
    );
  },
};

/**
 * Transport Layer Security (TLS) helper
 */
export const tlsHelper = {
  /**
   * Ensure HTTPS-only communication
   */
  enforceHTTPS: () => {
    if (window.location.protocol !== 'https:') {
      // Redirect to HTTPS
      window.location.href = 'https:' + window.location.href.substring(window.location.protocol.length);
    }
  },

  /**
   * Check for HSTS header (needs backend)
   */
  checkHSTS: async () => {
    // Would check response headers - only backend can fully verify
    console.info('HSTS checking requires backend verification');
  },

  /**
   * Detect HTTPS downgrade attacks
   */
  detectDowngrade: () => {
    if (document.referrer && !document.referrer.startsWith('https://')) {
      return true; // Possible downgrade
    }
    return false;
  },
};

export default securityConfig;
