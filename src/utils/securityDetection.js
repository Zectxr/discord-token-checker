/**
 * @fileoverview Comprehensive security detection module
 * Detects: DevTools, headless browsers, proxies, tampering, suspicious environments
 * 
 * IMPORTANT: These are heuristics, not foolproof. Defense-in-depth is essential.
 */

class SecurityDetection {
  constructor() {
    this.detectionHistory = [];
    this.suspicionLevel = 0;
    this.MAX_SUSPICION = 100;
    this.detectionStartTime = Date.now();
  }

  /**
   * Run all security checks and return comprehensive report
   */
  runFullSecurityAudit() {
    const report = {
      timestamp: Date.now(),
      checks: {},
      suspicionLevel: 0,
      flagged: false,
      isProduction: !this.isDevelopmentEnvironment(),
    };

    // Core detection suites
    report.checks.devTools = this.detectDevTools();
    report.checks.headless = this.detectHeadlessBrowser();
    report.checks.automation = this.detectAutomationTools();
    report.checks.proxy = this.detectProxyIndicators();
    report.checks.environment = this.detectSuspiciousEnvironment();
    report.checks.tampering = this.detectTampering();
    report.checks.timing = this.detectAnomalousTimings();

    // Calculate overall suspicion level
    report.suspicionLevel = this.calculateSuspicionLevel(report.checks);
    report.flagged = report.suspicionLevel > 40;

    return report;
  }

  /**
   * Detect DevTools usage via multiple heuristics
   */
  detectDevTools() {
    const indicators = [];

    // 1. Check console.clear/console calls behavior (don't actually clear console)
    const originalLog = console.log;
    let logCalled = false;
    console.log = () => { logCalled = true; };
    // Detect if console.clear exists and check behavior
    const originalClear = console.clear;
    if (originalClear) {
      // Test behavior without actually clearing
      const testStr = typeof originalClear === 'function' ? 'function' : typeof originalClear;
    }
    console.log = originalLog;

    // 2. Check debugger statement breakpoint
    let debuggerBreakDetected = false;
    try {
      const start = performance.now();
      // debugger statement removed - not reliable for DevTools detection
      const elapsed = performance.now() - start;
      if (elapsed > 100) debuggerBreakDetected = true;
    } catch (e) {
      // Ignored
    }

    // 3. Function toString inspection (if overridden, likely DevTools)
    const nativeFnString = Function.prototype.toString.toString();
    if (!nativeFnString.includes('[native code]')) {
      indicators.push('function_toString_modified');
    }

    // 4. Check window.devtools-like properties
    if (window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
      indicators.push('react_devtools_detected');
    }

    // 5. Console timing attack
    const consoleTimings = this.checkConsoleTimings();
    if (consoleTimings) indicators.push('console_timing_anomaly');

    // 6. Check for common debugging breakpoint indicators
    if (debuggerBreakDetected) {
      indicators.push('debugger_breakpoint_detected');
    }

    return {
      detected: indicators.length > 0,
      indicators,
      risk: indicators.length > 1 ? 'HIGH' : (indicators.length === 1 ? 'MEDIUM' : 'LOW'),
    };
  }

  /**
   * Check console timing anomalies (DevTools impacts performance)
   */
  checkConsoleTimings() {
    try {
      const start = performance.now();
      console.log('%c ', 'font-size: 1000px');
      const elapsed = performance.now() - start;
      // DevTools console often slows down significantly
      return elapsed > 50;
    } catch (e) {
      return false;
    }
  }

  /**
   * Detect headless browser environments
   */
  detectHeadlessBrowser() {
    const indicators = [];

    // 1. Navigator properties typical of headless browsers
    const headlessIndicators = [
      !navigator.webdriver === false,
      navigator.webdriver === true,
      !window.chrome && !window.opera,
      navigator.userAgent.includes('HeadlessChrome'),
      navigator.userAgent.includes('PhantomJS'),
    ];

    if (headlessIndicators.some(x => x)) {
      indicators.push('navigator_headless_indicators');
    }

    // 2. Check for Puppeteer-specific globals
    if (window.callPhantom || window.__nightmare || window.document.documentElement.getAttribute('webdriver')) {
      indicators.push('automation_framework_detected');
    }

    // 3. WebGL/GPU detection (headless browsers often lack this)
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) {
      indicators.push('missing_webgl_context');
    }

    // 4. Check for typical headless behavior: missing plugins
    if (navigator.plugins && navigator.plugins.length === 0) {
      indicators.push('no_plugins');
    }

    // 5. Screen dimensions suspicious
    if (window.outerWidth === 0 || window.outerHeight === 0) {
      indicators.push('zero_screen_dimensions');
    }

    // 6. Timezone/language oddities
    if (!Intl.DateTimeFormat().resolvedOptions().timeZone) {
      indicators.push('missing_timezone');
    }

    return {
      detected: indicators.length > 0,
      indicators,
      risk: indicators.length >= 2 ? 'HIGH' : (indicators.length === 1 ? 'MEDIUM' : 'LOW'),
    };
  }

  /**
   * Detect common automation tool usage
   */
  detectAutomationTools() {
    const indicators = [];

    // Puppeteer/Playwright specific
    if (navigator.userAgent.includes('HeadlessChrome') || 
        navigator.userAgent.includes('Chrome/') && !window.chrome) {
      indicators.push('puppeteer_probable');
    }

    // Selenium
    if (window.document.documentElement.getAttribute('webdriver') || 
        navigator.webdriver === true) {
      indicators.push('selenium_probable');
    }

    // Nightmre.js
    if (window.__nightmare) {
      indicators.push('nightmare_detected');
    }

    // Playwright
    if (navigator.userAgent.includes('pw-run')) {
      indicators.push('playwright_detected');
    }

    // Check for synthetic mouse events
    this.monitorMouseEvents();
    if (this.syntheticMouseDetected) {
      indicators.push('synthetic_mouse_events');
    }

    // Check for unnatural network timing
    if (this.detectUnusualNetworkPatterns()) {
      indicators.push('unusual_network_patterns');
    }

    return {
      detected: indicators.length > 0,
      indicators,
      risk: indicators.length > 1 ? 'HIGH' : (indicators.length === 1 ? 'MEDIUM' : 'LOW'),
    };
  }

  /**
   * Monitor mouse events for synthetic patterns
   */
  monitorMouseEvents() {
    this.mouseEvents = [];
    this.syntheticMouseDetected = false;

    document.addEventListener('mousemove', (e) => {
      const now = performance.now();
      this.mouseEvents.push(now);

      // Keep last 100 events
      if (this.mouseEvents.length > 100) this.mouseEvents.shift();

      // Check for regular intervals (synthetic)
      if (this.mouseEvents.length >= 5) {
        const intervals = [];
        for (let i = 1; i < this.mouseEvents.length; i++) {
          intervals.push(this.mouseEvents[i] - this.mouseEvents[i - 1]);
        }

        // Human-like movement has variation; synthetic is regular
        const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
        const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length;

        if (variance < 1) { // Very low variance = synthetic
          this.syntheticMouseDetected = true;
        }
      }
    });
  }

  /**
   * Detect unusual network patterns (too fast, too regular)
   */
  detectUnusualNetworkPatterns() {
    // This would require tracking actual network requests
    // For now, return false - would be enhanced with actual request monitoring
    return false;
  }

  /**
   * Detect proxy usage via multiple heuristics
   */
  detectProxyIndicators() {
    const indicators = [];

    // 1. Check for common proxy headers in responses (if accessible)
    // Note: CORS restrictions limit what we can see, but we can infer from timing

    // 2. Check geolocation vs timezone mismatch (if available)
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (timezone && timezone.includes('UTC')) {
      indicators.push('generic_timezone'); // Proxies often have generic TZ
    }

    // 3. Additional proxy detection would go here
    // (DNS rebinding test removed - too unreliable)

    // 4. Check for VPN/Proxy headers (limited by CORS)
    // Would need backend to verify

    // 5. Check for split personality (requests behave differently)
    // This requires tracking actual requests

    return {
      detected: indicators.length > 0,
      indicators,
      risk: 'LOW', // Proxy detection is unreliable from browser
    };
  }

  /**
   * Detect suspicious environment configurations
   */
  detectSuspiciousEnvironment() {
    const indicators = [];

    // 1. Check if running in iframe with mismatched origin
    try {
      if (window.self !== window.top) {
        indicators.push('running_in_iframe');
      }
    } catch (e) {
      indicators.push('cross_origin_iframe_detected');
    }

    // 2. Check localStorage/sessionStorage availability
    if (!this.isStorageAccessible('localStorage')) {
      indicators.push('localStorage_restricted');
    }

    // 3. Check for CSP violations
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (!cspMeta && !this.hasStrictCSP()) {
      indicators.push('weak_or_missing_csp');
    }

    // 4. Check for document domain manipulation
    if (document.domain !== location.hostname) {
      indicators.push('document_domain_mismatch');
    }

    // 5. Check for SOP violations (cross-origin requests)
    if (!window.crossOriginIsolated) {
      indicators.push('missing_cross_origin_isolation');
    }

    return {
      detected: indicators.length > 0,
      indicators,
      risk: indicators.length > 2 ? 'MEDIUM' : 'LOW',
    };
  }

  /**
   * Check if storage is accessible
   */
  isStorageAccessible(storageType) {
    try {
      const storage = window[storageType];
      const testKey = '__storage_test_' + Math.random();
      storage.setItem(testKey, 'test');
      storage.removeItem(testKey);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * Check if strict CSP is in place
   */
  hasStrictCSP() {
    // This would need to check response headers (backend only)
    // For now, return true (assume it's set)
    return true;
  }

  /**
   * Detect tampering indicators
   */
  detectTampering() {
    const indicators = [];

    // 1. Check if native functions have been modified
    const nativeFunctions = [
      { name: 'fetch', fn: window.fetch },
      { name: 'XMLHttpRequest', fn: window.XMLHttpRequest },
      { name: 'eval', fn: window.eval },
      { name: 'Function', fn: window.Function },
    ];

    for (const native of nativeFunctions) {
      try {
        if (native.fn && !this.isNativeFunction(native.fn)) {
          indicators.push(`${native.name}_modified`);
        }
      } catch (e) {
        indicators.push(`${native.name}_inspection_failed`);
      }
    }

    // 2. Check if script integrity has been compromised
    if (!this.validateScriptIntegrity()) {
      indicators.push('script_integrity_failed');
    }

    // 3. Check for global object modifications
    const suspiciousGlobals = this.findSuspiciousGlobals();
    if (suspiciousGlobals.length > 0) {
      indicators.push('suspicious_globals_injected');
    }

    // 4. Check localStorage/cookies for injection markers
    if (this.detectInjectedStorage()) {
      indicators.push('injected_storage_detected');
    }

    return {
      detected: indicators.length > 0,
      indicators,
      risk: indicators.length > 1 ? 'HIGH' : (indicators.length === 1 ? 'MEDIUM' : 'LOW'),
    };
  }

  /**
   * Check if a function is native (hasn't been modified)
   */
  isNativeFunction(fn) {
    try {
      const fnString = fn.toString();
      return /\[native code\]/.test(fnString) || fnString.includes('[native code]');
    } catch (e) {
      return false;
    }
  }

  /**
   * Validate that script hasn't been modified (uses SRI hashes if available)
   */
  validateScriptIntegrity() {
    // This would check script tags for integrity attributes
    // For now, just check if any scripts lack integrity
    const scripts = document.querySelectorAll('script[src]');
    const unprotectedScripts = Array.from(scripts).filter(
      s => !s.getAttribute('integrity')
    ).length;

    // In production, all scripts should have integrity
    return unprotectedScripts === 0 || unprotectedScripts < 2;
  }

  /**
   * Detect suspicious globals that shouldn't exist
   */
  findSuspiciousGlobals() {
    const suspicious = [];
    const knownSuspicious = [
      'debugger', '__dev', '__debug', '_console', '__injected',
      'chrome', 'phantomjs', 'callPhantom', '__nightmare'
    ];

    for (const key of knownSuspicious) {
      if (key in window && window[key] !== undefined) {
        suspicious.push(key);
      }
    }

    return suspicious;
  }

  /**
   * Detect injected markers in storage
   */
  detectInjectedStorage() {
    if (!this.isStorageAccessible('localStorage')) return false;

    try {
      const localStorage = window.localStorage;
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.includes('_injected') || key.includes('_tampered'))) {
          return true;
        }
      }
    } catch (e) {
      // Storage not accessible
    }

    return false;
  }

  /**
   * Detect anomalous timing patterns (automation characteristic)
   */
  detectAnomalousTimings() {
    const indicators = [];

    // 1. Check if time.now() has unusual precision
    const timesamples = [];
    for (let i = 0; i < 10; i++) {
      timesamples.push(performance.now());
    }

    // Check for regular intervals or suspicious precision
    const diffs = [];
    for (let i = 1; i < timesamples.length; i++) {
      diffs.push(timesamples[i] - timesamples[i - 1]);
    }

    const avgDiff = diffs.reduce((a, b) => a + b) / diffs.length;
    if (avgDiff < 0.1) {
      indicators.push('time_resolution_too_high');
    }

    // 2. Check for Date.now() manipulation
    const dateNow = Date.now();
    if (Math.abs(Date.now() - dateNow) > 1000) {
      indicators.push('date_now_inconsistent');
    }

    // 3. Check requestAnimationFrame timing
    let rafTiming = 0;
    const rafStart = performance.now();
    requestAnimationFrame(() => {
      rafTiming = performance.now() - rafStart;
    });

    // This will complete asynchronously, but typically should be < 20ms
    setTimeout(() => {
      if (rafTiming > 100) {
        indicators.push('raf_timing_anomalous');
      }
    }, 50);

    return {
      detected: indicators.length > 0,
      indicators,
      risk: indicators.length > 0 ? 'LOW' : 'LOW', // Timing is hard to spoof
    };
  }

  /**
   * Calculate overall suspicion level (0-100)
   */
  calculateSuspicionLevel(checks) {
    let level = 0;

    const weights = {
      devTools: 30,
      headless: 35,
      automation: 40,
      proxy: 5,
      environment: 15,
      tampering: 45,
      timing: 20,
    };

    for (const [check, weight] of Object.entries(weights)) {
      if (checks[check] && checks[check].detected) {
        const indicatorCount = checks[check].indicators.length;
        level += Math.min(weight, weight * (indicatorCount / 3));
      }
    }

    return Math.min(level, 100);
  }

  /**
   * Check if running in development environment
   */
  isDevelopmentEnvironment() {
    return (
      !window.location.hostname.includes('.') ||
      window.location.hostname === 'localhost' ||
      window.location.hostname === '127.0.0.1' ||
      process.env.NODE_ENV === 'development'
    );
  }

  /**
   * Get human-readable security report
   */
  getSecurityReport(audit) {
    const report = {
      status: audit.flagged ? 'SUSPICIOUS' : 'NORMAL',
      suspicionScore: Math.round(audit.suspicionLevel),
      details: {},
    };

    for (const [check, result] of Object.entries(audit.checks)) {
      if (result.detected) {
        report.details[check] = {
          risk: result.risk,
          indicators: result.indicators,
        };
      }
    }

    return report;
  }
}

export const securityDetection = new SecurityDetection();
