/**
 * @fileoverview Runtime integrity and anti-tampering measures
 */

class RuntimeIntegrity {
  constructor() {
    this.scriptHashes = new Map();
    this.domObservers = [];
    this.integrityViolations = [];
    this.frozenObjects = new WeakSet();
  }

  /**
   * Initialize runtime protection (should be called early)
   */
  initialize() {
    this.freezeCriticalObjects();
    this.setupDOMMonitoring();
    this.setupFunctionTraps();
    this.validateInitialScripts();
  }

  /**
   * Freeze critical objects to prevent modification
   */
  freezeCriticalObjects() {
    const criticalObjects = [
      window.location,
      window.history,
      window.navigator,
      window.crypto,
      window.localStorage,
      window.sessionStorage,
    ];

    for (const obj of criticalObjects) {
      try {
        Object.freeze(obj);
        Object.freeze(Object.getPrototypeOf(obj));
        this.frozenObjects.add(obj);
      } catch (e) {
        // Some objects may not be freezable
        console.debug('Could not freeze object');
      }
    }

    // Freeze global functions
    Object.freeze(window.fetch);
    Object.freeze(window.XMLHttpRequest);
    Object.freeze(Array.prototype);
    Object.freeze(Object.prototype);
  }

  /**
   * Monitor DOM for unauthorized modifications
   */
  setupDOMMonitoring() {
    // Monitor for script injection
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'childList') {
          for (const node of mutation.addedNodes) {
            if (node.tagName === 'SCRIPT') {
              this.integrityViolations.push({
                type: 'script_injection',
                timestamp: Date.now(),
                src: node.src || 'inline',
              });
              console.warn('Script injection detected');
            }

            // Check for suspicious attributes
            if (node.setAttribute && (
              node.getAttribute('onload') ||
              node.getAttribute('onerror') ||
              node.getAttribute('onclick')
            )) {
              this.integrityViolations.push({
                type: 'event_handler_injection',
                timestamp: Date.now(),
              });
            }
          }
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
    });

    this.domObservers.push(observer);
  }

  /**
   * Setup traps for critical functions
   */
  setupFunctionTraps() {
    // Trap eval
    const originalEval = window.eval;
    window.eval = new Proxy(originalEval, {
      apply: (target, thisArg, args) => {
        this.integrityViolations.push({
          type: 'eval_attempted',
          timestamp: Date.now(),
          args: String(args[0]).substring(0, 100), // First 100 chars
        });
        throw new Error('eval() is disabled for security');
      },
    });

    // Trap Function constructor
    const OriginalFunction = window.Function;
    window.Function = new Proxy(OriginalFunction, {
      construct: (target, args) => {
        this.integrityViolations.push({
          type: 'function_constructor_attempted',
          timestamp: Date.now(),
        });
        throw new Error('Function constructor is disabled for security');
      },
    });

    // Trap innerHTML assignment
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    Object.defineProperty(Element.prototype, 'innerHTML', {
      ...descriptor,
      set: new Proxy(descriptor.set, {
        apply: (target, thisArg, args) => {
          // Allow setting, but monitor it
          if (args[0] && args[0].includes('<script')) {
            this.integrityViolations.push({
              type: 'script_injection_via_innerHTML',
              timestamp: Date.now(),
            });
          }
          return target.apply(thisArg, args);
        },
      }),
    });
  }

  /**
   * Validate that scripts haven't been modified (via SRI if available)
   */
  validateInitialScripts() {
    const scripts = document.querySelectorAll('script[src]');
    for (const script of scripts) {
      const src = script.src;
      const integrity = script.getAttribute('integrity');

      // Skip Vite development server scripts (localhost) - they don't have SRI in dev
      const isViteDev = src.includes('localhost') || src.includes('127.0.0.1') || src.includes('@vite');
      
      if (!integrity && !isViteDev) {
        console.warn(`Script ${src} lacks SRI integrity attribute`);
      }

      // Store hash for later verification
      this.scriptHashes.set(src, {
        integrity: integrity || null,
        validated: !!integrity,
      });
    }
  }

  /**
   * Check for prototype pollution attacks
   */
  detectPrototypePollution() {
    const testObj = {};
    const suspicious = [];

    // Check if Object.prototype has been modified
    const protoKeys = Object.getOwnPropertyNames(Object.prototype);
    const expectedProtoKeys = [
      'constructor', 'toString', 'toLocaleString', 'valueOf',
      'hasOwnProperty', 'isPrototypeOf', 'propertyIsEnumerable',
      '__defineGetter__', '__defineSetter__', '__lookupGetter__', '__lookupSetter__',
    ];

    for (const key of protoKeys) {
      if (!expectedProtoKeys.includes(key) && !key.startsWith('__')) {
        suspicious.push(key);
      }
    }

    return suspicious;
  }

  /**
   * Check for XSS vulnerabilities in DOM
   */
  scanForXSS() {
    const issues = [];

    // Check all event handlers
    const elementsWithHandlers = document.querySelectorAll('[onclick], [onload], [onerror], [onmouseover]');
    if (elementsWithHandlers.length > 0) {
      issues.push({
        type: 'inline_event_handlers',
        count: elementsWithHandlers.length,
      });
    }

    // Check for suspicious attributes
    const allElements = document.querySelectorAll('*');
    for (const el of allElements) {
      const attrs = el.attributes;
      for (const attr of attrs) {
        if (attr.name.startsWith('on') || attr.value.includes('javascript:')) {
          issues.push({
            type: 'suspicious_attribute',
            element: el.tagName,
            attribute: attr.name,
          });
        }
      }
    }

    return issues;
  }

  /**
   * Get integrity violations
   */
  getViolations() {
    return {
      count: this.integrityViolations.length,
      violations: this.integrityViolations,
      xssIssues: this.scanForXSS(),
      prototypePollution: this.detectPrototypePollution(),
    };
  }

  /**
   * Report violations (would send to backend in real app)
   */
  reportViolations() {
    if (this.integrityViolations.length === 0) return;

    const report = {
      timestamp: Date.now(),
      violations: this.integrityViolations,
      url: window.location.href,
      userAgent: navigator.userAgent,
    };

    // In production, send to backend
    console.warn('Integrity violations detected:', report);
  }

  /**
   * Stop all monitoring
   */
  shutdown() {
    for (const observer of this.domObservers) {
      observer.disconnect();
    }
    this.domObservers = [];
  }
}

/**
 * Anti-automation behavioral analysis
 */
class BehaviorAnalysis {
  constructor() {
    this.interactions = [];
    this.maxInteractions = 1000;
  }

  /**
   * Start monitoring user interactions
   */
  startMonitoring() {
    this.setupInteractionTracking();
  }

  /**
   * Setup interaction tracking
   */
  setupInteractionTracking() {
    const trackInteraction = (type) => (event) => {
      this.interactions.push({
        type,
        timestamp: Date.now(),
        target: event.target?.tagName || 'unknown',
      });

      // Keep bounded size
      if (this.interactions.length > this.maxInteractions) {
        this.interactions.shift();
      }
    };

    document.addEventListener('click', trackInteraction('click'));
    document.addEventListener('keydown', trackInteraction('keydown'));
    document.addEventListener('mousemove', trackInteraction('mousemove'), { passive: true });
    document.addEventListener('scroll', trackInteraction('scroll'), { passive: true });
  }

  /**
   * Analyze interaction patterns for automation
   */
  analyzePatterns() {
    const analysis = {
      totalInteractions: this.interactions.length,
      isAutomated: false,
      suspicionScore: 0,
      indicators: [],
    };

    // Check for unnatural timing patterns
    if (this.interactions.length >= 10) {
      const intervals = [];
      for (let i = 1; i < Math.min(10, this.interactions.length); i++) {
        intervals.push(this.interactions[i].timestamp - this.interactions[i - 1].timestamp);
      }

      const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
      const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avgInterval, 2), 0) / intervals.length;

      // Very low variance = suspicious (automated)
      if (variance < 10) {
        analysis.indicators.push('regular_timing');
        analysis.suspicionScore += 25;
      }
    }

    // Check for lack of mouse movement
    const mouseEvents = this.interactions.filter(i => i.type === 'mousemove').length;
    if (mouseEvents === 0 && this.interactions.length > 5) {
      analysis.indicators.push('no_mouse_movement');
      analysis.suspicionScore += 30;
    }

    // Check for lack of user delays
    const noDelayClicks = this.interactions.filter(i => i.type === 'click').length;
    if (noDelayClicks > this.interactions.length * 0.8) {
      analysis.indicators.push('suspicious_click_ratio');
      analysis.suspicionScore += 15;
    }

    analysis.isAutomated = analysis.suspicionScore > 40;
    return analysis;
  }

  /**
   * Get interaction history
   */
  getHistory() {
    return this.interactions.slice(-50); // Last 50 interactions
  }
}

export const runtimeIntegrity = new RuntimeIntegrity();
export const behaviorAnalysis = new BehaviorAnalysis();
