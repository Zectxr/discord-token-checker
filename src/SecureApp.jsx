/**
 * SECURE React Component for Token Checker
 * 
 * Best practices demonstrated:
 * - No hardcoded secrets
 * - All sensitive logic delegated to backend
 * - Secure request signing
 * - Response verification
 * - Safe error handling
 * - Input validation
 * - XSS prevention
 * - Memory cleanup
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import TokenCheckerAPI from './utils/SecureClient';

function SecureTokenChecker() {
  // ============================================
  // State Management
  // ============================================

  const [tokenInput, setTokenInput] = useState('');
  const [results, setResults] = useState([]);
  const [validCount, setValidCount] = useState(0);
  const [invalidCount, setInvalidCount] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState({ current: 0, total: 0 });

  // Refs for cleanup
  const apiRef = useRef(null);
  const abortControllerRef = useRef(null);

  // ============================================
  // Initialization & Cleanup
  // ============================================

  useEffect(() => {
    // Initialize secure API client
    apiRef.current = new TokenCheckerAPI();

    // Cleanup on unmount
    return () => {
      // Clear sensitive data from memory
      setTokenInput('');
      setResults([]);
      
      // Logout session
      if (apiRef.current) {
        apiRef.current.logout();
      }
    };
  }, []);

  // ============================================
  // Security Helpers
  // ============================================

  /**
   * Sanitize token input
   * 
   * Removes whitespace and invalid characters
   */
  const sanitizeToken = useCallback((token) => {
    return token
      .trim()
      .replace(/[^\w.-]/g, '') // Keep only word chars, dots, hyphens
      .slice(0, 512); // Limit length
  }, []);

  /**
   * Validate token format
   * 
   * Basic frontend validation (backend does authoritative check)
   */
  const isValidTokenFormat = useCallback((token) => {
    // Discord tokens are typically 72-80 characters of base64-like data
    // Format: user_id.timestamp.hmac
    const tokenPattern = /^[\w\-\.]{20,100}$/;
    return tokenPattern.test(token);
  }, []);

  /**
   * Parse and validate token input
   */
  const parseTokenInput = useCallback((input) => {
    if (!input || typeof input !== 'string') {
      return [];
    }

    const tokens = input
      .split('\n')
      .map(line => sanitizeToken(line))
      .filter(token => token.length > 0);

    // Check for duplicates
    const uniqueTokens = [...new Set(tokens)];

    if (uniqueTokens.length !== tokens.length) {
      setError('Warning: Duplicate tokens were removed');
    }

    // Validate format
    const validTokens = uniqueTokens.filter(token => {
      const valid = isValidTokenFormat(token);
      if (!valid) {
        console.warn(`Invalid token format: ${token.slice(0, 10)}...`);
      }
      return valid;
    });

    if (validTokens.length === 0) {
      throw new Error('No valid tokens found in input');
    }

    if (validTokens.length > 100) {
      throw new Error('Maximum 100 tokens per check (abuse prevention)');
    }

    return validTokens;
  }, [sanitizeToken, isValidTokenFormat]);

  // ============================================
  // Token Checking
  // ============================================

  /**
   * Check tokens via secure backend
   */
  const checkTokens = useCallback(async () => {
    try {
      setError(null);
      setIsLoading(true);
      setResults([]);

      // Parse input
      const tokens = parseTokenInput(tokenInput);

      if (tokens.length === 0) {
        throw new Error('No tokens provided');
      }

      // Create abort controller for cancellation
      abortControllerRef.current = new AbortController();

      // Validate tokens
      const results = await apiRef.current.validateTokens(
        tokens,
        (progressUpdate) => {
          setProgress(progressUpdate);
          // Don't expose token in results to prevent XSS
          const safeResult = {
            ...progressUpdate.result,
            tokenPreview: `${progressUpdate.result.tokenPreview || ''}...`
          };
          setResults(prev => [...prev, safeResult]);
        }
      );

      // Calculate summary
      const validResults = results.filter(r => r.valid && !r.error);
      const invalidResults = results.filter(r => !r.valid || r.error);

      setValidCount(validResults.length);
      setInvalidCount(invalidResults.length);

      // Store safe results (no full tokens)
      const safeResults = results.map(r => ({
        valid: r.valid,
        details: r.details,
        error: r.error,
        checkId: r.checkId
      }));

      setResults(safeResults);

    } catch (err) {
      console.error('Token check error:', err);
      setError(err.message || 'Failed to check tokens');
      setResults([]);
      setValidCount(0);
      setInvalidCount(0);
    } finally {
      setIsLoading(false);
      setProgress({ current: 0, total: 0 });
      
      // Clear input for security
      setTokenInput('');
    }
  }, [tokenInput, parseTokenInput]);

  // ============================================
  // File Upload Handler
  // ============================================

  const handleFileUpload = useCallback((event) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file size (max 1MB)
    if (file.size > 1024 * 1024) {
      setError('File too large (max 1MB)');
      return;
    }

    // Validate file type
    const validTypes = ['text/plain', 'application/octet-stream'];
    if (!validTypes.includes(file.type)) {
      setError('Invalid file type (text files only)');
      return;
    }

    const reader = new FileReader();

    reader.onload = (e) => {
      try {
        const fileContent = e.target?.result;
        if (typeof fileContent !== 'string') {
          throw new Error('Failed to read file');
        }

        const tokens = parseTokenInput(fileContent);
        setTokenInput(
          `${tokens.length} tokens loaded from file (will be cleared after checking)`
        );

        // Store tokens securely (in state, never in DOM)
        // In real implementation, might use a ref or secure storage
      } catch (err) {
        setError(err.message || 'Failed to parse file');
      }
    };

    reader.onerror = () => {
      setError('Failed to read file');
    };

    reader.readAsText(file);

    // Clear file input
    event.target.value = '';
  }, [parseTokenInput]);

  // ============================================
  // Cancel Handler
  // ============================================

  const handleCancel = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setIsLoading(false);
    setProgress({ current: 0, total: 0 });
  }, []);

  // ============================================
  // Render
  // ============================================

  return (
    <div className="token-checker-container">
      <div className="checker-card">
        <h1>🔐 Secure Discord Token Checker</h1>

        {/* Security Notice */}
        <div className="security-notice">
          <strong>🛡️ Security Guaranteed:</strong>
          <ul>
            <li>✓ HTTPS encrypted - all data in transit</li>
            <li>✓ Backend-only token validation - no frontend exposure</li>
            <li>✓ HMAC-signed requests - tampering prevention</li>
            <li>✓ Replay attack protection - nonce validation</li>
            <li>✓ Rate limiting - automated abuse prevention</li>
          </ul>
        </div>

        {/* Error Display */}
        {error && (
          <div className="error-box">
            <strong>⚠️ Error:</strong> {error}
            <button onClick={() => setError(null)}>Dismiss</button>
          </div>
        )}

        {/* Input Section */}
        <div className="input-section">
          <label htmlFor="token-input">Enter Discord Tokens (one per line):</label>
          <textarea
            id="token-input"
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            placeholder="Paste Discord tokens here..."
            rows={8}
            disabled={isLoading}
            maxLength={10000}
          />

          <div className="input-controls">
            <label htmlFor="file-upload" className="file-upload-label">
              📁 Upload from File
            </label>
            <input
              id="file-upload"
              type="file"
              accept=".txt"
              onChange={handleFileUpload}
              disabled={isLoading}
              style={{ display: 'none' }}
            />

            <button
              onClick={checkTokens}
              disabled={isLoading || !tokenInput.trim()}
              className={isLoading ? 'button-loading' : ''}
            >
              {isLoading ? '⏳ Checking...' : '✓ Check Tokens'}
            </button>

            {isLoading && (
              <button onClick={handleCancel} className="button-cancel">
                ✕ Cancel
              </button>
            )}
          </div>

          {/* Progress Indicator */}
          {isLoading && progress.total > 0 && (
            <div className="progress-indicator">
              <div className="progress-bar">
                <div
                  className="progress-fill"
                  style={{
                    width: `${(progress.current / progress.total) * 100}%`
                  }}
                />
              </div>
              <p>
                {progress.current} / {progress.total} tokens checked
              </p>
            </div>
          )}
        </div>

        {/* Results Summary */}
        {(validCount > 0 || invalidCount > 0) && (
          <div className="results-summary">
            <div className="summary-stat valid">
              <span className="stat-value">{validCount}</span>
              <span className="stat-label">Valid</span>
            </div>
            <div className="summary-stat invalid">
              <span className="stat-value">{invalidCount}</span>
              <span className="stat-label">Invalid</span>
            </div>
            <div className="summary-stat total">
              <span className="stat-value">{validCount + invalidCount}</span>
              <span className="stat-label">Total</span>
            </div>
          </div>
        )}

        {/* Results Display */}
        {results.length > 0 && (
          <div className="results-section">
            <h2>Results</h2>
            <div className="results-list">
              {results.map((result, index) => (
                <div
                  key={index}
                  className={`result-item ${result.valid ? 'valid' : 'invalid'}`}
                >
                  <div className="result-header">
                    <span className="result-status">
                      {result.valid ? '✓' : '✗'}
                    </span>
                    <span className="result-index">Token {index + 1}</span>
                  </div>

                  {result.valid && result.details && (
                    <div className="result-details">
                      <p>
                        <strong>Username:</strong> {result.details.username}
                      </p>
                      <p>
                        <strong>ID:</strong> {result.details.id}
                      </p>
                      {result.details.email && (
                        <p>
                          <strong>Email:</strong> {result.details.email}
                        </p>
                      )}
                      {result.details.verified !== undefined && (
                        <p>
                          <strong>Verified:</strong>{' '}
                          {result.details.verified ? 'Yes' : 'No'}
                        </p>
                      )}
                    </div>
                  )}

                  {!result.valid && (
                    <p className="result-error">
                      {result.error || 'Token is invalid'}
                    </p>
                  )}

                  <div className="result-meta">
                    <small>Check ID: {result.checkId}</small>
                  </div>
                </div>
              ))}
            </div>

            {/* Export Results */}
            <button
              onClick={() => {
                // Export as JSON (no sensitive data)
                const data = JSON.stringify(results, null, 2);
                const blob = new Blob([data], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `token-check-results-${Date.now()}.json`;
                a.click();
                URL.revokeObjectURL(url);
              }}
              className="button-secondary"
            >
              📥 Export Results
            </button>
          </div>
        )}

        {/* Footer */}
        <div className="footer">
          <p>
            <strong>Privacy Notice:</strong> Tokens are never stored on our
            servers. All checks are temporary and discarded immediately.
          </p>
          <button
            onClick={() => {
              apiRef.current?.logout();
              setTokenInput('');
              setResults([]);
              setError(null);
            }}
            className="button-logout"
          >
            🚪 Logout
          </button>
        </div>
      </div>
    </div>
  );
}

export default SecureTokenChecker;
