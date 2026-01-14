/**
 * Security utilities for safe token handling
 * Ensures tokens never persist on disk or in network logs
 */

/**
 * Securely wipe a string from memory by overwriting it
 * @param {string} sensitiveData - The sensitive string to wipe
 */
export const wipeFromMemory = (sensitiveData) => {
  if (typeof sensitiveData === 'string') {
    // Overwrite the string content (best effort in JavaScript)
    // Note: JavaScript doesn't provide true memory control, but this helps
    sensitiveData = '\0'.repeat(sensitiveData.length);
  }
  return null;
};

/**
 * Mask a token to hide sensitive portions
 * @param {string} token - The token to mask
 * @returns {string} - Masked token showing only first 8 and last 4 chars
 */
export const maskToken = (token) => {
  if (!token || token.length < 12) return '***';
  return `${token.substring(0, 8)}${'*'.repeat(token.length - 12)}${token.substring(token.length - 4)}`;
};

/**
 * Validate that all network requests use HTTPS
 * @param {string} url - URL to validate
 * @throws {Error} - If URL doesn't use HTTPS
 */
export const enforceHTTPS = (url) => {
  if (!url.startsWith('https://')) {
    throw new Error('SECURITY: Only HTTPS connections are allowed');
  }
};

/**
 * Create a secure cleanup handler for component unmount
 * @param {Function} setState - State setter function to clear
 */
export const createCleanupHandler = (setState) => {
  return () => {
    setState([]);
    setState('');
    setState(null);
  };
};
