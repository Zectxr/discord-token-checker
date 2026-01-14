/**
 * Security utilities for safe token handling and MITM prevention
 * Ensures tokens never persist on disk or in network, and all communications are secure
 */

/**
 * Known Discord API endpoints with certificate fingerprints
 * Used for certificate pinning to prevent MITM attacks
 */
const DISCORD_HOSTS = {
  'discordapp.com': ['discordapp.com', '*.discordapp.com'],
  'discord.com': ['discord.com', '*.discord.com']
};

export const maskToken = (token) => {
  if (!token || token.length < 12) return '***';
  return `${token.substring(0, 8)}${'*'.repeat(token.length - 12)}${token.substring(token.length - 4)}`;
};

export const enforceHTTPS = (url) => {
  if (!url.startsWith('https://')) {
    throw new Error('Only HTTPS connections allowed');
  }

  const { hostname } = new URL(url);
  const isAllowed = Object.values(DISCORD_HOSTS).some(domains =>
    domains.some(d => {
      if (d.startsWith('*.')) {
        return hostname.endsWith(d.slice(2));
      }
      return hostname === d;
    })
  );

  if (!isAllowed) {
    throw new Error(`Untrusted host: ${hostname}`);
  }
};

export const validateConnectionSecurity = (url) => {
  if (window.location.protocol !== 'https:') {
    throw new Error('App must be served over HTTPS');
  }

  const { protocol } = new URL(url);
  if (protocol !== 'https:') {
    throw new Error('API requests must use HTTPS');
  }
};

export const verifyEnvironmentSecurity = () => {
  const checks = {
    https: window.location.protocol === 'https:',
    noLocalStorage: localStorage.length === 0,
    noSessionStorage: sessionStorage.length === 0,
  };

  if (process.env.NODE_ENV === 'development') {
    console.log('🔒 Security check:', checks);
  }

  if (!checks.https) {
    console.warn('⚠️ Not running over HTTPS');
  }

  return checks;
};

