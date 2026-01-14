import React, { createContext, useContext, useState } from 'react';

const OAuthContext = createContext(null);

export function OAuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Configuration
  const DISCORD_CLIENT_ID = process.env.REACT_APP_DISCORD_CLIENT_ID;
  const REDIRECT_URI = process.env.REACT_APP_DISCORD_REDIRECT_URI || 'https://tokencords.vercel.app/oauth-callback';
  const SCOPES = ['identify', 'email'];

  const startOAuthFlow = () => {
    const authUrl = new URL('https://discord.com/api/oauth2/authorize');
    authUrl.searchParams.append('client_id', DISCORD_CLIENT_ID);
    authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('scope', SCOPES.join(' '));
    authUrl.searchParams.append('prompt', 'consent');

    window.location.href = authUrl.toString();
  };

  const handleOAuthCallback = async (code) => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/discordOAuth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });

      if (!response.ok) {
        throw new Error('Failed to exchange authorization code');
      }

      const data = await response.json();
      setAccessToken(data.access_token);
      await fetchUserProfile(data.access_token);

    } catch (err) {
      console.error('OAuth error:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchUserProfile = async (token) => {
    try {
      const [userRes, securityRes] = await Promise.all([
        fetch('https://discord.com/api/v10/users/@me', {
          headers: { Authorization: `Bearer ${token}` },
        }),
        fetch('https://discord.com/api/v10/users/@me/settings', {
          headers: { Authorization: `Bearer ${token}` },
        }).catch(() => null),
      ]);

      if (!userRes.ok) {
        throw new Error('Failed to fetch user profile');
      }

      const userData = await userRes.json();
      const securityData = securityRes?.ok ? await securityRes.json() : null;

      setUser({
        id: userData.id,
        username: userData.username,
        email: userData.email,
        verified: userData.verified,
        avatar: userData.avatar,
        mfaEnabled: userData.mfa_enabled,
        premiumType: userData.premium_type,
        publicFlags: userData.public_flags,
        securitySettings: securityData,
      });

    } catch (err) {
      console.error('Profile fetch error:', err);
      setError(err.message);
    }
  };

  const logout = () => {
    setAccessToken(null);
    setUser(null);
    setError(null);
  };

  const isAuthenticated = !!accessToken && !!user;

  return (
    <OAuthContext.Provider
      value={{
        user,
        accessToken,
        loading,
        error,
        isAuthenticated,
        startOAuthFlow,
        handleOAuthCallback,
        logout,
      }}
    >
      {children}
    </OAuthContext.Provider>
  );
}

export function useOAuth() {
  const context = useContext(OAuthContext);
  if (!context) {
    throw new Error('useOAuth must be used within OAuthProvider');
  }
  return context;
}
