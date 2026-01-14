import React, { useState, useEffect } from 'react';
import { useOAuth } from '../context/OAuthContext';
import { SecurityEducation } from './SecurityEducation';
import { useTokenPasteDetection } from '../utils/tokenPasteDetection';
import './AppOAuth.css';

export function AppOAuth() {
  const { user, isAuthenticated, startOAuthFlow, logout, loading, error } = useOAuth();
  const [securityReport, setSecurityReport] = useState(null);
  const [tokenPasteWarning, setTokenPasteWarning] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    if (code && !isAuthenticated) {
      // callback handled by context
    }
  }, [isAuthenticated]);

  const analyzeAccountSecurity = () => {
    if (!user) return;

    const checks = [];
    let score = 0;

    if (user.verified) {
      checks.push({ status: '✓', label: 'Email verified', points: 20 });
      score += 20;
    } else {
      checks.push({ status: '✗', label: 'Email not verified', points: 0 });
    }

    if (user.mfaEnabled) {
      checks.push({ status: '✓', label: '2FA enabled', points: 30 });
      score += 30;
    } else {
      checks.push({ status: '✗', label: '2FA disabled', points: 0 });
    }

    if (user.premiumType) {
      const premiumType = user.premiumType === 1 ? 'Nitro' : 'Classic';
      checks.push({ status: '◆', label: `Premium: ${premiumType}`, points: 5 });
      score += 5;
    }

    if (user.publicFlags) {
      const flags = interpretPublicFlags(user.publicFlags);
      if (flags.length > 0) {
        checks.push({ status: 'ℹ️', label: `Badges: ${flags.join(', ')}`, points: 0 });
      }
    }

    setSecurityReport({
      score: Math.min(score, 100),
      checks,
      recommendations: generateRecommendations(user)
    });
  };

  const interpretPublicFlags = (flags) => {
    const flagMap = {
      1: 'Discord Employee',
      2: 'Discord Partner',
      4: 'HypeSquad Event',
      8: 'Bug Hunter Lvl 1',
      64: 'HypeSquad Balance',
      128: 'HypeSquad Bravery',
      256: 'HypeSquad Brilliance',
      512: 'Early Supporter',
      1024: 'Bot Developer',
      16384: 'Bug Hunter Lvl 2',
    };

    return Object.entries(flagMap)
      .filter(([value]) => (flags & parseInt(value)) !== 0)
      .map(([_, name]) => name);
  };

  const generateRecommendations = (user) => {
    const recs = [];
    if (!user.verified) recs.push('Verify your email in Discord settings');
    if (!user.mfaEnabled) recs.push('Enable Two-Factor Authentication (2FA)');
    if (!user.avatar) recs.push('Add a profile picture');
    if (recs.length === 0) recs.push('Your account security looks good');
    return recs;
  };

  const handleTokenPaste = useTokenPasteDetection((warning, risk) => {
    setTokenPasteWarning({ warning, risk });
    setTimeout(() => setTokenPasteWarning(null), 10000);
  });

  if (loading) {
    return <div className="app-oauth loading">Checking your account...</div>;
  }

  return (
    <div className="app-oauth">
      <header className="oauth-header">
        <h1>Discord Account Security Checker</h1>
        <p>Check your account security with OAuth2</p>
      </header>

      {error && (
        <div className="alert alert-error">
          <strong>Error:</strong> {error}
        </div>
      )}

      {tokenPasteWarning && (
        <div className={`alert alert-${tokenPasteWarning.risk.level === 'CRITICAL' ? 'error' : 'warning'}`}>
          <strong>{tokenPasteWarning.warning.title}</strong>
          <p>{tokenPasteWarning.warning.message}</p>
          <p><em>{tokenPasteWarning.warning.advice}</em></p>
        </div>
      )}

      {!isAuthenticated ? (
        <section className="login-section">
          <div className="login-card">
            <h2>Welcome to TokenCords</h2>
            <p>We'll analyze your Discord account security without ever asking for your token.</p>

            <div className="feature-list">
              <div className="feature">
                <strong>OAuth2 Login</strong>
                <p>Your password stays on Discord</p>
              </div>
              <div className="feature">
                <strong>No Token Storage</strong>
                <p>Tokens never stored or logged</p>
              </div>
              <div className="feature">
                <strong>Security Analysis</strong>
                <p>Get your account security report</p>
              </div>
            </div>

            <button 
              className="btn btn-primary btn-large"
              onClick={startOAuthFlow}
            >
              Login with Discord
            </button>

            <p className="privacy-notice">
              By logging in, you authorize us to view your account information. 
              You can revoke access anytime in your <a href="https://discord.com/user/settings/authorized-apps" target="_blank" rel="noopener noreferrer">Discord settings</a>.
            </p>
          </div>

          <SecurityEducation />
        </section>
      ) : (
        <section className="dashboard-section">
          <div className="user-card">
            {user.avatar && (
              <img
                src={`https://cdn.discord.com/avatars/${user.id}/${user.avatar}.png?size=256`}
                alt="Avatar"
                className="user-avatar"
              />
            )}
            <div className="user-info">
              <h2>{user.username}</h2>
              <p className="user-email">{user.email}</p>
              <button className="btn btn-secondary" onClick={logout}>Logout</button>
            </div>
          </div>

          {securityReport ? (
            <div className="security-report">
              <h3>Account Security Report</h3>
              
              <div className="security-score">
                <div className="score-circle" style={{
                  background: `conic-gradient(
                    ${securityReport.score > 60 ? '#4caf50' : securityReport.score > 30 ? '#ff9800' : '#f44336'} 0deg,
                    ${securityReport.score}%,
                    #ddd ${securityReport.score}%
                  )`
                }}>
                  <span className="score-text">{securityReport.score}</span>
                </div>
                <p>Security Score</p>
              </div>

              <div className="checks-list">
                {securityReport.checks.map((check, idx) => (
                  <div key={idx} className="check-item">
                    <span className="check-status">{check.status}</span>
                    <span className="check-label">{check.label}</span>
                  </div>
                ))}
              </div>

              <div className="recommendations">
                <h4>Recommendations</h4>
                <ul>
                  {securityReport.recommendations.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <button className="btn btn-primary" onClick={analyzeAccountSecurity}>
              Analyze My Account Security
            </button>
          )}

          <SecurityEducation />

          <div className="test-area">
            <h3>Test Token Paste Detection</h3>
            <p>Try pasting a Discord token here - we'll warn you:</p>
            <textarea
              className="test-input"
              placeholder="Try pasting a Discord token here..."
              onPaste={handleTokenPaste}
              disabled
            />
          </div>
        </section>
      )}
    </div>
  );
}
