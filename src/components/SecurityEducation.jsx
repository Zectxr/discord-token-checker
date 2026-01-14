import React, { useState } from 'react';
import './SecurityEducation.css';

export function SecurityEducation() {
  const [expanded, setExpanded] = useState({});

  const sections = [
    {
      id: 'why-tokens-dangerous',
      title: 'Why Tokens Are Dangerous',
      content: `Discord tokens grant full access to your account - reading DMs, changing passwords, deleting accounts, etc. If you paste your token anywhere, attackers can use it immediately.`,
      tips: [
        'Never paste tokens anywhere',
        'Never share tokens in screenshots',
        'If compromised, regenerate immediately'
      ]
    },
    {
      id: 'how-oauth-protects',
      title: 'How OAuth2 Protects You',
      content: `You login on Discord's official website. Your password stays with Discord. We get limited, controlled access. This is how Google, GitHub logins work.`,
      tips: [
        'Password stays on Discord',
        'Limited access only',
        'Revoke anytime',
        'No DM, payment, or password access'
      ]
    },
    {
      id: 'account-security',
      title: 'Account Security Best Practices',
      content: '',
      tips: [
        'Enable 2FA',
        'Use strong passwords',
        'Enable backup codes',
        'Review connected apps',
        'Check active sessions',
        'Regenerate tokens regularly'
      ]
    },
    {
      id: 'red-flags',
      title: 'Red Flags - What NOT to Do',
      content: '',
      tips: [
        'Sites asking for your token directly',
        'Fake account checkers',
        'DMs asking to verify your account',
        'Free Nitro offers for tokens',
        'SEO rank checkers',
        'Verification scams in servers'
      ]
    }
  ];

  return (
    <div className="security-education">
      <h2>Security Education</h2>
      
      <div className="education-alert alert-info">
        <p><strong>Why we don't ask for your token:</strong></p>
        <p>We use OAuth2. You login through Discord's official website. Limited access only. Your token never touches our servers.</p>
      </div>

      <div className="education-sections">
        {sections.map((section) => (
          <div key={section.id} className="education-card">
            <button
              className="education-header"
              onClick={() => setExpanded(prev => ({ ...prev, [section.id]: !prev[section.id] }))}
            >
              <h3>{section.title}</h3>
              <span className="expand-icon">{expanded[section.id] ? '−' : '+'}</span>
            </button>

            {expanded[section.id] && (
              <div className="education-content">
                <p>{section.content}</p>
                <ul className="tips-list">
                  {section.tips.map((tip, idx) => (
                    <li key={idx}>{tip}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="education-alert alert-success">
        <h4>How We Protect You</h4>
        <ul>
          <li>OAuth2 login - no token storage</li>
          <li>Token-paste detection in UI</li>
          <li>Client-side encryption</li>
          <li>No server-side logging</li>
          <li>HTTPS and security headers</li>
        </ul>
      </div>
    </div>
  );
}
