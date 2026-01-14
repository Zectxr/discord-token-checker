import React, { useState, useEffect } from 'react';
import { maskToken, enforceHTTPS, validateConnectionSecurity, verifyEnvironmentSecurity } from './utils/security';

const DISCORD_API = 'https://discordapp.com/api/v6';

function App() {
  const [input, setInput] = useState('');
  const [fileTokens, setFileTokens] = useState([]);
  const [results, setResults] = useState([]);
  const [stats, setStats] = useState({ valid: 0, invalid: 0 });
  const [visibility, setVisibility] = useState({});

  useEffect(() => {
    verifyEnvironmentSecurity();
  }, []);

  useEffect(() => {
    return () => {
      setInput('');
      setFileTokens([]);
      setResults([]);
    };
  }, []);

  const updateStats = (items) => {
    const valid = items.filter(r => r.result && !r.result.invalid && !r.result.error).length;
    const invalid = items.filter(r => r.result && (r.result.invalid || r.result.error)).length;
    setStats({ valid, invalid });
  };

  const checkToken = async (token) => {
    try {
      const url = `${DISCORD_API}/users/@me`;
      enforceHTTPS(url);
      validateConnectionSecurity(url);

      const res = await fetch(url, {
        headers: { Authorization: token },
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store'
      });

      if (!res.ok) return { invalid: true };
      const data = await res.json();

      if (!data.username) return { invalid: true };

      let phoneLocked = 'phone locked';
      try {
        const libUrl = `${DISCORD_API}/users/@me/library`;
        enforceHTTPS(libUrl);
        validateConnectionSecurity(libUrl);

        const libRes = await fetch(libUrl, {
          headers: { Authorization: token },
          mode: 'cors',
          credentials: 'omit',
          cache: 'no-store'
        });

        if (libRes.status === 200) phoneLocked = 'not phone locked';
      } catch (e) {
        // library check optional
      }

      const avatarId = data.avatar || (data.discriminator % 5);
      const avatarUrl = data.avatar
        ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png?size=256`
        : `https://cdn.discordapp.com/embed/avatars/${avatarId}.png?size=256`;

      return {
        tag: `${data.username}#${data.discriminator}`,
        email: data.email || 'no email',
        verified: data.verified ? 'Email verified' : 'Email not verified',
        id: data.id,
        locale: data.locale,
        phone: data.phone || 'no phone',
        phoneLocked,
        avatar: avatarUrl
      };
    } catch (e) {
      return { error: String(e) };
    }
  };

  const check = async () => {
    const tokens = fileTokens.length > 0
      ? fileTokens
      : input.split('\n').map(t => t.trim()).filter(Boolean);

    if (!tokens.length) {
      setResults([{ type: 'alert', msg: 'No tokens provided' }]);
      return;
    }

    setResults([]);
    setStats({ valid: 0, invalid: 0 });

    const checked = [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      const result = await checkToken(token);
      const item = { token: maskToken(token), result };
      checked.push(item);
      setResults([...checked]);
      updateStats(checked);
      tokens[i] = null;
    }

    setFileTokens([]);
    setInput('');
  };

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result || '';
      const tokens = String(content).split('\n').map(t => t.trim()).filter(Boolean);
      setFileTokens(tokens);
      setInput(`${tokens.length} tokens loaded (hidden)`);
      e.target.value = '';
    };
    reader.readAsText(file);
  };

  const copyResult = (data) => {
    const { token, ...safe } = data;
    navigator.clipboard.writeText(JSON.stringify(safe, null, 2));
  };

  const removeResult = (idx) => {
    const next = results.filter((_, i) => i !== idx);
    setResults(next);
    updateStats(next);
  };

  const isError = (r) => r.result?.error || r.result?.invalid;

  const toggleVisibility = (idx, field) => {
    setVisibility(prev => ({
      ...prev,
      [`${idx}-${field}`]: !prev[`${idx}-${field}`]
    }));
  };

  const isVisible = (idx, field) => visibility[`${idx}-${field}`] || false;

  const maskValue = (value) => '•'.repeat(value?.length || 8);

  return (
    <div>
      <header className="app-header">
        <div className="header-left">
          <h1>Account</h1>
          <p className="subtitle">Check your Discord tokens</p>
        </div>
        <div className="header-right">
          <div className="header-stats">
            <span className="stat"><strong>{stats.valid}</strong> Valid</span>
            <span className="stat"><strong>{stats.invalid}</strong> Invalid</span>
          </div>
        </div>
      </header>

      <main className="container">
        <div className="main">
          <textarea
            className="input_main"
            placeholder="Paste tokens here, one per line"
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setFileTokens([]);
            }}
          />
          <div className="buttons">
            <button className="default_button" onClick={check}>Check Tokens</button>
            <input type="file" id="file" accept=".txt" className="hidden-input" onChange={handleFile} />
            <button className="default_button" onClick={() => document.getElementById('file')?.click()}>
              Load from File
            </button>
          </div>
        </div>

        <section className="accounts-area">
          <div className="results">
            {results.length === 0 ? (
              <div className="no-results">Ready to check...</div>
            ) : (
              results.map((item, i) => {
                if (item.type === 'alert') {
                  return <div key={i} className="alert-card"><span className="alert">{item.msg}</span></div>;
                }

                const { result } = item;
                const failed = isError(result);

                return (
                  <div key={i} className="account-card" data-status={failed ? 'invalid' : 'valid'}>
                    <div className={`status-dot ${failed ? 'status-offline' : 'status-online'}`}></div>

                    {result.error ? (
                      <>
                        <div className="account-top">
                          <div className="account-info">
                            <div className="account-username">{item.token}</div>
                            <div className="account-sub">Request failed</div>
                          </div>
                        </div>
                        <div className="badges">
                          <span className="badge status">Error</span>
                        </div>
                        <span className="alert">{result.error}</span>
                      </>
                    ) : result.invalid ? (
                      <>
                        <div className="account-top">
                          <img className="account-avatar" src="https://cdn.discordapp.com/embed/avatars/0.png?size=256" alt="" />
                          <div className="account-info">
                            <div className="account-username">Invalid Token</div>
                            <div className="account-sub">{item.token}</div>
                          </div>
                        </div>
                        <div className="badges">
                          <span className="badge status">Offline</span>
                          <span className="badge">Invalid</span>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="account-top">
                          <img className="account-avatar" src={result.avatar} alt="" />
                          <div className="account-info">
                            <div className="account-username">{result.tag}</div>
                            <div className="account-sub">{result.id}</div>
                          </div>
                        </div>
                        <div className="badges">
                          <span className="badge status">Online</span>
                          <span className="badge valid">Valid</span>
                        </div>
                        <ul className="list_group">
                          <li className="list_item"><strong>Token:</strong> <code className="token-code">{item.token}</code></li>
                          <li className="list_item">
                            <strong>Email:</strong> 
                            <span className="sensitive-field">
                              {isVisible(i, 'email') ? result.email : maskValue(result.email)}
                              <button className="eye-btn" onClick={() => toggleVisibility(i, 'email')}>
                                {isVisible(i, 'email') ? '👁️' : '👁️‍🗨️'}
                              </button>
                            </span>
                          </li>
                          <li className="list_item"><strong>Verified:</strong> <span>{result.verified}</span></li>
                          <li className="list_item"><strong>Locale:</strong> <span>{result.locale}</span></li>
                          <li className="list_item">
                            <strong>Phone:</strong> 
                            <span className="sensitive-field">
                              {isVisible(i, 'phone') ? result.phone : maskValue(result.phone)}
                              <button className="eye-btn" onClick={() => toggleVisibility(i, 'phone')}>
                                {isVisible(i, 'phone') ? '👁️' : '👁️‍🗨️'}
                              </button>
                            </span>
                          </li>
                        </ul>
                        <div className="card-buttons">
                          <button className="default_button" onClick={() => copyResult(result)}>Copy</button>
                          <button className="delete-btn" title="Remove" onClick={() => removeResult(i)}>🗑️</button>
                        </div>
                      </>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </section>
      </main>

      <footer>
        <span className="a_container">[<a href="https://github.com/Zectxr">Github</a>]</span>
        <span className="a_container"> [<a href="https://github.com/Zectxr/discord-token-checker">Repo</a>] </span>
      </footer>
    </div>
  );
}

export default App;