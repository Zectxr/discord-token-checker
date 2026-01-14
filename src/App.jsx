import React, { useState, useEffect } from 'react';
import { maskToken, enforceHTTPS } from './utils/security';

function App() {
  const [tokenInput, setTokenInput] = useState('');
  const [hiddenTokens, setHiddenTokens] = useState([]);
  const [results, setResults] = useState([]);
  const [validCount, setValidCount] = useState(0);
  const [invalidCount, setInvalidCount] = useState(0);

  // SECURITY: Cleanup sensitive data on component unmount
  useEffect(() => {
    return () => {
      // Clear all sensitive state when component unmounts
      setTokenInput('');
      setHiddenTokens([]);
      setResults([]);
    };
  }, []);

  // SECURITY: Mask token to prevent exposure in DOM
  const maskToken = (token) => {
    if (!token || token.length < 10) return '***';
    // Show first 8 and last 4 characters only
    return `${token.substring(0, 8)}...${token.substring(token.length - 4)}`;
  };

  const checkTokens = async () => {
    const tokens = hiddenTokens.length > 0
      ? hiddenTokens
      : tokenInput.split('\n').map(t => t.trim()).filter(t => t);

    if (tokens.length === 0) {
      setResults([{ type: 'alert', message: 'No tokens provided' }]);
      return;
    }
    setResults([]); // Clear previous results
    setValidCount(0);
    setInvalidCount(0);

    const newResults = [];
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      const result = await checkSingleToken(token);
      // SECURITY: Store masked token only, never the real token
      const maskedToken = maskToken(token);
      const newResult = { token: maskedToken, result };
      newResults.push(newResult);
      setResults([...newResults]); // Update results incrementally
      updateCounts(newResults); // Update counts after each check
      
      // SECURITY: Explicitly overwrite token in memory
      tokens[i] = null;
    }
    
    // SECURITY: Clear all token references from memory
    setHiddenTokens([]);
    setTokenInput('');
  };

  const checkSingleToken = async (token) => {
    let response;
    try {
      // SECURITY: Enforce HTTPS for all API calls
      const apiUrl = "https://discordapp.com/api/v6/users/@me";
      enforceHTTPS(apiUrl);
      
      response = await fetch(apiUrl, {
        method: "GET",
        headers: { Authorization: token },
      });
      response = await response.json();
    } catch (e) {
      return { error: `Request failed: ${e}` };
    }

    if (!response.username) {
      return { invalid: true };
    }

    let phoneBlockCheck;
    try {
      // SECURITY: Enforce HTTPS for all API calls
      const libraryUrl = "https://discordapp.com/api/v6/users/@me/library";
      enforceHTTPS(libraryUrl);
      
      phoneBlockCheck = await fetch(libraryUrl, {
        method: "GET",
        headers: { Authorization: token },
      });
      phoneBlockCheck = phoneBlockCheck.status;
    } catch (e) {
      return { error: `Request failed: ${e}` };
    }

    switch (phoneBlockCheck) {
      case 200:
        phoneBlockCheck = "not phone locked";
        break;
      default:
        phoneBlockCheck = "phone locked";
        break;
    }

    return {
      tag: response.username + "#" + response.discriminator,
      email: response.email || "no email",
      verified: response.verified ? "Email verified" : "Email not verified",
      id: response.id,
      locale: response.locale,
      phone: response.phone || "no phone number",
      phoneblocked: phoneBlockCheck,
      avatar: response.avatar ? "https://cdn.discordapp.com/avatars/" + response.id + "/" + response.avatar + ".png?size=256" : "https://cdn.discordapp.com/embed/avatars/" + (response.discriminator % 5) + ".png?size=256"
    };
  };

  const updateCounts = (res) => {
    const valid = res.filter(r => r.result && !r.result.invalid && !r.result.error).length;
    const invalid = res.filter(r => r.result && (r.result.invalid || r.result.error)).length;
    setValidCount(valid);
    setInvalidCount(invalid);
  };

  const loadFile = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const fileContent = e.target.result;
        const tokens = fileContent.split('\n').map(t => t.trim()).filter(t => t);
        setHiddenTokens(tokens);
        setTokenInput(`${tokens.length} tokens loaded from file (hidden for security)`);
        
        // SECURITY: Clear file input to prevent re-reading
        event.target.value = null;
      };
      reader.readAsText(file);
    }
  };

  const copySingleResult = (result) => {
    // SECURITY: Copy result WITHOUT token, only account info
    const safeCopy = {
      tag: result.tag,
      email: result.email,
      verified: result.verified,
      id: result.id,
      locale: result.locale,
      phone: result.phone,
      phoneblocked: result.phoneblocked
    };
    navigator.clipboard.writeText(JSON.stringify(safeCopy, null, 2));
  };

  const deleteResult = (index) => {
    const newResults = results.filter((_, i) => i !== index);
    setResults(newResults);
    updateCounts(newResults);
  };

  return (
    <div>
      <header className="app-header">
        <div className="header-left">
          <h1>Account</h1>
          <p className="subtitle">Manage your connected Discord accounts</p>
        </div>
        <div className="header-right">
          <div className="header-stats">
            <span className="stat"><strong>{validCount}</strong> Valid</span>
            <span className="stat"><strong>{invalidCount}</strong> Invalid</span>
          </div>
        </div>
      </header>

      <main className="container">
        <div className="main">
          <textarea
            className="input_main"
            placeholder="Paste tokens here, one per line"
            value={tokenInput}
            onChange={(e) => {
              setTokenInput(e.target.value);
              setHiddenTokens([]); // Clear hidden tokens when user types
            }}
          />
          <div className="buttons">
            <button className="default_button" onClick={checkTokens}>Check Tokens</button>
            <input type="file" id="fileInput" accept=".txt" style={{ display: 'none' }} onChange={loadFile} />
            <button className="default_button" onClick={() => document.getElementById('fileInput').click()}>Load from File</button>
          </div>
        </div>
        <br />
        <br />
        <section className="accounts-area">
          <div className="results">
            {results.length === 0 ? (
              <div className="no-results">Ready to check tokens...</div>
            ) : (
              results.map((item, index) => {
                if (item.type === 'alert') {
                  return (
                    <div key={index} className="alert-card">
                      <span className="alert">{item.message}</span>
                    </div>
                  );
                }
                return (
                  <div key={index} className="account-card" data-status={item.result.invalid || item.result.error ? 'invalid' : 'valid'}>
                    <div className={`status-dot ${item.result.invalid || item.result.error ? 'status-offline' : 'status-online'}`}></div>
                    {item.result.error ? (
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
                        <span className="alert">{item.result.error}</span>
                      </>
                    ) : item.result.invalid ? (
                      <>
                        <div className="account-top">
                          <img className="account-avatar" src="https://cdn.discordapp.com/embed/avatars/0.png?size=256" />
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
                          <img className="account-avatar" src={item.result.avatar} />
                          <div className="account-info">
                            <div className="account-username">{item.result.tag}</div>
                            <div className="account-sub">{item.result.id}</div>
                          </div>
                        </div>
                        <div className="badges">
                          <span className="badge status">Online</span>
                          <span className="badge valid">Valid</span>
                        </div>
                        <ul className="list_group">
                          <li className="list_item token"><strong>Token:</strong> <span className="list_value">{item.token}</span></li>
                          <li className="list_item"><strong>Email:</strong> <span className="list_value">{item.result.email}</span></li>
                          <li className="list_item"><strong>Verified:</strong> <span className="list_value">{item.result.verified}</span></li>
                          <li className="list_item"><strong>Locale:</strong> <span className="list_value">{item.result.locale}</span></li>
                          <li className="list_item"><strong>Phone:</strong> <span className="list_value">{item.result.phone}</span></li>
                        </ul>
                        <div className="card-buttons">
                          <button className="default_button" onClick={() => copySingleResult(item.result)}>Copy</button>
                          <button className="delete-btn" title="Remove" onClick={() => deleteResult(index)}>🗑️</button>
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