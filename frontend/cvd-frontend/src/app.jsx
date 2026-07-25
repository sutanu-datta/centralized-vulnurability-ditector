import { useEffect, useMemo, useState } from "react";
import "./app.css";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

const DEFAULT_ENGINES = {
  nmap: {
    label: "Nmap",
    enabled: true,
    intensity: "normal",
    brutality: "safe",
    description: "Port, service, OS and NSE scanning",
  },
  nikto: {
    label: "Nikto",
    enabled: false,
    intensity: "normal",
    brutality: "safe",
    description: "Web server misconfiguration and vulnerability scanning",
  },
  wapiti: {
    label: "Wapiti",
    enabled: false,
    intensity: "normal",
    brutality: "safe",
    description: "Web application vulnerability scanning",
  },
  zap: {
    label: "OWASP ZAP",
    enabled: false,
    intensity: "normal",
    brutality: "safe",
    description: "DAST scanner for web applications",
  },
  openvas: {
    label: "OpenVAS",
    enabled: false,
    intensity: "deep",
    brutality: "safe",
    description: "Full vulnerability assessment engine",
  },
  nessus: {
    label: "Nessus",
    enabled: false,
    intensity: "deep",
    brutality: "safe",
    description: "Professional vulnerability scanner",
  },
};

const ESTIMATE_MAP = {
  nmap: { light: 1, normal: 3, deep: 8, full: 15 },
  nikto: { light: 2, normal: 5, deep: 10, full: 15 },
  wapiti: { light: 3, normal: 8, deep: 15, full: 25 },
  zap: { light: 5, normal: 15, deep: 30, full: 45 },
  openvas: { light: 15, normal: 30, deep: 60, full: 90 },
  nessus: { light: 15, normal: 30, deep: 60, full: 90 },
};

function App() {
  const [token, setToken] = useState(localStorage.getItem("cvd_token") || "");
  const [user, setUser] = useState(null);

  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({
    username: "",
    email: "",
    password: "",
  });

  const [view, setView] = useState("scanner");
  const [target, setTarget] = useState("");
  const [engines, setEngines] = useState(DEFAULT_ENGINES);

  const [history, setHistory] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [rawTab, setRawTab] = useState("");

  const [loading, setLoading] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const [error, setError] = useState("");

  const estimatedMinutes = useMemo(() => {
    return Object.entries(engines).reduce((total, [key, engine]) => {
      if (!engine.enabled) return total;
      return total + (ESTIMATE_MAP[key]?.[engine.intensity] || 5);
    }, 0);
  }, [engines]);

  const selectedEngineCount = useMemo(() => {
    return Object.values(engines).filter((engine) => engine.enabled).length;
  }, [engines]);

  const apiFetch = async (path, options = {}) => {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options.headers || {}),
      },
    });

    let data = {};

    try {
      data = await response.json();
    } catch {
      data = {};
    }

    if (!response.ok) {
      throw new Error(data.detail || "Request failed.");
    }

    return data;
  };

  const handleAuth = async (event) => {
    event.preventDefault();
    setError("");

    try {
      const path =
        authMode === "login" ? "/api/auth/login" : "/api/auth/register";

      const payload =
        authMode === "login"
          ? {
              username: authForm.username,
              password: authForm.password,
            }
          : authForm;

      const data = await fetch(`${API_BASE_URL}${path}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }).then(async (res) => {
        const body = await res.json();
        if (!res.ok) throw new Error(body.detail || "Authentication failed.");
        return body;
      });

      localStorage.setItem("cvd_token", data.token);
      setToken(data.token);
      setUser(data.user);
      setAuthForm({ username: "", email: "", password: "" });
    } catch (err) {
      setError(err.message);
    }
  };

  const logout = () => {
    localStorage.removeItem("cvd_token");
    setToken("");
    setUser(null);
    setHistory([]);
    setSelectedScan(null);
    setSelectedScanId(null);
  };

  const loadMe = async () => {
    if (!token) return;

    try {
      const data = await apiFetch("/api/me");
      setUser(data);
    } catch {
      logout();
    }
  };

  const loadHistory = async () => {
    if (!token) return;

    try {
      const data = await apiFetch("/api/scans/history");
      setHistory(data.jobs || []);

      if (!selectedScanId && data.jobs?.length) {
        setSelectedScanId(data.jobs[0].id);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const loadScanDetail = async (scanId) => {
    if (!scanId) return;

    try {
      const data = await apiFetch(`/api/scans/${scanId}`);
      setSelectedScan(data);

      const outputKeys = Object.keys(data.raw_outputs || {});
      if (outputKeys.length && !rawTab) {
        setRawTab(outputKeys[0]);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  useEffect(() => {
    if (token) {
      loadMe();
      loadHistory();
    }
  }, [token]);

  useEffect(() => {
    if (selectedScanId) {
      loadScanDetail(selectedScanId);
    }
  }, [selectedScanId]);

  useEffect(() => {
    if (!activeScanId) return;

    const timer = setInterval(async () => {
      try {
        const data = await apiFetch(`/api/scans/${activeScanId}`);
        setSelectedScan(data);

        if (
          data.scan.status === "completed" ||
          data.scan.status.startsWith("failed")
        ) {
          clearInterval(timer);
          setActiveScanId(null);
          loadHistory();
        }
      } catch (err) {
        setError(err.message);
      }
    }, 3000);

    return () => clearInterval(timer);
  }, [activeScanId]);

  const updateEngine = (key, field, value) => {
    setEngines((prev) => ({
      ...prev,
      [key]: {
        ...prev[key],
        [field]: value,
      },
    }));
  };

  const startScan = async () => {
    setError("");

    if (!target.trim()) {
      setError("Target is required.");
      return;
    }

    if (selectedEngineCount === 0) {
      setError("Select at least one scan engine.");
      return;
    }

    const cleanEngines = {};

    Object.entries(engines).forEach(([key, engine]) => {
      cleanEngines[key] = {
        enabled: engine.enabled,
        intensity: engine.intensity,
        brutality: engine.brutality,
      };
    });

    try {
      setLoading(true);

      const data = await apiFetch("/api/scans", {
        method: "POST",
        body: JSON.stringify({
          target: target.trim(),
          engines: cleanEngines,
        }),
      });

      setActiveScanId(data.scan_id);
      setSelectedScanId(data.scan_id);
      setView("raw");
      await loadHistory();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const severityClass = (severity) => {
    return `sev sev-${String(severity || "info").toLowerCase()}`;
  };

  if (!token) {
    return (
      <div className="authPage">
        <div className="authCard">
          <div className="authLogo">CVD</div>
          <h1>Centralized Vulnerability Detection</h1>
          <p>Login to manage scans, raw outputs, and vulnerability history.</p>

          {error && <div className="errorBox">{error}</div>}

          <form onSubmit={handleAuth}>
            <label>Username</label>
            <input
              value={authForm.username}
              onChange={(e) =>
                setAuthForm({ ...authForm, username: e.target.value })
              }
              placeholder="Enter username"
            />

            {authMode === "register" && (
              <>
                <label>Email</label>
                <input
                  type="email"
                  value={authForm.email}
                  onChange={(e) =>
                    setAuthForm({ ...authForm, email: e.target.value })
                  }
                  placeholder="Enter email"
                />
              </>
            )}

            <label>Password</label>
            <input
              type="password"
              value={authForm.password}
              onChange={(e) =>
                setAuthForm({ ...authForm, password: e.target.value })
              }
              placeholder="Enter password"
            />

            <button className="primaryBtn" type="submit">
              {authMode === "login" ? "Login" : "Create Account"}
            </button>
          </form>

          <button
            className="linkBtn"
            onClick={() => {
              setError("");
              setAuthMode(authMode === "login" ? "register" : "login");
            }}
          >
            {authMode === "login"
              ? "Need an account? Register"
              : "Already have an account? Login"}
          </button>
        </div>
      </div>
    );
  }

  const counts = selectedScan?.scan?.counts || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  return (
    <div className="appShell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brandIcon">CVD</div>
          <div>
            <h2>Centralized</h2>
            <p>Vulnerability Detection</p>
          </div>
        </div>

        <nav className="navMenu">
          <button
            className={`navItem ${view === "scanner" ? "active" : ""}`}
            onClick={() => setView("scanner")}
          >
            Scanner
          </button>

          <button
            className={`navItem ${view === "vulnerabilities" ? "active" : ""}`}
            onClick={() => setView("vulnerabilities")}
          >
            Vulnerabilities
          </button>

          <button
            className={`navItem ${view === "raw" ? "active" : ""}`}
            onClick={() => setView("raw")}
          >
            Raw Output
          </button>

          <button
            className={`navItem ${view === "history" ? "active" : ""}`}
            onClick={() => setView("history")}
          >
            Scan History
          </button>

          <button className="navItem disabled">Reports Later</button>
          <button className="navItem disabled">AI Assistant Later</button>
        </nav>

        <div className="sidebarFooter">
          <p>Logged in as</p>
          <strong>{user?.username}</strong>
          <span>Local backend connected</span>
          <button className="logoutBtn" onClick={logout}>
            Logout
          </button>
        </div>
      </aside>

      <main className="main">
        <header className="header">
          <div>
            <p className="eyebrow">Security Operations Dashboard</p>
            <h1>Multi-Engine Vulnerability Scanner</h1>
            <p className="subtitle">
              Select scan engines, configure intensity, store raw outputs, and
              review simplified vulnerability findings.
            </p>
          </div>

          <div className="apiBadge">
            <span className="dot"></span>
            API: {API_BASE_URL}
          </div>
        </header>

        {error && <div className="errorBox globalError">{error}</div>}

        <section className="statsGrid">
          <div className="statCard">
            <p>Selected Engines</p>
            <h3>{selectedEngineCount}</h3>
            <span>Active for next scan</span>
          </div>

          <div className="statCard">
            <p>Estimated Time</p>
            <h3>{estimatedMinutes} min</h3>
            <span>Approximate duration</span>
          </div>

          <div className="statCard">
            <p>Scan Status</p>
            <h3>{selectedScan?.scan?.status || "Idle"}</h3>
            <span>Current selected scan</span>
          </div>

          <div className="statCard">
            <p>Total History</p>
            <h3>{history.length}</h3>
            <span>Saved scans</span>
          </div>
        </section>

        {view === "scanner" && (
          <section className="contentGrid">
            <div className="panel">
              <div className="panelHeader">
                <div>
                  <h2>Scan Configuration</h2>
                  <p>Choose target and scan engines.</p>
                </div>
              </div>

              <div className="formGroup">
                <label>Target IP / CIDR / Domain / URL</label>
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="Example: 192.168.112.132 or http://testphp.vulnweb.com"
                />
              </div>

              <div className="engineGrid">
                {Object.entries(engines).map(([key, engine]) => (
                  <div
                    className={`engineCard ${
                      engine.enabled ? "engineActive" : ""
                    }`}
                    key={key}
                  >
                    <label className="engineTop">
                      <input
                        type="checkbox"
                        checked={engine.enabled}
                        onChange={(e) =>
                          updateEngine(key, "enabled", e.target.checked)
                        }
                      />
                      <div>
                        <strong>{engine.label}</strong>
                        <span>{engine.description}</span>
                      </div>
                    </label>

                    <div className="engineControls">
                      <div>
                        <label>Intensity</label>
                        <select
                          value={engine.intensity}
                          onChange={(e) =>
                            updateEngine(key, "intensity", e.target.value)
                          }
                        >
                          <option value="light">Light</option>
                          <option value="normal">Normal</option>
                          <option value="deep">Deep</option>
                          <option value="full">Full</option>
                        </select>
                      </div>

                      <div>
                        <label>Brutality</label>
                        <select
                          value={engine.brutality}
                          onChange={(e) =>
                            updateEngine(key, "brutality", e.target.value)
                          }
                        >
                          <option value="safe">Safe</option>
                          <option value="balanced">Balanced</option>
                          <option value="aggressive">Aggressive</option>
                        </select>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="buttonRow">
                <button
                  className="primaryBtn"
                  onClick={startScan}
                  disabled={loading || activeScanId}
                >
                  {loading || activeScanId ? "Scan Running..." : "Start Multi-Engine Scan"}
                </button>
              </div>
            </div>

            <div className="sideStack">
              <div className="panel">
                <h2>Engine Notes</h2>
                <p>
                  Nmap, Nikto and Wapiti run from CLI if installed. ZAP,
                  OpenVAS and Nessus are API-based engines and are kept as
                  placeholder adapters for the next phase.
                </p>
              </div>

              <div className="panel">
                <h2>Recent Scans</h2>
                <div className="historyList">
                  {history.length === 0 && (
                    <p className="emptyText">No saved scans yet.</p>
                  )}

                  {history.slice(0, 6).map((job) => (
                    <button
                      className="historyItem"
                      key={job.id}
                      onClick={() => {
                        setSelectedScanId(job.id);
                        setView("vulnerabilities");
                      }}
                    >
                      <strong>{job.target}</strong>
                      <span>
                        #{job.id} • {job.status} • {job.created_at}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </section>
        )}

        {view === "vulnerabilities" && (
          <section className="panel">
            <div className="panelHeader">
              <div>
                <h2>Vulnerabilities</h2>
                <p>
                  Simplified vulnerability view for selected target and scan.
                </p>
              </div>

              <select
                className="scanSelect"
                value={selectedScanId || ""}
                onChange={(e) => setSelectedScanId(Number(e.target.value))}
              >
                <option value="">Select scan</option>
                {history.map((job) => (
                  <option key={job.id} value={job.id}>
                    #{job.id} - {job.target}
                  </option>
                ))}
              </select>
            </div>

            {selectedScan && (
              <>
                <div className="vulnSummary">
                  <div className="summaryBox critical">
                    <span>Critical</span>
                    <strong>{counts.critical}</strong>
                  </div>
                  <div className="summaryBox high">
                    <span>High</span>
                    <strong>{counts.high}</strong>
                  </div>
                  <div className="summaryBox medium">
                    <span>Medium</span>
                    <strong>{counts.medium}</strong>
                  </div>
                  <div className="summaryBox low">
                    <span>Low</span>
                    <strong>{counts.low}</strong>
                  </div>
                  <div className="summaryBox info">
                    <span>Info</span>
                    <strong>{counts.info}</strong>
                  </div>
                </div>

                <div className="tableWrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Vulnerability</th>
                        <th>Engine</th>
                        <th>Component</th>
                        <th>CVE</th>
                        <th>Remediation</th>
                      </tr>
                    </thead>

                    <tbody>
                      {selectedScan.vulnerabilities.length === 0 && (
                        <tr>
                          <td colSpan="6">No vulnerabilities normalized yet.</td>
                        </tr>
                      )}

                      {selectedScan.vulnerabilities.map((vuln) => (
                        <tr key={vuln.id}>
                          <td>
                            <span className={severityClass(vuln.severity)}>
                              {vuln.severity}
                            </span>
                          </td>
                          <td>{vuln.title}</td>
                          <td>{vuln.engine}</td>
                          <td>{vuln.affected_component || "-"}</td>
                          <td>{vuln.cve || "-"}</td>
                          <td>{vuln.remediation || "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {!selectedScan && <p className="emptyText">Select a scan first.</p>}
          </section>
        )}

        {view === "raw" && (
          <section className="panel">
            <div className="panelHeader">
              <div>
                <h2>Raw Output</h2>
                <p>Exact scanner output for proof and debugging.</p>
              </div>

              <select
                className="scanSelect"
                value={selectedScanId || ""}
                onChange={(e) => setSelectedScanId(Number(e.target.value))}
              >
                <option value="">Select scan</option>
                {history.map((job) => (
                  <option key={job.id} value={job.id}>
                    #{job.id} - {job.target}
                  </option>
                ))}
              </select>
            </div>

            {selectedScan && (
              <>
                <div className="rawTabs">
                  {Object.keys(selectedScan.raw_outputs || {}).map((engine) => (
                    <button
                      key={engine}
                      className={rawTab === engine ? "activeRawTab" : ""}
                      onClick={() => setRawTab(engine)}
                    >
                      {engine}
                    </button>
                  ))}
                </div>

                <pre className="outputBox">
                  {selectedScan.raw_outputs?.[rawTab] ||
                    "No raw output available yet. If scan is running, wait a few seconds."}
                </pre>
              </>
            )}

            {!selectedScan && <p className="emptyText">Select a scan first.</p>}
          </section>
        )}

        {view === "history" && (
          <section className="panel">
            <div className="panelHeader">
              <div>
                <h2>Persistent Scan History</h2>
                <p>This data is saved in SQLite and remains after refresh.</p>
              </div>
            </div>

            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Estimate</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Created</th>
                  </tr>
                </thead>

                <tbody>
                  {history.map((job) => (
                    <tr
                      key={job.id}
                      onClick={() => {
                        setSelectedScanId(job.id);
                        setView("vulnerabilities");
                      }}
                    >
                      <td>#{job.id}</td>
                      <td>{job.target}</td>
                      <td>{job.status}</td>
                      <td>{job.estimated_minutes} min</td>
                      <td>{job.counts.critical}</td>
                      <td>{job.counts.high}</td>
                      <td>{job.counts.medium}</td>
                      <td>{job.created_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

export default App;