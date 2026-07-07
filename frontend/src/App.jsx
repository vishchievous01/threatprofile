import { useState } from 'react'
import axios from 'axios'
import './App.css'

function App() {
  const [ip, setIp] = useState('')
  const [profile, setProfile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [hasSearched, setHasSearched] = useState(false)

  const handleLookup = async () => {
    if (!ip.trim()) return
    setLoading(true)
    setError('')
    setProfile(null)
    setHasSearched(true)
    try {
      const res = await axios.post('http://127.0.0.1:8000/api/lookup/', { ip })
      setProfile(res.data)
    } catch (err) {
      setError(err.response?.data?.error || 'Lookup failed. Check the IP and try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter') handleLookup()
  }

  const scoreColor = (score) => {
    if (score >= 75) return '#e53935'
    if (score >= 30) return '#fb8c00'
    return '#43a047'
  }

  return (
    <div className="app">
      <h1>ThreatProfile</h1>
      <p className="subtitle">Automated attacker intelligence — one IP, one call, full profile.</p>

      <div className="search-bar">
        <input
          type="text"
          placeholder="Enter IP address (e.g. 185.220.101.1)"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          onKeyDown={handleKeyDown}
        />
        <button onClick={handleLookup} disabled={loading}>
          {loading ? 'Investigating...' : 'Lookup'}
        </button>
      </div>

      {error && <p className="error">{error}</p>}

      {loading && (
        <div className="profile-card skeleton">
          <div className="skeleton-line skeleton-title"></div>
          <div className="skeleton-line skeleton-short"></div>
          <div className="skeleton-grid">
            <div className="skeleton-line"></div>
            <div className="skeleton-line"></div>
            <div className="skeleton-line"></div>
            <div className="skeleton-line"></div>
          </div>
        </div>
      )}

      {!loading && !hasSearched && (
        <div className="empty-state">
          <p>Enter an IP address above to build a full attacker profile -</p>
          <p className="empty-state-sub">
            reputation, open ports, MITRE ATT&CK techniques, and related CVEs, all in one lookup.
          </p>
        </div>
      )}

      {!loading && profile && (
        <div className="profile-card">
          <div className="profile-header">
            <h2>{profile.ip_address}</h2>
            <span
              className="score-badge"
              style={{ backgroundColor: scoreColor(profile.abuse_score) }}
            >
              {profile.abuse_score}% Abuse Score
            </span>
          </div>

          <div className="profile-grid">
            <div><strong>Country:</strong> {profile.country || 'Unknown'}</div>
            <div><strong>ISP:</strong> {profile.isp || 'Unknown'}</div>
            <div><strong>Organization:</strong> {profile.org || 'Unknown'}</div>
            <div><strong>Total Reports:</strong> {profile.total_reports}</div>
            <div><strong>VT Malicious Votes:</strong> {profile.vt_malicious_votes}</div>
            <div><strong>VT Suspicious Votes:</strong> {profile.vt_suspicious_votes}</div>
            <div><strong>Open Ports:</strong> {profile.open_ports?.join(', ') || 'None detected'}</div>
            <div><strong>Hostnames:</strong> {profile.hostnames?.join(', ') || 'None'}</div>
          </div>

          {profile.techniques?.length > 0 && (
            <div className="section">
              <h3>MITRE ATT&CK Techniques</h3>
              {profile.techniques.map((t) => (
                <div key={t.technique_id} className="technique-item">
                  <span className="tag">{t.technique_id}</span>
                  <strong>{t.name}</strong> — <em>{t.tactic}</em>
                  <p>{t.description}</p>
                </div>
              ))}
            </div>
          )}

          {profile.cves?.length > 0 && (
            <div className="section">
              <h3>Related CVEs ({profile.cves.length})</h3>
              {profile.cves.map((cve) => (
                <div key={cve.cve_id} className="cve-item">
                  <span className="tag cve-tag">{cve.cve_id}</span>
                  <span className="cvss">CVSS: {cve.cvss_score}</span>
                  <p>{cve.description}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <footer className="app-footer">
        Powered by AbuseIPDB · VirusTotal · Shodan (InternetDB) · MITRE ATT&CK · NVD
      </footer>
    </div>
  )
}

export default App