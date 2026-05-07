import { Link } from 'react-router-dom'
import { useSessions, useDeleteSession } from '../api/client'
import FindingBadge from '../components/FindingBadge'

export default function Sessions() {
  const { data, isLoading } = useSessions()
  const deleteSession = useDeleteSession()
  const sessions = data?.sessions || []

  if (isLoading) return <p>Loading sessions...</p>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 600 }}>Sessions</h2>
        <Link to="/upload" style={{
          padding: '8px 16px',
          background: '#3b82f6',
          color: 'white',
          borderRadius: '6px',
          textDecoration: 'none',
          fontSize: '14px',
        }}>
          + Upload New
        </Link>
      </div>

      {sessions.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '48px', color: '#6b7280' }}>
          <p style={{ fontSize: '16px', marginBottom: '8px' }}>No sessions yet</p>
          <Link to="/upload" style={{ color: '#3b82f6' }}>Upload your first config</Link>
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr>
              <th style={thStyle}>Hostname</th>
              <th style={thStyle}>Vendor</th>
              <th style={thStyle}>Rules</th>
              <th style={thStyle}>Health</th>
              <th style={thStyle}>Findings</th>
              <th style={thStyle}>Uploaded</th>
              <th style={thStyle}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map(s => (
              <tr key={s.id}>
                <td style={tdStyle}>
                  <Link to={`/dashboard/${s.id}`} style={{ color: '#3b82f6', textDecoration: 'none', fontWeight: 500 }}>
                    {s.hostname || s.vendor}
                  </Link>
                </td>
                <td style={tdStyle}>{s.vendor}</td>
                <td style={tdStyle}>{s.rule_count}</td>
                <td style={tdStyle}>
                  <span style={{
                    color: s.health_score >= 70 ? '#16a34a' : s.health_score >= 40 ? '#ca8a04' : '#dc2626',
                    fontWeight: 600,
                  }}>
                    {s.health_score}
                  </span>
                </td>
                <td style={tdStyle}>
                  <div style={{ display: 'flex', gap: '4px' }}>
                    {Object.entries(s.finding_counts || {}).map(([sev, count]) => (
                      <FindingBadge key={sev} severity={sev} count={count as number} />
                    ))}
                  </div>
                </td>
                <td style={tdStyle}>{new Date(s.created_at).toLocaleDateString()}</td>
                <td style={tdStyle}>
                  <button
                    onClick={() => { if (confirm('Delete this session?')) deleteSession.mutate(s.id) }}
                    style={{
                      background: 'none',
                      border: 'none',
                      color: '#dc2626',
                      cursor: 'pointer',
                      fontSize: '12px',
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const thStyle = { background: '#f3f4f6', border: '1px solid #d1d5db', padding: '8px', textAlign: 'left' }
const tdStyle = { border: '1px solid #d1d5db', padding: '8px' }
