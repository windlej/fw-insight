import { useParams, Link } from 'react-router-dom'
import { useSession } from '../api/client'

export default function NatRules() {
  const { id } = useParams<{ id: string }>()
  const { data: session, isLoading } = useSession(id || '')

  if (isLoading || !session) return <p>Loading...</p>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 600 }}>NAT Rules</h2>
          <p style={{ fontSize: '13px', color: '#6b7280' }}>
            {session.hostname || session.vendor} | {session.nat_rules.length} rules
          </p>
        </div>
        <Link to={`/dashboard/${id}`} style={{ color: '#3b82f6', textDecoration: 'none', fontSize: '13px' }}>
          &larr; Back to Dashboard
        </Link>
      </div>

      {session.nat_rules.length === 0 ? (
        <p style={{ color: '#6b7280' }}>No NAT rules found.</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr>
              <th style={thStyle}>#</th>
              <th style={thStyle}>Name</th>
              <th style={thStyle}>Type</th>
              <th style={thStyle}>Original Source</th>
              <th style={thStyle}>Translated Source</th>
              <th style={thStyle}>Original Dest</th>
              <th style={thStyle}>Translated Dest</th>
              <th style={thStyle}>Enabled</th>
            </tr>
          </thead>
          <tbody>
            {session.nat_rules.map(rule => (
              <tr key={rule.id}>
                <td style={tdStyle}>{rule.position}</td>
                <td style={tdStyle}>{rule.name || rule.id}</td>
                <td style={tdStyle}>{rule.type}</td>
                <td style={tdStyle}>{rule.original_source || 'any'}</td>
                <td style={tdStyle}>{rule.translated_source || '-'}</td>
                <td style={tdStyle}>{rule.original_destination || 'any'}</td>
                <td style={tdStyle}>{rule.translated_destination || '-'}</td>
                <td style={tdStyle}>{rule.enabled ? 'Yes' : 'No'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

const thStyle = { background: '#f3f4f6', border: '1px solid #d1d5db', padding: '8px', textAlign: 'left' }
const tdStyle = { border: '1px solid #d1d5db', padding: '6px 8px', fontSize: '12px' }
