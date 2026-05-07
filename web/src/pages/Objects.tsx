import { useParams, Link } from 'react-router-dom'
import { useSession } from '../api/client'

export default function Objects() {
  const { id } = useParams<{ id: string }>()
  const { data: session, isLoading } = useSession(id || '')

  if (isLoading || !session) return <p>Loading...</p>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 600 }}>Objects</h2>
          <p style={{ fontSize: '13px', color: '#6b7280' }}>
            {session.hostname || session.vendor}
          </p>
        </div>
        <Link to={`/dashboard/${id}`} style={{ color: '#3b82f6', textDecoration: 'none', fontSize: '13px' }}>
          &larr; Back to Dashboard
        </Link>
      </div>

      <div style={{ marginBottom: '32px' }}>
        <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '12px' }}>
          Address Objects ({session.address_objects.length})
        </h3>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr>
              <th style={thStyle}>Name</th>
              <th style={thStyle}>Type</th>
              <th style={thStyle}>Value</th>
              <th style={thStyle}>Members</th>
              <th style={thStyle}>Description</th>
            </tr>
          </thead>
          <tbody>
            {session.address_objects.map(obj => (
              <tr key={obj.name}>
                <td style={tdStyle}>{obj.name}</td>
                <td style={tdStyle}>{obj.type}</td>
                <td style={tdStyle}>{obj.value}</td>
                <td style={tdStyle}>{obj.members ? obj.members.join(', ') : '-'}</td>
                <td style={tdStyle}>{obj.description || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div>
        <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '12px' }}>
          Service Objects ({session.service_objects.length})
        </h3>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr>
              <th style={thStyle}>Name</th>
              <th style={thStyle}>Protocol</th>
              <th style={thStyle}>Ports</th>
              <th style={thStyle}>Members</th>
              <th style={thStyle}>Description</th>
            </tr>
          </thead>
          <tbody>
            {session.service_objects.map(obj => (
              <tr key={obj.name}>
                <td style={tdStyle}>{obj.name}</td>
                <td style={tdStyle}>{obj.protocol}</td>
                <td style={tdStyle}>{obj.ports.join(', ') || '-'}</td>
                <td style={tdStyle}>{(obj as any).members ? (obj as any).members.join(', ') : '-'}</td>
                <td style={tdStyle}>{obj.description || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

const thStyle = { background: '#f3f4f6', border: '1px solid #d1d5db', padding: '8px', textAlign: 'left' }
const tdStyle = { border: '1px solid #d1d5db', padding: '6px 8px', fontSize: '12px' }
