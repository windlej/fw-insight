import { useParams, Link } from 'react-router-dom'
import { useSession, useAnalysis } from '../api/client'
import FindingBadge from '../components/FindingBadge'

export default function RuleDetail() {
  const { id, ruleId } = useParams<{ id: string; ruleId: string }>()
  const { data: session } = useSession(id || '')
  const { data: analysis } = useAnalysis(id || '')

  if (!session) return <p>Loading...</p>

  const policy = session.security_policies.find(p => p.id === ruleId)
  if (!policy) return <p>Rule not found: {ruleId}</p>

  const findings = (analysis?.findings || []).filter(f => f.entity_id === policy.id)

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <Link to={`/policies/${id}`} style={{ color: '#3b82f6', textDecoration: 'none', fontSize: '13px' }}>
          &larr; Back to Policies
        </Link>
      </div>

      <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '16px' }}>
        {policy.name || policy.id}
      </h2>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
        <div style={{ background: 'white', padding: '16px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
          <h3 style={{ fontSize: '13px', color: '#6b7280', textTransform: 'uppercase', marginBottom: '8px' }}>Source</h3>
          <p style={{ fontSize: '14px' }}>{policy.source.addresses.join(', ') || 'any'}</p>
          {policy.source.zones.length > 0 && (
            <p style={{ fontSize: '12px', color: '#6b7280' }}>Zones: {policy.source.zones.join(', ')}</p>
          )}
        </div>
        <div style={{ background: 'white', padding: '16px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
          <h3 style={{ fontSize: '13px', color: '#6b7280', textTransform: 'uppercase', marginBottom: '8px' }}>Destination</h3>
          <p style={{ fontSize: '14px' }}>{policy.destination.addresses.join(', ') || 'any'}</p>
          {policy.destination.zones.length > 0 && (
            <p style={{ fontSize: '12px', color: '#6b7280' }}>Zones: {policy.destination.zones.join(', ')}</p>
          )}
        </div>
        <div style={{ background: 'white', padding: '16px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
          <h3 style={{ fontSize: '13px', color: '#6b7280', textTransform: 'uppercase', marginBottom: '8px' }}>Services</h3>
          {policy.services.map((svc, i) => (
            <p key={i} style={{ fontSize: '14px' }}>
              {svc.protocol}{svc.ports.length > 0 ? `/${svc.ports.join(', ')}` : '/any'}
            </p>
          ))}
        </div>
        <div style={{ background: 'white', padding: '16px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
          <h3 style={{ fontSize: '13px', color: '#6b7280', textTransform: 'uppercase', marginBottom: '8px' }}>Action & Logging</h3>
          <p style={{
            fontSize: '14px', fontWeight: 600,
            color: policy.action === 'allow' ? '#16a34a' : '#dc2626',
          }}>
            {policy.action}
          </p>
          <p style={{ fontSize: '12px', color: '#6b7280' }}>
            Log End: {policy.logging.log_end ? 'Yes' : 'No'} | Log Start: {policy.logging.log_start ? 'Yes' : 'No'}
          </p>
        </div>
      </div>

      {policy.description && (
        <div style={{ background: 'white', padding: '16px', borderRadius: '8px', border: '1px solid #e5e7eb', marginBottom: '24px' }}>
          <h3 style={{ fontSize: '13px', color: '#6b7280', textTransform: 'uppercase', marginBottom: '8px' }}>Description</h3>
          <p style={{ fontSize: '14px' }}>{policy.description}</p>
        </div>
      )}

      {findings.length > 0 && (
        <div>
          <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '12px' }}>Findings ({findings.length})</h3>
          {findings.map(f => (
            <div key={f.id} style={{
              padding: '12px',
              background: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '6px',
              marginBottom: '8px',
              borderLeft: `4px solid ${f.severity === 'critical' ? '#dc2626' : f.severity === 'high' ? '#ea580c' : '#ca8a04'}`,
            }}>
              <FindingBadge severity={f.severity} />
              <p style={{ fontSize: '14px', fontWeight: 500, marginTop: '4px' }}>{f.title}</p>
              <p style={{ fontSize: '13px', color: '#6b7280' }}>{f.description}</p>
              {f.references.length > 0 && (
                <p style={{ fontSize: '11px', color: '#6b7280', marginTop: '4px' }}>
                  References: {f.references.join('; ')}
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      <details style={{ marginTop: '24px' }}>
        <summary style={{ fontSize: '13px', color: '#6b7280', cursor: 'pointer' }}>
          View vendor raw data
        </summary>
        <pre style={{
          fontSize: '11px',
          background: '#f3f4f6',
          padding: '16px',
          borderRadius: '6px',
          overflow: 'auto',
          maxHeight: '300px',
          marginTop: '8px',
        }}>
          {JSON.stringify(policy.vendor_raw, null, 2)}
        </pre>
      </details>
    </div>
  )
}
