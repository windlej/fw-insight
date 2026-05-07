import type { SecurityPolicy, Finding } from '../types'
import FindingBadge from './FindingBadge'

export default function RuleDetailPanel({
  policy,
  findings,
  onClose,
}: {
  policy: SecurityPolicy | null
  findings: Finding[]
  onClose: () => void
}) {
  if (!policy) return null

  const ruleFindings = findings.filter(f => f.entity_id === policy.id)

  return (
    <div style={{
      position: 'fixed',
      right: 0,
      top: 0,
      bottom: 0,
      width: '480px',
      background: 'white',
      boxShadow: '-4px 0 16px rgba(0,0,0,0.1)',
      padding: '24px',
      overflow: 'auto',
      zIndex: 100,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 600 }}>Rule Detail</h2>
        <button onClick={onClose} style={{
          background: 'none', border: 'none', fontSize: '20px', cursor: 'pointer', color: '#6b7280',
        }}>
          &times;
        </button>
      </div>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ fontSize: '11px', color: '#6b7280', textTransform: 'uppercase' }}>Name</label>
        <p style={{ fontSize: '14px', fontWeight: 500 }}>{policy.name || policy.id}</p>
      </div>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ fontSize: '11px', color: '#6b7280', textTransform: 'uppercase' }}>Position</label>
        <p style={{ fontSize: '14px' }}>{policy.position}</p>
      </div>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ fontSize: '11px', color: '#6b7280', textTransform: 'uppercase' }}>Action</label>
        <p style={{
          fontSize: '14px', fontWeight: 600,
          color: policy.action === 'allow' ? '#16a34a' : '#dc2626',
        }}>
          {policy.action}
        </p>
      </div>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ fontSize: '11px', color: '#6b7280', textTransform: 'uppercase' }}>Source</label>
        <p style={{ fontSize: '13px' }}>{policy.source.addresses.join(', ')}</p>
        {policy.source.zones.length > 0 && (
          <p style={{ fontSize: '12px', color: '#6b7280' }}>Zones: {policy.source.zones.join(', ')}</p>
        )}
      </div>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ fontSize: '11px', color: '#6b7280', textTransform: 'uppercase' }}>Destination</label>
        <p style={{ fontSize: '13px' }}>{policy.destination.addresses.join(', ')}</p>
        {policy.destination.zones.length > 0 && (
          <p style={{ fontSize: '12px', color: '#6b7280' }}>Zones: {policy.destination.zones.join(', ')}</p>
        )}
      </div>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ fontSize: '11px', color: '#6b7280', textTransform: 'uppercase' }}>Services</label>
        {policy.services.map((svc, i) => (
          <p key={i} style={{ fontSize: '13px' }}>
            {svc.protocol}{svc.ports.length > 0 ? `/${svc.ports.join(', ')}` : ''}
          </p>
        ))}
      </div>

      <div style={{ marginBottom: '16px' }}>
        <label style={{ fontSize: '11px', color: '#6b7280', textTransform: 'uppercase' }}>Logging</label>
        <p style={{ fontSize: '13px' }}>
          End: {policy.logging.log_end ? 'Yes' : 'No'} | Start: {policy.logging.log_start ? 'Yes' : 'No'}
        </p>
      </div>

      {policy.description && (
        <div style={{ marginBottom: '16px' }}>
          <label style={{ fontSize: '11px', color: '#6b7280', textTransform: 'uppercase' }}>Description</label>
          <p style={{ fontSize: '13px' }}>{policy.description}</p>
        </div>
      )}

      {ruleFindings.length > 0 && (
        <div>
          <h3 style={{ fontSize: '13px', fontWeight: 600, marginBottom: '8px' }}>
            Findings ({ruleFindings.length})
          </h3>
          {ruleFindings.map(f => (
            <div key={f.id} style={{
              padding: '10px',
              background: '#f9fafb',
              borderRadius: '6px',
              marginBottom: '8px',
              borderLeft: `3px solid ${f.severity === 'critical' ? '#dc2626' : f.severity === 'high' ? '#ea580c' : '#ca8a04'}`,
            }}>
              <FindingBadge severity={f.severity} />
              <p style={{ fontSize: '13px', marginTop: '4px' }}>{f.title}</p>
              <p style={{ fontSize: '12px', color: '#6b7280' }}>{f.description}</p>
            </div>
          ))}
        </div>
      )}

      <details style={{ marginTop: '16px' }}>
        <summary style={{ fontSize: '12px', color: '#6b7280', cursor: 'pointer' }}>
          View vendor raw data
        </summary>
        <pre style={{
          fontSize: '11px',
          background: '#f3f4f6',
          padding: '12px',
          borderRadius: '6px',
          overflow: 'auto',
          maxHeight: '200px',
          marginTop: '8px',
        }}>
          {JSON.stringify(policy.vendor_raw, null, 2)}
        </pre>
      </details>
    </div>
  )
}
