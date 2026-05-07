import { useParams, Link } from 'react-router-dom'
import { useState } from 'react'
import { useAnalysis, useSession } from '../api/client'
import FindingBadge from '../components/FindingBadge'

export default function Findings() {
  const { id } = useParams<{ id: string }>()
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  const { data: analysis, isLoading } = useAnalysis(id || '')
  const { data: session } = useSession(id || '')
  const findings = analysis?.findings || []

  const filtered = severityFilter === 'all' ? findings : findings.filter(f => f.severity === severityFilter)

  if (isLoading) return <p>Loading findings...</p>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 600 }}>Findings</h2>
          <p style={{ fontSize: '13px', color: '#6b7280' }}>
            {session?.hostname || ''} | {findings.length} total findings
          </p>
        </div>
        <Link to={`/dashboard/${id}`} style={{ color: '#3b82f6', textDecoration: 'none', fontSize: '13px' }}>
          &larr; Back to Dashboard
        </Link>
      </div>

      <div style={{ marginBottom: '16px', display: 'flex', gap: '8px' }}>
        {['all', 'critical', 'high', 'medium', 'low', 'info'].map(sev => (
          <button
            key={sev}
            onClick={() => setSeverityFilter(sev)}
            style={{
              padding: '6px 12px',
              border: severityFilter === sev ? '2px solid #3b82f6' : '1px solid #d1d5db',
              borderRadius: '6px',
              background: severityFilter === sev ? '#eff6ff' : 'white',
              fontSize: '12px',
              fontWeight: severityFilter === sev ? 600 : 400,
              cursor: 'pointer',
              textTransform: 'capitalize',
            }}
          >
            {sev}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <p style={{ color: '#6b7280' }}>No findings match the current filter.</p>
      ) : (
        <div>
          {filtered.map(f => (
            <div key={f.id} style={{
              padding: '16px',
              background: 'white',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
              marginBottom: '12px',
              borderLeft: `4px solid ${f.severity === 'critical' ? '#dc2626' : f.severity === 'high' ? '#ea580c' : f.severity === 'medium' ? '#ca8a04' : '#2563eb'}`,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div>
                  <span style={{ fontSize: '11px', color: '#6b7280' }}>{f.check_id}</span>
                  <h3 style={{ fontSize: '14px', fontWeight: 600, display: 'inline', marginLeft: '8px' }}>
                    {f.title}
                  </h3>
                </div>
                <FindingBadge severity={f.severity} />
              </div>
              <p style={{ fontSize: '13px', marginBottom: '8px' }}>{f.description}</p>
              <div style={{ fontSize: '12px', color: '#6b7280' }}>
                Affected: <strong>{f.entity_id}</strong>
                {f.related_entity_ids.length > 0 && (
                  <span> | Related: {f.related_entity_ids.join(', ')}</span>
                )}
              </div>
              {f.references.length > 0 && (
                <div style={{ fontSize: '11px', color: '#6b7280', marginTop: '6px' }}>
                  References: {f.references.join('; ')}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
