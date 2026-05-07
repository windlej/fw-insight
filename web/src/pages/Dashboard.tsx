import { useParams, Link } from 'react-router-dom'
import { useSession, useAnalysis } from '../api/client'
import RiskScore from '../components/RiskScore'
import FindingBadge from '../components/FindingBadge'

export default function Dashboard() {
  const { id } = useParams<{ id: string }>()
  if (!id) return <p>No session ID provided.</p>

  const { data: session, isLoading: sessionLoading } = useSession(id)
  const { data: analysis, isLoading: analysisLoading } = useAnalysis(id)

  if (sessionLoading || analysisLoading) return <p>Loading...</p>
  if (!session) return <p>Session not found.</p>

  const findings = analysis?.findings || []

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 600 }}>
            {session.hostname || session.vendor}
          </h2>
          <p style={{ fontSize: '13px', color: '#6b7280' }}>
            {session.vendor}{session.vendor_version ? ` ${session.vendor_version}` : ''} | {session.source_filename}
          </p>
        </div>
        <div style={{ display: 'flex', gap: '12px' }}>
          <Link to={`/policies/${id}`} style={{
            padding: '8px 16px', background: '#f3f4f6', borderRadius: '6px',
            textDecoration: 'none', color: '#374151', fontSize: '13px',
          }}>
            Policies
          </Link>
          <Link to={`/nat/${id}`} style={{
            padding: '8px 16px', background: '#f3f4f6', borderRadius: '6px',
            textDecoration: 'none', color: '#374151', fontSize: '13px',
          }}>
            NAT Rules
          </Link>
          <Link to={`/findings/${id}`} style={{
            padding: '8px 16px', background: '#f3f4f6', borderRadius: '6px',
            textDecoration: 'none', color: '#374151', fontSize: '13px',
          }}>
            Findings
          </Link>
          <Link to={`/objects/${id}`} style={{
            padding: '8px 16px', background: '#f3f4f6', borderRadius: '6px',
            textDecoration: 'none', color: '#374151', fontSize: '13px',
          }}>
            Objects
          </Link>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr', gap: '32px' }}>
        <RiskScore score={analysis?.health_score ?? session.health_score ?? 100} />

        <div>
          <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>Rule Counts</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '24px' }}>
            {[
              { label: 'Security Policies', value: session.security_policies.length },
              { label: 'NAT Rules', value: session.nat_rules.length },
              { label: 'Address Objects', value: session.address_objects.length },
              { label: 'Service Objects', value: session.service_objects.length },
            ].map(item => (
              <div key={item.label} style={{
                background: 'white',
                padding: '16px',
                borderRadius: '8px',
                border: '1px solid #e5e7eb',
                textAlign: 'center',
              }}>
                <div style={{ fontSize: '24px', fontWeight: 700 }}>{item.value}</div>
                <div style={{ fontSize: '12px', color: '#6b7280' }}>{item.label}</div>
              </div>
            ))}
          </div>

          <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>Findings by Severity</h3>
          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '24px' }}>
            {Object.entries(analysis?.finding_counts || session.finding_counts || {}).map(([sev, count]) => (
              <FindingBadge key={sev} severity={sev} count={count as number} />
            ))}
          </div>

          {findings.length > 0 && (
            <div>
              <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '12px' }}>Top Findings</h3>
              {findings.slice(0, 5).map(f => (
                <Link
                  key={f.id}
                  to={`/rule/${id}/${f.entity_id}`}
                  style={{
                    display: 'block',
                    padding: '12px',
                    background: 'white',
                    border: '1px solid #e5e7eb',
                    borderRadius: '6px',
                    marginBottom: '8px',
                    textDecoration: 'none',
                    borderLeft: `4px solid ${f.severity === 'critical' ? '#dc2626' : f.severity === 'high' ? '#ea580c' : f.severity === 'medium' ? '#ca8a04' : '#2563eb'}`,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '13px', fontWeight: 500, color: '#1f2937' }}>{f.title}</span>
                    <FindingBadge severity={f.severity} />
                  </div>
                  <p style={{ fontSize: '12px', color: '#6b7280', marginTop: '4px' }}>
                    Rule: {f.entity_id}
                  </p>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
