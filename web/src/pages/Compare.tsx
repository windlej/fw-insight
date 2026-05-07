import { useState } from 'react'
import { useSessions } from '../api/client'
import FindingBadge from '../components/FindingBadge'

export default function Compare() {
  const { data } = useSessions()
  const sessions = data?.sessions || []
  const [sessionA, setSessionA] = useState('')
  const [sessionB, setSessionB] = useState('')
  const [diff, setDiff] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleCompare = async () => {
    if (!sessionA || !sessionB) return
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/v1/diff', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_a_id: sessionA, session_b_id: sessionB }),
      })
      if (!res.ok) throw new Error('Diff failed')
      const result = await res.json()
      setDiff(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '24px' }}>Compare Configurations</h2>

      <div style={{ display: 'flex', gap: '16px', marginBottom: '24px' }}>
        <div style={{ flex: 1 }}>
          <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px' }}>Session A (Before)</label>
          <select
            value={sessionA}
            onChange={e => setSessionA(e.target.value)}
            style={selectStyle}
          >
            <option value="">Select session...</option>
            {sessions.map(s => (
              <option key={s.id} value={s.id}>{s.hostname || s.vendor} ({s.id.slice(0, 8)})</option>
            ))}
          </select>
        </div>
        <div style={{ flex: 1 }}>
          <label style={{ display: 'block', fontSize: '13px', fontWeight: 500, marginBottom: '6px' }}>Session B (After)</label>
          <select
            value={sessionB}
            onChange={e => setSessionB(e.target.value)}
            style={selectStyle}
          >
            <option value="">Select session...</option>
            {sessions.map(s => (
              <option key={s.id} value={s.id}>{s.hostname || s.vendor} ({s.id.slice(0, 8)})</option>
            ))}
          </select>
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end' }}>
          <button
            onClick={handleCompare}
            disabled={loading || !sessionA || !sessionB}
            style={{
              padding: '8px 24px',
              background: (!sessionA || !sessionB) ? '#9ca3af' : '#3b82f6',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: (!sessionA || !sessionB) ? 'not-allowed' : 'pointer',
            }}
          >
            {loading ? 'Comparing...' : 'Compare'}
          </button>
        </div>
      </div>

      {error && (
        <div style={{ padding: '12px', background: '#fef2f2', borderRadius: '6px', color: '#dc2626', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {diff && (
        <div>
          {!diff.vendor_match && (
            <div style={{
              padding: '12px', background: '#fef3c7', borderRadius: '6px',
              color: '#92400e', marginBottom: '16px', fontSize: '13px',
            }}>
              Warning: Sessions are from different vendors. Rule matching is approximate.
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', marginBottom: '24px' }}>
            <StatCard label="Added Rules" value={diff.added_rules?.length || 0} color="#16a34a" />
            <StatCard label="Removed Rules" value={diff.removed_rules?.length || 0} color="#dc2626" />
            <StatCard label="Modified Rules" value={diff.modified_rules?.length || 0} color="#ca8a04" />
          </div>

          {diff.added_rules?.length > 0 && (
            <div style={{ marginBottom: '24px' }}>
              <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px', color: '#16a34a' }}>
                Added Rules
              </h3>
              {diff.added_rules.map((r: any) => (
                <div key={r.id} style={{
                  padding: '10px', background: '#f0fdf4', borderRadius: '6px',
                  marginBottom: '6px', fontSize: '13px',
                }}>
                  <strong>{r.name || r.id}</strong> | {r.action} | {r.source?.addresses?.join(', ') || 'any'} &rarr; {r.destination?.addresses?.join(', ') || 'any'}
                </div>
              ))}
            </div>
          )}

          {diff.removed_rules?.length > 0 && (
            <div style={{ marginBottom: '24px' }}>
              <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px', color: '#dc2626' }}>
                Removed Rules
              </h3>
              {diff.removed_rules.map((r: any) => (
                <div key={r.id} style={{
                  padding: '10px', background: '#fef2f2', borderRadius: '6px',
                  marginBottom: '6px', fontSize: '13px',
                }}>
                  <strong>{r.name || r.id}</strong> | {r.action} | {r.source?.addresses?.join(', ') || 'any'} &rarr; {r.destination?.addresses?.join(', ') || 'any'}
                </div>
              ))}
            </div>
          )}

          {diff.modified_rules?.length > 0 && (
            <div>
              <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px', color: '#ca8a04' }}>
                Modified Rules
              </h3>
              {diff.modified_rules.map((r: any) => (
                <div key={r.rule_id} style={{
                  padding: '12px', background: '#fefce8', borderRadius: '6px',
                  marginBottom: '8px', fontSize: '13px',
                }}>
                  <strong>{r.rule_name || r.rule_id}</strong>
                  {r.changes?.map((c: any, i: number) => (
                    <div key={i} style={{ marginTop: '4px', paddingLeft: '12px', borderLeft: '2px solid #e5e7eb' }}>
                      <span style={{ color: '#6b7280' }}>{c.field}:</span>{' '}
                      <span style={{ color: '#dc2626' }}>{String(c.old_value || '-')}</span>
                      {' → '}
                      <span style={{ color: '#16a34a' }}>{String(c.new_value || '-')}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ background: 'white', padding: '20px', borderRadius: '8px', border: '1px solid #e5e7eb', textAlign: 'center' }}>
      <div style={{ fontSize: '28px', fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: '12px', color: '#6b7280' }}>{label}</div>
    </div>
  )
}

const selectStyle = {
  padding: '8px 12px',
  border: '1px solid #d1d5db',
  borderRadius: '6px',
  fontSize: '14px',
  width: '100%',
}
