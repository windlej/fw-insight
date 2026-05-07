import { useState } from 'react'
import { useSessions } from '../api/client'

export default function Report() {
  const { data } = useSessions()
  const sessions = data?.sessions || []
  const [selectedSession, setSelectedSession] = useState('')
  const [loading, setLoading] = useState(false)

  const handleExport = async (format: 'json' | 'pdf') => {
    if (!selectedSession) return
    setLoading(true)
    try {
      const res = await fetch(`/api/v1/sessions/${selectedSession}/export?format=${format}`)
      if (!res.ok) throw new Error('Export failed')

      if (format === 'pdf') {
        const blob = await res.blob()
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `fw-insight-${selectedSession.slice(0, 8)}.pdf`
        a.click()
        URL.revokeObjectURL(url)
      } else {
        const data = await res.json()
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `fw-insight-${selectedSession.slice(0, 8)}.json`
        a.click()
        URL.revokeObjectURL(url)
      }
    } catch (err) {
      console.error('Export failed:', err)
      alert(`Export failed: ${err instanceof Error ? err.message : 'Unknown error'}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '24px' }}>Generate Report</h2>

      <div style={{ background: 'white', padding: '24px', borderRadius: '8px', border: '1px solid #e5e7eb', maxWidth: '600px' }}>
        <label style={{ display: 'block', fontSize: '14px', fontWeight: 500, marginBottom: '8px' }}>
          Select Session
        </label>
        <select
          value={selectedSession}
          onChange={e => setSelectedSession(e.target.value)}
          style={{
            padding: '8px 12px',
            border: '1px solid #d1d5db',
            borderRadius: '6px',
            fontSize: '14px',
            width: '100%',
            marginBottom: '20px',
          }}
        >
          <option value="">Select a session...</option>
          {sessions.map(s => (
            <option key={s.id} value={s.id}>
              {s.hostname || s.vendor} — {s.source_filename || s.id.slice(0, 8)}
            </option>
          ))}
        </select>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            onClick={() => handleExport('pdf')}
            disabled={loading || !selectedSession}
            style={{
              padding: '10px 24px',
              background: (!selectedSession || loading) ? '#9ca3af' : '#3b82f6',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: (!selectedSession || loading) ? 'not-allowed' : 'pointer',
              fontSize: '14px',
            }}
          >
            {loading ? 'Generating...' : 'Download PDF Report'}
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={loading || !selectedSession}
            style={{
              padding: '10px 24px',
              background: (!selectedSession || loading) ? '#9ca3af' : '#6b7280',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: (!selectedSession || loading) ? 'not-allowed' : 'pointer',
              fontSize: '14px',
            }}
          >
            Export JSON
          </button>
        </div>

        <div style={{ marginTop: '16px', fontSize: '12px', color: '#6b7280' }}>
          PDF report includes executive summary, finding details, and full policy table.
        </div>
      </div>
    </div>
  )
}
