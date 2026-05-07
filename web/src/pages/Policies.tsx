import { useParams, Link } from 'react-router-dom'
import { useState } from 'react'
import { useSession, useAnalysis } from '../api/client'
import PolicyTable from '../components/PolicyTable'
import RuleDetailPanel from '../components/RuleDetailPanel'
import type { SecurityPolicy } from '../types'

export default function Policies() {
  const { id } = useParams<{ id: string }>()
  const [selectedPolicy, setSelectedPolicy] = useState<SecurityPolicy | null>(null)

  const { data: session, isLoading } = useSession(id || '')
  const { data: analysis } = useAnalysis(id || '')

  if (isLoading || !session) return <p>Loading...</p>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h2 style={{ fontSize: '20px', fontWeight: 600 }}>Security Policies</h2>
          <p style={{ fontSize: '13px', color: '#6b7280' }}>
            {session.hostname || session.vendor} | {session.security_policies.length} rules
          </p>
        </div>
        <Link to={`/dashboard/${id}`} style={{ color: '#3b82f6', textDecoration: 'none', fontSize: '13px' }}>
          &larr; Back to Dashboard
        </Link>
      </div>

      <PolicyTable
        policies={session.security_policies}
        onRowClick={setSelectedPolicy}
      />

      {selectedPolicy && (
        <RuleDetailPanel
          policy={selectedPolicy}
          findings={analysis?.findings || []}
          onClose={() => setSelectedPolicy(null)}
        />
      )}
    </div>
  )
}
