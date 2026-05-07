import { SEVERITY_COLORS } from '../types'

export default function FindingBadge({ severity, count }: { severity: string; count?: number }) {
  const color = SEVERITY_COLORS[severity] || '#6b7280'

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '4px',
      padding: '2px 8px',
      borderRadius: '4px',
      background: color,
      color: 'white',
      fontSize: '11px',
      fontWeight: 600,
      textTransform: 'uppercase',
    }}>
      {severity}
      {count !== undefined && count > 0 && (
        <span style={{
          background: 'rgba(255,255,255,0.3)',
          borderRadius: '50%',
          width: '16px',
          height: '16px',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: '10px',
        }}>
          {count}
        </span>
      )}
    </span>
  )
}
