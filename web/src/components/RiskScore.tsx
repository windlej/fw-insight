export default function RiskScore({ score }: { score: number }) {
  const color = score >= 70 ? '#16a34a' : score >= 40 ? '#ca8a04' : '#dc2626'
  const radius = 60
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  return (
    <div style={{ textAlign: 'center' }}>
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle
          cx="80" cy="80" r={radius}
          fill="none"
          stroke="#e5e7eb"
          strokeWidth="12"
        />
        <circle
          cx="80" cy="80" r={radius}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 80 80)"
          style={{ transition: 'stroke-dashoffset 0.5s ease' }}
        />
        <text
          x="80" y="75" textAnchor="middle"
          fontSize="32" fontWeight="bold"
          fill={color}
        >
          {score}
        </text>
        <text
          x="80" y="95" textAnchor="middle"
          fontSize="12" fill="#6b7280"
        >
          / 100
        </text>
      </svg>
      <div style={{ fontSize: '12px', color: '#6b7280', marginTop: '4px' }}>
        Policy Health Score
      </div>
    </div>
  )
}
