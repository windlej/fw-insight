import { Link, useLocation } from 'react-router-dom'

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/upload', label: 'Upload' },
  { path: '/sessions', label: 'Sessions' },
  { path: '/compare', label: 'Compare' },
  { path: '/report', label: 'Report' },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      <nav style={{
        width: '220px',
        background: '#1f2937',
        color: '#f9fafb',
        padding: '16px 0',
        flexShrink: 0,
      }}>
        <div style={{ padding: '0 16px 20px', borderBottom: '1px solid #374151', marginBottom: '12px' }}>
          <h1 style={{ fontSize: '18px', fontWeight: 700 }}>fw-insight</h1>
          <p style={{ fontSize: '11px', color: '#9ca3af' }}>Firewall Analysis</p>
        </div>
        {navItems.map(item => (
          <Link
            key={item.path}
            to={item.path}
            style={{
              display: 'block',
              padding: '10px 16px',
              color: location.pathname === item.path ? '#f9fafb' : '#9ca3af',
              background: location.pathname === item.path ? '#374151' : 'transparent',
              textDecoration: 'none',
              fontSize: '14px',
              fontWeight: location.pathname === item.path ? 600 : 400,
            }}
          >
            {item.label}
          </Link>
        ))}
      </nav>
      <main style={{ flex: 1, padding: '24px 32px', overflow: 'auto' }}>
        {children}
      </main>
    </div>
  )
}
