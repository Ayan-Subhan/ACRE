import { Link } from 'react-router-dom'
import { LogoMark, NAV } from './NavBar'

export default function Footer() {
  return (
    <footer style={{ borderTop: '1px solid var(--border)', marginTop: 'var(--space-6)', padding: '40px 0 56px' }}>
      <div className="container" style={{ display: 'flex', flexWrap: 'wrap', gap: 24, justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <LogoMark size={24} />
          <span className="muted" style={{ fontSize: 13 }}>ACRE · CICIoT2023 · milestones M1–M4</span>
        </div>
        <nav aria-label="Footer" style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
          {NAV.map((n) => (
            <Link key={n.to} to={n.to} className="muted" style={{ fontSize: 13, padding: '10px 8px' }}>{n.label}</Link>
          ))}
        </nav>
      </div>
    </footer>
  )
}
