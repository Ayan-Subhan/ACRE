import { useEffect, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { AnimatePresence, motion } from 'framer-motion'
import './NavBar.css'

export const NAV = [
  { to: '/', label: 'Architecture' },
  { to: '/validator', label: 'Validator' },
  { to: '/discriminator', label: 'Discriminator' },
  { to: '/ids', label: 'IDS' },
  { to: '/adversary', label: 'Adversary' },
  { to: '/base-paper', label: 'Base paper' },
  { to: '/pipeline', label: 'Pipeline' },
]

export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <linearGradient id="logo-g" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#22d3ee" />
          <stop offset="1" stopColor="#ff6a2b" />
        </linearGradient>
      </defs>
      <path d="M16 2.5 27 6.6v8.2c0 7.2-4.6 12.3-11 14.7C9.6 27.1 5 22 5 14.8V6.6L16 2.5Z" fill="none" stroke="url(#logo-g)" strokeWidth="2" />
      <path d="M10 16h3l2-4 3 8 2-4h2" fill="none" stroke="#e6edf3" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export default function NavBar() {
  const [open, setOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const { pathname } = useLocation()

  useEffect(() => setOpen(false), [pathname])
  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 24)
    on()
    window.addEventListener('scroll', on, { passive: true })
    return () => window.removeEventListener('scroll', on)
  }, [])

  return (
    <header className={`nav ${scrolled ? 'nav-scrolled' : ''}`}>
      <div className="nav-inner">
        <NavLink to="/" className="nav-brand" aria-label="ACRE home">
          <LogoMark />
          <span className="nav-brand-text">ACRE</span>
          <span className="badge nav-phase">M1–M4</span>
        </NavLink>
        <nav aria-label="Primary" className="nav-links">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
              {({ isActive }) => (
                <>
                  {n.label}
                  {isActive && <motion.span layoutId="nav-underline" className="nav-underline" />}
                </>
              )}
            </NavLink>
          ))}
        </nav>
        <button className="nav-burger" aria-label={open ? 'Close menu' : 'Open menu'} aria-expanded={open} onClick={() => setOpen((o) => !o)}>
          <span /><span />
        </button>
      </div>
      <AnimatePresence>
        {open && (
          <motion.nav
            aria-label="Mobile"
            className="nav-sheet"
            initial={{ opacity: 0, y: -12 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8, transition: { duration: 0.15 } }}
          >
            {NAV.map((n, i) => (
              <motion.div key={n.to} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0, transition: { delay: 0.03 * i } }}>
                <NavLink to={n.to} end className={({ isActive }) => `nav-sheet-link ${isActive ? 'active' : ''}`}>{n.label}</NavLink>
              </motion.div>
            ))}
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  )
}
