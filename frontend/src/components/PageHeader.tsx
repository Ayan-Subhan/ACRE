import { lazy, Suspense, type ReactNode } from 'react'
import { Reveal } from './ui'
import './PageHeader.css'

const MiniHero = lazy(() => import('../three/MiniHero'))

export default function PageHeader({ eyebrow, title, lead, icon, color, dim, children, badge }: {
  eyebrow: string; title: string; lead: string; icon: string; color: string; dim?: boolean; children?: ReactNode; badge?: ReactNode
}) {
  return (
    <header className="ph">
      <div className="ph-glow" style={{ background: `radial-gradient(600px 300px at 75% 40%, ${color}22, transparent 70%)` }} />
      <div className="container ph-inner">
        <div className="ph-text">
          <Reveal><span className="eyebrow" style={{ color }}>{eyebrow}</span></Reveal>
          <Reveal delay={60}><h1 className="ph-title">{title} {badge}</h1></Reveal>
          <Reveal delay={120}><p className="lead">{lead}</p></Reveal>
        </div>
        <div className="ph-hero" aria-hidden="true">
          <Suspense fallback={<img src={icon} alt="" className="ph-fallback" />}>
            <MiniHero icon={icon} color={color} dim={dim} />
          </Suspense>
        </div>
      </div>
      {children && <div className="container ph-stats">{children}</div>}
    </header>
  )
}
