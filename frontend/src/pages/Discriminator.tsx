import PageHeader from '../components/PageHeader'
import { Card, NeonDivider, Reveal, SectionHead } from '../components/ui'
import { C } from '../lib/theme'
import './pages.css'

const PLANNED = [
  { title: 'Catch rate vs false positives', line: 'Threshold calibrated to a 0.5% benign FPR.' },
  { title: 'Leave-one-strategy-out', line: 'Train without one attack family, test on it.' },
  { title: 'Leave-one-category-out', line: 'Generalisation to unseen attack categories.' },
  { title: 'Arms-race rounds', line: 'Attacker adapts, forest retrains, repeat.' },
]

const DESIGN = [
  ['Model', 'Random forest · 200 trees · Gini'],
  ['Positives', 'Unconstrained + realizable adversarial rows'],
  ['Negatives', 'Clean benign and clean attack rows'],
  ['Splits', 'Grouped by source flow, so no clean twin leaks into training'],
  ['Output', 'Quarantine before the EIDS'],
]

export default function Discriminator() {
  return (
    <div className="page">
      <PageHeader eyebrow="Gate 2 · M5" title="Discriminator" icon="/icons/discriminator.svg" color="#a3e635" dim
        badge={<span className="badge" style={{ color: 'var(--warn)', borderColor: 'rgba(250,204,21,.4)' }}>in progress</span>}
        lead="A random forest that tells adversarial rows from clean ones. Results will appear here once M5 lands." />

      <NeonDivider color="#a3e635" />

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Design" title="What it will do" />
          <div className="grid grid-2">
            <Reveal>
              <Card>
                <div className="rule-list">
                  {DESIGN.map(([k, v]) => (
                    <div key={k} className="rule-row" style={{ background: 'transparent' }}>
                      <span className="muted" style={{ fontSize: 13 }}>{k}</span>
                      <span style={{ fontSize: 14 }}>{v}</span>
                    </div>
                  ))}
                </div>
              </Card>
            </Reveal>
            <Reveal delay={80}>
              <Card style={{ display: 'grid', placeItems: 'center', minHeight: 260 }}>
                <img src="/icons/discriminator.svg" alt="" width={200} height={200} style={{ opacity: 0.85, filter: `drop-shadow(0 0 30px ${C.ok}33)` }} />
              </Card>
            </Reveal>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Planned results" title="Coming in M5" />
          <div className="grid grid-2">
            {PLANNED.map((p, i) => (
              <Reveal key={p.title} delay={i * 70}>
                <Card className="chart-card">
                  <div className="chart-head"><div><h3>{p.title}</h3><p className="chart-cap">{p.line}</p></div><span className="badge">pending</span></div>
                  <div className="pending" style={{ height: 220 }}>
                    <div className="skeleton" />
                    <span>Awaiting M5 results</span>
                  </div>
                </Card>
              </Reveal>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}
