import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import ArchitectureCanvas, { type SceneHandles } from '../three/ArchitectureScene'
import type { FlowRates, Kind, Outcome } from '../three/FlowParticles'
import { KIND_COLOR } from '../three/FlowParticles'
import { NODES, type NodeDef } from '../three/layout'
import { useData, type AdversaryData, type IdsData, type Overview, type ValidatorData } from '../lib/data'
import { useIsMobile, useReducedMotion, fmt } from '../lib/motion'
import { Card, NeonDivider, Reveal, SectionHead, Segmented, StatTile } from '../components/ui'
import './Home.css'

const emptyTally = (): Record<Kind, Record<Outcome, number>> => ({
  benign: { blocked: 0, alert: 0, lan: 0 }, attack: { blocked: 0, alert: 0, lan: 0 }, adversarial: { blocked: 0, alert: 0, lan: 0 },
})

const PAGES = [
  { to: '/validator', icon: '/icons/validator.svg', name: 'Validator', line: 'Four rule families mined from benign traffic.' },
  { to: '/discriminator', icon: '/icons/discriminator.svg', name: 'Discriminator', line: 'Random-forest gate. Coming in M5.' },
  { to: '/ids', icon: '/icons/ids.svg', name: 'IDS', line: 'MLP, CNN and LSTM, trained and stress-tested.' },
  { to: '/adversary', icon: '/icons/adversary.svg', name: 'Adversary', line: 'Six attackers, three knowledge tiers.' },
  { to: '/base-paper', icon: '/icons/paper.svg', name: 'Base paper', line: 'Our numbers next to the paper’s numbers.' },
  { to: '/pipeline', icon: '/icons/pipeline.svg', name: 'Pipeline', line: '46.7M flows down to a clean 2.5M.' },
]

export default function Home() {
  const overview = useData<Overview>('overview')
  const adv = useData<AdversaryData>('adversary')
  const val = useData<ValidatorData>('validator')
  const ids = useData<IdsData>('ids')
  const mobile = useIsMobile()
  const reduced = useReducedMotion()
  const navigate = useNavigate()
  const [spec, setSpec] = useState<'A' | 'B' | 'C'>('C')
  const [phase, setPhase] = useState<'hero' | 'arch' | 'content'>('hero')
  const [hovered, setHovered] = useState<NodeDef | null>(null)
  const [tally, setTally] = useState(emptyTally)
  const stageRef = useRef<HTMLDivElement>(null)

  const handles = useRef<SceneHandles>({
    progress: { current: reduced ? 1 : 0 },
    pointer: { current: [0, 0] },
    rates: {
      current: {
        benign: { blocked: 0.0101, alert: 0.0327 },
        attack: { blocked: 0.399, alert: 0.93 },
        adversarial: { blocked: 0.38, alert: 0.35 },
        mix: { benign: 0.5, attack: 0.22, adversarial: 0.28 },
      } as FlowRates,
    },
    tally: { current: emptyTally() },
    labelsVisible: { current: 1 },
  }).current

  // measured rates -> particle fates
  useEffect(() => {
    if (!overview || !adv || !ids) return
    const f = adv.flows.find((x) => x.attack === 'adaptive_feat' && x.spec === spec)!
    const passV = f.passes_validator / 100
    const r = handles.rates.current
    r.benign = { blocked: overview.flow_rates.benign_fpr_validator / 100, alert: ids.ensemble.fpr / 100 }
    r.attack = { blocked: overview.flow_rates.attack_reject_validator / 100, alert: overview.flow_rates.eids_recall / 100 }
    r.adversarial = { blocked: 1 - passV, alert: Math.max(0, (passV - f.pass_and_evade / 100) / passV) }
    handles.tally.current = emptyTally()
    setTally(emptyTally())
  }, [overview, adv, ids, spec, handles])

  // scroll -> morph progress and phase
  useEffect(() => {
    const on = () => {
      const vh = window.innerHeight
      const y = window.scrollY
      // reduced motion: no morph, the architecture is simply there
      handles.progress.current = reduced ? 1 : Math.min(1, Math.max(0, y / (vh * 1.1)))
      handles.labelsVisible.current = Math.max(0, 1 - Math.max(0, y - vh * 1.9) / (vh * 0.4))
      setPhase(y < vh * 0.9 ? 'hero' : y < vh * 2.2 ? 'arch' : 'content')
    }
    on()
    window.addEventListener('scroll', on, { passive: true })
    return () => window.removeEventListener('scroll', on)
  }, [reduced, handles])

  useEffect(() => {
    const on = (e: PointerEvent) => {
      handles.pointer.current = [(e.clientX / window.innerWidth) * 2 - 1, (e.clientY / window.innerHeight) * 2 - 1]
    }
    window.addEventListener('pointermove', on)
    return () => window.removeEventListener('pointermove', on)
  }, [handles])

  // live counters for the HUD
  useEffect(() => {
    const id = setInterval(() => setTally(JSON.parse(JSON.stringify(handles.tally.current))), 600)
    return () => clearInterval(id)
  }, [handles])

  useEffect(() => () => { document.body.style.cursor = '' }, [])

  const leaked = tally.adversarial.lan
  const advTotal = tally.adversarial.lan + tally.adversarial.alert + tally.adversarial.blocked
  const specFlow = adv?.flows.find((x) => x.attack === 'adaptive_feat' && x.spec === spec)

  return (
    <div className="home">
      <div ref={stageRef} className={`home-stage ${phase === 'content' ? 'dim' : ''}`} aria-hidden="true">
        <ArchitectureCanvas handles={handles} mobile={mobile} reduced={reduced}
          onSelect={(d) => navigate(d.route)} onHover={setHovered} />
      </div>

      {/* 1. hero */}
      <section className={`home-hero ${phase !== 'hero' ? 'gone' : ''}`}>
        <div className="container home-hero-inner">
          <span className="eyebrow">CICIoT2023 · adversarial IDS · M1–M4</span>
          <h1>
            <span className="grad-text">Adversarial traffic,</span><br />caught in layers.
          </h1>
          <p className="lead">A validator, a discriminator and an ensemble IDS stand between IoT devices and the LAN. Here is how far a realistic attacker still gets.</p>
          <div className="home-hero-cta">
            <a className="btn btn-primary" href="#arch" onClick={(e) => { e.preventDefault(); window.scrollTo({ top: window.innerHeight * 1.15, behavior: 'smooth' }) }}>Explore the architecture</a>
            <Link className="btn" to="/base-paper">Compare to base paper</Link>
          </div>
        </div>
        <div className="scroll-cue" aria-hidden="true"><span /></div>
      </section>

      {/* 2. architecture (canvas shows through) */}
      <section id="arch" className="home-arch" aria-label="Network architecture">
        <div className={`arch-hud ${phase === 'arch' ? 'on' : ''}`}>
          <div className="arch-hud-top container">
            <div>
              <span className="eyebrow">Network architecture</span>
              <h2 className="arch-title">Three gates, five zones</h2>
              <p className="arch-sub muted">Drag to rotate. Click any component.</p>
            </div>
            <div className="arch-legend">
              {(['benign', 'attack', 'adversarial'] as Kind[]).map((k) => (
                <span key={k}><span className="dot" style={{ background: KIND_COLOR[k], boxShadow: `0 0 10px ${KIND_COLOR[k]}` }} />{k === 'attack' ? 'clean attack' : k}</span>
              ))}
            </div>
          </div>
          <div className="arch-hud-bottom container">
            <div className="arch-panel">
              <div className="arch-panel-row">
                <span className="muted">Attacker freedom</span>
                <Segmented label="Realism spec" value={spec} onChange={setSpec}
                  options={[{ value: 'A', label: 'Spec A' }, { value: 'B', label: 'Spec B' }, { value: 'C', label: 'Spec C' }]} />
              </div>
              <div className="arch-panel-stats">
                <div><b className="mono" style={{ color: KIND_COLOR.adversarial }}>{specFlow ? fmt(specFlow.pass_and_evade, 1) : '–'}%</b><span>adversarial rows reach the LAN (measured)</span></div>
                <div><b className="mono">{leaked}<span className="arch-of"> / {advTotal}</span></b><span>reached the LAN in this live run</span></div>
              </div>
            </div>
            <div className={`arch-hover ${hovered ? 'on' : ''}`} aria-live="polite">
              {hovered && (<><img src={hovered.icon} alt="" width={44} height={44} /><div><b>{hovered.label}</b><span>{hovered.hint}</span></div></>)}
            </div>
          </div>
        </div>
        <nav className="sr-only sr-only-focusable arch-a11y" aria-label="Architecture components">
          {NODES.map((n) => <Link key={n.id} to={n.route} className="chip">{n.label}: {n.hint}</Link>)}
        </nav>
      </section>

      {/* 3. content */}
      <div className="home-content">
        <NeonDivider />
        <section className="section">
          <div className="container">
            <SectionHead eyebrow="Where M4 stands" title="The numbers that matter" />
            <div className="grid grid-4">
              <StatTile label="Best balanced accuracy" value={overview?.headline.best_bal_acc ?? 0} sub="MLP · clean test" />
              <StatTile label="Validator false positives" value={overview?.headline.validator_fpr ?? 0} decimals={2} sub="benign test rows" accent="var(--ok)" delay={80} />
              <StatTile label="Unconstrained attacks that get through" value={val ? Math.max(...val.art_sets.map((x) => x.pass_and_evade)) : 0} decimals={2} sub="ART sets, worst case" accent="var(--defense)" delay={160} />
              <StatTile label="Realizable attacks that get through" value={overview?.headline.best_pass_and_evade ?? 0} sub="adaptive, white-box, spec C" accent="var(--attack)" delay={240} />
            </div>
          </div>
        </section>

        <section className="section">
          <div className="container">
            <SectionHead eyebrow="Milestones" title="Progress" />
            <Reveal>
              <div className="milestones">
                {overview?.milestones.map((m) => (
                  <div key={m.id} className={`ms ms-${m.status}`}>
                    <span className="ms-dot" />
                    <span className="mono ms-id">{m.id}</span>
                    <span className="ms-name">{m.name}</span>
                    <span className="badge">{m.status}</span>
                  </div>
                ))}
              </div>
            </Reveal>
          </div>
        </section>

        <section className="section">
          <div className="container">
            <SectionHead eyebrow="Explore" title="Component pages" />
            <div className="grid grid-3">
              {PAGES.map((p, i) => (
                <Reveal key={p.to} delay={i * 60}>
                  <Link to={p.to} className="page-card-link">
                    <Card className="page-card">
                      <img src={p.icon} alt="" width={84} height={84} className="page-card-icon" />
                      <div>
                        <h3>{p.name}</h3>
                        <p className="muted" style={{ fontSize: 14, marginTop: 4 }}>{p.line}</p>
                      </div>
                      <span className="page-card-arrow" aria-hidden="true">→</span>
                    </Card>
                  </Link>
                </Reveal>
              ))}
            </div>
          </div>
        </section>
        <footer className="container home-foot muted">ACRE · extends Verma et al., IEEE TCE 2025 · CICIoT2023</footer>
      </div>
    </div>
  )
}
