import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import ReactECharts from 'echarts-for-react'
import type { EChartsOption } from 'echarts'
import { useInView, useReducedMotion, fmt } from '../lib/motion'
import './ui.css'

/** Fade-up on first view. */
export function Reveal({ children, delay = 0, className = '', style }: { children: ReactNode; delay?: number; className?: string; style?: CSSProperties }) {
  const ref = useRef<HTMLDivElement>(null)
  const seen = useInView(ref)
  return (
    <div ref={ref} className={`reveal ${seen ? 'in' : ''} ${className}`} style={{ transitionDelay: `${delay}ms`, ...style }}>
      {children}
    </div>
  )
}

/** Card with a cursor-following glow. */
export function Card({ children, className = '', style }: { children: ReactNode; className?: string; style?: CSSProperties }) {
  const onMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect()
    e.currentTarget.style.setProperty('--mx', `${e.clientX - r.left}px`)
    e.currentTarget.style.setProperty('--my', `${e.clientY - r.top}px`)
  }
  return <div className={`card ${className}`} style={style} onPointerMove={onMove}>{children}</div>
}

/** Counts up to `value` when it scrolls into view. */
export function CountUp({ value, decimals = 1, suffix = '', prefix = '' }: { value: number; decimals?: number; suffix?: string; prefix?: string }) {
  const ref = useRef<HTMLSpanElement>(null)
  const seen = useInView(ref)
  const reduced = useReducedMotion()
  const [v, setV] = useState(reduced ? value : 0)
  useEffect(() => {
    if (!seen || reduced) { if (reduced) setV(value); return }
    let raf = 0
    const t0 = performance.now()
    const dur = 1400
    const step = (t: number) => {
      const k = Math.min(1, (t - t0) / dur)
      setV(value * (1 - Math.pow(1 - k, 4)))
      if (k < 1) raf = requestAnimationFrame(step)
    }
    raf = requestAnimationFrame(step)
    return () => cancelAnimationFrame(raf)
  }, [seen, value, reduced])
  return <span ref={ref} className="mono">{prefix}{fmt(v, decimals)}{suffix}</span>
}

export function StatTile({ label, value, decimals = 1, suffix = '%', accent = 'var(--defense)', sub, delay = 0 }: {
  label: string; value: number; decimals?: number; suffix?: string; accent?: string; sub?: string; delay?: number
}) {
  return (
    <Reveal delay={delay}>
      <Card className="stat">
        <span className="stat-bar" style={{ background: accent, boxShadow: `0 0 18px ${accent}` }} />
        <div className="stat-label">{label}</div>
        <div className="stat-value"><CountUp value={value} decimals={decimals} suffix={suffix} /></div>
        {sub && <div className="stat-sub">{sub}</div>}
      </Card>
    </Reveal>
  )
}

export interface TableSpec { columns: { key: string; label: string; num?: boolean; digits?: number }[]; rows: Record<string, unknown>[] }

/** A chart in a card: mounts the chart when it scrolls into view (so the entrance animates), with a table toggle. */
export function ChartCard({ title, caption, option, height = 320, table, badges, controls, className = '', children, delay = 0 }: {
  title: string; caption?: string; option?: EChartsOption | null; height?: number; table?: TableSpec
  badges?: ReactNode; controls?: ReactNode; className?: string; children?: ReactNode; delay?: number
}) {
  const ref = useRef<HTMLDivElement>(null)
  const seen = useInView(ref, '0px 0px -15% 0px')
  const [showTable, setShowTable] = useState(false)
  return (
    <Reveal className={className} delay={delay}>
      <Card className="chart-card">
        <div className="chart-head">
          <div>
            <h3>{title}</h3>
            {caption && <p className="chart-cap">{caption}</p>}
          </div>
          <div className="chart-tools">
            {badges}
            {table && (
              <button className="chip chart-toggle" onClick={() => setShowTable((s) => !s)} aria-pressed={showTable}>
                {showTable ? 'Chart' : 'Table'}
              </button>
            )}
          </div>
        </div>
        {controls && <div className="chart-controls">{controls}</div>}
        <div ref={ref} style={{ minHeight: height }}>
          {showTable && table ? <DataTable spec={table} /> : children ?? (
            seen && option ? <Chart option={option} height={height} /> : <div className="skeleton" style={{ height }} />
          )}
        </div>
      </Card>
    </Reveal>
  )
}

export function Chart({ option, height = 320 }: { option: EChartsOption; height?: number }) {
  const reduced = useReducedMotion()
  return (
    <ReactECharts
      option={{ animation: !reduced, animationDuration: 900, animationEasing: 'cubicOut', ...option }}
      theme="acre"
      notMerge
      style={{ height, width: '100%' }}
      opts={{ renderer: 'canvas' }}
    />
  )
}

export function DataTable({ spec }: { spec: TableSpec }) {
  return (
    <div className="table-wrap">
      <table className="data">
        <thead><tr>{spec.columns.map((c) => <th key={c.key} className={c.num ? 'num' : ''}>{c.label}</th>)}</tr></thead>
        <tbody>
          {spec.rows.map((r, i) => (
            <tr key={i}>
              {spec.columns.map((c) => {
                const v = r[c.key]
                return <td key={c.key} className={c.num ? 'num' : ''}>{typeof v === 'number' ? fmt(v, c.digits ?? 2) : String(v ?? '–')}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} aria-pressed={value === o.value} onClick={() => onChange(o.value)}>{o.label}</button>
      ))}
    </div>
  )
}

export function Legend({ items }: { items: { label: string; color: string }[] }) {
  return (
    <div className="legend">
      {items.map((i) => <span key={i.label}><span className="dot" style={{ background: i.color }} />{i.label}</span>)}
    </div>
  )
}

export function SectionHead({ eyebrow, title, aside }: { eyebrow: string; title: string; aside?: ReactNode }) {
  return (
    <Reveal className="section-head">
      <div style={{ display: 'grid', gap: 10 }}>
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
      </div>
      {aside}
    </Reveal>
  )
}

/** Neon trace that morphs flat -> pulse -> packet wave as it crosses the viewport. */
export function NeonDivider({ color = '#22d3ee' }: { color?: string }) {
  const ref = useRef<SVGSVGElement>(null)
  const pathRef = useRef<SVGPathElement>(null)
  const reduced = useReducedMotion()
  useEffect(() => {
    const N = 120, W = 1200, H = 120, mid = H / 2
    const flat = (t: number) => mid + 0 * t
    const pulse = (t: number) => {
      const c = Math.abs(t - 0.5)
      if (c > 0.12) return mid
      const s = (t - 0.38) / 0.24
      if (s < 0.25) return mid - Math.sin(s * 4 * Math.PI) * 6
      if (s < 0.4) return mid + 10
      if (s < 0.5) return mid - 46
      if (s < 0.6) return mid + 30
      if (s < 0.72) return mid - 8
      return mid - Math.sin((s - 0.72) / 0.28 * Math.PI) * 10
    }
    const packets = (t: number) => {
      const env = Math.max(0, 1 - Math.abs(t - 0.5) / 0.32)
      const sq = Math.sign(Math.sin(t * Math.PI * 22))
      return mid - sq * 22 * env
    }
    const shapes = [flat, pulse, packets]
    const draw = (p: number) => {
      const seg = Math.min(1.999, Math.max(0, p * 2))
      const i = Math.floor(seg), k = seg - i
      const e = k * k * (3 - 2 * k)
      let d = ''
      for (let n = 0; n <= N; n++) {
        const t = n / N
        const y = shapes[i](t) * (1 - e) + shapes[i + 1](t) * e
        d += `${n ? 'L' : 'M'}${(t * W).toFixed(1)},${y.toFixed(1)}`
      }
      pathRef.current?.setAttribute('d', d)
    }
    if (reduced) { draw(0.5); return }
    let raf = 0
    const on = () => {
      cancelAnimationFrame(raf)
      raf = requestAnimationFrame(() => {
        const el = ref.current
        if (!el) return
        const r = el.getBoundingClientRect()
        const p = 1 - (r.top + r.height / 2) / window.innerHeight
        draw(Math.min(1, Math.max(0, p * 1.4 - 0.2)))
      })
    }
    on()
    window.addEventListener('scroll', on, { passive: true })
    return () => { window.removeEventListener('scroll', on); cancelAnimationFrame(raf) }
  }, [reduced])
  return (
    <svg ref={ref} className="neon-divider" viewBox="0 0 1200 120" preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id="nd-fade" x1="0" x2="1">
          <stop offset="0" stopColor={color} stopOpacity="0" />
          <stop offset="0.5" stopColor={color} stopOpacity="1" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
        <filter id="nd-glow" x="-10%" y="-100%" width="120%" height="300%"><feGaussianBlur stdDeviation="4" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
      </defs>
      <path ref={pathRef} d="M0,60L1200,60" fill="none" stroke="url(#nd-fade)" strokeWidth="2.5" filter="url(#nd-glow)" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}

export function Callout({ children, tone = 'defense' }: { children: ReactNode; tone?: 'defense' | 'attack' | 'warn' }) {
  return <div className={`callout callout-${tone}`}>{children}</div>
}
