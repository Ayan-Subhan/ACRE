import { useMemo, useState } from 'react'
import type { EChartsOption } from 'echarts'
import PageHeader from '../components/PageHeader'
import { Card, ChartCard, NeonDivider, Reveal, SectionHead, Segmented, StatTile } from '../components/ui'
import { useData, type AdversaryData } from '../lib/data'
import { axisTooltip, bar, grid, heatmapVisual, heatCell, legendTop, pct, valueAxis, hbar } from '../lib/charts'
import { C, SEQ_ORANGE, SERIES, SPEC_COLOR } from '../lib/theme'
import { fmt } from '../lib/motion'
import './pages.css'

const TIER_COLOR: Record<string, string> = { white: SERIES[0], grey: SERIES[1], black: SERIES[2] }
const KNOBS = [
  { k: 'pad', label: 'pad', line: 'add bytes to packets' },
  { k: 'dttl', label: 'ΔTTL', line: 'shift time-to-live' },
  { k: 'slow', label: 'slow', line: 'keep-alive, up to 5×' },
  { k: 'stretch', label: 'stretch', line: 'split into fresh connections' },
]

export default function Adversary() {
  const d = useData<AdversaryData>('adversary')
  const [attacker, setAttacker] = useState('adaptive_feat')
  const [spec, setSpec] = useState<'A' | 'B' | 'C'>('C')
  const [projSpec, setProjSpec] = useState<'A' | 'B' | 'C'>('C')
  const label = (a: string) => d?.attackers.find((x) => x.attack === a)?.label ?? a

  const sankey = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const f = d.flows.find((x) => x.attack === attacker && x.spec === spec)
    if (!f) return null
    const n = f.n
    const passV = Math.round((n * f.passes_validator) / 100)
    const lan = Math.round((n * f.pass_and_evade) / 100)
    const nodes = [
      { name: 'Crafted', itemStyle: { color: C.attack } },
      { name: 'Blocked by validator', itemStyle: { color: C.danger } },
      { name: 'Passes validator', itemStyle: { color: C.defense } },
      { name: 'Discriminator (M5)', itemStyle: { color: '#4b5563' } },
      { name: 'Alerted by EIDS', itemStyle: { color: C.adversarial } },
      { name: 'Reaches LAN', itemStyle: { color: C.warn } },
    ]
    return {
      tooltip: { trigger: 'item', formatter: (p: any) => p.dataType === 'edge' ? `${p.data.source} → ${p.data.target}<br/><b>${p.data.value.toLocaleString()}</b> rows (${((p.data.value / n) * 100).toFixed(1)}%)` : `${p.name}` },
      series: [{
        type: 'sankey', left: 8, right: 150, top: 12, bottom: 12, nodeWidth: 12, nodeGap: 18, draggable: false, nodeAlign: 'left',
        emphasis: { focus: 'adjacency' },
        label: { color: C.fg, fontFamily: 'Fira Sans', fontSize: 12, formatter: (p: any) => `${p.name}\n{v|${Number(p.value).toLocaleString()}}`, rich: { v: { color: C.muted, fontFamily: 'Fira Code', fontSize: 11, padding: [3, 0, 0, 0] } } },
        lineStyle: { color: 'gradient', opacity: 0.35, curveness: 0.5 },
        data: nodes,
        links: [
          { source: 'Crafted', target: 'Blocked by validator', value: n - passV },
          { source: 'Crafted', target: 'Passes validator', value: passV },
          { source: 'Passes validator', target: 'Discriminator (M5)', value: passV },
          { source: 'Discriminator (M5)', target: 'Alerted by EIDS', value: passV - lan },
          { source: 'Discriminator (M5)', target: 'Reaches LAN', value: lan },
        ],
      }],
    }
  }, [d, attacker, spec])

  const tiers = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const attackers = d.attackers.map((a) => a.attack)
    const specs = ['A', 'B', 'C']
    const val = (a: string, s: string) => d.tiers.find((t) => t.attack === a && t.spec === s)!
    return {
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: (ps: any) => {
        const a = attackers[ps[0].dataIndex]
        return `${label(a)}<br/>` + specs.map((s) => { const t = val(a, s); return `<span style="color:${SPEC_COLOR[s]}">●</span> spec ${s}: <b>${t.value.toFixed(1)}%</b> <span style="color:#8b98a8">[${t.lo.toFixed(1)}, ${t.hi.toFixed(1)}]</span>` }).join('<br/>')
      } },
      legend: { top: 0, left: 0, data: specs.map((s) => `Spec ${s}`) },
      grid: grid({ bottom: 8 }),
      xAxis: { type: 'category', data: attackers.map((a) => label(a).replace(' (', '\n(')), axisLabel: { interval: 0, fontSize: 10, lineHeight: 13 } },
      yAxis: valueAxis({ max: 45 }),
      series: [
        ...specs.map((s) => bar({ name: `Spec ${s}`, color: SPEC_COLOR[s], data: attackers.map((a) => val(a, s).value) })),
        {
          type: 'custom', name: '95% CI', silent: true, z: 10,
          renderItem: (_params: any, api: any) => {
            const xi = api.value(0), si = api.value(1)
            const lo = api.coord([xi, api.value(2)]), hi = api.coord([xi, api.value(3)])
            const band = api.size([1, 0])[0]
            const groupW = Math.min(band * 0.8, 26 * 3 * 1.18)
            const bw = groupW / 3
            const x = lo[0] - groupW / 2 + bw * (si + 0.5)
            const style = { stroke: C.fg2, lineWidth: 1.2 }
            return { type: 'group', children: [
              { type: 'line', shape: { x1: x, y1: lo[1], x2: x, y2: hi[1] }, style },
              { type: 'line', shape: { x1: x - 3, y1: lo[1], x2: x + 3, y2: lo[1] }, style },
              { type: 'line', shape: { x1: x - 3, y1: hi[1], x2: x + 3, y2: hi[1] }, style },
            ] }
          },
          encode: { x: 0, y: [2, 3] },
          data: attackers.flatMap((a, xi) => specs.map((s, si) => [xi, si, val(a, s).lo, val(a, s).hi])),
        } as any,
      ],
    }
  }, [d]) // eslint-disable-line react-hooks/exhaustive-deps

  const catHeat = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const cats = ['BruteForce', 'Web', 'Recon', 'Spoofing', 'DDoS', 'DoS', 'Mirai']
    const atts = d.attackers.map((a) => a.attack)
    return {
      tooltip: { formatter: (p: any) => `${label(atts[p.value[1]])} · ${cats[p.value[0]]}<br/><b>${pct(p.value[2])}</b> pass and evade` },
      grid: grid({ top: 8, bottom: 56 }),
      xAxis: { type: 'category', data: cats, axisLabel: { interval: 0 } },
      yAxis: { type: 'category', data: atts.map(label), axisLabel: { fontSize: 10 } },
      visualMap: heatmapVisual(0, 90, SEQ_ORANGE),
      series: [{
        type: 'heatmap',
        data: atts.flatMap((a, y) => cats.map((c, x) => heatCell(x, y, d.by_category.find((r) => r.attack === a && r.category === c)?.pass_and_evade ?? 0, 0, 90))),
        label: { show: true, fontFamily: 'Fira Code', fontSize: 10, formatter: (p: any) => Number(p.value[2]).toFixed(0) },
        itemStyle: { borderColor: C.surface, borderWidth: 2, borderRadius: 4 },
      }],
    }
  }, [d]) // eslint-disable-line react-hooks/exhaustive-deps

  const projection = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const rows = d.projection.filter((p) => p.spec === projSpec)
    const names = rows.map((r) => `${r.attack} × ${r.model}`)
    return {
      tooltip: axisTooltip(1),
      legend: legendTop(),
      grid: grid({ right: 24 }),
      yAxis: { type: 'category', data: names, axisLabel: { fontSize: 10 }, inverse: true },
      xAxis: valueAxis({ max: 100 }),
      series: [
        hbar({ name: 'Evasion as generated', color: SERIES[0], data: rows.map((r) => r.evasion_before), barMaxWidth: 9 }),
        hbar({ name: 'After repair to real traffic', color: SERIES[1], data: rows.map((r) => r.evasion_after), barMaxWidth: 9 }),
      ],
    }
  }, [d, projSpec])

  const levers = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const keys = [['younger_%', 'Shorter conn.'], ['padding_%', 'Padding'], ['throttling_%', 'Throttling'], ['ttl_%', 'TTL'], ['longer_%', 'Longer conn.']] as const
    const atts = d.levers.map((l) => l.attack.replace(/_(ens|surr)$/, ''))
    return {
      tooltip: axisTooltip(1),
      legend: legendTop(),
      grid: grid({ top: 56 }),
      xAxis: { type: 'category', data: keys.map((k) => k[1]), axisLabel: { interval: 0, fontSize: 11 } },
      yAxis: valueAxis({ max: 100 }),
      series: d.levers.map((l, i) => bar({ name: label(atts[i]), color: SERIES[i], data: keys.map((k) => l[k[0]]) })),
    }
  }, [d]) // eslint-disable-line react-hooks/exhaustive-deps

  const cost = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    return {
      tooltip: { trigger: 'item', formatter: (p: any) => `${p.data.name.split(' / ').map(label).join(' / ')}<br/>byte overhead ${p.data.value[0]}%<br/>rate loss ${p.data.value[1]}%<br/>pass-and-evade ${p.data.value[2]}%` },
      legend: { top: 0, left: 0, data: ['white', 'grey', 'black'].map((t) => ({ name: `${t}-box` })) },
      grid: grid({ right: 24, bottom: 24, top: 44 }),
      xAxis: { type: 'value', name: 'median byte overhead', nameLocation: 'middle', nameGap: 28, axisLabel: { formatter: '{value}%' } },
      yAxis: { type: 'value', name: 'median rate loss', axisLabel: { formatter: '{value}%' } },
      series: ['white', 'grey', 'black'].map((t) => ({
        name: `${t}-box`, type: 'scatter', color: TIER_COLOR[t],
        symbolSize: (v: number[]) => 10 + v[2] * 0.7,
        itemStyle: { borderColor: C.surface, borderWidth: 2, opacity: 0.9 },
        label: { show: true, position: 'right', color: C.fg2, fontFamily: 'Fira Code', fontSize: 10, formatter: (p: any) => p.data.name },
        data: Object.values(d.cost.filter((c) => d.attackers.find((a) => a.attack === c.attack)?.tier === t)
          .reduce<Record<string, { name: string; value: number[] }>>((acc, c) => {
            const k = `${c.byte_overhead}|${c.rate_loss}`
            if (acc[k]) { acc[k].name += ` / ${c.attack}`; acc[k].value[2] = Math.max(acc[k].value[2], c.pass_and_evade) }
            else acc[k] = { name: c.attack, value: [c.byte_overhead, c.rate_loss, c.pass_and_evade] }
            return acc
          }, {})),
      })),
    }
  }, [d]) // eslint-disable-line react-hooks/exhaustive-deps

  const unrealizable = d ? [Math.min(...d.projection.map((p) => p.unrealizable)), Math.max(...d.projection.map((p) => p.unrealizable))] : [0, 0]
  const best = d ? d.tiers.reduce((a, b) => (b.value > a.value ? b : a)) : null
  const younger = d?.levers.find((l) => l.attack.startsWith('prim_pgd'))?.['younger_%'] ?? 0

  return (
    <div className="page">
      <PageHeader eyebrow="Threat model · M4" title="Adversary" icon="/icons/adversary.svg" color={C.attack}
        lead="Attacks that only change what a real sender can change, at white, grey and black-box knowledge.">
        <div className="grid grid-4">
          <StatTile label="Best pass-and-evade" value={best?.value ?? 0} accent="var(--attack)" sub={best ? `${best.attack} · spec ${best.spec}` : ''} />
          <StatTile label="ART rows unrealizable" value={unrealizable[1]} decimals={0} accent="var(--danger)" sub={`min ${fmt(unrealizable[0], 0)}% across sets`} delay={80} />
          <StatTile label="Wins that shorten connections" value={younger} decimals={0} accent="var(--warn)" sub="physical-knob PGD, spec C" delay={160} />
          <StatTile label="Black-box with 1,000 queries" value={d?.tiers.find((t) => t.attack === 'blackbox' && t.spec === 'C')?.value ?? 0} accent="var(--adversarial)" sub="allow/stop answers only" delay={240} />
        </div>
      </PageHeader>

      <NeonDivider color="#ff6a2b" />

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Attacker freedom" title="Three realism specs" />
          <div className="spec-cards">
            {d && (['A', 'B', 'C'] as const).map((s, i) => (
              <Reveal key={s} delay={i * 80}>
                <Card className="spec-card">
                  <h3><span className="dot" style={{ background: SPEC_COLOR[s], boxShadow: `0 0 10px ${SPEC_COLOR[s]}` }} />Spec {s}</h3>
                  <p className="muted" style={{ fontSize: 13, marginTop: 4 }}>{d.specs[s].label}</p>
                  <div className="knobs">
                    {KNOBS.map((k) => <span key={k.k} className={`chip ${d.specs[s].knobs.includes(k.k) ? '' : 'knob-off'}`} title={k.line}>{k.label}</span>)}
                  </div>
                </Card>
              </Reveal>
            ))}
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Through the gates" title="How much gets through" />
          <div className="grid grid-2">
            <ChartCard className="span-2" title="Path of every crafted row" caption="6,300 attack rows, all detected before the attack. Each gate takes its share." option={sankey} height={360}
              controls={<>
                <select className="select" aria-label="Attacker" value={attacker} onChange={(e) => setAttacker(e.target.value)}>
                  {d?.attackers.map((a) => <option key={a.attack} value={a.attack}>{a.label} · {a.tier}</option>)}
                </select>
                <Segmented label="Spec" value={spec} onChange={setSpec} options={[{ value: 'A', label: 'A' }, { value: 'B', label: 'B' }, { value: 'C', label: 'C' }]} />
              </>} />
            <ChartCard className="span-2" title="Pass-and-evade by attacker" caption="Fools all three models and passes the validator. Whiskers show the 95% bootstrap CI." option={tiers} height={360}
              table={d ? { columns: [{ key: 'attack', label: 'Attacker' }, { key: 'tier', label: 'Tier' }, { key: 'spec', label: 'Spec' }, { key: 'value', label: 'Pass+evade %', num: true }, { key: 'lo', label: 'CI lo', num: true }, { key: 'hi', label: 'CI hi', num: true }], rows: d.tiers } : undefined} />
            <ChartCard className="span-2" title="Who gets through, by category" caption="Spec C. Low-volume attacks hide easily; floods must stay loud to work." option={catHeat} height={330}
              table={d ? { columns: [{ key: 'attack', label: 'Attacker' }, { key: 'category', label: 'Category' }, { key: 'pass_and_evade', label: '%', num: true, digits: 1 }], rows: d.by_category } : undefined} />
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Realism check" title="Unconstrained attacks fall apart" />
          <div className="grid grid-2">
            <ChartCard title="ART attacks, before and after repair" caption="Projecting each ART example back onto sendable traffic." option={projection} height={420}
              controls={<Segmented label="Spec" value={projSpec} onChange={setProjSpec} options={[{ value: 'A', label: 'A' }, { value: 'B', label: 'B' }, { value: 'C', label: 'C' }]} />}
              table={d ? { columns: [{ key: 'spec', label: 'Spec' }, { key: 'attack', label: 'Attack' }, { key: 'model', label: 'Model' }, { key: 'unrealizable', label: 'Unrealizable %', num: true }, { key: 'evasion_before', label: 'Before', num: true }, { key: 'evasion_after', label: 'After', num: true }], rows: d.projection } : undefined} />
            <div className="grid" style={{ alignContent: 'start' }}>
              <ChartCard title="What winning attacks change" caption="Share of successful rows using each action (spec C)." option={levers} height={280} />
              <ChartCard title="What success costs" caption="Bubble size is the pass-and-evade rate." option={cost} height={260} />
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
