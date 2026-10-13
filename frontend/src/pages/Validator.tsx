import { useMemo, useState } from 'react'
import type { EChartsOption } from 'echarts'
import PageHeader from '../components/PageHeader'
import { Callout, Card, ChartCard, NeonDivider, Reveal, SectionHead, Segmented, StatTile } from '../components/ui'
import { useData, type ValidatorData } from '../lib/data'
import { axisTooltip, bar, grid, hbar, heatmapVisual, heatCell, pct, valueAxis } from '../lib/charts'
import { C, SEQ_BLUE, SERIES } from '../lib/theme'
import { fmt } from '../lib/motion'
import './pages.css'

type Family = 'range' | 'integrality' | 'dependency' | 'distribution'
const FAMILIES: { value: Family; label: string; line: string }[] = [
  { value: 'range', label: 'Range', line: 'Each feature stays inside its benign [min, max], padded by 1% of the span.' },
  { value: 'integrality', label: 'Integrality', line: 'Flag and protocol columns must be exactly 0 or 1.' },
  { value: 'dependency', label: 'Dependency', line: 'Cross-feature identities that real traffic always obeys.' },
  { value: 'distribution', label: 'Distribution', line: 'Robust z-score per protocol group, threshold at 1% benign FPR.' },
]

const compact = (v: number) => {
  const a = Math.abs(v)
  if (a >= 1e6) return `${(v / 1e6).toFixed(1)}M`
  if (a >= 1e3) return `${(v / 1e3).toFixed(1)}k`
  if (a >= 10) return v.toFixed(0)
  return v.toFixed(2)
}

export default function Validator() {
  const d = useData<ValidatorData>('validator')
  const [family, setFamily] = useState<Family>('range')

  const heat = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const fams: Family[] = ['range', 'integrality', 'dependency', 'distribution']
    const sets = d.art_sets.map((s) => s.set.replace(' x ', ' × ').toUpperCase())
    return {
      tooltip: { formatter: (p: any) => `${sets[p.value[1]]}<br/>${fams[p.value[0]]}: <b>${pct(p.value[2])}</b> caught` },
      grid: grid({ top: 8, bottom: 56, left: 8 }),
      xAxis: { type: 'category', data: fams.map((f) => f[0].toUpperCase() + f.slice(1)), splitArea: { show: false } },
      yAxis: { type: 'category', data: sets, axisLabel: { fontSize: 10 } },
      visualMap: heatmapVisual(0, 100, SEQ_BLUE),
      series: [{
        type: 'heatmap',
        data: d.art_sets.flatMap((s, y) => fams.map((f, x) => heatCell(x, y, s[f], 0, 100))),
        label: { show: true, fontFamily: 'Fira Code', fontSize: 10, formatter: (p: any) => Number(p.value[2]).toFixed(0) },
        itemStyle: { borderColor: C.surface, borderWidth: 2, borderRadius: 4 },
        emphasis: { itemStyle: { borderColor: C.defense, borderWidth: 1 } },
      }],
    }
  }, [d])

  // groups with a handful of benign test rows give meaningless rates; table keeps them
  const fprGroups = useMemo(() => d?.fpr_by_group.filter((g) => g.n >= 100) ?? [], [d])
  const tinyGroups = d?.fpr_by_group.filter((g) => g.n < 100) ?? []
  const fprOpt = useMemo<EChartsOption | null>(() => d && ({
    tooltip: axisTooltip(2),
    grid: grid({ top: 16 }),
    xAxis: { type: 'category', data: fprGroups.map((g) => g.group) },
    yAxis: valueAxis({ max: 2 }),
    series: [bar({
      data: fprGroups.map((g) => g.fpr), color: SERIES[0], name: 'Benign FPR',
      markLine: { symbol: 'none', silent: true, lineStyle: { color: C.warn, type: 'dashed' }, label: { color: C.warn, formatter: '1% budget', fontFamily: 'Fira Code', fontSize: 10 }, data: [{ yAxis: 1 }] },
    })],
  }), [d, fprGroups])

  const rejectOpt = useMemo<EChartsOption | null>(() => d && ({
    tooltip: axisTooltip(1),
    grid: grid({ top: 16 }),
    xAxis: { type: 'category', data: d.reject_by_category.map((c) => c.category), axisLabel: { interval: 0, rotate: 30 } },
    yAxis: valueAxis({ max: 100 }),
    series: [bar({
      name: 'Rejected', data: d.reject_by_category.map((c) => ({ value: c.rejected, itemStyle: { color: c.category === 'Benign' ? C.ok : SERIES[1] } })),
      label: { show: true, position: 'top', color: C.fg2, fontFamily: 'Fira Code', fontSize: 10, formatter: (p: any) => `${Number(p.value).toFixed(0)}` },
    })],
  }), [d])

  const stopOpt = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const artStop = d.art_sets.reduce((a, s) => a + (s.evade_model_only - s.pass_and_evade) / s.evade_model_only, 0) / d.art_sets.length * 100
    const rows = [
      { name: 'Unconstrained ART (avg of 12)', v: artStop, c: SERIES[0] },
      ...d.realizable_stop.map((r) => ({ name: `Realizable ${r.attack.replace('_ens', '')} · spec ${r.spec}`, v: (r.stopped / r.fooled) * 100, c: SERIES[1] })),
    ]
    return {
      tooltip: axisTooltip(1),
      grid: grid({ top: 8, right: 40 }),
      yAxis: { type: 'category', data: rows.map((r) => r.name).reverse(), axisLabel: { fontSize: 11 } },
      xAxis: valueAxis({ max: 100 }),
      series: [hbar({
        name: 'Model-fooling rows stopped', data: rows.map((r) => ({ value: r.v, itemStyle: { color: r.c } })).reverse(),
        label: { show: true, position: 'right', color: C.fg2, fontFamily: 'Fira Code', fontSize: 10, formatter: (p: any) => `${Number(p.value).toFixed(1)}%` },
      })],
    }
  }, [d])

  const distOpt = useMemo<EChartsOption | null>(() => d && ({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, formatter: (ps: any) => { const g = d.distribution[ps[0].dataIndex]; return `${g.group}<br/>threshold <b>${g.threshold}</b><br/>${g.train_rows.toLocaleString()} benign train rows${g.global_profile ? '<br/>uses global profile' : ''}` } },
    grid: grid({ top: 16 }),
    xAxis: { type: 'category', data: d.distribution.map((g) => g.group) },
    yAxis: { type: 'value', name: 'z-score threshold' },
    series: [bar({ data: d.distribution.map((g) => g.threshold), color: SERIES[2], name: 'Threshold', label: { show: true, position: 'top', color: C.fg2, fontFamily: 'Fira Code', fontSize: 10 } })],
  }), [d])

  const fam = FAMILIES.find((f) => f.value === family)!

  return (
    <div className="page">
      <PageHeader eyebrow="Gate 1 · M3" title="Validator" icon="/icons/validator.svg" color={C.defense}
        lead="Rules mined from benign traffic reject anything a real flow could not look like, before any model sees it.">
        <div className="grid grid-4">
          <StatTile label="Benign false positives" value={d?.clean.benign_fpr ?? 0} decimals={2} accent="var(--ok)" sub={`${fmt((d?.clean.benign_n ?? 0) / 1000, 0)}k test rows`} />
          <StatTile label="ART examples caught" value={d ? Math.min(...d.art_sets.map((x) => x.combined)) : 0} decimals={2} sub="worst of 12 sets" delay={80} />
          <StatTile label="Pass + fool a model" value={d ? Math.max(...d.art_sets.map((x) => x.pass_and_evade)) : 0} decimals={2} accent="var(--attack)" sub="unconstrained, worst case" delay={160} />
          <StatTile label="Rules applied" value={d ? d.range.length + d.integrality.length + d.dependency.length + d.distribution.length : 0} decimals={0} suffix="" accent="var(--model)" sub="across 4 families" delay={240} />
        </div>
      </PageHeader>

      <NeonDivider />

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Rule explorer" title="What it checks"
            aside={<Segmented label="Rule family" value={family} onChange={setFamily} options={FAMILIES.map(({ value, label }) => ({ value, label }))} />} />
          <Reveal><p className="muted section-line">{fam.line}</p></Reveal>
          {d && family === 'range' && (
            <div className="feature-grid">
              {d.range.map((r, i) => (
                <Reveal key={r.feature} delay={(i % 12) * 25}>
                  <div className="feature-tile">
                    <span className="mono feature-name">{r.feature}{d.log1p_columns.includes(r.feature) && <em title="log1p-scaled">log</em>}</span>
                    <span className="mono feature-range">[{compact(r.min)}, {compact(r.max)}]</span>
                  </div>
                </Reveal>
              ))}
            </div>
          )}
          {d && family === 'integrality' && (
            <div className="chip-cloud">
              {d.integrality.map((c, i) => (
                <Reveal key={c} delay={i * 30}><span className="chip chip-lg">{c} <span className="muted">∈ {'{0, 1}'}</span></span></Reveal>
              ))}
            </div>
          )}
          {d && family === 'dependency' && (
            <div className="rule-list">
              {d.dependency.map((r, i) => (
                <Reveal key={r.name} delay={i * 30}>
                  <div className="rule-row">
                    <span className="mono rule-name">{r.name}</span>
                    <span className="badge">{r.kind.replace('_', ' ')}</span>
                    <span className="mono muted rule-res">tol {r.tolerance}</span>
                  </div>
                </Reveal>
              ))}
              {d.dependency_pruned.map((r) => (
                <Reveal key={r.name}>
                  <div className="rule-row pruned">
                    <span className="mono rule-name">{r.name}</span>
                    <span className="badge" style={{ color: 'var(--warn)' }}>pruned</span>
                    <span className="muted rule-res">{r.reason}</span>
                  </div>
                </Reveal>
              ))}
            </div>
          )}
          {d && family === 'distribution' && (
            <div className="grid grid-2">
              <ChartCard title="Threshold per protocol group" caption="Rows scoring above the line are rejected." option={distOpt} height={280}
                table={{ columns: [{ key: 'group', label: 'Group' }, { key: 'threshold', label: 'Threshold', num: true, digits: 3 }, { key: 'train_rows', label: 'Train rows', num: true, digits: 0 }], rows: d.distribution }} />
              <Card>
                <h3>How the score works</h3>
                <ol className="steps">
                  <li>Split traffic by protocol: TCP, UDP, ICMP, ARP, other.</li>
                  <li>Per feature, compute |x − median| / MAD from benign rows, clipped at 50.</li>
                  <li>Average over the 36 features to get one score per flow.</li>
                  <li>Set the cut at a 1% benign false-positive budget on validation data.</li>
                </ol>
              </Card>
            </div>
          )}
        </div>
      </section>

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Detection" title="How it performs" />
          <div className="grid grid-2">
            <ChartCard className="span-2" title="Catch rate by rule family" caption="Share of each unconstrained ART set that each family rejects on its own." option={heat} height={440}
              table={d ? { columns: [{ key: 'set', label: 'Set' }, { key: 'range', label: 'Range', num: true }, { key: 'integrality', label: 'Integrality', num: true }, { key: 'dependency', label: 'Dependency', num: true }, { key: 'distribution', label: 'Distribution', num: true }, { key: 'combined', label: 'Combined', num: true }], rows: d.art_sets } : undefined} />
            <ChartCard title="False positives by protocol" caption={`Benign test rows wrongly rejected.${tinyGroups.length ? ` ${tinyGroups.map((g) => `${g.group} (${g.n} rows)`).join(", ")} omitted: too few rows.` : ""}`} option={fprOpt} height={280}
              table={d ? { columns: [{ key: 'group', label: 'Group' }, { key: 'n', label: 'Rows', num: true, digits: 0 }, { key: 'fpr', label: 'FPR %', num: true, digits: 3 }], rows: d.fpr_by_group } : undefined} />
            <ChartCard title="Clean traffic rejected" caption="Unperturbed rows by category. Benign is the false-positive rate." option={rejectOpt} height={280}
              table={d ? { columns: [{ key: 'category', label: 'Category' }, { key: 'n', label: 'Rows', num: true, digits: 0 }, { key: 'rejected', label: 'Rejected %', num: true }], rows: d.reject_by_category } : undefined} />
            <ChartCard className="span-2" title="Realistic attacks slip past" caption="Of the rows that already fool the models, how many the validator still stops." option={stopOpt} height={300} />
          </div>
          <Reveal style={{ marginTop: 16 }}>
            <Callout tone="attack"><strong>Why the gap?</strong> ART perturbations produce impossible flows that break the rules. Realizable attacks only change things a real sender can change, so they stay inside the rules.</Callout>
          </Reveal>
        </div>
      </section>
    </div>
  )
}
