import { useMemo } from 'react'
import type { EChartsOption } from 'echarts'
import PageHeader from '../components/PageHeader'
import { ChartCard, NeonDivider, Reveal, SectionHead, StatTile } from '../components/ui'
import { useData, type PipelineData, type ValidatorData } from '../lib/data'
import { grid, hbar, legendTop } from '../lib/charts'
import { C, SERIES } from '../lib/theme'
import './pages.css'

const CATS = ['Benign', 'DDoS', 'DoS', 'Mirai', 'Recon', 'Spoofing', 'Web', 'BruteForce']
const CAT_COLOR: Record<string, string> = Object.fromEntries(CATS.map((c, i) => [c, c === 'Benign' ? C.ok : SERIES[(i - 1) % SERIES.length]]))
const M = (v: number) => (v >= 1e6 ? `${(v / 1e6).toFixed(2)}M` : v >= 1e3 ? `${(v / 1e3).toFixed(0)}k` : String(v))

export default function Pipeline() {
  const p = useData<PipelineData>('pipeline')
  const v = useData<ValidatorData>('validator')

  const funnel = useMemo<EChartsOption | null>(() => {
    if (!p) return null
    const train = p.classes.reduce((a, c) => a + c.train, 0)
    const steps = [
      { name: 'Rows in CSV', value: p.rows_in_file },
      { name: 'Distinct rows', value: p.distinct_rows },
      { name: 'Kept (≤60k per class)', value: p.rows_kept },
      { name: 'Training split (70%)', value: train },
    ]
    return {
      tooltip: { trigger: 'item', formatter: (x: any) => `${x.name}<br/><b>${x.value.toLocaleString()}</b>` },
      series: [{
        type: 'funnel', left: '6%', right: '6%', top: 10, bottom: 10, minSize: '18%', sort: 'none', gap: 4,
        label: { position: 'inside', color: '#fff', fontFamily: 'Fira Sans', fontSize: 12, formatter: (x: any) => `${x.name}  ·  ${M(x.value)}` },
        itemStyle: { borderColor: C.surface, borderWidth: 2, borderRadius: 6 },
        data: steps.map((s, i) => ({ ...s, itemStyle: { color: ['#1c5cab', '#2a78d6', '#199e70', '#8b5cf6'][i] } })),
      }],
    }
  }, [p])

  const treemap = useMemo<EChartsOption | null>(() => {
    if (!p) return null
    return {
      tooltip: { formatter: (x: any) => `${x.treePathInfo.map((t: any) => t.name).filter(Boolean).join(' › ')}<br/><b>${Number(x.value).toLocaleString()}</b> rows kept` },
      series: [{
        type: 'treemap', roam: false, nodeClick: false, breadcrumb: { show: false }, top: 0, left: 0, right: 0, bottom: 0,
        label: { color: '#fff', fontFamily: 'Fira Sans', fontSize: 11, overflow: 'truncate' },
        upperLabel: { show: true, height: 20, color: '#fff', fontFamily: 'Fira Code', fontSize: 11 },
        itemStyle: { borderColor: C.surface, borderWidth: 2, gapWidth: 2, borderRadius: 4 },
        levels: [{ itemStyle: { borderWidth: 0, gapWidth: 4 } }, { itemStyle: { gapWidth: 2 } }],
        data: CATS.map((cat) => ({
          name: cat, itemStyle: { color: CAT_COLOR[cat] },
          children: p.classes.filter((c) => c.category === cat).map((c) => ({ name: c.class.replace(/^(DDoS|DoS|Mirai|Recon)-/, ''), value: c.kept })),
        })),
      }],
    }
  }, [p])

  const rawKept = useMemo<EChartsOption | null>(() => {
    if (!p) return null
    const agg = CATS.map((cat) => {
      const cs = p.classes.filter((c) => c.category === cat)
      return { cat, raw: cs.reduce((a, c) => a + c.raw, 0), kept: cs.reduce((a, c) => a + c.kept, 0) }
    })
    return {
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: (x: any) => Number(x).toLocaleString() },
      legend: legendTop(),
      grid: grid({ right: 24 }),
      yAxis: { type: 'category', data: agg.map((a) => a.cat), inverse: true },
      xAxis: { type: 'log', min: 1000, axisLabel: { formatter: (x: number) => M(x) } },
      series: [
        { name: 'Raw rows', type: 'scatter', symbolSize: 12, color: SERIES[1], data: agg.map((a) => a.raw), itemStyle: { borderColor: C.surface, borderWidth: 2 } },
        { name: 'Kept', type: 'scatter', symbolSize: 12, color: SERIES[0], data: agg.map((a) => a.kept), itemStyle: { borderColor: C.surface, borderWidth: 2 } },
      ],
    }
  }, [p])

  const leak = useMemo<EChartsOption | null>(() => {
    if (!p) return null
    const rows = p.leakage.top_single_feature
    return {
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, valueFormatter: (x: any) => `${Number(x).toFixed(1)}%` },
      grid: grid({ top: 8, right: 40 }),
      yAxis: { type: 'category', data: rows.map((r) => r.feature), inverse: true, axisLabel: { fontFamily: 'Fira Code', fontSize: 11 } },
      xAxis: { type: 'value', min: 0, max: 100, axisLabel: { formatter: '{value}%' } },
      series: [hbar({
        name: 'Balanced accuracy (one feature alone)', color: SERIES[0], data: rows.map((r) => r.bal_acc),
        markLine: { symbol: 'none', silent: true, lineStyle: { color: C.danger, type: 'dashed' }, label: { color: C.danger, formatter: 'leak alarm 99%', fontFamily: 'Fira Code', fontSize: 10 }, data: [{ xAxis: 99 }] },
      })],
    }
  }, [p])

  return (
    <div className="page">
      <PageHeader eyebrow="Offline zone · M1" title="Data pipeline" icon="/icons/pipeline.svg" color={C.model}
        lead="From a 13.8 GB CSV to clean, deduplicated, leakage-checked splits.">
        <div className="grid grid-4">
          <StatTile label="Rows in the raw CSV" value={(p?.rows_in_file ?? 0) / 1e6} decimals={1} suffix="M" accent="var(--model)" />
          <StatTile label="Exact duplicates" value={p ? (p.exact_duplicates / p.rows_in_file) * 100 : 0} accent="var(--danger)" sub="removed before sampling" delay={80} />
          <StatTile label="Rows kept" value={(p?.rows_kept ?? 0) / 1e6} decimals={2} suffix="M" sub={`split ${p?.split ?? ''}`} delay={160} />
          <StatTile label="Features" value={p?.n_features ?? 0} decimals={0} suffix="" accent="var(--ok)" sub={`from ${p?.features_before ?? 0} after constant drop`} delay={240} />
        </div>
      </PageHeader>

      <NeonDivider color="#8b5cf6" />

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Reduction" title="What survives cleaning" />
          <div className="grid grid-2">
            <ChartCard title="Row funnel" caption="Deduplicate first, then cap each class." option={funnel} height={300} />
            <ChartCard title="Raw vs kept, by category" caption="Log scale. Floods shrink most; rare classes are kept whole." option={rawKept} height={300} />
            <ChartCard className="span-2" title="Class mix after cleaning" caption="34 classes in 8 categories." option={treemap} height={380}
              table={p ? { columns: [{ key: 'class', label: 'Class' }, { key: 'category', label: 'Category' }, { key: 'raw', label: 'Raw', num: true, digits: 0 }, { key: 'kept', label: 'Kept', num: true, digits: 0 }, { key: 'test', label: 'Test', num: true, digits: 0 }], rows: p.classes } : undefined} />
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Hygiene" title="Leakage probe and features" />
          <div className="grid grid-2">
            <ChartCard title="No single feature gives the answer away" caption={`Best one-feature classifiers. ${p?.leakage.identical_to_train ?? 0} of ${p?.leakage.test_rows.toLocaleString() ?? ''} test rows match a training row.`} option={leak} height={300} />
            <Reveal>
              <div className="card chart-card">
                <div className="chart-head"><div><h3>The 36 features</h3><p className="chart-cap">Purple = log1p-scaled. Struck through = dropped.</p></div></div>
                <div className="feature-chips">
                  {v?.features.map((f) => <span key={f} className="chip" style={p?.log1p_columns.includes(f) ? { borderColor: 'rgba(139,92,246,.5)', color: '#c4b5fd' } : undefined}>{f}</span>)}
                  {p && [...p.constant_columns, ...p.dropped_columns].map((f) => <span key={f} className="chip dropped">{f}</span>)}
                </div>
              </div>
            </Reveal>
          </div>
        </div>
      </section>
    </div>
  )
}
