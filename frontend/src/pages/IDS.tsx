import { useMemo, useState } from 'react'
import type { EChartsOption } from 'echarts'
import PageHeader from '../components/PageHeader'
import { ChartCard, Legend, NeonDivider, SectionHead, Segmented, StatTile } from '../components/ui'
import { useData, type IdsData } from '../lib/data'
import { axisTooltip, bar, grid, heatmapVisual, heatCell, legendTop, lineTooltip, pct, valueAxis } from '../lib/charts'
import { ATTACK_COLOR, C, MODEL_COLOR, SEQ_BLUE } from '../lib/theme'
import './pages.css'

const MODELS = ['MLP', 'CNN', 'LSTM']
const modelLegend = MODELS.map((m) => ({ label: m, color: MODEL_COLOR[m] }))

export default function IDS() {
  const d = useData<IdsData>('ids')
  const [metric, setMetric] = useState<'accuracy' | 'loss'>('accuracy')
  const [split, setSplit] = useState<'val' | 'train'>('val')
  const [atk, setAtk] = useState<'feat_pgd' | 'prim_pgd'>('feat_pgd')

  const curves = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const key = split === 'val' ? (`val_${metric}` as const) : metric
    const epochs = Math.max(...MODELS.map((m) => d.history[m.toLowerCase()][key].length))
    return {
      tooltip: lineTooltip(4),
      legend: legendTop(),
      grid: grid(),
      xAxis: { type: 'category', data: Array.from({ length: epochs }, (_, i) => i + 1), name: 'epoch', nameLocation: 'middle', nameGap: 26, boundaryGap: false },
      yAxis: { type: 'value', scale: true, axisLabel: { formatter: (v: number) => (metric === 'accuracy' ? `${(v * 100).toFixed(1)}%` : v.toFixed(3)) } },
      series: MODELS.map((m) => ({
        name: m, type: 'line', showSymbol: false, symbolSize: 8, color: MODEL_COLOR[m],
        data: d.history[m.toLowerCase()][key], lineStyle: { width: 2 },
      })),
    }
  }, [d, metric, split])

  const dots = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const cats = ['accuracy', 'balanced_accuracy', 'precision', 'recall', 'f1'] as const
    const names = ['Accuracy', 'Balanced acc.', 'Precision', 'Recall', 'F1']
    return {
      tooltip: axisTooltip(2),
      legend: legendTop(),
      grid: grid(),
      xAxis: { type: 'category', data: names, axisPointer: { type: 'shadow' }, axisLabel: { interval: 0, fontSize: 10 } },
      yAxis: valueAxis({ min: 88, max: 100 }),
      series: MODELS.map((m) => ({
        name: m, type: 'scatter', symbolSize: 13, color: MODEL_COLOR[m],
        itemStyle: { borderColor: C.surface, borderWidth: 2 },
        data: cats.map((c) => d.metrics.find((x) => x.model === m)![c]),
      })),
    }
  }, [d])

  const recallHeat = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const cats = d.per_category_recall.map((r) => r.category)
    return {
      tooltip: { formatter: (p: any) => `${MODELS[p.value[1]]} · ${cats[p.value[0]]}<br/>recall <b>${pct(p.value[2], 2)}</b>` },
      grid: grid({ top: 8, bottom: 56 }),
      xAxis: { type: 'category', data: cats, axisLabel: { interval: 0, rotate: 30 } },
      yAxis: { type: 'category', data: MODELS },
      visualMap: heatmapVisual(60, 100, SEQ_BLUE),
      series: [{
        type: 'heatmap', data: d.per_category_recall.flatMap((r, x) => MODELS.map((m, y) => heatCell(x, y, (r as unknown as Record<string, number>)[m], 60, 100))),
        label: { show: true, fontFamily: 'Fira Code', fontSize: 10, formatter: (p: any) => Number(p.value[2]).toFixed(0) },
        itemStyle: { borderColor: C.surface, borderWidth: 2, borderRadius: 4 },
      }],
    }
  }, [d])

  const evasion = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const attacks = ['FGSM', 'BIM', 'PGD', 'DeepFool']
    return {
      tooltip: axisTooltip(1),
      legend: legendTop(),
      grid: grid(),
      xAxis: { type: 'category', data: MODELS },
      yAxis: valueAxis({ max: 100 }),
      series: attacks.map((a) => bar({
        name: a, color: ATTACK_COLOR[a],
        data: MODELS.map((m) => d.evasion.find((e) => e.model === m && e.attack === a)?.evasion ?? null),
      })),
    }
  }, [d])

  const realizable = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    return {
      tooltip: lineTooltip(1),
      legend: legendTop(),
      grid: grid(),
      xAxis: { type: 'category', data: ['Spec A', 'Spec B', 'Spec C'], boundaryGap: false },
      yAxis: valueAxis({ max: 60 }),
      series: MODELS.map((m) => ({
        name: m, type: 'line', color: MODEL_COLOR[m], symbolSize: 9, lineStyle: { width: 2 },
        data: ['A', 'B', 'C'].map((s) => d.realizable.find((r) => r.spec === s && r.model === m && r.attack === atk)?.pass_and_evade ?? null),
      })),
    }
  }, [d, atk])

  const radar = useMemo<EChartsOption | null>(() => {
    if (!d) return null
    const ev = (m: string, a: string) => 100 - (d.evasion.find((e) => e.model === m && e.attack === a)?.evasion ?? 0)
    const re = (m: string) => 100 - (d.realizable.find((r) => r.spec === 'C' && r.model === m && r.attack === 'feat_pgd')?.pass_and_evade ?? 0)
    return {
      tooltip: { trigger: 'item' },
      legend: { bottom: 0 },
      radar: {
        radius: '62%', center: ['50%', '48%'], splitNumber: 4,
        indicator: [
          { name: 'Clean bal. acc', max: 100 }, { name: 'vs FGSM', max: 100 }, { name: 'vs BIM', max: 100 },
          { name: 'vs PGD', max: 100 }, { name: 'vs DeepFool', max: 100 }, { name: 'vs realizable', max: 100 },
        ],
        axisName: { color: C.muted, fontFamily: 'Fira Sans', fontSize: 11 },
        splitLine: { lineStyle: { color: '#1c2430' } }, splitArea: { show: false }, axisLine: { lineStyle: { color: '#1c2430' } },
      },
      series: [{
        type: 'radar', symbolSize: 6,
        data: MODELS.map((m) => ({
          name: m, value: [d.metrics.find((x) => x.model === m)!.balanced_accuracy, ev(m, 'FGSM'), ev(m, 'BIM'), ev(m, 'PGD'), ev(m, 'DeepFool'), re(m)],
          lineStyle: { color: MODEL_COLOR[m], width: 2 }, itemStyle: { color: MODEL_COLOR[m] }, areaStyle: { color: MODEL_COLOR[m], opacity: 0.08 },
        })),
      }],
    }
  }, [d])

  const fprBars = useMemo<EChartsOption | null>(() => d && ({
    tooltip: axisTooltip(2),
    grid: grid({ top: 16 }),
    xAxis: { type: 'category', data: [...MODELS, 'OR-ensemble'] },
    yAxis: valueAxis(),
    series: [bar({
      name: 'False-positive rate',
      data: [...MODELS.map((m) => ({ value: d.metrics.find((x) => x.model === m)!.fpr, itemStyle: { color: MODEL_COLOR[m] } })), { value: d.ensemble.fpr, itemStyle: { color: C.model } }],
      label: { show: true, position: 'top', color: C.fg2, fontFamily: 'Fira Code', fontSize: 10, formatter: (p: any) => `${Number(p.value).toFixed(2)}` },
    })],
  }), [d])

  const m = (name: string) => d?.metrics.find((x) => x.model === name)

  return (
    <div className="page">
      <PageHeader eyebrow="Gate 3 · M2" title="IDS" icon="/icons/ids.svg" color={C.model}
        lead="Three deep models vote with a logical OR. Strong on floods and weaker on stealthy traffic, and an easy target for gradient attacks.">
        <div className="grid grid-4">
          {MODELS.map((n, i) => (
            <StatTile key={n} label={`${n} balanced accuracy`} value={m(n)?.balanced_accuracy ?? 0} sub={m(n) ? `${m(n)!.params.toLocaleString()} params · ${m(n)!.epochs} epochs` : ''} accent={MODEL_COLOR[n]} delay={i * 80} />
          ))}
          <StatTile label="OR-ensemble FPR" value={d?.ensemble.fpr ?? 0} decimals={2} sub={`budget ${((d?.fpr_budget ?? 0) * 100).toFixed(0)}% per model`} accent="var(--model)" delay={240} />
        </div>
      </PageHeader>

      <NeonDivider color="#8b5cf6" />

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Training" title="How each model learned" />
          <div className="grid grid-2">
            <ChartCard className="span-2" title="Learning curves" caption="Per-epoch accuracy or loss." option={curves} height={340}
              controls={<>
                <Segmented label="Metric" value={metric} onChange={setMetric} options={[{ value: 'accuracy', label: 'Accuracy' }, { value: 'loss', label: 'Loss' }]} />
                <Segmented label="Split" value={split} onChange={setSplit} options={[{ value: 'val', label: 'Validation' }, { value: 'train', label: 'Train' }]} />
              </>} />
            <ChartCard title="Clean test metrics" caption="Zoomed to 88–100% so the differences show." option={dots} height={300}
              table={d ? { columns: [{ key: 'model', label: 'Model' }, { key: 'accuracy', label: 'Acc', num: true }, { key: 'balanced_accuracy', label: 'Bal-acc', num: true }, { key: 'precision', label: 'Prec', num: true }, { key: 'recall', label: 'Rec', num: true }, { key: 'f1', label: 'F1', num: true }, { key: 'fpr', label: 'FPR', num: true }], rows: d.metrics } : undefined} />
            <ChartCard title="False positives at the deployed threshold" caption="Thresholds calibrated for ≤2% FPR on validation data." option={fprBars} height={300} />
            <ChartCard className="span-2" title="Recall by attack category" caption="Floods are nearly perfect. Recon, spoofing, web and brute force are where it misses." option={recallHeat} height={260}
              table={d ? { columns: [{ key: 'category', label: 'Category' }, { key: 'support', label: 'Rows', num: true, digits: 0 }, { key: 'MLP', label: 'MLP', num: true }, { key: 'CNN', label: 'CNN', num: true }, { key: 'LSTM', label: 'LSTM', num: true }], rows: d.per_category_recall } : undefined} />
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Under attack" title="How each model holds up" aside={<Legend items={modelLegend} />} />
          <div className="grid grid-2">
            <ChartCard title="Unconstrained evasion" caption="Share of detected attacks flipped to benign (ε = 0.1, 5,000 rows)." option={evasion} height={320}
              table={d ? { columns: [{ key: 'model', label: 'Model' }, { key: 'attack', label: 'Attack' }, { key: 'clean_acc', label: 'Clean acc', num: true }, { key: 'adv_acc', label: 'Adv acc', num: true }, { key: 'evasion', label: 'Evasion', num: true }], rows: d.evasion } : undefined} />
            <ChartCard title="Realizable pass-and-evade" caption="Fools the target model and passes the validator, as attacker freedom grows." option={realizable} height={320}
              controls={<Segmented label="Attack" value={atk} onChange={setAtk} options={[{ value: 'feat_pgd', label: 'Feature PGD' }, { value: 'prim_pgd', label: 'Physical PGD' }]} />} />
            <ChartCard className="span-2" title="Robustness profile" caption="Further out is better: 100 minus evasion, plus clean balanced accuracy." option={radar} height={380} />
          </div>
        </div>
      </section>
    </div>
  )
}
