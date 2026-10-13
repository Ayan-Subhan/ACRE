import { useMemo, useState } from 'react'
import type { EChartsOption } from 'echarts'
import PageHeader from '../components/PageHeader'
import { Callout, Card, ChartCard, NeonDivider, Reveal, SectionHead, Segmented } from '../components/ui'
import { useData, type AdversaryData, type BasePaperData, type IdsData, type PipelineData } from '../lib/data'
import { axisTooltip, bar, grid, legendTop, lineTooltip, valueAxis } from '../lib/charts'
import { ATTACK_COLOR, C, SERIES, SOURCE_COLOR } from '../lib/theme'
import { fmt } from '../lib/motion'
import './pages.css'

const MODELS = ['MLP', 'CNN', 'LSTM']
const ATTACKS = ['FGSM', 'BIM', 'PGD', 'DeepFool']

function DsBadges({ ours = true }: { ours?: boolean }) {
  return (
    <>
      <span className="badge ds-badge"><span className="dot" style={{ background: SOURCE_COLOR.paper }} />Paper · IDS2018</span>
      {ours && <span className="badge ds-badge"><span className="dot" style={{ background: SOURCE_COLOR.ours }} />Ours · CICIoT2023</span>}
    </>
  )
}

export default function BasePaper() {
  const bp = useData<BasePaperData>('basepaper')
  const ids = useData<IdsData>('ids')
  const adv = useData<AdversaryData>('adversary')
  const pipe = useData<PipelineData>('pipeline')
  const [cleanMetric, setCleanMetric] = useState<'accuracy' | 'f1'>('accuracy')
  const [atkMetric, setAtkMetric] = useState<'accuracy' | 'attack_success'>('accuracy')

  const oursAttacked = useMemo(() => {
    if (!ids) return null
    return MODELS.map((m) => {
      const rows = ids.evasion.filter((e) => e.model === m)
      return {
        model: m,
        accuracy: rows.reduce((a, r) => a + r.adv_acc, 0) / rows.length,
        attack_success: rows.reduce((a, r) => a + r.evasion, 0) / rows.length,
      }
    })
  }, [ids])

  const clean = useMemo<EChartsOption | null>(() => {
    if (!bp || !ids) return null
    return {
      tooltip: axisTooltip(2),
      legend: legendTop(),
      grid: grid(),
      xAxis: { type: 'category', data: MODELS },
      yAxis: valueAxis({ max: 100 }),
      series: [
        bar({ name: 'Paper', color: SOURCE_COLOR.paper, data: MODELS.map((m) => bp.nids_clean.rows.find((r) => r.model === m)![cleanMetric]) }),
        bar({ name: 'Ours', color: SOURCE_COLOR.ours, data: MODELS.map((m) => ids.metrics.find((r) => r.model === m)![cleanMetric]) }),
      ],
    }
  }, [bp, ids, cleanMetric])

  const attacked = useMemo<EChartsOption | null>(() => {
    if (!bp || !oursAttacked) return null
    return {
      tooltip: axisTooltip(2),
      legend: legendTop(),
      grid: grid(),
      xAxis: { type: 'category', data: MODELS },
      yAxis: valueAxis({ max: 100 }),
      series: [
        bar({ name: 'Paper', color: SOURCE_COLOR.paper, data: MODELS.map((m) => bp.nids_under_attack.rows.find((r) => r.model === m)![atkMetric]) }),
        bar({ name: 'Ours', color: SOURCE_COLOR.ours, data: oursAttacked.map((r) => r[atkMetric]) }),
      ],
    }
  }, [bp, oursAttacked, atkMetric])

  const perAttack = useMemo<EChartsOption | null>(() => {
    if (!bp || !ids) return null
    const ours = ATTACKS.map((a) => {
      const rows = ids.evasion.filter((e) => e.attack === a)
      return rows.reduce((s, r) => s + r.evasion, 0) / rows.length
    })
    return {
      tooltip: axisTooltip(2),
      legend: legendTop(),
      grid: grid(),
      xAxis: { type: 'category', data: ATTACKS },
      yAxis: valueAxis({ max: 100 }),
      series: [
        bar({ name: 'Paper (before EIDS)', color: SOURCE_COLOR.paper, data: ATTACKS.map((a) => bp.eids_by_attack.rows.find((r) => r.attack === a)!.success_before) }),
        bar({ name: 'Ours (avg of 3 models)', color: SOURCE_COLOR.ours, data: ours }),
      ],
    }
  }, [bp, ids])

  const slope = useMemo<EChartsOption | null>(() => {
    if (!bp) return null
    return {
      tooltip: lineTooltip(2),
      legend: legendTop(),
      grid: grid({ right: 120 }),
      xAxis: { type: 'category', data: ['Before EIDS', 'After EIDS'], boundaryGap: false, axisLabel: { color: C.fg2 } },
      yAxis: valueAxis({ max: 100 }),
      series: ATTACKS.map((a) => {
        const r = bp.eids_by_attack.rows.find((x) => x.attack === a)!
        return {
          name: a, type: 'line', color: ATTACK_COLOR[a], symbolSize: 9, lineStyle: { width: 2 },
          data: [r.success_before, r.success_after],
          endLabel: { show: true, formatter: (p: any) => `${a} ${Number(p.value).toFixed(1)}%`, color: C.fg2, fontFamily: 'Fira Code', fontSize: 11 },
        }
      }),
    }
  }, [bp])

  const disc = useMemo<EChartsOption | null>(() => {
    if (!bp) return null
    const metrics = ['accuracy', 'precision', 'recall', 'f1'] as const
    return {
      tooltip: axisTooltip(2),
      legend: legendTop(),
      grid: grid({ top: 60 }),
      xAxis: { type: 'category', data: ['Accuracy', 'Precision', 'Recall', 'F1'] },
      yAxis: valueAxis({ max: 100 }),
      series: bp.discriminator.rows.map((r, i) => bar({ name: r.classifier, color: SERIES[i], barMaxWidth: 14, data: metrics.map((m) => r[m]) })),
    }
  }, [bp])

  const mixed = useMemo<EChartsOption | null>(() => {
    if (!bp) return null
    const names = bp.mixed_scenario.rows.map((r) => r.model)
    return {
      tooltip: axisTooltip(2),
      legend: legendTop(),
      grid: grid(),
      xAxis: { type: 'category', data: ['Accuracy', 'Recall', 'F1'] },
      yAxis: valueAxis({ max: 100 }),
      series: bp.mixed_scenario.rows.map((r, i) => bar({ name: names[i], color: r.model === 'EIDS' ? C.model : [SERIES[0], SERIES[1], SERIES[2]][i - 1], barMaxWidth: 18, data: [r.accuracy, r.recall, r.f1] })),
    }
  }, [bp])

  const best = adv ? adv.tiers.reduce((a, b) => (b.value > a.value ? b : a)) : null
  const unreal = adv ? Math.max(...adv.projection.map((p) => p.unrealizable)) : 0
  const grey = adv?.tiers.find((t) => t.attack === 'greybox' && t.spec === 'C')?.value ?? 0
  const black = adv?.tiers.find((t) => t.attack === 'blackbox' && t.spec === 'C')?.value ?? 0
  const dup = pipe ? (pipe.exact_duplicates / pipe.rows_in_file) * 100 : 0

  return (
    <div className="page">
      <PageHeader eyebrow="Reference · Verma et al. 2025" title="Base paper" icon="/icons/paper.svg" color={C.warn}
        lead="The paper's reported numbers next to ours. Different datasets, so read the gaps as context, not as a leaderboard." />

      <section className="section" style={{ paddingTop: 24 }}>
        <div className="container">
          <Reveal>
            <Card className="cite">
              <span className="eyebrow" style={{ color: 'var(--warn)' }}>Citation</span>
              <span className="cite-title">{bp?.citation.title}</span>
              <span className="cite-meta">{bp?.citation.authors} · {bp?.citation.venue} · DOI {bp?.citation.doi}</span>
              <span className="cite-meta">Dataset: {bp?.citation.dataset} · {bp?.citation.adversarial_samples.toLocaleString()} adversarial samples</span>
            </Card>
          </Reveal>
        </div>
      </section>

      <NeonDivider color="#facc15" />

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Head to head" title="Same models, different worlds" />
          <div className="grid grid-2">
            <ChartCard title="Clean detection" caption="IDS2018 is close to saturated. CICIoT2023 is harder." option={clean} height={300} badges={<DsBadges />}
              controls={<Segmented label="Metric" value={cleanMetric} onChange={setCleanMetric} options={[{ value: 'accuracy', label: 'Accuracy' }, { value: 'f1', label: 'F1' }]} />}
              table={bp && ids ? { columns: [{ key: 'model', label: 'Model' }, { key: 'pa', label: 'Paper acc', num: true }, { key: 'oa', label: 'Our acc', num: true }, { key: 'pf', label: 'Paper F1', num: true }, { key: 'of', label: 'Our F1', num: true }],
                rows: MODELS.map((m) => { const p = bp.nids_clean.rows.find((r) => r.model === m)!; const o = ids.metrics.find((r) => r.model === m)!; return { model: m, pa: p.accuracy, oa: o.accuracy, pf: p.f1, of: o.f1 } }) } : undefined} />
            <ChartCard title="Under unconstrained attack" caption="Averaged over FGSM, BIM, PGD and DeepFool." option={attacked} height={300} badges={<DsBadges />}
              controls={<Segmented label="Metric" value={atkMetric} onChange={setAtkMetric} options={[{ value: 'accuracy', label: 'Accuracy' }, { value: 'attack_success', label: 'Attack success' }]} />} />
            <ChartCard className="span-2" title="Attack success by method" caption="Paper: before EIDS. Ours: evasion rate averaged over the three models." option={perAttack} height={300} badges={<DsBadges />} />
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Paper only, for now" title="Results we have not reached yet" />
          <div className="grid grid-2">
            <ChartCard title="EIDS: attack success before → after" caption="Adversarial training kills BIM and PGD, barely moves FGSM and DeepFool." option={slope} height={300}
              badges={<><DsBadges ours={false} /><span className="badge">ours: M6</span></>}
              table={bp ? { columns: [{ key: 'attack', label: 'Attack' }, { key: 'success_before', label: 'Success before', num: true }, { key: 'success_after', label: 'Success after', num: true }, { key: 'acc_before', label: 'Acc before', num: true }, { key: 'acc_after', label: 'Acc after', num: true }, { key: 'f1_before', label: 'F1 before', num: true }, { key: 'f1_after', label: 'F1 after', num: true }], rows: bp.eids_by_attack.rows } : undefined} />
            <ChartCard title="Discriminator classifiers" caption="Random forest scores 100% on every metric (SVC values approximate)." option={disc} height={300}
              badges={<><DsBadges ours={false} /><span className="badge">ours: M5</span></>}
              table={bp ? { columns: [{ key: 'classifier', label: 'Classifier' }, { key: 'accuracy', label: 'Acc', num: true }, { key: 'precision', label: 'Prec', num: true }, { key: 'recall', label: 'Rec', num: true }, { key: 'f1', label: 'F1', num: true }], rows: bp.discriminator.rows } : undefined} />
            <ChartCard className="span-2" title="Mixed traffic: EIDS vs single models" caption="Intrusions, adversarial and benign rows together." option={mixed} height={280}
              badges={<><DsBadges ours={false} /><span className="badge">ours: M8</span></>} />
          </div>
        </div>
      </section>

      <section className="section">
        <div className="container">
          <SectionHead eyebrow="Beyond the paper" title="What this work adds" />
          <div className="grid grid-4">
            {[
              { big: `${fmt(unreal, 0)}%`, t: 'ART rows unrealizable', s: 'Paper-style attacks cannot be sent as real traffic.', c: 'var(--danger)' },
              { big: `${fmt(best?.value ?? 0, 1)}%`, t: 'Realizable pass-and-evade', s: 'A validator-aware attacker still gets through.', c: 'var(--attack)' },
              { big: `${fmt(grey, 1)} / ${fmt(black, 1)}%`, t: 'Grey / black-box', s: 'Knowledge tiers the paper does not test.', c: 'var(--adversarial)' },
              { big: `${fmt(dup, 1)}%`, t: 'Duplicate rows removed', s: 'Leakage check before any training.', c: 'var(--defense)' },
            ].map((x, i) => (
              <Reveal key={x.t} delay={i * 70}>
                <Card className="add-card">
                  <span className="big" style={{ color: x.c }}>{x.big}</span>
                  <h3>{x.t}</h3>
                  <p className="muted" style={{ fontSize: 13 }}>{x.s}</p>
                </Card>
              </Reveal>
            ))}
          </div>
          <Reveal style={{ marginTop: 16 }}>
            <Callout tone="warn"><strong>Reading note.</strong> The paper reports only white-box, unconstrained attacks on two IDS2018 files. Its validator has no published numbers.</Callout>
          </Reveal>
        </div>
      </section>
    </div>
  )
}
