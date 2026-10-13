import type { EChartsOption } from 'echarts'
import { C } from './theme'

export const grid = (o: Partial<{ left: number; right: number; top: number; bottom: number }> = {}) => ({
  left: 8, right: 16, top: 36, bottom: 8, containLabel: true, ...o,
})

export const pct = (v: unknown, d = 1) => (typeof v === 'number' ? `${v.toFixed(d)}%` : String(v))

export const axisTooltip = (d = 1): EChartsOption['tooltip'] => ({
  trigger: 'axis',
  axisPointer: { type: 'shadow', shadowStyle: { color: 'rgba(34,211,238,0.06)' } },
  valueFormatter: (v) => pct(v, d),
})

export const lineTooltip = (d = 2): EChartsOption['tooltip'] => ({
  trigger: 'axis',
  axisPointer: { type: 'line', lineStyle: { color: '#3a4a5e', type: 'dashed' } },
  valueFormatter: (v) => (typeof v === 'number' ? v.toFixed(d) : String(v)),
})

export const legendTop = (): EChartsOption['legend'] => ({ top: 0, left: 0 })

export const valueAxis = (o: Record<string, unknown> = {}) => ({
  type: 'value' as const,
  axisLabel: { formatter: (v: number) => `${v}%` },
  ...o,
})

/** Bar defaults: thin, rounded data-end, 2px surface gap between neighbours. */
export const bar = (o: Record<string, unknown> = {}) => ({
  type: 'bar' as const,
  barMaxWidth: 26,
  barGap: '18%',
  itemStyle: { borderRadius: [4, 4, 0, 0], borderColor: C.surface, borderWidth: 1 },
  emphasis: { focus: 'series' as const },
  ...o,
})

export const hbar = (o: Record<string, unknown> = {}) => bar({ itemStyle: { borderRadius: [0, 4, 4, 0], borderColor: C.surface, borderWidth: 1 }, ...o })

export const heatmapVisual = (min: number, max: number, colors: string[]): EChartsOption['visualMap'] => ({
  min, max, calculable: false, orient: 'horizontal', left: 'center', bottom: 0, itemWidth: 10, itemHeight: 160,
  inRange: { color: colors }, textStyle: { color: C.muted, fontFamily: 'Fira Code', fontSize: 11 },
  formatter: (v) => `${Number(v).toFixed(0)}%`,
})

/** Heatmap cell with label ink chosen for contrast against its ramp position. */
export const heatCell = (x: number, y: number, v: number, min: number, max: number) => ({
  value: [x, y, v],
  label: { color: (v - min) / (max - min) > 0.55 ? '#0b0f14' : '#e6edf3' },
})
