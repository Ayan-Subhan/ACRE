import * as echarts from 'echarts'

/** JS mirror of tokens.css for three.js and ECharts. */
export const C = {
  bg: '#000000',
  surface: '#0b0f14',
  border: '#1c2430',
  fg: '#e6edf3',
  fg2: '#c3ccd6',
  muted: '#8b98a8',
  defense: '#22d3ee',
  attack: '#ff6a2b',
  adversarial: '#e879f9',
  model: '#8b5cf6',
  ok: '#34d399',
  warn: '#facc15',
  danger: '#ef4444',
}

/** Categorical order (validated: adjacent pairs pass CVD + normal-vision on the dark surface). */
export const SERIES = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#9085e9']

/** Fixed entity -> colour maps (colour follows the entity, never its rank). */
export const MODEL_COLOR: Record<string, string> = { MLP: SERIES[0], CNN: SERIES[1], LSTM: SERIES[2] }
export const ATTACK_COLOR: Record<string, string> = { FGSM: SERIES[0], BIM: SERIES[1], PGD: SERIES[2], DeepFool: SERIES[3] }
export const SPEC_COLOR: Record<string, string> = { A: SERIES[0], B: SERIES[1], C: SERIES[2] }
export const SOURCE_COLOR = { ours: SERIES[0], paper: SERIES[1] }

/** Sequential ramps (dark surface: low recedes toward the surface). */
export const SEQ_BLUE = ['#0d1f3a', '#104281', '#1c5cab', '#2a78d6', '#5598e7', '#9ec5f4', '#cde2fb']
export const SEQ_ORANGE = ['#2a1206', '#5e240c', '#943711', '#d95926', '#ec8455', '#f6b591', '#fbdcc9']

let registered = false
export function registerTheme() {
  if (registered) return
  registered = true
  const axis = {
    axisLine: { show: true, lineStyle: { color: '#2a3647' } },
    axisTick: { show: false },
    axisLabel: { color: C.muted, fontFamily: 'Fira Code', fontSize: 11 },
    splitLine: { show: true, lineStyle: { color: '#161d27' } },
    nameTextStyle: { color: C.muted, fontFamily: 'Fira Sans', fontSize: 11 },
  }
  echarts.registerTheme('acre', {
    color: SERIES,
    backgroundColor: 'transparent',
    textStyle: { fontFamily: 'Fira Sans', color: C.fg2 },
    title: { textStyle: { color: C.fg } },
    legend: { textStyle: { color: C.fg2, fontSize: 12 }, icon: 'roundRect', itemWidth: 12, itemHeight: 8 },
    tooltip: {
      backgroundColor: 'rgba(11,15,20,0.96)',
      borderColor: '#2a3647',
      borderWidth: 1,
      textStyle: { color: C.fg, fontFamily: 'Fira Sans', fontSize: 12 },
      extraCssText: 'border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.6);',
    },
    categoryAxis: { ...axis, splitLine: { show: false } },
    valueAxis: { ...axis, axisLine: { show: false } },
    line: { symbolSize: 8, lineStyle: { width: 2 }, smooth: false },
    bar: { itemStyle: { borderRadius: [4, 4, 0, 0] } },
  })
}
