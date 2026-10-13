/** World layout of the architecture diagram (x = flow direction, z = depth, y = up). */

export type Vec3 = [number, number, number]

export interface ZoneDef {
  id: string
  label: string
  sub: string
  x0: number; x1: number; z0: number; z1: number
  color: string
}

export interface NodeDef {
  id: string
  label: string
  icon: string
  pos: Vec3
  route: string
  zone: string
  hint: string
  size?: number
  dim?: boolean
  badge?: string
}

export const ZONES: ZoneDef[] = [
  { id: 'untrusted', label: 'Untrusted zone', sub: 'internet · IoT testbed', x0: -11.4, x1: -5.6, z0: -1.6, z1: 4.6, color: '#ff6a2b' },
  { id: 'edge', label: 'Edge', sub: 'gateway · flow features', x0: -4.9, x1: -2.1, z0: -0.6, z1: 2.6, color: '#38bdf8' },
  { id: 'dmz', label: 'Defense DMZ', sub: 'three gates', x0: -1.4, x1: 9.2, z0: -1.6, z1: 5.8, color: '#22d3ee' },
  { id: 'lan', label: 'Protected LAN', sub: 'allowed traffic', x0: 9.9, x1: 14.2, z0: -0.6, z1: 2.6, color: '#34d399' },
  { id: 'offline', label: 'Offline training zone', sub: 'air-gapped from live traffic', x0: -2.6, x1: 9.2, z0: -7.4, z1: -3.6, color: '#8b5cf6' },
]

export const NODES: NodeDef[] = [
  { id: 'adversary', label: 'Adversary', icon: '/icons/adversary.svg', pos: [-8.5, 0, -0.1], route: '/adversary', zone: 'untrusted', hint: 'realizable, adaptive attacks' },
  { id: 'iot', label: 'IoT testbed', icon: '/icons/iot.svg', pos: [-8.5, 0, 3.0], route: '/pipeline', zone: 'untrusted', hint: '105 devices · CICIoT2023' },
  { id: 'gateway', label: 'Edge gateway', icon: '/icons/gateway.svg', pos: [-3.5, 0, 1.0], route: '/pipeline', zone: 'edge', hint: '36 flow features' },
  { id: 'validator', label: 'Validator', icon: '/icons/validator.svg', pos: [0.6, 0, 1.0], route: '/validator', zone: 'dmz', hint: 'gate 1 · rule checks' },
  { id: 'discriminator', label: 'Discriminator', icon: '/icons/discriminator.svg', pos: [3.9, 0, 1.0], route: '/discriminator', zone: 'dmz', hint: 'gate 2 · random forest', dim: true, badge: 'M5' },
  { id: 'eids', label: 'EIDS', icon: '/icons/ids.svg', pos: [7.3, 0, 1.0], route: '/ids', zone: 'dmz', hint: 'gate 3 · MLP ∨ CNN ∨ LSTM', size: 1.15 },
  { id: 'lan', label: 'Protected LAN', icon: '/icons/lan.svg', pos: [12.0, 0, 1.0], route: '/ids', zone: 'lan', hint: 'traffic that got through' },
  { id: 'blocked', label: 'Blocked', icon: '/icons/sink-blocked.svg', pos: [0.6, 0, 4.4], route: '/validator', zone: 'dmz', hint: 'validator rejects', size: 0.75 },
  { id: 'quarantine', label: 'Quarantine', icon: '/icons/sink-quarantine.svg', pos: [3.9, 0, 4.4], route: '/discriminator', zone: 'dmz', hint: 'discriminator (M5)', size: 0.75, dim: true },
  { id: 'alert', label: 'Alert', icon: '/icons/sink-alert.svg', pos: [7.3, 0, 4.4], route: '/ids', zone: 'dmz', hint: 'EIDS detections', size: 0.75 },
  { id: 'pipeline', label: 'Data pipeline', icon: '/icons/pipeline.svg', pos: [-0.6, 0, -5.5], route: '/pipeline', zone: 'offline', hint: '46.7M → 2.55M rows' },
  { id: 'rules', label: 'Rule mining', icon: '/icons/rules.svg', pos: [3.3, 0, -5.5], route: '/validator', zone: 'offline', hint: 'rules.json · 4 families' },
  { id: 'training', label: 'Model training', icon: '/icons/training.svg', pos: [7.3, 0, -5.5], route: '/ids', zone: 'offline', hint: 'MLP · CNN · LSTM' },
]

/** Satellite model chips orbiting the EIDS node. */
export const EIDS_MODELS = ['MLP', 'CNN', 'LSTM']

/** Segregation walls (x = const or z = const). */
export const WALLS: { a: [number, number]; b: [number, number]; color: string }[] = [
  { a: [-5.25, -1.6], b: [-5.25, 4.6], color: '#ff6a2b' },
  { a: [-1.75, -1.6], b: [-1.75, 5.8], color: '#22d3ee' },
  { a: [9.55, -1.6], b: [9.55, 5.8], color: '#34d399' },
  { a: [-2.6, -2.6], b: [9.2, -2.6], color: '#8b5cf6' },
]

/** Offline -> online deploy links. */
export const DEPLOY: { from: string; to: string; label: string }[] = [
  { from: 'rules', to: 'validator', label: 'rules.json' },
  { from: 'training', to: 'eids', label: '.keras + thresholds' },
  { from: 'pipeline', to: 'rules', label: '' },
  { from: 'pipeline', to: 'training', label: '' },
]

export const node = (id: string) => NODES.find((n) => n.id === id)!

export const ARCH_TARGET: Vec3 = [0.6, 0, -0.2]
export const HERO_TARGET: Vec3 = [1.6, 3.2, 1.0]
