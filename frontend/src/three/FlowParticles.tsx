import { useEffect, useLayoutEffect, useMemo, useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import { Line } from '@react-three/drei'
import * as THREE from 'three'
import { node } from './layout'

export type Outcome = 'blocked' | 'alert' | 'lan'
export type Kind = 'benign' | 'attack' | 'adversarial'

export interface FlowRates {
  benign: { blocked: number; alert: number }     // probabilities (0..1)
  attack: { blocked: number; alert: number }
  adversarial: { blocked: number; alert: number }
  mix: { benign: number; attack: number; adversarial: number }
}

export const KIND_COLOR: Record<Kind, string> = { benign: '#22d3ee', attack: '#ff6a2b', adversarial: '#e879f9' }

const H = 0.55 // travel height above the floor

function v(id: string, dy = H) {
  const p = node(id).pos
  return new THREE.Vector3(p[0], dy, p[2])
}

function buildCurves() {
  const curves: Record<string, THREE.CatmullRomCurve3> = {}
  for (const src of ['iot', 'adversary']) {
    const start = v(src)
    const head = [start, new THREE.Vector3((start.x + v('gateway').x) / 2, 1.1, (start.z + 1) / 2), v('gateway'), v('validator')]
    curves[`${src}:blocked`] = new THREE.CatmullRomCurve3([...head, new THREE.Vector3(0.6, 0.9, 2.7), v('blocked', 0.5)], false, 'centripetal')
    const mid = [...head, new THREE.Vector3(2.25, 0.85, 1.0), v('discriminator'), new THREE.Vector3(5.6, 0.85, 1.0), v('eids')]
    curves[`${src}:alert`] = new THREE.CatmullRomCurve3([...mid, new THREE.Vector3(7.3, 0.9, 2.7), v('alert', 0.5)], false, 'centripetal')
    curves[`${src}:lan`] = new THREE.CatmullRomCurve3([...mid, new THREE.Vector3(9.7, 1.0, 1.0), v('lan')], false, 'centripetal')
  }
  return curves
}

interface P { curve: string; u: number; speed: number; kind: Kind; outcome: Outcome; active: boolean }

/**
 * Traffic as particles. Each packet picks its fate at spawn from the measured
 * rates (validator reject, EIDS detect, adversarial pass-and-evade) and flies
 * the matching path; sinks pulse on arrival.
 */
export default function FlowParticles({ count, rates, appear, pulse, tally, paused }: {
  count: number
  rates: React.MutableRefObject<FlowRates>
  appear: React.MutableRefObject<number>
  pulse: React.MutableRefObject<Record<string, number>>
  tally: React.MutableRefObject<Record<Kind, Record<Outcome, number>>>
  paused?: boolean
}) {
  const mesh = useRef<THREE.InstancedMesh>(null)
  const rails = useRef<({ material: THREE.Material & { opacity: number } } | null)[]>([])
  const curves = useMemo(buildCurves, [])
  const lengths = useMemo(() => Object.fromEntries(Object.entries(curves).map(([k, c]) => [k, c.getLength()])), [curves])
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const tmp = useMemo(() => new THREE.Vector3(), [])
  const color = useMemo(() => new THREE.Color(), [])

  const spawn = (p: P, u0 = 0) => {
    const r = rates.current
    const x = Math.random()
    p.kind = x < r.mix.benign ? 'benign' : x < r.mix.benign + r.mix.attack ? 'attack' : 'adversarial'
    const pr = r[p.kind]
    const y = Math.random()
    p.outcome = y < pr.blocked ? 'blocked' : y < pr.blocked + (1 - pr.blocked) * pr.alert ? 'alert' : 'lan'
    p.curve = `${p.kind === 'adversarial' ? 'adversary' : 'iot'}:${p.outcome}`
    p.u = u0
    // equal travel time on every path, so live tallies converge to the measured rates
    p.speed = lengths[p.curve] / (5.5 + Math.random() * 1.5)
    p.active = true
  }

  const parts = useMemo<P[]>(() => {
    const arr: P[] = []
    for (let i = 0; i < count; i++) {
      const p = { curve: 'iot:lan', u: 0, speed: 3, kind: 'benign', outcome: 'lan', active: false } as P
      arr.push(p)
    }
    return arr
  }, [count])

  useEffect(() => { parts.forEach((p) => spawn(p, Math.random())) }, [parts]) // eslint-disable-line react-hooks/exhaustive-deps

  // create instanceColor before the first render so the shader compiles with it
  useLayoutEffect(() => {
    const m = mesh.current
    if (!m) return
    for (let i = 0; i < count; i++) { m.setColorAt(i, color.set('#ffffff')); m.setMatrixAt(i, new THREE.Matrix4().makeScale(0, 0, 0)) }
    if (m.instanceColor) m.instanceColor.needsUpdate = true
  }, [count, color])

  useFrame((_, dt) => {
    const m = mesh.current
    if (!m) return
    const show = THREE.MathUtils.clamp((appear.current - 0.85) / 0.15, 0, 1)
    rails.current.forEach((r) => { if (r) r.material.opacity = show * 0.18 })
    const step = paused ? 0 : Math.min(dt, 0.05)
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i]
      p.u += (p.speed * step) / lengths[p.curve]
      if (p.u >= 1) {
        tally.current[p.kind][p.outcome]++
        const sink = p.outcome === 'lan' ? 'lan' : p.outcome
        pulse.current[sink] = Math.min(1.5, (pulse.current[sink] ?? 0) + 0.35)
        spawn(p)
      }
      curves[p.curve].getPointAt(Math.min(p.u, 1), tmp)
      dummy.position.copy(tmp)
      const fadeIn = Math.min(1, p.u * 12)
      dummy.scale.setScalar(show * fadeIn * (p.kind === 'adversarial' ? 1.25 : 1))
      dummy.updateMatrix()
      m.setMatrixAt(i, dummy.matrix)
      m.setColorAt(i, color.set(KIND_COLOR[p.kind]).multiplyScalar(2.2))
    }
    m.instanceMatrix.needsUpdate = true
    if (m.instanceColor) m.instanceColor.needsUpdate = true
  })

  return (
    <group>
      {/* faint guide rails for the three outcomes */}
      {(['iot:lan', 'adversary:lan', 'iot:blocked', 'iot:alert'] as const).map((k, i) => (
        <Line key={k} ref={(l) => { rails.current[i] = l as unknown as { material: THREE.Material & { opacity: number } } }} points={curves[k].getPoints(80)} color={k.startsWith('adversary') ? '#e879f9' : '#22d3ee'} lineWidth={1} transparent opacity={0} />
      ))}
      <instancedMesh ref={mesh} args={[undefined, undefined, count]} frustumCulled={false}>
        <sphereGeometry args={[0.075, 10, 10]} />
        <meshBasicMaterial toneMapped={false} />
      </instancedMesh>
    </group>
  )
}
